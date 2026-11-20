// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Cuback Congestion Control
//!
//! An ACK-driven reformulation of CUBIC, based on the following draft:
//! <https://www.ietf.org/archive/id/draft-kazuho-ccwg-cuback-01.txt>
//!
//! Only congestion avoidance differs from CUBIC. Slow Start (with HyStart++
//! when enabled), PRR during recovery and the multiplicative decrease are the
//! same as for CUBIC.
//!
//! During congestion avoidance, cwnd grows by one MSS every time `D(cwnd)`
//! bytes have been acknowledged, as in Reno. `D(w)` is a pure function of the
//! congestion window and of the [`Epoch`] parameters, which are fixed when the
//! congestion avoidance stage begins.
//!
//! The window increase is limited as specified by
//! draft-ietf-ccwg-ratelimited-increase, following Section 3.3.1 of the Cuback
//! draft, rather than by suspending the increase while app limited.

use std::cmp;
use std::time::Duration;
use std::time::Instant;

use super::rtt::RttStats;
use super::Acked;
use super::Sent;

use super::reno;
use super::Congestion;
use super::CongestionControlOps;
use crate::recovery::MINIMUM_WINDOW_PACKETS;

pub(crate) static CUBACK: CongestionControlOps = CongestionControlOps {
    on_init,
    on_mtu_update,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    checkpoint,
    rollback,
    #[cfg(feature = "qlog")]
    state_str,
    debug_fmt,
};

/// Multiplicative decrease factor (Section 4.6 of RFC 9438).
const BETA_CUBIC: f64 = 0.7;

/// Cubic growth constant (Section 5 of RFC 9438).
const C: f64 = 0.4;

/// Reno-friendly additive increase factor (Section 4.3 of RFC 9438).
const ALPHA_CUBIC: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);

/// Lower bound on `D(w)`, in segments. Limits the increase to half of the
/// congestion window per round trip.
const MIN_INCREASE_THRESHOLD: f64 = 2.0;

/// Threshold for rolling back state, as percentage of lost packets relative to
/// cwnd.
const ROLLBACK_THRESHOLD_PERCENT: usize = 20;

/// Minimum threshold for rolling back state, as number of packets.
const MIN_ROLLBACK_THRESHOLD: usize = 2;

/// Lower bound on the smoothed RTT used to derive the bandwidth estimate, to
/// avoid dividing by zero.
const MIN_RTT_FOR_BANDWIDTH: Duration = Duration::from_micros(1);

/// The immutable parameters of a congestion avoidance stage (Section 3).
///
/// Window sizes are in segments and `bandwidth` in segments per second.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Epoch {
    /// W_max, possibly reduced by fast convergence.
    w_max: f64,

    /// The congestion window before the reduction. Determines the switch to
    /// `alpha_cubic = 1` in `A_reno` (Section 3.1).
    cwnd_prior: f64,

    /// The congestion window at the beginning of the stage.
    cwnd_epoch: f64,

    /// The rate at which the bottleneck delivers data.
    bandwidth: f64,
}

impl Epoch {
    fn new(w_max: f64, cwnd_prior: f64, cwnd_epoch: f64, bandwidth: f64) -> Self {
        // When the window is clamped to the minimum it can exceed the values
        // before the reduction. Keep the curves anchored at `cwnd_epoch`.
        Epoch {
            w_max: w_max.max(cwnd_epoch),
            cwnd_prior: cwnd_prior.max(cwnd_epoch),
            cwnd_epoch,
            bandwidth,
        }
    }

    /// Parameters for a congestion avoidance stage entered without a
    /// congestion event, e.g. on exiting HyStart++ Conservative Slow Start.
    fn without_reduction(cwnd: f64, smoothed_rtt: Duration) -> Self {
        Epoch::new(cwnd, cwnd, cwnd, bandwidth(cwnd, smoothed_rtt))
    }

    /// K(W_max, cwnd_epoch) = cbrt((W_max - cwnd_epoch) / C)
    fn k(&self) -> f64 {
        libm::cbrt((self.w_max - self.cwnd_epoch) / C)
    }

    /// A_cubic(w) = bandwidth * (K + cbrt((w - W_max) / C))
    fn a_cubic(&self, w: f64) -> f64 {
        self.bandwidth * (self.k() + libm::cbrt((w - self.w_max) / C))
    }

    /// The sum of the Reno-friendly thresholds from `cwnd_epoch` to `w`.
    fn a_reno(&self, w: f64) -> f64 {
        let ce = self.cwnd_epoch;
        let prior = self.cwnd_prior;

        if w <= prior {
            (w - ce) * (w + ce - 1.0) / (2.0 * ALPHA_CUBIC)
        } else {
            (prior - ce) * (prior + ce - 1.0) / (2.0 * ALPHA_CUBIC) +
                (w - prior) * (w + prior - 1.0) / 2.0
        }
    }

    /// A(w): the amount of data, in segments, that has to be acknowledged
    /// from the beginning of the stage for the window to reach `w`.
    pub(crate) fn a(&self, w: f64) -> f64 {
        f64::min(self.a_cubic(w), self.a_reno(w))
    }

    /// D(w): the amount of data, in segments, that has to be acknowledged to
    /// grow the window from `w` to `w + 1`.
    pub(crate) fn d(&self, w: f64) -> f64 {
        f64::max(MIN_INCREASE_THRESHOLD, self.a(w + 1.0) - self.a(w))
    }

    /// Whether Rate-Limited Increase permits growing the window from `w` to
    /// `w + 1`, given the largest FlightSize `max_fs` in segments (Section
    /// 3.3.1).
    pub(crate) fn increase_permitted(&self, w: f64, max_fs: f64) -> bool {
        w <= max_fs ||
            (w + 1.0 <= 1.5 * max_fs &&
                self.a(w + 1.0) - self.a(max_fs) <= max_fs)
    }
}

/// bandwidth = cwnd_prior / smoothed_rtt, in segments per second.
fn bandwidth(cwnd_prior: f64, smoothed_rtt: Duration) -> f64 {
    cwnd_prior / smoothed_rtt.max(MIN_RTT_FOR_BANDWIDTH).as_secs_f64()
}

/// Cuback state.
#[derive(Debug)]
pub struct State {
    /// Parameters of the current congestion avoidance stage. `None` until
    /// congestion avoidance is first entered.
    epoch: Option<Epoch>,

    /// Bytes that still need to be acknowledged before cwnd increases by one
    /// MSS. `None` when `D(cwnd)` must be evaluated again, which is equivalent
    /// to `pending = 0` in the draft.
    bytes_to_increase: Option<usize>,

    /// Largest FlightSize observed since cwnd was last reduced (maxFS in
    /// draft-ietf-ccwg-ratelimited-increase).
    max_fs: usize,

    /// Whether the heuristic detection of a spurious congestion event is
    /// pending, to be run on the first ACK after recovery.
    rollback_check_pending: bool,

    /// State preceding the last congestion event.
    prior: Option<PriorState>,
}

impl State {
    pub(crate) fn new(initial_congestion_window: usize) -> Self {
        State {
            epoch: None,
            bytes_to_increase: None,
            max_fs: initial_congestion_window,
            rollback_check_pending: false,
            prior: None,
        }
    }
}

/// Stores the state from before the last congestion event, so that it can be
/// restored if the event is determined to be spurious (Section 3.2).
#[derive(Debug)]
struct PriorState {
    congestion_window: usize,

    ssthresh: usize,

    epoch: Option<Epoch>,

    bytes_to_increase: Option<usize>,

    max_fs: usize,

    congestion_recovery_start_time: Option<Instant>,

    lost_count: usize,
}

fn on_init(_r: &mut Congestion) {}

fn on_mtu_update(r: &mut Congestion) {
    // cwnd may have been rescaled, evaluate D(cwnd) again.
    r.cuback_state.bytes_to_increase = None;
}

fn on_packet_sent(
    r: &mut Congestion, sent_bytes: usize, bytes_in_flight: usize, now: Instant,
) {
    reno::on_packet_sent(r, sent_bytes, bytes_in_flight, now);

    // There is no clock to adjust when coming out of quiescence: when no
    // ACKs arrive, the advance along the Cuback curves stops by itself.
    r.cuback_state.max_fs =
        cmp::max(r.cuback_state.max_fs, bytes_in_flight + sent_bytes);
}

fn on_packets_acked(
    r: &mut Congestion, bytes_in_flight: usize, packets: &mut Vec<Acked>,
    now: Instant, rtt_stats: &RttStats,
) {
    for pkt in packets.drain(..) {
        on_packet_acked(r, bytes_in_flight, &pkt, now, rtt_stats);
    }
}

fn on_packet_acked(
    r: &mut Congestion, bytes_in_flight: usize, packet: &Acked, now: Instant,
    rtt_stats: &RttStats,
) {
    if r.in_congestion_recovery(packet.time_sent) {
        r.prr.on_packet_acked(
            packet.size,
            bytes_in_flight,
            r.ssthresh.get(),
            r.max_datagram_size,
        );

        return;
    }

    let in_slow_start = r.congestion_window < r.ssthresh.get();

    // In congestion avoidance, Rate-Limited Increase bounds the growth of an
    // app limited sender instead.
    if in_slow_start && r.app_limited {
        return;
    }

    // Detecting spurious congestion events, once recovery is over.
    // <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
    //
    // If recovery ends after fewer than
    // `cwnd / mss * ROLLBACK_THRESHOLD_PERCENT` packets are lost, treat the
    // congestion event as spurious and restore the previous state.
    if std::mem::take(&mut r.cuback_state.rollback_check_pending) {
        let prior_lost_count = r
            .cuback_state
            .prior
            .as_ref()
            .map_or(r.lost_count, |p| p.lost_count);
        let new_lost = r.lost_count - prior_lost_count;

        let rollback_threshold = (r.congestion_window / r.max_datagram_size) *
            ROLLBACK_THRESHOLD_PERCENT /
            100;

        let rollback_threshold = rollback_threshold.max(MIN_ROLLBACK_THRESHOLD);

        if new_lost < rollback_threshold && rollback(r) {
            return;
        }
    }

    if in_slow_start {
        slow_start(r, packet, now, rtt_stats);
    } else {
        congestion_avoidance(r, packet.size, rtt_stats);
    }
}

fn slow_start(
    r: &mut Congestion, packet: &Acked, now: Instant, rtt_stats: &RttStats,
) {
    // In Slow start, bytes_acked_sl is used for counting acknowledged bytes.
    r.bytes_acked_sl += packet.size;

    if r.bytes_acked_sl >= r.max_datagram_size {
        if r.hystart.in_css() {
            r.congestion_window += r.hystart.css_cwnd_inc(r.max_datagram_size);
        } else {
            r.congestion_window += r.max_datagram_size;
        }

        r.bytes_acked_sl -= r.max_datagram_size;
    }

    if r.hystart.on_packet_acked(packet, rtt_stats.latest_rtt, now) {
        // Exit to congestion avoidance if CSS ends. As cwnd isn't reduced,
        // the parameters of the stage are established on the next ACK, with
        // W_max equal to cwnd_epoch (Section 3).
        r.ssthresh.update(r.congestion_window, true);

        r.cuback_state.epoch = None;
        r.cuback_state.bytes_to_increase = None;
    }
}

fn congestion_avoidance(
    r: &mut Congestion, mut bytes_acked: usize, rtt_stats: &RttStats,
) {
    let mss = r.max_datagram_size;
    let state = &mut r.cuback_state;

    let epoch = *state.epoch.get_or_insert_with(|| {
        Epoch::without_reduction(
            r.congestion_window as f64 / mss as f64,
            rtt_stats.smoothed_rtt,
        )
    });

    let max_fs = state.max_fs as f64 / mss as f64;

    loop {
        let w = r.congestion_window as f64 / mss as f64;

        let needed = state
            .bytes_to_increase
            .unwrap_or_else(|| (epoch.d(w) * mss as f64) as usize);

        if bytes_acked < needed {
            state.bytes_to_increase = Some(needed - bytes_acked);
            return;
        }

        if !epoch.increase_permitted(w, max_fs) {
            // Keep at most one increase worth of credit, which is used as
            // soon as the sender has more data in flight.
            state.bytes_to_increase = Some(0);
            return;
        }

        bytes_acked -= needed;
        r.congestion_window += mss;
        state.bytes_to_increase = None;
    }
}

fn congestion_event(
    r: &mut Congestion, bytes_in_flight: usize, _lost_bytes: usize,
    largest_lost_pkt: &Sent, now: Instant, rtt_stats: &RttStats,
) {
    // Start a new congestion event if packet was sent after the start of the
    // previous congestion recovery period.
    if r.in_congestion_recovery(largest_lost_pkt.time_sent) {
        return;
    }

    r.congestion_recovery_start_time = Some(now);

    let mss = r.max_datagram_size as f64;
    let cwnd_prior = r.congestion_window as f64 / mss;

    // Fast convergence (Section 3.1).
    let w_max = match r.cuback_state.epoch {
        Some(epoch) if cwnd_prior < epoch.w_max =>
            cwnd_prior * (1.0 + BETA_CUBIC) / 2.0,
        _ => cwnd_prior,
    };

    let ssthresh = (r.congestion_window as f64 * BETA_CUBIC) as usize;
    let ssthresh =
        cmp::max(ssthresh, r.max_datagram_size * MINIMUM_WINDOW_PACKETS);
    r.ssthresh.update(ssthresh, r.hystart.in_css());
    r.congestion_window = ssthresh;

    let state = &mut r.cuback_state;

    state.epoch = Some(Epoch::new(
        w_max,
        cwnd_prior,
        r.congestion_window as f64 / mss,
        bandwidth(cwnd_prior, rtt_stats.smoothed_rtt),
    ));
    state.bytes_to_increase = None;
    state.max_fs = 0;
    state.rollback_check_pending = true;

    if r.hystart.in_css() {
        r.hystart.congestion_event();
    }

    r.prr.congestion_event(bytes_in_flight);
}

fn checkpoint(r: &mut Congestion) {
    r.cuback_state.prior = Some(PriorState {
        congestion_window: r.congestion_window,
        ssthresh: r.ssthresh.get(),
        epoch: r.cuback_state.epoch,
        bytes_to_increase: r.cuback_state.bytes_to_increase,
        max_fs: r.cuback_state.max_fs,
        congestion_recovery_start_time: r.congestion_recovery_start_time,
        lost_count: r.lost_count,
    });
}

/// Reverts the last congestion event, restoring W_max, bandwidth and
/// cwnd_epoch along with cwnd and ssthresh (Section 3.2).
fn rollback(r: &mut Congestion) -> bool {
    let Some(prior) = r.cuback_state.prior.as_ref() else {
        return false;
    };

    // Don't go back to slow start.
    if prior.congestion_window < prior.ssthresh {
        return false;
    }

    if r.congestion_window >= prior.congestion_window {
        return false;
    }

    let Some(prior) = r.cuback_state.prior.take() else {
        return false;
    };

    r.congestion_window = prior.congestion_window;
    r.ssthresh.update(prior.ssthresh, false);
    r.congestion_recovery_start_time = prior.congestion_recovery_start_time;

    let state = &mut r.cuback_state;
    state.epoch = prior.epoch;
    state.bytes_to_increase = prior.bytes_to_increase;
    state.max_fs = prior.max_fs;
    state.rollback_check_pending = false;

    true
}

#[cfg(feature = "qlog")]
fn state_str(r: &Congestion, now: Instant) -> &'static str {
    reno::state_str(r, now)
}

fn debug_fmt(r: &Congestion, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let state = &r.cuback_state;

    write!(f, "cuback={{ ")?;

    if let Some(epoch) = &state.epoch {
        write!(
            f,
            "w_max={} cwnd_prior={} cwnd_epoch={} bandwidth={} ",
            epoch.w_max, epoch.cwnd_prior, epoch.cwnd_epoch, epoch.bandwidth
        )?;
    }

    write!(
        f,
        "bytes_to_increase={:?} max_fs={} }} ",
        state.bytes_to_increase, state.max_fs
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::CongestionControlAlgorithm;

    use crate::recovery::congestion::hystart;
    use crate::recovery::congestion::recovery::LegacyRecovery;
    use crate::recovery::congestion::test_sender::TestSender;
    use crate::recovery::RecoveryOps;

    const RTT: Duration = Duration::from_millis(100);

    fn test_sender() -> TestSender {
        TestSender::new(CongestionControlAlgorithm::Cuback, false)
    }

    fn hystart_test_sender() -> TestSender {
        TestSender::new(CongestionControlAlgorithm::Cuback, true)
    }

    fn assert_close(actual: f64, expected: f64, tolerance: f64) {
        assert!(
            (actual - expected).abs() <= tolerance,
            "actual={actual} expected={expected}"
        );
    }

    /// Appendix B, first vector: the Reno-friendly curve.
    #[test]
    fn test_vector_reno_friendly() {
        let epoch = Epoch::new(10.0, 10.0, 7.0, bandwidth(10.0, RTT));
        assert_close(epoch.bandwidth, 100.0, 1e-9);

        let vectors = [
            (7.0, 0.0, Some(13.2222)),
            (8.0, 13.2222, Some(15.1111)),
            (9.0, 28.3333, Some(17.0)),
            (10.0, 45.3333, Some(10.0)),
            (11.0, 55.3333, Some(11.0)),
            (12.0, 66.3333, None),
        ];

        for (w, a, d) in vectors {
            assert!(epoch.a_reno(w) <= epoch.a_cubic(w));
            assert_close(epoch.a(w), a, 1e-4);

            if let Some(d) = d {
                assert_close(epoch.d(w), d, 1e-4);
            }
        }
    }

    /// Appendix B, second vector: the cubic curve.
    #[test]
    fn test_vector_cubic() {
        let epoch = Epoch::new(1000.0, 1000.0, 600.0, bandwidth(1000.0, RTT));
        assert_close(epoch.bandwidth, 10_000.0, 1e-6);
        assert_close(epoch.k(), 10.0, 1e-9);

        let vectors = [
            (600.0, 0.0),
            (950.0, 50_000.0),
            (1000.0, 100_000.0),
            (1050.0, 150_000.0),
            (1400.0, 200_000.0),
        ];

        for (w, a) in vectors {
            assert!(epoch.a_cubic(w) <= epoch.a_reno(w));
            assert_close(epoch.a(w), a, 1e-6);
        }

        // A(W_max) divided by bandwidth recovers K.
        assert_close(epoch.a(1000.0) / epoch.bandwidth, epoch.k(), 1e-9);
    }

    #[test]
    fn increase_threshold_lower_bound() {
        // An understated bandwidth makes A_cubic small, D(w) is bounded to two
        // segments.
        let epoch = Epoch::new(1000.0, 1000.0, 600.0, 1.0);

        for w in [600.0, 900.0, 1000.0, 1100.0] {
            assert_eq!(epoch.d(w), MIN_INCREASE_THRESHOLD);
        }
    }

    #[test]
    fn without_reduction_has_no_concave_region() {
        let epoch = Epoch::without_reduction(100.0, RTT);

        assert_eq!(epoch.w_max, epoch.cwnd_epoch);
        assert_eq!(epoch.k(), 0.0);
        assert_eq!(epoch.a(100.0), 0.0);
        // Above W_max, alpha_cubic is replaced by one.
        assert_close(epoch.a_reno(101.0), 100.0, 1e-9);
    }

    #[test]
    fn epoch_is_anchored_at_cwnd_epoch() {
        // cwnd clamped to the minimum window exceeds the window before the
        // reduction.
        let epoch = Epoch::new(1.4, 1.0, 2.0, 10.0);

        assert_eq!(epoch.w_max, 2.0);
        assert_eq!(epoch.cwnd_prior, 2.0);
        assert_eq!(epoch.a(2.0), 0.0);
        assert!(epoch.d(2.0) >= MIN_INCREASE_THRESHOLD);
    }

    #[test]
    fn rate_limited_increase_permitted() {
        let epoch = Epoch::new(10.0, 10.0, 7.0, 100.0);

        // cwnd can always reach maxFS + 1.
        assert!(epoch.increase_permitted(7.0, 7.0));
        assert!(epoch.increase_permitted(9.0, 40.0));

        // A(9) - A(7) = 28.3 > maxFS.
        assert!(!epoch.increase_permitted(8.0, 7.0));

        // w + 1 <= 1.5 * maxFS doesn't hold.
        assert!(!epoch.increase_permitted(7.0, 4.0));
        assert!(!epoch.increase_permitted(61.0, 40.0));

        // A(41.5) - A(40) = 7.0 <= maxFS, on the cubic curve.
        assert!(epoch.increase_permitted(40.5, 40.0));
        assert_close(epoch.a(41.5) - epoch.a(40.0), 7.0, 0.1);
    }

    #[test]
    fn cuback_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Cuback);

        let r = LegacyRecovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight(), 0);
    }

    #[test]
    fn cuback_slow_start() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.congestion_window;

        sender.ack_n_packets(3, size);

        assert_eq!(sender.congestion_window, cwnd_prev + 3 * size);
        assert_eq!(sender.cuback_state.epoch, None);
    }

    #[test]
    fn cuback_slow_start_app_limited() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        sender.send_packet(size);

        let cwnd_prev = sender.congestion_window;

        sender.ack_n_packets(1, size);

        assert_eq!(sender.congestion_window, cwnd_prev);
    }

    /// Sends a window of packets, then loses one of them in slow start.
    /// Returns cwnd before the loss.
    fn enter_congestion_avoidance(sender: &mut TestSender) -> usize {
        let size = sender.max_datagram_size;

        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let prev_cwnd = sender.congestion_window;

        sender.update_rtt(RTT);
        sender.advance_time(RTT);
        sender.lose_n_packets(1, size, None);

        prev_cwnd
    }

    #[test]
    fn cuback_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = enter_congestion_avoidance(&mut sender);

        assert_eq!(
            sender.congestion_window,
            (prev_cwnd as f64 * BETA_CUBIC) as usize
        );
        assert_eq!(sender.ssthresh.get(), sender.congestion_window);

        // This is the first vector of Appendix B.
        let epoch = sender.cuback_state.epoch.unwrap();
        let prev_cwnd = (prev_cwnd / size) as f64;
        assert_eq!(epoch.w_max, prev_cwnd);
        assert_eq!(epoch.cwnd_prior, prev_cwnd);
        assert_close(epoch.cwnd_epoch, prev_cwnd * BETA_CUBIC, 1e-9);
        assert_close(epoch.bandwidth, prev_cwnd / RTT.as_secs_f64(), 1e-9);
        assert_eq!(sender.cuback_state.max_fs, 0);
    }

    #[test]
    fn cuback_congestion_avoidance() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        enter_congestion_avoidance(&mut sender);

        let cur_cwnd = sender.congestion_window;
        assert_eq!(cur_cwnd, 7 * size);

        // Packets sent before the loss event don't increase cwnd.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);
        assert_eq!(sender.congestion_window, cur_cwnd);

        sender.advance_time(RTT);
        for _ in 0..40 {
            sender.send_packet(size);
        }
        sender.advance_time(RTT);

        // D(7) = 13.2222 segments.
        sender.ack_n_packets(13, size);
        assert_eq!(sender.congestion_window, cur_cwnd);
        sender.ack_n_packets(1, size);
        assert_eq!(sender.congestion_window, cur_cwnd + size);

        // D(8) = 15.1111 segments, 0.7778 of which were already acked.
        sender.ack_n_packets(14, size);
        assert_eq!(sender.congestion_window, cur_cwnd + size);
        sender.ack_n_packets(1, size);
        assert_eq!(sender.congestion_window, cur_cwnd + 2 * size);
    }

    #[test]
    fn cuback_congestion_avoidance_rate_limited() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        enter_congestion_avoidance(&mut sender);

        let cur_cwnd = sender.congestion_window;

        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);
        sender.advance_time(RTT);

        // An app limited sender with at most 2 packets in flight doesn't grow
        // cwnd past 3 segments.
        for _ in 0..50 {
            sender.send_packet(size);
            sender.send_packet(size);
            sender.advance_time(RTT);
            sender.ack_n_packets(2, size);
        }

        assert_eq!(sender.cuback_state.max_fs, 2 * size);
        assert_eq!(sender.congestion_window, cur_cwnd);
        assert_eq!(sender.cuback_state.bytes_to_increase, Some(0));

        // Once the sender fills cwnd, the banked increase is applied, but only
        // one.
        for _ in 0..cur_cwnd / size {
            sender.send_packet(size);
        }

        sender.advance_time(RTT);
        sender.ack_n_packets(1, size);
        assert_eq!(sender.congestion_window, cur_cwnd + size);

        sender.ack_n_packets(1, size);
        assert_eq!(sender.congestion_window, cur_cwnd + size);
    }

    #[test]
    fn cuback_fast_convergence() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        enter_congestion_avoidance(&mut sender);

        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);
        sender.advance_time(RTT);
        for _ in 0..20 {
            sender.send_packet(size);
        }
        sender.advance_time(RTT);
        sender.ack_n_packets(14, size);

        let prev_cwnd = sender.congestion_window;
        assert_eq!(prev_cwnd, 8 * size);

        // Second congestion event, cwnd hasn't recovered to W_max.
        sender.lose_n_packets(1, size, None);

        let epoch = sender.cuback_state.epoch.unwrap();
        assert_close(epoch.w_max, 8.0 * (1.0 + BETA_CUBIC) / 2.0, 1e-9);
        // The switch to alpha_cubic = 1 is keyed to cwnd_prior.
        assert_eq!(epoch.cwnd_prior, 8.0);
        assert_close(epoch.cwnd_epoch, 8.0 * BETA_CUBIC, 1e-9);
    }

    #[test]
    fn cuback_spurious_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        enter_congestion_avoidance(&mut sender);

        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);
        sender.advance_time(RTT);
        for _ in 0..20 {
            sender.send_packet(size);
        }
        sender.advance_time(RTT);
        sender.ack_n_packets(14, size);

        let prev_cwnd = sender.congestion_window;
        let prev_epoch = sender.cuback_state.epoch;
        let prev_bytes_to_increase = sender.cuback_state.bytes_to_increase;

        sender.lose_n_packets(1, size, None);
        assert!(sender.congestion_window < prev_cwnd);
        assert_ne!(sender.cuback_state.epoch, prev_epoch);

        // Exit recovery with a single loss: the event is spurious.
        sender.advance_time(RTT);
        sender.send_packet(size);
        sender.advance_time(RTT);
        let acked = Acked {
            pkt_num: 0,
            time_sent: sender.time,
            size,
            delivered: 0,
            delivered_time: sender.time,
            first_sent_time: sender.time,
            is_app_limited: false,
            rtt: Duration::ZERO,
        };
        let now = sender.time;
        sender.inject_ack(acked, now);

        assert_eq!(sender.congestion_window, prev_cwnd);
        assert_eq!(sender.ssthresh.get(), 7 * size);
        assert_eq!(sender.cuback_state.epoch, prev_epoch);
        assert_eq!(
            sender.cuback_state.bytes_to_increase,
            prev_bytes_to_increase
        );
        assert!(sender.cuback_state.prior.is_none());
    }

    #[test]
    fn cuback_no_rollback_to_slow_start() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        enter_congestion_avoidance(&mut sender);
        let cur_cwnd = sender.congestion_window;

        assert!(!rollback(&mut sender));
        assert_eq!(sender.congestion_window, cur_cwnd);

        // Exit recovery, the heuristic doesn't revert to slow start either.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1, size);
        sender.advance_time(RTT);
        sender.send_packet(size);
        sender.send_packet(size);
        sender.advance_time(RTT);
        sender.ack_n_packets(1, size);

        assert_eq!(sender.congestion_window, cur_cwnd);
        assert!(!sender.cuback_state.rollback_check_pending);
    }

    #[test]
    fn cuback_hystart_css_to_ca() {
        let mut sender = hystart_test_sender();
        let size = sender.max_datagram_size;

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;

        let rtt_1st = Duration::from_millis(50);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        sender.advance_time(rtt_1st);
        sender.update_rtt(rtt_1st);
        sender.ack_n_packets(n_rtt_sample, size);

        assert!(sender.hystart.css_start_time().is_none());

        // 2nd round, increasing RTT to enter CSS.
        let mut rtt_2nd = Duration::from_millis(100);
        sender.advance_time(rtt_2nd);
        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        for _ in 0..n_rtt_sample {
            sender.update_rtt(rtt_2nd);
            sender.ack_n_packets(1, size);
            rtt_2nd += rtt_2nd.saturating_add(Duration::from_millis(4));
        }

        assert!(sender.hystart.css_start_time().is_some());

        // Run CSS_ROUNDS in CSS, to exit to congestion avoidance.
        let rtt_css = Duration::from_millis(100);
        sender.advance_time(rtt_css);

        for _ in 0..hystart::CSS_ROUNDS {
            let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
            sender.hystart.start_round(next_rnd);
            for _ in 0..n_rtt_sample {
                sender.send_packet(size);
            }
            sender.update_app_limited(false);

            sender.update_rtt(rtt_css);
            sender.ack_n_packets(n_rtt_sample, size);
        }

        // Now in congestion avoidance, without a reduction. The ACKs that
        // followed the exit from CSS didn't grow cwnd yet.
        let cwnd = sender.congestion_window();
        assert_eq!(cwnd, sender.ssthresh.get());

        // The stage parameters were established on entering congestion
        // avoidance, W_max equals cwnd_epoch and K is zero.
        let epoch = sender.cuback_state.epoch.unwrap();
        let w = cwnd as f64 / size as f64;
        assert_eq!(epoch.cwnd_epoch, w);
        assert_eq!(epoch.w_max, w);
        assert_eq!(epoch.cwnd_prior, w);
        assert_eq!(epoch.k(), 0.0);
        assert_close(
            epoch.bandwidth,
            w / sender.rtt_stats().smoothed_rtt.as_secs_f64(),
            1e-9,
        );
    }
}
