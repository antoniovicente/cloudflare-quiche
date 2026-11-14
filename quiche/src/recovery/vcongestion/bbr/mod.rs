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

//! BBR (version 3) congestion control.
//!
//! This is an implementation of the algorithm specified in
//! draft-ietf-ccwg-bbr-07, "BBR Congestion Control":
//! <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.txt>
//!
//! The code follows the structure and naming of the draft's pseudocode, and
//! each function references the section that specifies it. Variables named
//! `BBR.*` in the draft are fields of [`Bbr`]; the `C.*` connection state used
//! by the algorithm (C.cwnd, C.pacing_rate, C.send_quantum) is also owned by
//! [`Bbr`], while C.delivered, C.lost and C.app_limited live in the delivery
//! rate sampler (draft Section 4.1) and are passed in by the caller.
//!
//! Units: volumes of data are bytes, rates use [`Bandwidth`], and times use
//! [`Instant`]/[`Duration`] (draft Section 2).
//!
//! Where QUIC differs from the TCP-centric wording of the draft:
//!
//! * C.has_selective_acks is always true for QUIC (draft Section 2.2).
//! * C.SMSS is the QUIC maximum datagram size (draft Section 2.2, RFC 9000
//!   Section 14).
//! * "Fast Recovery" maps to the QUIC recovery period (RFC 9002 Section 7.3.2)
//!   and "RTO" maps to persistent congestion (RFC 9002 Section 7.6); see
//!   `vcongestion::recovery`.
//! * The offload budget follows draft Section 5.5.8.2 (QUIC Offload Budget).

use std::time::Duration;
use std::time::Instant;

use crate::recovery::Bandwidth;

use super::delivery_rate::DeliveryRateSampler;
use super::delivery_rate::PacketState;
use super::delivery_rate::RateSample;
use super::windowed_filter::WindowedMaxFilter;

/// Sentinel for an infinite volume of data ("Infinity" in the draft).
const INFINITE_BYTES: u64 = u64::MAX;

/// BBR.StartupPacingGain: 4 * ln(2) ~= 2.77 (draft Section 2.5).
const STARTUP_PACING_GAIN: f64 = 2.77;

/// BBR.DrainPacingGain (draft Section 2.5).
const DRAIN_PACING_GAIN: f64 = 0.5;

/// BBR.PacingMarginPercent (draft Section 2.5).
const PACING_MARGIN_PERCENT: f64 = 1.0;

/// BBR.DefaultCwndGain (draft Section 2.6).
const DEFAULT_CWND_GAIN: f64 = 2.0;

/// ProbeBW_DOWN pacing gain (draft Sections 5.3.3.1 and 5.6.1).
const PROBE_BW_DOWN_PACING_GAIN: f64 = 0.90;

/// ProbeBW_CRUISE pacing gain (draft Sections 5.3.3.2 and 5.6.1).
const PROBE_BW_CRUISE_PACING_GAIN: f64 = 1.0;

/// ProbeBW_REFILL pacing gain (draft Sections 5.3.3.3 and 5.6.1).
const PROBE_BW_REFILL_PACING_GAIN: f64 = 1.0;

/// ProbeBW_UP pacing gain (draft Sections 5.3.3.5 and 5.6.1).
const PROBE_BW_UP_PACING_GAIN: f64 = 1.25;

/// ProbeBW_UP cwnd gain (draft Sections 5.3.3.5 and 5.6.1).
const PROBE_BW_UP_CWND_GAIN: f64 = 2.25;

/// ProbeRTT pacing gain (draft Section 5.3.4.3, EnterProbeRTT()).
const PROBE_RTT_PACING_GAIN: f64 = 1.0;

/// BBR.LossThresh (draft Section 2.8).
const LOSS_THRESH: f64 = 0.02;

/// BBR.Beta (draft Section 2.8).
const BETA: f64 = 0.7;

/// BBR.Headroom (draft Section 2.8).
const HEADROOM: f64 = 0.15;

/// BBR.MinPipeCwnd, in units of C.SMSS (draft Section 2.8).
const MIN_PIPE_CWND_PACKETS: u64 = 4;

/// BBR.MaxBwFilterLen, in ProbeBW cycles (draft Section 2.11).
const MAX_BW_FILTER_LEN: u64 = 2;

/// BBR.ExtraAckedFilterLen, in round trips (draft Section 2.12).
const EXTRA_ACKED_FILTER_LEN: u64 = 10;

/// BBR.StartupFullLossCnt (draft Section 2.13).
const STARTUP_FULL_LOSS_CNT: u32 = 6;

/// Growth factor that counts as "still growing" when looking for a bandwidth
/// plateau (draft Section 5.3.1.2, CheckFullBWReached()).
const FULL_BW_GROWTH: f64 = 1.25;

/// Number of rounds without growth that indicate a bandwidth plateau (draft
/// Section 5.3.1.2, CheckFullBWReached()).
const FULL_BW_COUNT: u32 = 3;

/// Maximum number of rounds in Drain (draft Section 5.3.2, CheckDrainDone()).
const DRAIN_MAX_ROUNDS: u64 = 3;

/// BBR.MinRTTFilterLen (draft Section 2.16.1).
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);

/// BBR.ProbeRTTCwndGain (draft Section 2.16.2).
const PROBE_RTT_CWND_GAIN: f64 = 0.5;

/// BBR.ProbeRTTDuration (draft Section 2.16.2).
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// Upper bound on BBR.bw_probe_up_rounds (draft Section 5.3.3.9,
/// RaiseInflightLongtermSlope()).
const MAX_BW_PROBE_UP_ROUNDS: u32 = 30;

/// Upper bound of the Reno-coexistence time scale, in round trips (draft
/// Sections 5.3.3.8.2 and 5.3.3.9, IsRenoCoexistenceProbeTime()).
const RENO_COEXISTENCE_MAX_ROUNDS: u64 = 63;

/// Minimum wall clock time to wait between bandwidth probes (draft Sections
/// 5.3.3.8.2 and 5.3.3.9, PickProbeWait()).
const BW_PROBE_WAIT_BASE: Duration = Duration::from_secs(2);

/// Range of the random extra wall clock wait between bandwidth probes (draft
/// Section 5.3.3.9, PickProbeWait()).
const BW_PROBE_WAIT_RAND: Duration = Duration::from_secs(1);

/// Send quantum duration at the pacing rate (draft Section 5.6.3).
const SEND_QUANTUM_DURATION: Duration = Duration::from_millis(1);

/// Maximum send quantum (draft Section 5.6.3).
const MAX_SEND_QUANTUM: u64 = 64 * 1024;

/// Pacing rate denominator used before the first RTT sample (draft Section
/// 5.6.2, InitPacingRate()).
const DEFAULT_INIT_PACING_RTT: Duration = Duration::from_millis(1);

/// The BBR state machine states (draft Section 5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRtt,
}

impl State {
    /// `IsInAProbeBWState()` (draft Section 5.3.3.9).
    fn is_probe_bw(self) -> bool {
        match self {
            State::ProbeBwDown |
            State::ProbeBwCruise |
            State::ProbeBwRefill |
            State::ProbeBwUp => true,

            State::Startup | State::Drain | State::ProbeRtt => false,
        }
    }

    /// `IsProbingBW()` (draft Section 5.3.3.9).
    fn is_probing_bw(self) -> bool {
        match self {
            State::Startup | State::ProbeBwRefill | State::ProbeBwUp => true,

            State::Drain |
            State::ProbeBwDown |
            State::ProbeBwCruise |
            State::ProbeRtt => false,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            State::Startup => "vbbr_startup",
            State::Drain => "vbbr_drain",
            State::ProbeBwDown => "vbbr_probe_bw_down",
            State::ProbeBwCruise => "vbbr_probe_bw_cruise",
            State::ProbeBwRefill => "vbbr_probe_bw_refill",
            State::ProbeBwUp => "vbbr_probe_bw_up",
            State::ProbeRtt => "vbbr_probe_rtt",
        }
    }
}

/// Why BBR first left Startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupExitCause {
    /// BBR.max_bw plateaued (draft Section 5.3.1.2).
    BandwidthPlateau,

    /// Excessive packet loss (draft Section 5.3.1.3).
    Loss,
}

/// BBRv3 congestion controller state (draft Section 2).
#[derive(Debug)]
pub(crate) struct Bbr {
    // Transport connection state (draft Sections 2.2 and 2.4).
    /// C.SMSS.
    smss: u64,

    /// C.InitialCwnd, in packets.
    initial_cwnd_packets: u64,

    /// C.cwnd.
    cwnd: u64,

    /// C.pacing_rate.
    pacing_rate: Bandwidth,

    /// C.send_quantum.
    send_quantum: u64,

    /// C.delivered as of the most recent event, used by StartRound().
    delivered: u64,

    /// Whether C.pacing_rate has been initialized from a C.srtt sample (draft
    /// Section 5.6.2, InitPacingRate()).
    pacing_rate_from_srtt: bool,

    /// Whether the cwnd was fully used during the current round trip.
    cwnd_limited_this_round: bool,

    /// Whether the cwnd was fully used during the previous round trip.
    cwnd_limited_prev_round: bool,

    /// Whether the connection is in loss recovery (InLossRecovery()).
    in_loss_recovery: bool,

    // Pacing and cwnd gains (draft Sections 2.5 and 2.6).
    /// BBR.pacing_gain.
    pacing_gain: f64,

    /// BBR.cwnd_gain.
    cwnd_gain: f64,

    // General algorithm state (draft Section 2.7).
    /// BBR.state.
    state: State,

    /// BBR.round_count.
    round_count: u64,

    /// BBR.round_start.
    round_start: bool,

    /// BBR.next_round_delivered.
    next_round_delivered: u64,

    /// BBR.idle_restart.
    idle_restart: bool,

    /// BBR.drain_start_round.
    drain_start_round: u64,

    // Data rate model (draft Section 2.9.1).
    /// BBR.max_bw.
    max_bw: Bandwidth,

    /// BBR.bw_shortterm.
    bw_shortterm: Bandwidth,

    /// BBR.bw.
    bw: Bandwidth,

    // Data volume model (draft Section 2.9.2).
    /// BBR.min_rtt. `None` stands for Infinity.
    min_rtt: Option<Duration>,

    /// BBR.bdp.
    bdp: u64,

    /// BBR.extra_acked.
    extra_acked: u64,

    /// BBR.offload_budget.
    offload_budget: u64,

    /// BBR.max_inflight.
    max_inflight: u64,

    /// BBR.inflight_longterm.
    inflight_longterm: u64,

    /// BBR.inflight_shortterm.
    inflight_shortterm: u64,

    // Congestion signals (draft Section 2.10).
    /// BBR.bw_latest.
    bw_latest: Bandwidth,

    /// BBR.inflight_latest.
    inflight_latest: u64,

    // BBR.max_bw estimation (draft Section 2.11).
    /// BBR.max_bw_filter.
    max_bw_filter: WindowedMaxFilter<Bandwidth>,

    /// BBR.cycle_count.
    cycle_count: u64,

    // BBR.extra_acked estimation (draft Section 2.12).
    /// BBR.extra_acked_interval_start.
    extra_acked_interval_start: Instant,

    /// BBR.extra_acked_delivered.
    extra_acked_delivered: u64,

    /// BBR.extra_acked_filter.
    extra_acked_filter: WindowedMaxFilter<u64>,

    // Startup (draft Section 2.13).
    /// BBR.full_bw_reached.
    full_bw_reached: bool,

    /// BBR.full_bw_now.
    full_bw_now: bool,

    /// BBR.full_bw.
    full_bw: Bandwidth,

    /// BBR.full_bw_count.
    full_bw_count: u32,

    /// BBR.loss_events_in_round.
    loss_events_in_round: u32,

    /// BBR.loss_round_delivered (draft Section 5.5.10.3).
    loss_round_delivered: u64,

    /// BBR.loss_round_start (draft Section 5.5.10.3).
    loss_round_start: bool,

    // ProbeBW (draft Section 2.14).
    /// BBR.is_bw_probe_stopping.
    is_bw_probe_stopping: bool,

    /// BBR.check_probe_loss.
    check_probe_loss: bool,

    /// BBR.is_loss_in_round.
    is_loss_in_round: bool,

    /// BBR.bw_probe_up_acked.
    bw_probe_up_acked: u64,

    /// BBR.probe_up_acked_per_inc.
    probe_up_acked_per_inc: u64,

    /// BBR.bw_probe_up_rounds.
    bw_probe_up_rounds: u32,

    /// BBR.rounds_since_probe_up.
    rounds_since_probe_up: u64,

    /// BBR.bw_probe_wait.
    bw_probe_wait: Duration,

    /// BBR.cycle_stamp.
    cycle_stamp: Instant,

    /// BBR.prev_probe_too_high.
    prev_probe_too_high: bool,

    /// BBR.prev_probe_precautionary.
    prev_probe_precautionary: bool,

    // Undo state (draft Section 2.15).
    /// BBR.undo_state. `None` stands for the draft's None.
    undo_state: Option<State>,

    /// BBR.undo_bw_shortterm.
    undo_bw_shortterm: Bandwidth,

    /// BBR.undo_inflight_shortterm.
    undo_inflight_shortterm: u64,

    /// BBR.undo_inflight_longterm.
    undo_inflight_longterm: u64,

    // ProbeRTT and min_rtt (draft Section 2.16).
    /// BBR.min_rtt_stamp.
    min_rtt_stamp: Instant,

    /// BBR.min_rtt_expired.
    min_rtt_expired: bool,

    /// BBR.probe_rtt_done_stamp. `None` stands for 0.
    probe_rtt_done_stamp: Option<Instant>,

    /// BBR.probe_rtt_round_done.
    probe_rtt_round_done: bool,

    /// BBR.probe_rtt_cwnd.
    probe_rtt_cwnd: u64,

    /// BBR.prior_cwnd (draft Section 5.6.4.4).
    prior_cwnd: u64,

    /// Why BBR first exited Startup, for statistics.
    startup_exit: Option<StartupExitCause>,
}

impl Bbr {
    /// `OnInit()` (draft Section 5.2.1).
    ///
    /// No RTT sample is available at connection initialization, so C.srtt is
    /// treated as unset.
    pub(crate) fn new(
        initial_cwnd_packets: usize, smss: usize, now: Instant,
    ) -> Self {
        let smss = smss as u64;
        let initial_cwnd_packets = initial_cwnd_packets as u64;

        let mut bbr = Bbr {
            smss,
            initial_cwnd_packets,
            // Draft Section 5.6.4.1: use the transport's initial window.
            cwnd: initial_cwnd_packets * smss,
            pacing_rate: Bandwidth::zero(),
            send_quantum: 2 * smss,
            delivered: 0,
            pacing_rate_from_srtt: false,
            cwnd_limited_this_round: false,
            cwnd_limited_prev_round: false,
            in_loss_recovery: false,

            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: DEFAULT_CWND_GAIN,

            state: State::Startup,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            idle_restart: false,
            drain_start_round: 0,

            max_bw: Bandwidth::zero(),
            bw_shortterm: Bandwidth::infinite(),
            bw: Bandwidth::zero(),

            min_rtt: None,
            bdp: 0,
            extra_acked: 0,
            offload_budget: 0,
            max_inflight: 0,
            inflight_longterm: INFINITE_BYTES,
            inflight_shortterm: INFINITE_BYTES,

            bw_latest: Bandwidth::zero(),
            inflight_latest: 0,

            // InitWindowedMaxFilter(filter=BBR.max_bw_filter, value=0, time=0)
            max_bw_filter: WindowedMaxFilter::new(Bandwidth::zero(), 0),
            cycle_count: 0,

            extra_acked_interval_start: now,
            extra_acked_delivered: 0,
            extra_acked_filter: WindowedMaxFilter::new(0, 0),

            full_bw_reached: false,
            full_bw_now: false,
            full_bw: Bandwidth::zero(),
            full_bw_count: 0,
            loss_events_in_round: 0,
            loss_round_delivered: 0,
            loss_round_start: false,

            is_bw_probe_stopping: false,
            check_probe_loss: false,
            is_loss_in_round: false,
            bw_probe_up_acked: 0,
            probe_up_acked_per_inc: INFINITE_BYTES,
            bw_probe_up_rounds: 0,
            rounds_since_probe_up: 0,
            bw_probe_wait: Duration::ZERO,
            cycle_stamp: now,
            prev_probe_too_high: false,
            prev_probe_precautionary: false,

            undo_state: None,
            undo_bw_shortterm: Bandwidth::zero(),
            undo_inflight_shortterm: 0,
            undo_inflight_longterm: 0,

            min_rtt_stamp: now,
            min_rtt_expired: false,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            probe_rtt_cwnd: INFINITE_BYTES,
            prior_cwnd: 0,

            startup_exit: None,
        };

        bbr.reset_congestion_signals();
        bbr.reset_short_term_model();
        bbr.init_round_counting();
        bbr.reset_full_bw();
        bbr.init_pacing_rate(None);
        bbr.set_send_quantum();
        bbr.enter_startup();

        bbr
    }

    // Accessors.

    /// C.cwnd.
    pub(crate) fn cwnd(&self) -> u64 {
        self.cwnd
    }

    /// C.pacing_rate.
    pub(crate) fn pacing_rate(&self) -> Bandwidth {
        self.pacing_rate
    }

    /// C.send_quantum.
    pub(crate) fn send_quantum(&self) -> u64 {
        self.send_quantum
    }

    /// BBR.state.
    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// BBR.max_bw.
    pub(crate) fn max_bw(&self) -> Bandwidth {
        self.max_bw
    }

    /// BBR.bw.
    pub(crate) fn bw(&self) -> Bandwidth {
        self.bw
    }

    /// InLossRecovery().
    #[cfg(test)]
    pub(crate) fn in_loss_recovery(&self) -> bool {
        self.in_loss_recovery
    }

    /// Why BBR first exited Startup, if it has.
    pub(crate) fn startup_exit(&self) -> Option<StartupExitCause> {
        self.startup_exit
    }

    /// C.is_cwnd_limited: whether the connection fully utilized C.cwnd at any
    /// point in the last packet-timed round trip (draft Section 2.2).
    ///
    /// This is tracked over the current and the previous round trip so that
    /// the signal covers a full round trip at any point in time.
    pub(crate) fn is_cwnd_limited(&self) -> bool {
        self.cwnd_limited_this_round || self.cwnd_limited_prev_round
    }

    /// BBR.MinPipeCwnd (draft Section 2.8).
    fn min_pipe_cwnd(&self) -> u64 {
        MIN_PIPE_CWND_PACKETS * self.smss
    }

    /// C.InitialCwnd in bytes.
    fn initial_cwnd(&self) -> u64 {
        self.initial_cwnd_packets * self.smss
    }

    // Transport events.

    /// Updates C.SMSS, e.g. after path MTU discovery.
    ///
    /// RFC 9002 Section 7.2: if the maximum datagram size changes the initial
    /// congestion window SHOULD be recalculated with the new size; before any
    /// data has been delivered the cwnd still is the initial window, so it is
    /// recalculated as well.
    pub(crate) fn update_mss(&mut self, smss: usize) {
        self.smss = smss as u64;

        if self.delivered == 0 {
            self.cwnd = self.initial_cwnd();
        }
    }

    /// `OnTransmit()` (draft Section 5.2.2), called before sending a packet.
    ///
    /// `inflight` is C.inflight before this packet, and `app_limited` is
    /// whether C.app_limited is non-zero.
    pub(crate) fn on_transmit(
        &mut self, inflight: u64, app_limited: bool, now: Instant,
    ) {
        self.handle_restart_from_idle(inflight, app_limited, now);
    }

    /// Called after a congestion controlled packet is sent, with C.inflight
    /// including the packet. Tracks C.is_cwnd_limited (draft Section 2.2):
    /// the cwnd is considered fully used when it can't fit another C.SMSS.
    pub(crate) fn on_packet_sent(&mut self, inflight: u64) {
        if inflight.saturating_add(self.smss) > self.cwnd {
            self.cwnd_limited_this_round = true;
        }
    }

    /// `UpdateOnACK()` (draft Section 5.2.3).
    ///
    /// Must be called once per ACK that delivered data, after the delivery
    /// rate sampler processed the ACK and the losses it revealed, i.e. after
    /// `GenerateRateSample()`. `inflight` is C.inflight after the ACK, and
    /// `srtt` is C.srtt if an RTT sample is available.
    pub(crate) fn on_ack(
        &mut self, rs: &RateSample, sampler: &mut DeliveryRateSampler,
        inflight: u64, srtt: Option<Duration>, now: Instant,
    ) {
        self.delivered = sampler.delivered();

        // Draft Section 5.6.2: with no bw estimate yet, the initial pacing
        // rate is based on "the initial C.srtt after the first non-zero RTT
        // sample".
        if !self.pacing_rate_from_srtt && self.max_bw == Bandwidth::zero() {
            if let Some(srtt) = srtt.filter(|s| !s.is_zero()) {
                self.init_pacing_rate(Some(srtt));
                self.pacing_rate_from_srtt = true;
            }
        }

        self.update_model_and_state(rs, sampler, inflight, now);
        self.update_control_parameters(rs);
    }

    /// `HandleLostPacket(P)` (draft Sections 5.2.4 and 5.5.10.2), called for
    /// each packet newly declared lost, after C.lost was updated to include
    /// it.
    pub(crate) fn on_packet_lost(
        &mut self, p: &PacketState, sampler: &DeliveryRateSampler, now: Instant,
    ) {
        self.delivered = sampler.delivered();

        self.note_loss();

        if !self.check_probe_loss {
            // Not a packet sent while probing bandwidth.
            return;
        }

        // The draft temporarily overwrites RS fields here; use locals instead
        // to avoid clobbering the rate sample of an ACK being processed.
        let tx_in_flight = p.tx_in_flight;
        let lost = sampler.lost().saturating_sub(p.lost);
        let is_app_limited = p.is_app_limited;

        if is_inflight_too_high(lost, tx_in_flight) {
            let tx_in_flight = inflight_at_loss(p.size, tx_in_flight, lost);
            self.handle_inflight_too_high(is_app_limited, tx_in_flight, now);
        }
    }

    /// `OnEnterFastRecovery()` (draft Section 5.6.4.4).
    ///
    /// For QUIC this is the start of a recovery period (RFC 9002 Section
    /// 7.3.2). Must be called before `on_packet_lost()` for the losses that
    /// started the recovery period.
    pub(crate) fn on_enter_fast_recovery(&mut self) {
        self.save_cwnd();
        self.save_state_upon_loss();
        self.in_loss_recovery = true;
    }

    /// `OnEnterRTO()` (draft Section 5.6.4.4).
    ///
    /// QUIC has no retransmission timeout; the closest equivalent is
    /// persistent congestion (RFC 9002 Section 7.6), after which the cwnd is
    /// reduced to allow 1 C.SMSS to be transmitted.
    pub(crate) fn on_enter_rto(&mut self, inflight: u64) {
        self.save_cwnd();
        self.save_state_upon_loss();
        self.in_loss_recovery = true;
        self.cwnd = inflight + self.smss;
    }

    /// Exiting loss recovery after repairing all losses (draft Section
    /// 5.6.4.4): RestoreCwnd(). For QUIC, recovery ends when a packet sent
    /// during the recovery period is acknowledged (RFC 9002 Section 7.3.2).
    pub(crate) fn on_exit_loss_recovery(&mut self) {
        self.in_loss_recovery = false;
        self.restore_cwnd();
    }

    /// `HandleSpuriousLossDetection()` (draft Sections 5.2.5 and 5.5.11.2).
    /// This also exits loss recovery (draft Section 5.6.4.4).
    pub(crate) fn on_spurious_loss_detection(&mut self) {
        self.in_loss_recovery = false;

        self.restore_cwnd();
        self.is_loss_in_round = false;
        self.loss_events_in_round = 0;
        self.reset_full_bw();
        self.bw_shortterm = self.bw_shortterm.max(self.undo_bw_shortterm);
        self.inflight_shortterm =
            self.inflight_shortterm.max(self.undo_inflight_shortterm);
        self.inflight_longterm =
            self.inflight_longterm.max(self.undo_inflight_longterm);

        // If flow was probing bandwidth, return to that state.
        match self.undo_state {
            Some(State::Startup) if self.state != State::Startup => {
                self.full_bw_reached = false;
                if self.state != State::ProbeRtt {
                    self.enter_startup();
                }
            },

            Some(State::ProbeBwUp)
                if self.state != State::ProbeBwUp &&
                    self.state != State::ProbeRtt =>
            {
                self.start_probe_bw_refill();
            },

            _ => (),
        }

        self.undo_state = None;
    }

    // Draft Section 5.2.3: per-ACK steps.

    /// `UpdateModelAndState()` (draft Section 5.2.3).
    fn update_model_and_state(
        &mut self, rs: &RateSample, sampler: &mut DeliveryRateSampler,
        inflight: u64, now: Instant,
    ) {
        self.update_latest_delivery_signals(rs);
        self.update_congestion_signals(rs);
        self.update_ack_aggregation(rs, now);
        self.check_full_bw_reached(rs);
        self.check_startup_done(rs);
        self.check_drain_done(inflight, now);
        self.update_probe_bw_cycle_phase(rs, inflight, now);
        self.update_min_rtt(rs, now);
        self.check_probe_rtt(rs, sampler, inflight, now);
        self.advance_latest_delivery_signals(rs);
        self.bound_bw_for_model();
    }

    /// `UpdateControlParameters()` (draft Section 5.2.3).
    fn update_control_parameters(&mut self, rs: &RateSample) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd(rs);
    }

    // Draft Section 5.3.1: Startup.

    /// `EnterStartup()` (draft Section 5.3.1.1).
    fn enter_startup(&mut self) {
        self.state = State::Startup;
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    /// `CheckStartupDone()` (draft Section 5.3.1.1).
    fn check_startup_done(&mut self, rs: &RateSample) {
        self.check_startup_high_loss(rs);

        if self.state == State::Startup && self.full_bw_reached {
            if self.startup_exit.is_none() {
                self.startup_exit =
                    Some(if self.undo_state == Some(State::Startup) {
                        StartupExitCause::Loss
                    } else {
                        StartupExitCause::BandwidthPlateau
                    });
            }

            self.enter_drain();
        }
    }

    /// `ResetFullBW()` (draft Section 5.3.1.2).
    fn reset_full_bw(&mut self) {
        self.full_bw = Bandwidth::zero();
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// `CheckFullBWReached()` (draft Section 5.3.1.2).
    fn check_full_bw_reached(&mut self, rs: &RateSample) {
        if self.full_bw_now || !self.round_start || rs.is_app_limited {
            // No need to check for a full pipe now.
            return;
        }

        if rs.delivery_rate >= self.full_bw * FULL_BW_GROWTH {
            // Bandwidth is still growing, so reset and record a new baseline.
            self.reset_full_bw();
            self.full_bw = rs.delivery_rate;
            return;
        }

        // Another round without much growth.
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= FULL_BW_COUNT;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    /// `CheckStartupHighLoss()` (draft Section 5.3.1.3).
    fn check_startup_high_loss(&mut self, rs: &RateSample) {
        if self.full_bw_reached ||
            !self.loss_round_start ||
            !self.in_loss_recovery
        {
            return;
        }

        // C.has_selective_acks is always true for QUIC.
        if self.loss_events_in_round < STARTUP_FULL_LOSS_CNT {
            return;
        }

        if !is_inflight_too_high(rs.lost, rs.tx_in_flight) {
            return;
        }

        self.undo_state = Some(State::Startup);
        self.full_bw_reached = true;
        // Appendix A.2 expects BBR.full_bw_now to be set as well.
        self.full_bw_now = true;
        self.inflight_longterm = self.bdp.max(self.inflight_latest);
    }

    // Draft Section 5.3.2: Drain.

    /// `EnterDrain()` (draft Section 5.3.2).
    fn enter_drain(&mut self) {
        self.state = State::Drain;
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
        self.drain_start_round = self.round_count;
    }

    /// `CheckDrainDone()` (draft Section 5.3.2).
    fn check_drain_done(&mut self, inflight: u64, now: Instant) {
        if self.state == State::Drain &&
            (inflight <= self.inflight(1.0) ||
                self.round_count >
                    self.drain_start_round + DRAIN_MAX_ROUNDS)
        {
            self.enter_probe_bw(now);
        }
    }

    // Draft Section 5.3.3: ProbeBW.

    /// `EnterProbeBW()` (draft Section 5.3.3.9).
    fn enter_probe_bw(&mut self, now: Instant) {
        self.cwnd_gain = DEFAULT_CWND_GAIN;
        self.start_probe_bw_down(now);
    }

    /// `StartProbeBW_DOWN()` (draft Section 5.3.3.9). Gains are set per the
    /// table in draft Section 5.6.1.
    fn start_probe_bw_down(&mut self, now: Instant) {
        self.reset_congestion_signals();
        // Not growing BBR.inflight_longterm.
        self.probe_up_acked_per_inc = INFINITE_BYTES;
        self.pick_probe_wait();
        // Start wall clock.
        self.cycle_stamp = now;
        self.is_bw_probe_stopping = true;
        self.start_round();
        self.state = State::ProbeBwDown;
        self.pacing_gain = PROBE_BW_DOWN_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    /// `StartProbeBW_CRUISE()` (draft Section 5.3.3.9).
    fn start_probe_bw_cruise(&mut self) {
        self.state = State::ProbeBwCruise;
        self.pacing_gain = PROBE_BW_CRUISE_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    /// `StartProbeBW_REFILL()` (draft Section 5.3.3.9).
    fn start_probe_bw_refill(&mut self) {
        self.reset_short_term_model();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acked = 0;
        self.prev_probe_precautionary = false;
        self.is_bw_probe_stopping = false;
        self.start_round();
        self.state = State::ProbeBwRefill;
        self.pacing_gain = PROBE_BW_REFILL_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    /// `StartProbeBW_UP()` (draft Section 5.3.3.9).
    fn start_probe_bw_up(&mut self, rs: &RateSample) {
        self.start_round();
        self.reset_full_bw();
        self.full_bw = rs.delivery_rate;
        self.state = State::ProbeBwUp;
        self.pacing_gain = PROBE_BW_UP_PACING_GAIN;
        self.cwnd_gain = PROBE_BW_UP_CWND_GAIN;
        self.raise_inflight_longterm_slope();
    }

    /// `UpdateProbeBWCyclePhase()` (draft Section 5.3.3.9).
    fn update_probe_bw_cycle_phase(
        &mut self, rs: &RateSample, inflight: u64, now: Instant,
    ) {
        if !self.full_bw_reached {
            // Only handling steady-state behavior here.
            return;
        }

        if self.adapt_long_term_model(rs) {
            // Already decided state transition.
            return;
        }

        match self.state {
            State::ProbeBwDown => {
                if self.is_time_to_probe_bw(now) {
                    // Already decided state transition.
                    return;
                }

                if self.is_time_to_cruise(inflight) {
                    self.start_probe_bw_cruise();
                }
            },

            State::ProbeBwCruise => {
                self.is_time_to_probe_bw(now);
            },

            State::ProbeBwRefill =>
            // After one round of REFILL, start UP.
                if self.round_start {
                    self.check_probe_loss = true;
                    self.start_probe_bw_up(rs);
                },

            State::ProbeBwUp =>
                if self.is_time_to_go_down(rs, inflight) {
                    // No high loss (yet).
                    self.prev_probe_too_high = false;
                    self.start_probe_bw_down(now);
                },

            // Only handling ProbeBW states here.
            State::Startup | State::Drain | State::ProbeRtt => (),
        }
    }

    /// `IsTimeToCruise()` (draft Section 5.3.3.9).
    fn is_time_to_cruise(&mut self, inflight: u64) -> bool {
        if inflight > self.inflight_with_headroom() {
            // Not enough headroom.
            return false;
        }

        if inflight > self.inflight_with_bw(self.max_bw, 1.0) {
            // C.inflight > estimated BDP.
            return false;
        }

        true
    }

    /// `IsTimeToGoDown()` (draft Section 5.3.3.9).
    fn is_time_to_go_down(&mut self, rs: &RateSample, inflight: u64) -> bool {
        // Precautionary Bandwidth Probing: Deceleration.
        if self.prev_probe_too_high && inflight >= self.inflight_longterm {
            self.prev_probe_precautionary = true;
            return true;
        }

        if self.is_cwnd_limited() && self.cwnd >= self.inflight_longterm {
            // Bandwidth is limited by BBR.inflight_longterm.
            self.reset_full_bw();
            self.full_bw = rs.delivery_rate;
        } else if self.full_bw_now {
            // We estimate we've fully used path bandwidth.
            return true;
        }

        false
    }

    /// `HasElapsedInPhase(interval)` (draft Section 5.3.3.9).
    fn has_elapsed_in_phase(&self, interval: Duration, now: Instant) -> bool {
        now > self.cycle_stamp + interval
    }

    /// `InflightWithHeadroom()` (draft Section 5.3.3.9).
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == INFINITE_BYTES {
            return INFINITE_BYTES;
        }

        let headroom = self
            .smss
            .max((HEADROOM * self.inflight_longterm as f64) as u64);

        self.inflight_longterm
            .saturating_sub(headroom)
            .max(self.min_pipe_cwnd())
    }

    /// `RaiseInflightLongtermSlope()` (draft Section 5.3.3.9).
    fn raise_inflight_longterm_slope(&mut self) {
        let growth_this_round = 1u64 << self.bw_probe_up_rounds;
        self.bw_probe_up_rounds =
            (self.bw_probe_up_rounds + 1).min(MAX_BW_PROBE_UP_ROUNDS);
        self.probe_up_acked_per_inc =
            (self.cwnd / growth_this_round).max(self.smss);
    }

    /// `ProbeInflightLongtermUpward()` (draft Section 5.3.3.9).
    fn probe_inflight_longterm_upward(&mut self, rs: &RateSample) {
        if !self.is_cwnd_limited() || self.cwnd < self.inflight_longterm {
            // Not fully using BBR.inflight_longterm, so don't grow it.
            return;
        }

        self.bw_probe_up_acked += rs.newly_acked;
        if self.bw_probe_up_acked >= self.probe_up_acked_per_inc {
            let delta = self.bw_probe_up_acked / self.probe_up_acked_per_inc;
            self.bw_probe_up_acked -= delta * self.probe_up_acked_per_inc;
            self.inflight_longterm = self
                .inflight_longterm
                .saturating_add(delta.saturating_mul(self.smss));
        }

        if self.round_start {
            self.raise_inflight_longterm_slope();
        }
    }

    /// `AdaptLongTermModel()` (draft Section 5.3.3.9).
    ///
    /// Returns true if it decided a state transition.
    fn adapt_long_term_model(&mut self, rs: &RateSample) -> bool {
        if self.is_bw_probe_stopping && self.round_start {
            // End of samples from bandwidth probing phase.
            self.check_probe_loss = false;
            self.is_bw_probe_stopping = false;

            if self.state.is_probe_bw() && !rs.is_app_limited {
                self.advance_max_bw_filter();
            }

            // Precautionary Bandwidth Probing: Acceleration.
            if self.state.is_probe_bw() &&
                self.prev_probe_precautionary &&
                !self.prev_probe_too_high
            {
                self.start_probe_bw_refill();
                return true;
            }
        }

        if !is_inflight_too_high(rs.lost, rs.tx_in_flight) {
            // Loss rate is safe. Adjust upper bounds upward.
            if self.inflight_longterm == INFINITE_BYTES {
                // No upper bounds to raise.
                return false;
            }

            if rs.tx_in_flight > self.inflight_longterm {
                self.inflight_longterm = rs.tx_in_flight;
            }

            if self.state == State::ProbeBwUp {
                self.probe_inflight_longterm_upward(rs);
            }
        }

        false
    }

    // Draft Section 5.3.3.8: time scale for bandwidth probing.

    /// `IsTimeToProbeBW()` (draft Section 5.3.3.8.3): is it time to
    /// transition from DOWN or CRUISE to REFILL?
    fn is_time_to_probe_bw(&mut self, now: Instant) -> bool {
        if self.has_elapsed_in_phase(self.bw_probe_wait, now) ||
            self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill();
            return true;
        }

        false
    }

    /// `PickProbeWait()` (draft Section 5.3.3.8.3): randomized decision about
    /// how long to wait until probing for bandwidth, using round count and
    /// wall clock.
    fn pick_probe_wait(&mut self) {
        // Decide random round-trip bound for wait: 0 or 1.
        self.rounds_since_probe_up = crate::rand::rand_u64_uniform(2);

        // Decide the random wall clock bound for wait: 2..3 secs.
        let extra = crate::rand::rand_u64_uniform(
            BW_PROBE_WAIT_RAND.as_micros() as u64 + 1,
        );
        self.bw_probe_wait = BW_PROBE_WAIT_BASE + Duration::from_micros(extra);
    }

    /// `IsRenoCoexistenceProbeTime()` (draft Section 5.3.3.8.3).
    ///
    /// T_reno is measured in round trips and equals the Reno BDP in packets
    /// (draft Section 5.3.3.8.2), so TargetInflight() is converted from bytes
    /// to packets.
    fn is_reno_coexistence_probe_time(&self) -> bool {
        let reno_rounds = self.target_inflight() / self.smss.max(1);
        let rounds = reno_rounds.min(RENO_COEXISTENCE_MAX_ROUNDS);
        self.rounds_since_probe_up >= rounds
    }

    /// `TargetInflight()` (draft Section 5.3.3.8.3): our estimated BDP,
    /// unless congestion cut C.cwnd.
    fn target_inflight(&self) -> u64 {
        self.bdp.min(self.cwnd)
    }

    // Draft Section 5.3.4: ProbeRTT.

    /// `UpdateMinRTT()` (draft Section 5.3.4.3).
    fn update_min_rtt(&mut self, rs: &RateSample, now: Instant) {
        self.min_rtt_expired = now > self.min_rtt_stamp + MIN_RTT_FILTER_LEN;

        if self.min_rtt_expired {
            self.probe_rtt_cwnd = self.bdp_multiple(PROBE_RTT_CWND_GAIN);
        }

        if let Some(rtt) = rs.rtt {
            if self.min_rtt.is_none_or(|m| rtt < m) || self.min_rtt_expired {
                self.min_rtt = Some(rtt);
                self.min_rtt_stamp = now;
            }
        }
    }

    /// `CheckProbeRTT()` (draft Section 5.3.4.3).
    fn check_probe_rtt(
        &mut self, rs: &RateSample, sampler: &mut DeliveryRateSampler,
        inflight: u64, now: Instant,
    ) {
        if self.state != State::ProbeRtt &&
            self.min_rtt_expired &&
            !self.idle_restart
        {
            self.save_cwnd();
            self.enter_probe_rtt();
            self.probe_rtt_done_stamp = None;
            self.is_bw_probe_stopping = true;
            self.start_round();
        }

        if self.state == State::ProbeRtt {
            self.handle_probe_rtt(sampler, inflight, now);
        }

        if rs.delivered > 0 {
            self.idle_restart = false;
        }
    }

    /// `EnterProbeRTT()` (draft Section 5.3.4.3).
    fn enter_probe_rtt(&mut self) {
        self.state = State::ProbeRtt;
        self.pacing_gain = PROBE_RTT_PACING_GAIN;
        self.cwnd_gain = PROBE_RTT_CWND_GAIN;
    }

    /// `HandleProbeRTT()` (draft Section 5.3.4.3).
    fn handle_probe_rtt(
        &mut self, sampler: &mut DeliveryRateSampler, inflight: u64, now: Instant,
    ) {
        // Ignore low rate samples during ProbeRTT.
        sampler.mark_connection_app_limited(inflight);

        let probe_rtt_cwnd = self.probe_rtt_cwnd_target();

        match self.probe_rtt_done_stamp {
            None if inflight <= probe_rtt_cwnd => {
                // Wait for at least BBR.ProbeRTTDuration to elapse.
                self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
                // Wait for at least one round to elapse.
                self.probe_rtt_round_done = false;
                self.start_round();
            },

            None => (),

            Some(_) => {
                if self.round_start {
                    self.probe_rtt_round_done = true;
                }

                if self.probe_rtt_round_done {
                    self.check_probe_rtt_done(now);
                }
            },
        }
    }

    /// `CheckProbeRTTDone()` (draft Section 5.3.4.3).
    fn check_probe_rtt_done(&mut self, now: Instant) {
        if self.probe_rtt_done_stamp.is_some_and(|t| now > t) {
            // Schedule next ProbeRTT.
            self.min_rtt_stamp = now;
            self.restore_cwnd();
            self.exit_probe_rtt(now);
        }
    }

    /// `ExitProbeRTT()` (draft Section 5.3.4.4).
    fn exit_probe_rtt(&mut self, now: Instant) {
        self.reset_short_term_model();

        if self.full_bw_reached {
            self.start_probe_bw_down(now);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    // Draft Section 5.4: restarting from idle.

    /// `HandleRestartFromIdle()` (draft Section 5.4.1).
    fn handle_restart_from_idle(
        &mut self, inflight: u64, app_limited: bool, now: Instant,
    ) {
        if inflight == 0 && app_limited {
            self.idle_restart = true;
            self.extra_acked_interval_start = now;

            if self.state.is_probe_bw() {
                self.set_pacing_rate_with_gain(1.0);
            } else if self.state == State::ProbeRtt {
                self.check_probe_rtt_done(now);
            }
        }
    }

    // Draft Section 5.5: updating network path model parameters.

    /// `InitRoundCounting()` (draft Section 5.5.1).
    fn init_round_counting(&mut self) {
        self.next_round_delivered = 0;
        self.round_start = false;
        self.round_count = 0;
    }

    /// `UpdateRound()` (draft Section 5.5.1).
    ///
    /// The C.is_cwnd_limited round trip window is advanced here as well.
    fn update_round(&mut self, rs: &RateSample) {
        if rs.prior_delivered >= self.next_round_delivered {
            self.start_round();
            self.round_count += 1;
            self.rounds_since_probe_up += 1;
            self.round_start = true;

            self.cwnd_limited_prev_round = self.cwnd_limited_this_round;
            self.cwnd_limited_this_round = false;
        } else {
            self.round_start = false;
        }
    }

    /// `StartRound()` (draft Section 5.5.1).
    fn start_round(&mut self) {
        self.next_round_delivered = self.delivered;
    }

    /// `UpdateMaxBw()` (draft Section 5.5.5).
    fn update_max_bw(&mut self, rs: &RateSample) {
        self.update_round(rs);

        if rs.delivery_rate > Bandwidth::zero() &&
            (rs.delivery_rate >= self.max_bw || !rs.is_app_limited)
        {
            self.max_bw = self.max_bw_filter.update(
                rs.delivery_rate,
                self.cycle_count,
                MAX_BW_FILTER_LEN,
            );
        }
    }

    /// `AdvanceMaxBwFilter()` (draft Section 5.5.6).
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count += 1;
    }

    /// `UpdateOffloadBudget()` for QUIC (draft Section 5.5.8.2).
    fn update_offload_budget(&mut self) {
        self.offload_budget = self.send_quantum;
    }

    /// `UpdateACKAggregation()` (draft Section 5.5.9).
    fn update_ack_aggregation(&mut self, rs: &RateSample, now: Instant) {
        // Find excess ACKed beyond expected amount over this interval.
        let interval =
            now.saturating_duration_since(self.extra_acked_interval_start);
        let mut expected_delivered = self.bw * interval;

        // Reset interval if ACK rate is below expected rate.
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = now;
            expected_delivered = 0;
        }

        self.extra_acked_delivered += rs.newly_acked;
        let extra = self
            .extra_acked_delivered
            .saturating_sub(expected_delivered)
            .min(self.cwnd);

        let filter_len = if self.full_bw_reached {
            EXTRA_ACKED_FILTER_LEN
        } else {
            // In Startup, just remember 1 round.
            1
        };

        self.extra_acked =
            self.extra_acked_filter
                .update(extra, self.round_count, filter_len);
    }

    /// `NoteLoss()` (draft Section 5.5.10.2).
    fn note_loss(&mut self) {
        if !self.is_loss_in_round {
            // First loss in this round trip.
            self.loss_round_delivered = self.delivered;
            self.save_state_upon_loss();
        }

        self.is_loss_in_round = true;
        self.loss_events_in_round += 1;
    }

    /// `HandleInflightTooHigh()` (draft Section 5.5.10.2).
    fn handle_inflight_too_high(
        &mut self, is_app_limited: bool, tx_in_flight: u64, now: Instant,
    ) {
        self.prev_probe_too_high = true;
        // Only react once per bandwidth probe.
        self.check_probe_loss = false;

        if !is_app_limited {
            self.inflight_longterm =
                tx_in_flight.max((self.target_inflight() as f64 * BETA) as u64);
        }

        if self.state == State::ProbeBwUp {
            self.undo_state = Some(State::ProbeBwUp);
            self.start_probe_bw_down(now);
        }
    }

    /// `UpdateLatestDeliverySignals()` (draft Section 5.5.10.3), near the
    /// start of ACK processing.
    fn update_latest_delivery_signals(&mut self, rs: &RateSample) {
        self.loss_round_start = false;
        self.bw_latest = self.bw_latest.max(rs.delivery_rate);
        self.inflight_latest = self.inflight_latest.max(rs.delivered);

        if rs.prior_delivered >= self.loss_round_delivered {
            self.loss_round_delivered = self.delivered;
            self.loss_round_start = true;
        }
    }

    /// `AdvanceLatestDeliverySignals()` (draft Section 5.5.10.3), near the
    /// end of ACK processing.
    fn advance_latest_delivery_signals(&mut self, rs: &RateSample) {
        if self.loss_round_start {
            self.bw_latest = rs.delivery_rate;
            self.inflight_latest = rs.delivered;
            self.loss_events_in_round = 0;
        }
    }

    /// `ResetCongestionSignals()` (draft Section 5.5.10.3).
    fn reset_congestion_signals(&mut self) {
        self.is_loss_in_round = false;
        self.loss_events_in_round = 0;
        self.bw_latest = Bandwidth::zero();
        self.inflight_latest = 0;
    }

    /// `UpdateCongestionSignals()` (draft Section 5.5.10.3), on every ACK.
    fn update_congestion_signals(&mut self, rs: &RateSample) {
        self.update_max_bw(rs);

        if !self.loss_round_start {
            // Wait until end of round trip.
            return;
        }

        // Once per round, adapt.
        self.adapt_lower_bounds_from_congestion();
        self.is_loss_in_round = false;
    }

    /// `AdaptLowerBoundsFromCongestion()` (draft Section 5.5.10.3): once per
    /// round trip respond to congestion.
    fn adapt_lower_bounds_from_congestion(&mut self) {
        if self.state.is_probing_bw() {
            return;
        }

        if self.is_loss_in_round {
            self.init_lower_bounds();
            self.loss_lower_bounds();
        }
    }

    /// `InitLowerBounds()` (draft Section 5.5.10.3): handle the first
    /// congestion episode in this cycle.
    fn init_lower_bounds(&mut self) {
        if self.bw_shortterm == Bandwidth::infinite() {
            self.bw_shortterm = self.max_bw;
        }

        if self.inflight_shortterm == INFINITE_BYTES {
            self.inflight_shortterm = self.cwnd;
        }
    }

    /// `LossLowerBounds()` (draft Section 5.5.10.3): adjust model once per
    /// round based on loss.
    fn loss_lower_bounds(&mut self) {
        self.bw_shortterm = self.bw_latest.max(self.bw_shortterm * BETA);
        self.inflight_shortterm = self
            .inflight_latest
            .max((BETA * self.inflight_shortterm as f64) as u64);
    }

    /// `ResetShortTermModel()` (draft Section 5.5.10.3).
    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = Bandwidth::infinite();
        self.inflight_shortterm = INFINITE_BYTES;
    }

    /// `BoundBWForModel()` (draft Section 5.5.10.3).
    fn bound_bw_for_model(&mut self) {
        self.bw = self.max_bw.min(self.bw_shortterm);
    }

    /// `SaveStateUponLoss()` (draft Section 5.5.11.1).
    fn save_state_upon_loss(&mut self) {
        self.save_cwnd();
        self.undo_state = None;
        self.undo_bw_shortterm = self.bw_shortterm;
        self.undo_inflight_shortterm = self.inflight_shortterm;
        self.undo_inflight_longterm = self.inflight_longterm;
    }

    // Draft Section 5.6: updating control parameters.

    /// `InitPacingRate()` (draft Section 5.6.2).
    fn init_pacing_rate(&mut self, srtt: Option<Duration>) {
        let rtt = srtt.unwrap_or(DEFAULT_INIT_PACING_RTT);
        let nominal_bandwidth = Bandwidth::from_bytes_and_time_delta(
            self.initial_cwnd() as usize,
            rtt,
        );
        self.pacing_rate = nominal_bandwidth * STARTUP_PACING_GAIN;
    }

    /// `SetPacingRateWithGain(pacing_gain)` (draft Section 5.6.2).
    fn set_pacing_rate_with_gain(&mut self, pacing_gain: f64) {
        let rate =
            self.bw * (pacing_gain * (100.0 - PACING_MARGIN_PERCENT) / 100.0);

        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// `SetPacingRate()` (draft Section 5.6.2).
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// `SetSendQuantum()` (draft Section 5.6.3).
    fn set_send_quantum(&mut self) {
        self.send_quantum = (self.pacing_rate * SEND_QUANTUM_DURATION)
            .min(MAX_SEND_QUANTUM)
            .max(2 * self.smss);
    }

    /// `BDPMultiple(gain)` (draft Section 5.6.4.2).
    fn bdp_multiple(&mut self, gain: f64) -> u64 {
        let Some(min_rtt) = self.min_rtt else {
            // No valid RTT samples yet.
            return self.initial_cwnd();
        };

        self.bdp = self.bw * min_rtt;
        (gain * self.bdp as f64) as u64
    }

    /// `QuantizationBudget(inflight_cap)` (draft Section 5.6.4.2).
    fn quantization_budget(&mut self, inflight_cap: u64) -> u64 {
        self.update_offload_budget();

        let mut inflight_cap = inflight_cap
            .max(self.offload_budget)
            .max(self.min_pipe_cwnd());

        if self.state == State::ProbeBwUp {
            inflight_cap = inflight_cap.saturating_add(2 * self.smss);
        }

        inflight_cap
    }

    /// `Inflight(gain)` (draft Section 5.6.4.2).
    fn inflight(&mut self, gain: f64) -> u64 {
        let inflight_cap = self.bdp_multiple(gain);
        self.quantization_budget(inflight_cap)
    }

    /// `Inflight(bw, gain)`, the two-argument form used by IsTimeToCruise()
    /// (draft Section 5.3.3.9): like Inflight(gain) but using the given
    /// bandwidth instead of BBR.bw. It does not update BBR.bdp.
    fn inflight_with_bw(&mut self, bw: Bandwidth, gain: f64) -> u64 {
        let inflight_cap = match self.min_rtt {
            Some(min_rtt) => (gain * (bw * min_rtt) as f64) as u64,
            None => self.initial_cwnd(),
        };

        self.quantization_budget(inflight_cap)
    }

    /// `UpdateMaxInflight()` (draft Section 5.6.4.2).
    fn update_max_inflight(&mut self) {
        let inflight_cap = self
            .bdp_multiple(self.cwnd_gain)
            .saturating_add(self.extra_acked);
        self.max_inflight = self.quantization_budget(inflight_cap);
    }

    /// `SaveCwnd()` (draft Section 5.6.4.4).
    fn save_cwnd(&mut self) {
        if !self.in_loss_recovery && self.state != State::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
        }
    }

    /// `RestoreCwnd()` (draft Section 5.6.4.4).
    fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd);
    }

    /// `ProbeRTTCwnd()` (draft Section 5.6.4.5).
    fn probe_rtt_cwnd_target(&mut self) -> u64 {
        self.bdp_multiple(PROBE_RTT_CWND_GAIN)
            .min(self.probe_rtt_cwnd)
            .max(self.min_pipe_cwnd())
    }

    /// `BoundCwndForProbeRTT()` (draft Section 5.6.4.5).
    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == State::ProbeRtt {
            self.cwnd = self.cwnd.min(self.probe_rtt_cwnd_target());
        }
    }

    /// `SetCwnd()` (draft Section 5.6.4.6).
    fn set_cwnd(&mut self, rs: &RateSample) {
        self.update_max_inflight();

        if self.full_bw_reached {
            self.cwnd = self
                .cwnd
                .saturating_add(rs.newly_acked)
                .min(self.max_inflight);
        } else if self.cwnd < self.max_inflight ||
            self.delivered < self.initial_cwnd()
        {
            self.cwnd = self.cwnd.saturating_add(rs.newly_acked);
        }

        self.cwnd = self.cwnd.max(self.min_pipe_cwnd());
        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
    }

    /// `BoundCwndForModel()` (draft Section 5.6.4.7).
    fn bound_cwnd_for_model(&mut self) {
        let mut cap = INFINITE_BYTES;

        if self.state.is_probe_bw() && self.state != State::ProbeBwCruise {
            cap = self.inflight_longterm;
        } else if self.state == State::ProbeRtt ||
            self.state == State::ProbeBwCruise
        {
            cap = self.inflight_with_headroom();
        }

        // Apply BBR.inflight_shortterm (possibly infinite).
        cap = cap.min(self.inflight_shortterm).max(self.min_pipe_cwnd());
        self.cwnd = self.cwnd.min(cap);
    }
}

/// `IsInflightTooHigh()` (draft Section 5.5.10.2): do loss signals suggest
/// C.inflight was too high? C.has_selective_acks is always true for QUIC.
fn is_inflight_too_high(lost: u64, tx_in_flight: u64) -> bool {
    lost as f64 > tx_in_flight as f64 * LOSS_THRESH
}

/// `InflightAtLoss(P)` (draft Section 5.5.10.2): at what prefix of packet P
/// did losses exceed BBR.LossThresh?
fn inflight_at_loss(size: u64, tx_in_flight: u64, lost: u64) -> u64 {
    // What was in flight before this packet?
    let inflight_prev = tx_in_flight.saturating_sub(size) as f64;
    // What was lost before this packet?
    let lost_prev = lost.saturating_sub(size) as f64;

    let lost_prefix =
        (LOSS_THRESH * inflight_prev - lost_prev) / (1.0 - LOSS_THRESH);

    // At what C.inflight value did losses cross BBR.LossThresh?
    (inflight_prev + lost_prefix).max(0.0) as u64
}

#[cfg(test)]
mod tests;
