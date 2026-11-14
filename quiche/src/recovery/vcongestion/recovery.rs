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

//! Loss detection and congestion control glue for vcongestion.
//!
//! Loss detection follows RFC 9002 ("QUIC Loss Detection and Congestion
//! Control") Section 6 and the pseudocode in its Appendix A. Detected
//! acknowledgments and losses are fed into the delivery rate sampler
//! (draft-ietf-ccwg-bbr-07 Section 4.1) and the BBR state machine
//! (draft-ietf-ccwg-bbr-07 Section 5).
//!
//! Mapping of the draft's transport events to QUIC:
//!
//! * "Fast Recovery" is the RFC 9002 Section 7.3.2 recovery period: it starts
//!   when a packet sent after the start of the current recovery period (if any)
//!   is declared lost, and ends when a packet sent after the start of the
//!   recovery period is acknowledged.
//! * "RTO" is RFC 9002 Section 7.6 persistent congestion.
//! * A loss recovery episode is spurious (draft Section 5.5.11) when every
//!   packet declared lost during the episode is later acknowledged. QUIC packet
//!   numbers make such acknowledgments unambiguous (RFC 9002 Section 3).
//!
//! <https://www.rfc-editor.org/rfc/rfc9002.html>
//! <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.txt>

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use smallvec::SmallVec;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use crate::frame;
use crate::packet;
use crate::Error;
use crate::Result;

#[cfg(feature = "qlog")]
use crate::recovery::QlogMetrics;

use crate::recovery::bytes_in_flight::BytesInFlight;
use crate::recovery::rtt::RttStats;
use crate::recovery::Bandwidth;
use crate::recovery::CongestionControlAlgorithm;
use crate::recovery::HandshakeStatus;
use crate::recovery::LossDetectionTimer;
use crate::recovery::OnAckReceivedOutcome;
use crate::recovery::OnLossDetectionTimeoutOutcome;
use crate::recovery::RangeSet;
use crate::recovery::RecoveryConfig;
use crate::recovery::RecoveryOps;
use crate::recovery::RecoveryStats;
use crate::recovery::ReleaseDecision;
use crate::recovery::Sent;
use crate::recovery::StartupExit;
use crate::recovery::StartupExitReason;
use crate::recovery::GRANULARITY;
use crate::recovery::INITIAL_PACKET_THRESHOLD;
use crate::recovery::INITIAL_TIME_THRESHOLD;
use crate::recovery::MAX_OUTSTANDING_NON_ACK_ELICITING;
use crate::recovery::MAX_PACKET_THRESHOLD;
use crate::recovery::MAX_PTO_PROBES_COUNT;
use crate::recovery::PACKET_REORDER_TIME_THRESHOLD;

use super::bbr::Bbr;
use super::bbr::StartupExitCause;
use super::delivery_rate::DeliveryRateSampler;
use super::delivery_rate::PacketState;
use super::delivery_rate::RateSample;
use super::pacer::Pacer;

/// kPersistentCongestionThreshold (RFC 9002 Section 7.6.1).
const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

// Most tracked packets are in the `Sent` state, and boxing its contents would
// add an allocation per sent packet.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum SentStatus {
    /// Sent and neither acknowledged nor declared lost.
    Sent {
        ack_eliciting: bool,
        in_flight: bool,
        has_data: bool,
        is_pmtud_probe: bool,
        size: usize,
        frames: SmallVec<[frame::Frame; 1]>,
        /// Delivery rate sampling state, for in-flight packets.
        rate: Option<PacketState>,
    },

    /// Acknowledged.
    Acked,

    /// Declared lost. Kept around for a while to detect spurious losses.
    Lost {
        time_lost: Instant,
        /// Whether the loss was reported to congestion control.
        congestion_signal: bool,
    },
}

#[derive(Debug)]
struct SentPacket {
    pkt_num: u64,

    /// time_sent (RFC 9002 Appendix A.1.1), equal to P.send_time
    /// (draft-ietf-ccwg-bbr-07 Section 4.1.2.1.2).
    time_sent: Instant,

    status: SentStatus,
}

/// Per packet number space state (RFC 9002 Appendix A.3).
#[derive(Default)]
struct PacketSpace {
    /// sent_packets, ordered by packet number.
    sent_packets: VecDeque<SentPacket>,

    /// largest_acked_packet.
    largest_acked: Option<u64>,

    /// time_of_last_ack_eliciting_packet.
    time_of_last_ack_eliciting: Option<Instant>,

    /// loss_time.
    loss_time: Option<Instant>,

    /// Number of in-flight packets, used to determine whether there are
    /// ack-eliciting packets in flight (RFC 9002 Section 2: packets are in
    /// flight when they are ack-eliciting or contain PADDING).
    in_flight_count: usize,

    /// Number of probe packets to send after a PTO (RFC 9002 Section 6.2.4).
    loss_probes: usize,

    /// Frames from acknowledged packets.
    acked_frames: VecDeque<frame::Frame>,

    /// Frames to retransmit, from lost packets or PTO probes.
    lost_frames: VecDeque<frame::Frame>,

    #[allow(dead_code)]
    test_largest_sent_pkt_num: Option<u64>,
}

/// The result of scanning a packet number space for lost packets.
#[derive(Default)]
struct LossScan {
    lost_packets: usize,
    lost_bytes: usize,
    pmtud_lost_bytes: usize,

    /// The longest send time span of consecutive lost ack-eliciting packets
    /// with no acknowledged packets between them (RFC 9002 Section 7.6.2).
    persistent_congestion_span: Duration,
}

impl PacketSpace {
    /// Discards the state of this packet number space and returns the size of
    /// the in-flight packets removed (RFC 9002 Appendix A.11).
    fn discard(&mut self) -> usize {
        let unacked = self
            .sent_packets
            .drain(..)
            .map(|p| match p.status {
                SentStatus::Sent {
                    in_flight: true,
                    size,
                    ..
                } => size,
                _ => 0,
            })
            .sum();

        self.acked_frames.clear();
        self.lost_frames.clear();
        self.time_of_last_ack_eliciting = None;
        self.loss_time = None;
        self.in_flight_count = 0;
        self.loss_probes = 0;

        unacked
    }

    /// `DetectAndRemoveLostPackets()` (RFC 9002 Appendix A.10), also tracking
    /// the persistent congestion span (RFC 9002 Section 7.6.2).
    ///
    /// Packets are scanned in packet number order up to the first packet that
    /// is not yet lost, since send times increase with packet numbers.
    fn detect_lost_packets(
        &mut self, loss_delay: Duration, pkt_thresh: u64, now: Instant,
        first_rtt_sample: Option<Instant>, lost: &mut Vec<PacketState>,
    ) -> LossScan {
        lost.clear();
        self.loss_time = None;

        let mut scan = LossScan::default();

        let Some(largest_acked) = self.largest_acked else {
            return scan;
        };

        let lost_send_time = now.checked_sub(loss_delay);

        // Persistent congestion run (RFC 9002 Section 7.6.2).
        let mut run_start: Option<Instant> = None;

        for p in self.sent_packets.iter_mut() {
            if p.pkt_num > largest_acked {
                break;
            }

            match &p.status {
                SentStatus::Acked => {
                    // Persistent congestion requires that none of the packets
                    // sent between the two lost packets are acknowledged.
                    run_start = None;
                    continue;
                },

                SentStatus::Lost { .. } => continue,

                SentStatus::Sent { .. } => (),
            }

            // RFC 9002 Section 6.1.1 (packet threshold) and 6.1.2 (time
            // threshold).
            let lost_by_time = lost_send_time.is_some_and(|t| p.time_sent <= t);
            let lost_by_pkt =
                largest_acked >= p.pkt_num.saturating_add(pkt_thresh);

            if !lost_by_time && !lost_by_pkt {
                self.loss_time = Some(p.time_sent + loss_delay);
                break;
            }

            let SentStatus::Sent {
                ack_eliciting,
                in_flight,
                is_pmtud_probe,
                size,
                frames,
                rate,
                ..
            } = std::mem::replace(&mut p.status, SentStatus::Lost {
                time_lost: now,
                congestion_signal: false,
            })
            else {
                unreachable!();
            };

            self.lost_frames.extend(frames);

            if ack_eliciting && first_rtt_sample.is_some_and(|t| p.time_sent >= t)
            {
                let start = *run_start.get_or_insert(p.time_sent);
                scan.persistent_congestion_span = scan
                    .persistent_congestion_span
                    .max(p.time_sent.saturating_duration_since(start));
            }

            if !in_flight {
                continue;
            }

            self.in_flight_count = self.in_flight_count.saturating_sub(1);

            // Path MTU probe losses are not congestion signals (RFC 9000
            // Section 14.4, RFC 8899 Section 3).
            if is_pmtud_probe {
                scan.pmtud_lost_bytes += size;
                continue;
            }

            scan.lost_packets += 1;
            scan.lost_bytes += size;

            if let Some(rate) = rate {
                lost.push(rate);
            }

            p.status = SentStatus::Lost {
                time_lost: now,
                congestion_signal: true,
            };
        }

        scan
    }

    /// Removes acknowledged packets, and lost packets that were declared lost
    /// more than `retention` ago, from the front of the queue.
    fn drain(&mut self, now: Instant, retention: Duration) {
        while let Some(p) = self.sent_packets.front() {
            let done = match p.status {
                SentStatus::Acked => true,
                // Only losses reported to congestion control need to be
                // remembered for spurious loss detection.
                SentStatus::Lost {
                    congestion_signal: false,
                    ..
                } => true,
                SentStatus::Lost { time_lost, .. } =>
                    now.saturating_duration_since(time_lost) >= retention,
                SentStatus::Sent { .. } => false,
            };

            if !done {
                break;
            }

            self.sent_packets.pop_front();
        }
    }
}

/// RFC 9002 Section 7.3.2 recovery period, used as the draft's loss recovery
/// episode.
#[derive(Debug, Default)]
struct LossEpisode {
    /// congestion_recovery_start_time (RFC 9002 Appendix B.2). `None` when not
    /// in recovery.
    start: Option<Instant>,

    /// Packets declared lost during the episode.
    lost: u64,

    /// Packets declared lost during the episode and later acknowledged.
    spurious: u64,
}

impl LossEpisode {
    /// `InCongestionRecovery(sent_time)` (RFC 9002 Appendix B.5).
    fn in_recovery(&self, sent_time: Instant) -> bool {
        self.start.is_some_and(|start| sent_time <= start)
    }
}

/// Loss detection and BBRv3 congestion control.
pub(crate) struct VRecovery {
    spaces: [PacketSpace; packet::Epoch::count()],

    loss_timer: LossDetectionTimer,

    /// pto_count (RFC 9002 Appendix A.3).
    pto_count: u32,

    rtt_stats: RttStats,

    /// When the first RTT sample was taken (RFC 9002 Section 7.6.2).
    first_rtt_sample: Option<Instant>,

    recovery_stats: RecoveryStats,

    lost_count: usize,

    lost_spurious_count: usize,

    bytes_lost: u64,

    /// kPacketThreshold (RFC 9002 Section 6.1.1), adapted after spurious
    /// losses caused by reordering.
    pkt_thresh: u64,

    /// kTimeThreshold (RFC 9002 Section 6.1.2), adapted after spurious
    /// losses caused by reordering.
    time_thresh: f64,

    bytes_in_flight: BytesInFlight,

    max_datagram_size: usize,

    outstanding_non_ack_eliciting: usize,

    /// Departure time of the most recently sent packet.
    last_send_time: Option<Instant>,

    episode: LossEpisode,

    /// Reusable buffer for lost packets.
    lost_scratch: Vec<PacketState>,

    sampler: DeliveryRateSampler,

    bbr: Bbr,

    pacer: Pacer,

    #[cfg(feature = "qlog")]
    qlog_metrics: QlogMetrics,

    #[cfg(feature = "qlog")]
    qlog_prev_cc_state: &'static str,
}

impl VRecovery {
    pub(crate) fn new(recovery_config: &RecoveryConfig) -> Option<Self> {
        if recovery_config.cc_algorithm != CongestionControlAlgorithm::Vbbr {
            return None;
        }

        let now = Instant::now();

        Some(VRecovery {
            spaces: Default::default(),
            loss_timer: Default::default(),
            pto_count: 0,
            rtt_stats: RttStats::new(
                recovery_config.initial_rtt,
                recovery_config.max_ack_delay,
            ),
            first_rtt_sample: None,
            recovery_stats: RecoveryStats::default(),
            lost_count: 0,
            lost_spurious_count: 0,
            bytes_lost: 0,
            pkt_thresh: INITIAL_PACKET_THRESHOLD,
            time_thresh: INITIAL_TIME_THRESHOLD,
            bytes_in_flight: Default::default(),
            max_datagram_size: recovery_config.max_send_udp_payload_size,
            outstanding_non_ack_eliciting: 0,
            last_send_time: None,
            episode: LossEpisode::default(),
            lost_scratch: Vec::new(),
            sampler: DeliveryRateSampler::new(now),
            bbr: Bbr::new(
                recovery_config.initial_congestion_window_packets,
                recovery_config.max_send_udp_payload_size,
                now,
            ),
            // The max pacing rate is configured in Mbps, as for gcongestion.
            pacer: Pacer::new(
                recovery_config.pacing,
                recovery_config
                    .max_pacing_rate
                    .map(Bandwidth::from_mbits_per_second),
            ),

            #[cfg(feature = "qlog")]
            qlog_metrics: QlogMetrics::default(),

            #[cfg(feature = "qlog")]
            qlog_prev_cc_state: "",
        })
    }

    fn inflight(&self) -> u64 {
        self.bytes_in_flight.get() as u64
    }

    /// How long lost packets are remembered to detect spurious losses.
    ///
    /// RFC 9002 Section 6.1 notes that packets may be acknowledged after
    /// being declared lost due to reordering; one PTO covers a reasonable
    /// reordering window beyond the time threshold.
    fn lost_retention(&self) -> Duration {
        self.pto()
    }

    /// The persistent congestion duration (RFC 9002 Section 7.6.1).
    fn persistent_congestion_duration(&self) -> Duration {
        (self.rtt_stats.rtt() +
            (self.rtt_stats.rttvar() * 4).max(GRANULARITY) +
            self.rtt_stats.max_ack_delay) *
            PERSISTENT_CONGESTION_THRESHOLD
    }

    /// Detects lost packets in `epoch` and informs congestion control
    /// (RFC 9002 Appendix A.10 and B.8). Returns (lost_bytes, lost_packets).
    fn detect_and_handle_lost_packets(
        &mut self, epoch: packet::Epoch, now: Instant,
    ) -> (usize, usize) {
        let loss_delay = self.rtt_stats.loss_delay(self.time_thresh);

        let mut lost = std::mem::take(&mut self.lost_scratch);

        let scan = self.spaces[epoch].detect_lost_packets(
            loss_delay,
            self.pkt_thresh,
            now,
            self.first_rtt_sample,
            &mut lost,
        );

        self.bytes_in_flight
            .saturating_subtract(scan.lost_bytes + scan.pmtud_lost_bytes, now);

        self.lost_count += scan.lost_packets;
        self.bytes_lost += scan.lost_bytes as u64;

        if !lost.is_empty() {
            self.on_packets_lost(&lost, now);
        }

        if scan.persistent_congestion_span > self.persistent_congestion_duration()
        {
            // RFC 9002 Section 7.6.2; draft-ietf-ccwg-bbr-07 Section 5.6.4.4
            // OnEnterRTO().
            self.episode = LossEpisode {
                start: Some(now),
                ..Default::default()
            };
            self.bbr.on_enter_rto(self.inflight());
        }

        self.lost_scratch = lost;

        (scan.lost_bytes, scan.lost_packets)
    }

    /// `OnPacketsLost()` (RFC 9002 Appendix B.8) for BBR: starts a recovery
    /// period if needed and calls `HandleLostPacket(P)` for each packet
    /// (draft-ietf-ccwg-bbr-07 Section 5.2.4).
    fn on_packets_lost(&mut self, lost: &[PacketState], now: Instant) {
        // RFC 9002 Appendix B.6 OnCongestionEvent(): a new recovery period
        // starts unless all lost packets were sent during the current one.
        let new_episode =
            lost.iter().any(|p| !self.episode.in_recovery(p.send_time));

        if new_episode {
            self.episode = LossEpisode {
                start: Some(now),
                ..Default::default()
            };
            self.bbr.on_enter_fast_recovery();
        }

        for p in lost {
            self.episode.lost += 1;
            self.sampler.on_packet_lost(p.size);
            self.bbr.on_packet_lost(p, &self.sampler, now);
        }
    }

    /// GetLossTimeAndSpace() (RFC 9002 Appendix A.8).
    fn loss_time_and_space(&self) -> (Option<Instant>, packet::Epoch) {
        let mut epoch = packet::Epoch::Initial;
        let mut time = self.spaces[epoch].loss_time;

        for e in [packet::Epoch::Handshake, packet::Epoch::Application] {
            let t = self.spaces[e].loss_time;
            if time.is_none() || (t.is_some() && t < time) {
                time = t;
                epoch = e;
            }
        }

        (time, epoch)
    }

    /// GetPtoTimeAndSpace() (RFC 9002 Appendix A.8).
    fn pto_time_and_space(
        &self, handshake_status: HandshakeStatus, now: Instant,
    ) -> (Option<Instant>, packet::Epoch) {
        let backoff = 2_u32.saturating_pow(self.pto_count);
        let mut duration = self.pto().saturating_mul(backoff);

        // Arm PTO from now when there are no in-flight packets.
        if self.bytes_in_flight.is_zero() {
            let epoch = if handshake_status.has_handshake_keys {
                packet::Epoch::Handshake
            } else {
                packet::Epoch::Initial
            };

            return (now.checked_add(duration), epoch);
        }

        let mut pto_timeout = None;
        let mut pto_space = packet::Epoch::Initial;

        for &e in packet::Epoch::epochs(
            packet::Epoch::Initial..=packet::Epoch::Application,
        ) {
            let space = &self.spaces[e];

            if space.in_flight_count == 0 {
                continue;
            }

            if e == packet::Epoch::Application {
                // Skip Application Data until the handshake is confirmed.
                if !handshake_status.completed {
                    return (pto_timeout, pto_space);
                }

                // Include max_ack_delay and backoff for Application Data.
                duration = duration.saturating_add(
                    self.rtt_stats.max_ack_delay.saturating_mul(backoff),
                );
            }

            let t = space
                .time_of_last_ack_eliciting
                .and_then(|t| t.checked_add(duration));

            if pto_timeout.is_none() || (t.is_some() && t < pto_timeout) {
                pto_timeout = t;
                pto_space = e;
            }
        }

        (pto_timeout, pto_space)
    }

    /// SetLossDetectionTimer() (RFC 9002 Appendix A.8).
    fn set_loss_detection_timer(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
    ) {
        if let (Some(t), _) = self.loss_time_and_space() {
            // Time threshold loss detection.
            self.loss_timer.update(t);
            return;
        }

        if self.bytes_in_flight.is_zero() &&
            handshake_status.peer_verified_address
        {
            // There is nothing to detect lost, so no timer is set.
            self.loss_timer.clear();
            return;
        }

        match self.pto_time_and_space(handshake_status, now) {
            (Some(t), _) => self.loss_timer.update(t),
            (None, _) => self.loss_timer.clear(),
        }
    }

    /// Records the first time BBR exits Startup (RecoveryOps::startup_exit).
    fn maybe_record_startup_exit(&mut self) {
        if self.recovery_stats.startup_exit.is_some() {
            return;
        }

        if let Some(cause) = self.bbr.startup_exit() {
            let reason = match cause {
                StartupExitCause::BandwidthPlateau =>
                    StartupExitReason::BandwidthPlateau,
                StartupExitCause::Loss => StartupExitReason::Loss,
            };

            self.recovery_stats.set_startup_exit(StartupExit::new(
                self.bbr.cwnd() as usize,
                Some(self.bbr.max_bw()),
                reason,
            ));
        }
    }

    #[cfg(test)]
    pub(super) fn bbr(&self) -> &Bbr {
        &self.bbr
    }

    #[cfg(any(test, feature = "qlog"))]
    fn pacing_rate_bw(&self) -> Bandwidth {
        self.pacer.effective_rate(self.bbr.pacing_rate())
    }
}

impl RecoveryOps for VRecovery {
    fn lost_count(&self) -> usize {
        self.lost_count
    }

    fn bytes_lost(&self) -> u64 {
        self.bytes_lost
    }

    fn should_elicit_ack(&self, epoch: packet::Epoch) -> bool {
        self.spaces[epoch].loss_probes > 0 ||
            self.outstanding_non_ack_eliciting >=
                MAX_OUTSTANDING_NON_ACK_ELICITING
    }

    fn next_acked_frame(&mut self, epoch: packet::Epoch) -> Option<frame::Frame> {
        self.spaces[epoch].acked_frames.pop_front()
    }

    fn next_lost_frame(&mut self, epoch: packet::Epoch) -> Option<frame::Frame> {
        self.spaces[epoch].lost_frames.pop_front()
    }

    fn get_largest_acked_on_epoch(&self, epoch: packet::Epoch) -> Option<u64> {
        self.spaces[epoch].largest_acked
    }

    fn has_lost_frames(&self, epoch: packet::Epoch) -> bool {
        !self.spaces[epoch].lost_frames.is_empty()
    }

    fn loss_probes(&self, epoch: packet::Epoch) -> usize {
        self.spaces[epoch].loss_probes
    }

    #[cfg(test)]
    fn inc_loss_probes(&mut self, epoch: packet::Epoch) {
        self.spaces[epoch].loss_probes += 1;
    }

    #[cfg(test)]
    fn lost_frames_count(&self, epoch: packet::Epoch) -> usize {
        self.spaces[epoch].lost_frames.len()
    }

    fn ping_sent(&mut self, epoch: packet::Epoch) {
        let space = &mut self.spaces[epoch];
        space.loss_probes = space.loss_probes.saturating_sub(1);
    }

    /// OnPacketSent() (RFC 9002 Appendix A.5), with OnTransmit() and
    /// OnPacketSent(P) from draft-ietf-ccwg-bbr-07 Sections 5.2.2 and
    /// 4.1.2.2, and pacing from Section 5.6.2.
    fn on_packet_sent(
        &mut self, pkt: Sent, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    ) {
        let pkt_num = pkt.pkt_num;
        let size = pkt.size;
        let in_flight = pkt.in_flight;
        let ack_eliciting = pkt.ack_eliciting;

        if let Some(last) = self.spaces[epoch].sent_packets.back() {
            assert!(last.pkt_num < pkt_num, "Packet numbers must increase");
        }

        // Only congestion controlled packets are paced (RFC 9002 Section 7.7).
        let (time_sent, rate) = if in_flight {
            let prior_inflight = self.inflight();

            self.bbr.on_transmit(
                prior_inflight,
                self.sampler.is_app_limited(),
                now,
            );

            let send_time = self.pacer.on_packet_sent(
                now,
                size as u64,
                self.bbr.pacing_rate(),
                self.bbr.send_quantum(),
            );

            let rate = self.sampler.on_packet_sent(
                pkt_num,
                size as u64,
                send_time,
                prior_inflight,
            );

            (send_time, Some(rate))
        } else {
            (now, None)
        };

        self.last_send_time = Some(time_sent);

        let space = &mut self.spaces[epoch];

        #[cfg(test)]
        {
            space.test_largest_sent_pkt_num =
                space.test_largest_sent_pkt_num.max(Some(pkt_num));
        }

        space.sent_packets.push_back(SentPacket {
            pkt_num,
            time_sent,
            status: SentStatus::Sent {
                ack_eliciting,
                in_flight,
                has_data: pkt.has_data,
                is_pmtud_probe: pkt.is_pmtud_probe,
                size,
                frames: pkt.frames,
                rate,
            },
        });

        if ack_eliciting {
            self.outstanding_non_ack_eliciting = 0;
        } else {
            self.outstanding_non_ack_eliciting += 1;
        }

        if in_flight {
            if ack_eliciting {
                space.time_of_last_ack_eliciting = Some(time_sent);
            }

            space.in_flight_count += 1;

            self.bytes_in_flight.add(size, now);
            self.bbr.on_packet_sent(self.inflight());

            self.set_loss_detection_timer(handshake_status, now);
        }

        trace!("{trace_id} {self:?}");
    }

    fn get_packet_send_time(&self, now: Instant) -> Instant {
        self.last_send_time.map_or(now, |t| t.max(now))
    }

    /// OnAckReceived() (RFC 9002 Appendix A.7), with UpdateRateSample(),
    /// GenerateRateSample() (draft-ietf-ccwg-bbr-07 Section 4.1.2.3) and
    /// UpdateOnACK() (Section 5.2.3).
    fn on_ack_received(
        &mut self, ranges: &RangeSet, ack_delay: u64, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, skip_pn: Option<u64>,
        trace_id: &str,
    ) -> Result<OnAckReceivedOutcome> {
        let Some(largest_in_ack) = ranges.last() else {
            return Ok(OnAckReceivedOutcome::default());
        };

        let mut rs = RateSample::new();

        let mut acked_bytes = 0;
        let mut spurious_losses = 0;
        let mut spurious_pkt_thresh = None;
        let mut largest_newly_acked: Option<(u64, Instant)> = None;
        let mut has_ack_eliciting = false;
        let mut exits_recovery = false;

        let space = &mut self.spaces[epoch];
        let largest_acked = space.largest_acked.unwrap_or(0).max(largest_in_ack);

        for range in ranges.iter() {
            // RFC 9000 Section 13.1: an acknowledgment for a packet that was
            // never sent is a PROTOCOL_VIOLATION.
            if skip_pn.is_some_and(|pn| range.contains(&pn)) {
                return Err(Error::OptimisticAckDetected);
            }

            let start = space
                .sent_packets
                .binary_search_by_key(&range.start, |p| p.pkt_num)
                .unwrap_or_else(|i| i);

            for p in space.sent_packets.range_mut(start..) {
                if p.pkt_num >= range.end {
                    break;
                }

                match std::mem::replace(&mut p.status, SentStatus::Acked) {
                    SentStatus::Sent {
                        ack_eliciting,
                        in_flight,
                        size,
                        frames,
                        rate,
                        ..
                    } => {
                        has_ack_eliciting |= ack_eliciting;
                        largest_newly_acked = Some((p.pkt_num, p.time_sent));
                        space.acked_frames.extend(frames);

                        if in_flight {
                            space.in_flight_count =
                                space.in_flight_count.saturating_sub(1);
                            acked_bytes += size;
                        }

                        if let Some(rate) = rate {
                            self.sampler.on_packet_acked(&mut rs, &rate, now);

                            // RFC 9002 Section 7.3.2: the recovery period ends
                            // when a packet sent during it is acknowledged.
                            if self.episode.start.is_some() &&
                                !self.episode.in_recovery(p.time_sent)
                            {
                                exits_recovery = true;
                            }
                        }

                        trace!("{trace_id} packet newly acked {}", p.pkt_num);
                    },

                    SentStatus::Acked => (),

                    SentStatus::Lost {
                        time_lost,
                        congestion_signal,
                    } => {
                        // An acknowledged packet was declared lost: the loss
                        // was spurious, most likely due to reordering.
                        spurious_losses += 1;
                        spurious_pkt_thresh
                            .get_or_insert(largest_acked - p.pkt_num + 1);

                        if congestion_signal &&
                            self.episode
                                .start
                                .is_some_and(|start| time_lost >= start)
                        {
                            self.episode.spurious += 1;
                        }
                    },
                }
            }
        }

        self.lost_spurious_count += spurious_losses;

        // RFC 9002 Sections 6.1.1 and 6.1.2: implementations can adapt the
        // reordering thresholds; after a spurious loss raise the packet
        // threshold to the observed reordering distance, and use a more
        // lenient time threshold.
        if let Some(thresh) = spurious_pkt_thresh {
            self.pkt_thresh =
                self.pkt_thresh.max(thresh.min(MAX_PACKET_THRESHOLD));
            self.time_thresh = PACKET_REORDER_TIME_THRESHOLD;
        }

        // draft-ietf-ccwg-bbr-07 Section 5.5.11: the episode was spurious if
        // all the packets it declared lost were delivered.
        if self.episode.start.is_some() &&
            self.episode.lost > 0 &&
            self.episode.spurious >= self.episode.lost
        {
            self.episode = LossEpisode::default();
            self.bbr.on_spurious_loss_detection();
            exits_recovery = false;
        }

        let Some((largest_newly_acked_pn, largest_newly_acked_time)) =
            largest_newly_acked
        else {
            let retention = self.lost_retention();
            self.spaces[epoch].drain(now, retention);

            return Ok(OnAckReceivedOutcome {
                acked_bytes,
                spurious_losses,
                ..Default::default()
            });
        };

        self.bytes_in_flight.saturating_subtract(acked_bytes, now);

        let space = &mut self.spaces[epoch];
        let largest_acked =
            space.largest_acked.unwrap_or(0).max(largest_newly_acked_pn);
        space.largest_acked = Some(largest_acked);

        // RFC 9002 Section 5.1: generate an RTT sample if the largest
        // acknowledged packet is newly acknowledged and at least one newly
        // acknowledged packet was ack-eliciting.
        if largest_newly_acked_pn == largest_acked && has_ack_eliciting {
            let latest_rtt =
                now.saturating_duration_since(largest_newly_acked_time);

            self.rtt_stats.update_rtt(
                latest_rtt,
                Duration::from_micros(ack_delay),
                now,
                handshake_status.completed,
            );

            self.first_rtt_sample.get_or_insert(now);
        }

        let (lost_bytes, lost_packets) =
            self.detect_and_handle_lost_packets(epoch, now);

        // A new recovery period may have started while detecting losses on
        // this ACK, in which case none of the acknowledged packets were sent
        // after its start.
        if exits_recovery && self.episode.start.is_some_and(|start| start < now) {
            self.episode = LossEpisode::default();
            self.bbr.on_exit_loss_recovery();
        }

        self.sampler.generate_rate_sample(&mut rs, now);

        if rs.has_data {
            let srtt = self
                .rtt_stats
                .has_first_rtt_sample
                .then(|| self.rtt_stats.rtt());

            let inflight = self.inflight();
            self.bbr.on_ack(&rs, &mut self.sampler, inflight, srtt, now);

            self.maybe_record_startup_exit();
        }

        // RFC 9002 Appendix A.7: reset pto_count unless the client is unsure
        // if the server has validated the client's address.
        if handshake_status.peer_verified_address {
            self.pto_count = 0;
        }

        let retention = self.lost_retention();
        self.spaces[epoch].drain(now, retention);

        self.set_loss_detection_timer(handshake_status, now);

        trace!("{trace_id} {self:?}");

        Ok(OnAckReceivedOutcome {
            lost_packets,
            lost_bytes,
            acked_bytes,
            spurious_losses,
        })
    }

    /// OnLossDetectionTimeout() (RFC 9002 Appendix A.9).
    fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> OnLossDetectionTimeoutOutcome {
        let (earliest_loss_time, epoch) = self.loss_time_and_space();

        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            let (lost_bytes, lost_packets) =
                self.detect_and_handle_lost_packets(epoch, now);

            let retention = self.lost_retention();
            self.spaces[epoch].drain(now, retention);

            self.set_loss_detection_timer(handshake_status, now);

            trace!("{trace_id} {self:?}");

            return OnLossDetectionTimeoutOutcome {
                lost_packets,
                lost_bytes,
            };
        }

        let epoch = if !self.bytes_in_flight.is_zero() {
            // PTO. Send new data if available, else retransmit old data. If
            // neither is available, send a single PING frame.
            self.pto_time_and_space(handshake_status, now).1
        } else if handshake_status.has_handshake_keys {
            // Client sends an anti-deadlock packet: a Handshake packet proves
            // address ownership.
            packet::Epoch::Handshake
        } else {
            // Initial is padded to earn more anti-amplification credit.
            packet::Epoch::Initial
        };

        self.pto_count += 1;

        let space = &mut self.spaces[epoch];

        // RFC 9002 Section 6.2.4: send one or two ack-eliciting probes.
        space.loss_probes = MAX_PTO_PROBES_COUNT.min(self.pto_count as usize);

        // RFC 9002 Section 6.2.4: probes SHOULD carry data from packets that
        // are still outstanding. The packets aren't declared lost, so there is
        // no effect on congestion control. Skip this if frames from a previous
        // PTO or loss haven't been sent yet. DATAGRAM frames are never
        // retransmitted (RFC 9221 Section 5.2).
        if space.lost_frames.is_empty() {
            let frames = space
                .sent_packets
                .iter()
                .filter_map(|p| match &p.status {
                    SentStatus::Sent {
                        has_data: true,
                        frames,
                        ..
                    } => Some(frames),
                    _ => None,
                })
                .take(space.loss_probes)
                .flatten()
                .filter(|f| !matches!(f, frame::Frame::DatagramHeader { .. }))
                .cloned()
                .collect::<Vec<_>>();

            space.lost_frames.extend(frames);
        }

        self.set_loss_detection_timer(handshake_status, now);

        trace!("{trace_id} {self:?}");

        OnLossDetectionTimeoutOutcome {
            lost_packets: 0,
            lost_bytes: 0,
        }
    }

    /// OnPacketNumberSpaceDiscarded() (RFC 9002 Appendix A.11).
    fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let unacked = self.spaces[epoch].discard();
        self.bytes_in_flight.saturating_subtract(unacked, now);
        self.pto_count = 0;
        self.set_loss_detection_timer(handshake_status, now);
    }

    fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, _trace_id: &str,
    ) -> (usize, usize) {
        let (lost_bytes, lost_packets) =
            self.detect_and_handle_lost_packets(epoch, now);

        (lost_packets, lost_bytes)
    }

    fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_timer.time
    }

    fn cwnd(&self) -> usize {
        self.bbr.cwnd() as usize
    }

    fn cwnd_available(&self) -> usize {
        self.cwnd().saturating_sub(self.bytes_in_flight.get())
    }

    fn rtt(&self) -> Duration {
        self.rtt_stats.rtt()
    }

    fn min_rtt(&self) -> Option<Duration> {
        self.rtt_stats.min_rtt()
    }

    fn max_rtt(&self) -> Option<Duration> {
        self.rtt_stats.max_rtt()
    }

    fn rttvar(&self) -> Duration {
        self.rtt_stats.rttvar()
    }

    /// PTO without max_ack_delay (RFC 9002 Section 6.2.1).
    fn pto(&self) -> Duration {
        self.rtt_stats.rtt() + (self.rtt_stats.rttvar() * 4).max(GRANULARITY)
    }

    /// BBR.bw (draft-ietf-ccwg-bbr-07 Section 2.9.1).
    fn delivery_rate(&self) -> Bandwidth {
        self.bbr.bw()
    }

    /// BBR.max_bw (draft-ietf-ccwg-bbr-07 Section 2.9.1).
    fn max_bandwidth(&self) -> Option<Bandwidth> {
        Some(self.bbr.max_bw())
    }

    fn rtt_persistent_jump_count(&self) -> u64 {
        0
    }

    fn startup_exit(&self) -> Option<StartupExit> {
        self.recovery_stats.startup_exit
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    fn pmtud_update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        self.max_datagram_size = new_max_datagram_size;
        self.bbr.update_mss(new_max_datagram_size);
    }

    fn update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        self.pmtud_update_max_datagram_size(
            self.max_datagram_size.min(new_max_datagram_size),
        );
    }

    /// `CheckIfApplicationLimited()` (draft-ietf-ccwg-bbr-07 Section
    /// 4.1.2.4). The caller only invokes this when it has no data to send;
    /// lost data awaiting retransmission (C.lost_out > C.retrans_out) means
    /// the connection is not application-limited.
    fn on_app_limited(&mut self) {
        let inflight = self.inflight();
        let has_lost_frames =
            self.spaces.iter().any(|s| !s.lost_frames.is_empty());

        if inflight < self.bbr.cwnd() && !has_lost_frames {
            self.sampler.mark_connection_app_limited(inflight);
        }
    }

    #[cfg(test)]
    fn largest_sent_pkt_num_on_path(&self, epoch: packet::Epoch) -> Option<u64> {
        self.spaces[epoch].test_largest_sent_pkt_num
    }

    /// Whether the sender is application-limited: either delivery rate
    /// samples are currently marked application-limited (draft-ietf-ccwg-
    /// bbr-07 Section 4.1.1.3), or the cwnd was not fully used during the
    /// last round trip (C.is_cwnd_limited, Section 2.2).
    #[cfg(any(test, feature = "qlog"))]
    fn app_limited(&self) -> bool {
        self.sampler.is_app_limited() || !self.bbr.is_cwnd_limited()
    }

    fn sent_packets_len(&self, epoch: packet::Epoch) -> usize {
        self.spaces[epoch].sent_packets.len()
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight.get()
    }

    fn bytes_in_flight_duration(&self) -> Duration {
        self.bytes_in_flight.get_duration()
    }

    #[cfg(test)]
    fn in_flight_count(&self, epoch: packet::Epoch) -> usize {
        self.spaces[epoch].in_flight_count
    }

    #[cfg(test)]
    fn pacing_rate(&self) -> u64 {
        self.pacing_rate_bw().to_bytes_per_second()
    }

    #[cfg(test)]
    fn pto_count(&self) -> u32 {
        self.pto_count
    }

    #[cfg(test)]
    fn pkt_thresh(&self) -> Option<u64> {
        Some(self.pkt_thresh)
    }

    #[cfg(test)]
    fn time_thresh(&self) -> f64 {
        self.time_thresh
    }

    #[cfg(test)]
    fn lost_spurious_count(&self) -> usize {
        self.lost_spurious_count
    }

    #[cfg(test)]
    fn detect_lost_packets_for_test(
        &mut self, epoch: packet::Epoch, now: Instant,
    ) -> (usize, usize) {
        let ret = self.detect_and_handle_lost_packets(epoch, now);
        self.spaces[epoch].drain(now, Duration::ZERO);
        ret
    }

    // The application-limited signals below are specific to the legacy
    // delivery rate estimator; vbbr uses on_app_limited() instead.
    fn update_app_limited(&mut self, _v: bool) {}

    fn delivery_rate_update_app_limited(&mut self, _v: bool) {}

    fn update_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.rtt_stats.max_ack_delay = max_ack_delay;
    }

    #[cfg(feature = "qlog")]
    fn state_str(&self, _now: Instant) -> &'static str {
        self.bbr.state().as_str()
    }

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_event_data(&mut self) -> Option<EventData> {
        let qlog_metrics = QlogMetrics {
            min_rtt: *self.rtt_stats.min_rtt,
            smoothed_rtt: self.rtt(),
            latest_rtt: self.rtt_stats.latest_rtt(),
            rttvar: self.rtt_stats.rttvar(),
            cwnd: self.cwnd() as u64,
            bytes_in_flight: self.bytes_in_flight.get() as u64,
            ssthresh: None,
            pacing_rate: Some(self.pacing_rate_bw().to_bytes_per_second()),
            delivery_rate: Some(self.delivery_rate().to_bytes_per_second()),
            send_rate: None,
            ack_rate: None,
            lost_packets: Some(self.lost_count as u64),
            lost_bytes: Some(self.bytes_lost),
            pto_count: Some(self.pto_count),
            app_limited: Some(self.app_limited()),
        };

        self.qlog_metrics.maybe_update(qlog_metrics)
    }

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_cc_state(
        &mut self, now: Instant,
    ) -> Option<&'static str> {
        let cc_state = self.state_str(now);
        if cc_state != self.qlog_prev_cc_state {
            self.qlog_prev_cc_state = cc_state;
            Some(cc_state)
        } else {
            None
        }
    }

    /// C.send_quantum (draft-ietf-ccwg-bbr-07 Section 5.6.3).
    fn send_quantum(&self) -> usize {
        self.bbr.send_quantum() as usize
    }

    fn get_next_release_time(&self) -> ReleaseDecision {
        self.pacer.get_next_release_time()
    }

    /// vcongestion paces packets using release times, like gcongestion, so
    /// callers must use [`ReleaseDecision`]-based pacing.
    fn gcongestion_enabled(&self) -> bool {
        true
    }
}

impl std::fmt::Debug for VRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "timer={:?} ", self.loss_detection_timer())?;
        write!(f, "rtt_stats={:?} ", self.rtt_stats)?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight.get())?;
        write!(f, "state={} ", self.bbr.state().as_str())?;
        write!(f, "cwnd={} ", self.bbr.cwnd())?;
        write!(f, "pacing_rate={:?} ", self.bbr.pacing_rate())?;
        write!(f, "max_bw={:?} ", self.bbr.max_bw())?;
        write!(f, "in_recovery={}", self.episode.start.is_some())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::recovery::vcongestion::bbr::State;
    use crate::test_utils;
    use crate::Config;

    const MSS: usize = 1200;
    const EPOCH: packet::Epoch = packet::Epoch::Application;

    fn new_recovery() -> VRecovery {
        let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        config.set_cc_algorithm(CongestionControlAlgorithm::Vbbr);
        let mut recovery_config = RecoveryConfig::from_config(&config);
        recovery_config.max_send_udp_payload_size = MSS;
        VRecovery::new(&recovery_config).unwrap()
    }

    fn send(r: &mut VRecovery, pns: std::ops::Range<u64>, now: Instant) {
        for pn in pns {
            let p = test_utils::helper_packet_sent(pn, now, MSS);
            r.on_packet_sent(p, EPOCH, HandshakeStatus::default(), now, "");
        }
    }

    fn ack(
        r: &mut VRecovery, range: std::ops::Range<u64>, now: Instant,
    ) -> OnAckReceivedOutcome {
        let mut acked = RangeSet::default();
        acked.insert(range);

        r.on_ack_received(
            &acked,
            0,
            EPOCH,
            HandshakeStatus::default(),
            now,
            None,
            "",
        )
        .unwrap()
    }

    #[test]
    fn only_vbbr() {
        let config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        assert!(VRecovery::new(&RecoveryConfig::from_config(&config)).is_none());
    }

    #[test]
    fn recovery_period_and_spurious_loss() {
        let mut r = new_recovery();
        let mut now = Instant::now();

        send(&mut r, 0..10, now);
        now += Duration::from_millis(50);

        // Packets 0..2 are lost by packet threshold (RFC 9002 Section 6.1.1).
        let outcome = ack(&mut r, 2..10, now);
        assert_eq!(outcome.lost_packets, 2);
        assert_eq!(r.sampler.lost(), 2 * MSS as u64);

        // A recovery period started (RFC 9002 Section 7.3.2).
        assert_eq!(r.episode.start, Some(now));
        assert_eq!(r.episode.lost, 2);
        assert!(r.bbr.in_loss_recovery());
        assert_eq!(r.lost_count, 2);

        // Both lost packets arrive late: the loss was spurious
        // (draft-ietf-ccwg-bbr-07 Section 5.5.11).
        now += Duration::from_millis(1);
        let outcome = ack(&mut r, 0..1, now);
        assert_eq!(outcome.spurious_losses, 1);
        assert!(r.bbr.in_loss_recovery());

        let outcome = ack(&mut r, 0..2, now);
        assert_eq!(outcome.spurious_losses, 1);
        assert_eq!(r.episode.start, None);
        assert!(!r.bbr.in_loss_recovery());
        assert_eq!(r.lost_spurious_count, 2);

        // Reordering thresholds adapt to the observed reordering (RFC 9002
        // Sections 6.1.1 and 6.1.2).
        assert_eq!(r.pkt_thresh, 10);
        assert_eq!(r.time_thresh, PACKET_REORDER_TIME_THRESHOLD);
    }

    #[test]
    fn recovery_period_ends_on_ack_of_packet_sent_during_it() {
        let mut r = new_recovery();
        let mut now = Instant::now();

        send(&mut r, 0..10, now);
        now += Duration::from_millis(50);
        ack(&mut r, 3..10, now);
        assert!(r.bbr.in_loss_recovery());
        let start = r.episode.start.unwrap();

        // Packets sent before the start of recovery don't end it.
        send(&mut r, 10..12, start);
        now += Duration::from_millis(50);
        ack(&mut r, 10..11, now);
        assert!(r.bbr.in_loss_recovery());

        // A packet sent after the start of the recovery period does.
        let later = start + Duration::from_millis(1);
        send(&mut r, 12..13, later);
        now += Duration::from_millis(50);
        ack(&mut r, 12..13, now);
        assert!(!r.bbr.in_loss_recovery());
        assert_eq!(r.episode.start, None);
    }

    #[test]
    fn persistent_congestion() {
        let mut r = new_recovery();
        let mut now = Instant::now();

        // Get an RTT sample.
        send(&mut r, 0..1, now);
        now += Duration::from_millis(50);
        ack(&mut r, 0..1, now);

        // Send packets over a period much longer than the persistent
        // congestion duration (RFC 9002 Section 7.6.1).
        let duration = r.persistent_congestion_duration();
        send(&mut r, 1..2, now);
        now += duration * 2;
        send(&mut r, 2..3, now);
        send(&mut r, 3..10, now);

        // All but the last packets are lost.
        now += Duration::from_millis(50);
        // Packets 1..=6 are lost by the packet threshold.
        let outcome = ack(&mut r, 9..10, now);
        assert_eq!(outcome.lost_packets, 6);

        // draft-ietf-ccwg-bbr-07 Section 5.6.4.4, OnEnterRTO(), then the cwnd
        // floor of BBR.MinPipeCwnd once the ACK is processed.
        assert!(r.bbr.in_loss_recovery());
        assert_eq!(r.cwnd(), 4 * MSS);
    }

    #[test]
    fn no_persistent_congestion_without_long_span() {
        let mut r = new_recovery();
        let mut now = Instant::now();

        send(&mut r, 0..1, now);
        now += Duration::from_millis(50);
        ack(&mut r, 0..1, now);
        let cwnd = r.cwnd();

        send(&mut r, 1..10, now);
        now += Duration::from_millis(50);
        ack(&mut r, 4..10, now);

        assert!(r.bbr.in_loss_recovery());
        assert!(r.cwnd() >= cwnd);
    }

    #[test]
    fn pmtud_probe_loss_is_not_a_congestion_signal() {
        let mut r = new_recovery();
        let mut now = Instant::now();

        let mut p = test_utils::helper_packet_sent(0, now, 1400);
        p.is_pmtud_probe = true;
        r.on_packet_sent(p, EPOCH, HandshakeStatus::default(), now, "");
        send(&mut r, 1..5, now);

        now += Duration::from_millis(50);
        let outcome = ack(&mut r, 1..5, now);
        assert_eq!(outcome.lost_packets, 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert!(!r.bbr.in_loss_recovery());
        assert_eq!(r.sampler.lost(), 0);
    }

    #[test]
    fn paced_send_times() {
        let mut r = new_recovery();
        let mut now = Instant::now();

        // Complete one round trip so that pacing is based on C.srtt
        // (draft-ietf-ccwg-bbr-07 Section 5.6.2).
        send(&mut r, 0..1, now);
        now += Duration::from_millis(100);
        ack(&mut r, 0..1, now);

        let rate = r.bbr.pacing_rate();
        let quantum = r.bbr.send_quantum();
        assert_eq!(quantum, 2 * MSS as u64);

        // The first quantum departs immediately, the next is paced.
        let p = test_utils::helper_packet_sent(1, now, MSS);
        r.on_packet_sent(p, EPOCH, HandshakeStatus::default(), now, "");
        assert_eq!(r.get_packet_send_time(now), now);
        assert!(r.get_next_release_time().can_burst());

        let p = test_utils::helper_packet_sent(2, now, MSS);
        r.on_packet_sent(p, EPOCH, HandshakeStatus::default(), now, "");
        assert!(!r.get_next_release_time().can_burst());

        let next = now + rate.transfer_time(quantum);
        assert_eq!(r.get_next_release_time().time(now), Some(next));

        // Packets sent early are stamped with their pacing departure time.
        let p = test_utils::helper_packet_sent(3, now, MSS);
        r.on_packet_sent(p, EPOCH, HandshakeStatus::default(), now, "");
        assert_eq!(r.get_packet_send_time(now), next);
    }

    #[test]
    fn app_limited_marks_samples() {
        let mut r = new_recovery();
        let mut now = Instant::now();

        send(&mut r, 0..2, now);
        r.on_app_limited();
        assert!(r.sampler.is_app_limited());

        now += Duration::from_millis(50);
        ack(&mut r, 0..2, now);
        // The bubble is only gone once data sent after it is delivered
        // (draft-ietf-ccwg-bbr-07 Section 4.1.2.3).
        assert!(r.sampler.is_app_limited());

        send(&mut r, 2..3, now);
        now += Duration::from_millis(50);
        ack(&mut r, 2..3, now);
        assert!(!r.sampler.is_app_limited());
        assert_eq!(r.bbr.state(), State::Startup);
    }

    #[test]
    fn high_pto_count_does_not_panic() {
        let mut r = new_recovery();
        r.pto_count = 99_999;
        let now = Instant::now();
        send(&mut r, 0..1, now);
        let _ = r.pto_time_and_space(HandshakeStatus::default(), now);
    }

    #[test]
    fn pto_does_not_affect_congestion_control() {
        let mut r = new_recovery();
        let now = Instant::now();

        send(&mut r, 0..5, now);
        let cwnd = r.cwnd();

        let timer = r.loss_detection_timer().unwrap();
        let outcome =
            r.on_loss_detection_timeout(HandshakeStatus::default(), timer, "");
        assert_eq!(outcome.lost_packets, 0);
        assert_eq!(r.pto_count, 1);
        assert_eq!(r.loss_probes(EPOCH), 1);
        assert_eq!(r.cwnd(), cwnd);
        assert!(!r.bbr.in_loss_recovery());
    }
}
