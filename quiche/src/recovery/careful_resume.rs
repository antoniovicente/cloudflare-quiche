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

//! Public types for Careful Resume ([RFC 9959]).
//!
//! Careful Resume lets a sender reuse congestion control parameters observed
//! on a previous connection to the same remote endpoint to get up to speed
//! faster, while guarding against the saved parameters no longer being valid.
//!
//! quiche implements the congestion controller side of the mechanism. The
//! application is responsible for storing the saved parameters, which
//! includes:
//!
//! * keying them by remote endpoint (e.g. local and peer address),
//! * expiring them after a configured lifetime (RFC 9959, Section 4.3.1),
//! * making sure a set of saved parameters is only used by one connection at a
//!   time (RFC 9959, Section 3.2), and
//! * deleting them after a connection entered the Safe Retreat Phase (RFC 9959,
//!   Section 3.5).
//!
//! [RFC 9959]: https://www.rfc-editor.org/rfc/rfc9959.html

use std::time::Duration;

/// Congestion control parameters observed on a connection, which can be
/// saved and used to resume a subsequent connection to the same remote
/// endpoint with Careful Resume ([RFC 9959]).
///
/// An observation is obtained from [`PathStats::careful_resume_observation`].
///
/// [RFC 9959]: https://www.rfc-editor.org/rfc/rfc9959.html
/// [`PathStats::careful_resume_observation`]: crate::PathStats::careful_resume_observation
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CarefulResumeParams {
    /// The observed bottleneck bandwidth in bytes per second (the
    /// equivalent of `BBR.max_bw`).
    ///
    /// Applications that want to enforce a maximum jump (`max_jump` in RFC
    /// 9959) can clamp this value before applying it to a new connection.
    pub bandwidth: u64,

    /// The minimum RTT observed on the connection (`saved_rtt` in RFC 9959).
    pub min_rtt: Duration,
}

impl CarefulResumeParams {
    /// Returns the capacity in bytes implied by the saved parameters
    /// (`saved_cwnd` in RFC 9959), i.e. `bandwidth * min_rtt`.
    pub fn saved_cwnd(&self) -> u64 {
        let bytes = self.bandwidth as u128 * self.min_rtt.as_nanos() /
            Duration::from_secs(1).as_nanos();

        bytes.min(u64::MAX as u128) as u64
    }
}

/// The phases of Careful Resume ([RFC 9959, Section 3]).
///
/// [RFC 9959, Section 3]: https://www.rfc-editor.org/rfc/rfc9959.html#section-3
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CarefulResumePhase {
    /// The sender is checking that the current path is consistent with the
    /// saved parameters. The congestion controller is not modified.
    Reconnaissance,

    /// The sender is sending paced packets using the resumed rate, which has
    /// not yet been validated.
    Unvalidated,

    /// The sender is waiting for the packets sent in the Unvalidated Phase to
    /// be acknowledged.
    Validating,

    /// Congestion was detected for unvalidated packets. The sender is
    /// draining the path using a reduced congestion window.
    SafeRetreat,

    /// Careful Resume is no longer in use and the normal congestion
    /// controller is in charge.
    Normal,
}

/// The trigger of a Careful Resume phase transition, as defined in
/// [draft-ietf-tsvwg-careful-resume-qlog].
///
/// [draft-ietf-tsvwg-careful-resume-qlog]: https://datatracker.ietf.org/doc/draft-ietf-tsvwg-careful-resume-qlog/
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CarefulResumeTrigger {
    /// The path was confirmed and the sender had more data to send than the
    /// congestion window allowed.
    CongestionWindowLimited,

    /// More than one RTT passed in the Unvalidated Phase.
    RttExceeded,

    /// The first packet sent in the Unvalidated Phase was acknowledged.
    FirstUnvalidatedPacketAcknowledged,

    /// All unvalidated packets were sent, i.e. the flight size reached the
    /// congestion window.
    LastUnvalidatedPacketSent,

    /// The last packet sent in the Unvalidated Phase was acknowledged.
    LastUnvalidatedPacketAcknowledged,

    /// The current RTT is not consistent with the saved RTT.
    RttNotValidated,

    /// The sender sent fewer unvalidated packets than the congestion window
    /// permitted.
    RateLimited,

    /// A path change was detected, e.g. the RTT decreased significantly.
    PathChanged,

    /// Packet loss was detected.
    PacketLoss,

    /// The Safe Retreat Phase completed.
    ExitRecovery,
}

/// Careful Resume statistics of a path.
///
/// See [`PathStats::careful_resume`].
///
/// [`PathStats::careful_resume`]: crate::PathStats::careful_resume
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CarefulResumeStats {
    /// The current Careful Resume phase.
    pub phase: CarefulResumePhase,

    /// The trigger of the most recent phase transition, if any.
    pub trigger: Option<CarefulResumeTrigger>,

    /// Whether the Safe Retreat Phase was entered.
    ///
    /// When true, the saved parameters used to resume this connection were
    /// found to be invalid and must be deleted by the application ([RFC 9959,
    /// Section 3.5]).
    ///
    /// [RFC 9959, Section 3.5]: https://www.rfc-editor.org/rfc/rfc9959.html#section-3.5
    pub safe_retreat_entered: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ops::Range;
    use std::time::Instant;

    use smallvec::smallvec;

    use crate::packet;
    use crate::ranges::RangeSet;
    use crate::recovery::HandshakeStatus;
    use crate::recovery::Recovery;
    use crate::recovery::RecoveryConfig;
    use crate::recovery::RecoveryOps;
    use crate::recovery::Sent;
    use crate::Config;

    const MSS: usize = 1200;
    const RTT: Duration = Duration::from_millis(100);

    /// 1000 packets of capacity with a 100ms RTT.
    const SAVED: CarefulResumeParams = CarefulResumeParams {
        bandwidth: 12_000_000,
        min_rtt: RTT,
    };

    fn new_recovery(
        cc_algorithm_name: &str, pacing: bool, saved: Option<CarefulResumeParams>,
    ) -> Recovery {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm_name(cc_algorithm_name).unwrap();
        cfg.enable_pacing(pacing);

        let mut recovery_config = RecoveryConfig::from_config(&cfg);
        recovery_config.careful_resume = saved;

        Recovery::new_with_config(&recovery_config)
    }

    fn send(r: &mut Recovery, pkts: Range<u64>, now: Instant) {
        for pkt_num in pkts {
            let p = Sent {
                pkt_num,
                frames: smallvec![],
                time_sent: now,
                time_acked: None,
                time_lost: None,
                size: MSS,
                ack_eliciting: true,
                in_flight: true,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                has_data: true,
                is_pmtud_probe: false,
            };

            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }
    }

    fn ack(r: &mut Recovery, pkts: Range<u64>, now: Instant) -> usize {
        let mut acked = RangeSet::default();
        acked.insert(pkts);

        r.on_ack_received(
            &acked,
            0,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            None,
            "",
        )
        .unwrap()
        .lost_packets
    }

    fn phase(r: &Recovery) -> CarefulResumePhase {
        r.careful_resume_stats().unwrap().phase
    }

    fn trigger(r: &Recovery) -> Option<CarefulResumeTrigger> {
        r.careful_resume_stats().unwrap().trigger
    }

    /// Runs two rounds of 10 packets each, acknowledged after `rtt`, and
    /// returns the time of the last ACK.
    ///
    /// The first round is application limited, as is the case for the
    /// handshake, so Reconnaissance can only complete after the second one.
    fn reconnaissance(r: &mut Recovery, rtt: Duration) -> Instant {
        let mut now = Instant::now();

        for round in 0..2 {
            let pkts = round * 10..(round + 1) * 10;

            send(r, pkts.clone(), now);

            if let Some(stats) = r.careful_resume_stats() {
                assert_eq!(stats.phase, CarefulResumePhase::Reconnaissance);
            }

            now += rtt;
            assert_eq!(ack(r, pkts, now), 0);
        }

        now
    }

    #[test]
    fn unsupported() {
        for (cc, pacing) in
            [("cubic", true), ("reno", true), ("bbr2_gcongestion", false)]
        {
            let r = new_recovery(cc, pacing, Some(SAVED));
            assert_eq!(r.careful_resume_stats(), None);
        }

        let r = new_recovery("bbr2_gcongestion", true, None);
        assert_eq!(r.careful_resume_stats(), None);
    }

    #[test]
    fn resume_validated() {
        let mut r = new_recovery("bbr2_gcongestion", true, Some(SAVED));
        assert_eq!(r.careful_resume_observation(), None);

        let now = reconnaissance(&mut r, RTT);

        assert_eq!(phase(&r), CarefulResumePhase::Unvalidated);
        assert_eq!(
            trigger(&r),
            Some(CarefulResumeTrigger::CongestionWindowLimited)
        );

        // Paced at half the saved bandwidth, with a congestion window of the
        // probing rate times the RTT times the Startup cwnd gain.
        assert_eq!(r.pacing_rate(), SAVED.bandwidth / 2);
        assert_eq!(r.cwnd() as u64, SAVED.saved_cwnd());
        assert_eq!(r.careful_resume_observation(), None);

        send(&mut r, 20..120, now);

        let now = now + RTT;
        assert_eq!(ack(&mut r, 20..30, now), 0);

        assert_eq!(phase(&r), CarefulResumePhase::Validating);
        assert_eq!(
            trigger(&r),
            Some(CarefulResumeTrigger::FirstUnvalidatedPacketAcknowledged)
        );
        assert!(r.pacing_rate() >= SAVED.bandwidth / 2);
        assert_eq!(r.careful_resume_observation(), None);

        assert_eq!(ack(&mut r, 30..119, now), 0);
        assert_eq!(phase(&r), CarefulResumePhase::Validating);

        assert_eq!(ack(&mut r, 119..120, now), 0);

        assert_eq!(
            r.careful_resume_stats(),
            Some(CarefulResumeStats {
                phase: CarefulResumePhase::Normal,
                trigger: Some(
                    CarefulResumeTrigger::LastUnvalidatedPacketAcknowledged
                ),
                safe_retreat_entered: false,
            })
        );

        let observation = r.careful_resume_observation().unwrap();
        assert_eq!(observation.min_rtt, RTT);
        assert!(observation.bandwidth > 0);
    }

    #[test]
    fn resume_safe_retreat() {
        let mut r = new_recovery("bbr2_gcongestion", true, Some(SAVED));

        let now = reconnaissance(&mut r, RTT);
        assert_eq!(phase(&r), CarefulResumePhase::Unvalidated);

        send(&mut r, 20..120, now);

        let now = now + RTT;
        assert_eq!(ack(&mut r, 20..30, now), 0);
        assert_eq!(phase(&r), CarefulResumePhase::Validating);
        assert_eq!(ack(&mut r, 30..70, now), 0);

        // Packets 70, 71 and 72 are lost.
        assert_eq!(ack(&mut r, 73..110, now), 3);

        assert_eq!(
            r.careful_resume_stats(),
            Some(CarefulResumeStats {
                phase: CarefulResumePhase::SafeRetreat,
                trigger: Some(CarefulResumeTrigger::PacketLoss),
                safe_retreat_entered: true,
            })
        );
        assert_eq!(
            r.startup_exit().map(|e| e.reason),
            Some(crate::StartupExitReason::Loss)
        );

        // The PipeSize is 87 packets, the congestion window is capped at half
        // of that.
        assert!(r.cwnd() <= 87 * MSS / 2);
        assert_eq!(r.careful_resume_observation(), None);

        // The congestion window is not increased in Safe Retreat.
        let cwnd = r.cwnd();
        send(&mut r, 120..130, now);
        assert_eq!(ack(&mut r, 110..115, now), 0);
        assert!(r.cwnd() <= cwnd);
        assert_eq!(phase(&r), CarefulResumePhase::SafeRetreat);

        // The last unvalidated packet is acknowledged.
        assert_eq!(ack(&mut r, 115..130, now + RTT), 0);

        assert_eq!(
            r.careful_resume_stats(),
            Some(CarefulResumeStats {
                phase: CarefulResumePhase::Normal,
                trigger: Some(CarefulResumeTrigger::ExitRecovery),
                safe_retreat_entered: true,
            })
        );

        // Observations are not provided after the saved parameters were found
        // to be invalid.
        assert_eq!(r.careful_resume_observation(), None);
    }

    #[test]
    fn resume_loss_during_reconnaissance() {
        let mut r = new_recovery("bbr2_gcongestion", true, Some(SAVED));
        let now = Instant::now();

        send(&mut r, 0..10, now);

        // Packets 0 to 3 are lost.
        assert_eq!(ack(&mut r, 4..10, now + RTT), 4);

        assert_eq!(
            r.careful_resume_stats(),
            Some(CarefulResumeStats {
                phase: CarefulResumePhase::Normal,
                trigger: Some(CarefulResumeTrigger::PacketLoss),
                safe_retreat_entered: false,
            })
        );
    }

    #[test]
    fn resume_rtt_not_validated() {
        let saved = CarefulResumeParams {
            min_rtt: RTT * 3,
            ..SAVED
        };
        let mut r = new_recovery("bbr2_gcongestion", true, Some(saved));
        let mut normal = new_recovery("bbr2_gcongestion", true, None);

        reconnaissance(&mut r, RTT);
        reconnaissance(&mut normal, RTT);

        assert_eq!(phase(&r), CarefulResumePhase::Normal);
        assert_eq!(trigger(&r), Some(CarefulResumeTrigger::RttNotValidated));

        // The congestion controller is not modified.
        assert_eq!(r.cwnd(), normal.cwnd());
        assert_eq!(r.pacing_rate(), normal.pacing_rate());
    }

    #[test]
    fn resume_rate_limited() {
        let mut r = new_recovery("bbr2_gcongestion", true, Some(SAVED));

        let now = reconnaissance(&mut r, RTT);
        assert_eq!(phase(&r), CarefulResumePhase::Unvalidated);

        // Only two unvalidated packets are sent.
        send(&mut r, 20..22, now);
        assert_eq!(ack(&mut r, 20..22, now + RTT), 0);

        assert_eq!(phase(&r), CarefulResumePhase::Normal);
        assert_eq!(trigger(&r), Some(CarefulResumeTrigger::RateLimited));

        // The resumed congestion window and pacing rate are not retained.
        assert!(r.cwnd() < 100 * MSS);
        assert!(r.pacing_rate() < SAVED.bandwidth / 2);
    }

    #[test]
    fn saved_cwnd() {
        let params = CarefulResumeParams {
            bandwidth: 1_250_000,
            min_rtt: Duration::from_millis(100),
        };

        assert_eq!(params.saved_cwnd(), 125_000);

        let params = CarefulResumeParams {
            bandwidth: u64::MAX,
            min_rtt: Duration::from_secs(10),
        };

        assert_eq!(params.saved_cwnd(), u64::MAX);
    }
}
