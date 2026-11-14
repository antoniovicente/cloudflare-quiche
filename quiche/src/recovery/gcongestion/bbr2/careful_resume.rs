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

//! Careful Resume ([RFC 9959]) for BBRv2.
//!
//! The phases map onto BBR as described in Appendix C of RFC 9959:
//!
//! * Reconnaissance: BBR runs unmodified until a round trip completes without
//!   congestion, the RTT is consistent with the saved RTT and the sender is not
//!   application limited.
//! * Unvalidated: entered at the start of a BBR round while in Startup. The
//!   pacing rate is raised to at least the probing rate (half the saved
//!   bandwidth, and no more than half the saved capacity per current RTT), and
//!   the congestion window to at least the probing rate times the current RTT
//!   times the Startup cwnd gain.
//! * Validating: the pacing rate keeps being at least the probing rate, while
//!   the congestion window is managed by BBR Startup.
//! * Safe Retreat: entered when congestion is detected (or Startup is exited)
//!   while Unvalidated or Validating. BBR is moved to Drain, the congestion
//!   window is capped at half the PipeSize and is not increased, and delivery
//!   rate samples taken in Drain are discarded. On exit, `inflight_hi` (the BBR
//!   equivalent of ssthresh) is limited to `PipeSize * Beta`.
//!
//! [RFC 9959]: https://www.rfc-editor.org/rfc/rfc9959.html

#[cfg(feature = "qlog")]
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::recovery::careful_resume::CarefulResumeParams;
use crate::recovery::careful_resume::CarefulResumePhase;
#[cfg(feature = "qlog")]
use crate::recovery::careful_resume::CarefulResumePhaseUpdate;
use crate::recovery::careful_resume::CarefulResumeStats;
use crate::recovery::careful_resume::CarefulResumeTrigger;
use crate::recovery::gcongestion::Bandwidth;

/// Scaling factor applied to the PipeSize to compute the BBR equivalent of
/// ssthresh when leaving the Safe Retreat Phase (RFC 9959, Section 3.5).
const SAFE_RETREAT_BETA: f64 = 0.5;

/// A current RTT more than this many times the saved RTT indicates a path
/// change (RFC 9959, Section 4.2.1).
const MAX_RTT_INCREASE_FACTOR: u32 = 10;

/// Observations with a capacity smaller than this many initial congestion
/// windows are not worth saving (RFC 9959, Section 3.1).
const MIN_SAVED_CWND_IN_INITIAL_WINDOWS: usize = 4;

/// Tracks the validated capacity, i.e. the PipeSize.
///
/// The PipeSize is initialized to the flight size on entry to the Unvalidated
/// Phase. Because the packets in flight on entry are acknowledged first, the
/// PipeSize is the larger of the entry flight size and the bytes acknowledged
/// since entering the Unvalidated Phase.
#[derive(Debug, Clone, Copy)]
struct PipeSize {
    entry_flight_size: usize,
    acked: usize,
}

impl PipeSize {
    fn get(&self) -> usize {
        self.entry_flight_size.max(self.acked)
    }

    fn on_ack(&mut self, bytes_acked: usize) {
        self.acked = self.acked.saturating_add(bytes_acked);
    }
}

#[derive(Debug)]
struct Unvalidated {
    start_time: Instant,
    pipe_size: PipeSize,
    /// Packet number of the first packet sent in the Unvalidated Phase.
    first_pkt: Option<u64>,
    /// Packet number of the last packet sent in the Unvalidated Phase.
    last_pkt: Option<u64>,
    probing_rate: Bandwidth,
    /// The RTT the probing rate was derived from.
    current_rtt: Duration,
}

#[derive(Debug)]
struct Validating {
    pipe_size: PipeSize,
    first_pkt: u64,
    last_pkt: u64,
    probing_rate: Bandwidth,
}

#[derive(Debug)]
struct SafeRetreat {
    pipe_size: PipeSize,
    /// Packet number of the first unvalidated packet, only used for logging.
    #[cfg(feature = "qlog")]
    first_pkt: Option<u64>,
    last_pkt: Option<u64>,
    /// Upper bound for the congestion window. This never increases.
    cwnd_cap: usize,
}

#[derive(Debug)]
enum State {
    Reconnaissance,
    Unvalidated(Unvalidated),
    Validating(Validating),
    SafeRetreat(SafeRetreat),
    Normal,
}

impl State {
    fn phase(&self) -> CarefulResumePhase {
        match self {
            State::Reconnaissance => CarefulResumePhase::Reconnaissance,
            State::Unvalidated(_) => CarefulResumePhase::Unvalidated,
            State::Validating(_) => CarefulResumePhase::Validating,
            State::SafeRetreat(_) => CarefulResumePhase::SafeRetreat,
            State::Normal => CarefulResumePhase::Normal,
        }
    }

    #[cfg(feature = "qlog")]
    fn pipe_size(&self) -> usize {
        match self {
            State::Reconnaissance | State::Normal => 0,
            State::Unvalidated(s) => s.pipe_size.get(),
            State::Validating(s) => s.pipe_size.get(),
            State::SafeRetreat(s) => s.pipe_size.get(),
        }
    }

    #[cfg(feature = "qlog")]
    fn unvalidated_pkts(&self) -> (Option<u64>, Option<u64>) {
        match self {
            State::Reconnaissance | State::Normal => (None, None),
            State::Unvalidated(s) => (s.first_pkt, s.last_pkt),
            State::Validating(s) => (Some(s.first_pkt), Some(s.last_pkt)),
            State::SafeRetreat(s) => (s.first_pkt, s.last_pkt),
        }
    }
}

/// Congestion controller state needed by Careful Resume.
pub(super) struct CongestionContext {
    pub cwnd: usize,
    pub initial_cwnd: usize,
    pub min_cwnd: usize,
    pub max_cwnd: usize,
    pub startup_cwnd_gain: f32,
    pub in_startup: bool,
    pub in_drain: bool,
}

/// A summary of a congestion event.
pub(super) struct CongestionEventInfo {
    pub now: Instant,
    pub largest_acked: Option<u64>,
    pub bytes_acked: usize,
    pub bytes_lost: usize,
    /// Bytes in flight after processing the event.
    pub bytes_in_flight: usize,
    pub end_of_round_trip: bool,
    pub is_app_limited: bool,
    pub min_rtt: Option<Duration>,
    pub smoothed_rtt: Duration,
}

/// Changes to the congestion controller requested by Careful Resume after a
/// phase transition.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Action {
    None,

    /// Set the congestion window, e.g. to the flight size on entry to the
    /// Validating Phase.
    SetCwnd(usize),

    /// Careful Resume stopped because the sender was rate limited. Reset the
    /// congestion window to the given value and the pacing rate to the
    /// nominal rate.
    ResetCwnd(usize),

    /// Safe Retreat was entered. Startup must be exited.
    ExitStartup,

    /// Safe Retreat was completed. `inflight_hi` must be limited to the
    /// given value.
    LimitInflightHi(usize),
}

#[derive(Debug)]
pub(super) struct CarefulResume {
    saved: CarefulResumeParams,
    state: State,
    trigger: Option<CarefulResumeTrigger>,
    safe_retreat_entered: bool,
    largest_acked: Option<u64>,

    #[cfg(feature = "qlog")]
    qlog_updates: VecDeque<CarefulResumePhaseUpdate>,
}

impl CarefulResume {
    /// Creates a new Careful Resume state machine, if the saved parameters
    /// are usable.
    pub(super) fn new(saved: CarefulResumeParams) -> Option<Self> {
        if saved.bandwidth == 0 || saved.min_rtt.is_zero() {
            return None;
        }

        let mut cr = CarefulResume {
            saved,
            state: State::Reconnaissance,
            trigger: None,
            safe_retreat_entered: false,
            largest_acked: None,

            #[cfg(feature = "qlog")]
            qlog_updates: VecDeque::new(),
        };

        cr.record_update(None, None);

        Some(cr)
    }

    pub(super) fn phase(&self) -> CarefulResumePhase {
        self.state.phase()
    }

    pub(super) fn stats(&self) -> CarefulResumeStats {
        CarefulResumeStats {
            phase: self.phase(),
            trigger: self.trigger,
            safe_retreat_entered: self.safe_retreat_entered,
        }
    }

    /// Whether the current congestion state may be observed and saved for
    /// future connections.
    pub(super) fn allows_observation(&self) -> bool {
        if self.safe_retreat_entered {
            // The saved parameters were found to be invalid, and the current
            // bandwidth estimate might have been measured while overloading
            // the path.
            return false;
        }

        match self.state {
            // Reconnaissance does not modify the congestion controller.
            State::Reconnaissance | State::Normal => true,

            State::Unvalidated(_) |
            State::Validating(_) |
            State::SafeRetreat(_) => false,
        }
    }

    /// Whether delivery rate samples must be discarded.
    pub(super) fn discards_bandwidth_samples(&self, in_drain: bool) -> bool {
        matches!(self.state, State::SafeRetreat(_)) && in_drain
    }

    #[cfg(feature = "qlog")]
    pub(super) fn next_qlog_update(
        &mut self,
    ) -> Option<CarefulResumePhaseUpdate> {
        self.qlog_updates.pop_front()
    }

    fn transition(&mut self, new: State, trigger: Option<CarefulResumeTrigger>) {
        let old = self.state.phase();

        debug!(
            "careful resume: {:?} -> {:?} trigger={:?}",
            old,
            new.phase(),
            trigger
        );

        if matches!(new, State::SafeRetreat(_)) {
            self.safe_retreat_entered = true;
        }

        self.state = new;
        self.trigger = trigger;

        self.record_update(Some(old), trigger);
    }

    #[cfg(feature = "qlog")]
    fn record_update(
        &mut self, old: Option<CarefulResumePhase>,
        trigger: Option<CarefulResumeTrigger>,
    ) {
        let (first, last) = self.state.unvalidated_pkts();

        self.qlog_updates.push_back(CarefulResumePhaseUpdate {
            old,
            new: self.state.phase(),
            trigger,
            pipe_size: self.state.pipe_size() as u64,
            first_unvalidated_packet: first.unwrap_or(0),
            last_unvalidated_packet: last.unwrap_or(0),
            restored: old.is_none().then_some(self.saved),
        });
    }

    #[cfg(not(feature = "qlog"))]
    fn record_update(
        &mut self, _old: Option<CarefulResumePhase>,
        _trigger: Option<CarefulResumeTrigger>,
    ) {
    }

    /// Whether `min_rtt` is consistent with the saved RTT (RFC 9959, Section
    /// 4.2.1).
    fn rtt_confirmed(&self, min_rtt: Duration) -> bool {
        min_rtt > self.saved.min_rtt / 2 &&
            min_rtt <= self.saved.min_rtt * MAX_RTT_INCREASE_FACTOR
    }

    /// Must be called for every in-flight packet sent, after the packet was
    /// accounted in `bytes_in_flight`.
    pub(super) fn on_packet_sent(
        &mut self, pkt_num: u64, bytes_in_flight: usize, cwnd: usize, mss: usize,
        initial_cwnd: usize,
    ) -> Action {
        let State::Unvalidated(s) = &mut self.state else {
            return Action::None;
        };

        s.first_pkt.get_or_insert(pkt_num);
        s.last_pkt = Some(pkt_num);

        // The remaining unused congestion window is less than one maximum
        // sized packet.
        if bytes_in_flight.saturating_add(mss) > cwnd {
            return self.exit_unvalidated(
                bytes_in_flight,
                CarefulResumeTrigger::LastUnvalidatedPacketSent,
                initial_cwnd,
            );
        }

        Action::None
    }

    /// Processes a congestion event, before BBR's state machine.
    pub(super) fn on_congestion_event(
        &mut self, ev: &CongestionEventInfo, cc: &CongestionContext,
    ) -> Action {
        if let Some(largest_acked) = ev.largest_acked {
            self.largest_acked = self.largest_acked.max(Some(largest_acked));
        }

        match &mut self.state {
            State::Reconnaissance => self.on_reconnaissance_event(ev, cc),

            State::Unvalidated(s) => {
                s.pipe_size.on_ack(ev.bytes_acked);

                if ev.bytes_lost > 0 {
                    return self.enter_safe_retreat(
                        Some(CarefulResumeTrigger::PacketLoss),
                        cc,
                    );
                }

                if let Some(min_rtt) = ev.min_rtt {
                    if min_rtt <= self.saved.min_rtt / 2 {
                        return self.enter_safe_retreat(
                            Some(CarefulResumeTrigger::PathChanged),
                            cc,
                        );
                    }
                }

                let first_acked = matches!(
                    (s.first_pkt, self.largest_acked),
                    (Some(first), Some(largest)) if largest >= first
                );

                if first_acked {
                    return self.exit_unvalidated(
                        ev.bytes_in_flight,
                        CarefulResumeTrigger::FirstUnvalidatedPacketAcknowledged,
                        cc.initial_cwnd,
                    );
                }

                if ev.now.saturating_duration_since(s.start_time) >
                    ev.smoothed_rtt
                {
                    return self.exit_unvalidated(
                        ev.bytes_in_flight,
                        CarefulResumeTrigger::RttExceeded,
                        cc.initial_cwnd,
                    );
                }

                Action::None
            },

            State::Validating(s) => {
                s.pipe_size.on_ack(ev.bytes_acked);

                if ev.bytes_lost > 0 {
                    return self.enter_safe_retreat(
                        Some(CarefulResumeTrigger::PacketLoss),
                        cc,
                    );
                }

                if self.largest_acked >= Some(s.last_pkt) {
                    self.transition(
                        State::Normal,
                        Some(CarefulResumeTrigger::LastUnvalidatedPacketAcknowledged),
                    );
                }

                Action::None
            },

            State::SafeRetreat(s) => {
                s.pipe_size.on_ack(ev.bytes_acked);
                Action::None
            },

            State::Normal => Action::None,
        }
    }

    /// Processes the outcome of BBR's state machine for a congestion event.
    pub(super) fn on_mode_updated(&mut self, cc: &CongestionContext) -> Action {
        match &self.state {
            State::Unvalidated(_) | State::Validating(_) if !cc.in_startup => {
                // BBR left Startup while unvalidated packets were in flight
                // (RFC 9959, Appendix C.3).
                let action = self.enter_safe_retreat(None, cc);
                debug_assert_eq!(action, Action::ExitStartup);
                Action::None
            },

            State::SafeRetreat(s) if !cc.in_drain => {
                let last_acked = match s.last_pkt {
                    Some(last) => self.largest_acked >= Some(last),
                    None => true,
                };

                if !last_acked {
                    return Action::None;
                }

                let ssthresh =
                    (s.pipe_size.get() as f64 * SAFE_RETREAT_BETA) as usize;

                self.transition(
                    State::Normal,
                    Some(CarefulResumeTrigger::ExitRecovery),
                );

                Action::LimitInflightHi(ssthresh.max(cc.min_cwnd))
            },

            _ => Action::None,
        }
    }

    /// Adjusts the congestion window and pacing rate computed by BBR.
    pub(super) fn adjust(
        &mut self, cwnd: &mut usize, pacing_rate: &mut Bandwidth,
        bandwidth_estimate: Bandwidth, cc: &CongestionContext,
    ) {
        match &mut self.state {
            State::Unvalidated(s) => {
                *pacing_rate = (*pacing_rate).max(s.probing_rate);

                let cr_cwnd = (bandwidth_estimate.max(s.probing_rate) *
                    cc.startup_cwnd_gain)
                    .to_bytes_per_period(s.current_rtt)
                    as usize;

                *cwnd = (*cwnd).max(cr_cwnd.min(cc.max_cwnd));
            },

            State::Validating(s) => {
                *pacing_rate = (*pacing_rate).max(s.probing_rate);
            },

            State::SafeRetreat(s) => {
                s.cwnd_cap = s.cwnd_cap.min(*cwnd);
                *cwnd = s.cwnd_cap;
            },

            State::Reconnaissance | State::Normal => (),
        }
    }

    fn on_reconnaissance_event(
        &mut self, ev: &CongestionEventInfo, cc: &CongestionContext,
    ) -> Action {
        if ev.bytes_lost > 0 {
            self.transition(
                State::Normal,
                Some(CarefulResumeTrigger::PacketLoss),
            );
            return Action::None;
        }

        if !cc.in_startup {
            // Unvalidated packets can only be sent in Startup (RFC 9959,
            // Appendix C.1).
            self.transition(State::Normal, None);
            return Action::None;
        }

        // The Unvalidated Phase starts at the beginning of a BBR round, once
        // the data sent in the previous round was acknowledged without
        // congestion. It is deferred until the sender is not rate limited.
        if !ev.end_of_round_trip || ev.is_app_limited {
            return Action::None;
        }

        let Some(current_rtt) = ev.min_rtt else {
            return Action::None;
        };

        if !self.rtt_confirmed(current_rtt) {
            self.transition(
                State::Normal,
                Some(CarefulResumeTrigger::RttNotValidated),
            );
            return Action::None;
        }

        let jump_cwnd = usize::try_from(self.saved.saved_cwnd() / 2)
            .unwrap_or(usize::MAX)
            .min(cc.max_cwnd);

        if jump_cwnd <= cc.cwnd {
            // Jumping would not increase the congestion window.
            self.transition(State::Normal, None);
            return Action::None;
        }

        // Pace at no more than half the saved bandwidth, and based on the
        // current RTT (RFC 9959, Section 4.3.2 and Appendix C.1).
        let saved_bw = Bandwidth::from_bytes_per_second(
            self.saved.bandwidth.min(u64::MAX / 8),
        );
        let probing_rate =
            Bandwidth::from_bytes_and_time_delta(jump_cwnd, current_rtt)
                .min(saved_bw * 0.5);

        self.transition(
            State::Unvalidated(Unvalidated {
                start_time: ev.now,
                pipe_size: PipeSize {
                    entry_flight_size: ev.bytes_in_flight,
                    acked: 0,
                },
                first_pkt: None,
                last_pkt: None,
                probing_rate,
                current_rtt,
            }),
            Some(CarefulResumeTrigger::CongestionWindowLimited),
        );

        Action::None
    }

    /// Leaves the Unvalidated Phase, either to the Validating Phase or, if
    /// the sender was rate limited, to Normal (RFC 9959, Section 3.3).
    fn exit_unvalidated(
        &mut self, flight_size: usize, trigger: CarefulResumeTrigger,
        initial_cwnd: usize,
    ) -> Action {
        let State::Unvalidated(s) = &self.state else {
            return Action::None;
        };

        let pipe_size = s.pipe_size;

        match (s.first_pkt, s.last_pkt) {
            (Some(first_pkt), Some(last_pkt))
                if flight_size >= initial_cwnd &&
                    flight_size > pipe_size.get() =>
            {
                let probing_rate = s.probing_rate;

                self.transition(
                    State::Validating(Validating {
                        pipe_size,
                        first_pkt,
                        last_pkt,
                        probing_rate,
                    }),
                    Some(trigger),
                );

                Action::SetCwnd(flight_size)
            },

            _ => {
                self.transition(
                    State::Normal,
                    Some(CarefulResumeTrigger::RateLimited),
                );

                // In the absence of congestion the congestion window is not
                // reduced below the initial window.
                Action::ResetCwnd(pipe_size.get().max(initial_cwnd))
            },
        }
    }

    fn enter_safe_retreat(
        &mut self, trigger: Option<CarefulResumeTrigger>, cc: &CongestionContext,
    ) -> Action {
        let (pipe_size, first_pkt, last_pkt) = match &self.state {
            State::Unvalidated(s) => (s.pipe_size, s.first_pkt, s.last_pkt),
            State::Validating(s) =>
                (s.pipe_size, Some(s.first_pkt), Some(s.last_pkt)),
            State::Reconnaissance | State::SafeRetreat(_) | State::Normal =>
                return Action::None,
        };

        // The first unvalidated packet is only needed for logging.
        #[cfg(not(feature = "qlog"))]
        let _ = first_pkt;

        // Reduce the congestion window to no more than half the PipeSize, to
        // allow other flows to regain their share of the capacity.
        let cwnd_cap = (pipe_size.get() / 2).max(cc.min_cwnd).min(cc.cwnd);

        self.transition(
            State::SafeRetreat(SafeRetreat {
                pipe_size,
                #[cfg(feature = "qlog")]
                first_pkt,
                last_pkt,
                cwnd_cap,
            }),
            trigger,
        );

        Action::ExitStartup
    }
}

/// Returns the parameters to save for future connections, given the current
/// bandwidth estimate and minimum RTT.
pub(super) fn observation(
    max_bandwidth: Bandwidth, min_rtt: Option<Duration>, initial_cwnd: usize,
) -> Option<CarefulResumeParams> {
    let min_rtt = min_rtt?;

    if max_bandwidth == Bandwidth::zero() || min_rtt.is_zero() {
        return None;
    }

    let params = CarefulResumeParams {
        bandwidth: max_bandwidth.to_bytes_per_second(),
        min_rtt,
    };

    let min_saved_cwnd =
        initial_cwnd as u64 * MIN_SAVED_CWND_IN_INITIAL_WINDOWS as u64;

    if params.saved_cwnd() < min_saved_cwnd {
        return None;
    }

    Some(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: usize = 1200;
    const IW: usize = 10 * MSS;
    const RTT: Duration = Duration::from_millis(100);

    fn saved() -> CarefulResumeParams {
        // 1000 packets of capacity.
        CarefulResumeParams {
            bandwidth: (1000 * MSS) as u64 * 10,
            min_rtt: RTT,
        }
    }

    fn cc(in_startup: bool, in_drain: bool, cwnd: usize) -> CongestionContext {
        CongestionContext {
            cwnd,
            initial_cwnd: IW,
            min_cwnd: IW,
            max_cwnd: 20_000 * MSS,
            startup_cwnd_gain: 2.0,
            in_startup,
            in_drain,
        }
    }

    fn ev(now: Instant) -> CongestionEventInfo {
        CongestionEventInfo {
            now,
            largest_acked: None,
            bytes_acked: 0,
            bytes_lost: 0,
            bytes_in_flight: 0,
            end_of_round_trip: false,
            is_app_limited: false,
            min_rtt: Some(RTT),
            smoothed_rtt: RTT,
        }
    }

    /// Drives the state machine into the Unvalidated Phase and sends
    /// `unvalidated` packets, starting at packet number 10.
    fn enter_unvalidated(cr: &mut CarefulResume, now: Instant) {
        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(9),
                bytes_acked: IW,
                bytes_in_flight: 0,
                end_of_round_trip: true,
                ..ev(now)
            },
            &cc(true, false, 2 * IW),
        );
        assert_eq!(action, Action::None);
        assert_eq!(cr.phase(), CarefulResumePhase::Unvalidated);
        assert_eq!(
            cr.stats().trigger,
            Some(CarefulResumeTrigger::CongestionWindowLimited)
        );
    }

    #[test]
    fn invalid_params() {
        assert!(CarefulResume::new(CarefulResumeParams {
            bandwidth: 0,
            min_rtt: RTT,
        })
        .is_none());

        assert!(CarefulResume::new(CarefulResumeParams {
            bandwidth: 1000,
            min_rtt: Duration::ZERO,
        })
        .is_none());
    }

    #[test]
    fn reconnaissance_loss() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        assert_eq!(cr.phase(), CarefulResumePhase::Reconnaissance);
        assert!(cr.allows_observation());

        let now = Instant::now();
        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                bytes_lost: MSS,
                end_of_round_trip: true,
                ..ev(now)
            },
            &cc(true, false, IW),
        );

        assert_eq!(action, Action::None);
        assert_eq!(cr.stats(), CarefulResumeStats {
            phase: CarefulResumePhase::Normal,
            trigger: Some(CarefulResumeTrigger::PacketLoss),
            safe_retreat_entered: false,
        });
    }

    #[test]
    fn reconnaissance_waits_for_round_and_not_app_limited() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        cr.on_congestion_event(&ev(now), &cc(true, false, IW));
        assert_eq!(cr.phase(), CarefulResumePhase::Reconnaissance);

        cr.on_congestion_event(
            &CongestionEventInfo {
                end_of_round_trip: true,
                is_app_limited: true,
                ..ev(now)
            },
            &cc(true, false, IW),
        );
        assert_eq!(cr.phase(), CarefulResumePhase::Reconnaissance);

        cr.on_congestion_event(
            &CongestionEventInfo {
                end_of_round_trip: true,
                min_rtt: None,
                ..ev(now)
            },
            &cc(true, false, IW),
        );
        assert_eq!(cr.phase(), CarefulResumePhase::Reconnaissance);

        enter_unvalidated(&mut cr, now);
    }

    #[test]
    fn reconnaissance_rtt_not_validated() {
        for rtt in [RTT / 2, RTT * 10 + Duration::from_millis(1)] {
            let mut cr = CarefulResume::new(saved()).unwrap();

            cr.on_congestion_event(
                &CongestionEventInfo {
                    end_of_round_trip: true,
                    min_rtt: Some(rtt),
                    ..ev(Instant::now())
                },
                &cc(true, false, IW),
            );

            assert_eq!(
                cr.stats().trigger,
                Some(CarefulResumeTrigger::RttNotValidated)
            );
            assert_eq!(cr.phase(), CarefulResumePhase::Normal);
        }
    }

    #[test]
    fn reconnaissance_no_jump() {
        let mut cr = CarefulResume::new(saved()).unwrap();

        // The current window already exceeds half the saved capacity.
        cr.on_congestion_event(
            &CongestionEventInfo {
                end_of_round_trip: true,
                ..ev(Instant::now())
            },
            &cc(true, false, 600 * MSS),
        );

        assert_eq!(cr.phase(), CarefulResumePhase::Normal);
        assert_eq!(cr.stats().trigger, None);
    }

    #[test]
    fn reconnaissance_startup_exited() {
        let mut cr = CarefulResume::new(saved()).unwrap();

        cr.on_congestion_event(
            &CongestionEventInfo {
                end_of_round_trip: true,
                ..ev(Instant::now())
            },
            &cc(false, true, IW),
        );

        assert_eq!(cr.phase(), CarefulResumePhase::Normal);
    }

    #[test]
    fn unvalidated_pacing_and_cwnd() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);
        assert!(!cr.allows_observation());

        let mut cwnd = 2 * IW;
        let mut pacing_rate = Bandwidth::from_bytes_per_second(100_000);
        cr.adjust(
            &mut cwnd,
            &mut pacing_rate,
            Bandwidth::zero(),
            &cc(true, false, IW),
        );

        // Half the saved bandwidth.
        let probing_rate =
            Bandwidth::from_bytes_per_second(saved().bandwidth) * 0.5;
        assert_eq!(pacing_rate, probing_rate);

        // probing_rate * RTT * 2 == saved_cwnd.
        assert_eq!(cwnd as u64, saved().saved_cwnd());
    }

    #[test]
    fn unvalidated_pacing_uses_current_rtt() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        // The current RTT is twice the saved RTT, so the rate must be halved.
        cr.on_congestion_event(
            &CongestionEventInfo {
                end_of_round_trip: true,
                min_rtt: Some(RTT * 2),
                ..ev(now)
            },
            &cc(true, false, IW),
        );
        assert_eq!(cr.phase(), CarefulResumePhase::Unvalidated);

        let mut cwnd = IW;
        let mut pacing_rate = Bandwidth::zero();
        cr.adjust(
            &mut cwnd,
            &mut pacing_rate,
            Bandwidth::zero(),
            &cc(true, false, IW),
        );

        let expected = Bandwidth::from_bytes_and_time_delta(
            (saved().saved_cwnd() / 2) as usize,
            RTT * 2,
        );
        assert_eq!(pacing_rate, expected);
    }

    #[test]
    fn unvalidated_to_validating_to_normal() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);

        let cwnd = 1000 * MSS;
        for (i, pkt) in (10..60).enumerate() {
            let action =
                cr.on_packet_sent(pkt, (i + 1) * MSS + IW, cwnd, MSS, IW);
            assert_eq!(action, Action::None);
        }

        // First unvalidated packet acked.
        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(10),
                bytes_acked: MSS,
                bytes_in_flight: 49 * MSS + IW,
                ..ev(now + RTT)
            },
            &cc(true, false, IW),
        );
        assert_eq!(action, Action::SetCwnd(49 * MSS + IW));
        assert_eq!(
            cr.stats().trigger,
            Some(CarefulResumeTrigger::FirstUnvalidatedPacketAcknowledged)
        );
        assert_eq!(cr.phase(), CarefulResumePhase::Validating);

        // Packets sent while validating are not unvalidated.
        assert_eq!(cr.on_packet_sent(60, cwnd, cwnd, MSS, IW), Action::None);

        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(58),
                bytes_acked: 48 * MSS,
                ..ev(now + RTT * 2)
            },
            &cc(true, false, IW),
        );
        assert_eq!(action, Action::None);
        assert_eq!(cr.phase(), CarefulResumePhase::Validating);

        cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(59),
                bytes_acked: MSS,
                ..ev(now + RTT * 2)
            },
            &cc(true, false, IW),
        );
        assert_eq!(cr.stats(), CarefulResumeStats {
            phase: CarefulResumePhase::Normal,
            trigger: Some(
                CarefulResumeTrigger::LastUnvalidatedPacketAcknowledged
            ),
            safe_retreat_entered: false,
        });
        assert!(cr.allows_observation());
    }

    #[test]
    fn unvalidated_cwnd_filled() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);

        let cwnd = 20 * MSS;
        assert_eq!(cr.on_packet_sent(10, 10 * MSS, cwnd, MSS, IW), Action::None);
        let action = cr.on_packet_sent(11, 20 * MSS, cwnd, MSS, IW);

        assert_eq!(action, Action::SetCwnd(20 * MSS));
        assert_eq!(
            cr.stats().trigger,
            Some(CarefulResumeTrigger::LastUnvalidatedPacketSent)
        );
        assert_eq!(cr.phase(), CarefulResumePhase::Validating);
    }

    #[test]
    fn unvalidated_rate_limited() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);

        // Only a couple of unvalidated packets are sent.
        cr.on_packet_sent(10, MSS, 1000 * MSS, MSS, IW);
        cr.on_packet_sent(11, 2 * MSS, 1000 * MSS, MSS, IW);

        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(10),
                bytes_acked: MSS,
                bytes_in_flight: MSS,
                ..ev(now + RTT)
            },
            &cc(true, false, 1000 * MSS),
        );

        assert_eq!(action, Action::ResetCwnd(IW));
        assert_eq!(cr.stats(), CarefulResumeStats {
            phase: CarefulResumePhase::Normal,
            trigger: Some(CarefulResumeTrigger::RateLimited),
            safe_retreat_entered: false,
        });
    }

    #[test]
    fn unvalidated_rtt_exceeded() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);

        let cwnd = 1000 * MSS;
        for (i, pkt) in (10..40).enumerate() {
            cr.on_packet_sent(pkt, (i + 1) * MSS, cwnd, MSS, IW);
        }

        // An ACK unrelated to unvalidated packets arrives after more than one
        // RTT.
        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(9),
                bytes_in_flight: 30 * MSS,
                ..ev(now + RTT + Duration::from_millis(1))
            },
            &cc(true, false, IW),
        );

        assert_eq!(action, Action::SetCwnd(30 * MSS));
        assert_eq!(cr.stats().trigger, Some(CarefulResumeTrigger::RttExceeded));
        assert_eq!(cr.phase(), CarefulResumePhase::Validating);
    }

    #[test]
    fn unvalidated_path_changed() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);

        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                min_rtt: Some(RTT / 2),
                ..ev(now)
            },
            &cc(true, false, 1000 * MSS),
        );

        assert_eq!(action, Action::ExitStartup);
        assert_eq!(cr.stats(), CarefulResumeStats {
            phase: CarefulResumePhase::SafeRetreat,
            trigger: Some(CarefulResumeTrigger::PathChanged),
            safe_retreat_entered: true,
        });
    }

    #[test]
    fn validating_loss_safe_retreat() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);

        let mut cwnd = 1000 * MSS;
        for (i, pkt) in (10..110).enumerate() {
            cr.on_packet_sent(pkt, (i + 1) * MSS, cwnd, MSS, IW);
        }

        cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(10),
                bytes_acked: MSS,
                bytes_in_flight: 99 * MSS,
                ..ev(now + RTT)
            },
            &cc(true, false, IW),
        );
        assert_eq!(cr.phase(), CarefulResumePhase::Validating);

        // 59 more packets are acked (PipeSize = 60 packets), then one is lost.
        cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(69),
                bytes_acked: 59 * MSS,
                bytes_in_flight: 40 * MSS,
                ..ev(now + RTT)
            },
            &cc(true, false, IW),
        );

        let action = cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(73),
                bytes_acked: 3 * MSS,
                bytes_lost: MSS,
                bytes_in_flight: 36 * MSS,
                ..ev(now + RTT)
            },
            &cc(true, false, 1000 * MSS),
        );

        assert_eq!(action, Action::ExitStartup);
        assert_eq!(cr.stats(), CarefulResumeStats {
            phase: CarefulResumePhase::SafeRetreat,
            trigger: Some(CarefulResumeTrigger::PacketLoss),
            safe_retreat_entered: true,
        });
        assert!(!cr.allows_observation());

        // The congestion window is capped at PipeSize / 2.
        let mut pacing_rate = Bandwidth::zero();
        cr.adjust(
            &mut cwnd,
            &mut pacing_rate,
            Bandwidth::zero(),
            &cc(false, true, IW),
        );
        assert_eq!(cwnd, 63 * MSS / 2);

        // And is never increased.
        let mut larger_cwnd = 2000 * MSS;
        cr.adjust(
            &mut larger_cwnd,
            &mut pacing_rate,
            Bandwidth::zero(),
            &cc(false, true, IW),
        );
        assert_eq!(larger_cwnd, 63 * MSS / 2);

        let mut smaller_cwnd = 20 * MSS;
        cr.adjust(
            &mut smaller_cwnd,
            &mut pacing_rate,
            Bandwidth::zero(),
            &cc(false, true, IW),
        );
        assert_eq!(smaller_cwnd, 20 * MSS);

        let mut larger_cwnd = 2000 * MSS;
        cr.adjust(
            &mut larger_cwnd,
            &mut pacing_rate,
            Bandwidth::zero(),
            &cc(false, true, IW),
        );
        assert_eq!(larger_cwnd, 20 * MSS);

        assert!(cr.discards_bandwidth_samples(true));
        assert!(!cr.discards_bandwidth_samples(false));

        // The last unvalidated packet is acked, but BBR is still in Drain.
        cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(109),
                bytes_acked: 35 * MSS,
                ..ev(now + RTT * 2)
            },
            &cc(false, true, 1000 * MSS),
        );
        assert_eq!(cr.on_mode_updated(&cc(false, true, cwnd)), Action::None);
        assert_eq!(cr.phase(), CarefulResumePhase::SafeRetreat);

        // BBR left Drain.
        let action = cr.on_mode_updated(&cc(false, false, cwnd));
        assert_eq!(action, Action::LimitInflightHi(98 * MSS / 2));
        assert_eq!(cr.stats(), CarefulResumeStats {
            phase: CarefulResumePhase::Normal,
            trigger: Some(CarefulResumeTrigger::ExitRecovery),
            safe_retreat_entered: true,
        });
        assert!(!cr.allows_observation());
    }

    #[test]
    fn startup_exit_while_validating() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        enter_unvalidated(&mut cr, now);

        assert_eq!(cr.on_mode_updated(&cc(false, true, IW)), Action::None);
        assert_eq!(cr.phase(), CarefulResumePhase::SafeRetreat);
        assert_eq!(cr.stats().trigger, None);
    }

    #[test]
    fn observation_thresholds() {
        let bw = Bandwidth::from_bytes_per_second(1_000_000);

        assert_eq!(observation(bw, None, IW), None);
        assert_eq!(observation(Bandwidth::zero(), Some(RTT), IW), None);

        // 100 KB of capacity is above 4 * IW.
        assert_eq!(
            observation(bw, Some(RTT), IW),
            Some(CarefulResumeParams {
                bandwidth: 1_000_000,
                min_rtt: RTT,
            })
        );

        // 10 KB of capacity is below 4 * IW.
        assert_eq!(observation(bw, Some(RTT / 10), IW), None);
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_updates() {
        let mut cr = CarefulResume::new(saved()).unwrap();
        let now = Instant::now();

        let update = cr.next_qlog_update().unwrap();
        assert_eq!(update.old, None);
        assert_eq!(update.new, CarefulResumePhase::Reconnaissance);
        assert_eq!(update.restored, Some(saved()));
        assert!(cr.next_qlog_update().is_none());

        enter_unvalidated(&mut cr, now);
        cr.on_packet_sent(10, MSS, 1000 * MSS, MSS, IW);
        cr.on_packet_sent(11, 2 * MSS, 1000 * MSS, MSS, IW);

        let update = cr.next_qlog_update().unwrap();
        assert_eq!(update.old, Some(CarefulResumePhase::Reconnaissance));
        assert_eq!(update.new, CarefulResumePhase::Unvalidated);
        assert_eq!(update.restored, None);
        assert_eq!(update.pipe_size, 0);

        cr.on_congestion_event(
            &CongestionEventInfo {
                largest_acked: Some(11),
                bytes_acked: 2 * MSS,
                bytes_lost: 0,
                bytes_in_flight: 0,
                ..ev(now + RTT)
            },
            &cc(true, false, 1000 * MSS),
        );

        let update = cr.next_qlog_update().unwrap();
        assert_eq!(update.new, CarefulResumePhase::Normal);
        assert_eq!(update.trigger, Some(CarefulResumeTrigger::RateLimited));
        assert!(cr.next_qlog_update().is_none());
    }
}
