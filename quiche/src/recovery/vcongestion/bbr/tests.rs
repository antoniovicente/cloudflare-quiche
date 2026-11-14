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

//! Tests for the BBR state machine, based on the test cases in
//! draft-ietf-ccwg-bbr-07 Appendix A ("BBR Example Test Cases").
//!
//! Most tests drive [`VRecovery`](super::super::VRecovery) through the
//! simulated bottleneck in `vcongestion::sim`; a few exercise rare event
//! sequences directly on [`Bbr`].

use super::*;

use crate::recovery::RecoveryOps;

use crate::recovery::vcongestion::sim::AppData;
use crate::recovery::vcongestion::sim::Sim;
use crate::recovery::vcongestion::sim::MSS;

const RTT: Duration = Duration::from_millis(40);

fn mbps(v: u64) -> Bandwidth {
    Bandwidth::from_mbits_per_second(v)
}

fn kbps(v: u64) -> Bandwidth {
    Bandwidth::from_kbits_per_second(v)
}

/// A bulk flow over a 10Mbps / 40ms path with a 2 BDP buffer.
fn bulk_sim() -> Sim {
    let mut sim = Sim::new(mbps(10), RTT, 0);
    sim.buffer = 2 * sim.bdp();
    sim
}

/// Runs until BBR leaves Startup and Drain.
fn run_to_probe_bw(sim: &mut Sim) {
    assert!(sim
        .run_until_cond(Duration::from_secs(5), |s| s.bbr().state.is_probe_bw()));
}

fn ratio(a: Bandwidth, b: Bandwidth) -> f64 {
    a.to_bits_per_second() as f64 / b.to_bits_per_second() as f64
}

fn state_follows(states: &[State], first: State, then: State) -> bool {
    states.windows(2).any(|w| w[0] == first && w[1] == then)
}

#[test]
fn init() {
    // Draft Section 5.2.1, OnInit().
    let now = Instant::now();
    let b = Bbr::new(10, MSS, now);

    assert_eq!(b.state, State::Startup);
    assert_eq!(b.pacing_gain, STARTUP_PACING_GAIN);
    assert_eq!(b.cwnd_gain, DEFAULT_CWND_GAIN);
    assert_eq!(b.cwnd, 10 * MSS as u64);
    assert_eq!(b.min_rtt, None);
    assert_eq!(b.inflight_longterm, INFINITE_BYTES);
    assert_eq!(b.inflight_shortterm, INFINITE_BYTES);
    assert_eq!(b.bw_shortterm, Bandwidth::infinite());
    assert!(!b.full_bw_reached);

    // Draft Section 5.6.2, InitPacingRate() without an RTT sample:
    // 2.77 * 12000 bytes / 1ms.
    assert_eq!(
        b.pacing_rate,
        Bandwidth::from_bytes_per_second(12_000_000) * STARTUP_PACING_GAIN
    );
    // Draft Section 5.6.3: 1ms worth of data at the pacing rate.
    assert_eq!(b.send_quantum, b.pacing_rate * SEND_QUANTUM_DURATION);
    assert!(b.send_quantum <= MAX_SEND_QUANTUM);
}

#[test]
fn initial_pacing_rate_uses_first_srtt() {
    // Draft Section 5.6.2: "the initial C.srtt after the first non-zero RTT
    // sample".
    let mut sim = bulk_sim();
    sim.run_for(RTT + Duration::from_millis(5));

    let b = sim.bbr();
    assert!(b.pacing_rate_from_srtt);
    assert!(b.pacing_rate < mbps(100));
}

#[test]
fn a1_exit_startup_on_bandwidth_plateau() {
    let mut sim = bulk_sim();

    assert!(
        sim.run_until_cond(Duration::from_secs(5), |s| s.bbr().state !=
            State::Startup)
    );

    let b = sim.bbr();
    assert_eq!(b.state, State::Drain);
    assert!(b.full_bw_now);
    assert!(b.full_bw_reached);
    assert_eq!(b.full_bw_count, FULL_BW_COUNT);
    assert_eq!(b.startup_exit, Some(StartupExitCause::BandwidthPlateau));

    // BBR.max_bw is within 2% of the bottleneck bandwidth.
    let r = ratio(b.max_bw, sim.bottleneck);
    assert!((0.98..=1.02).contains(&r), "max_bw ratio {r}");

    // The 2 BDP buffer is enough to avoid losses in Startup.
    assert_eq!(sim.dropped, 0);
}

#[test]
fn a2_exit_startup_on_loss_when_app_limited() {
    // A long RTT and 10% loss give more than BBR.StartupFullLossCnt losses
    // per round trip.
    let mut sim = Sim::new(mbps(10), Duration::from_millis(200), 0);
    sim.buffer = 2 * sim.bdp();
    sim.set_app(AppData::Rate(mbps(5)));
    sim.drop_every = Some(10);

    assert!(
        sim.run_until_cond(Duration::from_secs(5), |s| s.bbr().state !=
            State::Startup)
    );

    // Inflight is low since the flow is application-limited, so Drain ends
    // on the same ACK that exits Startup.
    assert!(sim.states[1] == State::Drain || sim.states[1].is_probe_bw());

    let b = sim.bbr();
    assert!(b.full_bw_reached);
    assert!(b.full_bw_now);
    assert_eq!(b.startup_exit, Some(StartupExitCause::Loss));
    assert_ne!(b.inflight_longterm, INFINITE_BYTES);
}

#[test]
fn a3_exit_drain_based_on_inflight() {
    let mut sim = bulk_sim();

    assert!(
        sim.run_until_cond(Duration::from_secs(5), |s| s.bbr().state ==
            State::Drain)
    );
    assert_eq!(sim.bbr().pacing_gain, DRAIN_PACING_GAIN);
    let drain_start_round = sim.bbr().drain_start_round;

    run_to_probe_bw(&mut sim);

    // Drain ended because inflight dropped to the estimated BDP, before the
    // round trip limit.
    let b = sim.bbr();
    assert!(b.round_count <= drain_start_round + DRAIN_MAX_ROUNDS);
    assert!(sim.r.bytes_in_flight() as u64 <= sim.r.bbr().bdp * 2);
}

#[test]
fn a4_exit_drain_based_on_time() {
    let mut sim = bulk_sim();

    assert!(
        sim.run_until_cond(Duration::from_secs(5), |s| s.bbr().state ==
            State::Drain)
    );
    let drain_start_round = sim.bbr().drain_start_round;

    // Simulate an over-estimation of the bandwidth: with the bottleneck
    // below the Drain pacing rate the queue doesn't drain. The reduction is
    // larger than the draft's 10% because the simulated queue at the end of
    // Startup is small enough to drain quickly otherwise.
    sim.bottleneck = mbps(4);

    run_to_probe_bw(&mut sim);

    let b = sim.bbr();
    assert_eq!(b.round_count, drain_start_round + DRAIN_MAX_ROUNDS + 1);
}

#[test]
fn a5_exit_probe_up_and_a8_exit_probe_down_on_inflight() {
    let mut sim = bulk_sim();
    sim.run_for(Duration::from_secs(10));

    // ProbeBW_UP ends with a plateau and moves to ProbeBW_DOWN, which then
    // moves to ProbeBW_CRUISE once the queue is drained.
    assert!(state_follows(
        &sim.states,
        State::ProbeBwRefill,
        State::ProbeBwUp
    ));
    assert!(state_follows(
        &sim.states,
        State::ProbeBwUp,
        State::ProbeBwDown
    ));
    assert!(state_follows(
        &sim.states,
        State::ProbeBwDown,
        State::ProbeBwCruise
    ));

    assert!(
        sim.run_until_cond(Duration::from_secs(5), |s| s.bbr().state ==
            State::ProbeBwDown)
    );
    assert_eq!(sim.bbr().pacing_gain, PROBE_BW_DOWN_PACING_GAIN);
    assert_eq!(sim.bbr().cwnd_gain, DEFAULT_CWND_GAIN);

    assert!(
        sim.run_until_cond(Duration::from_secs(5), |s| s.bbr().state ==
            State::ProbeBwCruise)
    );
    assert_eq!(sim.bbr().pacing_gain, PROBE_BW_CRUISE_PACING_GAIN);

    // Throughput is close to the bottleneck bandwidth.
    let delivered = sim.received_bytes;
    let elapsed = sim.elapsed();
    let throughput =
        Bandwidth::from_bytes_and_time_delta(delivered as usize, elapsed);
    assert!(ratio(throughput, sim.bottleneck) > 0.9);
}

#[test]
fn a7_never_exit_startup_when_app_limited_without_loss() {
    let mut sim = bulk_sim();
    sim.set_app(AppData::Rate(mbps(2)));

    // Stop before BBR.MinRTTFilterLen so that ProbeRTT isn't triggered.
    sim.run_for(Duration::from_secs(8));

    assert_eq!(sim.states, vec![State::Startup]);
    assert!(!sim.bbr().full_bw_reached);
}

#[test]
fn a9_exit_probe_down_after_max_time() {
    let mut sim = bulk_sim();
    run_to_probe_bw(&mut sim);

    assert!(
        sim.run_until_cond(Duration::from_secs(10), |s| s.bbr().state ==
            State::ProbeBwDown)
    );

    // Prevent inflight from dropping enough to move to ProbeBW_CRUISE.
    sim.bottleneck = mbps(5);
    let states = sim.states.len();

    assert!(
        sim.run_until_cond(Duration::from_secs(10), |s| s.bbr().state !=
            State::ProbeBwDown)
    );
    assert_eq!(sim.bbr().state, State::ProbeBwRefill);
    assert_eq!(&sim.states[states - 1..], &[
        State::ProbeBwDown,
        State::ProbeBwRefill
    ]);
}

#[test]
fn a10_enter_and_exit_probe_rtt() {
    let mut sim = bulk_sim();
    run_to_probe_bw(&mut sim);

    // The simulated RTT never decreases, so BBR.min_rtt expires after
    // BBR.MinRTTFilterLen.
    assert!(
        sim.run_until_cond(Duration::from_secs(11), |s| s.bbr().state ==
            State::ProbeRtt)
    );
    assert!(sim.elapsed() >= MIN_RTT_FILTER_LEN);
    assert_eq!(sim.bbr().cwnd_gain, PROBE_RTT_CWND_GAIN);

    let entered = sim.now;
    let mut max_cwnd_in_probe_rtt = 0;
    let mut target = 0;
    assert!(sim.run_until_cond(Duration::from_secs(2), |s| {
        let b = s.bbr();
        if b.state == State::ProbeRtt && b.probe_rtt_done_stamp.is_some() {
            max_cwnd_in_probe_rtt = max_cwnd_in_probe_rtt.max(b.cwnd);
            target = b
                .bdp
                .min(b.probe_rtt_cwnd)
                .max(MIN_PIPE_CWND_PACKETS * MSS as u64);
        }
        b.state != State::ProbeRtt
    }));

    // cwnd was bounded to ProbeRTTCwnd(), and ProbeRTT lasted at least
    // BBR.ProbeRTTDuration.
    assert!(max_cwnd_in_probe_rtt > 0);
    assert!(max_cwnd_in_probe_rtt <= target);
    assert!(sim.now - entered >= PROBE_RTT_DURATION);

    let b = sim.bbr();
    assert_eq!(b.state, State::ProbeBwCruise);
    assert_eq!(b.cwnd_gain, DEFAULT_CWND_GAIN);
    assert!(!b.min_rtt_expired);
}

#[test]
fn a11_skip_probe_rtt_due_to_app_limited_sending() {
    let mut sim = bulk_sim();
    run_to_probe_bw(&mut sim);

    sim.set_app(AppData::Idle);
    sim.run_for(MIN_RTT_FILTER_LEN + Duration::from_secs(1));
    assert_eq!(sim.r.bytes_in_flight(), 0);

    let states = sim.states.len();
    sim.set_app(AppData::Unlimited);

    // The first transmission after idle sets BBR.idle_restart.
    assert!(
        sim.run_until_cond(Duration::from_millis(1), |s| s.bbr().idle_restart)
    );

    sim.run_for(RTT * 3);
    assert!(!sim.states[states..].contains(&State::ProbeRtt));
    assert!(!sim.bbr().idle_restart);
    // The expired BBR.min_rtt was refreshed.
    assert!(!sim.bbr().min_rtt_expired);
}

#[test]
fn a12_startup_bandwidth_with_aggregation() {
    let mut sim = bulk_sim();
    sim.ack_batch = Some(Duration::from_millis(10));

    assert!(
        sim.run_until_cond(Duration::from_secs(5), |s| s.bbr().state !=
            State::Startup)
    );

    let b = sim.bbr();
    assert!(b.extra_acked > 0);
    let r = ratio(b.max_bw, sim.bottleneck);
    assert!((0.95..=1.25).contains(&r), "max_bw ratio {r}");
}

#[test]
fn a13_cruise_bandwidth_with_aggregation() {
    let mut sim = bulk_sim();
    sim.ack_batch = Some(Duration::from_millis(10));
    run_to_probe_bw(&mut sim);

    assert!(
        sim.run_until_cond(Duration::from_secs(10), |s| s.bbr().state ==
            State::ProbeBwCruise)
    );

    let start_bytes = sim.received_bytes;
    let start = sim.now;
    sim.run_for(Duration::from_secs(2));

    let b = sim.bbr();
    assert!(b.extra_acked > 0);
    // cwnd is augmented by BBR.extra_acked.
    assert!(b.max_inflight >= b.bdp * 2 + b.extra_acked);

    let throughput = Bandwidth::from_bytes_and_time_delta(
        (sim.received_bytes - start_bytes) as usize,
        sim.now - start,
    );
    assert!(ratio(throughput, sim.bottleneck) > 0.9);
}

#[test]
fn a14_sub_packet_bdp() {
    // 64kbit/s with a 10ms RTT is a BDP of 80 bytes.
    let mut sim = Sim::new(kbps(64), Duration::from_millis(10), 4 * MSS);
    sim.run_for(Duration::from_secs(20));

    let b = sim.bbr();
    assert!(b.state.is_probe_bw(), "{:?}", sim.states);
    assert!(b.cwnd >= MIN_PIPE_CWND_PACKETS * MSS as u64);

    let r = ratio(b.max_bw, sim.bottleneck);
    assert!((0.9..=1.1).contains(&r), "max_bw ratio {r}");
    assert!(b.pacing_rate <= kbps(64) * PROBE_BW_UP_PACING_GAIN);
}

#[test]
fn a15_increase_bandwidth_10x() {
    // A shallow buffer causes losses that set BBR.inflight_longterm.
    let mut sim = Sim::new(mbps(2), RTT, 0);
    sim.buffer = sim.bdp() / 2;
    run_to_probe_bw(&mut sim);
    sim.run_for(Duration::from_secs(5));
    assert_ne!(sim.bbr().inflight_longterm, INFINITE_BYTES);

    sim.bottleneck = mbps(20);
    sim.buffer = 2 * sim.bdp();

    let mut probe_up_rounds = 0;
    assert!(sim.run_until_cond(Duration::from_secs(10), |s| {
        probe_up_rounds = probe_up_rounds.max(s.bbr().bw_probe_up_rounds);
        ratio(s.bbr().max_bw, s.bottleneck) >= 0.95
    }));

    // The BBR.inflight_longterm growth step doubled over several rounds
    // while probing (draft Section 5.3.3.5).
    assert!(probe_up_rounds >= 2, "{probe_up_rounds}");
}

#[test]
fn a16_decrease_bandwidth_10x() {
    let mut sim = Sim::new(mbps(20), RTT, 0);
    sim.buffer = 2 * sim.bdp();
    run_to_probe_bw(&mut sim);
    sim.run_for(Duration::from_secs(2));

    sim.bottleneck = mbps(2);

    let mut bw_shortterm_reduced = false;
    assert!(sim.run_until_cond(Duration::from_secs(20), |s| {
        bw_shortterm_reduced |= s.bbr().bw_shortterm < mbps(20);
        ratio(s.bbr().max_bw, s.bottleneck) <= 1.1
    }));

    // Losses reduced BBR.bw_shortterm before BBR.max_bw adapted.
    assert!(bw_shortterm_reduced);
}

#[test]
fn a18_a21_loss_in_probe_up_and_spurious_recovery() {
    let now = Instant::now();
    let mss = MSS as u64;

    let mut b = Bbr::new(10, MSS, now);
    b.full_bw_reached = true;
    b.max_bw = mbps(10);
    b.bw = mbps(10);
    b.min_rtt = Some(RTT);
    b.bdp = 50_000;
    b.cwnd = 120_000;
    b.inflight_longterm = 120_000;
    b.state = State::ProbeBwUp;
    b.check_probe_loss = true;

    let mut sampler = DeliveryRateSampler::new(now);

    // Draft Section 5.6.4.4, OnEnterFastRecovery().
    b.on_enter_fast_recovery();
    assert!(b.in_loss_recovery);
    assert_eq!(b.prior_cwnd, 120_000);

    // Ten packets lost out of 100KB in flight is over BBR.LossThresh.
    for _ in 0..10 {
        sampler.on_packet_lost(mss);
    }
    let p = PacketState {
        packet_id: 100,
        size: mss,
        send_time: now,
        delivered: 0,
        delivered_time: now,
        first_send_time: now,
        is_app_limited: false,
        tx_in_flight: 100_000,
        lost: 0,
    };
    b.on_packet_lost(&p, &sampler, now);

    // A.21: HandleInflightTooHigh() lowers BBR.inflight_longterm to
    // InflightAtLoss() (bounded by BBR.Beta) and aborts ProbeBW_UP.
    let expected_longterm = inflight_at_loss(mss, 100_000, 10 * mss);
    assert_eq!(expected_longterm, 89_795);
    assert_eq!(b.inflight_longterm, expected_longterm);
    assert_eq!(b.state, State::ProbeBwDown);
    assert!(b.prev_probe_too_high);
    assert!(!b.check_probe_loss);

    // A.18: SaveStateUponLoss() saved the model before the loss.
    assert_eq!(b.undo_state, Some(State::ProbeBwUp));
    assert_eq!(b.undo_inflight_longterm, 120_000);
    assert_eq!(b.undo_inflight_shortterm, INFINITE_BYTES);

    // The loss turns out to be spurious: the model is restored, and the
    // bandwidth probe restarts.
    b.on_spurious_loss_detection();
    assert_eq!(b.inflight_longterm, 120_000);
    assert_eq!(b.state, State::ProbeBwRefill);
    assert_eq!(b.undo_state, None);
    assert!(!b.in_loss_recovery);
    assert!(!b.is_loss_in_round);
}

#[test]
fn spurious_loss_in_startup_returns_to_startup() {
    let now = Instant::now();
    let mut b = Bbr::new(10, MSS, now);

    b.on_enter_fast_recovery();
    b.undo_state = Some(State::Startup);
    b.full_bw_reached = true;
    b.enter_drain();

    b.on_spurious_loss_detection();
    assert_eq!(b.state, State::Startup);
    assert!(!b.full_bw_reached);
}

#[test]
fn a20_probe_rtt_during_startup() {
    let mut sim = bulk_sim();
    // Application-limited enough to never exit Startup, but busy enough to
    // always have data in flight so that idle restarts don't skip ProbeRTT.
    sim.set_app(AppData::Rate(mbps(5)));

    sim.run_for(MIN_RTT_FILTER_LEN + Duration::from_secs(1));

    assert_eq!(sim.states, vec![
        State::Startup,
        State::ProbeRtt,
        State::Startup
    ]);
    assert!(!sim.bbr().full_bw_reached);
}

#[test]
fn a22_app_limited_during_probe_refill() {
    let mut sim = bulk_sim();
    run_to_probe_bw(&mut sim);

    assert!(
        sim.run_until_cond(Duration::from_secs(10), |s| s.bbr().state ==
            State::ProbeBwRefill)
    );
    let max_bw = sim.bbr().max_bw;

    // Pause the application for the REFILL round trip.
    sim.set_app(AppData::Idle);
    sim.run_for(RTT * 2);
    assert!(sim.bbr().max_bw >= max_bw);

    sim.set_app(AppData::Unlimited);
    assert!(
        sim.run_until_cond(Duration::from_secs(1), |s| s.bbr().state ==
            State::ProbeBwUp)
    );
    assert!(sim.bbr().max_bw >= max_bw);
}

#[test]
fn inflight_at_loss_examples() {
    // Draft Section 5.5.10.2: with no prior losses, the threshold is crossed
    // when the lost prefix is LossThresh of inflight.
    let inflight = inflight_at_loss(1000, 101_000, 1000);
    // inflight_prev = 100000, lost_prefix = 2000 / 0.98.
    assert_eq!(inflight, 102_040);

    // Losses before the packet already exceed the threshold.
    assert!(inflight_at_loss(1000, 101_000, 50_000) < 100_000);
}

#[test]
fn is_inflight_too_high_threshold() {
    // Draft Section 5.5.10.2, BBR.LossThresh = 2%.
    assert!(!is_inflight_too_high(2000, 100_000));
    assert!(is_inflight_too_high(2001, 100_000));
}

#[test]
fn bound_cwnd_for_model() {
    // Draft Section 5.6.4.7.
    let now = Instant::now();
    let mut b = Bbr::new(10, MSS, now);
    b.cwnd = 200_000;
    b.inflight_longterm = 100_000;
    b.inflight_shortterm = INFINITE_BYTES;

    // No cap in Startup.
    b.bound_cwnd_for_model();
    assert_eq!(b.cwnd, 200_000);

    b.state = State::ProbeBwUp;
    b.bound_cwnd_for_model();
    assert_eq!(b.cwnd, 100_000);

    // CRUISE leaves BBR.Headroom free.
    b.state = State::ProbeBwCruise;
    b.bound_cwnd_for_model();
    assert_eq!(b.cwnd, 85_000);

    b.inflight_shortterm = 50_000;
    b.bound_cwnd_for_model();
    assert_eq!(b.cwnd, 50_000);

    // Never below BBR.MinPipeCwnd.
    b.inflight_shortterm = 1;
    b.cwnd = 1;
    b.bound_cwnd_for_model();
    assert_eq!(b.cwnd, 1);
    b.cwnd = 10 * MSS as u64;
    b.bound_cwnd_for_model();
    assert_eq!(b.cwnd, MIN_PIPE_CWND_PACKETS * MSS as u64);
}

#[test]
fn raise_inflight_longterm_slope_doubles() {
    // Draft Section 5.3.3.9: growth per round of 1, 2, 4, 8, ... C.SMSS.
    let now = Instant::now();
    let mut b = Bbr::new(10, MSS, now);
    b.cwnd = 64 * MSS as u64;

    let mut per_inc = vec![];
    for _ in 0..4 {
        b.raise_inflight_longterm_slope();
        per_inc.push(b.probe_up_acked_per_inc / MSS as u64);
    }

    assert_eq!(per_inc, vec![64, 32, 16, 8]);
}
