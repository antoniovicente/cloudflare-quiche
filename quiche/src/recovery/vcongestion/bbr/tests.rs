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

//! Unit tests for the BBR state machine, exercising individual
//! draft-ietf-ccwg-bbr-07 algorithms directly on [`Bbr`].

use super::*;

const MSS: usize = 1200;

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
