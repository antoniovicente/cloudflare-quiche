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

//! A small discrete-event network simulator for testing vbbr.
//!
//! It models the controlled path used by the test cases in
//! draft-ietf-ccwg-bbr-07 Appendix A: a single flow over a bottleneck with a
//! fixed rate, a drop-tail buffer and a fixed propagation delay. The receiver
//! acknowledges every packet immediately (optionally batching ACKs to emulate
//! ACK aggregation), and the sender transmits whenever the congestion window
//! and the pacer allow it.

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::packet;
use crate::ranges::RangeSet;
use crate::recovery::Bandwidth;
use crate::recovery::HandshakeStatus;
use crate::recovery::RecoveryConfig;
use crate::recovery::RecoveryOps;
use crate::test_utils;
use crate::Config;
use crate::CongestionControlAlgorithm;

use super::bbr::Bbr;
use super::bbr::State;
use super::VRecovery;

pub(super) const MSS: usize = 1200;

const EPOCH: packet::Epoch = packet::Epoch::Application;

/// How much data the application has to send.
#[derive(Clone, Copy, Debug)]
pub(super) enum AppData {
    /// Always has data to send.
    Unlimited,

    /// Produces data at a fixed rate.
    Rate(Bandwidth),

    /// Has no data to send.
    Idle,
}

pub(super) struct Sim {
    pub(super) r: VRecovery,
    pub(super) now: Instant,

    /// Bottleneck rate.
    pub(super) bottleneck: Bandwidth,

    /// One way propagation delay; the ACK path has the same delay.
    pub(super) one_way_delay: Duration,

    /// Bottleneck buffer size in bytes.
    pub(super) buffer: usize,

    /// If set, the receiver sends ACKs only at multiples of this interval.
    pub(super) ack_batch: Option<Duration>,

    pub(super) app: AppData,

    /// If set, every Nth packet is dropped at the bottleneck, in addition to
    /// buffer overflow drops.
    pub(super) drop_every: Option<u64>,

    /// Every state BBR has been in, in order, without repetitions.
    pub(super) states: Vec<State>,

    /// Total bytes received by the receiver.
    pub(super) received_bytes: u64,

    /// Total packets dropped at the bottleneck.
    pub(super) dropped: u64,

    start: Instant,
    next_pn: u64,
    link_free: Instant,
    app_sent: u64,
    app_rate_start: Instant,

    /// Packets in flight on the path: (time the ACK reaches the sender, pn).
    deliveries: VecDeque<(Instant, u64)>,

    /// Packets received by the receiver.
    received: RangeSet,
}

impl Sim {
    pub(super) fn new(
        bottleneck: Bandwidth, rtt: Duration, buffer: usize,
    ) -> Self {
        let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        config.set_cc_algorithm(CongestionControlAlgorithm::Vbbr);
        Self::with_config(&config, bottleneck, rtt, buffer)
    }

    pub(super) fn with_config(
        config: &Config, bottleneck: Bandwidth, rtt: Duration, buffer: usize,
    ) -> Self {
        let mut recovery_config = RecoveryConfig::from_config(config);
        recovery_config.max_send_udp_payload_size = MSS;

        let r = VRecovery::new(&recovery_config).unwrap();
        let now = Instant::now();

        Sim {
            states: vec![r.bbr().state()],
            r,
            now,
            bottleneck,
            one_way_delay: rtt / 2,
            buffer,
            ack_batch: None,
            app: AppData::Unlimited,
            drop_every: None,
            received_bytes: 0,
            dropped: 0,
            start: now,
            next_pn: 0,
            link_free: now,
            app_sent: 0,
            app_rate_start: now,
            deliveries: VecDeque::new(),
            received: RangeSet::default(),
        }
    }

    pub(super) fn bbr(&self) -> &Bbr {
        self.r.bbr()
    }

    pub(super) fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    pub(super) fn set_app(&mut self, app: AppData) {
        self.app = app;
        self.app_sent = 0;
        self.app_rate_start = self.now;
    }

    /// The bandwidth-delay product of the path.
    pub(super) fn bdp(&self) -> usize {
        (self.bottleneck * (self.one_way_delay * 2)) as usize
    }

    /// Runs the simulation for `duration`.
    pub(super) fn run_for(&mut self, duration: Duration) {
        let end = self.now + duration;
        self.run_until(end, |_| false);
    }

    /// Runs the simulation until `cond` is true, or for at most `max`.
    /// Returns whether `cond` became true.
    pub(super) fn run_until_cond(
        &mut self, max: Duration, cond: impl FnMut(&Sim) -> bool,
    ) -> bool {
        let end = self.now + max;
        self.run_until(end, cond)
    }

    fn run_until(
        &mut self, end: Instant, mut cond: impl FnMut(&Sim) -> bool,
    ) -> bool {
        loop {
            self.process_acks();
            self.process_timer();
            self.record_state();

            if cond(self) {
                return true;
            }

            let next_send = self.send();
            self.record_state();

            let next_event = [
                self.deliveries.front().map(|(t, _)| *t),
                next_send,
                self.r.loss_detection_timer(),
            ]
            .into_iter()
            .flatten()
            .min();

            match next_event {
                Some(t) if t <= end => self.now = self.now.max(t),
                _ => {
                    self.now = end;
                    return cond(self);
                },
            }
        }
    }

    fn record_state(&mut self) {
        let state = self.r.bbr().state();
        if self.states.last() != Some(&state) {
            self.states.push(state);
        }
    }

    fn process_acks(&mut self) {
        let mut acked = false;

        while let Some(&(t, pn)) = self.deliveries.front() {
            if t > self.now {
                break;
            }

            self.deliveries.pop_front();
            self.received.insert(pn..pn + 1);
            acked = true;
        }

        if !acked {
            return;
        }

        // Only acknowledge recent packets, as a real receiver would.
        let largest = self.received.last().unwrap();
        let mut ranges = RangeSet::default();
        for r in self.received.iter() {
            if r.end + 1000 > largest {
                ranges.insert(r);
            }
        }

        self.r
            .on_ack_received(
                &ranges,
                0,
                EPOCH,
                HandshakeStatus::default(),
                self.now,
                None,
                "",
            )
            .unwrap();
    }

    fn process_timer(&mut self) {
        if self.r.loss_detection_timer().is_some_and(|t| t <= self.now) {
            self.r.on_loss_detection_timeout(
                HandshakeStatus::default(),
                self.now,
                "",
            );
        }
    }

    /// Whether the application has data to send now, or when it will.
    fn app_data(&self) -> Result<(), Option<Instant>> {
        match self.app {
            AppData::Unlimited => Ok(()),

            AppData::Idle => Err(None),

            AppData::Rate(rate) => {
                let produced = rate * (self.now - self.app_rate_start);
                if produced >= self.app_sent + MSS as u64 {
                    Ok(())
                } else {
                    let missing = self.app_sent + MSS as u64 - produced;
                    Err(Some(self.now + rate.transfer_time(missing)))
                }
            },
        }
    }

    /// Sends as many packets as allowed. Returns when sending can resume, if
    /// it is blocked by pacing or the application.
    fn send(&mut self) -> Option<Instant> {
        loop {
            // PTO probes are not subject to congestion control (RFC 9002
            // Section 7.5).
            let probe = self.r.loss_probes(EPOCH) > 0;

            if !probe {
                if let Err(next) = self.app_data() {
                    // Nothing to send: draft-ietf-ccwg-bbr-07 Section 4.1.2.4.
                    self.r.on_app_limited();
                    return next;
                }

                if self.r.cwnd_available() < MSS {
                    return None;
                }

                if let Some(t) = self.r.get_next_release_time().time(self.now) {
                    return Some(t);
                }
            }

            self.send_packet();

            if probe {
                self.r.ping_sent(EPOCH);
            }
        }
    }

    fn send_packet(&mut self) {
        let pn = self.next_pn;
        self.next_pn += 1;
        self.app_sent += MSS as u64;

        let pkt = test_utils::helper_packet_sent(pn, self.now, MSS);
        self.r.on_packet_sent(
            pkt,
            EPOCH,
            HandshakeStatus::default(),
            self.now,
            "",
        );

        if self.drop_every.is_some_and(|n| pn % n == n - 1) {
            self.dropped += 1;
            return;
        }

        // Drop-tail bottleneck queue.
        let backlog =
            self.bottleneck * self.link_free.saturating_duration_since(self.now);
        if backlog as usize > self.buffer {
            self.dropped += 1;
            return;
        }

        let depart = self.link_free.max(self.now) +
            self.bottleneck.transfer_time(MSS as u64);
        self.link_free = depart;
        self.received_bytes += MSS as u64;

        let mut ack_arrival = depart + self.one_way_delay * 2;
        if let Some(batch) = self.ack_batch {
            // Delay the ACK until the next batching boundary at the receiver.
            let since = (ack_arrival - self.start).as_nanos();
            let batch = batch.as_nanos();
            let rounded = since.div_ceil(batch) * batch;
            ack_arrival = self.start + Duration::from_nanos(rounded as u64);
        }

        self.deliveries.push_back((ack_arrival, pn));
    }
}
