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

//! Packet pacing.
//!
//! Implements the pacing mechanism described in draft-ietf-ccwg-bbr-07
//! Section 5.6.2 ("Pacing Rate: C.pacing_rate"):
//!
//! ```text
//!   C.next_send_time = max(Now(), C.next_send_time)
//!   P.send_time = C.next_send_time
//!   pacing_delay = packet.size / C.pacing_rate
//!   C.next_send_time = C.next_send_time + pacing_delay
//! ```
//!
//! combined with the send quantum of Section 5.6.3 ("Send Quantum:
//! C.send_quantum"): pacing maintains inter-*quantum* spacing, so packets are
//! grouped into aggregates of up to `C.send_quantum` bytes that share a single
//! departure time, and the next aggregate departs once the previous one has
//! been paced out at `C.pacing_rate`.
//!
//! RFC 9002 Section 7.7 requires senders to pace or otherwise limit bursts;
//! the quantum is bounded by Section 5.6.3 to roughly 1ms worth of data at the
//! pacing rate (and at most 64KB).
//!
//! The pacing decision is exposed through the same [`ReleaseDecision`] API used
//! by other pacing congestion controllers, so applications that schedule
//! packets using release times (e.g. tokio-quiche) work unchanged.
//!
//! <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.txt>
//! <https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7>

use std::time::Instant;

use crate::recovery::Bandwidth;
use crate::recovery::ReleaseDecision;
use crate::recovery::ReleaseTime;

#[derive(Debug)]
pub(crate) struct Pacer {
    /// Whether pacing is enabled. When disabled all packets are released
    /// immediately.
    enabled: bool,

    /// Optional application-configured upper bound on the pacing rate.
    max_pacing_rate: Option<Bandwidth>,

    /// C.next_send_time: the earliest pacing departure time of the next
    /// quantum. `None` until the first paced packet is sent.
    next_send_time: Option<Instant>,

    /// Departure time shared by all the packets of the current quantum.
    quantum_send_time: Option<Instant>,

    /// Bytes scheduled so far in the current quantum. Zero when the next
    /// packet starts a new quantum.
    quantum_bytes: u64,
}

impl Pacer {
    pub(crate) fn new(enabled: bool, max_pacing_rate: Option<Bandwidth>) -> Self {
        Pacer {
            enabled,
            max_pacing_rate,
            next_send_time: None,
            quantum_send_time: None,
            quantum_bytes: 0,
        }
    }

    /// Applies the configured maximum to the congestion controller's
    /// C.pacing_rate.
    pub(crate) fn effective_rate(&self, pacing_rate: Bandwidth) -> Bandwidth {
        match self.max_pacing_rate {
            Some(max) if self.enabled => pacing_rate.min(max),
            _ => pacing_rate,
        }
    }

    /// Schedules a congestion controlled packet of `size` bytes and returns
    /// its departure time, P.send_time.
    pub(crate) fn on_packet_sent(
        &mut self, now: Instant, size: u64, pacing_rate: Bandwidth,
        send_quantum: u64,
    ) -> Instant {
        if !self.enabled {
            return now;
        }

        let pacing_rate = self.effective_rate(pacing_rate);

        // C.next_send_time = max(Now(), C.next_send_time)
        let next_send_time = self.next_send_time.map_or(now, |t| t.max(now));

        // Start a new quantum if the previous one is complete, or if sending
        // fell behind the pacing schedule (e.g. because the sender was
        // application-limited), so stale quanta don't cause extra bursts.
        let quantum_send_time = match self.quantum_send_time {
            Some(t)
                if self.quantum_bytes > 0 &&
                    self.next_send_time.is_some_and(|n| n > now) =>
                t,
            _ => {
                self.quantum_bytes = 0;
                next_send_time
            },
        };
        self.quantum_send_time = Some(quantum_send_time);

        // P.send_time is the departure time of the quantum the packet belongs
        // to, which can't be in the past.
        let send_time = quantum_send_time.max(now);

        // pacing_delay = packet.size / C.pacing_rate
        // C.next_send_time = C.next_send_time + pacing_delay
        self.next_send_time =
            Some(next_send_time + pacing_rate.transfer_time(size));

        self.quantum_bytes += size;
        if self.quantum_bytes >= send_quantum {
            self.quantum_bytes = 0;
        }

        send_time
    }

    /// When the next packet can be released, and whether it may be part of
    /// the same burst (quantum) as the previous packet.
    pub(crate) fn get_next_release_time(&self) -> ReleaseDecision {
        if !self.enabled {
            return ReleaseDecision {
                time: ReleaseTime::Immediate,
                allow_burst: true,
            };
        }

        if self.quantum_bytes > 0 {
            if let Some(t) = self.quantum_send_time {
                return ReleaseDecision {
                    time: ReleaseTime::At(t),
                    allow_burst: true,
                };
            }
        }

        ReleaseDecision {
            time: self
                .next_send_time
                .map_or(ReleaseTime::Immediate, ReleaseTime::At),
            allow_burst: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const MSS: u64 = 1200;

    #[test]
    fn disabled_is_immediate() {
        let now = Instant::now();
        let mut p = Pacer::new(false, None);
        assert_eq!(
            p.on_packet_sent(now, MSS, Bandwidth::from_kbits_per_second(1), MSS),
            now
        );
        assert_eq!(p.get_next_release_time().time(now), None);
        assert!(p.get_next_release_time().can_burst());
    }

    #[test]
    fn paces_quanta() {
        let now = Instant::now();
        let mut p = Pacer::new(true, None);

        // 1200 bytes per ms.
        let rate = Bandwidth::from_bytes_per_second(1_200_000);
        let quantum = 2 * MSS;

        assert_eq!(p.get_next_release_time().time(now), None);

        // First quantum departs immediately.
        assert_eq!(p.on_packet_sent(now, MSS, rate, quantum), now);
        let d = p.get_next_release_time();
        assert!(d.can_burst());
        assert_eq!(d.time(now), None);
        assert_eq!(p.on_packet_sent(now, MSS, rate, quantum), now);

        // The quantum is complete, so the next one is paced 2ms later.
        let d = p.get_next_release_time();
        assert!(!d.can_burst());
        assert_eq!(d.time(now), Some(now + Duration::from_millis(2)));

        let t1 = now + Duration::from_millis(2);
        assert_eq!(p.on_packet_sent(now, MSS, rate, quantum), t1);
        assert_eq!(p.on_packet_sent(now, MSS, rate, quantum), t1);
        assert_eq!(
            p.get_next_release_time().time(now),
            Some(now + Duration::from_millis(4))
        );
    }

    #[test]
    fn idle_does_not_accumulate_credit() {
        let now = Instant::now();
        let mut p = Pacer::new(true, None);
        let rate = Bandwidth::from_bytes_per_second(1_200_000);

        p.on_packet_sent(now, MSS, rate, MSS);

        // After an idle period, the next packet leaves now and the following
        // one is paced relative to now.
        let later = now + Duration::from_secs(1);
        assert_eq!(p.on_packet_sent(later, MSS, rate, MSS), later);
        assert_eq!(
            p.get_next_release_time().time(later),
            Some(later + Duration::from_millis(1))
        );
    }

    #[test]
    fn stale_partial_quantum_is_not_reused() {
        let now = Instant::now();
        let mut p = Pacer::new(true, None);
        let rate = Bandwidth::from_bytes_per_second(1_200_000);

        // Partially fill a quantum, then stall past the pacing schedule.
        p.on_packet_sent(now, MSS, rate, 10 * MSS);
        let later = now + Duration::from_millis(5);
        assert_eq!(p.on_packet_sent(later, MSS, rate, 10 * MSS), later);
    }

    #[test]
    fn max_pacing_rate() {
        let now = Instant::now();
        let mut p =
            Pacer::new(true, Some(Bandwidth::from_bytes_per_second(1_200_000)));
        let fast = Bandwidth::from_bytes_per_second(1_200_000_000);
        assert_eq!(
            p.effective_rate(fast),
            Bandwidth::from_bytes_per_second(1_200_000)
        );

        p.on_packet_sent(now, MSS, fast, MSS);
        assert_eq!(
            p.get_next_release_time().time(now),
            Some(now + Duration::from_millis(1))
        );
    }
}
