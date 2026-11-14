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

//! Delivery rate sampling, as specified in draft-ietf-ccwg-bbr-07 Section 4.1
//! ("Delivery Rate Samples").
//!
//! <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.txt>
//!
//! The names used here follow the draft: connection state (`C.*`) lives in
//! [`DeliveryRateSampler`], per-packet state (`P.*`) in [`PacketState`] and the
//! per-ACK rate sample (`RS.*`) in [`RateSample`].

use std::time::Duration;
use std::time::Instant;

use crate::recovery::Bandwidth;

/// Per-packet (P) state, snapshotted when the packet is sent (Section
/// 4.1.2.1.2).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PacketState {
    /// P.packet_id: the QUIC packet number.
    pub(crate) packet_id: u64,

    /// P.size: bytes counted towards C.inflight.
    pub(crate) size: u64,

    /// P.send_time: the pacing departure time selected for the packet.
    pub(crate) send_time: Instant,

    /// P.delivered: C.delivered when the packet was sent.
    pub(crate) delivered: u64,

    /// P.delivered_time: C.delivered_time when the packet was sent.
    pub(crate) delivered_time: Instant,

    /// P.first_send_time: C.first_send_time when the packet was sent.
    pub(crate) first_send_time: Instant,

    /// P.is_app_limited: whether C.app_limited was non-zero when sent.
    pub(crate) is_app_limited: bool,

    /// P.tx_in_flight: C.inflight immediately after sending, including P.
    pub(crate) tx_in_flight: u64,

    /// P.lost: C.lost when the packet was sent.
    pub(crate) lost: u64,
}

/// Rate sample (RS) generated for each ACK (Sections 2.3 and 4.1.2.1.3).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateSample {
    /// RS.delivery_rate. Zero if no reliable sample was obtained.
    pub(crate) delivery_rate: Bandwidth,

    /// RS.is_app_limited: P.is_app_limited of the most recently sent packet
    /// delivered by this ACK.
    pub(crate) is_app_limited: bool,

    /// RS.interval: the length of the sampling interval.
    pub(crate) interval: Duration,

    /// RS.delivered: data delivered over the sampling interval.
    pub(crate) delivered: u64,

    /// RS.prior_delivered: P.delivered of the most recently sent packet
    /// delivered by this ACK.
    pub(crate) prior_delivered: u64,

    /// RS.prior_time: P.delivered_time of the most recently sent packet
    /// delivered by this ACK. `None` stands for the draft's value 0, meaning
    /// nothing was delivered by this ACK.
    pub(crate) prior_time: Option<Instant>,

    /// RS.send_elapsed.
    pub(crate) send_elapsed: Duration,

    /// RS.ack_elapsed.
    pub(crate) ack_elapsed: Duration,

    /// RS.last_acked_packet_id.
    pub(crate) last_acked_packet_id: u64,

    /// RS.rtt: RTT sample from the most recently sent packet delivered by this
    /// ACK. `None` stands for the draft's value -1.
    pub(crate) rtt: Option<Duration>,

    /// RS.newly_acked: data newly acknowledged by this ACK.
    pub(crate) newly_acked: u64,

    /// RS.tx_in_flight: P.tx_in_flight of the most recently sent packet
    /// delivered by this ACK.
    pub(crate) tx_in_flight: u64,

    /// RS.lost: data declared lost between the transmission and the
    /// acknowledgment of the most recently sent packet delivered by this ACK.
    pub(crate) lost: u64,

    /// RS.has_data: whether this ACK delivered any in-flight data.
    pub(crate) has_data: bool,

    /// P.lost of the most recently sent packet delivered by this ACK, used to
    /// compute RS.lost once loss detection for this ACK has completed.
    prior_lost: u64,

    /// P.send_time of the most recently sent packet delivered by this ACK.
    newest_send_time: Option<Instant>,
}

impl RateSample {
    /// `InitRateSample()`.
    pub(crate) fn new() -> Self {
        RateSample {
            delivery_rate: Bandwidth::zero(),
            is_app_limited: false,
            interval: Duration::ZERO,
            delivered: 0,
            prior_delivered: 0,
            prior_time: None,
            send_elapsed: Duration::ZERO,
            ack_elapsed: Duration::ZERO,
            last_acked_packet_id: 0,
            rtt: None,
            newly_acked: 0,
            tx_in_flight: 0,
            lost: 0,
            has_data: false,
            prior_lost: 0,
            newest_send_time: None,
        }
    }
}

/// Per-connection (C) delivery rate sampling state (Section 4.1.2.1.1).
#[derive(Debug)]
pub(crate) struct DeliveryRateSampler {
    /// C.delivered: total data delivered so far.
    delivered: u64,

    /// C.delivered_time: when C.delivered was last updated.
    delivered_time: Instant,

    /// C.first_send_time.
    first_send_time: Instant,

    /// C.app_limited: index of the last transmitted packet marked as
    /// application-limited (in units of C.delivered), or 0 if not currently
    /// application-limited.
    app_limited: u64,

    /// C.lost: total data marked as lost so far.
    lost: u64,

    /// C.min_rtt: the minimum observed RTT over the lifetime of the
    /// connection.
    min_rtt: Option<Duration>,
}

impl DeliveryRateSampler {
    pub(crate) fn new(now: Instant) -> Self {
        DeliveryRateSampler {
            delivered: 0,
            delivered_time: now,
            first_send_time: now,
            app_limited: 0,
            lost: 0,
            min_rtt: None,
        }
    }

    /// C.delivered.
    pub(crate) fn delivered(&self) -> u64 {
        self.delivered
    }

    /// C.lost.
    pub(crate) fn lost(&self) -> u64 {
        self.lost
    }

    /// Whether C.app_limited is non-zero.
    pub(crate) fn is_app_limited(&self) -> bool {
        self.app_limited != 0
    }

    /// `OnPacketSent(P)` (Section 4.1.2.2).
    ///
    /// `prior_inflight` is C.inflight before this packet is sent, and the
    /// returned state records P.tx_in_flight including this packet.
    pub(crate) fn on_packet_sent(
        &mut self, packet_id: u64, size: u64, send_time: Instant,
        prior_inflight: u64,
    ) -> PacketState {
        if prior_inflight == 0 {
            self.first_send_time = send_time;
            self.delivered_time = send_time;
        }

        PacketState {
            packet_id,
            size,
            send_time,
            delivered: self.delivered,
            delivered_time: self.delivered_time,
            first_send_time: self.first_send_time,
            is_app_limited: self.app_limited != 0,
            tx_in_flight: prior_inflight + size,
            lost: self.lost,
        }
    }

    /// `UpdateRateSample(P)` (Section 4.1.2.3), called for each newly
    /// acknowledged packet. The caller guarantees each packet is delivered
    /// at most once.
    pub(crate) fn on_packet_acked(
        &mut self, rs: &mut RateSample, p: &PacketState, now: Instant,
    ) {
        self.delivered += p.size;
        self.delivered_time = now;
        rs.newly_acked += p.size;

        // Update info using the newest packet.
        if !rs.has_data || self.is_newest_packet(rs, p) {
            rs.has_data = true;
            rs.prior_delivered = p.delivered;
            rs.prior_time = Some(p.delivered_time);
            rs.is_app_limited = p.is_app_limited;
            rs.send_elapsed =
                p.send_time.saturating_duration_since(p.first_send_time);
            rs.ack_elapsed = self
                .delivered_time
                .saturating_duration_since(p.delivered_time);
            rs.last_acked_packet_id = p.packet_id;
            rs.tx_in_flight = p.tx_in_flight;
            rs.prior_lost = p.lost;
            rs.newest_send_time = Some(p.send_time);
            self.first_send_time = p.send_time;
        }
    }

    /// `IsNewestPacket(P)`.
    fn is_newest_packet(&self, rs: &RateSample, p: &PacketState) -> bool {
        p.send_time > self.first_send_time ||
            (p.send_time == self.first_send_time &&
                p.packet_id > rs.last_acked_packet_id)
    }

    /// Records data newly marked lost, updating C.lost.
    pub(crate) fn on_packet_lost(&mut self, size: u64) {
        self.lost += size;
    }

    /// `GenerateRateSample()` (Section 4.1.2.3), called once all packets
    /// acknowledged and lost on this ACK have been processed.
    ///
    /// Also fills in RS.rtt (Section 4.2) and RS.lost (Section 2.3).
    pub(crate) fn generate_rate_sample(
        &mut self, rs: &mut RateSample, now: Instant,
    ) {
        // Clear app-limited field if bubble is ACKed and gone.
        if self.app_limited != 0 && self.delivered > self.app_limited {
            self.app_limited = 0;
        }

        if rs.prior_time.is_none() {
            // Nothing delivered on this ACK.
            return;
        }

        // draft-ietf-ccwg-bbr-07 Section 4.2: RS.rtt = Now() - P.send_time,
        // using the most recently sent packet (Section 5.5.7.1). QUIC packet
        // numbers are never reused, so the sample is unambiguous (RFC 9000
        // Section 12.3).
        if let Some(send_time) = rs.newest_send_time {
            let rtt = now.saturating_duration_since(send_time);
            rs.rtt = Some(rtt);
            self.min_rtt = Some(self.min_rtt.map_or(rtt, |m| m.min(rtt)));
        }

        // RS.lost (draft-ietf-ccwg-bbr-07 Section 2.3).
        rs.lost = self.lost.saturating_sub(rs.prior_lost);

        // Use the longer of the send_elapsed and ack_elapsed.
        rs.interval = rs.send_elapsed.max(rs.ack_elapsed);

        rs.delivered = self.delivered - rs.prior_delivered;

        // Normally we expect interval >= MinRTT. Discard implausible samples
        // (draft-ietf-ccwg-bbr-07 Sections 4.1.2.3 and 4.1.3.5).
        if rs.interval < self.min_rtt.unwrap_or(Duration::ZERO) {
            return;
        }

        if !rs.interval.is_zero() {
            rs.delivery_rate = Bandwidth::from_bytes_and_time_delta(
                rs.delivered as usize,
                rs.interval,
            );
        }
    }

    /// `MarkConnectionAppLimited()` (Section 4.1.2.4).
    pub(crate) fn mark_connection_app_limited(&mut self, inflight: u64) {
        self.app_limited = (self.delivered + inflight).max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u64 = 1200;

    #[test]
    fn ack_rate_sample() {
        let start = Instant::now();
        let mut s = DeliveryRateSampler::new(start);

        // Send 10 packets back to back at time 0.
        let mut inflight = 0;
        let pkts: Vec<_> = (0..10)
            .map(|i| {
                let p = s.on_packet_sent(i, MSS, start, inflight);
                inflight += MSS;
                p
            })
            .collect();
        assert_eq!(pkts[9].tx_in_flight, 10 * MSS);

        // All acked 100ms later in one ACK.
        let now = start + Duration::from_millis(100);
        let mut rs = RateSample::new();
        for p in &pkts {
            s.on_packet_acked(&mut rs, p, now);
        }
        s.generate_rate_sample(&mut rs, now);

        assert!(rs.has_data);
        assert_eq!(rs.newly_acked, 10 * MSS);
        assert_eq!(rs.delivered, 10 * MSS);
        assert_eq!(rs.last_acked_packet_id, 9);
        assert_eq!(rs.rtt, Some(Duration::from_millis(100)));
        assert_eq!(rs.interval, Duration::from_millis(100));
        assert_eq!(
            rs.delivery_rate,
            Bandwidth::from_bytes_and_time_delta(
                10 * MSS as usize,
                Duration::from_millis(100)
            )
        );
        assert_eq!(s.delivered(), 10 * MSS);
    }

    #[test]
    fn send_rate_caps_delivery_rate() {
        let start = Instant::now();
        let mut s = DeliveryRateSampler::new(start);

        // Two packets sent 200ms apart, both acked in the same ACK at 210ms.
        let p0 = s.on_packet_sent(0, MSS, start, 0);
        let p1 =
            s.on_packet_sent(1, MSS, start + Duration::from_millis(200), MSS);
        let now = start + Duration::from_millis(210);
        let mut rs = RateSample::new();
        s.on_packet_acked(&mut rs, &p0, now);
        s.on_packet_acked(&mut rs, &p1, now);
        s.generate_rate_sample(&mut rs, now);

        // ack_elapsed is measured from P.delivered_time, which is the send
        // time of p0 since nothing was in flight before it.
        assert_eq!(rs.ack_elapsed, Duration::from_millis(210));
        assert_eq!(rs.send_elapsed, Duration::from_millis(200));
        assert_eq!(rs.interval, Duration::from_millis(210));
        assert_eq!(rs.rtt, Some(Duration::from_millis(10)));
    }

    #[test]
    fn app_limited_bubble() {
        let start = Instant::now();
        let mut s = DeliveryRateSampler::new(start);

        s.mark_connection_app_limited(0);
        assert!(s.is_app_limited());

        let p = s.on_packet_sent(0, MSS, start, 0);
        assert!(p.is_app_limited);

        let now = start + Duration::from_millis(50);
        let mut rs = RateSample::new();
        s.on_packet_acked(&mut rs, &p, now);
        s.generate_rate_sample(&mut rs, now);
        assert!(rs.is_app_limited);
        // The bubble has been acked.
        assert!(!s.is_app_limited());
    }

    #[test]
    fn lost_since_transmit() {
        let start = Instant::now();
        let mut s = DeliveryRateSampler::new(start);

        let p0 = s.on_packet_sent(0, MSS, start, 0);
        let p1 = s.on_packet_sent(1, MSS, start, MSS);
        let _ = p0;

        let now = start + Duration::from_millis(50);
        let mut rs = RateSample::new();
        s.on_packet_acked(&mut rs, &p1, now);
        s.on_packet_lost(MSS);
        s.generate_rate_sample(&mut rs, now);
        assert_eq!(rs.lost, MSS);
        assert_eq!(rs.tx_in_flight, 2 * MSS);
    }

    #[test]
    fn no_data_no_sample() {
        let start = Instant::now();
        let mut s = DeliveryRateSampler::new(start);
        let mut rs = RateSample::new();
        s.generate_rate_sample(&mut rs, start);
        assert!(!rs.has_data);
        assert_eq!(rs.delivery_rate, Bandwidth::zero());
        assert_eq!(rs.rtt, None);
    }
}
