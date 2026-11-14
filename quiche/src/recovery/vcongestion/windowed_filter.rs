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

//! Windowed maximum filter over a virtual (non wall-clock) time.
//!
//! draft-ietf-ccwg-bbr-07 uses `UpdateWindowedMaxFilter()` for both
//! `BBR.max_bw_filter` (Sections 5.5.3, 5.5.5 and 5.5.6: time is
//! `BBR.cycle_count`, window of `BBR.MaxBwFilterLen` = 2 ProbeBW cycles) and
//! `BBR.extra_acked_filter` (Section 5.5.9: time is `BBR.round_count`, window
//! of 1 round trip in Startup and `BBR.ExtraAckedFilterLen` = 10 round trips
//! afterwards). Section 5.5.5 suggests, but does not require, Kathleen
//! Nichols' algorithm.
//!
//! <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.txt>
//!
//! Because both windows are short and measured in discrete units, this filter
//! computes the exact windowed maximum using a monotonic queue: it keeps at
//! most one candidate per distinct time value, with candidate values strictly
//! decreasing from front to back. A sample taken at time `t` is part of the
//! window at time `now` while `now - t < window_length`.

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sample<T> {
    time: u64,
    value: T,
}

/// Exact windowed max filter over a discrete virtual time.
#[derive(Debug)]
pub(super) struct WindowedMaxFilter<T> {
    samples: VecDeque<Sample<T>>,
}

impl<T: Copy + Ord> WindowedMaxFilter<T> {
    /// `InitWindowedMaxFilter(filter, value, time)`.
    pub(super) fn new(value: T, time: u64) -> Self {
        let mut samples = VecDeque::with_capacity(4);
        samples.push_back(Sample { time, value });
        WindowedMaxFilter { samples }
    }

    /// Discard all samples and start over with a single sample.
    #[allow(dead_code)]
    pub(super) fn reset(&mut self, value: T, time: u64) {
        self.samples.clear();
        self.samples.push_back(Sample { time, value });
    }

    /// `UpdateWindowedMaxFilter(filter, value, time, window_length)`.
    ///
    /// Inserts a new sample and returns the maximum over the samples taken in
    /// the last `window_length` units of virtual time (including `time`).
    pub(super) fn update(
        &mut self, value: T, time: u64, window_length: u64,
    ) -> T {
        let window_length = window_length.max(1);

        // Expire samples that are no longer within the window.
        while let Some(front) = self.samples.front() {
            if time.saturating_sub(front.time) >= window_length {
                self.samples.pop_front();
            } else {
                break;
            }
        }

        // Drop candidates that can never again be the maximum because the new
        // sample is both newer and at least as large.
        while let Some(back) = self.samples.back() {
            if back.value <= value {
                self.samples.pop_back();
            } else {
                break;
            }
        }

        // Keep at most one candidate per time value: if the newest candidate
        // shares this time and is larger, the new sample adds nothing.
        let redundant = self
            .samples
            .back()
            .is_some_and(|back| back.time >= time && back.value > value);

        if !redundant {
            self.samples.push_back(Sample { time, value });
        }

        self.get()
    }

    /// The current windowed maximum, as of the most recent update.
    pub(super) fn get(&self) -> T {
        // The filter always holds at least one sample: `update()` pushes the
        // new sample unless a larger, newer-or-equal one is already present.
        self.samples
            .front()
            .map(|s| s.value)
            .expect("filter always has a sample")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_max_within_window() {
        let mut f = WindowedMaxFilter::new(0u64, 0);
        assert_eq!(f.get(), 0);

        assert_eq!(f.update(10, 0, 2), 10);
        assert_eq!(f.update(5, 0, 2), 10);
        assert_eq!(f.update(7, 1, 2), 10);
        // Sample at time 0 expires at time 2, leaving the sample at time 1.
        assert_eq!(f.update(3, 2, 2), 7);
        // Sample at time 1 expires at time 3.
        assert_eq!(f.update(1, 3, 2), 3);
        assert_eq!(f.update(20, 3, 2), 20);
    }

    #[test]
    fn window_of_one_only_remembers_current_time() {
        let mut f = WindowedMaxFilter::new(0u64, 0);
        assert_eq!(f.update(100, 5, 1), 100);
        assert_eq!(f.update(50, 5, 1), 100);
        assert_eq!(f.update(10, 6, 1), 10);
    }

    #[test]
    fn varying_window_length() {
        let mut f = WindowedMaxFilter::new(0u64, 0);
        f.update(100, 1, 10);
        f.update(50, 5, 10);
        assert_eq!(f.update(10, 10, 10), 100);
        assert_eq!(f.update(10, 11, 10), 50);
        // Shrinking the window expires older samples immediately.
        assert_eq!(f.update(1, 12, 1), 1);
    }

    #[test]
    fn bounded_size() {
        let mut f = WindowedMaxFilter::new(0u64, 0);
        for t in 0..1000u64 {
            for v in (0..100u64).rev() {
                f.update(v, t, 10);
            }
            assert!(f.samples.len() <= 10);
        }
    }
}
