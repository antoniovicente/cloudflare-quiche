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

//! BBRv3 congestion control implemented from the IETF specification.
//!
//! This module implements BBR as specified in draft-ietf-ccwg-bbr-07, "BBR
//! Congestion Control" (selected with the `vbbr` algorithm name), on top of
//! QUIC loss detection as specified in RFC 9002:
//!
//! * `delivery_rate`: delivery rate sampling (draft Section 4.1).
//! * `bbr`: the BBR state machine, network path model and control parameters
//!   (draft Section 5).
//! * `pacer`: pacing with a send quantum (draft Sections 5.6.2 and 5.6.3, RFC
//!   9002 Section 7.7).
//! * `windowed_filter`: windowed max filters (draft Sections 5.5.5 and 5.5.9).
//!
//! References:
//!
//! * <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.txt>
//! * <https://www.rfc-editor.org/rfc/rfc9002.html>

// The module isn't used by `Recovery` until `VRecovery` is added.
#![allow(dead_code)]

mod bbr;
mod delivery_rate;
mod pacer;
mod windowed_filter;
