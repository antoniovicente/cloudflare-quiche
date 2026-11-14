// Copyright (C) 2025, Cloudflare, Inc.
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

use std::net::SocketAddr;

use boring::ssl::SslContextBuilder;
use foundations::telemetry::log;

use crate::quic::QuicheConnection;
use crate::settings::TlsCertificatePaths;

/// A set of hooks executed at the level of a [quiche::Connection].
pub trait ConnectionHook {
    /// Constructs an optional [`SslContextBuilder`].
    ///
    /// This method allows full customization of quiche's SSL context, for
    /// example to specify async callbacks during the QUIC handshake. It is
    /// called once per socket during initial setup, and then reused across
    /// all connections on that socket.
    ///
    /// Only called if both the hook and [`TlsCertificatePaths`] are set in
    /// [`ConnectionParams`](crate::ConnectionParams).
    fn create_custom_ssl_context_builder(
        &self, settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder>;

    /// Called when the QUIC connection reports a path-specific event.
    ///
    /// This runs synchronously on the connection's I/O worker and must not
    /// block. Applications that need asynchronous processing should copy the
    /// event into a non-blocking channel.
    fn on_path_event(
        &self, _qconn: &mut QuicheConnection, _event: &quiche::PathEvent,
    ) {
    }

    /// Returns saved congestion control parameters to resume a new
    /// connection with Careful Resume ([RFC 9959]).
    ///
    /// This is called once for every new connection, before any packet is
    /// sent, with the local and peer address of the connection. The returned
    /// parameters are applied with
    /// [`quiche::Connection::set_careful_resume_params()`]. Careful Resume is
    /// only supported by the `bbr2_gcongestion` congestion control algorithm
    /// with pacing enabled, and the parameters are ignored otherwise.
    ///
    /// Implementations are responsible for storing the parameters observed by
    /// previous connections (see
    /// [`save_careful_resume_params()`](Self::save_careful_resume_params)).
    /// In particular, they must:
    ///
    /// * only return parameters observed between the same endpoints;
    /// * not return parameters older than a configured lifetime;
    /// * not return the same parameters to more than one connection at a time,
    ///   e.g. by reserving them until
    ///   [`save_careful_resume_params()`](Self::save_careful_resume_params) is
    ///   called for the connection.
    ///
    /// This runs synchronously on the connection's packet router task and
    /// must not block.
    ///
    /// [RFC 9959]: https://www.rfc-editor.org/rfc/rfc9959.html
    fn careful_resume_params(
        &self, _local_addr: SocketAddr, _peer_addr: SocketAddr,
    ) -> Option<quiche::CarefulResumeParams> {
        None
    }

    /// Called when a connection is closed, with the final statistics of its
    /// active path, to save the congestion control parameters observed on
    /// the path for Careful Resume ([RFC 9959]).
    ///
    /// Implementations should store
    /// [`careful_resume_observation`](quiche::PathStats::careful_resume_observation),
    /// if any, keyed by the path's `local_addr` and `peer_addr`, together
    /// with the time it was observed. If
    /// [`careful_resume`](quiche::PathStats::careful_resume) reports that the
    /// Safe Retreat Phase was entered, the saved parameters used to resume the
    /// connection were found to be invalid and must be deleted unless they are
    /// replaced by a new observation.
    ///
    /// This is called for every connection that reaches the close stage of
    /// its I/O worker, so it can also be used to release parameters reserved
    /// by [`careful_resume_params()`](Self::careful_resume_params). It runs
    /// synchronously on the connection's I/O worker and must not block.
    ///
    /// [RFC 9959]: https://www.rfc-editor.org/rfc/rfc9959.html
    fn save_careful_resume_params(&self, _path_stats: &quiche::PathStats) {}
}

/// Applies the Careful Resume parameters provided by `hook`, if any, to a
/// connection that has not sent any packet yet.
pub(crate) fn apply_careful_resume_params(
    hook: Option<&(dyn ConnectionHook + Send + Sync)>,
    qconn: &mut QuicheConnection, local_addr: SocketAddr, peer_addr: SocketAddr,
) {
    let Some(params) =
        hook.and_then(|hook| hook.careful_resume_params(local_addr, peer_addr))
    else {
        return;
    };

    if let Err(error) = qconn.set_careful_resume_params(params) {
        log::warn!("failed to set careful resume params"; "error" => ?error);
    }
}

/// Reports the final statistics of a connection's active path to `hook`.
pub(crate) fn save_careful_resume_params(
    hook: Option<&(dyn ConnectionHook + Send + Sync)>, qconn: &QuicheConnection,
) {
    let Some(hook) = hook else {
        return;
    };

    if let Some(path_stats) = qconn.path_stats().find(|stats| stats.active) {
        hook.save_careful_resume_params(&path_stats);
    }
}
