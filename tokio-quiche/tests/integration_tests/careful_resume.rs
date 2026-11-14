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
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quiche::CarefulResumeParams;
use tokio_quiche::quiche::CarefulResumePhase;
use tokio_quiche::quiche::PathStats;
use tokio_quiche::settings::TlsCertificatePaths;

use crate::fixtures::*;

/// A [`ConnectionHook`] that provides fixed saved parameters and reports the
/// final path statistics of every connection.
struct CarefulResumeHook {
    saved: CarefulResumeParams,
    requested: Mutex<Vec<(SocketAddr, SocketAddr)>>,
    saved_tx: mpsc::UnboundedSender<PathStats>,
}

impl ConnectionHook for CarefulResumeHook {
    fn create_custom_ssl_context_builder(
        &self, _settings: TlsCertificatePaths<'_>,
    ) -> Option<boring::ssl::SslContextBuilder> {
        None
    }

    fn careful_resume_params(
        &self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> Option<CarefulResumeParams> {
        self.requested.lock().unwrap().push((local_addr, peer_addr));
        Some(self.saved)
    }

    fn save_careful_resume_params(&self, path_stats: &PathStats) {
        let _ = self.saved_tx.send(path_stats.clone());
    }
}

#[tokio::test]
async fn careful_resume_hooks() {
    let saved = CarefulResumeParams {
        bandwidth: 12_000_000,
        min_rtt: Duration::from_millis(100),
    };

    let (saved_tx, mut saved_rx) = mpsc::unbounded_channel();
    let hook = Arc::new(CarefulResumeHook {
        saved,
        requested: Mutex::new(Vec::new()),
        saved_tx,
    });

    let mut quic_settings = QuicSettings::default();
    quic_settings.cc_algorithm = "bbr2_gcongestion".to_string();
    // Careful Resume requires pacing.
    quic_settings.enable_pacing = true;

    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    );

    let responses = request(url, 1).await.unwrap();
    assert_eq!(responses.len(), 1);

    // The server reports the path statistics when the connection closes.
    let path_stats = timeout(Duration::from_secs(5), saved_rx.recv())
        .await
        .expect("connection should be closed")
        .unwrap();

    // The saved parameters were requested for the connection's endpoints.
    assert_eq!(*hook.requested.lock().unwrap(), vec![(
        path_stats.local_addr,
        path_stats.peer_addr
    )]);

    // The saved parameters were applied. The loopback RTT is much smaller than
    // the saved RTT, so they are not used to increase the sending rate.
    let careful_resume = path_stats.careful_resume.unwrap();
    assert!(matches!(
        careful_resume.phase,
        CarefulResumePhase::Reconnaissance | CarefulResumePhase::Normal
    ));
    assert!(!careful_resume.safe_retreat_entered);
}
