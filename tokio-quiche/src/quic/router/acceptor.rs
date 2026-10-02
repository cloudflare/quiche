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

use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use datagram_socket::DatagramSocketSend;
use datagram_socket::DatagramSocketSendExt;
use datagram_socket::MAX_DATAGRAM_SIZE;
use qlog::writer::make_qlog_writer_from_path;
use qlog::writer::qlog_file_name;
use qlog::writer::QlogCompression;
use quiche::ConnectionId;
use quiche::Header;
use quiche::RetryConnectionIds;
use quiche::Type as PacketType;
use quiche::MIN_CLIENT_INITIAL_LEN;
use task_killswitch::spawn_with_killswitch;

use crate::metrics::labels;
use crate::metrics::Metrics;
use crate::quic::addr_validation_token::AddrValidationTokenManager;
use crate::quic::connection::SharedConnectionIdGenerator;
use crate::quic::router::NewConnection;
use crate::quic::Incoming;
use crate::QuicResultExt;

use super::InitialPacketHandler;

/// A [`ConnectionAcceptor`] is an [`InitialPacketHandler`] that acts as a
/// server and accepts quic connections.
pub(crate) struct ConnectionAcceptor<S, M> {
    config: ConnectionAcceptorConfig,
    socket: Arc<S>,
    token_manager: AddrValidationTokenManager,
    cid_generator: SharedConnectionIdGenerator,
    metrics: M,
}

pub(crate) struct ConnectionAcceptorConfig {
    pub(crate) disable_client_ip_validation: bool,
    pub(crate) qlog_dir: Option<String>,
    pub(crate) qlog_compression: QlogCompression,
    pub(crate) keylog_file: Option<File>,
    #[cfg(target_os = "linux")]
    pub(crate) with_pktinfo: bool,
}

impl<S, M> ConnectionAcceptor<S, M>
where
    S: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    pub(crate) fn new(
        config: ConnectionAcceptorConfig, socket: Arc<S>,
        token_manager: AddrValidationTokenManager,
        cid_generator: SharedConnectionIdGenerator, metrics: M,
    ) -> Self {
        Self {
            config,
            socket,
            token_manager,
            cid_generator,
            metrics,
        }
    }

    fn accept_conn(
        &mut self, incoming: Incoming, retry_cids: Option<RetryConnectionIds>,
        pending_cid: ConnectionId<'static>, quiche_config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>> {
        let handshake_start_time = Instant::now();
        let scid = self.cid_generator.new_connection_id();

        let mut conn = if let Some(retry_cids) = retry_cids {
            quiche::accept_with_retry(
                &scid,
                retry_cids,
                incoming.local_addr,
                incoming.peer_addr,
                quiche_config,
            )
        } else {
            quiche::accept_with_buf_factory(
                &scid,
                None,
                incoming.local_addr,
                incoming.peer_addr,
                quiche_config,
            )
        }
        .into_io()?;

        if let Some(qlog_dir) = &self.config.qlog_dir {
            let id = format!("{:?}", scid);
            let path = std::path::Path::new(qlog_dir)
                .join(qlog_file_name(&id, self.config.qlog_compression));
            if let Ok(writer) =
                make_qlog_writer_from_path(&path, self.config.qlog_compression)
            {
                conn.set_qlog(
                    writer,
                    "tokio-quiche qlog".to_string(),
                    format!("tokio-quiche qlog id={id}"),
                );
            }
        }

        if let Some(keylog_file) = &self.config.keylog_file {
            if let Ok(keylog_clone) = keylog_file.try_clone() {
                conn.set_keylog(Box::new(keylog_clone));
            }
        }

        Ok(Some(NewConnection {
            conn: Box::new(conn),
            handshake_start_time,
            pending_cid: Some(pending_cid),
            cid_generator: Some(Arc::clone(&self.cid_generator)),
            initial_pkt: Some(incoming),
        }))
    }

    fn handshake_reply(
        &self, incoming: Incoming,
        writer: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<Option<NewConnection>> {
        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE];
        let written = writer(&mut send_buf)?;
        let socket = Arc::clone(&self.socket);
        #[cfg(target_os = "linux")]
        let with_pktinfo = self.config.with_pktinfo;
        #[cfg(target_os = "linux")]
        let would_block_metric = self
            .metrics
            .write_errors(labels::QuicWriteError::WouldBlock);
        #[cfg(target_os = "linux")]
        let send_to_wouldblock_duration_s =
            self.metrics.send_to_wouldblock_duration_s();

        spawn_with_killswitch(async move {
            let send_buf = &send_buf[..written];
            let to = incoming.peer_addr;

            #[allow(unused_variables)]
            let Some(udp) = socket.as_udp_socket() else {
                let _ = socket.send_to(send_buf, to).await;
                return;
            };

            #[cfg(target_os = "linux")]
            {
                let from = with_pktinfo.then_some(incoming.local_addr);
                let _ = crate::quic::io::gso::send_to(
                    udp,
                    to,
                    from,
                    send_buf,
                    send_buf.len(),
                    None,
                    would_block_metric,
                    send_to_wouldblock_duration_s,
                )
                .await;
            }

            #[cfg(not(target_os = "linux"))]
            let _ = socket.send_to(send_buf, to).await;
        });

        Ok(None)
    }

    fn stateless_retry(
        &mut self, incoming: Incoming, hdr: Header,
    ) -> io::Result<Option<NewConnection>> {
        let scid = self.cid_generator.new_connection_id();

        let token = self.token_manager.gen(&hdr.dcid, incoming.peer_addr);

        self.handshake_reply(incoming, move |buf| {
            quiche::retry(&hdr.scid, &hdr.dcid, &scid, &token, hdr.version, buf)
                .into_io()
        })
    }
}

impl<S, M> InitialPacketHandler for ConnectionAcceptor<S, M>
where
    S: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    fn handle_initials(
        &mut self, incoming: Incoming, hdr: quiche::Header<'static>,
        quiche_config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>> {
        if hdr.ty != PacketType::Initial {
            // Non-initial packets should have a valid CID, but we want to have
            // some telemetry if this isn't the case.
            if let Err(e) = self.cid_generator.verify_connection_id(&hdr.dcid) {
                self.metrics.invalid_cid_packet_count(e).inc();
            }

            Err(labels::QuicInvalidInitialPacketError::WrongType(hdr.ty))?;
        }

        // Clients must expand datagrams carrying Initial packets to at least
        // 1200 bytes (RFC 9000 Section 14.1). Anything shorter is discarded
        // before any stateless reply, so a spoofed-source datagram can't
        // elicit a Retry or Version Negotiation packet larger than itself.
        let dgram_len = match incoming.gro {
            Some(gro) => incoming.buf.len().min(gro as usize),
            None => incoming.buf.len(),
        };

        if dgram_len < MIN_CLIENT_INITIAL_LEN {
            Err(labels::QuicInvalidInitialPacketError::DatagramTooShort)?;
        }

        if !quiche::version_is_supported(hdr.version) {
            return self.handshake_reply(incoming, |buf| {
                quiche::negotiate_version(&hdr.scid, &hdr.dcid, buf).into_io()
            });
        }

        if self.config.disable_client_ip_validation {
            return self.accept_conn(incoming, None, hdr.dcid, quiche_config);
        }

        // NOTE: token is always present in Initial packets
        let token = hdr.token.as_ref().unwrap();
        if token.is_empty() {
            return self.stateless_retry(incoming, hdr);
        }

        let original_dcid = self
            .token_manager
            .validate_and_extract_original_dcid(token, incoming.peer_addr)
            .or(Err(
                labels::QuicInvalidInitialPacketError::TokenValidationFail,
            ))?;

        let retry_cids = Some(RetryConnectionIds {
            original_destination_cid: &original_dcid,
            retry_source_cid: &hdr.dcid,
        });

        self.accept_conn(incoming, retry_cids, hdr.dcid.clone(), quiche_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::metrics::labels::QuicInvalidInitialPacketError;
    use crate::metrics::DefaultMetrics;
    use crate::quic::connection::SimpleConnectionIdGenerator;
    use crate::quic::router::initial_packet_error_type;

    use quiche::MAX_CONN_ID_LEN;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    /// Builds a datagram carrying a client Initial with an 8-byte DCID, an
    /// empty SCID and an empty token, zero-padded to `len` bytes.
    fn initial_dgram(len: usize) -> Vec<u8> {
        let mut dgram = vec![0u8; len];

        dgram[0] = 0xc0;
        dgram[1..5].copy_from_slice(&quiche::PROTOCOL_VERSION.to_be_bytes());
        dgram[5] = 8;
        dgram[6..14].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        dgram
    }

    async fn acceptor(
    ) -> (ConnectionAcceptor<UdpSocket, DefaultMetrics>, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        let acceptor = ConnectionAcceptor::new(
            ConnectionAcceptorConfig {
                disable_client_ip_validation: false,
                qlog_dir: None,
                qlog_compression: QlogCompression::None,
                keylog_file: None,
                #[cfg(target_os = "linux")]
                with_pktinfo: false,
            },
            Arc::new(socket),
            AddrValidationTokenManager::default(),
            Arc::new(SimpleConnectionIdGenerator),
            DefaultMetrics,
        );

        (acceptor, local_addr)
    }

    fn incoming(
        mut buf: Vec<u8>, peer_addr: SocketAddr, local_addr: SocketAddr,
    ) -> (Incoming, Header<'static>) {
        let hdr = Header::from_slice(&mut buf, MAX_CONN_ID_LEN).unwrap();

        let incoming = Incoming {
            peer_addr,
            local_addr,
            rx_time: None,
            buf,
            gro: None,
            #[cfg(target_os = "linux")]
            so_mark_data: None,
        };

        (incoming, hdr)
    }

    #[tokio::test]
    async fn short_initial_dgram_is_dropped_without_reply() {
        let (mut acceptor, local_addr) = acceptor().await;
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        let (incoming, hdr) = incoming(
            initial_dgram(MIN_CLIENT_INITIAL_LEN - 1),
            peer.local_addr().unwrap(),
            local_addr,
        );

        let err = match acceptor.handle_initials(incoming, hdr, &mut config) {
            Err(e) => e,
            Ok(_) => panic!("short Initial datagram was not rejected"),
        };

        assert_eq!(
            initial_packet_error_type(&err),
            QuicInvalidInitialPacketError::DatagramTooShort
        );

        let mut out = [0u8; MAX_DATAGRAM_SIZE];
        assert!(
            timeout(Duration::from_millis(200), peer.recv_from(&mut out))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn full_size_initial_dgram_gets_retry() {
        let (mut acceptor, local_addr) = acceptor().await;
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        let (incoming, hdr) = incoming(
            initial_dgram(MIN_CLIENT_INITIAL_LEN),
            peer.local_addr().unwrap(),
            local_addr,
        );

        assert!(acceptor
            .handle_initials(incoming, hdr, &mut config)
            .unwrap()
            .is_none());

        let mut out = [0u8; MAX_DATAGRAM_SIZE];
        let (len, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut out))
            .await
            .unwrap()
            .unwrap();

        let hdr = Header::from_slice(&mut out[..len], MAX_CONN_ID_LEN).unwrap();
        assert_eq!(hdr.ty, PacketType::Retry);
    }
}
