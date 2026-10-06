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
    pub(crate) enable_per_connection_dscp: bool,
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
            enable_per_connection_dscp: self.config.enable_per_connection_dscp,
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
                    Some(send_buf.len()),
                    None,
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

#[cfg(all(target_os = "linux", test, not(feature = "fuzzing")))]
mod tests {
    use super::*;
    use crate::metrics::DefaultMetrics;
    use crate::quic::connection::SimpleConnectionIdGenerator;
    use crate::quic::io::gso::test::enable_tos;
    use crate::quic::io::gso::test::recv_tos;
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt;
    use tokio::net::UdpSocket;

    async fn check_stateless_reply_inherits_socket_dscp(
        bind_addr: &str, dscp: u8,
    ) {
        let sender = Arc::new(UdpSocket::bind(bind_addr).await.unwrap());
        let receiver = UdpSocket::bind(bind_addr).await.unwrap();
        enable_tos(&receiver);
        let tos = i32::from(dscp) << 2;
        if sender.local_addr().unwrap().is_ipv4() {
            setsockopt(sender.as_ref(), sockopt::Ipv4Tos, &tos).unwrap();
        } else {
            setsockopt(sender.as_ref(), sockopt::Ipv6TClass, &tos).unwrap();
        }

        let acceptor = ConnectionAcceptor::new(
            ConnectionAcceptorConfig {
                disable_client_ip_validation: false,
                enable_per_connection_dscp: dscp != 0,
                qlog_dir: None,
                qlog_compression: QlogCompression::None,
                keylog_file: None,
                with_pktinfo: true,
            },
            Arc::clone(&sender),
            Default::default(),
            Arc::new(SimpleConnectionIdGenerator),
            DefaultMetrics,
        );

        let incoming = Incoming {
            peer_addr: receiver.local_addr().unwrap(),
            local_addr: sender.local_addr().unwrap(),
            rx_time: None,
            buf: Vec::new(),
            gro: None,
            so_mark_data: None,
        };
        acceptor
            .handshake_reply(incoming, |buf| {
                buf[..5].copy_from_slice(b"reply");
                Ok(5)
            })
            .unwrap();

        let (payload, tos) = recv_tos(&receiver).await;
        assert_eq!(payload, b"reply");
        assert_eq!(tos >> 2, dscp);
    }

    #[tokio::test]
    async fn stateless_reply_inherits_ipv4_socket_dscp() {
        for dscp in [34, 0] {
            check_stateless_reply_inherits_socket_dscp("127.0.0.1:0", dscp).await;
        }
    }

    #[tokio::test]
    async fn stateless_reply_inherits_ipv6_socket_dscp() {
        for dscp in [34, 0] {
            check_stateless_reply_inherits_socket_dscp("[::1]:0", dscp).await;
        }
    }
}
