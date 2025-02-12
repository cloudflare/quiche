use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use datagram_socket::{DatagramSocketSend, DatagramSocketSendExt, MAX_DATAGRAM_SIZE};
use quiche::{ConnectionId, Header, Type as PacketType};
use task_killswitch::spawn_with_killswitch;

use crate::metrics::{labels, Metrics};
use crate::quic::addr_validation_token::AddrValidationTokenManager;
use crate::quic::router::NewConnection;
use crate::quic::{make_qlog_writer, Incoming};
use crate::{ConnectionIdGenerator, QuicResultExt};

use super::InitialPacketHandler;

/// A [`ConnectionAcceptor`] is an [`InitialPacketHandler`] that acts as a server and
/// accepts quic connections.
pub(crate) struct ConnectionAcceptor<S, M> {
    config: ConnectionAcceptorConfig,
    socket: Arc<S>,
    socket_cookie: u64,
    token_manager: AddrValidationTokenManager,
    cid_generator: Box<dyn ConnectionIdGenerator<'static>>,
    metrics: M,
}

pub(crate) struct ConnectionAcceptorConfig {
    pub(crate) disable_client_ip_validation: bool,
    pub(crate) qlog_dir: Option<String>,
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
        config: ConnectionAcceptorConfig,
        socket: Arc<S>,
        socket_cookie: u64,
        token_manager: AddrValidationTokenManager,
        cid_generator: Box<dyn ConnectionIdGenerator<'static>>,
        metrics: M,
    ) -> Self {
        Self {
            config,
            socket,
            socket_cookie,
            token_manager,
            cid_generator,
            metrics,
        }
    }

    fn accept_conn(
        &mut self,
        incoming: Incoming,
        scid: ConnectionId<'static>,
        original_dcid: Option<&ConnectionId>,
        pending_cid: Option<ConnectionId<'static>>,
        quiche_config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>> {
        let handshake_start_time = Instant::now();

        #[cfg(feature = "zero-copy")]
        let mut conn = quiche::accept_with_buf_factory(
            &scid,
            original_dcid,
            incoming.local_addr,
            incoming.peer_addr,
            quiche_config,
        )
        .into_io()?;

        #[cfg(not(feature = "zero-copy"))]
        let mut conn = quiche::accept(
            &scid,
            original_dcid,
            incoming.local_addr,
            incoming.peer_addr,
            quiche_config,
        )
        .into_io()?;

        if let Some(qlog_dir) = &self.config.qlog_dir {
            let id = format!("{:?}", &scid);
            if let Ok(writer) = make_qlog_writer(qlog_dir, &id) {
                conn.set_qlog(
                    std::boxed::Box::new(writer),
                    "oxy qlog".to_string(),
                    format!("oxy qlog id={id}"),
                );
            }
        }

        if let Some(keylog_file) = &self.config.keylog_file {
            if let Ok(keylog_clone) = keylog_file.try_clone() {
                conn.set_keylog(Box::new(keylog_clone));
            }
        }

        Ok(Some(NewConnection {
            conn,
            handshake_start_time,
            pending_cid,
            initial_pkt: Some(incoming),
        }))
    }

    fn handshake_reply(
        &self,
        incoming: Incoming,
        writer: impl FnOnce(&mut [u8]) -> io::Result<usize>,
    ) -> io::Result<Option<NewConnection>> {
        let mut send_buf = [0u8; MAX_DATAGRAM_SIZE];
        let written = writer(&mut send_buf)?;
        let socket = Arc::clone(&self.socket);
        #[cfg(target_os = "linux")]
        let with_pktinfo = self.config.with_pktinfo;

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
                let from = Some(incoming.local_addr).filter(|_| with_pktinfo);
                let _ = crate::quic::io::gso::send_to(udp, to, from, send_buf, 1, 1, None).await;
            }

            #[cfg(not(target_os = "linux"))]
            let _ = socket.send_to(send_buf, to).await;
        });

        Ok(None)
    }

    fn stateless_retry(
        &mut self,
        incoming: Incoming,
        hdr: Header,
    ) -> io::Result<Option<NewConnection>> {
        let scid = self.new_connection_id();

        let token = self.token_manager.gen(&hdr.dcid, incoming.peer_addr);

        self.handshake_reply(incoming, move |buf| {
            quiche::retry(&hdr.scid, &hdr.dcid, &scid, &token, hdr.version, buf).into_io()
        })
    }

    fn new_connection_id(&self) -> ConnectionId<'static> {
        self.cid_generator.new_connection_id(self.socket_cookie)
    }
}

impl<S, M> InitialPacketHandler for ConnectionAcceptor<S, M>
where
    S: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    fn handle_initials(
        &mut self,
        incoming: Incoming,
        hdr: quiche::Header<'static>,
        quiche_config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>> {
        if hdr.ty != PacketType::Initial {
            // Non-initial packets should have a valid CID, but we want to have some
            // telemetry if this isn't the case.
            if let Err(e) = self
                .cid_generator
                .verify_connection_id(self.socket_cookie, &hdr.dcid)
            {
                self.metrics.invalid_cid_packet_count(e).inc();
            }

            Err(labels::QuicInvalidInitialPacketError::WrongType(hdr.ty))?;
        }

        if !quiche::version_is_supported(hdr.version) {
            return self.handshake_reply(incoming, |buf| {
                quiche::negotiate_version(&hdr.scid, &hdr.dcid, buf).into_io()
            });
        }

        let (scid, original_dcid, pending_cid) = if self.config.disable_client_ip_validation {
            (self.new_connection_id(), None, Some(hdr.dcid))
        } else {
            // NOTE: token is always present in Initial packets
            let token = hdr.token.as_ref().unwrap();

            if token.is_empty() {
                return self.stateless_retry(incoming, hdr);
            }

            (
                hdr.dcid,
                Some(
                    self.token_manager
                        .validate_and_extract_original_dcid(token, incoming.peer_addr)
                        .or(Err(
                            labels::QuicInvalidInitialPacketError::TokenValidationFail,
                        ))?,
                ),
                None,
            )
        };

        self.accept_conn(
            incoming,
            scid,
            original_dcid.as_ref(),
            pending_cid,
            quiche_config,
        )
    }
}
