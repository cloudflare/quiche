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

use std::io;
use std::mem;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

use datagram_socket::DatagramSocketSend;
use datagram_socket::DatagramSocketSendExt;
use datagram_socket::MaybeConnectedSocket;
use datagram_socket::MAX_DATAGRAM_SIZE;
use foundations::telemetry::log;
use quiche::ConnectionId;
use quiche::Header;
use tokio_util::task::AbortOnDropHandle;
use tokio_util::time::delay_queue::Key;
use tokio_util::time::DelayQueue;

use crate::quic::router::InitialPacketHandler;
use crate::quic::router::NewConnection;
use crate::quic::Incoming;
use crate::quic::QuicheConnection;

/// A [`ClientConnector`] manages client-initiated [`quiche::Connection`]s. When
/// a connection is established, this struct returns the connection to the
/// [`InboundPacketRouter`](super::InboundPacketRouter) for further processing.
pub(crate) struct ClientConnector<Tx> {
    socket_tx: MaybeConnectedSocket<Arc<Tx>>,
    connection: ConnectionState,
    timeout_queue: DelayQueue<ConnectionId<'static>>,
    /// The most recently spawned send task. Each new one waits for it to
    /// finish, so only one task sends on the socket at a time. Dropping the
    /// connector aborts every unfinished send task.
    send_task: Option<AbortOnDropHandle<()>>,
}

/// State the connecting connection is in.
enum ConnectionState {
    /// Connection hasn't had any initials sent for it
    Queued(Box<QuicheConnection>),
    /// It's currently in a QUIC handshake
    Pending(PendingConnection),
    /// It's been returned to the
    /// [`InboundPacketRouter`](super::InboundPacketRouter).
    Returned,
}

impl ConnectionState {
    fn take_if_queued(&mut self) -> Option<Box<QuicheConnection>> {
        match mem::replace(self, Self::Returned) {
            Self::Queued(conn) => Some(conn),
            state => {
                *self = state;
                None
            },
        }
    }

    fn take_if_pending_and_id_matches(
        &mut self, scid: &ConnectionId<'static>,
    ) -> Option<PendingConnection> {
        match mem::replace(self, Self::Returned) {
            Self::Pending(pending) if *scid == pending.conn.source_id() =>
                Some(pending),
            state => {
                *self = state;
                None
            },
        }
    }
}

/// A [`PendingConnection`] holds an internal [`quiche::Connection`] and an
/// optional timeout [`Key`].
struct PendingConnection {
    conn: Box<QuicheConnection>,
    timeout_key: Option<Key>,
    handshake_start_time: Instant,
}

impl<Tx> ClientConnector<Tx>
where
    Tx: DatagramSocketSend + Send + 'static,
{
    pub(crate) fn new(
        socket_tx: Arc<Tx>, connection: Box<QuicheConnection>,
    ) -> Self {
        Self {
            socket_tx: MaybeConnectedSocket::new(socket_tx),
            connection: ConnectionState::Queued(connection),
            timeout_queue: Default::default(),
            send_task: None,
        }
    }

    /// Sets the connection to it's pending state. Await [`Incoming`] packets.
    ///
    /// This sends any pending packets and arms the connection's timeout timer.
    fn set_connection_to_pending(
        &mut self, mut conn: Box<QuicheConnection>,
    ) -> io::Result<()> {
        simple_conn_send(&self.socket_tx, &mut conn, &mut self.send_task)?;

        let timeout_key = conn.timeout_instant().map(|instant| {
            self.timeout_queue
                .insert_at(conn.source_id().into_owned(), instant.into())
        });

        self.connection = ConnectionState::Pending(PendingConnection {
            conn,
            timeout_key,
            handshake_start_time: Instant::now(),
        });

        Ok(())
    }

    /// Handles an incoming packet (or packets) designated for this pending
    /// connection.
    ///
    /// If the connection is pending, we return it
    fn on_incoming(
        &mut self, mut incoming: Incoming, hdr: Header<'static>,
    ) -> io::Result<Option<NewConnection>> {
        let Some(PendingConnection {
            mut conn,
            timeout_key,
            handshake_start_time,
        }) = self.connection.take_if_pending_and_id_matches(&hdr.dcid)
        else {
            log::debug!("Received Initial packet for unknown connection ID"; "scid" => ?hdr.dcid);
            return Ok(None);
        };

        let recv_info = quiche::RecvInfo {
            from: incoming.peer_addr,
            to: incoming.local_addr,
        };

        if let Some(gro) = incoming.gro {
            for dgram in incoming.buf.chunks_mut(gro as usize) {
                // Log error here if recv fails
                let _ = conn.recv(dgram, recv_info);
            }
        } else {
            // Log error here if recv fails
            let _ = conn.recv(&mut incoming.buf, recv_info);
        }

        // disarm the timer since we're either going to immediately rearm it or
        // return an established connection.
        if let Some(key) = timeout_key {
            self.timeout_queue.remove(&key);
        }

        let scid = conn.source_id();
        if conn.is_established() {
            log::debug!("QUIC connection established"; "scid" => ?scid);

            Ok(Some(NewConnection {
                conn,
                pending_cid: None,
                initial_pkt: None,
                enable_per_connection_dscp: false,
                cid_generator: None,
                handshake_start_time,
            }))
        } else if conn.is_closed() {
            let scid = conn.source_id();
            log::error!("QUIC connection closed on_incoming"; "scid" => ?scid);

            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connection {scid:?} timed out"),
            ))
        } else {
            self.set_connection_to_pending(conn).map(|()| None)
        }
    }

    /// [`ClientConnector::on_timeout`] runs [`quiche::Connection::on_timeout`]
    /// for a pending connection. If the connection is closed, this sends an
    /// error upstream.
    fn on_timeout(&mut self, scid: ConnectionId<'static>) -> io::Result<()> {
        log::debug!("connection timedout"; "scid" => ?scid);

        let Some(mut pending) =
            self.connection.take_if_pending_and_id_matches(&scid)
        else {
            log::debug!("timedout connection missing from pending map"; "scid" => ?scid);
            return Ok(());
        };

        pending.conn.on_timeout();

        if pending.conn.is_closed() {
            log::error!("pending connection closed on_timeout"; "scid" => ?scid);

            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connection {scid:?} timed out"),
            ));
        }

        self.set_connection_to_pending(pending.conn)
    }

    /// [`ClientConnector::update`] handles expired pending connections and
    /// checks starts the inner connection if not started yet.
    fn update(&mut self, cx: &mut Context) -> io::Result<()> {
        while let Poll::Ready(Some(expired)) = self.timeout_queue.poll_expired(cx)
        {
            let scid = expired.into_inner();
            self.on_timeout(scid)?;
        }

        if let Some(conn) = self.connection.take_if_queued() {
            self.set_connection_to_pending(conn)?;
        }

        Ok(())
    }
}

impl<Tx> InitialPacketHandler for ClientConnector<Tx>
where
    Tx: DatagramSocketSend + Send + 'static,
{
    fn update(&mut self, ctx: &mut Context<'_>) -> io::Result<()> {
        ClientConnector::update(self, ctx)
    }

    fn handle_initials(
        &mut self, incoming: Incoming, hdr: Header<'static>,
        _: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>> {
        self.on_incoming(incoming, hdr)
    }
}

/// Repeatedly send packets until quiche reports that it's done.
///
/// This does not have to be efficent, since once a connection is established
/// the [`crate::quic::io::worker::IoWorker`] will take over sending and
/// receiving.
///
/// The packets are sent in order from a task that first waits for
/// `prev_send_task`: the socket's `poll_send` only wakes the most recent
/// caller, so concurrent senders can hang forever.
fn simple_conn_send<Tx: DatagramSocketSend + Send + Sync + 'static>(
    socket_tx: &MaybeConnectedSocket<Arc<Tx>>, conn: &mut QuicheConnection,
    prev_send_task: &mut Option<AbortOnDropHandle<()>>,
) -> io::Result<()> {
    let scid = conn.source_id().into_owned();
    log::debug!("sending client Initials to peer"; "scid" => ?scid);

    let mut packets = Vec::new();
    let result = loop {
        let mut buf = [0; MAX_DATAGRAM_SIZE];
        let send_res = conn.send(&mut buf);

        match send_res {
            Ok((n, send_info)) =>
                packets.push((buf[0..n].to_vec(), send_info.to)),
            Err(quiche::Error::Done) => break Ok(()),
            Err(error) => {
                log::error!("error writing packets to quiche's internal buffer"; "scid" => ?scid, "error" => error.to_string());
                break Err(std::io::Error::other(error));
            },
        }
    };

    if !packets.is_empty() {
        let socket = socket_tx.clone();
        let prev = prev_send_task.take();
        *prev_send_task = Some(AbortOnDropHandle::new(tokio::spawn(
            async move {
                if let Some(prev) = prev {
                    let _ = prev.await;
                }
                for (buf, to) in packets {
                    if let Err(error) = socket.send_to(&buf, to).await {
                        log::error!("error sending client Initial packets to peer"; "scid" => ?scid, "peer_addr" => to, "error" => error.to_string());
                    }
                }
            },
        )));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::poll_fn;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::task::Waker;
    use std::time::Duration;

    /// A socket that isn't writable until the test says so and, like
    /// `tokio::net::UdpSocket::poll_send`, only wakes the most recent caller.
    #[derive(Default)]
    struct LatestWakerSocket(Mutex<SocketState>);

    #[derive(Default)]
    struct SocketState {
        writable: bool,
        waker: Option<Waker>,
        sent: usize,
    }

    impl DatagramSocketSend for LatestWakerSocket {
        fn poll_send(
            &self, cx: &mut Context, buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.lock().unwrap();
            if !state.writable {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            state.sent += 1;
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_send_to(
            &self, cx: &mut Context, buf: &[u8], _addr: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            self.poll_send(cx, buf)
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn sends_every_initial_when_socket_wakes_only_latest_sender() {
        // A long ALPN list makes the ClientHello span more than one Initial.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        let alpn: Vec<Vec<u8>> = (0..10u8).map(|i| vec![b'a' + i; 200]).collect();
        let alpn: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).collect();
        config.set_application_protos(&alpn).unwrap();
        config.set_initial_rtt(Duration::from_millis(1));
        let conn = quiche::connect_with_buffer_factory(
            Some("test.com"),
            &ConnectionId::from_ref(&[0xba; 16]),
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            &mut config,
        )
        .unwrap();

        let socket = Arc::new(LatestWakerSocket::default());
        let mut connector =
            ClientConnector::new(Arc::clone(&socket), Box::new(conn));
        poll_fn(|cx| Poll::Ready(connector.update(cx)))
            .await
            .unwrap();
        assert!(
            pending_conn(&connector).stats().sent > 1,
            "ClientHello fit in one Initial"
        );

        // The PTO fires while the first flight is still waiting, so a
        // retransmission is queued behind it.
        fire_pto(&mut connector).await;
        let waker = {
            let mut state = socket.0.lock().unwrap();
            state.writable = true;
            state.waker.take().expect("no sender waiting on the socket")
        };
        waker.wake();
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            socket.0.lock().unwrap().sent,
            pending_conn(&connector).stats().sent,
            "a send task never finished"
        );

        // Dropping the connector aborts a send that is still waiting.
        socket.0.lock().unwrap().writable = false;
        fire_pto(&mut connector).await;
        drop(connector);
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            Arc::strong_count(&socket),
            1,
            "a send task outlived the connector"
        );
    }

    fn pending_conn(
        connector: &ClientConnector<LatestWakerSocket>,
    ) -> &QuicheConnection {
        match &connector.connection {
            ConnectionState::Pending(pending) => &pending.conn,
            _ => panic!("connection isn't pending"),
        }
    }

    /// Runs the connector's timeout, checks that it queued a retransmission
    /// and lets the send task reach the socket.
    async fn fire_pto(connector: &mut ClientConnector<LatestWakerSocket>) {
        // quiche's loss timer reads the real clock, which pausing doesn't stop.
        std::thread::sleep(Duration::from_millis(50));
        let before = pending_conn(connector).stats().sent;
        let scid = pending_conn(connector).source_id().into_owned();
        connector.on_timeout(scid).unwrap();
        assert!(
            pending_conn(connector).stats().sent > before,
            "PTO didn't queue a retransmission"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
