use std::time::Instant;

use anyhow::Context;
use futures::FutureExt as _;
use quiche::h3;
use quiche::h3::Header;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;

use crate::http3::driver::client::ClientHooks;
use crate::http3::driver::hooks::DriverHooks;
use crate::http3::driver::server::ServerHooks;
use crate::http3::driver::ClientH3Event;
use crate::http3::driver::H3Controller;
use crate::http3::driver::H3Driver;
use crate::http3::driver::H3Event;
use crate::http3::driver::InboundFrame;
use crate::http3::driver::InboundFrameStream;
use crate::http3::driver::NewClientRequest;
use crate::http3::driver::OutboundFrameSender;
use crate::http3::driver::ServerH3Event;
use crate::http3::settings::Http3Settings;
use crate::quic::HandshakeInfo;
use crate::ApplicationOverQuic as _;
use quiche::test_utils::Pipe;

pub fn default_quiche_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_initial_max_data(1500);
    config.set_initial_max_stream_data_bidi_local(150);
    config.set_initial_max_stream_data_bidi_remote(150);
    config.set_initial_max_stream_data_uni(150);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(5);
    config.verify_peer(false);
    config
}

pub fn make_request_headers(method: &str) -> Vec<Header> {
    vec![
        Header::new(b":method", method.as_bytes()),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"quic.tech"),
        Header::new(b":path", b"/test"),
    ]
}

pub fn make_response_headers() -> Vec<Header> {
    vec![
        Header::new(b":status", b"200"),
        Header::new(b"server", b"quiche-test"),
    ]
}

/// Helper trait to get the either right `quiche::Connection` for
/// ourselvers (to use with the `H3Driver`) or our peer (to use
/// with `quiche::H3::Connection`
pub trait GetConnectionForHook {
    fn qconn(pipe: &mut Pipe) -> &mut quiche::Connection;
    fn peer_qconn(pipe: &mut Pipe) -> &mut quiche::Connection;
}

impl GetConnectionForHook for ClientHooks {
    fn qconn(pipe: &mut Pipe) -> &mut quiche::Connection {
        &mut pipe.client
    }

    fn peer_qconn(pipe: &mut Pipe) -> &mut quiche::Connection {
        &mut pipe.server
    }
}

impl GetConnectionForHook for ServerHooks {
    fn qconn(pipe: &mut Pipe) -> &mut quiche::Connection {
        &mut pipe.server
    }

    fn peer_qconn(pipe: &mut Pipe) -> &mut quiche::Connection {
        &mut pipe.client
    }
}

/// Similar to `quiche::test_utils::Pipe`, a wrapper with helper functions
/// for a client and server endpoint. One endpoint is driven by an H3Driver
/// to allow testing the H3Driver logic. The other endpoint (the peer) is
/// driven directly by an `quiche::h3::Connection`.
pub struct DriverTestHelper<H: DriverHooks + GetConnectionForHook> {
    pub pipe: quiche::test_utils::Pipe,
    pub driver: H3Driver<H>,
    pub controller: H3Controller<H>,
    /// Our peer, not using a driver, just the h3::Connection directly
    pub peer: h3::Connection,
}

impl<H: DriverHooks + GetConnectionForHook> DriverTestHelper<H> {
    pub fn new() -> anyhow::Result<Self> {
        Self::with_pipe_and_http3_settings(
            Pipe::with_config(&mut default_quiche_config())?,
            Http3Settings::default(),
        )
    }

    pub fn with_pipe(pipe: Pipe) -> anyhow::Result<Self> {
        Self::with_pipe_and_http3_settings(pipe, Http3Settings::default())
    }

    pub fn with_pipe_and_http3_settings(
        mut pipe: Pipe, h3_settings: Http3Settings,
    ) -> anyhow::Result<Self> {
        pipe.handshake().context("Failed to handshake pipe")?;
        let (driver, controller) = H3Driver::<H>::new(h3_settings);
        let peer = h3::Connection::with_transport(
            H::peer_qconn(&mut pipe),
            &h3::Config::new().unwrap(),
        )
        .context("create H3 peer connection")?;
        Ok(Self {
            pipe,
            driver,
            controller,
            peer,
        })
    }

    /// Advance the pipe and run work_loop_iterations.
    /// TODO: We just run a couple of times to "make sure" all pending work has
    /// been processed. Ideally, we'd have some feedback from `work_loop_iter()`
    /// to decide if need to run `advance()` / `work_loop_iter()` instead of
    /// blindly calling it a couple of time...
    pub fn advance_and_run_loop(&mut self) -> anyhow::Result<()> {
        self.pipe.advance()?;
        self.work_loop_iter()?;
        self.pipe.advance()?;
        self.work_loop_iter()?;
        self.pipe.advance()?;
        self.work_loop_iter()?;
        self.pipe.advance()?;
        Ok(())
    }

    /// call `on_conn_established()` on the driver and advance to pipe to
    /// complete the H3 handshake
    pub fn complete_handshake(&mut self) -> anyhow::Result<()> {
        self.driver
            .on_conn_established(
                H::qconn(&mut self.pipe),
                &HandshakeInfo::new(Instant::now(), None),
            )
            .map_err(anyhow::Error::from_boxed)
            .context("on_conn_established")?;
        // advance pipe to complete H3 handshake
        self.pipe.advance().context("advance pipe")?;
        self.driver.settings_received_and_forwarded = true;
        Ok(())
    }

    /// call `forward_settings()` on the driver. This will enqueue an
    /// IncomingSettings event for the controller
    /// deal with IncomingSettings events
    pub fn forward_settings(&mut self) -> anyhow::Result<()> {
        Ok(self.driver.forward_settings()?)
    }

    /// Run one iteration of the work loop *without* advancing the pipe
    pub fn work_loop_iter(&mut self) -> anyhow::Result<()> {
        let qconn = H::qconn(&mut self.pipe);
        self.driver
            .process_reads(qconn)
            .map_err(anyhow::Error::from_boxed)
            .context("process_reads")?;
        self.driver
            .process_writes(qconn)
            .map_err(anyhow::Error::from_boxed)
            .context("process_writes")?;
        tokio::task::unconstrained(self.driver.wait_for_data(qconn))
            .now_or_never()
            .unwrap_or(Ok(()))
            .map_err(anyhow::Error::from_boxed)
            .context("wait_for_data")?;
        self.forward_settings()?;

        Ok(())
    }

    /// process any commands the driver might have received, returns
    /// the nubmer of commands processed
    /// Note that commands will also be processed by
    /// [`Self::work_loop_iter()`], but this function allows one to
    /// only process the events.
    pub fn process_commands(&mut self) -> anyhow::Result<u64> {
        let mut iter = 0;
        while let Ok(cmd) = self.driver.cmd_recv.try_recv() {
            H::conn_command(&mut self.driver, H::qconn(&mut self.pipe), cmd)
                .with_context(|| format!("H::conn_command iter={}", iter))?;
            iter += 1;
        }
        Ok(iter)
    }

    /// Call [`h3::Connection::poll()`] on the peer
    fn poll_peer(&mut self) -> h3::Result<(u64, h3::Event)> {
        self.peer.poll(H::peer_qconn(&mut self.pipe))
    }

    /// Send a body from the peer
    fn peer_send_body(
        &mut self, stream_id: u64, body: &[u8], fin: bool,
    ) -> h3::Result<usize> {
        self.peer
            .send_body(H::peer_qconn(&mut self.pipe), stream_id, body, fin)
    }

    /// Call `h3::Connection::recv_body()` on the peer and read at most
    /// `max_read` bytes into a Vector, returns the Vec.
    fn peer_recv_body_vec(
        &mut self, stream_id: u64, max_read: usize,
    ) -> h3::Result<Vec<u8>> {
        let mut buf = vec![0; max_read];

        let written = self.peer.recv_body(
            H::peer_qconn(&mut self.pipe),
            stream_id,
            &mut buf,
        )?;
        buf.truncate(written);
        Ok(buf)
    }

    // Repeately calls try_recv() on the given receiver and work_loop_iter()
    // until the receiver returns an empty or disconnected.
    // Merges all received parts into a single Vec.
    pub fn driver_try_recv_body(
        &mut self, recv: &mut InboundFrameStream,
    ) -> (Vec<u8>, bool, TryRecvError) {
        let mut buf = Vec::new();
        let mut had_fin = false;
        loop {
            match recv.try_recv() {
                Ok(InboundFrame::Body(pooled, fin)) => {
                    if had_fin {
                        panic!("Received data after fin");
                    }
                    buf.extend_from_slice(&pooled);
                    had_fin = fin;
                },
                Ok(InboundFrame::Datagram(..)) => {
                    panic!("Unexepected InboundFrame::Datagram");
                },
                Err(err) => return (buf, had_fin, err),
            }
            self.work_loop_iter().unwrap();
        }
    }
}

impl DriverTestHelper<ClientHooks> {
    /// Sends a new client request, by enqueuing a `NewClientRequest`
    /// command, processing it, and receiving the `NewOutboundRequest` from
    /// the controllers. It returns `stream_id`.
    ///
    /// This function assumes that there are no commands or events queued
    /// when called.
    pub fn driver_send_request(
        &mut self, headers: Vec<Header>, fin: bool,
    ) -> anyhow::Result<u64> {
        let body_writer_oneshot_tx = if fin {
            None
        } else {
            let (tx, _) = oneshot::channel();
            Some(tx)
        };
        self.driver_enqueue_request(1, headers, body_writer_oneshot_tx);
        anyhow::ensure!(
            self.process_commands()? == 1,
            "More than one command processed"
        );
        match self.driver_recv_client_event() {
            Ok(ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id: 1,
            }) => Ok(stream_id),
            other => Err(anyhow::anyhow!("Unexpected result: {other:?}")),
        }
    }

    /// enqueue a `NewClientRequest` command
    pub fn driver_enqueue_request(
        &mut self, request_id: u64, headers: Vec<Header>,
        body_writer: Option<oneshot::Sender<OutboundFrameSender>>,
    ) {
        self.controller
            .request_sender()
            .send(NewClientRequest {
                request_id,
                headers: headers.clone(),
                body_writer,
            })
            .unwrap();
    }

    /// Try to receive an event from the controller, returns an error if
    /// the receive fails
    pub fn driver_recv_core_event(&mut self) -> anyhow::Result<H3Event> {
        match self.controller.event_receiver_mut().try_recv()? {
            ClientH3Event::Core(h3_event) => Ok(h3_event),
            ev => Err(anyhow::anyhow!("Not a core event: {ev:?}")),
        }
    }

    /// Try to receive a `ClientH3Event` from the controller's event receiver
    pub fn driver_recv_client_event(&mut self) -> anyhow::Result<ClientH3Event> {
        Ok(self.controller.event_receiver_mut().try_recv()?)
    }

    /// Sends a response from server with default headers.
    ///
    /// On success it returns the headers.
    pub fn peer_server_send_response(
        &mut self, stream: u64, fin: bool,
    ) -> h3::Result<Vec<Header>> {
        let resp = vec![
            Header::new(b":status", b"200"),
            Header::new(b"server", b"quiche-test"),
        ];

        self.peer
            .send_response(&mut self.pipe.server, stream, &resp, fin)?;

        Ok(resp)
    }

    pub fn peer_server_poll(&mut self) -> h3::Result<(u64, h3::Event)> {
        self.poll_peer()
    }

    /// Send a body from the server
    pub fn peer_server_send_body(
        &mut self, stream_id: u64, body: &[u8], fin: bool,
    ) -> h3::Result<usize> {
        self.peer_send_body(stream_id, body, fin)
    }

    /// Receive at most `max_read` body bytes and return the read
    /// bytes as a `Vec`
    pub fn peer_server_recv_body_vec(
        &mut self, stream_id: u64, max_read: usize,
    ) -> h3::Result<Vec<u8>> {
        self.peer_recv_body_vec(stream_id, max_read)
    }
}

impl DriverTestHelper<ServerHooks> {
    /// Sends a new client request
    pub fn peer_client_send_request(
        &mut self, headers: Vec<Header>, fin: bool,
    ) -> anyhow::Result<u64> {
        Ok(self
            .peer
            .send_request(&mut self.pipe.client, &headers, fin)?)
    }

    /// Try to receive an event from the controller, returns an error if
    /// the receive fails
    pub fn driver_recv_core_event(&mut self) -> anyhow::Result<H3Event> {
        match self.controller.event_receiver_mut().try_recv()? {
            ServerH3Event::Core(h3_event) => Ok(h3_event),
        }
    }

    pub fn peer_client_poll(&mut self) -> h3::Result<(u64, h3::Event)> {
        self.poll_peer()
    }

    /// Send a body from the server
    pub fn peer_client_send_body(
        &mut self, stream_id: u64, body: &[u8], fin: bool,
    ) -> h3::Result<usize> {
        self.peer_send_body(stream_id, body, fin)
    }

    /// Receive at most `max_read` body bytes and return the read
    /// bytes as a `Vec`
    pub fn peer_client_recv_body_vec(
        &mut self, stream_id: u64, max_read: usize,
    ) -> h3::Result<Vec<u8>> {
        self.peer_recv_body_vec(stream_id, max_read)
    }
}
