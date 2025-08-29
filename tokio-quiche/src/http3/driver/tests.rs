use crate::http3::driver::client::ClientHooks;
use crate::http3::driver::H3Controller;
use crate::http3::driver::H3Driver;
use crate::http3::settings::Http3Settings;

use super::*;
use anyhow::Context as _;
use quiche::h3::Header;
use std::time::Instant;
use tokio::sync::oneshot;

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

pub struct ClientTestHelper {
    pub pipe: quiche::test_utils::Pipe,
    pub driver: H3Driver<ClientHooks>,
    pub controller: H3Controller<ClientHooks>,
    pub server: h3::Connection,
}

impl ClientTestHelper {
    pub fn new(
        mut pipe: quiche::test_utils::Pipe, client_h3_settings: Http3Settings,
    ) -> anyhow::Result<Self> {
        pipe.handshake().context("Failed to handshake pipe")?;
        let (driver, controller) =
            H3Driver::<ClientHooks>::new(client_h3_settings);
        let server = h3::Connection::with_transport(
            &mut pipe.server,
            &h3::Config::new().unwrap(),
        )
        .context("create H3 server connection")?;
        Ok(Self {
            pipe,
            driver,
            controller,
            server,
        })
    }

    /// call `on_conn_established()` on the driver and advance to pipe to
    /// complete the H3 handshake
    pub fn on_conn_established(&mut self) -> anyhow::Result<()> {
        self.driver
            .on_conn_established(
                &mut self.pipe.client,
                &HandshakeInfo::new(Instant::now(), None),
            )
            .map_err(anyhow::Error::from_boxed)
            .context("on_conn_established")?;
        // advance pipe to complete H3 handshake
        self.pipe.advance().context("advance pipe")
    }

    /// call `forward_settings()` on the driver so that we don't have to
    /// deal with IncomingSettings events
    pub fn forward_settings(&mut self) -> anyhow::Result<()> {
        Ok(self.driver.forward_settings()?)
    }

    /// enqueue a `NewClientRequest` command
    pub fn enqueue_request(
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

    /// process any commands the driver might have received, returns
    /// the nubmer of commands processed
    pub fn process_commands(&mut self) -> anyhow::Result<u64> {
        let mut iter = 0;
        while let Ok(cmd) = self.driver.cmd_recv.try_recv() {
            ClientHooks::conn_command(
                &mut self.driver,
                &mut self.pipe.client,
                cmd,
            )
            .with_context(|| {
                format!("ClientHooks::conn_command iter={}", iter)
            })?;
            iter += 1;
        }
        Ok(iter)
    }

    /// Run one iteration of the work loop *without* advancing the pipe
    pub fn work_loop_iter(&mut self) -> anyhow::Result<()> {
        self.driver
            .process_reads(&mut self.pipe.client)
            .map_err(anyhow::Error::from_boxed)
            .context("process_reads")?;
        self.driver
            .process_writes(&mut self.pipe.client)
            .map_err(anyhow::Error::from_boxed)
            .context("process_writes")?;
        tokio::task::unconstrained(
            self.driver.wait_for_data(&mut self.pipe.client),
        )
        .now_or_never()
        .unwrap_or(Ok(()))
        .map_err(anyhow::Error::from_boxed)
        .context("wait_for_data")?;

        Ok(())
    }

    pub fn expect_new_outbound_request_ev(
        &mut self,
    ) -> anyhow::Result<(u64, u64)> {
        match self.controller.event_receiver_mut().try_recv() {
            Err(e) => Err(e.into()),
            Ok(ev) => match ev {
                ClientH3Event::NewOutboundRequest {
                    stream_id,
                    request_id,
                } => Ok((stream_id, request_id)),
                other_ev =>
                    Err(anyhow::anyhow!("unexpected event {:?}", other_ev)),
            },
        }
    }

    pub fn expect_outbound_request_failed_ev(
        &mut self,
    ) -> anyhow::Result<(u64, H3ConnectionError)> {
        match self.controller.event_receiver_mut().try_recv() {
            Err(e) => Err(e.into()),
            Ok(ev) => match ev {
                ClientH3Event::OutboundRequestFailed { request_id, error } =>
                    Ok((request_id, error)),
                other_ev =>
                    Err(anyhow::anyhow!("unexpected event {:?}", other_ev)),
            },
        }
    }

    /// Repeately call `h3::Connection::poll()` on the server and return
    /// list of events
    pub fn drain_server_events(
        &mut self,
    ) -> anyhow::Result<Vec<(u64, h3::Event)>> {
        let mut ret = Vec::new();
        loop {
            match self.server.poll(&mut self.pipe.server) {
                Ok((id, event)) => {
                    ret.push((id, event));
                },
                Err(h3::Error::Done) => return Ok(ret),
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[test]
fn test_retry_requests() {
    let mut config = default_quiche_config();
    // NOTE: 70 bytes is enough for one request, but not two
    config.set_initial_max_data(70);

    let mut helper = ClientTestHelper::new(
        quiche::test_utils::Pipe::with_config(&mut config)
            .expect("Pipe::with_config"),
        Http3Settings::default(),
    )
    .unwrap();

    helper.on_conn_established().unwrap();

    // create and send a request but do NOT advance the pipe
    helper.enqueue_request(42, make_request_headers("GET"), None);
    helper.process_commands().unwrap();

    let (_stream_id, request_id) =
        helper.expect_new_outbound_request_ev().unwrap();
    assert_eq!(request_id, 42);

    // not enough flow control to send a second request.
    helper.enqueue_request(43, make_request_headers("GET"), None);
    helper.process_commands().unwrap();
    assert!(helper.controller.event_receiver_mut().is_empty());
    assert_eq!(helper.driver.hooks.unsend_requests().len(), 1);

    // run a work loop iteration ==> no change
    helper.work_loop_iter().unwrap();
    assert!(helper.controller.event_receiver_mut().is_empty());
    assert_eq!(helper.driver.hooks.unsend_requests().len(), 1);

    // and try to send yet another request
    helper.enqueue_request(44, make_request_headers("GET"), None);
    helper.process_commands().unwrap();
    assert!(helper.controller.event_receiver_mut().is_empty());
    assert_eq!(helper.driver.hooks.unsend_requests().len(), 2);

    helper.work_loop_iter().unwrap();
    assert!(helper.controller.event_receiver_mut().is_empty());
    assert_eq!(helper.driver.hooks.unsend_requests().len(), 2);

    // pending requests are ones the driver has written to the quiche
    // connection
    assert_eq!(helper.driver.hooks.pending_requests_stream_ids(), vec![0]);

    // now lets advance the pipe to finally these requests
    // we need to read the requests on the server (to open up the flow
    // control window) but don't need to respond
    helper.pipe.advance().unwrap();
    while !helper.drain_server_events().unwrap().is_empty() {
        helper.pipe.advance().unwrap();
        helper.work_loop_iter().unwrap();
        helper.pipe.advance().unwrap();
    }

    let (_stream_id, request_id) =
        helper.expect_new_outbound_request_ev().unwrap();
    assert_eq!(request_id, 43);
    let (_stream_id, request_id) =
        helper.expect_new_outbound_request_ev().unwrap();
    assert_eq!(request_id, 44);

    assert!(helper.controller.event_receiver_mut().is_empty());
    assert_eq!(helper.driver.hooks.unsend_requests().len(), 0);

    assert_eq!(helper.driver.hooks.pending_requests_stream_ids(), vec![
        0, 4, 8
    ]);
}

#[test]
fn test_failing_request_stream_limit() {
    let mut config = default_quiche_config();
    // only allow a single bidi stream
    config.set_initial_max_streams_bidi(1);

    let mut helper = ClientTestHelper::new(
        quiche::test_utils::Pipe::with_config(&mut config)
            .expect("Pipe::with_config"),
        Http3Settings::default(),
    )
    .unwrap();

    helper.on_conn_established().unwrap();

    // create and send a request but do NOT advance the pipe
    helper.enqueue_request(42, make_request_headers("GET"), None);
    helper.process_commands().unwrap();

    let (_stream_id, request_id) =
        helper.expect_new_outbound_request_ev().unwrap();
    assert_eq!(request_id, 42);

    // try to send a second request, we will get a StreamLimit error
    // back
    helper.enqueue_request(43, make_request_headers("GET"), None);
    helper.process_commands().unwrap();

    let (request_id, error) = helper.expect_outbound_request_failed_ev().unwrap();
    assert_eq!(request_id, 43);
    assert_eq!(
        error,
        H3ConnectionError::H3(h3::Error::TransportError(
            quiche::Error::StreamLimit
        ))
    );
}

#[test]
fn test_failing_request_fatal() {
    let mut config = default_quiche_config();

    let mut helper = ClientTestHelper::new(
        quiche::test_utils::Pipe::with_config(&mut config)
            .expect("Pipe::with_config"),
        Http3Settings::default(),
    )
    .unwrap();

    // Don't call on_call_established(). Sending a request will
    // fail with a "fatal" error

    // create and send a request but do NOT advance the pipe
    helper.enqueue_request(42, make_request_headers("GET"), None);
    assert!(helper.process_commands().is_err());

    let (request_id, _error) =
        helper.expect_outbound_request_failed_ev().unwrap();
    assert_eq!(request_id, 42);
}
