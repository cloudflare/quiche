use crate::http3::driver::client::ClientHooks;
use crate::http3::driver::server::ServerHooks;
use assert_matches::assert_matches;

use super::test_utils::*;
use super::*;

/// Tests that use an H3Driver for the client side. We mostly focus on testing
/// the driver's handling of stream state, and data, rather than H3 semantics.
/// Note that most of these tests could have just as easily been written for
/// the server side.
mod client_side_driver {
    use super::*;

    #[test]
    fn client_fin_before_server_body() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        let to_server = resp.send.get_ref().unwrap().clone();
        let mut from_server = resp.recv;
        // client sends body
        to_server
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[1; 5]),
                false,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // server receives client body
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_server_recv_body_vec(0, 1024), Ok(vec![1; 5]));

        // client sends fin, server sends body and fin
        to_server
            .try_send(OutboundFrame::Body(BufFactory::get_empty_buf(), true))
            .unwrap();
        helper.peer_server_send_body(0, &[2; 10], true).unwrap();

        // Server reads fin
        helper.advance_and_run_loop().unwrap();
        // TODO: the server sees an h3::Event::Data, but it's for an empty buffer.
        // Ideally, it wouldn't do that.
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        // No data to be read
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
        helper.advance_and_run_loop().unwrap();

        // client receives the server body
        assert_matches!(from_server.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.into_inner().into_vec(), vec![2; 10]);
            // TODO: it would be nice if we could receive the fin here, but that's not
            // how quiche::h3 works. Instead we need another receive call on the channel
            assert!(!fin);
        });
        helper.work_loop_iter().unwrap();

        // FIXME: This is an edge case. We should not see a `Disconnected` error
        // here. The `from_server` / `InboudFrame` channel is set to 1 in tests.
        // What happens, is the driver reads the previous body frame, then it
        // sees an `Event::Finished` and calls `process_h3_fin`, which sets
        // `ctx.fin_recv`. Then it processes the pending write that sends the fin
        // from client to server. The driver now sees both ctx.fin_read &&
        // ctx.fin_sent and drops the context and thus the channel. Application
        // code (H3Body) is not affected by -- it treats a disconnected channel
        // like receiving a fin. It's a different question if it should treat it
        // as such

        // assert_matches!(from_server.try_recv(), Ok(InboundFrame::Body(buf,
        // fin)) => {
        //    assert_eq!(buf.into_inner().into_vec().len(), 0);
        //    assert!(fin);
        //});
        assert_matches!(from_server.try_recv(), Err(TryRecvError::Disconnected));
        assert_eq!(helper.driver.stream_map.len(), 0);
    }
    /// Test that dropping the OutboundFrame channel causes the driver to
    /// send a RESET_STREAM frame to the peer.
    #[test]
    fn client_send_reset_stream_when_outbound_frame_channel_drops() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // the stream is waiting on writes
        assert_eq!(helper.driver.waiting_streams.len(), 1);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        // ... and drop the outbound frame
        drop(resp.send);

        helper.advance_and_run_loop().unwrap();

        // server receives the reset
        assert_eq!(
            helper.peer_server_poll(),
            Ok((0, h3::Event::Reset(REQUEST_CANCELED_ERR)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.peer_server_send_body(0, &[2; 10], true).unwrap();
        helper.advance_and_run_loop().unwrap();

        // client receives the server body
        assert_matches!(from_server.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.into_inner().into_vec(), vec![2; 10]);
            // TODO: it would be nice if we could receive the fin here, but that's not
            // how quiche::h3 works. Instead we need another receive call on the channel
            assert!(!fin);
        });
        helper.work_loop_iter().unwrap();
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 10);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    /// Test that dropping the OutboundFrame channel causes the driver to
    /// send a RESET_STREAM frame to the peer.
    #[test]
    fn client_send_reset_stream_when_outbound_frame_channel_drops_2() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers, body, and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();
        helper.peer_server_send_body(0, &[2; 10], true).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let mut resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, vec![2; 10]);
        assert!(fin);
        helper.advance_and_run_loop().unwrap();

        // clsoe the channel.
        resp.send.close();

        helper.advance_and_run_loop().unwrap();

        // server receives the reset
        assert_eq!(
            helper.peer_server_poll(),
            Ok((0, h3::Event::Reset(REQUEST_CANCELED_ERR)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.advance_and_run_loop().unwrap();

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 10);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    /// Send data until the stream is no longer writable, then drop the
    /// OutboundFrame channel to trigger a RESET_STREAM
    #[test]
    fn client_send_reset_stream_with_full_stream() {
        let mut config = default_quiche_config();
        config.set_initial_max_stream_data_bidi_local(30);
        config.set_initial_max_stream_data_bidi_remote(30);
        let mut helper = DriverTestHelper::<ClientHooks>::with_pipe(
            quiche::test_utils::Pipe::with_config(&mut config).unwrap(),
        )
        .unwrap();
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers, and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, true).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(resp.read_fin);
        let audit_stats = resp.h3_audit_stats.clone();
        // send a body the to server, but not enough flow control for the full
        // body
        resp.send
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[23; 50]),
                false,
            ))
            .unwrap();
        assert_eq!(helper.driver.waiting_streams.len(), 1);
        // run `work_loop_iter()` to write the body into quiche
        helper.work_loop_iter().unwrap();
        // make sure we couldn't write the full body
        assert!(audit_stats.downstream_bytes_sent() < 50);
        let written = audit_stats.downstream_bytes_sent();
        // advance the pipe, the stream is writable again, but
        // don't advance the work_loop yet.
        helper.pipe.advance().unwrap();
        while helper.peer_server_poll().is_ok() {}
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024).unwrap().len(),
            written as usize
        );
        helper.pipe.advance().unwrap();
        assert_eq!(helper.driver.waiting_streams.len(), 0);
        assert!(helper.driver.stream_map.get(&0).unwrap().recv.is_some());
        assert!(helper
            .driver
            .stream_map
            .get(&0)
            .unwrap()
            .queued_frame
            .is_some());

        // clsoe the channel.
        drop(resp.send);

        helper.work_loop_iter().unwrap();
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        helper.advance_and_run_loop().unwrap();

        // server receives the reset
        assert_eq!(
            helper.peer_server_poll(),
            Ok((0, h3::Event::Reset(REQUEST_CANCELED_ERR)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.advance_and_run_loop().unwrap();

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
    }

    /// Test that dropping the OutboundFrame channel after we've send a fin
    /// is a no-op.
    #[test]
    fn client_drop_outbound_frame_channel_after_fin_no_reset() {
        let mut helper = DriverTestHelper::<ClientHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // The client uses H3Driver
        // client sends a request
        let stream_id = helper
            .driver_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers, body, and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_server_poll().unwrap(),
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false).unwrap();

        helper.advance_and_run_loop().unwrap();

        // Client receives response headers
        let mut resp = assert_matches!(
            helper.driver_recv_core_event().unwrap(),
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        helper.advance_and_run_loop().unwrap();
        resp.send
            .get_ref()
            .unwrap()
            .try_send(OutboundFrame::Body(BufFactory::get_empty_buf(), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // clsoe the channel.
        resp.send.close();

        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_server_send_body(0, &[42], true), Ok(1));
        helper.advance_and_run_loop().unwrap();

        // server receives the fin
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.advance_and_run_loop().unwrap();

        // client receives the body and fin
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_server);
        assert_eq!(body, &[42]);
        assert!(fin);

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 1);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }
}

/// Tests that use an H3Driver for the server side. We mostly focus on testing
/// the driver's handling of stream state, and data, rather than H3 semantics.
/// Note that most of these tests could have just as easily been written for
/// the client side.
mod server_side_driver {
    use super::*;

    #[test]
    fn client_fin_before_server_body() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(fin);

        // server sends body and fin
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[42]),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    // This test verifies https://github.com/cloudflare/quiche/pull/2162
    #[test]
    fn verify_pr_2162() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request but NO FIN.
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.work_loop_iter().unwrap();
        // server sends body and fin. This caused an infinite loop before #2162
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[42]),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends body and fin
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, &[1; 5]);
        assert!(fin);

        // Stream is done
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    /// Test the case where the client sends a STOP_SENDING quiche frame.
    #[test]
    fn client_sends_stop_sending() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client sends a STOP_SENDING
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Read, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // the client didn't send any additional data, a try_recv on the server
        // returns empty
        assert_matches!(from_client.try_recv(), Err(TryRecvError::Empty));
        // The way quiche is implemented, we need to attempt a write to the stream
        // to learn that it's closed. So we add an OutboundFrame to the
        // channel and let the driver write it. The driver gets a
        // StreamStopped back and closes the channel.
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[23; 10]),
                false,
            ))
            .unwrap();
        helper.work_loop_iter().unwrap();
        assert!(to_client.is_closed());
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), 4242);
        helper.work_loop_iter().unwrap();

        // STOP_SENDING only closes one half of the stream. The client
        // can still send data and it MUST send a `fin` to close the
        // other half.
        helper.peer_client_send_body(0, &[1, 2, 3], true).unwrap();
        helper.advance_and_run_loop().unwrap();
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, &[1, 2, 3]);
        assert!(fin);

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), 4242);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        // technically quiche will automatically respond to a STOP_SENDING
        // frame with a STREAM_RESET echoing the error code, but the user
        // didn't *actively* send a STREAM_RESET.
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 3);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame.
    /// The peer sends its reset before we send a fin
    #[test]
    fn client_sends_reset_stream_before_server_fin() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client sends a RESET_STREAM frame
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // We can still write to the peer and in fact, we must eventually send a
        // fin.
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[5; 4]),
                false,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[6; 4]),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![5, 5, 5, 5, 6, 6, 6, 6])
        );

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 0);
        assert_eq!(audit_stats.downstream_bytes_sent(), 8);
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame.
    /// We send a fin before the client sends reset
    #[test]
    fn client_sends_reset_stream_after_server_fin() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        // Send response, body, and fin to client
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.work_loop_iter().unwrap();
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(b"foobar 42"),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a RESET_STREAM frame
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_matches!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        helper.peer_client_recv_body_vec(0, 1024).unwrap();
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 0);
        assert_eq!(
            audit_stats.downstream_bytes_sent(),
            b"foobar 42".len() as u64
        );
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame while
    /// we're in the middle of reading data. We want to excercise the
    /// code-path where `upstream_ready` is called before `process_reads`.
    /// If `process_reads()` is called first, it will get the Reset event.
    /// If `upstream_ready()` is called first, it will attempt to read from
    /// the h3::Connection and will get a
    /// `TransportError(StreamReset(code))`
    #[test]
    fn client_sends_reset_stream_while_reading_wait_for_data() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers and some body bytes
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.work_loop_iter().unwrap();
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[1, 2, 3, 4]),
                false,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends data
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_matches!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 10], false), Ok(10));

        // Advance the pipe and let the driver read a part of the body and
        // put it into the `from_client` channel
        helper.pipe.advance().unwrap();
        // Limit the amount of data we read from the stream.
        helper.driver.pooled_buf = BufFactory::buf_from_slice(&[0; 5]);
        helper.work_loop_iter().unwrap();
        assert_matches!(from_client.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.into_inner().into_vec(), &[1; 5]);
            assert!(!fin);
        });
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // client sends a reset.
        // TODO: This is a bit finnicky to test properly. We don't want to
        // run a full `work_loop_iter()` because that would call `process_reads()`
        // first.
        helper.pipe.advance().unwrap();
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.pipe.advance().unwrap();
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never()
        .unwrap_or(Ok(()))
        .unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // We can still write to the peer and in fact, we must eventually send a
        // fin.
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[6; 4]),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![1, 2, 3, 4, 6, 6, 6, 6])
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 8);
    }

    /// Test the case where the client sends a RESET_STREAM quiche frame while
    /// we're in the middle of reading data. We want to excercise the
    /// code-path where where we call `process_reads` before
    /// `upstream_ready()`.
    #[test]
    fn server_sends_reset_stream_while_reading_process_reads() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client (peer) sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends data
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 10], false), Ok(10));

        // Advance the pipe and let the driver read a part of the body and
        // put it into the `from_client` channel
        helper.pipe.advance().unwrap();
        // Limit the amount of data we read from the stream.
        helper.driver.pooled_buf = BufFactory::buf_from_slice(&[0; 5]);
        helper.work_loop_iter().unwrap();
        assert_matches!(from_client.try_recv(), Ok(InboundFrame::Body(buf, fin)) => {
            assert_eq!(buf.into_inner().into_vec(), &[1; 5]);
            assert!(!fin);
        });
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );

        // client sends a reset.
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop().unwrap();

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // send fin to client
        to_client
            .try_send(OutboundFrame::Body(BufFactory::get_empty_buf(), true))
            .unwrap();
        helper.advance_and_run_loop().unwrap();

        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), 4242);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
    }

    #[test]
    fn server_driver_send_stop_sending_after_channel_drop() {
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        let audit_stats = req.h3_audit_stats.clone();
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body without fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(!fin);

        // peer (client) sends more data
        assert_eq!(helper.peer_client_send_body(0, &[1; 6], false), Ok(6));
        // advance the pipe only
        helper.pipe.advance().unwrap();
        // we drop the channel.
        drop(from_client);
        helper.advance_and_run_loop().unwrap();

        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // Make sure the peer has received our STOP_SENDING frame
        assert_eq!(
            helper.peer_client_send_body(0, &[1; 7], false),
            Err(h3::Error::TransportError(quiche::Error::StreamStopped(
                REQUEST_CANCELED_ERR
            )))
        );
        helper.advance_and_run_loop().unwrap();

        // we still need to send a fin
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[42]),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    // Verify we don't send a STOP_SENDING frame if we've already processed a
    // fin
    #[test]
    fn server_driver_drop_channel_after_fin() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        let audit_stats = req.h3_audit_stats.clone();
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body WITH fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(fin);

        helper.advance_and_run_loop().unwrap();
        // we drop the channel.
        drop(from_client);
        helper.advance_and_run_loop().unwrap();

        // we still need to send a fin
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[42]),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    // Test the edge case where the driver has read a fin from the stream but
    // hasn't been able to deliver it before the channel is dropped.
    #[test]
    fn server_driver_drop_channel_after_fin_2() {
        const REQUEST_CANCELED_ERR: u64 =
            h3::WireErrorCode::RequestCancelled as u64;
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        let audit_stats = req.h3_audit_stats.clone();
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body without fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // peer (client) sends more data and fin
        assert_eq!(helper.peer_client_send_body(0, &[1; 6], true), Ok(6));
        helper.advance_and_run_loop().unwrap();
        // we drop the channel.
        drop(req.recv);
        helper.advance_and_run_loop().unwrap();

        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // we still need to send a fin
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[42]),
                true,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(audit_stats.recvd_stop_sending_error_code(), -1);
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), -1);
        assert_eq!(audit_stats.sent_reset_stream_error_code(), -1);
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            REQUEST_CANCELED_ERR as i64
        );
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
    }

    #[test]
    fn server_send_trailers() {
        let mut helper = DriverTestHelper::<ServerHooks>::new().unwrap();
        helper.complete_handshake().unwrap();
        helper.advance_and_run_loop().unwrap();

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(make_request_headers("GET"), false)
            .unwrap();

        // servers reads request and sends response headers
        helper.advance_and_run_loop().unwrap();
        let req = assert_matches!(
            helper.driver_recv_server_event().unwrap(),
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req.send.get_ref().unwrap().clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .unwrap();

        // client reads response and sends body and fin
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop().unwrap();

        // server receives body
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client);
        assert_eq!(body, vec![1; 5]);
        assert!(fin);

        // server sends body
        to_client
            .try_send(OutboundFrame::Body(
                BufFactory::buf_from_slice(&[42]),
                false,
            ))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );

        // server sends trailers
        to_client
            .try_send(OutboundFrame::Trailers(make_response_trailers(), None))
            .unwrap();
        helper.advance_and_run_loop().unwrap();
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );

        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
    }
}
