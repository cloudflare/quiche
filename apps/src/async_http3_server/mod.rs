mod args;
mod body;

pub use args::Args;

use self::body::send_body;
use self::body::ExampleBody;
use futures_util::Future;
use futures_util::SinkExt;
use http::request;
use http::uri::PathAndQuery;
use http::uri::{
    self,
};
use http::HeaderName;
use http::HeaderValue;
use http::Request;
use http::Response;
use http::Uri;
use quiche::h3::Header;
use quiche::h3::NameValue;
use std::sync::Arc;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::OutboundFrameSender;
use tokio_quiche::http3::driver::ServerEventStream;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::BoxError;
use tokio_quiche::QuicResult;

/// A simple [service function].
///
/// If the request's path follows the form `/stream-bytes/<num_bytes>`, the
/// response will come with a body that is `num_bytes` long.
///
/// For example, `https://test.com/stream-bytes/57` will return a 200 response with a body that is
/// 57 bytes long.
///
/// [service function]: https://docs.rs/hyper/latest/hyper/service/index.html
pub async fn service_fn(req: Request<()>) -> Response<ExampleBody> {
    let body = ExampleBody::new(&req);
    Response::builder().status(200).body(body).unwrap()
}

/// A basic asynchronous HTTP/3 server served by tokio-quiche. Note that this is
/// simply an example, and **should not be run in production**. This merely
/// shows how one could use tokio-quiche to write an HTTP/3 server.
pub struct Server<S, R>
where
    S: Fn(Request<()>) -> R + Send + Sync + 'static,
{
    service_fn: Arc<S>,
}

impl<S, R> Server<S, R>
where
    S: Fn(Request<()>) -> R + Send + Sync + 'static,
    R: Future<Output = Response<ExampleBody>> + Send + 'static,
{
    /// Create the server by registering a [service function].
    ///
    /// [service function]: https://docs.rs/hyper/latest/hyper/service/index.html
    pub fn new(service_fn: S) -> Self {
        Server {
            service_fn: Arc::new(service_fn),
        }
    }

    /// Serve the connection.
    ///
    /// The [`Server`] will listen for [`ServerH3Event`]s, process them, and
    /// send response data back to tokio-quiche for quiche-side processing
    /// and flushing.
    ///
    /// tokio-quiche's `H3Driver` emits these events in response to data that
    /// comes off the underlying socket.
    pub async fn serve_connection(
        &mut self, h3_event_receiver: &mut ServerEventStream,
    ) -> QuicResult<()> {
        loop {
            match h3_event_receiver.recv().await {
                Some(event) => self.handle_forwarded_event(event).await?,
                None => return Ok(()), /* The sender was dropped, implying
                                        * connection was terminated */
            }
        }
    }

    /// Handle a [`ServerH3Event`]. For simplicity's sake, we only handle a
    /// couple of events here.
    // TODO(evanrittenhouse): support POST requests
    async fn handle_forwarded_event(
        &mut self, event: ServerH3Event,
    ) -> QuicResult<()> {
        let ServerH3Event::Core(event) = event;

        match event {
            // Received an explicit connection level error. Not much to do here.
            H3Event::ConnectionError(err) => QuicResult::Err(Box::new(err)),

            // The connection has shutdown.
            H3Event::ConnectionShutdown(err) => {
                let error = err.map_or_else(
                    || Box::new(quiche::h3::Error::Done) as BoxError,
                    |e| Box::new(e),
                );

                QuicResult::Err(error)
            },

            // Received headers for a new stream from the H3Driver.
            H3Event::IncomingHeaders(headers) => {
                self.handle_incoming_headers(headers).await;

                Ok(())
            },

            _ => {
                log::info!("received unknown event: {event:?}");
                Ok(())
            },
        }
    }

    /// Respond to the request corresponding to the [`IncomingH3Headers`].
    ///
    /// This function transforms the incoming headers into a [`Request`],
    /// creating the proper response body if requested. It then spawns a
    /// Tokio task which calls the `service_fn` on the [`Request`].
    async fn handle_incoming_headers(&mut self, headers: IncomingH3Headers) {
        let IncomingH3Headers {
            headers: list,
            send: mut frame_sender,
            ..
        } = headers;

        let Ok((uri_builder, req_builder)) = convert_headers(list) else {
            Self::end_stream(&mut frame_sender).await;
            return;
        };

        let uri = uri_builder.build().expect("can't build uri");
        let req = req_builder.uri(uri).body(()).expect("can't build request");

        let service_fn = Arc::clone(&self.service_fn);

        tokio::spawn(async move {
            Self::handle_request(service_fn, req, frame_sender).await;
        });
    }

    /// Get a [`Response`] for a [`Request`] by calling the `service_fn`.
    ///
    /// The `frame_sender` parameter connects back to tokio-quiche `H3Driver`,
    /// which communicates the data back to quiche.
    async fn handle_request(
        service_fn: Arc<S>, req: Request<()>,
        mut frame_sender: OutboundFrameSender,
    ) {
        let res = service_fn(req).await;

        // Convert the result of the `service_fn` into headers and a body which
        // can be transmitted to tokio-quiche.
        let (h3_headers, body) = convert_response(res);
        let _ = frame_sender
            .send(OutboundFrame::Headers(h3_headers, None))
            .await;

        send_body(body, frame_sender).await;
    }

    /// End the stream by sending STOP_SENDING and RESET_STREAM frames to the
    /// client.
    async fn end_stream(frame_sender: &mut OutboundFrameSender) {
        let _ = frame_sender.send(OutboundFrame::PeerStreamError).await;
    }
}

/// Convert a list of [Header]s into a request object which can be processed by
/// the [`Server`].
///
/// This isn't complete or robust by any means.
fn convert_headers(
    headers: Vec<Header>,
) -> QuicResult<(uri::Builder, request::Builder)> {
    let mut req_builder = Request::builder();
    let mut uri_builder = Uri::builder();

    for header in headers {
        let name = header.name();
        let value = header.value();

        let Some(first) = name
            .iter()
            .next()
            .and_then(|f| std::char::from_u32(*f as u32))
        else {
            log::warn!("received header with no or invalid first character");
            continue;
        };

        if first == ':' {
            match name {
                b":method" => {
                    req_builder = req_builder.method(value);
                },
                b":scheme" => {
                    uri_builder = uri_builder.scheme(value);
                },
                b":authority" => {
                    let host = HeaderValue::from_bytes(value)?;
                    uri_builder = uri_builder.authority(host.as_bytes());
                    req_builder.headers_mut().map(|h| h.insert("host", host));
                },
                b":path" => {
                    let path = PathAndQuery::try_from(value)?;
                    uri_builder = uri_builder.path_and_query(path);
                },
                _ => {
                    log::warn!("received unknown pseudo-header: {name:?}");
                },
            }
        } else {
            req_builder.headers_mut().map(|h| {
                h.insert(
                    HeaderName::from_bytes(name).expect("invalid header name"),
                    HeaderValue::from_bytes(value).expect("invalid header value"),
                )
            });
        }
    }

    Ok((uri_builder, req_builder))
}

/// Convert a [`Response`] into headers and a body, readable by tokio-quiche.
fn convert_response<B>(res: Response<B>) -> (Vec<Header>, B) {
    let mut h3_headers =
        vec![Header::new(b":status", res.status().as_str().as_bytes())];

    for (name, value) in res.headers().iter() {
        h3_headers.push(Header::new(name.as_ref(), value.as_bytes()));
    }

    (h3_headers, res.into_body())
}
