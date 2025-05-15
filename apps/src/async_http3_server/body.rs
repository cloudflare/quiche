use bytes::Bytes;
use futures_util::SinkExt;
use futures_util::StreamExt;
use http::Request;
use http_body::Body;
use http_body::Frame;
use http_body::SizeHint;
use http_body_util::BodyDataStream;
use log;
use std::fmt::Debug;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::OutboundFrameSender;

const STREAM_BYTES: &'static str = "/stream-bytes/";

/// An extremely simply response body, for example purposes only.
pub struct ExampleBody {
    remaining: usize,
    chunk: Bytes,
}

impl ExampleBody {
    /// Create a new body.
    ///
    /// This takes the request's path and sees if the client has requested a
    /// body back. If so, the body with the requested size is created.
    ///
    /// We statically allocate memory at the beginning to avoid allocation costs
    /// when sending the body back.
    pub fn new(req: &Request<()>) -> Self {
        const DUMMY_CONTENT: u8 = 0x57;
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB
        static CHUNK_DATA: [u8; CHUNK_SIZE] = [DUMMY_CONTENT; CHUNK_SIZE];

        let req_path = req.uri().path();
        let size = if req_path.starts_with(STREAM_BYTES) {
            req_path
                .split("/")
                .into_iter()
                .last()
                .and_then(|last| last.parse::<usize>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        Self {
            remaining: size,
            chunk: Bytes::from_static(&CHUNK_DATA),
        }
    }
}

impl Body for ExampleBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>, _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(match self.remaining {
            0 => None,

            _ => {
                let chunk_len = std::cmp::min(self.remaining, self.chunk.len());

                self.remaining -= chunk_len;

                // Borrowing the slice of data and avoid copy.
                Some(Ok(Frame::data(self.chunk.slice(..chunk_len))))
            },
        })
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining as u64)
    }
}

/// Use the `frame_sender` to send all frames for the `Body` over to
/// tokio-quiche. The sender is paired with the underlying `H3Driver`.
pub(crate) async fn send_body<B>(
    body: B, mut frame_sender: OutboundFrameSender,
) -> Option<()>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Send + Debug,
{
    let mut body_stream = BodyDataStream::new(body);

    while let Some(maybe_chunk) = body_stream.next().await {
        match maybe_chunk {
            Ok(chunk) => {
                for chunk in chunk.chunks(BufFactory::MAX_BUF_SIZE) {
                    // Is it too many levels of chunking?
                    let chunk = OutboundFrame::body(
                        BufFactory::buf_from_slice(chunk),
                        false,
                    );
                    frame_sender.send(chunk).await.ok()?;
                }
            },
            Err(error) => {
                log::error!("Received error when sending or receiving HTTP body: {error:?}");

                let fin_chunk = OutboundFrame::PeerStreamError;
                frame_sender.send(fin_chunk).await.ok()?;

                return None;
            },
        }
    }

    frame_sender
        .send(OutboundFrame::Body(BufFactory::get_empty_buf(), true))
        .await
        .ok()?;

    Some(())
}
