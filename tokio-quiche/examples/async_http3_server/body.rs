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

use futures_util::SinkExt;
use futures_util::StreamExt;
use http::Request;
use http_body::Body;
use http_body::Frame;
use http_body::SizeHint;
use http_body_util::BodyDataStream;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio_quiche::buf_factory::BufFactory as BufFactoryImpl;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::OutboundFrameSender;
use tokio_util::bytes::Bytes;

const STREAM_BYTES: &str = "/stream-bytes/";

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

    /// Use the `frame_sender` to send DATA frames to tokio-quiche.
    ///
    /// The sender is paired with the underlying tokio-quiche `H3Driver`.
    pub(crate) async fn send(
        self, mut frame_sender: OutboundFrameSender,
    ) -> Option<()> {
        let mut body_stream = BodyDataStream::new(self);

        while let Some(chunk) = body_stream.next().await {
            match chunk {
                Ok(chunk) => {
                    for chunk in chunk.chunks(BufFactoryImpl::MAX_BUF_SIZE) {
                        let chunk = OutboundFrame::body(
                            BufFactoryImpl::buf_from_slice(chunk),
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
            .send(OutboundFrame::Body(BufFactoryImpl::get_empty_buf(), true))
            .await
            .ok()?;

        Some(())
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
