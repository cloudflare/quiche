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
use std::task::Context;
use std::task::Poll;

use crate::ConsumeBuffer;
use crate::Pooled;

pub type PooledBuf = Pooled<ConsumeBuffer>;

/// A trait to optimize read and write operations on pooled buffers.
pub trait RawPoolBufIo: Send {
    fn poll_send_reserve(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;

    fn send_buf(&mut self, buf: PooledBuf, fin: bool) -> io::Result<()>;

    fn poll_recv_buf(&mut self, cx: &mut Context) -> Poll<io::Result<PooledBuf>>;
}

pub trait RawPoolBufDatagramIo: Send {
    fn poll_send_datagrams(
        &mut self, cx: &mut Context, datagrams: &mut [PooledBuf],
    ) -> Poll<io::Result<usize>>;

    fn poll_recv_dgram(
        &mut self, cx: &mut Context,
    ) -> Poll<io::Result<PooledBuf>>;

    fn poll_recv_datagrams(
        &mut self, cx: &mut Context, buffer: &mut Vec<PooledBuf>, limit: usize,
    ) -> Poll<io::Result<usize>> {
        for i in 0..limit {
            match self.poll_recv_dgram(cx) {
                Poll::Ready(Ok(buf)) => buffer.push(buf),
                Poll::Ready(Err(err)) =>
                    if i > 0 {
                        return Poll::Ready(Ok(i));
                    } else {
                        return Poll::Ready(Err(err));
                    },
                Poll::Pending =>
                    if i > 0 {
                        return Poll::Ready(Ok(i));
                    } else {
                        return Poll::Pending;
                    },
            }
        }

        Poll::Ready(Ok(limit))
    }
}
