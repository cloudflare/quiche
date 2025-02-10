use std::io;
use std::task::{Context, Poll};

use crate::{ConsumeBuffer, Pooled};

pub type PooledBuf = Pooled<ConsumeBuffer>;

/// A trait to optimize read and write operations on pooled buffers.
pub trait RawPoolBufIo: Send {
    fn poll_send_reserve(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;

    fn send_buf(&mut self, buf: PooledBuf, fin: bool) -> io::Result<()>;

    fn poll_recv_buf(&mut self, cx: &mut Context) -> Poll<io::Result<PooledBuf>>;
}

pub trait RawPoolBufDatagramIo: Send {
    fn poll_send_datagrams(
        &mut self,
        cx: &mut Context,
        datagrams: &mut [PooledBuf],
    ) -> Poll<io::Result<usize>>;

    fn poll_recv_dgram(&mut self, cx: &mut Context) -> Poll<io::Result<PooledBuf>>;

    fn poll_recv_datagrams(
        &mut self,
        cx: &mut Context,
        buffer: &mut Vec<PooledBuf>,
        limit: usize,
    ) -> Poll<io::Result<usize>> {
        for i in 0..limit {
            match self.poll_recv_dgram(cx) {
                Poll::Ready(Ok(buf)) => buffer.push(buf),
                Poll::Ready(Err(err)) => {
                    if i > 0 {
                        return Poll::Ready(Ok(i));
                    } else {
                        return Poll::Ready(Err(err));
                    }
                }
                Poll::Pending => {
                    if i > 0 {
                        return Poll::Ready(Ok(i));
                    } else {
                        return Poll::Pending;
                    }
                }
            }
        }

        Poll::Ready(Ok(limit))
    }
}
