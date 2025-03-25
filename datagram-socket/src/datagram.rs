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

use buffer_pool::RawPoolBufDatagramIo;
use futures_util::future::poll_fn;
use futures_util::ready;
use futures_util::FutureExt;
use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::task::coop::unconstrained;

#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::fd::BorrowedFd;
#[cfg(unix)]
use std::os::fd::FromRawFd;
#[cfg(unix)]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use tokio::net::UnixDatagram;

use crate::socket_stats::AsSocketStats;

// This is the largest datagram we expect to support.
// UDP and Unix sockets can support larger datagrams than this, but we only
// expect to support packets coming to/from the Internet.
pub const MAX_DATAGRAM_SIZE: usize = 1500;

pub trait DatagramSocketWithStats: DatagramSocket {}

impl<T> DatagramSocketWithStats for T where T: DatagramSocket + AsSocketStats {}

/// Describes an implementation of a connected datagram socket.
///
/// Rather than using Socket for datagram-oriented sockets, the DatagramSocket
/// trait purposely does not implement AsyncRead/AsyncWrite, which are traits
/// with stream semantics. For example, the `AsyncReadExt::read_exact` method
/// which issues as many reads as possible to fill the buffer provided.
///
/// For a similar reason, [`std::net::UdpSocket`] does not implement
/// [`io::Read`] nor does [`tokio::net::UdpSocket`] implement
/// [`tokio::io::AsyncRead`].
pub trait DatagramSocket:
    DatagramSocketSend + DatagramSocketRecv + 'static
{
    #[cfg(unix)]
    fn as_raw_io(&self) -> Option<BorrowedFd<'_>>;

    #[cfg(unix)]
    fn into_fd(self) -> Option<OwnedFd>;

    fn as_buf_io(&mut self) -> Option<&mut dyn RawPoolBufDatagramIo> {
        None
    }
}

/// Describes the send half of a connected datagram socket.
pub trait DatagramSocketSend: Sync {
    /// Attempts to send data on the socket to the remote address to which it
    /// was previously connected.
    ///
    /// Note that on multiple calls to a `poll_*` method in the send direction,
    /// only the `Waker` from the `Context` passed to the most recent call will
    /// be scheduled to receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not available to write
    /// * `Poll::Ready(Ok(n))` `n` is the number of bytes sent
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    fn poll_send(&self, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>>;

    /// Attempts to send data on the socket to a given address.
    ///
    /// If this socket only supports a single address, it should forward to
    /// `send`. It should *not* panic or discard the data.
    /// It's recommended that this return an error if `addr` doesn't match the
    /// only supported address.
    ///
    /// Note that on multiple calls to a `poll_*` method in the send direction,
    /// only the `Waker` from the `Context` passed to the most recent call
    /// will be scheduled to receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not ready to write
    /// * `Poll::Ready(Ok(n))` `n` is the number of bytes sent.
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    fn poll_send_to(
        &self, cx: &mut Context, buf: &[u8], addr: SocketAddr,
    ) -> Poll<io::Result<usize>>;

    /// Attempts to send multiple packets of data on the socket to the remote
    /// address to which it was previously connected.
    ///
    /// Note that on multiple calls to a `poll_*` method in the send direction,
    /// only the `Waker` from the `Context` passed to the most recent call
    /// will be scheduled to receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not ready to write
    /// * `Poll::Ready(Ok(n))` `n` is the number of packets sent. If any packet
    ///   was sent only partially, that information is lost.
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    fn poll_send_many(
        &self, cx: &mut Context, bufs: &[ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut sent = 0;

        for buf in bufs {
            match self.poll_send(cx, buf.filled()) {
                Poll::Ready(Ok(_)) => sent += 1,
                Poll::Ready(err) => {
                    if sent == 0 {
                        return Poll::Ready(err);
                    }
                    break;
                },
                Poll::Pending => {
                    if sent == 0 {
                        return Poll::Pending;
                    }
                    break;
                },
            }
        }

        Poll::Ready(Ok(sent))
    }

    /// If the underlying socket is a `UdpSocket`, return the reference to it.
    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        None
    }

    /// Returns the socket address of the remote peer this socket was connected
    /// to.
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// Writes datagrams to a socket.
///
/// Implemented as an extension trait, adding utility methods to all
/// [`DatagramSocketSend`] types. Callers will tend to import this trait instead
/// of [`DatagramSocketSend`].
///
/// [`DatagramSocketSend`]: DatagramSocketSend
pub trait DatagramSocketSendExt: DatagramSocketSend {
    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>> {
        poll_fn(move |cx| self.poll_send(cx, buf))
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    fn send_to(
        &self, buf: &[u8], addr: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> {
        poll_fn(move |cx| self.poll_send_to(cx, buf, addr))
    }

    /// Sends multiple data packets on the socket to the to the remote address
    /// that the socket is connected to. On success, returns the number of
    /// packets sent.
    fn send_many(
        &self, bufs: &[ReadBuf<'_>],
    ) -> impl Future<Output = io::Result<usize>> {
        poll_fn(move |cx| self.poll_send_many(cx, bufs))
    }

    fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        match unconstrained(poll_fn(|cx| self.poll_send(cx, buf))).now_or_never()
        {
            Some(result) => result,
            None => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn try_send_many(&self, bufs: &[ReadBuf<'_>]) -> io::Result<usize> {
        match unconstrained(poll_fn(|cx| self.poll_send_many(cx, bufs)))
            .now_or_never()
        {
            Some(result) => result,
            None => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Describes the receive half of a connected datagram socket.
pub trait DatagramSocketRecv: Send {
    /// Attempts to receive a single datagram message on the socket from the
    /// remote address to which it is `connect`ed.
    ///
    /// Note that on multiple calls to a `poll_*` method in the `recv`
    /// direction, only the `Waker` from the `Context` passed to the most
    /// recent call will be scheduled to receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not ready to read
    /// * `Poll::Ready(Ok(()))` reads data `ReadBuf` if the socket is ready
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    fn poll_recv(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;

    /// Attempts to receive a single datagram on the socket.
    ///
    /// Note that on multiple calls to a `poll_*` method in the `recv`
    /// direction, only the `Waker` from the `Context` passed to the most
    /// recent call will be scheduled to receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not ready to read
    /// * `Poll::Ready(Ok(addr))` reads data from `addr` into `ReadBuf` if the
    ///   socket is ready
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    fn poll_recv_from(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.poll_recv(cx, buf).map_ok(|_| {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        })
    }

    /// Attempts to receive multiple datagrams on the socket from the remote
    /// address to which it is `connect`ed.
    ///
    /// Note that on multiple calls to a `poll_*` method in the `recv`
    /// direction, only the `Waker` from the `Context` passed to the most
    /// recent call will be scheduled to receive a wakeup.
    ///
    /// # Return value
    ///
    /// The function returns:
    ///
    /// * `Poll::Pending` if the socket is not ready to read
    /// * `Poll::Ready(Ok(n))` reads data `ReadBuf` if the socket is ready `n`
    ///   is the number of datagrams read.
    /// * `Poll::Ready(Err(e))` if an error is encountered.
    ///
    /// # Errors
    ///
    /// This function may encounter any standard I/O error except `WouldBlock`.
    fn poll_recv_many(
        &mut self, cx: &mut Context<'_>, bufs: &mut [ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut read = 0;

        for buf in bufs {
            match self.poll_recv(cx, buf) {
                Poll::Ready(Ok(())) => read += 1,

                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),

                // Only return `Poll::Ready` if at least one datagram was
                // successfully read, otherwise block.
                Poll::Pending if read == 0 => return Poll::Pending,
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(read))
    }

    /// If the underlying socket is a `UdpSocket`, return the reference to it.
    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        None
    }
}

/// Reads datagrams from a socket.
///
/// Implemented as an extension trait, adding utility methods to all
/// [`DatagramSocketRecv`] types. Callers will tend to import this trait instead
/// of [`DatagramSocketRecv`].
///
/// [`DatagramSocketRecv`]: DatagramSocketRecv
pub trait DatagramSocketRecvExt: DatagramSocketRecv {
    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    fn recv(
        &mut self, buf: &mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send {
        poll_fn(|cx| {
            let mut buf = ReadBuf::new(buf);

            ready!(self.poll_recv(cx, &mut buf)?);

            Poll::Ready(Ok(buf.filled().len()))
        })
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    fn recv_from(
        &mut self, buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send {
        poll_fn(|cx| {
            let mut buf = ReadBuf::new(buf);

            let addr = ready!(self.poll_recv_from(cx, &mut buf)?);

            Poll::Ready(Ok((buf.filled().len(), addr)))
        })
    }

    /// Receives multiple datagrams on the socket from the remote address
    /// to which it is connected. Returns the number of buffers used (i.e.
    /// number of datagrams read). Each used buffer can be read up to its
    /// `filled().len()`.
    fn recv_many(
        &mut self, bufs: &mut [ReadBuf<'_>],
    ) -> impl Future<Output = io::Result<usize>> + Send {
        poll_fn(|cx| self.poll_recv_many(cx, bufs))
    }
}

impl<T: DatagramSocketSend + ?Sized> DatagramSocketSendExt for T {}

impl<T: DatagramSocketRecv + ?Sized> DatagramSocketRecvExt for T {}

/// A convenience method that can be implemented for any type if it wants
/// to forward its `DatagramSocketSend` functionality to an inner field/socket.
/// This automatically derives `DatagramSocketSend`.
pub trait AsDatagramSocketSend {
    type AsSend: DatagramSocketSend + ?Sized;

    fn as_datagram_socket_send(&self) -> &Self::AsSend;
}

/// A convenience method that can be implemented for any type if it wants
/// to forward its `DatagramSocketRecv` functionality to an inner field/socket.
/// This automatically derives `DatagramSocketRecv`.
pub trait AsDatagramSocketRecv {
    type AsRecv: DatagramSocketRecv + ?Sized;

    fn as_datagram_socket_recv(&mut self) -> &mut Self::AsRecv;
    fn as_shared_datagram_socket_recv(&self) -> &Self::AsRecv;
}

impl<T: AsDatagramSocketSend + Sync> DatagramSocketSend for T {
    #[inline]
    fn poll_send(&self, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.as_datagram_socket_send().poll_send(cx, buf)
    }

    #[inline]
    fn poll_send_to(
        &self, cx: &mut Context, buf: &[u8], addr: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.as_datagram_socket_send().poll_send_to(cx, buf, addr)
    }

    #[inline]
    fn poll_send_many(
        &self, cx: &mut Context, bufs: &[ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        self.as_datagram_socket_send().poll_send_many(cx, bufs)
    }

    #[inline]
    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        self.as_datagram_socket_send().as_udp_socket()
    }

    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.as_datagram_socket_send().peer_addr()
    }
}

impl<T: AsDatagramSocketRecv + Send> DatagramSocketRecv for T {
    #[inline]
    fn poll_recv(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.as_datagram_socket_recv().poll_recv(cx, buf)
    }

    #[inline]
    fn poll_recv_from(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.as_datagram_socket_recv().poll_recv_from(cx, buf)
    }

    #[inline]
    fn poll_recv_many(
        &mut self, cx: &mut Context<'_>, bufs: &mut [ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        self.as_datagram_socket_recv().poll_recv_many(cx, bufs)
    }

    #[inline]
    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        self.as_shared_datagram_socket_recv().as_udp_socket()
    }
}

impl<T> AsDatagramSocketSend for &mut T
where
    T: DatagramSocketSend + Send + ?Sized,
{
    type AsSend = T;

    fn as_datagram_socket_send(&self) -> &Self::AsSend {
        self
    }
}

impl<T> AsDatagramSocketSend for Box<T>
where
    T: DatagramSocketSend + Send + ?Sized,
{
    type AsSend = T;

    fn as_datagram_socket_send(&self) -> &Self::AsSend {
        self
    }
}

impl<T> AsDatagramSocketSend for Arc<T>
where
    T: DatagramSocketSend + Send + ?Sized,
{
    type AsSend = T;

    fn as_datagram_socket_send(&self) -> &Self::AsSend {
        self
    }
}

impl<T> AsDatagramSocketRecv for &mut T
where
    T: DatagramSocketRecv + Send + ?Sized,
{
    type AsRecv = T;

    fn as_datagram_socket_recv(&mut self) -> &mut Self::AsRecv {
        self
    }

    fn as_shared_datagram_socket_recv(&self) -> &Self::AsRecv {
        self
    }
}

impl<T> AsDatagramSocketRecv for Box<T>
where
    T: DatagramSocketRecv + Send + ?Sized,
{
    type AsRecv = T;

    fn as_datagram_socket_recv(&mut self) -> &mut Self::AsRecv {
        self
    }

    fn as_shared_datagram_socket_recv(&self) -> &Self::AsRecv {
        self
    }
}

impl DatagramSocket for UdpSocket {
    #[cfg(unix)]
    fn as_raw_io(&self) -> Option<BorrowedFd<'_>> {
        Some(self.as_fd())
    }

    #[cfg(unix)]
    fn into_fd(self) -> Option<OwnedFd> {
        Some(into_owned_fd(self.into_std().ok()?))
    }
}

impl DatagramSocketSend for UdpSocket {
    #[inline]
    fn poll_send(&self, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send(self, cx, buf)
    }

    #[inline]
    fn poll_send_to(
        &self, cx: &mut Context, buf: &[u8], addr: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, buf, addr)
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn poll_send_many(
        &self, cx: &mut Context, bufs: &[ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        crate::poll_sendmmsg!(self, cx, bufs)
    }

    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        Some(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
}

impl DatagramSocketRecv for UdpSocket {
    #[inline]
    fn poll_recv(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        UdpSocket::poll_recv(self, cx, buf)
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn poll_recv_many(
        &mut self, cx: &mut Context<'_>, bufs: &mut [ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        crate::poll_recvmmsg!(self, cx, bufs)
    }

    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        Some(self)
    }
}

impl DatagramSocket for Arc<UdpSocket> {
    #[cfg(unix)]
    fn as_raw_io(&self) -> Option<BorrowedFd<'_>> {
        Some(self.as_fd())
    }

    #[cfg(unix)]
    fn into_fd(self) -> Option<OwnedFd> {
        None
    }
}

impl DatagramSocketRecv for Arc<UdpSocket> {
    #[inline]
    fn poll_recv(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        UdpSocket::poll_recv(self, cx, buf)
    }

    #[inline]
    fn poll_recv_from(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        UdpSocket::poll_recv_from(self, cx, buf)
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn poll_recv_many(
        &mut self, cx: &mut Context<'_>, bufs: &mut [ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        crate::poll_recvmmsg!(self, cx, bufs)
    }

    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        Some(self)
    }
}

#[cfg(unix)]
impl DatagramSocket for UnixDatagram {
    fn as_raw_io(&self) -> Option<BorrowedFd<'_>> {
        Some(self.as_fd())
    }

    fn into_fd(self) -> Option<OwnedFd> {
        Some(into_owned_fd(self.into_std().ok()?))
    }
}

#[cfg(unix)]
impl DatagramSocketSend for UnixDatagram {
    #[inline]
    fn poll_send(&self, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        UnixDatagram::poll_send(self, cx, buf)
    }

    #[inline]
    fn poll_send_to(
        &self, _: &mut Context, _: &[u8], _: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "invalid address family",
        )))
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn poll_send_many(
        &self, cx: &mut Context, bufs: &[ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        crate::poll_sendmmsg!(self, cx, bufs)
    }
}

#[cfg(unix)]
impl DatagramSocketRecv for UnixDatagram {
    #[inline]
    fn poll_recv(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        UnixDatagram::poll_recv(self, cx, buf)
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn poll_recv_many(
        &mut self, cx: &mut Context<'_>, bufs: &mut [ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        crate::poll_recvmmsg!(self, cx, bufs)
    }
}

#[cfg(unix)]
impl DatagramSocketRecv for Arc<UnixDatagram> {
    #[inline]
    fn poll_recv(
        &mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        UnixDatagram::poll_recv(self, cx, buf)
    }

    #[cfg(target_os = "linux")]
    #[inline]
    fn poll_recv_many(
        &mut self, cx: &mut Context<'_>, bufs: &mut [ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        crate::poll_recvmmsg!(self, cx, bufs)
    }
}

/// `Into<OwnedFd>::into` for types (tokio sockets etc) that don't implement
/// `From<OwnedFd>`.
#[cfg(unix)]
fn into_owned_fd<F: IntoRawFd>(into_fd: F) -> OwnedFd {
    unsafe { OwnedFd::from_raw_fd(into_fd.into_raw_fd()) }
}

/// A cheap wrapper around a datagram socket which describes if it is connected
/// to an explicit peer.
///
/// This struct essentially forwards its underlying socket's `send_to()` method
/// to `send()` if the socket is explicitly connected to a peer. This is helpful
/// for preventing issues on platforms that do not support `send_to` on
/// already-connected sockets.
///
/// # Warning
/// A socket's "connectedness" is determined once, when it is created. If the
/// socket is created as connected, then later disconnected from its peer, its
/// `send_to()` call will fail.
///
/// For example, MacOS errors if `send_to` is used on a socket that's already
/// connected. Only `send` can be used. By using `MaybeConnectedSocket`, you can
/// use the same `send` and `send_to` APIs in both client- and server-side code.
/// Clients, usually with connected sockets, will then forward `send_to` to
/// `send`, whereas servers, usually with unconnected sockets, will use
/// `send_to`.
#[derive(Clone)]
pub struct MaybeConnectedSocket<T> {
    inner: T,
    peer: Option<SocketAddr>,
}

impl<T: DatagramSocketSend> MaybeConnectedSocket<T> {
    pub fn new(inner: T) -> Self {
        Self {
            peer: inner.peer_addr(),
            inner,
        }
    }

    /// Provides access to the wrapped socket, allowing the user to override
    /// `send_to()` behavior if required.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Consumes `self`, returning the wrapped socket.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: DatagramSocketSend> DatagramSocketSend for MaybeConnectedSocket<T> {
    #[inline]
    fn poll_send(&self, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.inner.poll_send(cx, buf)
    }

    #[inline]
    fn poll_send_to(
        &self, cx: &mut Context, buf: &[u8], addr: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if let Some(peer) = self.peer {
            debug_assert_eq!(peer, addr);
            self.inner.poll_send(cx, buf)
        } else {
            self.inner.poll_send_to(cx, buf, addr)
        }
    }

    #[inline]
    fn poll_send_many(
        &self, cx: &mut Context, bufs: &[ReadBuf<'_>],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_send_many(cx, bufs)
    }

    #[inline]
    fn as_udp_socket(&self) -> Option<&UdpSocket> {
        self.inner.as_udp_socket()
    }

    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }
}
