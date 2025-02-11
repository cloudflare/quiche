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

use std::future::poll_fn;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use tokio::net::UdpSocket;

#[cfg(unix)]
use tokio::net::UnixDatagram;

pub trait ShutdownConnection {
    /// Initiates or attempts to shut down this writer, returning success when
    /// the I/O connection has completely shut down.
    ///
    /// # Return value
    ///
    /// This function returns a `Poll<io::Result<()>>` classified as such:
    ///
    /// * `Poll::Ready(Ok(()))` - indicates that the connection was successfully
    ///   shut down and is now safe to deallocate/drop/close resources
    ///   associated with it. This method means that the current task will no
    ///   longer receive any notifications due to this method and the I/O object
    ///   itself is likely no longer usable.
    ///
    /// * `Poll::Pending` - indicates that shutdown is initiated but could not
    ///   complete just yet. This may mean that more I/O needs to happen to
    ///   continue this shutdown operation. The current task is scheduled to
    ///   receive a notification when it's otherwise ready to continue the
    ///   shutdown operation. When woken up this method should be called again.
    ///
    /// * `Poll::Ready(Err(e))` - indicates a fatal error has happened with
    ///   shutdown, indicating that the shutdown operation did not complete
    ///   successfully. This typically means that the I/O object is no longer
    ///   usable.
    ///
    /// # Errors
    ///
    /// This function can return normal I/O errors through `Err`, described
    /// above. Additionally this method may also render the underlying
    /// `Write::write` method no longer usable (e.g. will return errors in the
    /// future). It's recommended that once `shutdown` is called the
    /// `write` method is no longer called.
    fn poll_shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>>;
}

impl ShutdownConnection for UdpSocket {
    #[inline]
    fn poll_shutdown(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(unix)]
impl ShutdownConnection for UnixDatagram {
    #[inline]
    fn poll_shutdown(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl<T: ShutdownConnection + Send + Sync> ShutdownConnection for Arc<T> {
    #[inline]
    fn poll_shutdown(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Shuts down a datagram oriented connection.
///
/// Implemented as an extension trait, adding utility methods to all
/// [`ShutdownConnection`] types. Callers will tend to import this trait instead
/// of [`ShutdownConnection`].
///
/// [`ShutdownConnection`]: ShutdownConnection
pub trait ShutdownConnectionExt: ShutdownConnection {
    #[inline]
    fn shutdown_connection(&mut self) -> impl Future<Output = io::Result<()>> {
        poll_fn(move |cx| self.poll_shutdown(cx))
    }
}

impl<T: ShutdownConnection + ?Sized> ShutdownConnectionExt for T {}
