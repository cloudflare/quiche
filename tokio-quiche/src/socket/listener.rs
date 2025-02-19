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
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::BorrowedFd;
#[cfg(unix)]
use std::os::fd::RawFd;
use tokio::net::UdpSocket;

use super::SocketCapabilities;

/// Wrapper around a [`UdpSocket`] for server-side QUIC connections.
///
/// The wrapper carries socket-specific parameters, in contrast to the
/// [`settings`](crate::settings) structs which apply to _all_ sockets
/// for a given QUIC server.
///
/// To create a [`QuicListener`], you may either instantiate the struct yourself
/// or use one of the `TryFrom` implementations.
#[derive(Debug)]
pub struct QuicListener {
    /// The wrapped [tokio] socket.
    pub socket: UdpSocket,
    /// An opaque value that is later passed to the
    /// [`ConnectionIdGenerator`](crate::ConnectionIdGenerator).
    pub socket_cookie: u64,
    /// The [`SocketCapabilities`] to use for this socket.
    ///
    /// By default, [`QuicListener`]s are constructed with all capabilities
    /// disabled. On Linux, you can use `apply_max_capabilities()` to (try
    /// to) enable all supported capabilities.
    pub capabilities: SocketCapabilities,
}

impl QuicListener {
    /// Tries to enable all sockopts supported by the crate for this socket.
    /// See `SocketCapabilities::apply_all_and_get_compatibility` for details.
    #[cfg(target_os = "linux")]
    pub fn apply_max_capabilities(&mut self, max_send_udp_payload_size: usize) {
        let capabilities = SocketCapabilities::apply_all_and_get_compatibility(
            &self.socket,
            max_send_udp_payload_size,
        );
        self.capabilities = capabilities;
    }
}

impl TryFrom<UdpSocket> for QuicListener {
    type Error = io::Error;

    fn try_from(socket: UdpSocket) -> Result<Self, Self::Error> {
        Ok(Self {
            socket,
            socket_cookie: 0,
            capabilities: SocketCapabilities::default(),
        })
    }
}

impl TryFrom<std::net::UdpSocket> for QuicListener {
    type Error = io::Error;

    fn try_from(socket: std::net::UdpSocket) -> Result<Self, Self::Error> {
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;
        Self::try_from(socket)
    }
}

#[cfg(unix)]
impl AsFd for QuicListener {
    fn as_fd(&self) -> BorrowedFd {
        self.socket.as_fd()
    }
}

#[cfg(unix)]
impl AsRawFd for QuicListener {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}
