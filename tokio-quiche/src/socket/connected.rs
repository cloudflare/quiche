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

use datagram_socket::DatagramSocketRecv;
use datagram_socket::DatagramSocketSend;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use super::SocketCapabilities;

/// A connected datagram socket with separate `send` and `recv` halves.
///
/// [`Socket`] abstracts over both real UDP-based connections and in-process
/// tunneled flows like (multi-hop) MASQUE flows. It uses the
/// [`datagram_socket`] traits for this purpose.
#[derive(Debug)]
pub struct Socket<Tx, Rx> {
    /// The sending half of the connection. This generally supports concurrent
    /// senders.
    pub send: Tx,
    /// The receiving half of the connection. This is generally owned by a
    /// single caller.
    pub recv: Rx,
    /// The address of the local endpoint.
    pub local_addr: SocketAddr,
    /// The address of the remote endpoint.
    pub peer_addr: SocketAddr,
    /// The [`SocketCapabilities`] to use for this socket.
    ///
    /// By default, [`Socket`]s are constructed with all capabilities
    /// disabled. On Linux, you can use `apply_max_capabilities()` to (try
    /// to) enable all supported capabilities.
    pub capabilities: SocketCapabilities,
}

/// A type-erased variant of [`Socket`] with boxed `Tx` and `Rx` halves.
pub type BoxedSocket = Socket<
    Box<dyn DatagramSocketSend + Send + 'static>,
    Box<dyn DatagramSocketRecv + Sync + 'static>,
>;

impl<Tx, Rx> Socket<Tx, Rx> {
    /// Creates a [`Socket`] from a [`UdpSocket`] by wrapping the file
    /// descriptor in an [`Arc`].
    pub fn from_udp(
        socket: UdpSocket,
    ) -> io::Result<Socket<Arc<UdpSocket>, Arc<UdpSocket>>> {
        let local_addr = socket.local_addr()?;
        let peer_addr = socket.peer_addr()?;

        let send = Arc::new(socket);
        let recv = Arc::clone(&send);

        Ok(Socket {
            send,
            recv,
            local_addr,
            peer_addr,
            capabilities: SocketCapabilities::default(),
        })
    }
}

impl<Tx, Rx> Socket<Tx, Rx>
where
    Tx: DatagramSocketSend,
    Rx: DatagramSocketRecv,
{
    /// Checks whether both `send` and `recv` refer to the same underlying
    /// UDP socket FD and returns a reference to that socket.
    ///
    /// # Note
    /// The file descriptor _numbers_ have to be identical. A pair of FDs
    /// created by [`dup(2)`](https://man7.org/linux/man-pages/man2/dup.2.html) will
    /// return `None`.
    #[cfg(unix)]
    pub fn as_udp_socket(&self) -> Option<&UdpSocket> {
        use std::os::fd::AsRawFd;

        let send = self.send.as_udp_socket()?;
        let recv = self.recv.as_udp_socket()?;
        (send.as_raw_fd() == recv.as_raw_fd()).then_some(send)
    }

    /// Tries to enable all sockopts supported by the crate for this socket.
    ///
    /// This does nothing unless `send` and `recv` refer to the same UDP socket
    /// FD. See `SocketCapabilities::apply_all_and_get_compatibility` for
    /// details.
    #[cfg(target_os = "linux")]
    pub fn apply_max_capabilities(&mut self, max_send_udp_payload_size: usize) {
        let Some(socket) = self.as_udp_socket() else {
            return;
        };

        let capabilities = SocketCapabilities::apply_all_and_get_compatibility(
            socket,
            max_send_udp_payload_size,
        );
        self.capabilities = capabilities;
    }
}

impl TryFrom<UdpSocket> for Socket<Arc<UdpSocket>, Arc<UdpSocket>> {
    type Error = io::Error;

    fn try_from(socket: UdpSocket) -> Result<Self, Self::Error> {
        Self::from_udp(socket)
    }
}
