use datagram_socket::DatagramSocketRecv;
use datagram_socket::DatagramSocketSend;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

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
}

impl TryFrom<UdpSocket> for Socket<Arc<UdpSocket>, Arc<UdpSocket>> {
    type Error = io::Error;

    fn try_from(socket: UdpSocket) -> Result<Self, Self::Error> {
        Self::from_udp(socket)
    }
}
