use dgram::RecvData;

#[cfg(target_os = "linux")]
use std::io;

/// For Linux, try to detect if GRO is available. If it is, the
/// [`UdpGroSegment`] socket option will be set on the passed socket.
///
/// [`UdpGroSegment`]: https://docs.rs/nix/latest/nix/sys/socket/sockopt/struct.UdpGroSegment.html
#[cfg(target_os = "linux")]
pub fn detect_gro(socket: &mio::net::UdpSocket) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGroSegment;
    use std::os::unix::io::AsRawFd;

    // mio::net::UdpSocket doesn't implement AsFd (yet?).
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(socket.as_raw_fd()) };

    match setsockopt(&fd, UdpGroSegment, &true) {
        Ok(_) => {
            debug!("Successfully set UDP_GRO socket option");
            true
        },
        Err(e) => {
            debug!("Setting UDP_GRO failed: {:?}", e);
            false
        },
    }
}

#[cfg(not(target_os = "linux"))]
pub fn detect_gro(_socket: &mio::net::UdpSocket) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn recv_from(
    socket: &mio::net::UdpSocket, buf: &mut [u8],
) -> io::Result<RecvData> {
    use dgram::RecvMsgSettings;
    use std::os::unix::io::AsRawFd;

    let mut recvmsg_cmsg_settings = RecvMsgSettings {
        store_cmsgs: false,
        cmsg_space: &mut vec![],
    };
    socket.try_io(|| {
        let fd =
            unsafe { std::os::fd::BorrowedFd::borrow_raw(socket.as_raw_fd()) };

        dgram::sync::recv_from(&fd, buf, &mut recvmsg_cmsg_settings)
    })
}

#[cfg(not(target_os = "linux"))]
pub fn recv_from(
    socket: &mio::net::UdpSocket, buf: &mut [u8],
) -> std::io::Result<RecvData> {
    match socket.recv_from(buf) {
        Ok((read, from)) => Ok(RecvData::new(Some(from), read, 0)),
        Err(e) => Err(e),
    }
}
