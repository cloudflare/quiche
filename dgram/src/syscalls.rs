#[cfg(target_os = "linux")]
mod linux {
    pub(super) use super::super::linux_imports::*;
    pub(super) use std::os::fd::AsFd;
    pub(super) use std::time::Instant;
    pub(super) use std::time::SystemTime;

    pub(crate) type SyscallResult<T> = std::result::Result<T, Errno>;

    // An instant with the value of zero, since [`Instant`] is backed by a version
    // of timespec this allows to extract raw values from an [`Instant`]
    pub(super) const INSTANT_ZERO: Instant =
        unsafe { std::mem::transmute(std::time::UNIX_EPOCH) };
}

#[cfg(target_os = "linux")]
use linux::*;

#[cfg(target_os = "linux")]
fn raw_send_to(
    fd: &impl AsFd, send_buf: &[u8], cmsgs: &[ControlMessage],
    msg_flags: MsgFlags, client_addr: Option<SockaddrStorage>,
) -> SyscallResult<usize> {
    let iov = [IoSlice::new(send_buf)];
    let borrowed = fd.as_fd();

    sendmsg(
        borrowed.as_raw_fd(),
        &iov,
        cmsgs,
        msg_flags,
        client_addr.as_ref(),
    )
}

/// GSO-compatible convenience wrapper for the `sendmsg` syscall.
///
/// It is the caller's responsibility to set any relevant socket options.
#[cfg(target_os = "linux")]
pub fn send_msg(
    fd: impl AsFd, send_buf: &[u8], send_msg_settings: SendMsgSettings,
) -> SyscallResult<usize> {
    use crate::IpPktInfo;

    let SendMsgSettings {
        ref segment_size,
        tx_time,
        dst,
        pkt_info,
    } = send_msg_settings;

    let raw_time = tx_time
        .map(|t| t.duration_since(INSTANT_ZERO).as_nanos() as u64)
        .unwrap_or(0);

    let mut cmsgs: SmallVec<[ControlMessage; 3]> = SmallVec::new();

    if let Some(ss) = segment_size {
        // Create cmsg for UDP_SEGMENT.
        cmsgs.push(ControlMessage::UdpGsoSegments(ss));
    }

    if tx_time.filter(|t| *t > Instant::now()).is_some() {
        // Create cmsg for TXTIME.
        cmsgs.push(ControlMessage::TxTime(&raw_time));
    }

    if let Some(pkt_info) = pkt_info.as_ref() {
        // Create cmsg for IP_PKTINFO.
        match pkt_info {
            IpPktInfo::V4(pi) => cmsgs.push(ControlMessage::Ipv4PacketInfo(pi)),
            IpPktInfo::V6(pi) => cmsgs.push(ControlMessage::Ipv6PacketInfo(pi)),
        }
    }

    let client_addr = dst.map(SockaddrStorage::from);
    raw_send_to(
        &fd.as_fd(),
        send_buf,
        &cmsgs,
        MsgFlags::empty(),
        client_addr,
    )
}

/// Receive a message via `recvmsg`. The returned `RecvData` will contain data
/// from supported cmsgs regardless of if the passed [`StoreCmsgSettings`]
/// indicates that we should store the cmsgs.
///
/// # Note
///
/// It is the caller's responsibility to create and clear the cmsg space.`nix`
/// recommends that the space be created via the `cmsg_space!()` macro. Calling
/// this function will clear the cmsg buffer. It is also the caller's
/// responsibility to set any relevant socket options.
#[cfg(target_os = "linux")]
pub fn recv_msg(
    fd: impl AsFd, read_buf: &mut [u8], recvmsg_settings: &mut RecvMsgSettings,
) -> SyscallResult<RecvData> {
    use crate::IpOrigDstAddr;

    let RecvMsgSettings {
        store_cmsgs,
        ref mut cmsg_space,
    } = recvmsg_settings;

    cmsg_space.clear();

    let iov_s = &mut [IoSliceMut::new(read_buf)];
    let cmsg_space_len = cmsg_space.len();

    let borrowed = fd.as_fd();
    match recvmsg::<SockaddrStorage>(
        borrowed.as_raw_fd(),
        iov_s,
        Some(cmsg_space),
        MsgFlags::empty(),
    ) {
        Ok(r) => {
            let bytes = r.bytes;

            let address = match r.address {
                Some(a) => a,
                _ => return Err(Errno::EINVAL),
            };

            let peer_addr = match address.family() {
                Some(AddressFamily::Inet) => Some(
                    SocketAddrV4::from(*address.as_sockaddr_in().unwrap()).into(),
                ),
                Some(AddressFamily::Inet6) => Some(
                    SocketAddrV6::from(*address.as_sockaddr_in6().unwrap())
                        .into(),
                ),
                _ => None,
            };

            let mut recv_data = RecvData::new(peer_addr, bytes, cmsg_space_len);
            for msg in r.cmsgs() {
                match msg {
                    ControlMessageOwned::ScmTimestampns(time) =>
                        recv_data.rx_time =
                            SystemTime::UNIX_EPOCH.checked_add(time.into()),
                    ControlMessageOwned::UdpGroSegments(gro) =>
                        recv_data.gro = Some(gro),
                    ControlMessageOwned::RxqOvfl(c) => {
                        if let Ok(1) = getsockopt(&borrowed, RxqOvfl) {
                            recv_data.metrics = Some(RecvMetrics {
                                udp_packets_dropped: c as u64,
                            });
                        }
                    },
                    ControlMessageOwned::Ipv4OrigDstAddr(addr) =>
                        recv_data.original_addr = Some(IpOrigDstAddr::V4(addr)),
                    ControlMessageOwned::Ipv6OrigDstAddr(addr) =>
                        recv_data.original_addr = Some(IpOrigDstAddr::V6(addr)),
                    _ => return Err(Errno::EINVAL),
                }

                if *store_cmsgs {
                    recv_data.cmsgs.push(msg);
                }
            }

            Ok(recv_data)
        },
        Err(e) => Err(e),
    }
}

#[cfg(all(test, target_os = "linux", not(target_os = "android")))]
mod tests {
    use nix::cmsg_space;
    use nix::sys::socket::sockopt::ReceiveTimestampns;
    use nix::sys::socket::sockopt::UdpGroSegment;
    use nix::sys::socket::*;
    use nix::sys::time::TimeVal;
    use std::io::IoSliceMut;
    use std::io::Result;
    use std::net::SocketAddr;
    use std::os::fd::OwnedFd;
    use std::str::FromStr;

    use super::*;

    fn new_sockets() -> Result<(OwnedFd, OwnedFd)> {
        let recv = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let recv_addr = SockaddrIn::from_str("127.0.0.1:0").unwrap();
        bind(recv.as_raw_fd(), &recv_addr).unwrap();

        let send = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        connect(send.as_raw_fd(), &recv_addr).unwrap();

        Ok((send, recv))
    }

    fn fd_to_socket_addr(fd: &impl AsRawFd) -> Option<SocketAddrV4> {
        SocketAddrV4::from_str(
            &getsockname::<SockaddrStorage>(fd.as_raw_fd())
                .unwrap()
                .to_string(),
        )
        .ok()
    }

    #[test]
    fn send_msg_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let send_buf = b"njd";
        let addr = fd_to_socket_addr(&recv);

        let sent = send_msg(send, send_buf, SendMsgSettings {
            segment_size: None,
            tx_time: None,
            dst: Some(SocketAddr::V4(addr.unwrap())),
            pkt_info: None,
        })?;
        assert_eq!(sent, send_buf.len());

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            None,
            MsgFlags::empty(),
        )
        .unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn recv_msg_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        sendmsg(send.as_raw_fd(), &iov, &[], MsgFlags::empty(), Some(&addr))?;

        let mut read_buf = [0; 4];
        let recv_data = recv_msg(recv, &mut read_buf, &mut RecvMsgSettings {
            store_cmsgs: false,
            cmsg_space: &mut vec![],
        })?;

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");
        assert!(recv_data.cmsgs().is_empty());

        Ok(())
    }

    #[test]
    fn send_to_multiple_segments() -> Result<()> {
        let (send, recv) = new_sockets()?;
        // TODO: determine why this has to be set before sendmsg
        setsockopt(&recv, UdpGroSegment, &true).expect("couldn't set UDP_GRO");

        let addr = fd_to_socket_addr(&recv);
        let send_buf = b"devils";
        let sent = send_msg(send, send_buf, SendMsgSettings {
            segment_size: Some(1),
            tx_time: None,
            dst: Some(SocketAddr::V4(addr.unwrap())),
            pkt_info: None,
        })?;
        assert_eq!(sent, send_buf.len());

        let mut buf = [0; 6];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let mut cmsgs = cmsg_space!(i32);
        let recv = recvmsg::<SockaddrStorage>(
            recv.as_raw_fd(),
            &mut read_buf,
            Some(&mut cmsgs),
            MsgFlags::empty(),
        )
        .unwrap();
        assert_eq!(recv.bytes, 6);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );
        // TODO: determine why no cmsg shows up
        assert!(cmsgs.is_empty());

        Ok(())
    }

    #[test]
    fn recvfrom_cmsgs() -> Result<()> {
        let (send, recv) = new_sockets()?;
        setsockopt(&recv, ReceiveTimestampns, &true)?;

        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();
        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        sendmsg(send.as_raw_fd(), &iov, &[], MsgFlags::empty(), Some(&addr))?;

        let mut cmsg_space = cmsg_space!(TimeVal);
        let mut recvmsg_settings = RecvMsgSettings {
            store_cmsgs: true,
            cmsg_space: &mut cmsg_space,
        };

        let mut read_buf = [0; 4];
        let recv_data = recv_msg(recv, &mut read_buf, &mut recvmsg_settings)?;

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");

        assert_eq!(recv_data.cmsgs().len(), 1);
        match recv_data.cmsgs()[0] {
            ControlMessageOwned::ScmTimestampns(_) => {},
            _ => panic!("invalid cmsg received"),
        };

        Ok(())
    }
}
