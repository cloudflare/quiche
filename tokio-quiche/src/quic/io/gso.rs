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
use std::net::SocketAddr;
use std::time::Instant;

use crate::quic::Dscp;

use foundations::telemetry::metrics::Counter;
use foundations::telemetry::metrics::TimeHistogram;

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
mod linux_imports {
    pub(super) use nix::sys::socket::sendmsg;
    pub(super) use nix::sys::socket::ControlMessage;
    pub(super) use nix::sys::socket::MsgFlags;
    pub(super) use nix::sys::socket::SockaddrStorage;
    pub(super) use smallvec::SmallVec;
    pub(super) use std::io::ErrorKind;
    pub(super) use std::os::fd::AsRawFd;
    pub(super) use tokio::io::Interest;
}

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use self::linux_imports::*;

// Maximum number of packets can be sent in UDP GSO.
pub(crate) const UDP_MAX_SEGMENT_COUNT: usize = 64;

#[cfg(not(feature = "gcongestion"))]
/// Returns a new max send buffer size to avoid the fragmentation
/// at the end. Maximum send buffer size is min(MAX_SEND_BUF_SIZE,
/// connection's send_quantum).
/// For example,
///
/// - max_send_buf = 1000 and mss = 100, return 1000
/// - max_send_buf = 1000 and mss = 90, return 990
///
/// not to have last 10 bytes packet.
pub(crate) fn tune_max_send_size(
    segment_size: Option<usize>, send_quantum: usize, max_capacity: usize,
) -> usize {
    let max_send_buf_size = send_quantum.min(max_capacity);

    if let Some(mss) = segment_size {
        max_send_buf_size / mss * mss
    } else {
        max_send_buf_size
    }
}

// https://wiki.cfdata.org/pages/viewpage.action?pageId=436188159
pub(crate) const UDP_MAX_GSO_PACKET_SIZE: usize = 65507;

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
#[derive(Copy, Clone, Debug)]
pub(crate) enum PktInfo {
    V4(libc::in_pktinfo),
    V6(libc::in6_pktinfo),
}

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
impl PktInfo {
    fn make_cmsg(&'_ self) -> ControlMessage<'_> {
        match self {
            Self::V4(pkt) => ControlMessage::Ipv4PacketInfo(pkt),
            Self::V6(pkt) => ControlMessage::Ipv6PacketInfo(pkt),
        }
    }

    fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(ipv4) => {
                // This is basically a safe wrapper around `mem::transmute()`.
                // Calling this on the raw octets will ensure they
                // become a native-endian, kernel-readable u32
                let s_addr = u32::from_ne_bytes(ipv4.ip().octets());

                Self::V4(libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                })
            },
            SocketAddr::V6(ipv6) => Self::V6(libc::in6_pktinfo {
                ipi6_ifindex: 0,
                ipi6_addr: libc::in6_addr {
                    s6_addr: ipv6.ip().octets(),
                },
            }),
        }
    }
}

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
#[allow(clippy::too_many_arguments)]
pub async fn send_to(
    socket: &tokio::net::UdpSocket, to: SocketAddr, from: Option<SocketAddr>,
    send_buf: &[u8], segment_size: Option<usize>, tx_time: Option<Instant>,
    dscp: Option<Dscp>, would_block_metric: Counter,
    send_to_wouldblock_duration_s: TimeHistogram,
) -> io::Result<usize> {
    // SAFETY: This Linux-only code assumes `Instant` uses the same layout as a
    // zero-valid timespec. The zero instant allows raw time extraction.
    const INSTANT_ZERO: Instant = unsafe { std::mem::transmute(0u128) };

    let mut sendmsg_retry_timer = None;
    loop {
        let iov = [std::io::IoSlice::new(send_buf)];
        let segment_size_u16 = segment_size.map(|size| size as u16);

        let raw_time = tx_time
            .map(|t| t.duration_since(INSTANT_ZERO).as_nanos() as u64)
            .unwrap_or(0);

        let pkt_info = from.map(PktInfo::from_socket_addr);
        let tos = dscp.map(Dscp::tos);
        let tclass = tos.map(i32::from);

        let mut cmsgs: SmallVec<[ControlMessage; 4]> = SmallVec::new();

        if let Some(segment_size) = segment_size_u16.as_ref() {
            cmsgs.push(ControlMessage::UdpGsoSegments(segment_size));
        }

        if tx_time.is_some() {
            // Create cmsg for TXTIME.
            cmsgs.push(ControlMessage::TxTime(&raw_time));
        }

        if let Some(pkt) = pkt_info.as_ref() {
            // Create cmsg for IP(V6)_PKTINFO.
            cmsgs.push(pkt.make_cmsg());
        }

        match (to, tos.as_ref(), tclass.as_ref()) {
            (SocketAddr::V4(_), Some(tos), _) =>
                cmsgs.push(ControlMessage::Ipv4Tos(tos)),
            // Linux transmits IPv4-mapped destinations as IPv4 and silently
            // ignores IPV6_TCLASS for them.
            (SocketAddr::V6(to), Some(tos), _)
                if to.ip().to_ipv4_mapped().is_some() =>
                cmsgs.push(ControlMessage::Ipv4Tos(tos)),
            (SocketAddr::V6(_), _, Some(tclass)) =>
                cmsgs.push(ControlMessage::Ipv6TClass(tclass)),
            _ => (),
        }

        let addr = SockaddrStorage::from(to);

        // Must use [`try_io`] so tokio can properly clear its readyness flag
        let res = socket.try_io(Interest::WRITABLE, || {
            let fd = socket.as_raw_fd();
            sendmsg(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&addr))
                .map_err(Into::into)
        });

        match res {
            // Wait for the socket to become writable and try again
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if sendmsg_retry_timer.is_none() {
                    sendmsg_retry_timer =
                        Some(send_to_wouldblock_duration_s.start_timer());
                }
                would_block_metric.inc();
                socket.writable().await?
            },
            res => return res,
        }
    }
}

#[cfg(any(not(target_os = "linux"), feature = "fuzzing"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_to(
    socket: &tokio::net::UdpSocket, to: SocketAddr, _from: Option<SocketAddr>,
    send_buf: &[u8], _segment_size: Option<usize>, _tx_time: Option<Instant>,
    _dscp: Option<Dscp>, _would_block_metric: Counter,
    _send_to_wouldblock_duration_s: TimeHistogram,
) -> io::Result<usize> {
    socket.send_to(send_buf, to).await
}

#[cfg(all(target_os = "linux", test, not(feature = "fuzzing")))]
pub(crate) mod test {
    use super::*;
    use crate::metrics::labels::QuicWriteError;
    use crate::metrics::DefaultMetrics;
    use crate::metrics::Metrics;
    use crate::quic::DscpHandle;
    use nix::sys::socket::recvmsg;
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt;
    use nix::sys::socket::ControlMessageOwned;
    use nix::sys::socket::MsgFlags;
    use std::io::IoSliceMut;
    use std::os::fd::AsRawFd;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;
    use tokio::time::Duration;

    const TEST_DSCP: Dscp = Dscp::new(34).unwrap();

    pub(crate) fn enable_tos(socket: &UdpSocket) {
        if socket.local_addr().unwrap().is_ipv4() {
            setsockopt(socket, sockopt::IpRecvTos, &true).unwrap();
        } else {
            setsockopt(socket, sockopt::Ipv6RecvTClass, &true).unwrap();
        }
    }

    pub(crate) async fn recv_tos(socket: &UdpSocket) -> (Vec<u8>, u8) {
        let receive = async {
            let mut buf = [0u8; 2048];
            let mut cmsg_space = nix::cmsg_space!(libc::c_int);

            loop {
                socket.readable().await.unwrap();
                match socket.try_io(Interest::READABLE, || {
                    let mut iov = [IoSliceMut::new(&mut buf)];
                    let msg = recvmsg::<()>(
                        socket.as_raw_fd(),
                        &mut iov,
                        Some(&mut cmsg_space),
                        MsgFlags::empty(),
                    )
                    .map_err(io::Error::from)?;
                    let tos =
                        msg.cmsgs().map_err(io::Error::from)?.find_map(|cmsg| {
                            match cmsg {
                                ControlMessageOwned::Ipv4Tos(tos) => Some(tos),
                                ControlMessageOwned::Ipv6TClass(tclass) =>
                                    Some(u8::try_from(tclass).unwrap()),
                                _ => None,
                            }
                        });
                    Ok((msg.bytes, tos))
                }) {
                    Ok((len, Some(tos))) => return (buf[..len].to_vec(), tos),
                    Ok((_, None)) => panic!("IP TOS control message missing"),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("recvmsg failed: {e}"),
                }
            }
        };

        timeout(Duration::from_secs(2), receive)
            .await
            .expect("timed out waiting for UDP packet")
    }

    async fn send_packet(
        sender: &UdpSocket, receiver: &UdpSocket, buf: &[u8],
        segment_size: Option<usize>, from: Option<SocketAddr>,
        dscp: Option<Dscp>,
    ) {
        let metrics = DefaultMetrics;
        let bytes = send_to(
            sender,
            receiver.local_addr().unwrap(),
            from,
            buf,
            segment_size,
            None,
            dscp,
            metrics.write_errors(QuicWriteError::WouldBlock),
            metrics.send_to_wouldblock_duration_s(),
        )
        .await
        .unwrap();
        assert_eq!(bytes, buf.len());
    }

    #[tokio::test]
    async fn per_packet_dscp_overrides_socket_without_leaking() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_tos(&receiver);

        // A nonzero socket default makes an explicit zero distinguishable from
        // omitting the cmsg after a marking is cleared.
        setsockopt(&sender, sockopt::Ipv4Tos, &136).unwrap();
        let first = DscpHandle::new();
        let second = DscpHandle::new();
        second.set(Dscp::new(1));

        for (dscp, expected) in
            [(first.get(), 136), (second.get(), 4), (first.get(), 136)]
        {
            send_packet(
                &sender,
                &receiver,
                b"quic",
                None,
                Some(sender.local_addr().unwrap()),
                dscp,
            )
            .await;
            let (payload, tos) = recv_tos(&receiver).await;
            assert_eq!(payload, b"quic");
            assert_eq!(tos & 0xfc, expected);
        }

        first.set(Dscp::new(28));
        send_packet(&sender, &receiver, b"updated", None, None, first.get())
            .await;
        assert_eq!(recv_tos(&receiver).await.1 & 0xfc, 112);

        first.set(Dscp::new(0));
        send_packet(&sender, &receiver, b"zero", None, None, first.get()).await;
        assert_eq!(recv_tos(&receiver).await.1 & 0xfc, 0);

        first.set(None);
        send_packet(&sender, &receiver, b"unmarked", None, None, first.get())
            .await;
        assert_eq!(recv_tos(&receiver).await.1 & 0xfc, 136);
    }

    #[tokio::test]
    async fn gso_segments_keep_dscp_with_pktinfo() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_tos(&receiver);

        let buf = vec![42u8; 2400];
        send_packet(
            &sender,
            &receiver,
            &buf,
            Some(1200),
            Some(sender.local_addr().unwrap()),
            Some(TEST_DSCP),
        )
        .await;

        for _ in 0..2 {
            let (payload, tos) = recv_tos(&receiver).await;
            assert_eq!(payload, &buf[..1200]);
            assert_eq!(tos >> 2, TEST_DSCP.value());
        }
    }

    #[tokio::test]
    async fn ipv6_tclass_marks_packet_without_gso() {
        let sender = UdpSocket::bind("[::1]:0").await.unwrap();
        let receiver = UdpSocket::bind("[::1]:0").await.unwrap();
        enable_tos(&receiver);

        send_packet(
            &sender,
            &receiver,
            b"ipv6",
            None,
            Some(sender.local_addr().unwrap()),
            Some(TEST_DSCP),
        )
        .await;
        let (payload, tos) = recv_tos(&receiver).await;
        assert_eq!(payload, b"ipv6");
        assert_eq!(tos >> 2, TEST_DSCP.value());
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_peer_uses_ipv4_tos() {
        use std::net::Ipv4Addr;
        use std::net::SocketAddr;
        use std::net::SocketAddrV6;

        let sender = UdpSocket::bind("[::]:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_tos(&receiver);

        let SocketAddr::V4(peer) = receiver.local_addr().unwrap() else {
            unreachable!()
        };
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            peer.ip().to_ipv6_mapped(),
            peer.port(),
            0,
            0,
        ));
        let mapped_source = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            sender.local_addr().unwrap().port(),
            0,
            0,
        ));
        let metrics = DefaultMetrics;
        for from in [None, Some(mapped_source)] {
            send_to(
                &sender,
                mapped,
                from,
                b"mapped",
                None,
                None,
                Some(TEST_DSCP),
                metrics.write_errors(QuicWriteError::WouldBlock),
                metrics.send_to_wouldblock_duration_s(),
            )
            .await
            .unwrap();

            let (payload, tos) = recv_tos(&receiver).await;
            assert_eq!(payload, b"mapped");
            assert_eq!(tos >> 2, TEST_DSCP.value());
        }
    }

    #[test]
    /// If this test begins to fail, it means the implementation of [`Instant`]
    /// has changed in the std library.
    fn instant_zero() {
        use std::time::Instant;

        const INSTANT_ZERO: Instant = unsafe { std::mem::transmute(0u128) };
        const NANOS_PER_SEC: u128 = 1_000_000_000;

        // Define a [`Timespec`] similar to the one backing [`Instant`]
        #[derive(Debug)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: u32,
        }

        let now = Instant::now();
        let now_timespec: Timespec = unsafe { std::mem::transmute(now) };

        let ref_elapsed = now.duration_since(INSTANT_ZERO).as_nanos();
        let raw_elapsed = now_timespec.tv_sec as u128 * NANOS_PER_SEC +
            now_timespec.tv_nsec as u128;

        assert_eq!(ref_elapsed, raw_elapsed);
    }
}
