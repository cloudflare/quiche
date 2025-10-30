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
    send_buf: &[u8], segment_size: usize, tx_time: Option<Instant>,
    would_block_metric: Counter, send_to_wouldblock_duration_s: TimeHistogram,
) -> io::Result<usize> {
    // An instant with the value of zero, since [`Instant`] is backed by a version
    // of timespec this allows to extract raw values from an [`Instant`]
    const INSTANT_ZERO: Instant = unsafe { std::mem::transmute(0u128) };

    let iov = [std::io::IoSlice::new(send_buf)];
    let segment_size_u16 = segment_size as u16;

    let raw_time = tx_time
        .map(|t| t.duration_since(INSTANT_ZERO).as_nanos() as u64)
        .unwrap_or(0);

    let pkt_info = from.map(PktInfo::from_socket_addr);

    let mut cmsgs: SmallVec<[ControlMessage; 3]> = SmallVec::new();

    // Create cmsg for UDP_SEGMENT.
    cmsgs.push(ControlMessage::UdpGsoSegments(&segment_size_u16));

    if tx_time.is_some() {
        // Create cmsg for TXTIME.
        cmsgs.push(ControlMessage::TxTime(&raw_time));
    }

    if let Some(pkt) = pkt_info.as_ref() {
        // Create cmsg for IP(V6)_PKTINFO.
        cmsgs.push(pkt.make_cmsg());
    }

    let addr = SockaddrStorage::from(to);

    let mut sendmsg_retry_timer = None;
    loop {
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
    send_buf: &[u8], _segment_size: usize, _tx_time: Option<Instant>,
    _would_block_metric: Counter, _send_to_wouldblock_duration_s: TimeHistogram,
) -> io::Result<usize> {
    socket.send_to(send_buf, to).await
}

#[cfg(all(target_os = "linux", test))]
mod test {
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
