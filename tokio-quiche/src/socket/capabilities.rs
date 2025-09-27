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

#[cfg(target_os = "linux")]
mod linux_imports {
    pub use libc::c_int;
    pub use libc::c_void;
    pub use libc::sock_txtime;
    pub use libc::socklen_t;
    pub use libc::IPPROTO_IP;
    pub use libc::IPPROTO_IPV6;
    pub use libc::IPV6_MTU_DISCOVER;
    pub use libc::IPV6_PMTUDISC_PROBE;
    pub use libc::IP_MTU_DISCOVER;
    pub use libc::IP_PMTUDISC_PROBE;
    pub use libc::SOL_SOCKET;
    pub use libc::SO_RCVMARK;
    pub use nix::errno::Errno;
    pub use nix::sys::socket::getsockopt;
    pub use nix::sys::socket::setsockopt;
    pub use nix::sys::socket::sockopt::IpFreebind;
    pub use nix::sys::socket::sockopt::IpTransparent;
    pub use nix::sys::socket::sockopt::Ipv4OrigDstAddr;
    pub use nix::sys::socket::sockopt::Ipv4PacketInfo;
    pub use nix::sys::socket::sockopt::Ipv6OrigDstAddr;
    pub use nix::sys::socket::sockopt::Ipv6RecvPacketInfo;
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub use nix::sys::socket::sockopt::ReceiveTimestampns;
    pub use nix::sys::socket::sockopt::RxqOvfl;
    pub use nix::sys::socket::sockopt::TxTime;
    pub use nix::sys::socket::sockopt::UdpGroSegment;
    pub use nix::sys::socket::sockopt::UdpGsoSegment;
    pub use nix::sys::socket::SetSockOpt;
    pub use std::io;
    pub use std::os::fd::AsFd;
    pub use std::os::fd::AsRawFd;
    pub use std::os::fd::BorrowedFd;
}

#[cfg(target_os = "linux")]
use linux_imports::*;

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct IpMtuDiscoverProbe;

#[cfg(target_os = "linux")]
impl SetSockOpt for IpMtuDiscoverProbe {
    type Val = ();

    fn set<F: AsFd>(&self, fd: &F, _val: &Self::Val) -> nix::Result<()> {
        let pmtud_mode: c_int = IP_PMTUDISC_PROBE;
        let ret = unsafe {
            libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                IPPROTO_IP,
                IP_MTU_DISCOVER,
                &pmtud_mode as *const c_int as *const c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            )
        };

        match ret {
            0 => Ok(()),
            _ => Err(Errno::last()),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct Ipv6MtuDiscoverProbe;

#[cfg(target_os = "linux")]
impl SetSockOpt for Ipv6MtuDiscoverProbe {
    type Val = ();

    fn set<F: AsFd>(&self, fd: &F, _val: &Self::Val) -> nix::Result<()> {
        let pmtud_mode: c_int = IPV6_PMTUDISC_PROBE;
        let ret = unsafe {
            libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                IPPROTO_IPV6,
                IPV6_MTU_DISCOVER,
                &pmtud_mode as *const c_int as *const c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            )
        };

        match ret {
            0 => Ok(()),
            _ => Err(Errno::last()),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct RcvMark;

#[cfg(target_os = "linux")]
impl SetSockOpt for RcvMark {
    type Val = ();

    fn set<F: AsFd>(&self, fd: &F, _val: &Self::Val) -> nix::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                SOL_SOCKET,
                SO_RCVMARK,
                &1 as *const c_int as *const c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            )
        };

        match ret {
            0 => Ok(()),
            _ => Err(Errno::last()),
        }
    }
}

/// Builder to enable Linux sockopts which improve QUIC performance.
#[cfg(target_os = "linux")]
pub struct SocketCapabilitiesBuilder<'s> {
    socket: BorrowedFd<'s>,
    cap: SocketCapabilities,
}

#[cfg(target_os = "linux")]
impl<'s> SocketCapabilitiesBuilder<'s> {
    /// Creates a new sockopt builder for `socket`.
    pub fn new<S: AsFd>(socket: &'s S) -> Self {
        Self {
            socket: socket.as_fd(),
            cap: Default::default(),
        }
    }

    /// Enables [`UDP_SEGMENT`](https://man7.org/linux/man-pages/man7/udp.7.html),
    /// a generic segmentation offload (GSO).
    ///
    /// GSO improves transmit performance by treating multiple sequential UDP
    /// packets as a single entity in the kernel. Segmentation into
    /// individual packets happens in the NIC, if it supports GSO. The
    /// parameter specifies the packet size.
    pub fn gso(&mut self) -> io::Result<()> {
        // We initialize GSO on the socket with the maximum possible segment size
        // to prevent accidentally setting it too small and running into
        // issues when increasing max_send_udp_payload_size later on.
        //
        // https://elixir.bootlin.com/linux/v6.14.6/source/net/ipv4/udp.c#L2998
        // https://elixir.bootlin.com/linux/v6.14.6/source/include/vdso/limits.h#L5
        setsockopt(&self.socket.as_fd(), UdpGsoSegment, &(u16::MAX as i32))?;
        self.cap.has_gso = true;
        Ok(())
    }

    /// Enables [`SO_RXQ_OVFL`](https://man7.org/linux/man-pages/man7/socket.7.html),
    /// which reports dropped packets due to insufficient buffer space.
    pub fn check_udp_drop(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), RxqOvfl, &1)?;

        self.cap.check_udp_drop = true;
        Ok(())
    }

    /// Enables [`SO_TXTIME`](https://man7.org/linux/man-pages/man8/tc-etf.8.html)
    /// to control packet transmit timestamps for QUIC pacing.
    pub fn txtime(&mut self) -> io::Result<()> {
        let cfg = sock_txtime {
            clockid: libc::CLOCK_MONOTONIC,
            flags: 0,
        };
        setsockopt(&self.socket.as_fd(), TxTime, &cfg)?;

        self.cap.has_txtime = true;
        Ok(())
    }

    /// Enables [`SO_TIMESTAMPNS`](https://man7.org/linux/man-pages/man7/socket.7.html),
    /// which records a wall-clock timestamp for each received packet.
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub fn rxtime(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), ReceiveTimestampns, &true)?;

        self.cap.has_rxtime = true;
        Ok(())
    }

    /// Enables [`UDP_GRO`](https://man7.org/linux/man-pages/man7/udp.7.html),
    /// a generic receive offload (GRO).
    ///
    /// GRO improves receive performance by allowing the kernel to yield
    /// multiple UDP packets in one [`recvmsg(2)`](https://man7.org/linux/man-pages/man2/recv.2.html)
    /// call. It is the equivalent of GSO for the receive path.
    pub fn gro(&mut self) -> io::Result<()> {
        UdpGroSegment.set(&self.socket.as_fd(), &true)?;

        self.cap.has_gro = true;
        Ok(())
    }

    /// Enables [`IP_PKTINFO`](https://man7.org/linux/man-pages/man7/ip.7.html)
    /// to control the source IP in outbound IPv4 packets.
    pub fn ipv4_pktinfo(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), Ipv4PacketInfo, &true)?;

        self.cap.has_ippktinfo = true;
        Ok(())
    }

    /// Enables [`IP_RECVORIGDSTADDR`](https://man7.org/linux/man-pages/man7/ip.7.html),
    /// which reports each packet's real IPv4 destination address.
    ///
    /// This can be different from the socket's local address due to netfilter
    /// TPROXY rules or eBPF redirects.
    pub fn ipv4_recvorigdstaddr(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), Ipv4OrigDstAddr, &true)?;

        self.cap.has_iprecvorigdstaddr = true;
        Ok(())
    }

    /// Enables [`IPV6_RECVPKTINFO`](https://man7.org/linux/man-pages/man7/ipv6.7.html)
    /// to control the source IP in outbound IPv6 packets.
    pub fn ipv6_pktinfo(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), Ipv6RecvPacketInfo, &true)?;

        self.cap.has_ipv6pktinfo = true;
        Ok(())
    }

    /// Enables [`IPV6_RECVORIGDSTADDR`](https://elixir.bootlin.com/linux/v6.12/source/net/ipv6/datagram.c#L722-L743),
    /// which reports each packet's real IPv6 destination address.
    ///
    /// This can be different from the socket's local address due to netfilter
    /// TPROXY rules or eBPF redirects.
    pub fn ipv6_recvorigdstaddr(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), Ipv6OrigDstAddr, &true)?;

        self.cap.has_ipv6recvorigdstaddr = true;
        Ok(())
    }

    /// Sets [`IP_MTU_DISCOVER`](https://man7.org/linux/man-pages/man7/ip.7.html), to
    /// `IP_PMTUDISC_PROBE`, which disables kernel PMTUD and sets the `DF`
    /// (Don't Fragment) flag.
    pub fn ip_mtu_discover_probe(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), IpMtuDiscoverProbe, &())?;

        self.cap.has_ip_mtu_discover_probe = true;
        Ok(())
    }

    /// Sets [`IPV6_MTU_DISCOVER`](https://man7.org/linux/man-pages/man7/ipv6.7.html), to
    /// `IPV6_PMTUDISC_PROBE`, which disables kernel PMTUD and sets the `DF`
    /// (Don't Fragment) flag.
    pub fn ipv6_mtu_discover_probe(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), Ipv6MtuDiscoverProbe, &())?;

        self.cap.has_ipv6_mtu_discover_probe = true;
        Ok(())
    }

    /// Tests whether [`IP_FREEBIND`](https://man7.org/linux/man-pages/man7/ip.7.html)
    /// or [`IP_TRANSPARENT`](https://man7.org/linux/man-pages/man7/ip.7.html) are
    /// enabled for this socket.
    ///
    /// # Warning
    /// These sockopts require elevated permissions to enable, so the builder
    /// will only check their status. **If neither of them is enabled, the
    /// `PKTINFO` sockopts will cause errors when sending packets.**
    pub fn allows_nonlocal_source(&self) -> io::Result<bool> {
        Ok(getsockopt(&self.socket.as_fd(), IpFreebind)? ||
            getsockopt(&self.socket.as_fd(), IpTransparent)?)
    }

    pub fn mark(&mut self) -> io::Result<()> {
        setsockopt(&self.socket.as_fd(), RcvMark, &())?;

        self.cap.has_mark = true;
        Ok(())
    }

    /// Consumes the builder and returns the configured [`SocketCapabilities`].
    pub fn finish(self) -> SocketCapabilities {
        self.cap
    }
}

// TODO(erittenhouse): use `dgram`'s SocketCapabilities when we migrate over
#[cfg_attr(not(target_os = "linux"), expect(rustdoc::broken_intra_doc_links))]
/// Indicators of sockopts configured for a socket.
///
/// On Linux, a socket can be configured using a [`SocketCapabilitiesBuilder`],
/// which returns the sockopts that were applied successfully. By default, all
/// options are assumed to be disabled (including on OSes besides Linux).
///
/// As a shortcut, you may call `apply_all_and_get_compatibility` to apply the
/// maxmimum set of capabilities supported by this crate. The result will
/// indicate which options were actually enabled.
#[derive(Debug, Default)]
pub struct SocketCapabilities {
    /// Indicates if the socket has `UDP_SEGMENT` enabled.
    pub(crate) has_gso: bool,

    /// Indicates if the socket has `SO_RXQ_OVFL` set.
    // NOTE: RX-side sockopts are `expect(dead_code)` because we check for
    // received cmsgs directly
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub(crate) check_udp_drop: bool,

    /// Indicates if the socket was configured with `SO_TXTIME`.
    pub(crate) has_txtime: bool,

    /// Indicates if the socket has `SO_TIMESTAMPNS` enabled.
    #[cfg_attr(
        not(all(target_os = "linux", feature = "perf-quic-listener-metrics")),
        expect(dead_code)
    )]
    pub(crate) has_rxtime: bool,

    /// Indicates if the socket has `UDP_GRO` enabled.
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub(crate) has_gro: bool,

    /// Indicates if the socket has `IP_PKTINFO` set.
    pub(crate) has_ippktinfo: bool,

    /// Indicates if the socket has `IP_RECVORIGDSTADDR` set.
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub(crate) has_iprecvorigdstaddr: bool,

    /// Indicates if the socket has `IPV6_RECVPKTINFO` set.
    pub(crate) has_ipv6pktinfo: bool,

    /// Indicates if the socket has `IPV6_RECVORIGDSTADDR` set.
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub(crate) has_ipv6recvorigdstaddr: bool,

    // Indicates if the socket has `IP_MTU_DISCOVER` set to `IP_PMTUDISC_PROBE`.
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub(crate) has_ip_mtu_discover_probe: bool,

    // Indicates if the socket has `IPV6_MTU_DISCOVER` set to
    // `IPV6_PMTUDISC_PROBE`.
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub(crate) has_ipv6_mtu_discover_probe: bool,

    /// Indicates if the socket is set to receive `SO_MARK` messages via
    /// `SO_RCVMARK`.
    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub(crate) has_mark: bool,
}

impl SocketCapabilities {
    /// Tries to enable all supported sockopts and returns indicators
    /// of which settings were successfully applied.
    #[cfg(target_os = "linux")]
    pub fn apply_all_and_get_compatibility<S>(socket: &S) -> Self
    where
        S: AsFd,
    {
        let mut b = SocketCapabilitiesBuilder::new(socket);
        let _ = b.gso();
        let _ = b.check_udp_drop();
        let _ = b.txtime();
        #[cfg(feature = "perf-quic-listener-metrics")]
        let _ = b.rxtime();
        let _ = b.gro();
        let _ = b.mark();

        // We can't determine if this is an IPv4 or IPv6 socket, so try setting
        // the relevant options for both
        let _ = b.ip_mtu_discover_probe();
        let _ = b.ipv6_mtu_discover_probe();
        if let Ok(true) = b.allows_nonlocal_source() {
            let _ = b.ipv4_pktinfo();
            let _ = b.ipv4_recvorigdstaddr();
            let _ = b.ipv6_pktinfo();
            let _ = b.ipv6_recvorigdstaddr();
        }
        b.finish()
    }
}
