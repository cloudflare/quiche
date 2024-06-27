pub mod socket_setup;
pub mod sync;
mod syscalls;
#[cfg(feature = "async")]
pub mod tokio;

use std::net::SocketAddr;
use std::time::Instant;
use std::time::SystemTime;

use libc::in6_pktinfo;
use libc::in_pktinfo;
use libc::sockaddr_in;
use libc::sockaddr_in6;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::MsgFlags;

/// Settings for handling control messages when sending data.
#[cfg(target_os = "linux")]
#[derive(Default, Copy, Clone)]
pub struct SendMsgSettings {
    /// Segment sized used in a UDP_SEGMENT control message
    pub segment_size: Option<u16>,
    /// Send time used in a TX_TIME control message
    pub tx_time: Option<Instant>,
    /// Destination socket address
    pub dst: Option<SocketAddr>,
    /// Packet info used in an IP_PKTINFO control message
    pub pkt_info: Option<IpPktInfo>,
}

/// Settings for handling control messages when receiving data.
#[cfg(target_os = "linux")]
pub struct RecvMsgSettings<'c> {
    /// If cmsgs should be stored when receiving a message. If set, cmsgs will
    /// be stored in the [`RecvData`]'s `cmsgs` field.
    pub store_cmsgs: bool,
    /// The vector where cmsgs will be stored, if store_cmsgs is set.
    ///
    /// It is the caller's responsibility to create and clear the vector. The
    /// `nix` crate recommends that the space be created with the
    /// [`cmsg_space`] macro.
    ///
    /// [`cmsg_space`]: https://docs.rs/nix/latest/nix/macro.cmsg_space.html
    pub cmsg_space: &'c mut Vec<u8>,
}

impl<'c> RecvMsgSettings<'c> {
    // Convenience to avoid forcing a specific version of nix
    pub fn new(store_cmsgs: bool, cmsg_space: &'c mut Vec<u8>) -> Self {
        Self {
            store_cmsgs,
            cmsg_space,
        }
    }
}

/// Output of a `recvmsg` call.
#[derive(Debug, Default)]
pub struct RecvData {
    /// The number of bytes returned by `recvmsg`.
    pub bytes: usize,
    /// The peer address for this message.
    pub peer_addr: Option<SocketAddr>,
    /// Metrics for this `recvmsg` call.
    ///
    /// If no valid metrics exist - for example, when the RXQOVFL sockopt is not
    /// set - this will be `None`.
    pub metrics: Option<RecvMetrics>,
    /// The `UDP_GRO_SEGMENTS` control message data from the result of
    /// `recvmsg`, if it exist.
    pub gro: Option<u16>,
    /// The `RX_TIME` control message data from the result of `recvmsg`, if it
    /// exists.
    pub rx_time: Option<SystemTime>,
    /// The original IP destination address for the message.
    ///
    /// This can be either an IPv4 or IPv6 address, depending on whether
    /// `IPV4_ORIGDSTADDR` or `IPV6_ORIGDSTADDR` was received.
    pub original_addr: Option<IpOrigDstAddr>,
    cmsgs: Vec<ControlMessageOwned>,
}

impl RecvData {
    pub fn new(
        peer_addr: Option<SocketAddr>, bytes: usize, cmsg_space_len: usize,
    ) -> Self {
        Self {
            peer_addr,
            bytes,
            metrics: None,
            gro: None,
            rx_time: None,
            original_addr: None,
            cmsgs: Vec::with_capacity(cmsg_space_len),
        }
    }

    /// A constructor which only sets the `bytes` field.
    pub fn with_bytes(bytes: usize) -> Self {
        Self {
            bytes,
            ..Default::default()
        }
    }

    /// Returns the list of cmsgs which were returned from calling `recvmsg`. If
    /// `recvmsg` was called with its [`RecvMsgCmsgSettings::store_cmsgs`]
    /// field set to to `false`, this will return an empty slice.
    pub fn cmsgs(&self) -> &[ControlMessageOwned] {
        &self.cmsgs
    }
}

/// Metrics for `recvmsg` calls.
#[derive(Debug, Default)]
pub struct RecvMetrics {
    /// The number of packets dropped between the last received packet and this
    /// one.
    ///
    /// See SO_RXQOVFL for more.
    pub udp_packets_dropped: u64,
}

#[derive(Debug)]
pub enum IpOrigDstAddr {
    V4(sockaddr_in),
    V6(sockaddr_in6),
}

#[derive(Copy, Clone, Debug)]
pub enum IpPktInfo {
    V4(in_pktinfo),
    V6(in6_pktinfo),
}

#[cfg(target_os = "linux")]
mod linux_imports {
    pub(super) use crate::syscalls::recv_msg;
    pub(super) use crate::syscalls::send_msg;
    pub(super) use crate::RecvData;
    pub(super) use crate::RecvMetrics;
    pub(super) use crate::RecvMsgSettings;
    pub(super) use crate::SendMsgSettings;
    pub(super) use nix::errno::Errno;
    pub(super) use nix::sys::socket::getsockopt;
    pub(super) use nix::sys::socket::recvmsg;
    pub(super) use nix::sys::socket::sendmsg;
    pub(super) use nix::sys::socket::setsockopt;
    pub(super) use nix::sys::socket::sockopt::ReceiveTimestampns;
    pub(super) use nix::sys::socket::sockopt::RxqOvfl;
    pub(super) use nix::sys::socket::sockopt::TxTime;
    pub(super) use nix::sys::socket::sockopt::UdpGroSegment;
    pub(super) use nix::sys::socket::sockopt::UdpGsoSegment;
    pub(super) use nix::sys::socket::AddressFamily;
    pub(super) use nix::sys::socket::ControlMessage;
    pub(super) use nix::sys::socket::ControlMessageOwned;
    pub(super) use nix::sys::socket::MsgFlags;
    pub(super) use nix::sys::socket::SetSockOpt;
    pub(super) use nix::sys::socket::SockaddrLike;
    pub(super) use nix::sys::socket::SockaddrStorage;
    pub(super) use smallvec::SmallVec;
    pub(super) use std::io::IoSlice;
    pub(super) use std::io::IoSliceMut;
    pub(super) use std::net::SocketAddrV4;
    pub(super) use std::net::SocketAddrV6;
    pub(super) use std::os::fd::AsRawFd;
}
