// Copyright (C) 2026, Cloudflare, Inc.
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

//! UDP receive offload (URO) on Windows.
//!
//! A socket with `UDP_RECV_MAX_COALESCED_SIZE` set, as
//! [`SocketCapabilities::apply_all_and_get_compatibility`](crate::socket::SocketCapabilities::apply_all_and_get_compatibility)
//! sets it, lets Windows merge consecutive datagrams of a flow into one
//! receive. The size of the merged datagrams arrives in a `UDP_COALESCED_INFO`
//! control message, which only `WSARecvMsg` returns.
//!
//! Some machines coalesce without attaching that control message, turning a
//! train of datagrams into one payload that can't be split
//! (<https://github.com/quinn-rs/quinn/issues/2041>). A receive larger than
//! [`MAX_DATAGRAM_SIZE`] without a segment size that fits is treated as such
//! a train: it is dropped, and its socket opts out of URO. A single datagram
//! that large looks the same and is dropped too; it wouldn't fit a
//! [`MAX_DATAGRAM_SIZE`] receive buffer without URO either.
//!
//! A merged train that stays within [`MAX_DATAGRAM_SIZE`] can't be detected
//! this way. QUIC then parses merged long header packets as packets coalesced
//! into one datagram and fails to authenticate merged short header packets as
//! one packet, so such a train is lost rather than misread.

use crate::socket::windows::set_max_coalesced_size;
use crate::socket::windows::wsa_cmsg_align;
use crate::socket::windows::wsa_cmsg_len;
use datagram_socket::MAX_DATAGRAM_SIZE;
use foundations::telemetry::log;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::os::windows::io::AsRawSocket;
use std::ptr;
use tokio::net::UdpSocket;
use windows_sys::Win32::Networking::WinSock::getsockopt;
use windows_sys::Win32::Networking::WinSock::WSAGetLastError;
use windows_sys::Win32::Networking::WinSock::WSAIoctl;
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Networking::WinSock::AF_INET6;
use windows_sys::Win32::Networking::WinSock::CMSGHDR;
use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;
use windows_sys::Win32::Networking::WinSock::LPFN_WSARECVMSG;
use windows_sys::Win32::Networking::WinSock::LPWSAOVERLAPPED_COMPLETION_ROUTINE;
use windows_sys::Win32::Networking::WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER;
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6;
use windows_sys::Win32::Networking::WinSock::SOCKADDR_STORAGE;
use windows_sys::Win32::Networking::WinSock::SOCKET;
use windows_sys::Win32::Networking::WinSock::SOCKET_ERROR;
use windows_sys::Win32::Networking::WinSock::UDP_COALESCED_INFO;
use windows_sys::Win32::Networking::WinSock::UDP_RECV_MAX_COALESCED_SIZE;
use windows_sys::Win32::Networking::WinSock::WSABUF;
use windows_sys::Win32::Networking::WinSock::WSAID_WSARECVMSG;
use windows_sys::Win32::Networking::WinSock::WSAMSG;
use windows_sys::Win32::System::IO::OVERLAPPED;

/// Room for `UDP_COALESCED_INFO` plus packet info control messages the
/// application may have enabled on the socket.
const CONTROL_LEN: usize = 128;

/// The `WSARecvMsg` extension function.
type WsaRecvMsg = unsafe extern "system" fn(
    SOCKET,
    *mut WSAMSG,
    *mut u32,
    *mut OVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;

/// Receives from one socket through `WSARecvMsg`, which reports how a
/// coalesced receive splits into datagrams.
pub(super) struct Receiver {
    /// `WSARecvMsg` of the socket's Winsock provider.
    recv_msg: WsaRecvMsg,
    /// Whether the socket may still coalesce receives.
    coalescing: bool,
}

/// One completed receive.
pub(super) struct Received {
    /// Bytes written to the receive buffer.
    pub len: usize,
    /// The sender of the datagrams.
    pub peer: SocketAddr,
    /// Size of each datagram in the buffer, the last one possibly shorter, if
    /// the receive holds more than one.
    pub segment_size: Option<usize>,
}

/// How a receive splits into datagrams.
#[derive(Debug, PartialEq)]
enum Segments {
    /// The receive is a single datagram.
    One,
    /// The receive is a train of datagrams of this size; the last may be
    /// shorter.
    Split(usize),
    /// The receive is larger than any QUIC datagram: a train that coalescing
    /// failed to describe, or a single oversized datagram.
    Oversized,
}

impl Receiver {
    /// Returns a receiver for `socket`, or `None` if the socket's provider
    /// doesn't offer `WSARecvMsg`.
    pub(super) fn new(socket: &UdpSocket) -> Option<Self> {
        Some(Self {
            recv_msg: get_wsa_recv_msg_fn(socket)?,
            coalescing: max_coalesced_size(socket).is_ok_and(|size| size > 0),
        })
    }

    /// Receives one datagram, or one coalesced train of datagrams, into `buf`.
    ///
    /// A receive larger than any QUIC datagram is dropped with an
    /// [`io::ErrorKind::InvalidData`] error, and the socket opts out of URO.
    pub(super) fn recv(
        &mut self, socket: &UdpSocket, buf: &mut [u8],
    ) -> io::Result<Received> {
        // SAFETY: all-zero bytes are a valid `SOCKADDR_STORAGE`.
        let mut peer: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
        let mut control = [0u8; CONTROL_LEN];
        let mut data = WSABUF {
            len: u32::try_from(buf.len()).unwrap_or(u32::MAX),
            buf: buf.as_mut_ptr(),
        };
        let mut msg = WSAMSG {
            name: ptr::from_mut(&mut peer).cast(),
            namelen: size_of::<SOCKADDR_STORAGE>() as i32,
            lpBuffers: &mut data,
            dwBufferCount: 1,
            Control: WSABUF {
                len: CONTROL_LEN as u32,
                buf: control.as_mut_ptr(),
            },
            dwFlags: 0,
        };
        let mut len = 0;
        // SAFETY: `recv_msg` is the `WSARecvMsg` of `socket`'s provider. Every
        // pointer in `msg` refers to a live local or to `buf`, each valid for
        // the length given, and the call is synchronous.
        let rc = unsafe {
            (self.recv_msg)(
                socket.as_raw_socket() as SOCKET,
                &mut msg,
                &mut len,
                ptr::null_mut(),
                None,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(last_error());
        }

        let len = len as usize;
        let control_len = (msg.Control.len as usize).min(CONTROL_LEN);
        let reported = coalesced_segment_size(&control[..control_len]);
        let segment_size = match segments(len, reported) {
            Segments::One => None,
            Segments::Split(segment_size) => Some(segment_size),
            Segments::Oversized => {
                if self.coalescing {
                    self.coalescing = false;
                    let opt_out = set_max_coalesced_size(
                        socket.as_raw_socket() as SOCKET,
                        0,
                    );
                    log::warn!(
                        "Disabling UDP receive offload after a receive larger than MAX_DATAGRAM_SIZE";
                        "len" => len, "segment_size" => ?reported,
                        "opt_out" => ?opt_out
                    );
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "receive larger than MAX_DATAGRAM_SIZE",
                ));
            },
        };
        let peer = socket_addr(&peer).ok_or(io::ErrorKind::InvalidData)?;

        Ok(Received {
            len,
            peer,
            segment_size,
        })
    }
}

/// Returns `WSARecvMsg` of `socket`'s Winsock provider, or `None` if the
/// provider doesn't offer it. The pointer is only valid for that provider's
/// sockets.
fn get_wsa_recv_msg_fn(socket: &UdpSocket) -> Option<WsaRecvMsg> {
    let mut func: LPFN_WSARECVMSG = None;
    let mut returned = 0;
    // SAFETY: the input and output buffers are valid for the sizes passed and
    // the call is synchronous.
    let rc = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            ptr::from_ref(&WSAID_WSARECVMSG).cast(),
            size_of_val(&WSAID_WSARECVMSG) as u32,
            ptr::from_mut(&mut func).cast(),
            size_of::<LPFN_WSARECVMSG>() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        return None;
    }

    func
}

fn max_coalesced_size(socket: &UdpSocket) -> io::Result<u32> {
    let mut size = 0u32;
    let mut len = size_of::<u32>() as i32;
    // SAFETY: `size` and `len` are live locals describing a 4-byte buffer.
    let rc = unsafe {
        getsockopt(
            socket.as_raw_socket() as SOCKET,
            IPPROTO_UDP,
            UDP_RECV_MAX_COALESCED_SIZE,
            ptr::from_mut(&mut size).cast(),
            &mut len,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(last_error());
    }

    Ok(size)
}

fn last_error() -> io::Error {
    // SAFETY: no preconditions.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

/// Splits a receive of `len` bytes whose `UDP_COALESCED_INFO` reported
/// `segment_size`. A zero segment size carries no information.
fn segments(len: usize, segment_size: Option<u32>) -> Segments {
    let segment_size = match segment_size {
        Some(size @ 1..) => size as usize,
        _ => len,
    };

    if segment_size > MAX_DATAGRAM_SIZE {
        Segments::Oversized
    } else if segment_size < len {
        Segments::Split(segment_size)
    } else {
        Segments::One
    }
}

/// Returns the segment size of the `UDP_COALESCED_INFO` message in `control`,
/// the control data `WSARecvMsg` returned.
fn coalesced_segment_size(mut control: &[u8]) -> Option<u32> {
    while control.len() >= size_of::<CMSGHDR>() {
        // SAFETY: `control` holds at least a header's worth of bytes.
        let header =
            unsafe { ptr::read_unaligned(control.as_ptr().cast::<CMSGHDR>()) };
        let message = control
            .get(..header.cmsg_len)
            .filter(|message| message.len() >= size_of::<CMSGHDR>())?;

        if header.cmsg_level == IPPROTO_UDP &&
            header.cmsg_type == UDP_COALESCED_INFO as i32
        {
            let data = message.get(wsa_cmsg_len(0)..)?;
            return Some(u32::from_ne_bytes(*data.first_chunk()?));
        }

        control = control
            .get(wsa_cmsg_align(header.cmsg_len)..)
            .unwrap_or_default();
    }

    None
}

fn socket_addr(storage: &SOCKADDR_STORAGE) -> Option<SocketAddr> {
    match storage.ss_family {
        AF_INET => {
            // SAFETY: `SOCKADDR_STORAGE` is at least as large and as aligned as
            // `SOCKADDR_IN`, and both hold only integers.
            let addr = unsafe { &*ptr::from_ref(storage).cast::<SOCKADDR_IN>() };
            // SAFETY: every variant of the address union is a plain integer.
            let ip = unsafe { addr.sin_addr.S_un.S_addr }.to_ne_bytes();

            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(ip),
                u16::from_be(addr.sin_port),
            )))
        },
        AF_INET6 => {
            // SAFETY: `SOCKADDR_STORAGE` is at least as large and as aligned as
            // `SOCKADDR_IN6`, and both hold only integers.
            let addr = unsafe { &*ptr::from_ref(storage).cast::<SOCKADDR_IN6>() };
            // SAFETY: every variant of these unions is plain integers.
            let (ip, scope_id) =
                unsafe { (addr.sin6_addr.u.Byte, addr.Anonymous.sin6_scope_id) };

            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                scope_id,
            )))
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::InboundPacketRouter;
    use super::super::InitialPacketHandler;
    use super::super::NewConnection;
    use super::*;

    use crate::metrics::DefaultMetrics;
    use crate::quic::connection::Incoming;
    use crate::settings::Config;
    use crate::socket::windows::wsa_cmsg_space;
    use crate::socket::SocketCapabilities;
    use crate::ConnectionParams;

    use quiche::Header;
    use std::sync::Arc;
    use std::time::Duration;
    use windows_sys::Win32::Networking::WinSock::IPPROTO_IP;
    use windows_sys::Win32::Networking::WinSock::IP_PKTINFO;

    type TestRouter = InboundPacketRouter<
        UdpSocket,
        Arc<UdpSocket>,
        DefaultMetrics,
        NoopInitialHandler,
    >;

    struct NoopInitialHandler;
    impl InitialPacketHandler for NoopInitialHandler {
        fn handle_initials(
            &mut self, _incoming: Incoming, _hdr: Header<'static>,
            _quiche_config: &mut quiche::Config,
        ) -> io::Result<Option<NewConnection>> {
            Ok(None)
        }
    }

    #[rstest::rstest]
    #[case::datagram(1200, None, Segments::One)]
    #[case::largest_datagram(MAX_DATAGRAM_SIZE, None, Segments::One)]
    #[case::reported_as_one(1200, Some(1200), Segments::One)]
    #[case::zero_segment_size(1200, Some(0), Segments::One)]
    #[case::train(3000, Some(1200), Segments::Split(1200))]
    #[case::oversized_datagram(MAX_DATAGRAM_SIZE + 1, None, Segments::Oversized)]
    #[case::oversized_segment(4000, Some(2000), Segments::Oversized)]
    #[case::oversized_zero_segment_size(3000, Some(0), Segments::Oversized)]
    fn splits_receives(
        #[case] len: usize, #[case] segment_size: Option<u32>,
        #[case] expected: Segments,
    ) {
        assert_eq!(segments(len, segment_size), expected);
    }

    #[test]
    fn finds_coalesced_info() {
        let coalesced = cmsg(IPPROTO_UDP, UDP_COALESCED_INFO as i32, 1200);
        let pktinfo = cmsg(IPPROTO_IP, IP_PKTINFO, 7);

        assert_eq!(coalesced_segment_size(&coalesced), Some(1200));
        assert_eq!(
            coalesced_segment_size(&[pktinfo.as_slice(), &coalesced].concat()),
            Some(1200)
        );
        assert_eq!(coalesced_segment_size(&pktinfo), None);
        assert_eq!(coalesced_segment_size(&[]), None);
        assert_eq!(
            coalesced_segment_size(&coalesced[..size_of::<CMSGHDR>() + 2]),
            None
        );
    }

    /// Ordinary datagrams pass through URO sockets, connected or not,
    /// unchanged. One larger than any QUIC datagram is dropped and turns URO
    /// off for its socket only.
    #[tokio::test]
    async fn router_receives_with_uro() {
        let v4_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v6_peer = UdpSocket::bind("[::1]:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(v4_peer.local_addr().unwrap()).await.unwrap();

        let mut v4 = router(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut v6 = router(UdpSocket::bind("[::1]:0").await.unwrap());
        let mut client = router(client);

        for (router, sender) in [
            (&mut v4, &v4_peer),
            (&mut v6, &v6_peer),
            (&mut client, &v4_peer),
        ] {
            assert_ne!(coalesced_size(router), 0);
            for len in [1, 1200, MAX_DATAGRAM_SIZE] {
                let payload = vec![len as u8; len];
                sender.send_to(&payload, router.local_addr).await.unwrap();

                let packet = recv(router).await.unwrap();
                assert_eq!(packet.buf, payload);
                assert_eq!(packet.src_addr, sender.local_addr().unwrap());
                assert_eq!(packet.gro, None);
            }
        }

        let oversized = [0; MAX_DATAGRAM_SIZE + 1];
        v4_peer.send_to(&oversized, v4.local_addr).await.unwrap();
        v4_peer.send_to(&[1; 100], v4.local_addr).await.unwrap();

        let dropped = recv(&mut v4).await.unwrap_err();
        assert_eq!(dropped.kind(), io::ErrorKind::InvalidData);
        assert_eq!(recv(&mut v4).await.unwrap().buf, [1; 100]);
        assert_eq!(coalesced_size(&v4), 0);
        assert_ne!(coalesced_size(&v6), 0);
        assert_ne!(coalesced_size(&client), 0);
        let later = router(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        assert_ne!(coalesced_size(&later), 0);
    }

    fn router(socket: UdpSocket) -> TestRouter {
        let capabilities =
            SocketCapabilities::apply_all_and_get_compatibility(&socket);
        let socket = Arc::new(socket);
        let local_addr = socket.local_addr().unwrap();
        let config =
            Config::new(&ConnectionParams::default(), capabilities).unwrap();

        InboundPacketRouter::new(
            config,
            Arc::clone(&socket),
            socket,
            local_addr,
            NoopInitialHandler,
            DefaultMetrics,
        )
        .0
    }

    async fn recv(
        router: &mut TestRouter,
    ) -> io::Result<super::super::PollRecvData> {
        tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| router.poll_recv_and_rx_time(cx)),
        )
        .await
        .expect("timed out receiving")
    }

    fn coalesced_size(router: &TestRouter) -> u32 {
        max_coalesced_size(&router.socket_rx).expect("getsockopt failed")
    }

    /// A control message carrying the 4-byte `value`, padded like Windows
    /// pads it.
    fn cmsg(level: i32, ty: i32, value: u32) -> Vec<u8> {
        let header = CMSGHDR {
            cmsg_len: wsa_cmsg_len(size_of::<u32>()),
            cmsg_level: level,
            cmsg_type: ty,
        };
        let mut message = vec![0; wsa_cmsg_space(size_of::<u32>())];
        // SAFETY: `message` is longer than a header.
        unsafe {
            ptr::write_unaligned(message.as_mut_ptr().cast(), header);
        }
        message[wsa_cmsg_len(0)..header.cmsg_len]
            .copy_from_slice(&value.to_ne_bytes());
        message
    }
}
