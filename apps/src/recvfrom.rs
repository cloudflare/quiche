// Copyright (C) 2022, Cloudflare, Inc.
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

use quiche::RecvInfo;
use std::io;
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
fn set_ecn_support(socket: &mio::net::UdpSocket) -> std::io::Result<()> {
    use crate::common::setsockopt;
    use libc::IPPROTO_IP;
    use libc::IPPROTO_IPV6;
    use libc::IPV6_RECVTCLASS;
    use libc::IP_RECVTOS;
    use std::os::unix::io::AsRawFd;

    let recv_ecn: u32 = 1;

    // Opportunistically set support on both address families.
    let res1 = unsafe {
        setsockopt(socket.as_raw_fd(), IPPROTO_IP, IP_RECVTOS, recv_ecn)
    };
    let res2 = unsafe {
        setsockopt(socket.as_raw_fd(), IPPROTO_IPV6, IPV6_RECVTCLASS, recv_ecn)
    };
    if res1.is_ok() {
        res1
    } else {
        res2
    }
}

#[cfg(not(target_os = "linux"))]
fn set_ecn_support(_socket: &mio::net::UdpSocket) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ecn not supported",
    ))
}

// The following is taken from https://github.com/mxinden/udp-socket,
// with some adaptations.

#[cfg(target_os = "linux")]
fn recvmsg(
    socket: &mio::net::UdpSocket, local_addr: SocketAddr, buf: &mut [u8],
) -> std::io::Result<(usize, RecvInfo)> {
    use std::io::IoSliceMut;
    use std::mem::MaybeUninit;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::net::SocketAddrV4;
    use std::net::SocketAddrV6;
    use std::os::unix::io::AsRawFd;

    use libc::CMSG_LEN;

    use crate::cmsg;
    use crate::common;

    let mut iov = IoSliceMut::new(buf);
    let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut ctrl = cmsg::Aligned(MaybeUninit::<
        [u8; (std::mem::size_of::<libc::in6_pktinfo>() as _)],
    >::uninit());
    let mut hdr = unsafe { std::mem::zeroed::<libc::msghdr>() };

    hdr.msg_name = name.as_mut_ptr() as _;
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = (&mut iov) as *mut IoSliceMut as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    hdr.msg_flags = 0;

    let read = common::macro_helper::syscall!(recvmsg(
        socket.as_raw_fd(),
        (&mut hdr) as *mut libc::msghdr,
        0
    ))?;

    let name = unsafe { name.assume_init() };
    let mut ecn_bits = 0;

    let cmsg_iter = unsafe { cmsg::Iter::new(&hdr) };
    for cmsg in cmsg_iter {
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            // FreeBSD uses IP_RECVTOS here, and we can be liberal because cmsgs
            // are opt-in.
            (libc::IPPROTO_IP, libc::IP_TOS) |
            (libc::IPPROTO_IP, libc::IP_RECVTOS) => unsafe {
                ecn_bits = cmsg::decode::<u8>(cmsg);
            },
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                ecn_bits = cmsg::decode::<libc::c_int>(cmsg) as u8;
            },
            _ => {},
        }
    }

    let source = match libc::c_int::from(name.ss_family) {
        libc::AF_INET => {
            let addr =
                unsafe { &*(&name as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(addr.sin_port);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        },
        libc::AF_INET6 => {
            let addr =
                unsafe { &*(&name as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            ))
        },
        _ => unreachable!(),
    };

    Ok((read as usize, RecvInfo {
        from: source,
        to: local_addr,
        ecn: ecn_bits,
    }))
}

#[cfg(not(target_os = "linux"))]
fn recvmsg(
    socket: &mio::net::UdpSocket, local_addr: SocketAddr, buf: &mut [u8],
) -> std::io::Result<(usize, RecvInfo)> {
    let (len, from) = socket.recv_from(buf)?;
    Ok((len, RecvInfo {
        from,
        to: local_addr,
        ecn: 0,
    }))
}

pub fn recv_from(
    socket: &mio::net::UdpSocket, local_addr: SocketAddr, buf: &mut [u8],
    enable_ecn: bool,
) -> io::Result<(usize, RecvInfo)> {
    if enable_ecn {
        set_ecn_support(socket).ok();
    }

    recvmsg(socket, local_addr, buf)
}
