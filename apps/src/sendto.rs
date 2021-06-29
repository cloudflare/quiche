// Copyright (C) 2021, Cloudflare, Inc.
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

use std::cmp;

use std::io;

/// For Linux, try to detect GSO is available.
#[cfg(target_os = "linux")]
pub fn detect_gso(socket: &mio::net::UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsRawFd;

    setsockopt(socket.as_raw_fd(), UdpGsoSegment, &(segment_size as i32)).is_ok()
}

/// For non-Linux, there is no GSO support.
#[cfg(not(target_os = "linux"))]
pub fn detect_gso(_socket: &mio::net::UdpSocket, _segment_size: usize) -> bool {
    false
}

/// Send packets using sendmsg() with GSO.
#[cfg(target_os = "linux")]
fn send_to_gso_pacing(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let iov = [IoSlice::new(buf)];
    let segment_size = segment_size as u16;
    let dst = SockaddrStorage::from(send_info.to);
    let sockfd = socket.as_raw_fd();

    // GSO option.
    let cmsg_gso = ControlMessage::UdpGsoSegments(&segment_size);
    let nanos_per_sec: u64 = 1_000_000_000;

    // Pacing option.
    let mut time_spec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        std::ptr::copy_nonoverlapping(
            &send_info.at as *const _ as *const libc::timespec,
            &mut time_spec,
            1,
        )
    };

    let send_time =
        time_spec.tv_sec as u64 * nanos_per_sec + time_spec.tv_nsec as u64;

    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    match sendmsg(
        sockfd,
        &iov,
        &[cmsg_gso, cmsg_txtime],
        MsgFlags::empty(),
        Some(&dst),
    ) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.into()),
    }
}

/// For non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn send_to_gso_pacing(
    _socket: &mio::net::UdpSocket, _buf: &[u8], _send_info: &quiche::SendInfo,
    _segment_size: usize,
) -> io::Result<usize> {
    panic!("send_to_gso() should not be called on non-linux platforms");
}

/// A wrapper function of send_to().
/// - when GSO and SO_TXTIME enabled, send a packet using send_to_gso().
/// Otherwise, send packet using socket.send_to().
pub fn send_to(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize, pacing: bool, enable_gso: bool,
) -> io::Result<usize> {
    if pacing && enable_gso {
        match send_to_gso_pacing(socket, buf, send_info, segment_size) {
            Ok(v) => {
                return Ok(v);
            },
            Err(e) => {
                return Err(e);
            },
        }
    }

    let mut off = 0;
    let mut left = buf.len();
    let mut written = 0;

    while left > 0 {
        let pkt_len = cmp::min(left, segment_size);

        match socket.send_to(&buf[off..off + pkt_len], send_info.to) {
            Ok(v) => {
                written += v;
            },
            Err(e) => return Err(e),
        }

        off += pkt_len;
        left -= pkt_len;
    }

    Ok(written)
}
