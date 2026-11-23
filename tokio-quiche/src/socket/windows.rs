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

//! Winsock helpers shared by socket setup and the Windows send and receive
//! paths.
//!
//! The control message helpers mirror the `WSA_CMSG_*` macros from `ws2def.h`,
//! which `windows-sys` doesn't bind. `WSA_CMSG_NXTHDR` aligns to the header's
//! alignment and `WSA_CMSG_DATA` to `MAX_NATURAL_ALIGNMENT`, which are equal on
//! every Windows target, so one alignment serves both.

use std::io;
use std::mem;
use std::ptr;
use windows_sys::Win32::Networking::WinSock::setsockopt;
use windows_sys::Win32::Networking::WinSock::CMSGHDR;
use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;
use windows_sys::Win32::Networking::WinSock::SOCKET;
use windows_sys::Win32::Networking::WinSock::SOCKET_ERROR;
use windows_sys::Win32::Networking::WinSock::UDP_RECV_MAX_COALESCED_SIZE;

/// Rounds `len` up to the alignment of a control message header, like
/// `WSA_CMSGHDR_ALIGN`.
pub(crate) const fn wsa_cmsg_align(len: usize) -> usize {
    len.next_multiple_of(mem::align_of::<CMSGHDR>())
}

/// The `cmsg_len` of a control message carrying `data_len` bytes, like
/// `WSA_CMSG_LEN`.
pub(crate) const fn wsa_cmsg_len(data_len: usize) -> usize {
    wsa_cmsg_align(mem::size_of::<CMSGHDR>()) + data_len
}

/// The control buffer space a message carrying `data_len` bytes takes,
/// trailing padding included, like `WSA_CMSG_SPACE`.
pub(crate) const fn wsa_cmsg_space(data_len: usize) -> usize {
    wsa_cmsg_align(mem::size_of::<CMSGHDR>() + data_len)
}

/// Sets `UDP_RECV_MAX_COALESCED_SIZE`, the largest receive Windows may
/// coalesce datagrams into. Zero turns UDP receive offload (URO) off.
pub(crate) fn set_max_coalesced_size(
    socket: SOCKET, size: u32,
) -> io::Result<()> {
    // SAFETY: `size` is a DWORD that outlives the call.
    let rc = unsafe {
        setsockopt(
            socket,
            IPPROTO_UDP,
            UDP_RECV_MAX_COALESCED_SIZE,
            ptr::from_ref(&size).cast(),
            mem::size_of::<u32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
