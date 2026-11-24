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

//! Batched UDP sends on macOS.
//!
//! `sendmsg_x` sends several datagrams on a connected socket in one system
//! call. libSystem exports it, but the SDK declares neither it nor
//! `struct msghdr_x`; both come from XNU's `bsd/sys/socket_private.h`, so
//! the symbol is resolved at runtime.

use std::ffi::CStr;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::ptr;
use std::sync::OnceLock;

/// Most datagrams one [`send_batch`] call sends, as many as the IO worker
/// coalesces into one flush (`UDP_MAX_SEGMENT_COUNT`).
const MAX_SEND_BATCH: usize = 64;

/// `struct msghdr_x` from XNU's `bsd/sys/socket_private.h`.
#[repr(C)]
struct MsghdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    msg_datalen: usize,
}

impl MsghdrX {
    /// A header for one datagram in `iov`, with no address or ancillary
    /// data, which these calls don't support.
    fn for_iov(iov: &mut libc::iovec) -> Self {
        Self {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: iov,
            msg_iovlen: 1,
            msg_control: ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
            msg_datalen: 0,
        }
    }
}

type SendmsgX = unsafe extern "C" fn(
    libc::c_int,
    *const MsghdrX,
    libc::c_uint,
    libc::c_int,
) -> libc::ssize_t;

/// Whether this process can batch sends with [`send_batch`].
pub(crate) fn can_send_batches() -> bool {
    sendmsg_x().is_some()
}

/// Whether `socket` is connected to a peer.
pub(crate) fn is_connected(socket: BorrowedFd<'_>) -> bool {
    // SAFETY: an all-zero `sockaddr_storage` is valid.
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&addr) as libc::socklen_t;
    // SAFETY: `addr` and `len` describe a live buffer of `len` bytes.
    let rc = unsafe {
        libc::getpeername(
            socket.as_raw_fd(),
            ptr::from_mut(&mut addr).cast(),
            &mut len,
        )
    };
    rc == 0
}

/// Sends `buf` on the connected `socket` as datagrams of `segment_size`
/// bytes, the last of which may be shorter, with one `sendmsg_x` call.
///
/// # Returns
/// The number of datagrams sent. This is at most [`MAX_SEND_BATCH`], and
/// fewer when the kernel stops part way through the batch, for example
/// because the interface queue is full.
///
/// # Errors
/// [`io::ErrorKind::Unsupported`] if libSystem doesn't export `sendmsg_x`.
/// Otherwise the error `sendmsg_x` returned, after which some datagrams of
/// the batch may still have been sent.
pub(crate) fn send_batch(
    socket: BorrowedFd<'_>, buf: &[u8], segment_size: usize,
) -> io::Result<usize> {
    let Some(sendmsg_x) = sendmsg_x() else {
        return Err(io::ErrorKind::Unsupported.into());
    };

    let mut iovs = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }; MAX_SEND_BATCH];
    let mut count = 0;
    for (iov, dgram) in iovs.iter_mut().zip(buf.chunks(segment_size)) {
        iov.iov_base = dgram.as_ptr().cast_mut().cast();
        iov.iov_len = dgram.len();
        count += 1;
    }

    let hdrs: [MsghdrX; MAX_SEND_BATCH] =
        std::array::from_fn(|i| MsghdrX::for_iov(&mut iovs[i]));

    // SAFETY: the first `count` headers each point at one entry of `iovs`,
    // which points into `buf`. All outlive the call, and `sendmsg_x` only
    // reads through them.
    let sent = unsafe {
        sendmsg_x(socket.as_raw_fd(), hdrs.as_ptr(), count as libc::c_uint, 0)
    };
    if sent >= 0 {
        return Ok(sent as usize);
    }

    Err(io::Error::last_os_error())
}

/// Returns `sendmsg_x`, or `None` if libSystem doesn't export it.
fn sendmsg_x() -> Option<SendmsgX> {
    static SENDMSG_X: OnceLock<Option<SendmsgX>> = OnceLock::new();

    *SENDMSG_X.get_or_init(|| {
        // SAFETY: XNU's `sendmsg_x` has the signature `SendmsgX` declares.
        resolve(c"sendmsg_x").map(|sym| unsafe {
            mem::transmute::<*mut libc::c_void, SendmsgX>(sym)
        })
    })
}

/// Looks `name` up among the images loaded into the process.
fn resolve(name: &CStr) -> Option<*mut libc::c_void> {
    // SAFETY: `name` is NUL-terminated.
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!sym.is_null()).then_some(sym)
}
