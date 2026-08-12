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

use std::io::IoSlice;
use std::io::{
    self,
};
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

use smallvec::SmallVec;
use tokio::io::ReadBuf;

/// Maximum number of messages passed to a single `sendmmsg(2)` or
/// `recvmmsg(2)` call.
pub const MAX_MMSG: usize = 16;

pub fn recvmmsg(fd: BorrowedFd, bufs: &mut [ReadBuf<'_>]) -> io::Result<usize> {
    let mut msgvec: SmallVec<[libc::mmsghdr; MAX_MMSG]> = SmallVec::new();
    let mut slices: SmallVec<[IoSlice; MAX_MMSG]> = SmallVec::new();

    let mut ret = 0;

    for bufs in bufs.chunks_mut(MAX_MMSG) {
        msgvec.clear();
        slices.clear();

        for buf in bufs.iter_mut() {
            // Safety: will not read the maybe uninitialized bytes.
            let b = unsafe {
                &mut *(buf.unfilled_mut() as *mut [std::mem::MaybeUninit<u8>]
                    as *mut [u8])
            };

            slices.push(IoSlice::new(b));

            msgvec.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: slices.last_mut().unwrap() as *mut _ as *mut _,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: buf.capacity().try_into().unwrap(),
            });
        }

        // SAFETY: `slices` and `msgvec` are `SmallVec`s with inline capacity
        // `MAX_MMSG`, and each chunk has at most `MAX_MMSG` elements, so the
        // pushes above cannot trigger a reallocation that would invalidate
        // the pointers into `slices` taken by `msg_iov` above. Neither
        // vector is modified before the syscall returns, and `fd` remains
        // valid for the duration of the call.
        let result = unsafe {
            libc::recvmmsg(
                fd.as_raw_fd(),
                msgvec.as_mut_ptr(),
                msgvec.len() as _,
                0,
                std::ptr::null_mut(),
            )
        };

        if result == -1 {
            break;
        }

        for i in 0..result as usize {
            let filled = msgvec[i].msg_len as usize;
            unsafe { bufs[i].assume_init(filled) };
            bufs[i].advance(filled);
            ret += 1;
        }

        if (result as usize) < MAX_MMSG {
            break;
        }
    }

    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret)
}

/// Sends multiple datagrams with a single system call where possible.
///
/// The returned value is the number of datagrams sent.
pub fn sendmmsg(fd: BorrowedFd, bufs: &[ReadBuf<'_>]) -> io::Result<usize> {
    sendmmsg_impl(fd, bufs, None)
}

/// Sends multiple datagrams, appending the same suffix to every datagram.
///
/// The returned value is the number of datagrams sent. The suffix is framing
/// supplied on the caller's behalf and does not affect that count.
pub fn sendmmsg_with_suffix(
    fd: BorrowedFd, bufs: &[ReadBuf<'_>], suffix: &[u8],
) -> io::Result<usize> {
    sendmmsg_impl(fd, bufs, Some(suffix))
}

fn sendmmsg_impl(
    fd: BorrowedFd, bufs: &[ReadBuf<'_>], suffix: Option<&[u8]>,
) -> io::Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }

    let mut msgvec: SmallVec<[libc::mmsghdr; MAX_MMSG]> = SmallVec::new();
    let mut iovecs: SmallVec<[libc::iovec; 2 * MAX_MMSG]> = SmallVec::new();

    let mut ret = 0;

    for bufs in bufs.chunks(MAX_MMSG) {
        msgvec.clear();
        iovecs.clear();

        for buf in bufs {
            iovecs.push(iovec(buf.filled()));

            if let Some(suffix) = suffix {
                iovecs.push(iovec(suffix));
            }
        }

        // Populate all iovecs before taking pointers into the vector. This
        // ensures none of the pointers can be invalidated by a reallocation.
        let iovecs_per_message = if suffix.is_some() { 2 } else { 1 };
        for message_iovecs in iovecs.chunks_exact_mut(iovecs_per_message) {
            msgvec.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: message_iovecs.as_mut_ptr(),
                    msg_iovlen: iovecs_per_message,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                // Output field populated by the kernel.
                msg_len: 0,
            });
        }

        // SAFETY: `iovecs` was fully populated before the pointers in
        // `msgvec` were created, and neither vector is modified before the
        // syscall returns. Each header points to one or two live iovecs, and
        // `fd` remains valid for the duration of the call.
        let result = unsafe {
            libc::sendmmsg(
                fd.as_raw_fd(),
                msgvec.as_mut_ptr(),
                msgvec.len() as _,
                0,
            )
        };

        if result == -1 {
            let err = io::Error::last_os_error();

            if ret == 0 {
                return Err(err);
            }

            break;
        }

        ret += result as usize;

        if (result as usize) < bufs.len() {
            break;
        }
    }

    Ok(ret)
}

fn iovec(buf: &[u8]) -> libc::iovec {
    libc::iovec {
        // `sendmmsg(2)` does not mutate the memory described by an iovec, but
        // the C API represents the pointer as mutable.
        iov_base: buf.as_ptr().cast_mut().cast(),
        iov_len: buf.len(),
    }
}

#[macro_export]
macro_rules! poll_recvmmsg {
    ($self: expr, $cx: ident, $bufs: ident) => {
        loop {
            match $self.poll_recv_ready($cx)? {
                Poll::Ready(()) => {
                    match $self.try_io(tokio::io::Interest::READABLE, || {
                        $crate::mmsg::recvmmsg($self.as_fd(), $bufs)
                    }) {
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}  // Have to poll for recv ready
                        res => break Poll::Ready(res),
                    }
                }
                Poll::Pending => break Poll::Pending,
            }
        }
    };
}

#[macro_export]
macro_rules! poll_sendmmsg {
    ($self: expr, $cx: ident, $bufs: ident) => {
        loop {
            match $self.poll_send_ready($cx)? {
                Poll::Ready(()) => {
                    match $self.try_io(tokio::io::Interest::WRITABLE, || {
                        $crate::mmsg::sendmmsg($self.as_fd(), $bufs)
                    }) {
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {} // Have to poll for send ready
                        res => break Poll::Ready(res),
                    }
                }
                Poll::Pending => break Poll::Pending,
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::fd::AsFd;

    use tokio::io::ReadBuf;
    use tokio::net::UnixDatagram;

    use super::sendmmsg;
    use super::sendmmsg_with_suffix;
    use super::MAX_MMSG;
    use crate::DatagramSocketRecvExt;
    use crate::DatagramSocketSendExt;

    #[tokio::test]
    async fn recvmmsg() -> io::Result<()> {
        let (s, mut r) = UnixDatagram::pair()?;
        let mut bufs = [[0u8; 128]; 128];

        for i in 0..5 {
            s.send(&[i; 128]).await?;
        }

        let mut rbufs: Vec<_> =
            bufs.iter_mut().map(|s| ReadBuf::new(&mut s[..])).collect();
        assert_eq!(r.recv_many(&mut rbufs).await?, 5);

        for (i, buf) in rbufs[0..5].iter().enumerate() {
            assert_eq!(buf.filled(), &[i as u8; 128]);
        }

        for i in 0..92 {
            s.send(&[i; 128]).await?;
        }

        let mut rbufs: Vec<_> =
            bufs.iter_mut().map(|s| ReadBuf::new(&mut s[..])).collect();
        assert_eq!(r.recv_many(&mut rbufs).await?, 92);

        for (i, buf) in rbufs[0..92].iter().enumerate() {
            assert_eq!(buf.filled(), &[i as u8; 128]);
        }

        Ok(())
    }

    #[tokio::test]
    async fn send_many() -> io::Result<()> {
        let (s, r) = UnixDatagram::pair()?;
        let mut bufs: [_; 128] = std::array::from_fn(|i| [i as u8; 128]);

        let wbufs: Vec<_> = bufs
            .iter_mut()
            .map(|s| {
                let mut b = ReadBuf::new(&mut s[..]);
                b.set_filled(128);
                b
            })
            .collect();

        assert_eq!(s.send_many(&wbufs[..5]).await?, 5);

        let mut rbuf = [0u8; 128];

        for i in 0..5 {
            assert_eq!(r.recv(&mut rbuf).await?, 128);
            assert_eq!(rbuf, [i as u8; 128]);
        }

        Ok(())
    }

    #[tokio::test]
    async fn sendmmsg_with_suffix_appends_to_every_datagram() -> io::Result<()> {
        let (s, r) = UnixDatagram::pair()?;
        let suffix = b"-suffix";
        let mut payloads: Vec<Vec<u8>> =
            (0..MAX_MMSG + 4).map(|i| vec![i as u8; i]).collect();
        let bufs: Vec<_> = payloads
            .iter_mut()
            .map(|payload| {
                let len = payload.len();
                let mut buf = ReadBuf::new(payload);
                buf.set_filled(len);
                buf
            })
            .collect();

        assert_eq!(
            sendmmsg_with_suffix(s.as_fd(), &bufs, suffix)?,
            payloads.len()
        );

        let mut received = vec![0; MAX_MMSG + suffix.len() + 4];
        for expected in &payloads {
            let received_len = r.recv(&mut received).await?;
            assert_eq!(
                &received[..received_len],
                [expected.as_slice(), suffix].concat()
            );
        }

        Ok(())
    }

    #[test]
    fn empty_send_batches_are_noops() -> io::Result<()> {
        let (s, _r) = std::os::unix::net::UnixDatagram::pair()?;

        assert_eq!(sendmmsg(s.as_fd(), &[])?, 0);
        assert_eq!(sendmmsg_with_suffix(s.as_fd(), &[], b"suffix")?, 0);

        Ok(())
    }

    #[test]
    fn sendmmsg_with_suffix_reports_an_error_without_progress() -> io::Result<()>
    {
        let (s, r) = std::os::unix::net::UnixDatagram::pair()?;
        drop(r);

        let mut payload = *b"payload";
        let payload_len = payload.len();
        let mut buf = ReadBuf::new(&mut payload);
        buf.set_filled(payload_len);

        assert!(sendmmsg_with_suffix(s.as_fd(), &[buf], b"suffix").is_err());

        Ok(())
    }
}
