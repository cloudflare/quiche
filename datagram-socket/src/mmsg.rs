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

const MAX_MMSG: usize = 16;

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

pub fn sendmmsg(fd: BorrowedFd, bufs: &[ReadBuf<'_>]) -> io::Result<usize> {
    let mut msgvec: SmallVec<[libc::mmsghdr; MAX_MMSG]> = SmallVec::new();
    let mut slices: SmallVec<[IoSlice; MAX_MMSG]> = SmallVec::new();

    let mut ret = 0;

    for bufs in bufs.chunks(MAX_MMSG) {
        msgvec.clear();
        slices.clear();

        for buf in bufs.iter() {
            slices.push(IoSlice::new(buf.filled()));

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

        let result = unsafe {
            libc::sendmmsg(
                fd.as_raw_fd(),
                msgvec.as_mut_ptr(),
                msgvec.len() as _,
                0,
            )
        };

        if result == -1 {
            break;
        }

        ret += result as usize;

        if (result as usize) < MAX_MMSG {
            break;
        }
    }

    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret)
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

    use tokio::io::ReadBuf;
    use tokio::net::UnixDatagram;

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
    async fn sendmmsg() -> io::Result<()> {
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
}
