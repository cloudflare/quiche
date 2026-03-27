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

//! Buffers for zero-copy packet handling and for allowing copying into
//! uninitialized memory.

use bytes::Bytes;
use datagram_socket::DgramBuffer;

#[derive(Default, Clone, Debug)]
pub struct BufFactory;

impl BufFactory {
    /// Sized to hold two QUIC varints (max 8 bytes each).
    pub const DGRAM_HEADROOM: usize = 16;
    pub const MAX_BUF_SIZE: usize = 64 * 1024;

    /// Return a `DgramBuffer` with enough capacity for `MAX_DATAGRAM_SIZE`
    /// payload bytes and enough headroom for two QUIC varints.
    pub fn get_max_dgram_buf() -> DgramBuffer {
        DgramBuffer::with_capacity_and_headroom(
            datagram_socket::MAX_DATAGRAM_SIZE + BufFactory::DGRAM_HEADROOM,
            BufFactory::DGRAM_HEADROOM,
        )
    }
}

impl quiche::BufFactory for BufFactory {
    type Buf = Bytes;
    type DgramBuf = DgramBuffer;

    fn buf_from_slice(buf: &[u8]) -> Bytes {
        Bytes::copy_from_slice(buf)
    }

    fn dgram_buf_from_slice(buf: &[u8]) -> DgramBuffer {
        DgramBuffer::from_slice(buf)
    }
}
