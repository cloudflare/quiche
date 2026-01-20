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

//! Pooled buffers for zero-copy packet handling.
//!
//! tokio-quiche maintains multiple [`buffer_pool::Pool`] instances for the
//! lifetime of the program. Buffers from those pools are used for received
//! network packets and HTTP/3 data, which is passed directly to users of the
//! crate. Outbound HTTP/3 data (like a message body or a datagram) is provided
//! by users in the same format.
//!
//! [`BufFactory`] provides access to the crate's pools to create outbound
//! buffers, but users can also use their own custom [`buffer_pool::Pool`]s.
//! There are two types of built-in pools:
//! - The generic buffer pool with very large buffers, which is used for stream
//!   data such as HTTP bodies.
//! - The datagram pool, which retains buffers the size of a single UDP packet.

use buffer_pool::ConsumeBuffer;
use buffer_pool::Pool;
use buffer_pool::Pooled;
use datagram_socket::MAX_DATAGRAM_SIZE;

const POOL_SHARDS: usize = 8;
const POOL_SIZE: usize = 16 * 1024;
const DATAGRAM_POOL_SIZE: usize = 64 * 1024;

const TINY_BUF_SIZE: usize = 64;
const SMALL_BUF_SIZE: usize = 1024;
const MEDIUM_BUF_SIZE: usize = 4096;
const MAX_POOL_BUF_SIZE: usize = 64 * 1024;

type BufPool = Pool<POOL_SHARDS, ConsumeBuffer>;

static TINY_POOL: BufPool =
    BufPool::new(TINY_BUF_SIZE, TINY_BUF_SIZE, "tiny_pool");
static SMALL_POOL: BufPool =
    BufPool::new(SMALL_BUF_SIZE, SMALL_BUF_SIZE, "small_pool");
static MEDIUM_POOL: BufPool =
    BufPool::new(MEDIUM_BUF_SIZE, MEDIUM_BUF_SIZE, "medium_pool");

/// A generic buffer pool used to pass data around without copying.
static BUF_POOL: BufPool =
    BufPool::new(POOL_SIZE, MAX_POOL_BUF_SIZE, "generic_pool");

/// A datagram pool shared for both UDP streams, and incoming QUIC packets.
static DATAGRAM_POOL: BufPool =
    BufPool::new(DATAGRAM_POOL_SIZE, MAX_DATAGRAM_SIZE, "datagram_pool");

/// A pooled byte buffer to pass stream data around without copying.
pub type PooledBuf = Pooled<ConsumeBuffer>;
/// A pooled byte buffer to pass datagrams around without copying.
///
/// The buffer type records a head offset, which allows cheaply inserting
/// data at the front given sufficient capacity.
pub type PooledDgram = Pooled<ConsumeBuffer>;

#[cfg(feature = "zero-copy")]
pub use self::zero_copy::QuicheBuf;

/// Prefix size to reserve in a [`PooledDgram`]. Up to 8 bytes for the flow ID
/// plus 1 byte for the flow context.
const DGRAM_PREFIX: usize = 8 + 1;

/// Handle to the crate's static buffer pools.
#[derive(Default, Clone, Debug)]
pub struct BufFactory;

impl BufFactory {
    /// The maximum size of the buffers in the generic pool. Larger buffers
    /// will shrink to this size before returning to the pool.
    pub const MAX_BUF_SIZE: usize = MAX_POOL_BUF_SIZE;
    /// The maximum size of the buffers in the datagram pool.
    pub const MAX_DGRAM_SIZE: usize = MAX_DATAGRAM_SIZE;

    /// Creates an empty [`PooledBuf`] which is not taken from the pool. When
    /// dropped, it may be assigned to the generic pool if no longer empty.
    pub fn get_empty_buf() -> PooledBuf {
        BUF_POOL.get_empty()
    }

    /// Creates an empty [`PooledDgram`] which is not taken from the pool. When
    /// dropped, it may be assigned to the datagram pool if no longer empty.
    pub fn get_empty_datagram() -> PooledDgram {
        DATAGRAM_POOL.get_empty()
    }

    /// Fetches a `MAX_BUF_SIZE` sized [`PooledBuf`] from the generic pool.
    pub fn get_max_buf() -> PooledBuf {
        BUF_POOL.get_with(|d| d.expand(MAX_POOL_BUF_SIZE))
    }

    /// Fetches a `MAX_DATAGRAM_SIZE` sized [`PooledDgram`] from the datagram
    /// pool.
    pub fn get_max_datagram() -> PooledDgram {
        DATAGRAM_POOL.get_with(|d| {
            d.expand(MAX_DATAGRAM_SIZE);
            // Make room to inject a prefix
            d.pop_front(DGRAM_PREFIX);
        })
    }

    /// Adds `dgram` to the datagram pool without copying it.
    pub fn dgram_from_vec(dgram: Vec<u8>) -> PooledDgram {
        DATAGRAM_POOL.from_owned(ConsumeBuffer::from_vec(dgram))
    }

    /// Fetches a [`PooledBuf`] from the generic pool and initializes it
    /// with the contents of `slice`.
    pub fn buf_from_slice(slice: &[u8]) -> PooledBuf {
        #[allow(clippy::match_overlapping_arm)]
        match slice.len() {
            0 => TINY_POOL.get_empty(),
            ..=TINY_BUF_SIZE => TINY_POOL.with_slice(slice),
            ..=SMALL_BUF_SIZE => SMALL_POOL.with_slice(slice),
            ..=MEDIUM_BUF_SIZE => MEDIUM_POOL.with_slice(slice),
            _ => BUF_POOL.with_slice(slice),
        }
    }

    /// Fetches a [`PooledDgram`] from the datagram pool and initializes it
    /// with the contents of `slice`.
    pub fn dgram_from_slice(slice: &[u8]) -> PooledDgram {
        let mut dgram = Self::get_max_datagram();
        dgram.truncate(0);
        dgram.extend(slice);
        dgram
    }
}

#[cfg(feature = "zero-copy")]
mod zero_copy {
    use super::PooledBuf;
    use quiche::BufSplit;

    /// A pooled, splittable byte buffer for zero-copy [`quiche`] calls.
    #[derive(Clone, Debug)]
    pub struct QuicheBuf {
        inner: triomphe::Arc<PooledBuf>,
        start: usize,
        end: usize,
    }

    impl QuicheBuf {
        pub(crate) fn new(inner: PooledBuf) -> Self {
            QuicheBuf {
                start: 0,
                end: inner.len(),
                inner: triomphe::Arc::new(inner),
            }
        }
    }

    impl AsRef<[u8]> for QuicheBuf {
        fn as_ref(&self) -> &[u8] {
            &self.inner[self.start..self.end]
        }
    }

    impl BufSplit for QuicheBuf {
        fn split_at(&mut self, at: usize) -> Self {
            assert!(self.start + at <= self.end);

            let split = QuicheBuf {
                inner: self.inner.clone(),
                start: self.start + at,
                end: self.end,
            };

            self.end = self.start + at;

            split
        }

        fn try_add_prefix(&mut self, prefix: &[u8]) -> bool {
            if self.start != 0 {
                return false;
            }

            if let Some(unique) = triomphe::Arc::get_mut(&mut self.inner) {
                if unique.add_prefix(prefix) {
                    self.end += prefix.len();
                    return true;
                }
            }

            false
        }
    }

    impl quiche::BufFactory for super::BufFactory {
        type Buf = QuicheBuf;

        fn buf_from_slice(buf: &[u8]) -> Self::Buf {
            QuicheBuf::new(Self::buf_from_slice(buf))
        }
    }
}
