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

mod buffer;
mod raw_pool_buf_io;

use std::collections::VecDeque;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use crossbeam::queue::SegQueue;

use foundations::telemetry::metrics::metrics;
use foundations::telemetry::metrics::Gauge;

pub use crate::buffer::*;
pub use crate::raw_pool_buf_io::*;

#[metrics]
pub mod buffer_pool {
    /// Number of objects available for reuse in the pool.
    pub fn pool_idle_count(name: &'static str) -> Gauge;
    /// Memory footprint of objects currently in the pool.
    pub fn pool_idle_bytes(name: &'static str) -> Gauge;
    /// Number of objects currently active and in-use.
    pub fn pool_active_count(name: &'static str) -> Gauge;
    /// Total number of bytes allocated across all `ConsumeBuffer` objects.
    ///
    /// We're not able to track this with better granularity because
    /// the ConsumeBuffers may be resized, and they don't know their pools.
    pub fn consume_buffer_total_bytes() -> Gauge;
}

/// A sharded pool of elements.
#[derive(Debug)]
pub struct Pool<const S: usize, T: 'static> {
    /// List of distinct shards to reduce contention.
    queues: [QueueShard<T>; S],
    /// The index of the next shard to use, in round-robin order.
    next_shard: AtomicUsize,
}

#[derive(Debug)]
struct QueueShard<T> {
    /// The inner stack of pooled values.
    queue: SegQueue<T>,
    /// The number of elements currently stored in this shard.
    elem_cnt: AtomicUsize,
    /// The value to use when calling [`Reuse::reuse`]. Typically the capacity
    /// to keep in a reused buffer.
    trim: usize,
    /// The max number of values to keep in the shard.
    max: usize,
    /// Name of the pool, for metrics.
    name: &'static str,
}

impl<T> QueueShard<T> {
    const fn new(trim: usize, max: usize, name: &'static str) -> Self {
        QueueShard {
            queue: SegQueue::new(),
            elem_cnt: AtomicUsize::new(0),
            trim,
            max,
            name,
        }
    }
}

/// A value borrowed from the [`Pool`] that can be dereferenced to `T`.
#[derive(Debug)]
pub struct Pooled<T: Default + Reuse + 'static> {
    inner: T,
    pool: &'static QueueShard<T>,
}

impl<T: Default + Reuse> Pooled<T> {
    fn new(inner: T, shard: &'static QueueShard<T>) -> Self {
        buffer_pool::pool_active_count(shard.name).inc();
        Pooled { inner, pool: shard }
    }

    pub fn into_inner(mut self) -> T {
        std::mem::take(&mut self.inner)
    }
}

impl<T: Default + Reuse> Drop for Pooled<T> {
    fn drop(&mut self) {
        let QueueShard {
            queue,
            elem_cnt,
            trim,
            max,
            name,
        } = self.pool;
        // The memory associated with this object is no longer live.
        buffer_pool::pool_active_count(name).dec();
        if self.inner.reuse(*trim) {
            if elem_cnt.fetch_add(1, Ordering::Acquire) < *max {
                // If returning the element to the queue would not exceed max
                // number of elements, return it
                buffer_pool::pool_idle_count(name).inc();
                buffer_pool::pool_idle_bytes(name)
                    .inc_by(self.inner.capacity() as u64);
                queue.push(std::mem::take(&mut self.inner));
                return;
            }
            // There was no room for the buffer, return count to previous value
            // and drop
            elem_cnt.fetch_sub(1, Ordering::Release);
        }
        // If item did not qualify for return, drop it
    }
}

// Currently there is no way to const init an array that does not implement
// Copy, so this macro generates initializators for up to 32 shards. If
// const Default is ever stabilized this will all go away.
macro_rules! array_impl_new_queues {
    {$n:expr, $t:ident $($ts:ident)*} => {
        impl<$t: Default + Reuse> Pool<{$n}, $t> {
            #[allow(dead_code)]
            pub const fn new(limit: usize, trim: usize, name: &'static str) -> Self {
                let limit = limit / $n;
                Pool {
                    queues: [QueueShard::new(trim, limit, name), $(QueueShard::<$ts>::new(trim, limit, name)),*],
                    next_shard: AtomicUsize::new(0),
                }
            }
        }

        array_impl_new_queues!{($n - 1), $($ts)*}
    };
    {$n:expr,} => {  };
}

array_impl_new_queues! { 32, T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T T }

impl<const S: usize, T: Default + Reuse> Pool<S, T> {
    /// Get a value from the pool, or create a new default value if the
    /// assigned shard is currently empty.
    pub fn get(&'static self) -> Pooled<T> {
        let shard = self.next_shard.fetch_add(1, Ordering::Relaxed) % S;
        let shard = &self.queues[shard];
        let inner = match shard.queue.pop() {
            Some(el) => {
                shard.elem_cnt.fetch_sub(1, Ordering::Relaxed);
                buffer_pool::pool_idle_count(shard.name).dec();
                buffer_pool::pool_idle_bytes(shard.name)
                    .dec_by(el.capacity() as u64);
                el
            },
            None => Default::default(),
        };

        Pooled::new(inner, shard)
    }

    /// Create a new default value assigned for a pool, if it is ends up
    /// being expanded and eligible for reuse it will return to the pool,
    /// otherwise it will end up being dropped.
    pub fn get_empty(&'static self) -> Pooled<T> {
        let shard = self.next_shard.load(Ordering::Relaxed) % S;
        let shard = &self.queues[shard];
        Pooled::new(Default::default(), shard)
    }

    /// Get a value from the pool and apply the provided transformation on
    /// it before returning.
    pub fn get_with(&'static self, f: impl Fn(&mut T)) -> Pooled<T> {
        let mut pooled = self.get();
        f(&mut pooled);
        pooled
    }

    pub fn from_owned(&'static self, inner: T) -> Pooled<T> {
        let shard = self.next_shard.fetch_add(1, Ordering::Relaxed) % S;
        let shard = &self.queues[shard];
        Pooled::new(inner, shard)
    }
}

impl<'a, const S: usize, T: Default + Extend<&'a u8> + Reuse> Pool<S, T> {
    /// Get a value from the pool and extend it with the provided slice.
    pub fn with_slice(&'static self, v: &'a [u8]) -> Pooled<T> {
        let mut buf = self.get();
        buf.deref_mut().extend(v);
        buf
    }
}

impl<T: Default + Reuse> Deref for Pooled<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Default + Reuse> DerefMut for Pooled<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// A trait that prepares an item to be returned to the pool. For example
/// clearing it. `true` is returned if the item should be returned to the pool,
/// `false` if it should be dropped.
pub trait Reuse {
    fn reuse(&mut self, trim: usize) -> bool;

    /// Returns the capacity of the object in bytes, to allow for more precise
    /// tracking.
    fn capacity(&self) -> usize;
}

impl Reuse for Vec<u8> {
    fn reuse(&mut self, trim: usize) -> bool {
        self.clear();
        self.shrink_to(trim);
        self.capacity() > 0
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }
}

impl Reuse for VecDeque<u8> {
    fn reuse(&mut self, val: usize) -> bool {
        self.clear();
        self.shrink_to(val);
        self.capacity() > 0
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sharding() {
        const SHARDS: usize = 3;
        const MAX_IN_SHARD: usize = 2;
        const POOL_NAME: &str = "test_sharding_pool";

        let pool = Box::leak(Box::new(Pool::<SHARDS, Vec<u8>>::new(
            SHARDS * MAX_IN_SHARD,
            4,
            POOL_NAME,
        )));

        let bufs = (0..SHARDS * 4).map(|_| pool.get()).collect::<Vec<_>>();

        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 0);
        }
        assert_eq!(buffer_pool::pool_idle_count(POOL_NAME).get(), 0);
        assert_eq!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            bufs.len() as u64
        );

        for (i, buf) in bufs.iter().enumerate() {
            assert!(buf.is_empty());
            // Check the buffer is sharded properly.
            assert_eq!(
                buf.pool as *const _,
                &pool.queues[i % SHARDS] as *const _
            );
        }

        // Shards are still empty.
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 0);
        }
        assert_eq!(buffer_pool::pool_idle_count(POOL_NAME).get(), 0);
        assert_eq!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            bufs.len() as u64
        );

        // Now drop the buffers, they will not go into the pool because they have
        // no capacity, so reuse returns false. What is the point in
        // pooling empty buffers?
        drop(bufs);
        assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 0);
        assert_eq!(buffer_pool::pool_idle_count(POOL_NAME).get(), 0);

        // Get buffers with capacity next.
        let bufs = (0..SHARDS * 4)
            .map(|_| pool.get_with(|b| b.extend(&[0, 1])))
            .collect::<Vec<_>>();

        for (i, buf) in bufs.iter().enumerate() {
            // Check the buffer is sharded properly.
            assert_eq!(
                buf.pool as *const _,
                &pool.queues[i % SHARDS] as *const _
            );
            // Check that the buffer was properly extended
            assert_eq!(&buf[..], &[0, 1]);
        }
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            bufs.len() as u64
        );

        drop(bufs);

        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), MAX_IN_SHARD);
        }
        assert_eq!(
            buffer_pool::pool_idle_count(POOL_NAME).get(),
            (SHARDS * MAX_IN_SHARD) as u64
        );
        assert_ne!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 0);

        // Now get buffers again, this time they should come from the pool.
        let bufs = (0..SHARDS).map(|_| pool.get()).collect::<Vec<_>>();

        for (i, buf) in bufs.iter().enumerate() {
            // Check that the buffer was properly cleared.
            assert!(buf.is_empty());
            // Check the buffer is sharded properly.
            assert_eq!(
                buf.pool as *const _,
                &pool.queues[i % SHARDS] as *const _
            );
        }

        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 1);
        }
        assert_eq!(buffer_pool::pool_idle_count(POOL_NAME).get(), SHARDS as u64);
        assert_ne!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            bufs.len() as u64
        );

        // Get more buffers from the pool.
        let bufs2 = (0..SHARDS).map(|_| pool.get()).collect::<Vec<_>>();
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 0);
        }
        assert_eq!(buffer_pool::pool_idle_count(POOL_NAME).get(), 0);
        assert_eq!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            (bufs.len() + bufs2.len()) as u64
        );

        // Get even more buffers.
        let bufs3 = (0..SHARDS).map(|_| pool.get()).collect::<Vec<_>>();
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 0);
        }
        assert_eq!(buffer_pool::pool_idle_count(POOL_NAME).get(), 0);
        assert_eq!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            (bufs.len() + bufs2.len() + bufs3.len()) as u64
        );

        // Now begin dropping.
        drop(bufs);
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 1);
        }
        assert_eq!(buffer_pool::pool_idle_count(POOL_NAME).get(), SHARDS as u64);
        assert_ne!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            (bufs2.len() + bufs3.len()) as u64
        );

        drop(bufs2);
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), MAX_IN_SHARD);
        }
        assert_eq!(
            buffer_pool::pool_idle_count(POOL_NAME).get(),
            (SHARDS * MAX_IN_SHARD) as u64
        );
        assert_ne!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(
            buffer_pool::pool_active_count(POOL_NAME).get(),
            bufs3.len() as u64
        );

        drop(bufs3);
        for shard in pool.queues.iter() {
            // Can't get over limit.
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), MAX_IN_SHARD);
        }
        assert_eq!(
            buffer_pool::pool_idle_count(POOL_NAME).get(),
            (SHARDS * MAX_IN_SHARD) as u64
        );
        assert_ne!(buffer_pool::pool_idle_bytes(POOL_NAME).get(), 0);
        assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 0);
    }

    #[test]
    fn test_creation() {
        const SHARDS: usize = 3;
        const MAX_IN_SHARD: usize = 2;
        const POOL_NAME: &str = "test_creation_pool";

        let pool = Box::leak(Box::new(Pool::<SHARDS, Vec<u8>>::new(
            SHARDS * MAX_IN_SHARD,
            4,
            POOL_NAME,
        )));

        assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 0);

        {
            let _buf1 = pool.get();
            assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 1);

            let _buf2 = pool.get_empty();
            assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 2);

            let _buf3 = pool.get_with(|_| ());
            assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 3);

            let _buf4 = pool.from_owned(vec![0, 1, 2, 4]);
            assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 4);
        }

        assert_eq!(buffer_pool::pool_active_count(POOL_NAME).get(), 0);
    }
}
