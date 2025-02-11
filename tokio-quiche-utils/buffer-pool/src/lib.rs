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

pub use crate::buffer::*;
pub use crate::raw_pool_buf_io::*;

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
}

impl<T> QueueShard<T> {
    const fn new(trim: usize, max: usize) -> Self {
        QueueShard {
            queue: SegQueue::new(),
            elem_cnt: AtomicUsize::new(0),
            trim,
            max,
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
        } = self.pool;
        if self.inner.reuse(*trim) {
            if elem_cnt.fetch_add(1, Ordering::Acquire) < *max {
                // If returning the element to the queue would not exceed max
                // number of elements, return it
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
            pub const fn new(limit: usize, trim: usize) -> Self {
                let limit = limit / $n;
                Pool {
                    queues: [QueueShard::new(trim, limit), $(QueueShard::<$ts>::new(trim, limit)),*],
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
                el
            },
            None => Default::default(),
        };

        Pooled { inner, pool: shard }
    }

    /// Create a new default value assigned for a pool, if it is ends up
    /// being expanded and eligible for reuse it will return to the pool,
    /// otherwise it will end up being dropped.
    pub fn get_empty(&'static self) -> Pooled<T> {
        let shard = self.next_shard.load(Ordering::Relaxed) % S;
        let shard = &self.queues[shard];

        Pooled {
            inner: Default::default(),
            pool: shard,
        }
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
        Pooled { inner, pool: shard }
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
}

impl Reuse for Vec<u8> {
    fn reuse(&mut self, trim: usize) -> bool {
        self.clear();
        self.shrink_to(trim);
        self.capacity() > 0
    }
}

impl Reuse for VecDeque<u8> {
    fn reuse(&mut self, val: usize) -> bool {
        self.clear();
        self.shrink_to(val);
        self.capacity() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sharding() {
        const SHARDS: usize = 3;
        const MAX_IN_SHARD: usize = 2;

        let pool = Box::leak(Box::new(Pool::<SHARDS, Vec<u8>>::new(
            SHARDS * MAX_IN_SHARD,
            4,
        )));

        let bufs = (0..SHARDS * 4).map(|_| pool.get()).collect::<Vec<_>>();

        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 0);
        }

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

        // Now drop the buffers, they will not go into the pool because they have
        // no capacity, so reuse returns false. What is the point in
        // pooling empty buffers?
        drop(bufs);

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

        drop(bufs);

        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), MAX_IN_SHARD);
        }

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

        // Get more buffers from the pool.
        let bufs2 = (0..SHARDS).map(|_| pool.get()).collect::<Vec<_>>();
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 0);
        }

        // Get even more buffers.
        let bufs3 = (0..SHARDS).map(|_| pool.get()).collect::<Vec<_>>();
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 0);
        }

        // Now begin dropping.
        drop(bufs);
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), 1);
        }

        drop(bufs2);
        for shard in pool.queues.iter() {
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), MAX_IN_SHARD);
        }

        drop(bufs3);
        for shard in pool.queues.iter() {
            // Can't get over limit.
            assert_eq!(shard.elem_cnt.load(Ordering::Relaxed), MAX_IN_SHARD);
        }
    }
}
