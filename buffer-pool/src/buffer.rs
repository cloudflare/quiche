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

use std::ops::Deref;
use std::ops::DerefMut;

use crate::Reuse;

/// A convinience wrapper around Vec that allows to "consume" data from the
/// front *without* shifting.
///
/// This is not unlike `VecDeque` but more ergonomic
/// for the operations we require. Conceptually `VecDeque` is two slices, and
/// this is one slice. Also there is no `set_len` for `VecDeque`, so it has to
/// be converted to `Vec` and then back again.
#[derive(Default, Debug)]
pub struct ConsumeBuffer {
    inner: Vec<u8>,
    head: usize,
}

impl Deref for ConsumeBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner[self.head..]
    }
}

impl DerefMut for ConsumeBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner[self.head..]
    }
}

impl Reuse for ConsumeBuffer {
    fn reuse(&mut self, val: usize) -> bool {
        self.inner.clear();
        self.inner.shrink_to(val);
        self.head = 0;
        self.inner.capacity() > 0
    }
}

impl ConsumeBuffer {
    pub fn from_vec(inner: Vec<u8>) -> Self {
        ConsumeBuffer { inner, head: 0 }
    }

    pub fn into_vec(self) -> Vec<u8> {
        let mut inner = self.inner;
        inner.drain(0..self.head);
        inner
    }

    pub fn pop_front(&mut self, count: usize) {
        assert!(self.head + count <= self.inner.len());
        self.head += count;
    }

    pub fn expand(&mut self, count: usize) {
        self.inner.reserve_exact(count);
        // SAFETY: u8 is always initialized and we reserved the capacity.
        unsafe { self.inner.set_len(count) };
    }

    pub fn truncate(&mut self, count: usize) {
        self.inner.truncate(self.head + count);
    }

    pub fn add_prefix(&mut self, prefix: &[u8]) -> bool {
        if self.head < prefix.len() {
            return false;
        }

        self.head -= prefix.len();
        self.inner[self.head..self.head + prefix.len()].copy_from_slice(prefix);

        true
    }
}

impl<'a> Extend<&'a u8> for ConsumeBuffer {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}
