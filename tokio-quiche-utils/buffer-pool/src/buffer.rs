use std::ops::{Deref, DerefMut};

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
