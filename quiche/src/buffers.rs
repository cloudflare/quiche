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

use std::fmt::Debug;
use std::sync::Arc;

/// A trait for providing internal storage buffers for streams,
/// enabling zero-copy operations.
/// The associated type `Buf` can be any type that dereferences to
/// a slice, but should be fast to clone, eg. by wrapping it with an
/// [`Arc`].
pub trait BufFactory: Clone + Default + Debug {
    /// The type of the generated buffer. The clone operation should be cheap,
    /// e.g., by using an [`Arc`].
    type Buf: Clone + Debug + AsRef<[u8]>;

    /// Generate a new buffer from a given slice, the buffer must contain the
    /// same data as the original slice.
    fn buf_from_slice(buf: &[u8]) -> Self::Buf;
}

/// A trait that enables zero-copy sends to quiche. When buffers produced
/// by the `BufFactory` implement this trait, quiche and h3 can supply the
/// raw buffers to be sent, instead of slices that must be copied first.
pub trait BufSplit {
    /// Split the buffer at a given point, after the split the old buffer
    /// must only contain the first `at` bytes, while the newly produced
    /// buffer must containt the remaining bytes.
    fn split_at(&mut self, at: usize) -> Self;

    /// Try to prepend a prefix to the buffer, return true if succeeded.
    fn try_add_prefix(&mut self, _prefix: &[u8]) -> bool {
        false
    }
}

/// The default [`BufFactory`] allocates buffers on the heap on demand.
#[derive(Debug, Clone, Default)]
pub struct DefaultBufFactory;

/// The default [`BufFactory::Buf`] is a boxed slice wrapped in an [`Arc`].
#[derive(Debug, Clone, Default)]
pub struct DefaultBuf(Arc<Box<[u8]>>);

impl BufFactory for DefaultBufFactory {
    type Buf = DefaultBuf;

    fn buf_from_slice(buf: &[u8]) -> Self::Buf {
        DefaultBuf(Arc::new(buf.into()))
    }
}

impl AsRef<[u8]> for DefaultBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
