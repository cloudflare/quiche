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

/// A simple buffer for working with datagrams.
///
/// This is a thin wrapper around a `Vec<u8>` but it maintains an offset / read
/// position into the vector to the actual start of the datagram. This enables
/// users to preallocate headroom in front of the actual datagram to prepend
/// additional headers, or to advance the cursor to consume such prefixes.
#[derive(Default, Clone)]
pub struct DgramBuffer {
    data: Vec<u8>,
    start: usize,
}

impl DgramBuffer {
    /// Creates an empty `DgramBuffer` with no allocated capacity.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a `DgramBuffer` by copying `data`; the read cursor starts at
    /// the beginning.
    pub fn from_slice(data: &[u8]) -> Self {
        DgramBuffer {
            data: data.into(),
            start: 0,
        }
    }

    /// Creates an empty `DgramBuffer` pre-allocated for at least `capacity`
    /// bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        DgramBuffer {
            data: Vec::with_capacity(capacity),
            start: 0,
        }
    }

    /// Creates a `DgramBuffer` pre-allocated for `capacity` bytes with
    /// `headroom` zero bytes reserved at the front for later prefix insertion
    /// via [`try_add_prefix`]. The read cursor is positioned after the
    /// headroom. Panics if `headroom > capacity`.
    ///
    /// [`try_add_prefix`]: DgramBuffer::try_add_prefix
    pub fn with_capacity_and_headroom(capacity: usize, headroom: usize) -> Self {
        assert!(capacity >= headroom);
        let mut v = Vec::with_capacity(capacity);
        v.resize(headroom, 0);
        DgramBuffer {
            data: v,
            start: headroom,
        }
    }

    /// Wraps an existing `Vec<u8>`, treating the first `headroom` bytes as
    /// reserved prefix space. The read cursor is positioned after the
    /// headroom. Panics if `headroom > v.len()`.
    pub fn from_vec_with_headroom(v: Vec<u8>, headroom: usize) -> Self {
        assert!(headroom <= v.len());
        DgramBuffer {
            data: v,
            start: headroom,
        }
    }

    /// Truncates the readable portion to `count` bytes, discarding any data
    /// beyond that point. If count is greater or equal to the buffer’s current
    /// length, this has no effect.
    pub fn truncate(&mut self, count: usize) {
        self.data.truncate(self.start + count);
    }

    /// Advances the cursor by `count` bytes; panics if `count` exceeds
    /// the number of readable bytes.
    pub fn advance(&mut self, count: usize) {
        assert!(self.start + count <= self.data.len());
        self.start += count;
    }

    /// Prepends `prefix` into the headroom region, sliding the read cursor
    /// backwards. Returns `Err(())` if the headroom is smaller than
    /// `prefix.len()`.
    #[allow(
        clippy::result_unit_err,
        reason = "There is only a single error case, adding a custom error type doesn't make sense"
    )]
    pub fn try_add_prefix(&mut self, prefix: &[u8]) -> Result<(), ()> {
        if self.start < prefix.len() {
            return Err(());
        }

        self.start -= prefix.len();
        self.data[self.start..self.start + prefix.len()].copy_from_slice(prefix);
        Ok(())
    }

    /// Ensures that at least `headroom` bytes of headroom are available,
    /// potentially shifting elements and reallocating. If `headroom` is
    /// less than the existing headroom, this method does nothing.
    pub fn splice_headroom(&mut self, headroom: usize) {
        if self.start >= headroom {
            return;
        }
        self.data
            .splice(0..self.start, std::iter::repeat_n(0u8, headroom));
        self.start = headroom;
    }

    /// Resets the buffer to an empty state, dropping all data and headroom.
    pub fn clear(&mut self) {
        self.start = 0;
        self.data.clear();
    }

    /// Returns the number of readable bytes (i.e. `data.len() - pos`).
    pub fn len(&self) -> usize {
        self.data.len() - self.start
    }

    /// Returns `true` if there are no readable bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the readable bytes as a slice (i.e. `data[pos..]`).
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..]
    }

    /// Returns the readable bytes as a mutable slice (i.e. `data[pos..]`).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.start..]
    }

    /// Returns the number of bytes the underlying `Vec` can accept before
    /// reallocating (i.e. `capacity - len`).
    pub fn spare_capacity(&self) -> usize {
        self.data.capacity() - self.data.len()
    }

    /// Consumes the buffer and returns the inner `Vec<u8>` and the current
    /// read position as `(data, pos)`.
    pub fn into_parts(self) -> (Vec<u8>, usize) {
        (self.data, self.start)
    }
}

impl AsRef<[u8]> for DgramBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for DgramBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl std::fmt::Debug for DgramBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return f.write_str("[]");
        }

        write!(f, "[0x")?;
        // Render payload bytes as two-char hex, underscore-separated after every
        // 4.
        for (i, byte) in self.as_slice().iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                f.write_str("_")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ", len={}]", self.len())?;

        Ok(())
    }
}

// SAFETY: All required methods delegate directly to `Vec<u8>`'s trusted
// `BufMut` implementation.
unsafe impl bytes::BufMut for DgramBuffer {
    fn remaining_mut(&self) -> usize {
        self.data.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        // SAFETY: We trust `Vec<u8>`'s `BufMut` implementation.
        self.data.advance_mut(cnt);
    }

    fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
        self.data.chunk_mut()
    }

    // Forwarding these provided methods of `BufMut`, because the
    // implementation on `Vec<u8>` has specialization for them.
    fn put<T: bytes::Buf>(&mut self, src: T)
    where
        Self: Sized,
    {
        self.data.put(src);
    }

    fn put_slice(&mut self, src: &[u8]) {
        self.data.put_slice(src);
    }

    fn put_bytes(&mut self, val: u8, cnt: usize) {
        self.data.put_bytes(val, cnt);
    }
}

impl From<Vec<u8>> for DgramBuffer {
    fn from(v: Vec<u8>) -> Self {
        DgramBuffer { data: v, start: 0 }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    use super::*;

    #[test]
    fn new_is_empty() {
        let b = DgramBuffer::new();
        assert_eq!(b.as_slice(), &[]);
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
    }

    #[test]
    fn from_slice_copies_data() {
        let b = DgramBuffer::from_slice(&[1, 2, 3]);
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        assert_eq!(b.len(), 3);
        assert!(!b.is_empty());
    }

    #[test]
    fn with_capacity_is_empty_with_allocation() {
        let b = DgramBuffer::with_capacity(64);
        assert_eq!(b.as_slice(), &[]);
        assert_eq!(b.spare_capacity(), 64);
        assert!(b.is_empty());
    }

    #[test]
    fn with_capacity_and_headroom_positions_cursor() {
        let b = DgramBuffer::with_capacity_and_headroom(16, 4);
        assert_eq!(b.as_slice(), &[]);
        assert_eq!(b.len(), 0);
        assert_eq!(b.spare_capacity(), 12);
    }

    #[test]
    fn from_vec_with_headroom_exposes_payload() {
        let v = vec![0u8, 0, 0, 1, 2, 3];
        let b = DgramBuffer::from_vec_with_headroom(v, 3);
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn truncate_shortens_readable_view() {
        let mut b = DgramBuffer::from_slice(&[1, 2, 3, 4, 5]);
        b.truncate(3);
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn advance_moves_cursor() {
        let mut b = DgramBuffer::from_slice(&[1, 2, 3, 4]);
        b.advance(2);
        assert_eq!(b.as_slice(), &[3, 4]);
        assert_eq!(b.len(), 2);
    }

    #[test]
    #[should_panic]
    fn advance_past_end_panics() {
        let mut b = DgramBuffer::from_slice(&[1, 2]);
        b.advance(3);
    }

    #[test]
    fn try_add_prefix() {
        let mut b = DgramBuffer::with_capacity_and_headroom(8, 4);
        b.put_slice(&[0xaa, 0xbb]);
        b.try_add_prefix(&[0x01, 0x02]).unwrap();
        assert_eq!(b.as_slice(), &[0x01, 0x02, 0xaa, 0xbb]);
        assert_eq!(b.len(), 4);
        b.try_add_prefix(&[0x42, 0x23]).unwrap();
        assert_eq!(b.as_slice(), &[0x42, 0x23, 0x01, 0x02, 0xaa, 0xbb]);
        assert_eq!(b.len(), 6);
        assert!(b.try_add_prefix(&[0x01]).is_err());
    }

    #[test]
    fn try_add_prefix_fails_when_headroom_insufficient() {
        let mut b = DgramBuffer::with_capacity_and_headroom(8, 1);
        assert!(b.try_add_prefix(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn clear_resets_to_empty() {
        let mut b = DgramBuffer::from_slice(&[1, 2, 3]);
        b.clear();
        assert_eq!(b.as_slice(), &[]);
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
    }

    #[test]
    fn from_vec() {
        let b = DgramBuffer::from(vec![7, 8, 9]);
        assert_eq!(b.as_slice(), &[7, 8, 9]);
    }

    #[test]
    fn into_parts_returns_data_and_pos() {
        let mut b = DgramBuffer::with_capacity_and_headroom(8, 3);
        b.put_slice(&[1, 2, 3]);
        let (data, pos) = b.into_parts();
        assert_eq!(pos, 3);
        assert_eq!(&data, &[0, 0, 0, 1, 2, 3]);
    }

    #[test]
    fn bufmut_put_slice_appends() {
        let mut b = DgramBuffer::new();
        b.put_slice(&[0x0a, 0x0b, 0x0c]);
        assert_eq!(b.as_slice(), &[0x0a, 0x0b, 0x0c]);
    }

    #[test]
    fn as_ref_matches_as_slice() {
        let b = DgramBuffer::from_slice(&[1, 2, 3]);
        assert_eq!(b.as_ref(), b.as_slice());
    }

    #[test]
    fn as_mut_slice_allows_mutation() {
        let mut b = DgramBuffer::from_slice(&[1, 2, 3]);
        b.as_mut_slice()[1] = 0xff;
        assert_eq!(b.as_slice(), &[1, 0xff, 3]);
    }

    #[test]
    fn as_mut_via_trait_allows_mutation() {
        let mut b = DgramBuffer::from_slice(&[1, 2, 3]);
        b.as_mut()[1] = 0xff;
        assert_eq!(b.as_slice(), &[1, 0xff, 3]);
    }

    // Debug format

    #[test]
    fn debug_empty() {
        let b = DgramBuffer::new();
        assert_eq!(format!("{:?}", b), "[]");
    }

    #[test]
    fn debug_payload_hex_with_group_separator() {
        let b = DgramBuffer::from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(format!("{:?}", b), "[0x00010203_04050607_08, len=9]");
    }

    #[test]
    fn debug_payload_exact_group_boundary() {
        let b = DgramBuffer::from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(format!("{:?}", b), "[0xaabbccdd, len=4]");
    }

    /// When existing headroom already satisfies the request, nothing changes.
    #[test]
    fn splice_headroom_noop() {
        // 4 bytes of headroom, 3 bytes of payload.
        let mut b = DgramBuffer::with_capacity_and_headroom(16, 4);
        b.put_slice(&[1, 2, 3]);
        let (data_before, pos_before) = b.into_parts();

        let mut b =
            DgramBuffer::from_vec_with_headroom(data_before.clone(), pos_before);
        b.splice_headroom(3); // less than existing -- noop
        let (data_after, pos_after) = b.clone().into_parts();
        assert_eq!(pos_after, pos_before);
        assert_eq!(data_after, data_before);

        b.splice_headroom(4); // same as existing -- noop
        assert_eq!(pos_after, pos_before);
        assert_eq!(data_after, data_before);
    }

    /// When there is no existing headroom, splice_headroom inserts the
    /// requested number of zero bytes at the front.
    #[test]
    fn splice_headroom_inserts_headroom_when_none_exists() {
        // from_slice starts with pos=0 (no headroom).
        let mut b = DgramBuffer::from_slice(&[1, 2, 3]);
        b.splice_headroom(4);

        // pos advances to 4; payload is unchanged.
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        let (data, pos) = b.into_parts();
        assert_eq!(pos, 4);
        // The first four bytes are the new headroom zeros; payload follows.
        assert_eq!(&data, &[0, 0, 0, 0, 1, 2, 3]);
    }

    /// When headroom is smaller than requested, the gap is filled with zeros
    /// and the prefix region is correctly sized.
    #[test]
    fn splice_headroom_grows_insufficient_headroom() {
        // 2 bytes of headroom, 3 bytes of payload.
        let mut b = DgramBuffer::with_capacity_and_headroom(16, 2);
        b.put_slice(&[10, 20, 30]);
        // pos=2, request 6 bytes of headroom.
        b.splice_headroom(6);

        assert_eq!(b.as_slice(), &[10, 20, 30]);
        let (data, pos) = b.into_parts();
        assert_eq!(pos, 6);
        assert_eq!(&data[..6], &[0u8; 6]);
        assert_eq!(&data[6..], &[10, 20, 30]);
    }
}
