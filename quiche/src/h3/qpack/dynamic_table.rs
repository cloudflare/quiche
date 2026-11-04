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

//! The QPACK decoder's dynamic table.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2>.

// TODO: field lines can't reference this table yet; see the TODOs in
// decoder.rs.

use std::collections::VecDeque;
use std::sync::Arc;

/// The overhead, in bytes, added to the lengths of an entry's name and value
/// to compute its size (RFC 9204, Section 3.2.1).
pub(super) const ENTRY_OVERHEAD: usize = 32;

/// A dynamic table error.
///
/// When caused by an encoder instruction, each of these is a connection error
/// of type `QPACK_ENCODER_STREAM_ERROR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TableError {
    /// The capacity exceeds the table's maximum capacity.
    CapacityExceedsMaximum,

    /// The entry's size exceeds the table's capacity.
    EntryTooLarge,

    /// The encoder-relative index doesn't refer to a dynamic table entry.
    InvalidReference,
}

/// The name of a dynamic table entry.
#[derive(Clone)]
pub(super) enum EntryName {
    /// A name borrowed from the static table.
    Static(&'static [u8]),

    /// A name received from the encoder, shared by all entries that use it.
    Shared(Arc<[u8]>),
}

impl EntryName {
    fn as_bytes(&self) -> &[u8] {
        match self {
            EntryName::Static(name) => name,

            EntryName::Shared(name) => name,
        }
    }
}

/// A dynamic table entry.
///
/// Cloning an entry clones the handles to its name and value, not their bytes.
#[derive(Clone)]
pub(crate) struct Entry {
    pub(super) name: EntryName,

    pub(super) value: Arc<[u8]>,

    /// The entry's QPACK table size: name.len() + value.len() + 32 bytes
    /// (RFC 9204, Section 3.2.1).
    size: usize,
}

impl Entry {
    fn new(name: EntryName, value: Arc<[u8]>) -> Result<Entry, TableError> {
        let size = name
            .as_bytes()
            .len()
            .checked_add(value.len())
            .and_then(|len| len.checked_add(ENTRY_OVERHEAD))
            .ok_or(TableError::EntryTooLarge)?;

        Ok(Entry { name, value, size })
    }

    /// Returns the entry's name.
    pub(crate) fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// Returns the entry's value.
    pub(crate) fn value(&self) -> &[u8] {
        &self.value
    }
}

/// A QPACK decoder's dynamic table (RFC 9204, Section 3.2).
///
/// The table starts empty, with a capacity of zero.
/// Invariant: `size <= capacity <= max_capacity`.
pub(crate) struct DynamicTable {
    /// The entries, from oldest to newest.
    entries: VecDeque<Entry>,

    /// Equal to the sum of `entry.size` for all entries in `entries`.
    size: usize,

    /// The capacity set by the encoder.
    capacity: usize,

    /// The decoder's locally configured maximum, advertised to the encoder via
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204, Section 3.2.3).
    max_capacity: usize,

    /// The number of entries ever inserted, including duplicates. This is also
    /// the absolute index of the next inserted entry.
    insert_count: u64,
}

impl DynamicTable {
    /// Creates an empty table with a capacity of zero.
    ///
    /// `max_capacity` must be the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` value
    /// advertised to the peer. It bounds the memory charged to the table and
    /// can't change during the table's lifetime.
    pub(crate) fn new(max_capacity: usize) -> DynamicTable {
        DynamicTable {
            entries: VecDeque::new(),
            size: 0,
            capacity: 0,
            max_capacity,
            insert_count: 0,
        }
    }

    /// Returns the table's capacity.
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the entry with the given absolute index, unless it was evicted
    /// or hasn't been inserted yet (RFC 9204, Section 3.2.4).
    pub(crate) fn get_by_absolute_index(
        &self, absolute_index: u64,
    ) -> Option<&Entry> {
        // The absolute index of the oldest entry.
        let oldest = self.insert_count.checked_sub(self.entries.len() as u64)?;
        let pos = absolute_index.checked_sub(oldest)?;

        self.entries.get(usize::try_from(pos).ok()?)
    }

    /// Sets the table's capacity, evicting the oldest entries that no longer
    /// fit (RFC 9204, Section 4.3.1).
    pub(super) fn set_dynamic_table_capacity(
        &mut self, capacity: u64,
    ) -> Result<(), TableError> {
        if capacity > self.max_capacity as u64 {
            return Err(TableError::CapacityExceedsMaximum);
        }

        let capacity = capacity as usize;
        self.evict_to(capacity);
        self.capacity = capacity;

        Ok(())
    }

    /// Returns the entry with the given encoder-instruction relative index,
    /// where 0 is the most recently inserted entry (RFC 9204, Section 3.2.5).
    /// Returns `InvalidReference` if the entry was evicted or never inserted.
    pub(super) fn get_by_encoder_relative_index(
        &self, encoder_relative_index: u64,
    ) -> Result<&Entry, TableError> {
        let absolute_index = self
            .insert_count
            .checked_sub(encoder_relative_index)
            .and_then(|index| index.checked_sub(1))
            .ok_or(TableError::InvalidReference)?;

        self.get_by_absolute_index(absolute_index)
            .ok_or(TableError::InvalidReference)
    }

    /// Adds an entry as the newest entry, first evicting the oldest entries to
    /// make room for it (RFC 9204, Section 3.2.2).
    pub(super) fn insert(
        &mut self, name: EntryName, value: Arc<[u8]>,
    ) -> Result<(), TableError> {
        let entry = Entry::new(name, value)?;

        // The size that the existing entries must fit in alongside `entry`.
        let limit = self
            .capacity
            .checked_sub(entry.size)
            .ok_or(TableError::EntryTooLarge)?;

        self.evict_to(limit);

        self.size += entry.size;
        self.entries.push_back(entry);

        // Can't overflow, as a QUIC stream carries fewer than 2^62 bytes and
        // each encoder instruction takes at least one.
        self.insert_count += 1;

        Ok(())
    }

    /// Evicts the oldest entries until the table's size is at most `limit`.
    fn evict_to(&mut self, limit: usize) {
        while self.size > limit {
            let entry = self
                .entries
                .pop_front()
                .expect("nonzero size requires an entry");

            self.size -= entry.size;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_table_errors() {
        let mut table = DynamicTable::new(40);
        assert_eq!(
            table.set_dynamic_table_capacity(41),
            Err(TableError::CapacityExceedsMaximum)
        );
        assert_eq!(
            table.get_by_encoder_relative_index(0).err(),
            Some(TableError::InvalidReference)
        );

        table.set_dynamic_table_capacity(40).unwrap();
        let name = Arc::from(&b"key"[..]);
        assert_eq!(
            table.insert(EntryName::Shared(name), Arc::from(&b"foobar"[..])),
            Err(TableError::EntryTooLarge)
        );
    }
}
