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

// TODO: the decoder doesn't use this table yet; see the TODOs in decoder.rs.

use std::collections::VecDeque;
use std::sync::Arc;

use super::static_table::STATIC_DECODE_TABLE;

/// The overhead, in bytes, added to the lengths of an entry's name and value
/// to compute its size (RFC 9204, Section 3.2.1).
const ENTRY_OVERHEAD: usize = 32;

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

    /// The index doesn't refer to an entry in the static or dynamic table.
    InvalidReference,
}

/// The name of a dynamic table entry.
#[derive(Clone)]
enum EntryName {
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
    name: EntryName,

    value: Arc<[u8]>,

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
    fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the maximum capacity the encoder may set.
    fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Returns the sum of the sizes of the table's entries.
    fn size(&self) -> usize {
        self.size
    }

    /// Returns the number of entries ever inserted, including duplicates.
    ///
    /// Evictions and capacity changes don't decrease it.
    fn insert_count(&self) -> u64 {
        self.insert_count
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
    fn set_dynamic_table_capacity(
        &mut self, capacity: u64,
    ) -> Result<(), TableError> {
        let capacity = usize::try_from(capacity)
            .map_err(|_| TableError::CapacityExceedsMaximum)?;

        if capacity > self.max_capacity {
            return Err(TableError::CapacityExceedsMaximum);
        }

        self.evict_to(capacity);
        self.capacity = capacity;

        Ok(())
    }

    /// Inserts an entry named after the static table entry at `static_index`
    /// (RFC 9204, Section 4.3.2).
    ///
    /// The name is borrowed from the static table, not copied.
    fn insert_with_static_name_reference(
        &mut self, static_index: u64, value: Arc<[u8]>,
    ) -> Result<(), TableError> {
        let index = usize::try_from(static_index)
            .map_err(|_| TableError::InvalidReference)?;
        let &(name, _) = STATIC_DECODE_TABLE
            .get(index)
            .ok_or(TableError::InvalidReference)?;

        self.insert(Entry::new(EntryName::Static(name), value)?)
    }

    /// Inserts an entry named after the dynamic table entry at
    /// `encoder_relative_index` (RFC 9204, Section 4.3.2).
    ///
    /// The name is shared with the referenced entry, not copied.
    fn insert_with_dynamic_name_reference(
        &mut self, encoder_relative_index: u64, value: Arc<[u8]>,
    ) -> Result<(), TableError> {
        // Take a handle to the name first, as inserting may evict the
        // referenced entry (RFC 9204, Section 3.2.2).
        let name = self
            .get_by_encoder_relative_index(encoder_relative_index)
            .ok_or(TableError::InvalidReference)?
            .name
            .clone();

        self.insert(Entry::new(name, value)?)
    }

    /// Inserts an entry with a literal name (RFC 9204, Section 4.3.3).
    fn insert_with_literal_name(
        &mut self, name: Arc<[u8]>, value: Arc<[u8]>,
    ) -> Result<(), TableError> {
        self.insert(Entry::new(EntryName::Shared(name), value)?)
    }

    /// Re-inserts the dynamic table entry at `encoder_relative_index` (RFC
    /// 9204, Section 4.3.4).
    ///
    /// The new entry shares its name and value with the existing one.
    fn duplicate(
        &mut self, encoder_relative_index: u64,
    ) -> Result<(), TableError> {
        // Take handles to the entry's name and value first, as inserting may
        // evict the entry (RFC 9204, Section 3.2.2).
        let entry = self
            .get_by_encoder_relative_index(encoder_relative_index)
            .ok_or(TableError::InvalidReference)?
            .clone();

        self.insert(entry)
    }

    /// Returns the entry with the given encoder-instruction relative index,
    /// where 0 is the most recently inserted entry (RFC 9204, Section 3.2.5).
    fn get_by_encoder_relative_index(
        &self, encoder_relative_index: u64,
    ) -> Option<&Entry> {
        let absolute_index = self
            .insert_count
            .checked_sub(encoder_relative_index)?
            .checked_sub(1)?;

        self.get_by_absolute_index(absolute_index)
    }

    /// Adds `entry` as the newest entry, first evicting the oldest entries to
    /// make room for it (RFC 9204, Section 3.2.2).
    fn insert(&mut self, entry: Entry) -> Result<(), TableError> {
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

    /// The maximum capacity used by most tests.
    const MAX_CAPACITY: usize = 4096;

    /// The size of an entry with a 4-byte name and a 4-byte value, such as
    /// ("key0", "val0").
    const SMALL_ENTRY_SIZE: usize = 4 + 4 + 32;

    fn bytes(s: &str) -> Arc<[u8]> {
        Arc::from(s.as_bytes())
    }

    /// Returns a value that makes an entry named `name` exactly `size` bytes.
    fn value_of_size(name: &str, size: usize) -> String {
        "x".repeat(size - name.len() - 32)
    }

    fn insert(
        table: &mut DynamicTable, name: &str, value: &str,
    ) -> Result<(), TableError> {
        table.insert_with_literal_name(bytes(name), bytes(value))
    }

    /// Inserts the entries ("key{i}", "val{i}") for each `i` in `range`.
    fn insert_small(table: &mut DynamicTable, range: std::ops::Range<usize>) {
        assert!(
            range.end <= 10,
            "insert_small requires single-digit indices"
        );

        for i in range {
            insert(table, &format!("key{i}"), &format!("val{i}")).unwrap();
        }
    }

    fn name_str(entry: &Entry) -> &str {
        std::str::from_utf8(entry.name()).unwrap()
    }

    fn absolute(table: &DynamicTable, index: u64) -> Option<&str> {
        table.get_by_absolute_index(index).map(name_str)
    }

    fn encoder_relative(table: &DynamicTable, index: u64) -> Option<&str> {
        table.get_by_encoder_relative_index(index).map(name_str)
    }

    /// Returns the names and values of the entries, from oldest to newest.
    fn contents(table: &DynamicTable) -> Vec<(&str, &str)> {
        table
            .entries
            .iter()
            .map(|e| (name_str(e), std::str::from_utf8(e.value()).unwrap()))
            .collect()
    }

    /// The table's observable state.
    #[derive(Debug, PartialEq)]
    struct Snapshot {
        capacity: usize,
        size: usize,
        insert_count: u64,
        entries: Vec<(String, String)>,
    }

    fn snapshot(table: &DynamicTable) -> Snapshot {
        Snapshot {
            capacity: table.capacity(),
            size: table.size(),
            insert_count: table.insert_count(),
            entries: contents(table)
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        }
    }

    fn shared_name(entry: &Entry) -> &Arc<[u8]> {
        match &entry.name {
            EntryName::Shared(name) => name,

            EntryName::Static(_) => panic!("expected a shared name"),
        }
    }

    #[test]
    fn entry_new_size_and_buffer_sharing() {
        let name = bytes("x-name");
        let value = bytes("value");

        let shared_entry =
            Entry::new(EntryName::Shared(name.clone()), value.clone()).unwrap();
        assert_eq!(shared_entry.size, 6 + 5 + 32);
        assert!(Arc::ptr_eq(shared_name(&shared_entry), &name));
        assert!(Arc::ptr_eq(&shared_entry.value, &value));

        let static_name = STATIC_DECODE_TABLE[0].0;
        let static_entry =
            Entry::new(EntryName::Static(static_name), value.clone()).unwrap();
        assert_eq!(static_entry.size, 10 + 5 + 32);
        assert!(std::ptr::eq(static_entry.name(), static_name));
        assert!(Arc::ptr_eq(&static_entry.value, &value));
    }

    #[test]
    fn new_table_has_zero_capacity() {
        let mut table = DynamicTable::new(MAX_CAPACITY);

        assert_eq!(table.max_capacity(), MAX_CAPACITY);
        assert_eq!(table.capacity(), 0);
        assert_eq!(table.size(), 0);
        assert_eq!(table.insert_count(), 0);
        assert_eq!(absolute(&table, 0), None);

        // Even the smallest entry doesn't fit until the encoder sets a
        // capacity.
        assert_eq!(insert(&mut table, "", ""), Err(TableError::EntryTooLarge));
        assert_eq!(table.insert_count(), 0);
    }

    #[test]
    fn max_capacity_is_configurable() {
        for max_capacity in [0, 100, 4096, 8192] {
            let mut table = DynamicTable::new(max_capacity);
            assert_eq!(table.max_capacity(), max_capacity);
            assert_eq!(table.capacity(), 0);

            assert_eq!(
                table.set_dynamic_table_capacity((max_capacity + 1) as u64),
                Err(TableError::CapacityExceedsMaximum)
            );
            assert_eq!(
                table.set_dynamic_table_capacity(max_capacity as u64),
                Ok(())
            );
            assert_eq!(table.capacity(), max_capacity);
        }

        // With a maximum of zero, the encoder can't insert anything.
        let mut table = DynamicTable::new(0);
        table.set_dynamic_table_capacity(0).unwrap();
        assert_eq!(insert(&mut table, "", ""), Err(TableError::EntryTooLarge));

        // Sizes are computed without overflow, whatever the maximum.
        let mut table = DynamicTable::new(usize::MAX);
        assert_eq!(table.set_dynamic_table_capacity(usize::MAX as u64), Ok(()));
        insert_small(&mut table, 0..2);
        assert_eq!(table.size(), 2 * SMALL_ENTRY_SIZE);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn capacity_above_usize_max_is_rejected() {
        let mut table = DynamicTable::new(usize::MAX);

        assert_eq!(
            table.set_dynamic_table_capacity(usize::MAX as u64 + 1),
            Err(TableError::CapacityExceedsMaximum)
        );
        assert_eq!(table.capacity(), 0);
    }

    #[test]
    fn set_dynamic_table_capacity() {
        let mut table = DynamicTable::new(MAX_CAPACITY);

        assert_eq!(
            table.set_dynamic_table_capacity(MAX_CAPACITY as u64),
            Ok(())
        );
        assert_eq!(table.capacity(), MAX_CAPACITY);

        assert_eq!(
            table.set_dynamic_table_capacity((3 * SMALL_ENTRY_SIZE) as u64),
            Ok(())
        );
        insert_small(&mut table, 0..3);

        // Capacities above the maximum are rejected without evicting entries.
        let before = snapshot(&table);
        assert_eq!(
            table.set_dynamic_table_capacity((MAX_CAPACITY + 1) as u64),
            Err(TableError::CapacityExceedsMaximum)
        );
        assert_eq!(
            table.set_dynamic_table_capacity(u64::MAX),
            Err(TableError::CapacityExceedsMaximum)
        );
        assert_eq!(snapshot(&table), before);

        // Reducing the capacity evicts the oldest entries until the rest fit.
        assert_eq!(
            table.set_dynamic_table_capacity((3 * SMALL_ENTRY_SIZE - 1) as u64),
            Ok(())
        );
        assert_eq!(contents(&table), [("key1", "val1"), ("key2", "val2")]);
        assert_eq!(table.size(), 2 * SMALL_ENTRY_SIZE);

        // A capacity equal to the table's size evicts nothing.
        assert_eq!(
            table.set_dynamic_table_capacity((2 * SMALL_ENTRY_SIZE) as u64),
            Ok(())
        );
        assert_eq!(contents(&table), [("key1", "val1"), ("key2", "val2")]);

        // A capacity of zero evicts every entry.
        assert_eq!(table.set_dynamic_table_capacity(0), Ok(()));
        assert!(contents(&table).is_empty());
        assert_eq!(table.size(), 0);

        // The capacity can be raised again, and absolute indexing continues.
        assert_eq!(
            table.set_dynamic_table_capacity(SMALL_ENTRY_SIZE as u64),
            Ok(())
        );
        insert_small(&mut table, 3..4);
        assert_eq!(absolute(&table, 3), Some("key3"));
    }

    #[test]
    fn insert_exact_fit() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity(MAX_CAPACITY as u64)
            .unwrap();

        // Entries whose sizes add up to exactly the capacity all fit.
        let value0 = value_of_size("key0", 1000);
        let value1 = value_of_size("key1", MAX_CAPACITY - 1000);
        assert_eq!(insert(&mut table, "key0", &value0), Ok(()));
        assert_eq!(insert(&mut table, "key1", &value1), Ok(()));
        assert_eq!(contents(&table), [
            ("key0", value0.as_str()),
            ("key1", value1.as_str())
        ]);
        assert_eq!(table.size(), MAX_CAPACITY);

        // An entry as large as the capacity fits by evicting all others.
        let value2 = value_of_size("key2", MAX_CAPACITY);
        assert_eq!(insert(&mut table, "key2", &value2), Ok(()));
        assert_eq!(contents(&table), [("key2", value2.as_str())]);
        assert_eq!(table.size(), MAX_CAPACITY);

        // One byte more doesn't fit, and evicts nothing.
        let before = snapshot(&table);
        let value3 = value_of_size("key3", MAX_CAPACITY + 1);
        assert_eq!(
            insert(&mut table, "key3", &value3),
            Err(TableError::EntryTooLarge)
        );
        assert_eq!(snapshot(&table), before);
    }

    #[test]
    fn insert_evicts_oldest_entries_first() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity((3 * SMALL_ENTRY_SIZE) as u64)
            .unwrap();
        insert_small(&mut table, 0..3);

        // Making room for one more entry evicts only the oldest one.
        insert_small(&mut table, 3..4);
        assert_eq!(contents(&table), [
            ("key1", "val1"),
            ("key2", "val2"),
            ("key3", "val3")
        ]);
        assert_eq!(table.size(), 3 * SMALL_ENTRY_SIZE);

        // A larger entry evicts as many of the oldest entries as needed.
        let value = value_of_size("key4", 2 * SMALL_ENTRY_SIZE);
        assert_eq!(insert(&mut table, "key4", &value), Ok(()));
        assert_eq!(contents(&table), [
            ("key3", "val3"),
            ("key4", value.as_str())
        ]);
        assert_eq!(table.size(), 3 * SMALL_ENTRY_SIZE);
    }

    #[test]
    #[should_panic(expected = "nonzero size requires an entry")]
    fn evict_panics_if_size_is_nonzero_without_entries() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table.size = 40;

        table.evict_to(0);
    }

    #[test]
    fn insert_rejects_entry_larger_than_capacity() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity((3 * SMALL_ENTRY_SIZE) as u64)
            .unwrap();
        insert_small(&mut table, 0..2);
        let before = snapshot(&table);

        let too_large = 3 * SMALL_ENTRY_SIZE + 1;

        // Rejected before evicting anything, however the name is given.
        assert_eq!(
            insert(&mut table, "key2", &value_of_size("key2", too_large)),
            Err(TableError::EntryTooLarge)
        );
        assert_eq!(
            table.insert_with_dynamic_name_reference(
                0,
                bytes(&value_of_size("key1", too_large))
            ),
            Err(TableError::EntryTooLarge)
        );
        // Static table entry 2 is named "age".
        assert_eq!(
            table.insert_with_static_name_reference(
                2,
                bytes(&value_of_size("age", too_large))
            ),
            Err(TableError::EntryTooLarge)
        );
        assert_eq!(snapshot(&table), before);
    }

    #[test]
    fn absolute_and_encoder_relative_indexing() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity((3 * SMALL_ENTRY_SIZE) as u64)
            .unwrap();
        // Evicts "key0".
        insert_small(&mut table, 0..4);

        // Absolute indices count insertions from zero.
        assert_eq!(absolute(&table, 0), None);
        assert_eq!(absolute(&table, 1), Some("key1"));
        assert_eq!(absolute(&table, 3), Some("key3"));
        assert_eq!(absolute(&table, 4), None);
        assert_eq!(absolute(&table, u64::MAX), None);

        // Encoder-relative index 0 is the most recently inserted entry.
        assert_eq!(encoder_relative(&table, 0), Some("key3"));
        assert_eq!(encoder_relative(&table, 2), Some("key1"));
        assert_eq!(encoder_relative(&table, 3), None);
        assert_eq!(encoder_relative(&table, 4), None);
        assert_eq!(encoder_relative(&table, u64::MAX), None);

        // An insertion shifts relative indices but not absolute ones. This
        // one duplicates "key1", evicting the original.
        assert_eq!(table.duplicate(2), Ok(()));
        assert_eq!(encoder_relative(&table, 0), Some("key1"));
        assert_eq!(encoder_relative(&table, 1), Some("key3"));
        assert_eq!(encoder_relative(&table, 2), Some("key2"));
        assert_eq!(absolute(&table, 1), None);
        assert_eq!(absolute(&table, 3), Some("key3"));
        assert_eq!(absolute(&table, 4), Some("key1"));
    }

    #[test]
    fn insert_count_is_monotonic() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity((2 * SMALL_ENTRY_SIZE) as u64)
            .unwrap();

        // Each successful insertion increments the insert count by one,
        // including those that evict entries.
        insert_small(&mut table, 0..1);
        assert_eq!(table.insert_count(), 1);

        assert_eq!(
            table.insert_with_static_name_reference(2, bytes("12345")),
            Ok(())
        );
        assert_eq!(table.insert_count(), 2);

        // Evicts "key0".
        assert_eq!(
            table.insert_with_dynamic_name_reference(0, bytes("val2")),
            Ok(())
        );
        assert_eq!(table.insert_count(), 3);

        // Evicts the duplicated entry.
        assert_eq!(table.duplicate(1), Ok(()));
        assert_eq!(table.insert_count(), 4);
        assert_eq!(contents(&table), [("age", "val2"), ("age", "12345")]);

        // Failed operations leave it unchanged.
        let too_large = value_of_size("key9", 2 * SMALL_ENTRY_SIZE + 1);
        assert!(insert(&mut table, "key9", &too_large).is_err());
        assert!(table.duplicate(2).is_err());
        assert!(table
            .insert_with_static_name_reference(99, bytes(""))
            .is_err());
        assert!(table
            .set_dynamic_table_capacity((MAX_CAPACITY + 1) as u64)
            .is_err());
        assert_eq!(table.insert_count(), 4);

        // So do capacity changes, even when they evict every entry.
        table.set_dynamic_table_capacity(0).unwrap();
        table
            .set_dynamic_table_capacity(MAX_CAPACITY as u64)
            .unwrap();
        assert_eq!(table.insert_count(), 4);

        insert_small(&mut table, 4..5);
        assert_eq!(table.insert_count(), 5);
        assert_eq!(absolute(&table, 4), Some("key4"));
    }

    #[test]
    fn invalid_references() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity((2 * SMALL_ENTRY_SIZE) as u64)
            .unwrap();

        // An empty table has no entries to refer to.
        assert_eq!(table.duplicate(0), Err(TableError::InvalidReference));
        assert_eq!(
            table.insert_with_dynamic_name_reference(0, bytes("val")),
            Err(TableError::InvalidReference)
        );

        // Evicts "key0".
        insert_small(&mut table, 0..3);
        let before = snapshot(&table);

        // Relative index 2 refers to the evicted "key0", and larger ones to
        // entries that never existed.
        for index in [2, 3, u64::MAX] {
            assert_eq!(table.duplicate(index), Err(TableError::InvalidReference));
            assert_eq!(
                table.insert_with_dynamic_name_reference(index, bytes("val")),
                Err(TableError::InvalidReference)
            );
        }

        // The static table has 99 entries.
        for index in [99, u64::MAX] {
            assert_eq!(
                table.insert_with_static_name_reference(index, bytes("val")),
                Err(TableError::InvalidReference)
            );
        }

        assert_eq!(snapshot(&table), before);
    }

    #[test]
    fn static_name_reference_borrows_static_name() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity(MAX_CAPACITY as u64)
            .unwrap();

        // The first and last static table entries.
        assert_eq!(
            table.insert_with_static_name_reference(0, bytes("example.com")),
            Ok(())
        );
        assert_eq!(
            table.insert_with_static_name_reference(98, bytes("deny")),
            Ok(())
        );
        assert_eq!(contents(&table), [
            (":authority", "example.com"),
            ("x-frame-options", "deny")
        ]);
        assert_eq!(table.size(), (10 + 11 + 32) + (15 + 4 + 32));

        // Names taken from these entries keep borrowing the static table.
        table.duplicate(1).unwrap();
        table
            .insert_with_dynamic_name_reference(1, bytes("sameorigin"))
            .unwrap();
        assert_eq!(contents(&table)[2..], [
            (":authority", "example.com"),
            ("x-frame-options", "sameorigin")
        ]);

        assert!(table
            .entries
            .iter()
            .all(|e| matches!(e.name, EntryName::Static(_))));
    }

    #[test]
    fn entries_share_buffers() {
        let mut table = DynamicTable::new(MAX_CAPACITY);
        table
            .set_dynamic_table_capacity(MAX_CAPACITY as u64)
            .unwrap();

        let name = bytes("x-name");
        let value = bytes("x-value");
        table
            .insert_with_literal_name(name.clone(), value.clone())
            .unwrap();

        // A duplicate shares the name and the value with the original.
        table.duplicate(0).unwrap();

        // A dynamic name reference shares only the name.
        let other_value = bytes("other");
        table
            .insert_with_dynamic_name_reference(0, other_value.clone())
            .unwrap();

        for entry in &table.entries {
            assert!(Arc::ptr_eq(shared_name(entry), &name));
        }
        assert!(Arc::ptr_eq(&table.entries[0].value, &value));
        assert!(Arc::ptr_eq(&table.entries[1].value, &value));
        assert!(Arc::ptr_eq(&table.entries[2].value, &other_value));

        // Each entry is charged its full size, even with shared buffers.
        assert_eq!(table.size(), 2 * (6 + 7 + 32) + (6 + 5 + 32));
    }

    #[test]
    fn insert_evicting_referenced_entry_keeps_its_buffers() {
        let name = bytes("key0");
        let value = bytes("val0");

        let mut table = DynamicTable::new(MAX_CAPACITY);
        // With room for a single entry, each insertion below evicts the entry
        // it refers to.
        table
            .set_dynamic_table_capacity(SMALL_ENTRY_SIZE as u64)
            .unwrap();
        table
            .insert_with_literal_name(name.clone(), value.clone())
            .unwrap();

        assert_eq!(table.duplicate(0), Ok(()));
        assert_eq!(absolute(&table, 0), None);
        let entry = table.get_by_absolute_index(1).unwrap();
        assert!(Arc::ptr_eq(shared_name(entry), &name));
        assert!(Arc::ptr_eq(&entry.value, &value));
        // The evicted original released its handles, leaving only this test
        // and the duplicate holding the buffers.
        assert_eq!(Arc::strong_count(&name), 2);
        assert_eq!(Arc::strong_count(&value), 2);

        assert_eq!(
            table.insert_with_dynamic_name_reference(0, bytes("val1")),
            Ok(())
        );
        assert_eq!(absolute(&table, 1), None);
        let entry = table.get_by_absolute_index(2).unwrap();
        assert!(Arc::ptr_eq(shared_name(entry), &name));
        assert_eq!(entry.value(), b"val1");
        assert_eq!(Arc::strong_count(&name), 2);
        assert_eq!(Arc::strong_count(&value), 1);
    }
}
