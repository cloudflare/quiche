// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use std::iter::FromIterator;
use std::ops::Range;

use std::collections::BTreeMap;
use std::collections::Bound;

use either::Either;
use smallvec::SmallVec;

const MAX_INLINE_CAPACITY: usize = 4;
const MIN_TO_INLINE: usize = 2;

/// A sorted collection of non overlapping [`u64`] ranges
#[derive(Clone, PartialEq, Eq, PartialOrd)]
pub enum RangeSet {
    Inline(InlineRangeSet),
    BTree(BTreeRangeSet),
}

/// A [`RangeSet`] variant backed by a [`SmallVec`] that is capable of storing
/// [`MAX_INLINE_CAPACITY`] of ranges without allocation
#[derive(Clone, PartialEq, Eq, PartialOrd)]
pub struct InlineRangeSet {
    inner: SmallVec<[(u64, u64); MAX_INLINE_CAPACITY]>,
    capacity: usize,
}

/// A [`RangeSet`] variant backed by a [`BTreeMap`] that is capable of storing
/// an arbitrary number of ranges
#[derive(Clone, PartialEq, Eq, PartialOrd)]
pub struct BTreeRangeSet {
    inner: BTreeMap<u64, u64>,
    capacity: usize,
}

impl RangeSet {
    /// Create a new [`RangeSet`].
    ///
    /// When the length of a [`RangeSet`] overflows `capacity` it will remove
    /// the smallest range.
    pub fn new(capacity: usize) -> Self {
        RangeSet::Inline(InlineRangeSet {
            inner: Default::default(),
            capacity,
        })
    }

    /// The number of nonoverlapping ranges stored in this [`RangeSet`].
    pub fn len(&self) -> usize {
        match self {
            RangeSet::Inline(set) => set.inner.len(),
            RangeSet::BTree(set) => set.inner.len(),
        }
    }

    /// Converts the inner representation from a BTree to Inline and vice versa
    /// when the proper conditions are met. Keeps the stored data intact.
    #[inline(always)]
    fn fixup(&mut self) {
        match self {
            RangeSet::Inline(set) if set.inner.len() == MAX_INLINE_CAPACITY => {
                let old_inner = std::mem::take(&mut set.inner);
                *self = RangeSet::BTree(BTreeRangeSet {
                    inner: old_inner.into_inner().expect("At capacity").into(),
                    capacity: set.capacity,
                });
            },

            RangeSet::BTree(set) if set.inner.len() <= MIN_TO_INLINE => {
                let old_inner = std::mem::take(&mut set.inner);
                *self = RangeSet::Inline(InlineRangeSet {
                    inner: SmallVec::from_iter(old_inner),
                    capacity: set.capacity,
                })
            },

            _ => {},
        }
    }

    /// Insert a new [`Range`] into the collection.
    ///
    /// If the [`Range`] overlaps with any existing range, it may be merged with
    /// one or more other [`Range`]s. If following the insertion the number of
    /// stored ranges overflows capacity, the smalles range will be removed.
    #[inline]
    pub fn insert(&mut self, item: Range<u64>) {
        match self {
            RangeSet::Inline(set) => set.insert(item),
            RangeSet::BTree(set) => set.insert(item),
        }

        self.fixup();
    }

    /// Iterate over the stored ranges in incremental order.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Range<u64>> + DoubleEndedIterator + ExactSizeIterator + '_
    {
        match self {
            RangeSet::BTree(set) =>
                Either::Left(set.inner.iter().map(|(k, v)| *k..*v)),

            RangeSet::Inline(set) =>
                Either::Right(set.inner.iter().map(|(s, e)| *s..*e)),
        }
    }

    /// Iterate over every single [`u64`] value covered by the ranges in this
    /// [`RangeSet`] in incremental order.
    pub fn flatten(
        &self,
    ) -> impl Iterator<Item = u64> + DoubleEndedIterator + '_ {
        match self {
            RangeSet::BTree(set) =>
                Either::Left(set.inner.iter().flat_map(|(k, v)| *k..*v)),

            RangeSet::Inline(set) =>
                Either::Right(set.inner.iter().flat_map(|(s, e)| *s..*e)),
        }
    }

    /// The smallest value covered by ranges in this collection.
    pub fn first(&self) -> Option<u64> {
        match self {
            RangeSet::Inline(set) => set.inner.first().map(|(s, _)| *s),

            RangeSet::BTree(set) => set.inner.first_key_value().map(|(k, _)| *k),
        }
    }

    /// The largest value covered by ranges in this collection.
    pub fn last(&self) -> Option<u64> {
        match self {
            RangeSet::Inline(set) => set.inner.last().map(|(_, e)| *e - 1),

            RangeSet::BTree(set) =>
                set.inner.last_key_value().map(|(_, v)| *v - 1),
        }
    }

    #[inline]
    pub fn remove_until(&mut self, largest: u64) {
        match self {
            RangeSet::Inline(set) => set.remove_until(largest),
            RangeSet::BTree(set) => set.remove_until(largest),
        }

        self.fixup();
    }

    pub fn push_item(&mut self, item: u64) {
        self.insert(item..item + 1)
    }
}

impl InlineRangeSet {
    fn insert(&mut self, item: Range<u64>) {
        let start = item.start;
        let mut end = item.end;
        let mut pos = 0;

        loop {
            match self.inner.get_mut(pos) {
                Some((s, e)) => {
                    if start > *e {
                        // Skip while start is greater than end
                        pos += 1;
                        continue;
                    }

                    if end < *s {
                        // Inserted range is entirely before this range. Insert
                        // and return.
                        if self.inner.len() == self.capacity {
                            self.inner.remove(0);
                            pos -= 1;
                        }

                        self.inner.insert(pos, (start, end));
                        return;
                    }

                    // At this point we know (start <= *e)
                    if start < *s {
                        // We know we are completely past the previous range, so
                        // we can simply adjust the lower bound
                        *s = start;
                    }

                    if end > *e {
                        // We adjusted the upper bound of an existing range, we
                        // must now check it does not overlap with the next range
                        *e = end;
                        break;
                    } else {
                        return;
                    }
                },

                None => {
                    if self.inner.len() == self.capacity {
                        self.inner.remove(0);
                    }

                    self.inner.push((start, end));
                    return;
                },
            }
        }

        // Merge any newly overlaping ranges
        while let Some((s, e)) = self.inner.get(pos + 1).copied() {
            if end < s {
                // We are done, since the next range is completely disjoint
                break;
            }

            let new_e = e.max(end);
            self.inner[pos].1 = new_e;
            end = new_e;
            self.inner.remove(pos + 1);
        }
    }

    fn remove_until(&mut self, largest: u64) {
        while let Some((s, e)) = self.inner.first_mut() {
            if largest >= *e {
                self.inner.remove(0);
                continue;
            }

            *s = (largest + 1).max(*s);
            if *s == *e {
                self.inner.remove(0);
            }

            break;
        }
    }
}

impl BTreeRangeSet {
    // TODO: use RangeInclusive
    fn insert(&mut self, item: Range<u64>) {
        let mut start = item.start;
        let mut end = item.end;

        // Check if preceding existing range overlaps with the new one.
        if let Some(r) = self.prev_to(start) {
            // New range overlaps with existing range in the set, merge them.
            if range_overlaps(&r, &item) {
                self.inner.remove(&r.start);

                start = std::cmp::min(start, r.start);
                end = std::cmp::max(end, r.end);
            }
        }

        // Check if following existing ranges overlap with the new one.
        while let Some(r) = self.next_to(start) {
            // Existing range is fully contained in the new range, remove it.
            if item.contains(&r.start) && item.contains(&r.end) {
                self.inner.remove(&r.start);
                continue;
            }

            // New range doesn't overlap anymore, we are done.
            if !range_overlaps(&r, &item) {
                break;
            }

            // New range overlaps with existing range in the set, merge them.
            self.inner.remove(&r.start);

            start = std::cmp::min(start, r.start);
            end = std::cmp::max(end, r.end);
        }

        if self.inner.len() >= self.capacity {
            self.inner.pop_first();
        }

        self.inner.insert(start, end);
    }

    fn remove_until(&mut self, largest: u64) {
        let ranges: Vec<Range<u64>> = self
            .inner
            .range((Bound::Unbounded, Bound::Included(&largest)))
            .map(|(&s, &e)| (s..e))
            .collect();

        for r in ranges {
            self.inner.remove(&r.start);

            if r.end > largest + 1 {
                let start = largest + 1;
                self.insert(start..r.end);
            }
        }
    }

    fn prev_to(&self, item: u64) -> Option<Range<u64>> {
        self.inner
            .range((Bound::Unbounded, Bound::Included(item)))
            .map(|(&s, &e)| (s..e))
            .next_back()
    }

    fn next_to(&self, item: u64) -> Option<Range<u64>> {
        self.inner
            .range((Bound::Included(item), Bound::Unbounded))
            .map(|(&s, &e)| (s..e))
            .next()
    }
}

impl Default for RangeSet {
    fn default() -> Self {
        RangeSet::Inline(InlineRangeSet {
            inner: Default::default(),
            capacity: usize::MAX,
        })
    }
}

// This implements comparison between `BTreeRangeSet` and standard `Range`. The
// idea is that a `RangeSet` with no gaps (i.e. that only contains a single
// range) is basically equvalent to a normal `Range` so they should be
// comparable.
impl PartialEq<Range<u64>> for RangeSet {
    fn eq(&self, other: &Range<u64>) -> bool {
        // If there is more than one range it means that the range set is not
        // contiguous, so can't be equal to a single range.
        if self.len() != 1 {
            return false;
        }

        // Get the first and only range in the set.
        let range = self.iter().next().unwrap();
        range == *other
    }
}

impl std::fmt::Debug for RangeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ranges: Vec<Range<u64>> = self
            .iter()
            .map(|mut r| {
                r.end -= 1;
                r
            })
            .collect();

        write!(f, "{ranges:?}")
    }
}

fn range_overlaps(r: &Range<u64>, other: &Range<u64>) -> bool {
    other.start >= r.start && other.start <= r.end ||
        other.end >= r.start && other.end <= r.end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_non_overlapping() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);

        r.insert(4..7);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6]);

        r.insert(9..12);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
    }

    #[test]
    fn insert_contained() {
        let mut r = RangeSet::default();

        r.insert(4..7);
        r.insert(9..12);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(4..7);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(4..6);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(5..6);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(10..11);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(9..11);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
    }

    #[test]
    fn insert_overlapping() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(9..12);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[3, 4, 5, 9, 10, 11]);

        r.insert(5..7);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[3, 4, 5, 6, 9, 10, 11]);

        r.insert(10..15);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 6, 9, 10, 11, 12, 13, 14
        ]);

        r.insert(2..5);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14
        ]);

        r.insert(8..10);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14
        ]);

        r.insert(6..10);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
        ]);
    }

    #[test]
    fn insert_overlapping_multi() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(16..20);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 16, 17, 18, 19
        ]);

        r.insert(10..11);
        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 10, 16, 17, 18, 19
        ]);

        assert!(matches!(r, RangeSet::Inline(_)));

        r.insert(13..14);
        assert_eq!(r.len(), 4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 10, 13, 16, 17, 18, 19
        ]);

        // Make sure it converted to a btree at capacity
        assert!(matches!(r, RangeSet::BTree(_)));

        r.insert(4..17);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19
        ]);

        // Make sure it converted back to inline
        assert!(matches!(r, RangeSet::Inline(_)));
    }

    #[test]
    fn prev_to() {
        let mut r = BTreeRangeSet {
            inner: Default::default(),
            capacity: usize::MAX,
        };

        r.insert(4..7);
        r.insert(9..12);

        assert_eq!(r.prev_to(2), None);
        assert_eq!(r.prev_to(4), Some(4..7));
        assert_eq!(r.prev_to(15), Some(9..12));
        assert_eq!(r.prev_to(5), Some(4..7));
        assert_eq!(r.prev_to(8), Some(4..7));
    }

    #[test]
    fn next_to() {
        let mut r = BTreeRangeSet {
            inner: Default::default(),
            capacity: usize::MAX,
        };

        r.insert(4..7);
        r.insert(9..12);

        assert_eq!(r.next_to(2), Some(4..7));
        assert_eq!(r.next_to(12), None);
        assert_eq!(r.next_to(15), None);
        assert_eq!(r.next_to(5), Some(9..12));
        assert_eq!(r.next_to(8), Some(9..12));
    }

    #[test]
    fn push_item() {
        let mut r = RangeSet::default();

        r.insert(4..7);
        r.insert(9..12);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.push_item(15);
        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            4, 5, 6, 9, 10, 11, 15
        ]);

        r.push_item(15);
        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            4, 5, 6, 9, 10, 11, 15
        ]);

        r.push_item(1);
        assert_eq!(r.len(), 4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 4, 5, 6, 9, 10, 11, 15
        ]);

        r.push_item(12);
        r.push_item(13);
        r.push_item(14);

        assert_eq!(r.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
        ]);

        r.push_item(2);
        r.push_item(3);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15
        ]);

        r.push_item(8);
        r.push_item(7);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
        ]);
    }

    #[test]
    fn flatten_rev() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);

        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);

        r.insert(4..7);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[6, 5, 4]);

        r.insert(9..12);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[
            11, 10, 9, 6, 5, 4
        ]);
    }

    #[test]
    fn flatten_one() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);

        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);

        r.insert(0..1);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[0]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[0]);
    }

    #[test]
    fn remove_largest() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(9..11);
        r.insert(13..14);
        r.insert(16..20);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            3, 4, 5, 9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            5, 9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(6);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[
            9, 10, 13, 16, 17, 18, 19
        ]);

        r.remove_until(10);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[13, 16, 17, 18, 19]);

        r.remove_until(17);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[18, 19]);

        r.remove_until(18);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[19]);

        r.remove_until(20);

        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);
    }

    #[test]
    fn eq_range() {
        let mut r = RangeSet::default();
        assert_ne!(r, 0..0);

        let expected = 3..20;

        r.insert(3..6);
        assert_ne!(r, expected);

        r.insert(16..20);
        assert_ne!(r, expected);

        r.insert(10..11);
        assert_ne!(r, expected);

        r.insert(13..14);
        assert_ne!(r, expected);

        r.insert(4..17);

        assert_eq!(r, expected);
    }

    #[test]
    fn first_last() {
        let mut r = RangeSet::default();
        assert_eq!(r.first(), None);
        assert_eq!(r.last(), None);

        r.insert(10..11);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(10));

        r.insert(13..14);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(13));

        r.insert(3..6);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(13));

        r.insert(16..20);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(19));

        r.insert(4..17);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(19));
    }

    #[test]
    fn capacity() {
        let mut r = RangeSet::new(3);
        assert_eq!(r.first(), None);
        assert_eq!(r.last(), None);

        r.insert(10..11);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(10));

        r.insert(13..14);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(13));

        r.insert(3..6);
        assert_eq!(r.first(), Some(3));
        assert_eq!(r.last(), Some(13));

        r.insert(16..20);
        assert_eq!(r.first(), Some(10));
        assert_eq!(r.last(), Some(19));

        r.insert(4..17);
        assert_eq!(r.first(), Some(4));
        assert_eq!(r.last(), Some(19));
    }
}
