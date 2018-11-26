// Copyright (c) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
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

use std::cmp;
use std::fmt;
use std::ops::Range;

use std::collections::Bound::{Excluded, Included, Unbounded};

use std::collections::btree_map;
use std::collections::BTreeMap;

#[derive(Clone, Default, PartialEq, PartialOrd)]
pub struct RangeSet {
    inner: BTreeMap<u64, u64>,
}

impl RangeSet {
    pub fn insert(&mut self, item: Range<u64>) {
        let mut start = item.start;
        let mut end = item.end;

        if let Some(r) = self.prev_to(start) {
            if range_contains(&r, start) && range_contains(&r, end) {
                return;
            }

            if range_contains(&r, start) && !range_contains(&r, end) {
                self.inner.remove(&r.start);
                start = cmp::min(start, r.start);
            }

            if !range_contains(&r, start) && range_contains(&r, end) {
                self.inner.remove(&r.start);
                end = cmp::max(end, r.end);
            }
        }

        while let Some(r) = self.next_to(start) {
            if range_contains(&r, start) && range_contains(&r, end) {
                return;
            }

            if range_contains(&item, r.start) &&
               range_contains(&item, r.end) {
                self.inner.remove(&r.start);
                continue;
            }

            if range_contains(&r, start) && !range_contains(&r, end) {
                self.inner.remove(&r.start);
                start = cmp::min(start, r.start);
            }

            if !range_contains(&r, start) && range_contains(&r, end) {
                self.inner.remove(&r.start);
                end = cmp::max(end, r.end);
            }

            if !range_contains(&r, start) && !range_contains(&r, end) {
                break;
            }
        }

        self.inner.insert(start, end);
    }

    pub fn remove_until(&mut self, largest: u64) {
        let ranges: Vec<(u64, u64)> =
            self.inner
                .range((Included(&0), Included(&largest)))
                .map(|(s, e)| (*s, *e))
                .collect();

        for (start, end) in ranges {
            self.inner.remove(&start);

            if end > largest + 1 {
                let start = largest + 1;
                self.insert(Range { start, end });
            }
        }
    }

    pub fn push_item(&mut self, item: u64) {
        let r = Range {
            start: item,
            end: item + 1,
        };

        self.insert(r);
    }

    pub fn smallest(&self) -> Option<u64> {
        self.flatten().next()
    }

    pub fn largest(&self) -> Option<u64> {
        self.flatten().next_back()
    }

    pub fn iter(&self) -> Iter {
        Iter {
            inner: self.inner.iter(),
        }
    }

    pub fn flatten(&self) -> Flatten {
        Flatten {
            inner: self.inner.iter(),
            next: 0,
            end: 0,
        }
    }

    fn prev_to(&self, item: u64) -> Option<Range<u64>> {
        match self.inner.range((Unbounded, Included(item))).next_back() {
            Some((start, end)) => Some(*start..*end),
            None => None,
        }
    }

    fn next_to(&self, item: u64) -> Option<Range<u64>> {
        match self.inner.range((Included(item), Unbounded)).next() {
            Some((start, end)) => Some(*start..*end),
            None => None,
        }
    }
}

impl fmt::Debug for RangeSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.iter().map(|mut r| { r.end -= 1; r })
                                     .collect::<Vec<Range<u64>>>())
    }
}

pub struct Iter<'a> {
    inner: btree_map::Iter<'a, u64, u64>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Range<u64>> {
        let (&start, &end) = self.inner.next()?;
        Some(start..end)
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<Range<u64>> {
        let (&start, &end) = self.inner.next_back()?;
        Some(start..end)
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

pub struct Flatten<'a> {
    inner: btree_map::Iter<'a, u64, u64>,
    next: u64,
    end: u64,
}

impl<'a> Iterator for Flatten<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.next == self.end {
            let (&start, &end) = self.inner.next()?;

            self.next = start;
            self.end = end;
        }

        let next = self.next;
        self.next += 1;

        Some(next)
    }
}

impl<'a> DoubleEndedIterator for Flatten<'a> {
    fn next_back(&mut self) -> Option<u64> {
        if self.next == self.end {
            let (&start, &end) = self.inner.next_back()?;

            self.next = start;
            self.end = end;
        }

        self.end -= 1;

        Some(self.end)
    }
}

fn range_contains(r: &Range<u64>, item: u64) -> bool {
    (match Included(r.start) {
        Included(start) => start <= item,
        Excluded(start) => start < item,
        Unbounded => true,
    })
    &&
    (match Included(r.end) {
        Included(end) => item <= end,
        Excluded(end) => item < end,
        Unbounded => true,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_non_overlapping() {
        let mut r = RangeSet::default();
        assert_eq!(r.inner.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[]);

        r.insert(4..7);
        assert_eq!(r.inner.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6]);

        r.insert(9..12);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
    }

    #[test]
    fn insert_contained() {
        let mut r = RangeSet::default();

        r.insert(4..7);
        r.insert(9..12);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(4..7);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(4..6);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(5..6);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(10..11);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.insert(9..11);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
    }

    #[test]
    fn insert_overlapping() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(9..12);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[3, 4, 5, 9, 10, 11]);

        r.insert(5..7);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 6, 9, 10, 11]);

        r.insert(10..15);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 6, 9, 10, 11, 12, 13, 14]);

        r.insert(2..5);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14]);

        r.insert(8..10);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14]);

        r.insert(6..10);
        assert_eq!(r.inner.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    }

    #[test]
    fn insert_overlapping_multi() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(16..20);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 16, 17, 18, 19]);

        r.insert(10..11);
        assert_eq!(r.inner.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 10, 16, 17, 18, 19]);

        r.insert(13..14);
        assert_eq!(r.inner.len(), 4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 10, 13, 16, 17, 18, 19]);

        r.insert(4..17);
        assert_eq!(r.inner.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
    }

    #[test]
    fn prev_to() {
        let mut r = RangeSet::default();

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
        let mut r = RangeSet::default();

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
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);

        r.push_item(15);
        assert_eq!(r.inner.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[4, 5, 6, 9, 10, 11, 15]);

        r.push_item(15);
        assert_eq!(r.inner.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[4, 5, 6, 9, 10, 11, 15]);

        r.push_item(1);
        assert_eq!(r.inner.len(), 4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[1, 4, 5, 6, 9, 10, 11, 15]);

        r.push_item(12);
        r.push_item(13);
        r.push_item(14);
        assert_eq!(r.inner.len(), 3);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[1, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15]);

        r.push_item(2);
        r.push_item(3);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15]);

        r.push_item(8);
        r.push_item(7);
        assert_eq!(r.inner.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn flatten_rev() {
        let mut r = RangeSet::default();
        assert_eq!(r.inner.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[]);

        r.insert(4..7);
        assert_eq!(r.inner.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[6, 5, 4]);

        r.insert(9..12);
        assert_eq!(r.inner.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[4, 5, 6, 9, 10, 11]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(),
                   &[11, 10, 9, 6, 5, 4]);
    }

    #[test]
    fn remove_largest() {
        let mut r = RangeSet::default();

        r.insert(3..6);
        r.insert(9..11);
        r.insert(13..14);
        r.insert(16..20);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 9, 10, 13, 16, 17, 18, 19]);

        r.remove_until(2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[3, 4, 5, 9, 10, 13, 16, 17, 18, 19]);

        r.remove_until(4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[5, 9, 10, 13, 16, 17, 18, 19]);

        r.remove_until(6);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[9, 10, 13, 16, 17, 18, 19]);

        r.remove_until(10);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[13, 16, 17, 18, 19]);

        r.remove_until(17);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(),
                   &[18, 19]);

        r.remove_until(20);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[]);
    }
}
