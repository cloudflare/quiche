// Copyright (C) 2020, Cloudflare, Inc.
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

use crate::Error;
use crate::Result;

use std::collections::VecDeque;

/// Keeps track of DATAGRAM frames.
#[derive(Default)]
pub struct DatagramQueue {
    queue: Option<VecDeque<Vec<u8>>>,
    queue_max_len: usize,
    queue_bytes_size: usize,
}

impl DatagramQueue {
    pub fn new(queue_max_len: usize) -> Self {
        DatagramQueue {
            queue: None,
            queue_bytes_size: 0,
            queue_max_len,
        }
    }

    pub fn push(&mut self, data: Vec<u8>) -> Result<()> {
        if self.is_full() {
            return Err(Error::Done);
        }

        self.queue_bytes_size += data.len();
        self.queue
            .get_or_insert_with(Default::default)
            .push_back(data);

        Ok(())
    }

    pub fn peek_front_len(&self) -> Option<usize> {
        self.queue.as_ref().and_then(|q| q.front().map(|d| d.len()))
    }

    pub fn peek_front_bytes(&self, buf: &mut [u8], len: usize) -> Result<usize> {
        match self.queue.as_ref().and_then(|q| q.front()) {
            Some(d) => {
                let len = std::cmp::min(len, d.len());
                if buf.len() < len {
                    return Err(Error::BufferTooShort);
                }

                buf[..len].copy_from_slice(&d[..len]);
                Ok(len)
            },

            None => Err(Error::Done),
        }
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        if let Some(d) = self.queue.as_mut().and_then(|q| q.pop_front()) {
            self.queue_bytes_size = self.queue_bytes_size.saturating_sub(d.len());
            return Some(d);
        }

        None
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.as_ref().map(|q| q.is_empty()).unwrap_or(true)
    }

    pub fn purge<F: Fn(&[u8]) -> bool>(&mut self, f: F) {
        if let Some(q) = self.queue.as_mut() {
            q.retain(|d| !f(d));
            self.queue_bytes_size = q.iter().fold(0, |total, d| total + d.len());
        }
    }

    pub fn is_full(&self) -> bool {
        self.len() == self.queue_max_len
    }

    pub fn len(&self) -> usize {
        self.queue.as_ref().map(|q| q.len()).unwrap_or(0)
    }

    pub fn byte_size(&self) -> usize {
        self.queue_bytes_size
    }
}
