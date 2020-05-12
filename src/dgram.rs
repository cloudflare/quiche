// Copyright (C) 2019, Cloudflare, Inc.
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

use std::collections::VecDeque;

use crate::Error;
use crate::Result;

const MAX_FRAME_COUNT: usize = 1000;

/// Keeps track of Datagram frames.
#[derive(Default)]
pub struct DatagramQueue {
    readable: VecDeque<Vec<u8>>,
    writable: VecDeque<Vec<u8>>,
}

impl DatagramQueue {
    pub fn new() -> Self {
        DatagramQueue {
            readable: VecDeque::new(),
            writable: VecDeque::new(),
        }
    }

    fn push(queue: &mut VecDeque<Vec<u8>>, data: &[u8]) -> Result<()> {
        if queue.len() == MAX_FRAME_COUNT {
            return Err(Error::Done);
        }

        queue.push_back(data.to_vec());
        Ok(())
    }

    fn peek(queue: &VecDeque<Vec<u8>>) -> Option<usize> {
        queue.front().map(|d| d.len())
    }

    fn pop(queue: &mut VecDeque<Vec<u8>>, buf: &mut [u8]) -> Result<usize> {
        match queue.front() {
            Some(d) =>
                if d.len() > buf.len() {
                    return Err(Error::BufferTooShort);
                },

            None => return Err(Error::Done),
        }

        if let Some(d) = queue.pop_front() {
            buf[..d.len()].copy_from_slice(&d);
            return Ok(d.len());
        }

        Err(Error::Done)
    }

    pub fn push_readable(&mut self, data: &[u8]) -> Result<()> {
        DatagramQueue::push(&mut self.readable, data)
    }

    #[allow(dead_code)]
    pub fn peek_readable(&self) -> Option<usize> {
        DatagramQueue::peek(&self.readable)
    }

    pub fn pop_readable(&mut self, buf: &mut [u8]) -> Result<usize> {
        DatagramQueue::pop(&mut self.readable, buf)
    }

    pub fn push_writable(&mut self, data: &[u8]) -> Result<()> {
        DatagramQueue::push(&mut self.writable, data)
    }

    pub fn peek_writable(&self) -> Option<usize> {
        DatagramQueue::peek(&self.writable)
    }

    pub fn has_writable(&self) -> bool {
        !&self.writable.is_empty()
    }

    pub fn pop_writable(&mut self, buf: &mut [u8]) -> Result<usize> {
        DatagramQueue::pop(&mut self.writable, buf)
    }
}
