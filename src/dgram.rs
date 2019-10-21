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

use crate::stream;

const MAX_FRAME_COUNT: usize = 1000;

/// Keeps track of Datagram frames.
#[derive(Default)]
pub struct DatagramQueue {
    pub readable: VecDeque<stream::RangeBuf>,
    pub writable: VecDeque<stream::RangeBuf>,
}

impl DatagramQueue {
    pub fn new() -> Self {
        DatagramQueue {
            readable: VecDeque::new(),
            writable: VecDeque::new(),
        }
    }

    pub fn push_readable(&mut self, data: stream::RangeBuf) -> Result<()> {
        if self.writable.len() == MAX_FRAME_COUNT {
            return Err(Error::Done);
        }

        self.readable.push_back(data);

        Ok(())
    }

    pub fn pop_readable(&mut self) -> Result<stream::RangeBuf> {
        match self.readable.pop_front() {
            Some(v) => Ok(v),

            None => Err(Error::Done),
        }
    }

    pub fn push_writable(&mut self, data: stream::RangeBuf) -> Result<()> {
        if self.writable.len() == MAX_FRAME_COUNT {
            return Err(Error::Done);
        }

        self.writable.push_back(data);

        Ok(())
    }

    pub fn peek_writable(&self) -> Option<usize> {
        let data = self.writable.front()?.as_ref();
        Some(data.len())
    }

    pub fn pop_writable(&mut self) -> Option<stream::RangeBuf> {
        self.writable.pop_front()

        // match self.writable.pop_front() {
        // Some(v) => Ok(v),
        //
        // None => Err(Error::Done)
        // }
    }
}
