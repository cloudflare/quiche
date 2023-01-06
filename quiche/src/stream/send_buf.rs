use std::collections::VecDeque;

use crate::ranges::RangeSet;

use crate::Error;
use crate::Result;

/// Send-side stream buffer.
///
/// Stream data scheduled to be sent to the peer and is buffered in a circular
/// buffer.
#[derive(Debug, Default)]
pub struct SendBuf {
    /// A circular buffer that stores the data that should be sent to the peer
    pub(super) data: VecDeque<u8>,
    /// The index of the `data` buffer in the stream
    pos: usize,
    /// The maximum offset of data buffered in the stream.
    off: u64,
    /// The maximum offset we are allowed to send to the peer.
    pub(super) max_data: u64,
    /// The last offset the stream was blocked at, if any.
    blocked_at: Option<u64>,
    /// The final stream offset written to the stream, if any.
    fin_off: Option<u64>,
    /// Whether the stream's send-side has been shut down.
    shutdown: bool,
    /// Ranges of data offsets that have been acked.
    acked: RangeSet,
    /// Ranges of data that are either acked, or are in-flight, and shouldn't be
    /// currently sent to the peer.
    acked_or_inflight: RangeSet,
    /// The error code received via STOP_SENDING.
    error: Option<u64>,
    /// The maximum offset of data ever sent
    max_sent: u64,
}

pub struct PlannedPacket<'a> {
    buf: &'a mut SendBuf,
    pub offset: u64,
    pub max_len: u64,
}

impl<'a> PlannedPacket<'a> {
    pub fn emit(self, out: &mut [u8]) -> Result<(usize, bool)> {
        let send_buf = self.buf;

        let to_copy = (self.max_len as usize).min(out.len());
        send_buf.copy_to_slice(out, self.offset as usize, to_copy);

        let fin = Some(self.offset + to_copy as u64) == send_buf.fin_off;

        send_buf
            .acked_or_inflight
            .insert(self.offset..(self.offset + to_copy as u64));

        send_buf.max_sent = send_buf.max_sent.max(self.offset + to_copy as u64);
        Ok((to_copy, fin))
    }
}

impl SendBuf {
    /// Creates a new send buffer.
    pub(super) fn new(max_data: u64) -> SendBuf {
        SendBuf {
            max_data,
            ..SendBuf::default()
        }
    }

    /// Find the offset of the next packet to emit, and the maximal number of
    /// bytes available to send.
    pub fn plan_packet(&mut self) -> PlannedPacket<'_> {
        let mut sent = self.acked_or_inflight.iter();
        // Find the next gap in the sent intervals.
        let first_interval = sent.next();
        let not_sent_start = first_interval
            .as_ref()
            .map(|r| if r.start == 0 { r.end } else { 0 } as usize)
            .unwrap_or(self.pos)
            .min(self.fin_off.unwrap_or(u64::MAX) as usize);

        let not_sent_end = if not_sent_start == 0 {
            first_interval.map(|r| r.start as usize)
        } else {
            sent.next().map(|r| r.start as usize)
        }
        .unwrap_or(self.pos + self.data.len())
        .min(self.fin_off.unwrap_or(u64::MAX) as usize);

        drop(sent); // Unborrow self
        PlannedPacket {
            buf: self,
            offset: not_sent_start as u64,
            max_len: (not_sent_end - not_sent_start) as u64,
        }
    }

    /// Inserts the given slice of data at the end of the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes).
    pub fn write(&mut self, mut data: &[u8], mut fin: bool) -> Result<usize> {
        let max_off = self.off + data.len() as u64;
        // Get the stream send capacity. This will return an error if the stream
        // was stopped.
        let capacity = self.cap()?;
        if data.len() > capacity {
            // Truncate the input buffer according to the stream's capacity.
            let len = capacity;
            data = &data[..len];
            // We are not buffering the full input, so clear the fin flag.
            fin = false;
        }

        if let Some(fin_off) = self.fin_off {
            // Can't write past final offset.
            if max_off > fin_off {
                return Err(Error::FinalSize);
            }

            // Can't "undo" final offset.
            if max_off == fin_off && !fin {
                return Err(Error::FinalSize);
            }
        }

        self.data.extend(data);
        self.off += data.len() as u64;

        if fin {
            self.fin_off = Some(max_off);
        }

        Ok(data.len())
    }

    fn copy_to_slice(&self, out: &mut [u8], start: usize, len: usize) {
        let start = match start.checked_sub(self.pos) {
            None => return,
            Some(start) => start,
        };

        let (a, b) = self.data.as_slices();
        if start >= a.len() {
            let start = start - a.len();
            // All the data is in the second half
            out[..len].copy_from_slice(&b[start..start + len]);
            return;
        }

        // First copy as many as possible from `a`
        let from_a = len.min(a.len() - start);
        out[..from_a].copy_from_slice(&a[start..start + from_a]);
        if let Some(from_b) = len.checked_sub(from_a) {
            // Copy remaining from `b`
            out[from_a..from_a + from_b].copy_from_slice(&b[..from_b]);
        }
    }

    /// Writes data from the send buffer into the given output buffer.
    pub fn emit(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        self.plan_packet().emit(out)
    }

    /// Updates the max_data limit to the given value.
    pub fn update_max_data(&mut self, max_data: u64) {
        self.max_data = self.max_data.max(max_data);
    }

    /// Updates the last offset the stream was blocked at, if any.
    pub fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }

    /// The last offset the stream was blocked at, if any.
    pub fn blocked_at(&self) -> Option<u64> {
        self.blocked_at
    }

    pub fn ack(&mut self, off: u64, len: usize) {
        let acked_range = off..off + len as u64;
        self.acked_or_inflight.insert(acked_range.clone()); // Shouldn't do anything, as packets that are acked, must already be
                                                            // inflight
        self.acked.insert(acked_range);

        if let Some(advance) = self
            .acked
            .iter()
            .next()
            .and_then(|r| (r.end as usize).checked_sub(self.pos))
        {
            let advance = advance.min(self.data.len());
            self.data.drain(..advance);
            self.pos += advance;
            if Some(self.pos as u64) == self.fin_off {
                // All data was received, drop the buffer
                std::mem::take(&mut self.data);
            }
        }
    }

    pub fn ack_and_drop(&mut self, off: u64, len: usize) {
        self.ack(off, len);
    }

    pub fn retransmit(&mut self, off: u64, len: usize) {
        match self.pos.checked_sub(off as usize) {
            Some(diff) => {
                // Current fully acked position is already passed the
                // retransmitted offset, adjust accordingly
                if diff >= len {
                    return;
                }
                let off = off - diff as u64;
                let len = len - diff;
                self.acked_or_inflight.remove(off..off + len as u64);
            },
            None => {
                self.acked_or_inflight.remove(off..off + len as u64);
            },
        }
    }

    /// Resets the stream at the current offset and clears all buffered data.
    fn reset(&mut self) -> Result<(u64, u64)> {
        let unsent_off = self.max_sent;
        let unsent_len = self.off_back() - unsent_off;

        self.fin_off = Some(unsent_off);

        // Drop all buffered data, note that clear does not free the allocated
        // capacity.
        std::mem::take(&mut self.data);

        // Mark all data as acked.
        self.ack(0, self.off as usize);

        Ok((self.fin_off.unwrap(), unsent_len))
    }

    /// Resets the streams and records the received error code.
    ///
    /// Calling this again after the first time has no effect.
    pub fn stop(&mut self, error_code: u64) -> Result<(u64, u64)> {
        if self.error.is_some() {
            return Err(Error::Done);
        }

        let (fin_off, unsent) = self.reset()?;

        self.error = Some(error_code);

        Ok((fin_off, unsent))
    }

    /// Shuts down sending data.
    pub fn shutdown(&mut self) -> Result<(u64, u64)> {
        if self.shutdown {
            return Err(Error::Done);
        }

        self.shutdown = true;

        self.reset()
    }

    /// Returns the largest offset of data buffered.
    pub fn off_back(&self) -> u64 {
        (self.pos + self.data.len()) as u64
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        self.acked_or_inflight
            .iter()
            .next()
            .map(|r| if r.start == 0 { r.end } else { 0 })
            .unwrap_or(self.pos as u64)
    }

    /// The maximum offset we are allowed to send to the peer.
    pub fn max_off(&self) -> u64 {
        self.max_data
    }

    /// Returns true if all data in the stream has been sent.
    ///
    /// This happens when the stream's send final size is known, and the
    /// application has already written data up to that point.
    pub fn is_fin(&self) -> bool {
        if self.fin_off == Some(self.off) {
            return true;
        }

        false
    }

    /// Returns true if the send-side of the stream is complete.
    ///
    /// This happens when the stream's send final size is known, and the peer
    /// has already acked all stream data up to that point.
    pub fn is_complete(&self) -> bool {
        if let Some(fin_off) = self.fin_off {
            if self.acked == (0..fin_off) {
                return true;
            }
        }

        false
    }

    /// Returns true if the stream was stopped before completion.
    pub fn is_stopped(&self) -> bool {
        self.error.is_some()
    }

    /// Returns true if there is data to be written.
    pub(super) fn ready(&self) -> bool {
        !self.data.is_empty() && self.off_front() < self.off
    }

    /// Returns the outgoing flow control capacity.
    pub fn cap(&self) -> Result<usize> {
        // The stream was stopped, so return the error code instead.
        if let Some(e) = self.error {
            return Err(Error::StreamStopped(e));
        }

        Ok((self.max_data - self.off) as usize)
    }

    pub(super) fn is_writable(&self) -> bool {
        !self.shutdown && !self.is_fin() && self.off < self.max_data
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.data.len() + self.pos - self.off_front() as usize
    }
}
