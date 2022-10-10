// Copyright (C) 2022, Cloudflare, Inc.
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

//! Pacer provides the timestamp for the next packet to be sent based on the
//! current send_quantum, pacing rate and last updated time.
//!
//! It's a kind of leaky bucket algorithm (RFC9002, 7.7 Pacing) but it considers
//! max burst (send_quantum, in bytes) and provide the same timestamp for the
//! same sized packets (except last one) to be GSO friendly, assuming we send
//! packets using multiple sendmsg(), a sendmmsg(), or sendmsg() with GSO
//! without waiting for new I/O events.
//!
//! After sending a burst of packets, the next timestamp will be updated based
//! on the current pacing rate. It will make actual timestamp sent and recorded
//! timestamp (Sent.time_sent) as close as possible. If GSO is not used, it will
//! still try to provide close timestamp if the send burst is implemented.

use std::time::Duration;
use std::time::Instant;

#[derive(Debug)]
pub struct Pacer {
    /// Whether pacing is enabled.
    enabled: bool,

    /// Bucket capacity (bytes).
    capacity: usize,

    /// Bucket used (bytes).
    used: usize,

    /// Sending pacing rate (bytes/sec).
    rate: u64,

    /// Timestamp of the last packet sent time update.
    last_update: Instant,

    /// Timestamp of the next packet to be sent.
    next_time: Instant,

    /// Current MSS.
    max_datagram_size: usize,

    /// Last packet size.
    last_packet_size: Option<usize>,

    /// Interval to be added in next burst.
    iv: Duration,
}

impl Pacer {
    pub fn new(
        enabled: bool, capacity: usize, rate: u64, max_datagram_size: usize,
    ) -> Self {
        // Round capacity to MSS.
        let capacity = capacity / max_datagram_size * max_datagram_size;

        Pacer {
            enabled,

            capacity,

            used: 0,

            rate,

            last_update: Instant::now(),

            next_time: Instant::now(),

            max_datagram_size,

            last_packet_size: None,

            iv: Duration::ZERO,
        }
    }

    /// Returns whether pacing is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the current pacing rate.
    pub fn rate(&self) -> u64 {
        self.rate
    }

    /// Updates the bucket capacity or pacing_rate.
    pub fn update(&mut self, capacity: usize, rate: u64, now: Instant) {
        let capacity = capacity / self.max_datagram_size * self.max_datagram_size;

        if self.capacity != capacity {
            self.reset(now);
        }

        self.capacity = capacity;

        self.rate = rate;
    }

    /// Resets the pacer for the next burst.
    pub fn reset(&mut self, now: Instant) {
        self.used = 0;

        self.last_update = now;

        self.next_time = self.next_time.max(now);

        self.last_packet_size = None;

        self.iv = Duration::ZERO;
    }

    /// Updates the timestamp for the packet to send.
    pub fn send(&mut self, packet_size: usize, now: Instant) {
        if self.rate == 0 {
            self.reset(now);

            return;
        }

        if !self.iv.is_zero() {
            self.next_time = self.next_time.max(now) + self.iv;

            self.iv = Duration::ZERO;
        }

        let interval =
            Duration::from_secs_f64(self.capacity as f64 / self.rate as f64);

        let elapsed = now.saturating_duration_since(self.last_update);

        // If too old, reset it.
        if elapsed > interval {
            self.reset(now);
        }

        self.used += packet_size;

        let same_size = if let Some(last_packet_size) = self.last_packet_size {
            last_packet_size == packet_size
        } else {
            true
        };

        self.last_packet_size = Some(packet_size);

        if self.used >= self.capacity || !same_size {
            self.iv =
                Duration::from_secs_f64(self.used as f64 / self.rate as f64);

            self.used = 0;

            self.last_update = now;

            self.last_packet_size = None;
        };
    }

    /// Returns the timestamp for the next packet.
    pub fn next_time(&self) -> Instant {
        self.next_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_update() {
        let datagram_size = 1200;
        let max_burst = datagram_size * 10;
        let pacing_rate = 100_000;

        let mut p = Pacer::new(true, max_burst, pacing_rate, datagram_size);

        let now = Instant::now();

        // Send 6000 (half of max_burst) -> no timestamp change yet.
        p.send(6000, now);

        assert!(now.duration_since(p.next_time()) < Duration::from_millis(1));

        // Send 6000 bytes -> max_burst filled.
        p.send(6000, now);

        assert!(now.duration_since(p.next_time()) < Duration::from_millis(1));

        // Start of a new burst.
        let now = now + Duration::from_millis(5);

        // Send 1000 bytes and next_time is updated.
        p.send(1000, now);

        let interval = max_burst as f64 / pacing_rate as f64;

        assert_eq!(p.next_time() - now, Duration::from_secs_f64(interval));
    }

    #[test]
    /// Same as pacer_update() but adds some idle time between transfers to
    /// trigger a reset.
    fn pacer_idle() {
        let datagram_size = 1200;
        let max_burst = datagram_size * 10;
        let pacing_rate = 100_000;

        let mut p = Pacer::new(true, max_burst, pacing_rate, datagram_size);

        let now = Instant::now();

        // Send 6000 (half of max_burst) -> no timestamp change yet.
        p.send(6000, now);

        assert!(now.duration_since(p.next_time()) < Duration::from_millis(1));

        // Sleep 200ms to reset the idle pacer (at least 120ms).
        let now = now + Duration::from_millis(200);

        // Send 6000 bytes -> idle reset and a new burst  isstarted.
        p.send(6000, now);

        assert_eq!(p.next_time(), now);
    }
}
