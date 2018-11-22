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
use std::time;

use std::collections::BTreeMap;

use frame;
use polyfill;
use ranges;

pub struct Sent {
    pkt_num: u64,

    frames: Vec<frame::Frame>,

    timestamp: time::Instant,

    sent_bytes: usize,

    retransmittable: bool,

    crypto: bool,
}

pub struct Recovery {
    latest_rtt: u64,

    smoothed_rtt: u64,

    min_rtt: u64,

    rttvar: u64,
}

impl Recovery {
    pub fn on_packet_sent(&mut self, pkt_num: u64, frames: Vec<frame::Frame>,
                          sent_bytes: usize, retransmittable: bool, crypto: bool,
                          sent_pkt: &mut BTreeMap<u64, Sent>) {
        let pkt = Sent {
            pkt_num,
            frames,
            timestamp: time::Instant::now(),
            sent_bytes,
            retransmittable,
            crypto,
        };

        sent_pkt.insert(pkt_num, pkt);
    }

    pub fn on_ack_received(&mut self, ranges: &ranges::RangeSet, ack_delay: u64,
                           sent_pkt: &mut BTreeMap<u64, Sent>, trace_id: &str) {
        if ranges.iter().len() == 0 {
            return;
        }

        let largest_acked = ranges.flatten().next_back().unwrap();

        if let Some(pkt) = sent_pkt.get(&largest_acked) {
            let latest_rtt = pkt.timestamp.elapsed();

            self.latest_rtt = polyfill::duration_as_micros(&latest_rtt);
            self.update_rtt(ack_delay);
        }

        for pn in ranges.flatten().rev() {
            trace!("{} acked {}", trace_id, pn);

            if let None = sent_pkt.remove(&pn) {
                trace!("{} acked packet {} was not sent", trace_id, pn);
            }
        }

        // TODO: DetectLostPackets
        // TODO: SetLossDetectionTimer

        trace!("{} {:?}", trace_id, self);
    }

    fn update_rtt(&mut self, ack_delay: u64) {
        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);

        if self.latest_rtt - self.min_rtt > ack_delay {
            self.latest_rtt -= ack_delay;
        }

        if self.smoothed_rtt == 0 {
            self.smoothed_rtt = self.latest_rtt;
            self.rttvar = self.latest_rtt / 2;
        } else {
            let rttvar_sample = polyfill::sub_abs(self.smoothed_rtt,
                                                  self.latest_rtt);

            self.rttvar = ((3 * self.rttvar) + rttvar_sample) / 4;
            self.smoothed_rtt = ((7 * self.smoothed_rtt) + self.latest_rtt) / 8;
        }
    }
}

impl Default for Recovery {
    fn default() -> Recovery {
        Recovery {
            latest_rtt: 0,

            smoothed_rtt: 0,

            min_rtt: std::u64::MAX,

            rttvar: 0,
        }
    }
}

impl fmt::Debug for Recovery {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "updated rtt: latest={} smoothed={} min={} var={}",
               self.latest_rtt, self.smoothed_rtt, self.min_rtt, self.rttvar)
    }
}
