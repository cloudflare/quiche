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

use super::stream;

use std::collections::HashMap;

const MAX_PROTECTED_STREAM_ID_OFFSET: u64 = 14;
const PRIORITY_SCALE_FACTOR: u64 = 2000;

/// An Extensible Priority.
///
/// This holds the extensible priority parameters, with methods for
/// serialization, deserialization and conversion to quiche's stream priority
/// space.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Priority {
    /// Urgency.
    pub urgency: u8,
    /// Incremental.
    pub incremental: bool,
    /// Preempt.
    pub preempt: bool,
}

impl Default for Priority {
    fn default() -> Self {
        Priority {
            urgency: 1,
            incremental: false,
            preempt: false,
        }
    }
}

impl Priority {
    /// Converts from the priority wire format.
    pub fn from_wire(priority_field: &str) -> Self {
        let mut priority = Priority::default();

        for param in priority_field.split(',') {
            if param.trim() == "i" {
                priority.incremental = true;
            }

            if param.trim().starts_with("u=") {
                // u is an sh-integer (an i64) but it has a constrained range of
                // 0-7. So detect anything outside that range and clamp it to
                // the lowest priority in order to avoid it interfering with
                // valid items.
                //
                // TODO: this also detects when u is not an
                // sh-integer and clamps it in the same way. A real structured
                // header parser would actually fail to parse.
                let mut u =
                    i64::from_str_radix(param.rsplit('=').next().unwrap(), 10)
                        .unwrap_or(7);

                if u < 0 || u > 7 {
                    u = 7
                };

                priority.urgency = u as u8;
            }
        }

        priority
    }

    /// Converts to the priority wire format.
    pub fn to_wire(self) -> String {
        let mut response_priority = format!("u={}", self.urgency);
        if self.incremental {
            response_priority.push_str(",i");
        }

        response_priority
    }

    /// Converts to the quiche stream priority.
    pub fn to_quiche(
        self, stream_id: u64, streams: &HashMap<u64, stream::Stream>,
    ) -> u64 {
        let mut stream_alias = stream_id;

        if stream_id % 4 != 0 && stream_id <= MAX_PROTECTED_STREAM_ID_OFFSET {
            return stream_id;
        }

        // Incremental streams need to be handled specially so they don't get
        // round-robined with non-incremental streams of the same urgency.
        //
        // Depending on the application, it may prefer to send the
        // non-incremental bytes before or after the incremental ones. This is
        // signalled with the the preempt parameter.
        //
        // This code tries to find a non-incremental stream ID with the same
        // urgency, if none are found it just uses the last stream ID. When
        // preempt is true we want the lowest stream ID, when preempt is false
        // we want the highest stream ID. Since the streams are stored in a
        // HashMap the iterator is unordered. We work around that by iterating
        // through all the items and storing min/max.
        //
        // TODO: using an ordered iterator might speed up things, but creating a
        // temporary collection but for that also has a cost...
        if self.incremental {
            stream_alias = 0;
            let mut closest_stream = None;
            for (k, v) in streams {
                if stream_id % 4 == 0 &&
                    v.priority.urgency == self.urgency &&
                    !v.priority.incremental
                {
                    match closest_stream {
                        Some(id) =>
                            if self.preempt {
                                closest_stream = Some(std::cmp::min(id, *k));
                            } else {
                                closest_stream = Some(std::cmp::max(id, *k));
                            },

                        None => {
                            closest_stream = Some(*k);
                        },
                    }
                }
            }

            if let Some(id) = closest_stream {
                stream_alias = id;
            }
        }

        let incremental_offset = match (self.incremental, self.preempt) {
            (false, _) => 1,

            (true, true) => 0,

            (true, false) => 2,
        };

        MAX_PROTECTED_STREAM_ID_OFFSET +
            PRIORITY_SCALE_FACTOR * self.urgency as u64 +
            stream_alias +
            incremental_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_mapping() {
        let h3_config = crate::h3::Config::new().unwrap();
        let mut c = crate::h3::Connection::new(&h3_config, true).unwrap();

        // Test mixing incremental and non-incremental requests
        // when there is no stream state in the connection.
        let priority = Priority {
            urgency: 6,
            incremental: false,
            preempt: false,
        };
        assert_eq!(12015, priority.to_quiche(0, &c.streams));

        let priority = Priority {
            urgency: 6,
            incremental: true,
            preempt: true,
        };
        assert_eq!(12014, priority.to_quiche(0, &c.streams));

        let priority = Priority {
            urgency: 6,
            incremental: true,
            preempt: false,
        };
        assert_eq!(12016, priority.to_quiche(0, &c.streams));

        let priority = Priority {
            urgency: 3,
            incremental: false,
            preempt: false,
        };
        assert_eq!(6019, priority.to_quiche(4, &c.streams));

        let priority = Priority {
            urgency: 2,
            incremental: false,
            preempt: false,
        };
        assert_eq!(4023, priority.to_quiche(8, &c.streams));

        let priority = Priority {
            urgency: 6,
            incremental: false,
            preempt: false,
        };
        assert_eq!(12027, priority.to_quiche(12, &c.streams));

        let priority = Priority {
            urgency: 6,
            incremental: true,
            preempt: false,
        };
        assert_eq!(12016, priority.to_quiche(16, &c.streams));

        // Test mixing incremental and non-incremental requests
        // when there is stream state. First we need to populate
        // the connection with a collection of streams, then we
        // test the priority conversion maths.

        let mut req_1 = stream::Stream::new(0, false);
        req_1.priority.urgency = 6;
        req_1.priority.incremental = true;

        let mut req_2 = stream::Stream::new(4, false);
        req_2.priority.urgency = 3;

        let mut req_3 = stream::Stream::new(8, false);
        req_3.priority.urgency = 2;

        let mut req_4 = stream::Stream::new(12, false);
        req_4.priority.urgency = 6;

        let mut req_5 = stream::Stream::new(16, false);
        req_5.priority.urgency = 6;
        req_5.priority.incremental = true;

        c.streams.insert(0, req_1);
        c.streams.insert(4, req_2);
        c.streams.insert(8, req_3);
        c.streams.insert(12, req_4);
        c.streams.insert(16, req_5);

        let priority = Priority {
            urgency: 6,
            incremental: true,
            preempt: true,
        };
        assert_eq!(12026, priority.to_quiche(0, &c.streams));

        let priority = Priority {
            urgency: 3,
            incremental: false,
            preempt: false,
        };
        assert_eq!(6019, priority.to_quiche(4, &c.streams));

        let priority = Priority {
            urgency: 2,
            incremental: false,
            preempt: false,
        };
        assert_eq!(4023, priority.to_quiche(8, &c.streams));

        let priority = Priority {
            urgency: 6,
            incremental: false,
            preempt: false,
        };
        assert_eq!(12027, priority.to_quiche(12, &c.streams));

        let priority = Priority {
            urgency: 6,
            incremental: true,
            preempt: true,
        };
        assert_eq!(12026, priority.to_quiche(16, &c.streams));
    }
}
