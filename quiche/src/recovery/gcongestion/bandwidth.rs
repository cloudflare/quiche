// Copyright (C) 2023, Cloudflare, Inc.
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

use std::time::Duration;

const NUM_MILLIS_PER_SECOND: u64 = 1000;
const NUM_MICROS_PER_MILLI: u64 = 1000;
const NUM_MICROS_PER_SECOND: u64 = NUM_MICROS_PER_MILLI * NUM_MILLIS_PER_SECOND;
const NUM_NANOS_PER_SECOND: u64 = 1000 * NUM_MICROS_PER_SECOND;

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
pub struct Bandwidth {
    bits_per_second: u64,
}

impl std::ops::Mul<f64> for Bandwidth {
    type Output = Bandwidth;

    fn mul(self, rhs: f64) -> Self::Output {
        Bandwidth {
            bits_per_second: (self.bits_per_second as f64 * rhs).round() as u64,
        }
    }
}

impl std::ops::Mul<f32> for Bandwidth {
    type Output = Bandwidth;

    fn mul(self, rhs: f32) -> Self::Output {
        self * rhs as f64
    }
}

impl std::ops::Sub<Bandwidth> for Bandwidth {
    type Output = Option<Bandwidth>;

    fn sub(self, rhs: Bandwidth) -> Self::Output {
        self.bits_per_second
            .checked_sub(rhs.bits_per_second)
            .map(|bps| Bandwidth {
                bits_per_second: bps,
            })
    }
}

impl std::ops::Add<Bandwidth> for Bandwidth {
    type Output = Bandwidth;

    fn add(self, rhs: Bandwidth) -> Self::Output {
        Bandwidth {
            bits_per_second: self.bits_per_second.add(rhs.bits_per_second),
        }
    }
}

impl std::ops::Mul<Duration> for Bandwidth {
    type Output = u64;

    fn mul(self, rhs: Duration) -> Self::Output {
        self.to_bytes_per_period(rhs)
    }
}

impl Bandwidth {
    pub const fn from_bytes_and_time_delta(
        bytes: usize, time_delta: Duration,
    ) -> Self {
        if bytes == 0 {
            return Bandwidth { bits_per_second: 0 };
        }

        let mut nanos = time_delta.as_nanos() as u64;
        if nanos == 0 {
            nanos = 1;
        }

        let num_nano_bits = 8 * bytes as u64 * NUM_NANOS_PER_SECOND;
        if num_nano_bits < nanos {
            return Bandwidth { bits_per_second: 1 };
        }

        Bandwidth {
            bits_per_second: num_nano_bits / nanos,
        }
    }

    #[allow(dead_code)]
    pub const fn from_bytes_per_second(bytes_per_second: u64) -> Self {
        Bandwidth {
            bits_per_second: bytes_per_second * 8,
        }
    }

    #[allow(dead_code)]
    pub const fn to_bits_per_second(self) -> u64 {
        self.bits_per_second
    }

    pub const fn from_kbits_per_second(k_bits_per_second: u64) -> Self {
        Bandwidth {
            bits_per_second: k_bits_per_second * 1_000,
        }
    }

    #[allow(dead_code)]
    pub const fn from_mbits_per_second(m_bits_per_second: u64) -> Self {
        Bandwidth::from_kbits_per_second(m_bits_per_second * 1_000)
    }

    pub const fn infinite() -> Self {
        Bandwidth {
            bits_per_second: u64::MAX,
        }
    }

    pub const fn zero() -> Self {
        Bandwidth { bits_per_second: 0 }
    }

    pub fn transfer_time(&self, bytes: usize) -> Duration {
        if self.bits_per_second == 0 {
            Duration::ZERO
        } else {
            Duration::from_nanos(
                (bytes as u64 * 8 * NUM_NANOS_PER_SECOND) / self.bits_per_second,
            )
        }
    }

    pub fn to_bytes_per_period(self, time_period: Duration) -> u64 {
        self.bits_per_second * time_period.as_nanos() as u64 /
            8 /
            NUM_NANOS_PER_SECOND
    }
}

impl std::fmt::Debug for Bandwidth {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.bits_per_second {
            x if x < 1_000_000 => write!(f, "{:.2} Kbps", x as f64 / 1_000.),
            x if x < 1_000_000_000 => {
                write!(f, "{:.2} Mbps", x as f64 / 1_000_000.)
            },
            x => write!(f, "{:.2} Gbps", x as f64 / 1_000_000_000.),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors() {
        // Internal representation is bits per second.
        assert_eq!(Bandwidth::from_bytes_per_second(100).bits_per_second, 800);
        assert_eq!(
            Bandwidth::from_bytes_per_second(100).to_bits_per_second(),
            800
        );

        // kbits == 1000 bits
        assert_eq!(
            Bandwidth::from_kbits_per_second(100).bits_per_second,
            100_000
        );

        // mbits == 1000,000 bits
        assert_eq!(
            Bandwidth::from_mbits_per_second(100).bits_per_second,
            100_000_000
        );

        assert_eq!(Bandwidth::infinite().bits_per_second, u64::MAX);
        assert_eq!(Bandwidth::zero().bits_per_second, 0);
    }

    #[test]
    fn arithmetic_ops() {
        let bw_1k = Bandwidth::from_kbits_per_second(1);
        let bw_5k = Bandwidth::from_kbits_per_second(5);
        let bw_6k = Bandwidth::from_kbits_per_second(6);

        // Addition
        assert_eq!(bw_1k + bw_5k, bw_6k);

        // Subtraction
        assert_eq!(bw_6k - bw_5k, Some(bw_1k));
        assert_eq!(bw_6k - bw_6k, Some(Bandwidth::zero()));

        // Negative bw is not defined.
        assert_eq!(bw_1k - bw_5k, None);

        // Multiplication by scalars
        assert_eq!(bw_1k * 6.0f64, bw_6k);
        assert_eq!(bw_1k * 6.0f32, bw_6k);
        assert_eq!(bw_5k * 0.0, Bandwidth::zero());
        assert_eq!(bw_5k * 1.0, bw_5k);

        // Multiplication saturates on overflow and underflow.
        assert_eq!(Bandwidth::infinite() * -1.0, Bandwidth::zero());
        assert_eq!((Bandwidth::infinite() * 2.0f64).bits_per_second, u64::MAX);

        // Multiplication rounds up.
        assert_eq!(
            (Bandwidth::infinite() * 0.5f64).bits_per_second,
            u64::MAX / 2 + 1
        );
    }

    #[test]
    fn from_bytes_and_time_delta() {
        assert_eq!(
            Bandwidth::from_bytes_and_time_delta(10, Duration::from_millis(1000))
                .bits_per_second,
            80
        );
        assert_eq!(
            Bandwidth::from_bytes_and_time_delta(10, Duration::from_millis(100))
                .bits_per_second,
            800
        );
        assert_eq!(
            Bandwidth::from_bytes_and_time_delta(
                100,
                Duration::from_millis(1000)
            )
            .bits_per_second,
            800
        );
    }

    #[test]
    fn transfer_time() {
        let one_kbit_sec = Bandwidth::from_kbits_per_second(1);
        assert_eq!(one_kbit_sec.transfer_time(0), Duration::ZERO);
        assert_eq!(one_kbit_sec.transfer_time(100), Duration::from_millis(800));
    }

    #[test]
    fn to_bytes_per_period() {
        let one_kbit_sec = Bandwidth::from_kbits_per_second(1);
        assert_eq!(
            one_kbit_sec.to_bytes_per_period(Duration::from_millis(10_000)),
            1250
        );
        assert_eq!(
            one_kbit_sec.to_bytes_per_period(Duration::from_millis(1000)),
            125
        );
        assert_eq!(
            one_kbit_sec.to_bytes_per_period(Duration::from_millis(100)),
            12
        );
        assert_eq!(
            one_kbit_sec.to_bytes_per_period(Duration::from_millis(10)),
            1
        );
        assert_eq!(
            one_kbit_sec.to_bytes_per_period(Duration::from_millis(1)),
            0
        );

        // Mul<Duration> implementation.
        assert_eq!(one_kbit_sec * Duration::from_millis(10_000), 1250);
    }

    #[test]
    fn debug() {
        assert_eq!(
            format!("{:?}", Bandwidth { bits_per_second: 1 }),
            "0.00 Kbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 12
            }),
            "0.01 Kbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 123
            }),
            "0.12 Kbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 1234
            }),
            "1.23 Kbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 12345
            }),
            "12.35 Kbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 123456
            }),
            "123.46 Kbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 1234567
            }),
            "1.23 Mbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 12345678
            }),
            "12.35 Mbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 123456789
            }),
            "123.46 Mbps"
        );
        assert_eq!(
            format!("{:?}", Bandwidth {
                bits_per_second: 1234567890
            }),
            "1.23 Gbps"
        );
    }
}
