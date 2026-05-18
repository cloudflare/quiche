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

    pub const fn to_bytes_per_second(self) -> u64 {
        self.bits_per_second / 8
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

    /// Returns a sentinel representing infinite bandwidth.
    pub const fn infinite() -> Self {
        Bandwidth {
            bits_per_second: u64::MAX,
        }
    }

    pub const fn zero() -> Self {
        Bandwidth { bits_per_second: 0 }
    }

    /// Returns the time to transfer `bytes` at this bandwidth.
    ///
    /// Returns `Duration::ZERO` for infinite or zero bandwidth.
    /// Saturates to `Duration::from_nanos(u64::MAX)` if the
    /// calculation would overflow.
    pub fn transfer_time(&self, bytes: usize) -> Duration {
        // Handle infinite bandwidth sentinel: transfer is instantaneous
        if self.bits_per_second == u64::MAX {
            return Duration::ZERO;
        }

        if self.bits_per_second == 0 {
            return Duration::ZERO;
        }

        let bytes = bytes as u64;

        // Fast path: try u64 arithmetic first. At typical packet sizes
        // (< 10 KB) and bandwidths, this won't overflow.
        if let Some(nanos) = bytes.checked_mul(8 * NUM_NANOS_PER_SECOND) {
            return Duration::from_nanos(nanos / self.bits_per_second);
        }

        // Slow path: use u128 for intermediate calculation to avoid overflow.
        // At very large byte counts, bytes * 8 * NUM_NANOS_PER_SECOND can
        // overflow u64.
        let nanos = (bytes as u128) * (8 * NUM_NANOS_PER_SECOND) as u128;
        let nanos = nanos / (self.bits_per_second as u128);

        // Saturate to Duration::MAX if result exceeds u64 range.
        Duration::from_nanos(nanos.min(u64::MAX as u128) as u64)
    }

    /// Returns the number of bytes that can be sent in
    /// `time_period` at this bandwidth.
    ///
    /// Returns `u64::MAX` for infinite bandwidth (unless
    /// `time_period` is zero). Saturates to `u64::MAX` if the
    /// calculation would overflow.
    pub fn to_bytes_per_period(self, time_period: Duration) -> u64 {
        // Handle infinite bandwidth sentinel.
        if self.bits_per_second == u64::MAX {
            if time_period != Duration::ZERO {
                return u64::MAX;
            } else {
                return 0;
            }
        }

        // Fast path: try u64 arithmetic first. At typical bandwidths (< 10
        // Gbps) and short time periods (< 1 second), this won't overflow.
        if let Ok(time_nanos) = u64::try_from(time_period.as_nanos()) {
            if let Some(bits) = self.bits_per_second.checked_mul(time_nanos) {
                return bits / (8 * NUM_NANOS_PER_SECOND);
            }
        }

        // Slow path: use u128 for intermediate calculation to avoid overflow.
        // At high bandwidths (e.g., 10+ Gbps) with non-trivial time periods,
        // bits_per_second * time_period.as_nanos() can overflow u64.
        let time_nanos = time_period.as_nanos();
        let bits = (self.bits_per_second as u128).saturating_mul(time_nanos);
        let bytes = bits / (8 * NUM_NANOS_PER_SECOND) as u128;

        // Saturate to u64::MAX if result exceeds u64 range.
        bytes.min(u64::MAX as u128) as u64
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
        let bw = Bandwidth::from_bytes_per_second(100);
        assert_eq!(bw.to_bits_per_second(), 800);
        assert_eq!(bw.to_bytes_per_second(), 100);

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
    fn transfer_time_overflow() {
        // Test that large byte values that would overflow u64 are handled
        // correctly using u128 arithmetic.
        let low_bandwidth = Bandwidth::from_kbits_per_second(1);

        // This value would overflow: (usize::MAX as u64) * 8 * 1_000_000_000
        // which exceeds u64::MAX.
        let large_bytes = usize::MAX;
        let result = low_bandwidth.transfer_time(large_bytes);

        // At 1 kbit/s = 125 bytes/s, transferring usize::MAX bytes would take
        // an astronomically long time. Result should saturate to Duration::MAX
        // (u64::MAX nanoseconds).
        assert_eq!(result, Duration::from_nanos(u64::MAX));

        // Test a more realistic large value: 10 GiB at 1 Gbps should work.
        let one_gbps = Bandwidth::from_mbits_per_second(1_000); // 1 Gbps
        let ten_gib = 10 * 1024 * 1024 * 1024;
        // 10 GiB * 8 bits/byte / 1 Gbit/s = 85.899... seconds
        let expected = Duration::from_nanos(85_899_345_920);
        assert_eq!(one_gbps.transfer_time(ten_gib), expected);
    }

    #[test]
    fn transfer_time_infinite() {
        // Infinite bandwidth should have zero transfer time (instantaneous)
        let inf = Bandwidth::infinite();

        // Zero bytes
        assert_eq!(inf.transfer_time(0), Duration::ZERO);

        // Small transfers
        assert_eq!(inf.transfer_time(1), Duration::ZERO);
        assert_eq!(inf.transfer_time(100), Duration::ZERO);
        assert_eq!(inf.transfer_time(1024), Duration::ZERO);

        // Large transfers
        assert_eq!(inf.transfer_time(1_000_000), Duration::ZERO);
        assert_eq!(inf.transfer_time(usize::MAX), Duration::ZERO);
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
    fn to_bytes_per_period_high_bandwidth() {
        // 10 Gbps with 1 second would overflow u64 in the old implementation.
        let ten_gbps = Bandwidth::from_mbits_per_second(10_000);
        assert_eq!(
            ten_gbps.to_bytes_per_period(Duration::from_secs(1)),
            1_250_000_000
        );

        // 100 Gbps with 100ms.
        let hundred_gbps = Bandwidth::from_mbits_per_second(100_000);
        assert_eq!(
            hundred_gbps.to_bytes_per_period(Duration::from_millis(100)),
            1_250_000_000
        );

        // 1 Tbps with 10ms.
        let one_tbps = Bandwidth::from_mbits_per_second(1_000_000);
        assert_eq!(
            one_tbps.to_bytes_per_period(Duration::from_millis(10)),
            1_250_000_000
        );
    }

    #[test]
    fn to_bytes_per_period_overflow_intermediate() {
        // Test case that would overflow u64 in intermediate calculation:
        // bits_per_second=10^19, time_period=1sec would give 10^19 * 10^9 =
        // 10^28.
        let huge_bw = Bandwidth {
            bits_per_second: 10_000_000_000_000_000_000,
        };
        let result = huge_bw.to_bytes_per_period(Duration::from_secs(1));
        assert_eq!(result, 1_250_000_000_000_000_000);
    }

    #[test]
    fn to_bytes_per_period_saturate_very_high_bandwidth() {
        // Test case where result exceeds u64::MAX and should saturate.
        // 2^63 bits/sec * 100 seconds / 8 = 6.25 * u64::MAX bytes.
        let very_high_bw = Bandwidth {
            bits_per_second: 1u64 << 63, // 2^63
        };
        let result = very_high_bw.to_bytes_per_period(Duration::from_secs(100));
        // Should saturate to u64::MAX since result exceeds u64 range.
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn to_bytes_per_period_saturate_long_period() {
        // Test saturation case: high bandwidth, long period.
        let high_bw = Bandwidth {
            bits_per_second: u64::MAX / 2,
        };
        let result = high_bw.to_bytes_per_period(Duration::from_secs(100));
        // Should saturate to u64::MAX.
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn to_bytes_per_period_large_no_saturate() {
        // Test large but reasonable case that doesn't saturate.
        let high_bw = Bandwidth::from_mbits_per_second(100_000); // 100 Gbps
        let one_hour = Duration::from_secs(3600);
        let result = high_bw.to_bytes_per_period(one_hour);
        assert_eq!(result, 45_000_000_000_000); // 45 TB
    }

    #[test]
    fn to_bytes_per_period_infinite() {
        // Infinite bandwidth sentinel should return u64::MAX.
        let inf = Bandwidth::infinite();
        assert_eq!(inf.to_bytes_per_period(Duration::from_secs(1)), u64::MAX);
        assert_eq!(inf.to_bytes_per_period(Duration::from_millis(1)), u64::MAX);
        assert_eq!(inf.to_bytes_per_period(Duration::ZERO), 0);

        // Mul<Duration> should also return u64::MAX.
        assert_eq!(inf * Duration::from_secs(1), u64::MAX);
    }

    #[test]
    fn to_bytes_per_period_duration_exceeds_u64_nanos() {
        // Test case where duration.as_nanos() exceeds u64::MAX.
        // u64::MAX nanoseconds is ~584 years. We can create a Duration larger
        // than that. Duration::MAX is ~584 billion years.
        let bw = Bandwidth::from_mbits_per_second(1000); // 1 Gbps

        // Create a duration that exceeds u64::MAX nanoseconds.
        // u64::MAX = 18_446_744_073_709_551_615 nanoseconds
        // = 18_446_744_073 seconds + 709_551_615 nanoseconds
        // So any duration > 18_446_744_073 seconds will exceed u64::MAX nanos.
        let huge_duration = Duration::from_secs(20_000_000_000); // ~634 years

        // Should fall back to u128 arithmetic and not panic.
        // 1 Gbps * 20 billion seconds = 2.5 * 10^18 bytes
        let result = bw.to_bytes_per_period(huge_duration);
        assert_eq!(result, 2_500_000_000_000_000_000);
    }

    #[test]
    fn to_bytes_per_period_u128_overflow() {
        // Test case where even u128 multiplication would overflow.
        // u128::MAX is ~3.4 * 10^38. Duration::MAX.as_nanos() is ~10^29.
        // We need bits_per_second * time_nanos > u128::MAX.
        // Use maximum possible values: u64::MAX - 1 bits/sec (since u64::MAX
        // is infinite sentinel) and Duration::MAX.
        let huge_bw = Bandwidth {
            bits_per_second: u64::MAX - 1,
        };
        let max_duration = Duration::MAX;

        // u128 multiplication should overflow and saturate to u64::MAX.
        // (u64::MAX - 1) * Duration::MAX.as_nanos() > u128::MAX
        let result = huge_bw.to_bytes_per_period(max_duration);
        assert_eq!(result, u64::MAX);
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
