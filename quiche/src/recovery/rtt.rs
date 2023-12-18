use core::time::Duration;
use std::time::Instant;

use crate::minmax;

pub(crate) const INITIAL_RTT: Duration = Duration::from_millis(333);

pub(crate) const RTT_WINDOW: Duration = Duration::from_secs(300);

pub(crate) struct RttStats {
    pub(crate) latest_rtt: Duration,

    pub(crate) smoothed_rtt: Option<Duration>,

    pub(crate) rttvar: Duration,

    pub(crate) min_rtt: Duration,

    pub(crate) max_ack_delay: Duration,

    minmax_filter: minmax::Minmax<Duration>,
}

impl RttStats {
    pub(crate) fn new(max_ack_delay: Duration) -> Self {
        RttStats {
            latest_rtt: Duration::ZERO,

            // This field should be initialized to `INITIAL_RTT` for the initial
            // PTO calculation, but it also needs to be an `Option` to track
            // whether any RTT sample was received, so the initial value is
            // handled by the `rtt()` method instead.
            smoothed_rtt: None,

            minmax_filter: minmax::Minmax::new(Duration::ZERO),

            min_rtt: Duration::ZERO,

            max_ack_delay,

            rttvar: INITIAL_RTT / 2,
        }
    }

    pub(crate) fn update_rtt(
        &mut self, latest_rtt: Duration, ack_delay: Duration, now: Instant,
    ) {
        self.latest_rtt = latest_rtt;

        match self.smoothed_rtt {
            // First RTT sample.
            None => {
                self.min_rtt = self.minmax_filter.reset(now, latest_rtt);

                self.smoothed_rtt = Some(latest_rtt);

                self.rttvar = latest_rtt / 2;
            },

            Some(srtt) => {
                self.min_rtt =
                    self.minmax_filter.running_min(RTT_WINDOW, now, latest_rtt);

                let ack_delay = self.max_ack_delay.min(ack_delay);

                // Adjust for ack delay if plausible.
                let adjusted_rtt = if latest_rtt > self.min_rtt + ack_delay {
                    latest_rtt - ack_delay
                } else {
                    latest_rtt
                };

                let abs_difference = srtt
                    .saturating_sub(adjusted_rtt)
                    .max(adjusted_rtt.saturating_sub(srtt));

                self.rttvar = self.rttvar.mul_f64(3.0 / 4.0) +
                    abs_difference.mul_f64(1.0 / 4.0);

                self.smoothed_rtt = Some(
                    srtt.mul_f64(7.0 / 8.0) + adjusted_rtt.mul_f64(1.0 / 8.0),
                );
            },
        }
    }

    pub(crate) fn rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(INITIAL_RTT)
    }

    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt.ne(&Duration::ZERO).then_some(self.min_rtt)
    }
}
