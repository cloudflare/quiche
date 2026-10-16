//! Path MTU Discovery ([RFC 8899] DPLPMTUD).
//!
//! Discovers the path MTU using loss-based inference: probe packets are sent
//! and their acknowledgment (or lack thereof) determines path capacity.
//!
//! # Algorithm
//!
//! Optimistic binary search between [`MIN_PLPMTU`] (1200) and max supported
//! MTU:
//! 1. Probe at max MTU
//! 2. On max_probes consecutive failures, record as smallest failed size
//! 3. Binary search between largest success and smallest failure
//! 4. Complete when difference ≤ 1 byte
//!
//! A successful probe at any point resets the failure counter and updates
//! the largest known working size.
//!
//! A search that ends below the max supported MTU runs again after
//! [`RESEARCH_INTERVAL`], in case the path has grown.
//!
//! # Black hole detection
//!
//! After the search, the path MTU can shrink, for example when a VPN starts
//! or a route changes. Full-size packets are then lost while small ones still
//! get through. [`BlackHoleDetector`] watches for that pattern in the losses
//! of ordinary packets. When it fires, the MTU drops back to [`MIN_PLPMTU`]
//! and the search runs again after [`BLACK_HOLE_COOLDOWN`].
//!
//! [RFC 8899]: https://datatracker.ietf.org/doc/html/rfc8899

use std::time::Duration;
use std::time::Instant;

use crate::recovery::PmtudSignals;

/// Maximum number of probe attempts before treating a size as failed.
/// https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2
pub(crate) const MAX_PROBES_DEFAULT: u8 = 3;

/// Min Packetization Layer Path MTU (PLPMTU).
/// https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2
/// For QUIC, this is 1200 bytes per https://datatracker.ietf.org/doc/html/rfc9000#section-14.1
const MIN_PLPMTU: usize = crate::MIN_CLIENT_INITIAL_LEN;

/// How long after a black hole the search runs again.
const BLACK_HOLE_COOLDOWN: Duration = Duration::from_secs(60);

/// How long after a search that ended below the max supported MTU it runs
/// again.
const RESEARCH_INTERVAL: Duration = Duration::from_secs(600);

/// The number of suspicious loss bursts that must be exceeded to declare a
/// black hole.
const BLACK_HOLE_THRESHOLD: usize = 3;

#[derive(Default)]
pub struct Pmtud {
    /// The PMTU after the completion of PMTUD.
    /// Will be [`None`] if the PMTU is less than the minimum supported MTU.
    pmtu: Option<usize>,

    /// The current PMTUD probe size. Set to maximum_supported_mtu at
    /// initialization.
    probe_size: usize,

    /// The maximum supported MTU.
    maximum_supported_mtu: usize,

    /// The size of the smallest failed probe.
    smallest_failed_probe_size: Option<usize>,

    /// The size of the largest successful probe.
    largest_successful_probe_size: Option<usize>,

    /// Indicates if a PMTUD probe is in flight. Used to limit probes to 1/RTT.
    in_flight: bool,

    /// The number of times the current probe size has failed.
    probe_failure_count: u8,

    /// The maximum number of failed probe attempts before treating a size as
    /// failed.
    max_probes: u8,

    /// When probing may resume, after a black hole or a search that ended
    /// below the max supported MTU.
    next_search: Option<Instant>,

    black_hole: BlackHoleDetector,
}

impl Pmtud {
    /// Creates new PMTUD instance.
    ///
    /// If `max_probes` is 0, uses the default value of [`MAX_PROBES_DEFAULT`].
    pub fn new(maximum_supported_mtu: usize, max_probes: u8) -> Self {
        let max_probes = if max_probes == 0 {
            warn!(
                "max_probes is 0, using default value {}",
                MAX_PROBES_DEFAULT
            );
            MAX_PROBES_DEFAULT
        } else {
            max_probes
        };

        Self {
            maximum_supported_mtu,
            probe_size: maximum_supported_mtu,
            max_probes,
            ..Default::default()
        }
    }

    /// Indicates whether probing should continue on the connection.
    ///
    /// Checks there are no probes in flight, that a PMTU has not been
    /// found, that the minimum supported MTU has not been reached, and that
    /// probing is not paused until a later search.
    pub fn should_probe(&self) -> bool {
        !self.in_flight &&
            self.next_search.is_none() &&
            self.pmtu.is_none() &&
            self.smallest_failed_probe_size != Some(MIN_PLPMTU)
    }

    /// Advances the search timers. A search that ended below the max
    /// supported MTU is scheduled to run again after [`RESEARCH_INTERVAL`],
    /// and a paused search resumes once its time comes.
    pub fn poll_search(&mut self, now: Instant) {
        match self.next_search {
            Some(next_search) if now >= next_search => {
                self.next_search = None;
                if self.search_ended_below_max() {
                    self.reopen_search();
                }
            },

            Some(_) => (),

            None if self.search_ended_below_max() =>
                self.next_search = Some(now + RESEARCH_INTERVAL),

            None => (),
        }
    }

    fn search_ended_below_max(&self) -> bool {
        match self.pmtu {
            Some(pmtu) => pmtu < self.maximum_supported_mtu,
            None => self.smallest_failed_probe_size == Some(MIN_PLPMTU),
        }
    }

    /// Probes the max supported MTU again, keeping the largest size known to
    /// work.
    fn reopen_search(&mut self) {
        self.pmtu = None;
        self.smallest_failed_probe_size = None;
        self.probe_failure_count = 0;
        self.probe_size = self.maximum_supported_mtu;
    }

    /// Feeds the packets recovery just settled to the black hole detector.
    ///
    /// Returns true if they show a black hole. The current MTU has then
    /// dropped back to [`MIN_PLPMTU`], and the caller must lower the path's
    /// max datagram size to match.
    pub fn on_packets_settled(
        &mut self, signals: &PmtudSignals, now: Instant,
    ) -> bool {
        if let Some((pkt_num, size)) = signals.largest_acked {
            self.black_hole.on_non_probe_acked(pkt_num, size);
        }

        if signals.lost.is_empty() {
            return false;
        }

        for &(pkt_num, size) in &signals.lost {
            self.black_hole.on_non_probe_lost(pkt_num, size);
        }

        if !self.black_hole.black_hole_detected() {
            return false;
        }

        if self.get_current_mtu() <= MIN_PLPMTU {
            return false;
        }

        warn!(
            "PMTU black hole detected at {}, falling back to {}",
            self.get_current_mtu(),
            MIN_PLPMTU
        );

        self.restart_pmtud();
        self.next_search = Some(now + BLACK_HOLE_COOLDOWN);

        true
    }

    /// Sets the PMTUD probe size.
    fn set_probe_size(&mut self, probe_size: usize) {
        self.probe_size = std::cmp::min(probe_size, self.maximum_supported_mtu);
    }

    /// Returns the PMTUD probe size.
    pub fn get_probe_size(&self) -> usize {
        self.probe_size
    }

    /// Returns the largest successful PMTUD probe size if one exists, otherwise
    /// returns the minimum supported MTU.
    pub fn get_current_mtu(&self) -> usize {
        self.largest_successful_probe_size.unwrap_or(MIN_PLPMTU)
    }

    /// Returns the PMTU.
    pub fn get_pmtu(&self) -> Option<usize> {
        self.pmtu
    }

    /// Selects PMTU probe size based on the binary search algorithm.
    ///
    /// Based on the Optimistic Binary algorithm defined in:
    /// Ref: <https://www.hb.fh-muenster.de/opus4/frontdoor/deliver/index/docId/14965/file/dplpmtudQuicPaper.pdf>
    fn update_probe_size(&mut self) {
        match (
            self.smallest_failed_probe_size,
            self.largest_successful_probe_size,
        ) {
            // Binary search between successful and failed probes
            (Some(failed_probe_size), Some(successful_probe_size)) => {
                // Something has changed along the path that invalidates
                // previous PMTUD probes. Restart PMTUD
                if failed_probe_size <= successful_probe_size {
                    warn!(
                        "Inconsistent PMTUD probing results. Restarting PMTUD. \
                        failed_probe_size: {failed_probe_size}, \
                        successful_probe_size: {successful_probe_size}",
                    );

                    return self.restart_pmtud();
                }

                // Found the PMTU
                if failed_probe_size - successful_probe_size <= 1 {
                    debug!("Found PMTU: {successful_probe_size}");
                    self.set_pmtu(successful_probe_size);
                } else {
                    self.probe_size =
                        (successful_probe_size + failed_probe_size) / 2
                }
            },

            // With only failed probes, binary search between the smallest failed
            // probe and the minimum supported MTU
            (Some(failed_probe_size), None) =>
                self.probe_size = (MIN_PLPMTU + failed_probe_size) / 2,

            // As the algorithm is optimistic in that the initial probe size
            // is the maximum supported MTU, then having only a successful probe
            // means the maximum supported MTU is <= PMTU
            (None, Some(successful_probe_size)) => {
                self.set_pmtu(successful_probe_size);
            },

            // Use the initial probe size if no record of success/failures
            (None, None) => self.probe_size = self.maximum_supported_mtu,
        }
    }

    /// Sets whether a probe is currently in flight for this connection.
    pub fn set_in_flight(&mut self, in_flight: bool) {
        self.in_flight = in_flight;
    }

    /// Records a successful probe and returns the largest successful probe size
    pub fn successful_probe(&mut self, probe_size: usize) -> Option<usize> {
        self.probe_failure_count = 0;

        self.largest_successful_probe_size = std::cmp::max(
            // make sure we don't exceed the maximum supported MTU
            Some(probe_size.min(self.maximum_supported_mtu)),
            self.largest_successful_probe_size,
        );

        self.update_probe_size();
        self.in_flight = false;

        self.largest_successful_probe_size
    }

    /// Records a failed probe
    pub fn failed_probe(&mut self, probe_size: usize) {
        // Treat errant probes as if they failed at the minimum supported MTU
        let probe_size = std::cmp::max(probe_size, MIN_PLPMTU);
        self.probe_failure_count += 1;

        if self.probe_failure_count < self.max_probes {
            debug!(
                "Probe size {} failed ({}/{}), will retry",
                probe_size, self.probe_failure_count, self.max_probes
            );
            self.in_flight = false;
            return;
        }

        debug!(
            "Probe size {} failed {} times, treating as MTU limitation",
            probe_size, self.probe_failure_count
        );

        // Check if we have one instance of a failed probe so that a min
        // comparison can be made otherwise if this is the first failed
        // probe just record it
        self.smallest_failed_probe_size = Some(
            self.smallest_failed_probe_size
                .map_or(probe_size, |s| s.min(probe_size)),
        );

        self.probe_failure_count = 0;
        self.update_probe_size();
        self.in_flight = false;
    }

    // Resets PMTUD internals such that PMTUD will be recalculated
    // on the next opportunity
    fn restart_pmtud(&mut self) {
        self.set_probe_size(self.maximum_supported_mtu);
        self.smallest_failed_probe_size = None;
        self.largest_successful_probe_size = None;
        self.pmtu = None;
        self.probe_failure_count = 0;
    }

    // Checks that a probe of PMTU size can be ack'd by enabling
    // a probe on the next opportunity. If this probe is dropped
    // PMTUD will restart from a fresh state
    pub fn revalidate_pmtu(&mut self) {
        if let Some(pmtu) = self.pmtu {
            self.set_probe_size(pmtu);
            self.pmtu = None;
            self.probe_failure_count = 0;
            self.largest_successful_probe_size = None;
            self.next_search = None;
        }
    }

    fn set_pmtu(&mut self, successful_probe_size: usize) {
        self.pmtu = Some(successful_probe_size);
        self.probe_size = successful_probe_size;
        self.probe_failure_count = 0;
    }
}

impl std::fmt::Debug for Pmtud {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pmtu={:?} ", self.pmtu)?;
        write!(f, "probe_size={:?} ", self.probe_size)?;
        write!(f, "in_flight={:?} ", self.in_flight)?;
        write!(f, "next_search={:?} ", self.next_search)?;
        write!(
            f,
            "failures={}/{} ",
            self.probe_failure_count, self.max_probes
        )?;
        Ok(())
    }
}

/// Spots a path MTU that shrank after the search, from the losses of ordinary
/// packets.
///
/// A loss burst is a run of consecutive packet numbers declared lost. A burst
/// is suspicious when every packet in it is larger than [`MIN_PLPMTU`], unless
/// a packet at least as large as its smallest one was acked after it. More
/// than [`BLACK_HOLE_THRESHOLD`] suspicious bursts declare a black hole.
///
/// Ported from Quinn's `BlackHoleDetector`.
struct BlackHoleDetector {
    /// Suspicious loss bursts, as the size of the smallest packet in each.
    suspicious_loss_bursts: Vec<usize>,

    /// The loss burst being aggregated, if any.
    current_loss_burst: Option<CurrentLossBurst>,

    /// The packet number of the largest packet acked more recently than any
    /// suspicious loss burst.
    largest_post_loss_packet: u64,

    /// The size of `largest_post_loss_packet`, or [`MIN_PLPMTU`] if no larger
    /// packet has been acked since the most recent suspicious loss burst.
    acked_mtu: usize,
}

#[derive(Clone, Copy)]
struct CurrentLossBurst {
    latest_non_probe: u64,
    smallest_packet_size: usize,
}

impl Default for BlackHoleDetector {
    fn default() -> Self {
        Self {
            suspicious_loss_bursts: Vec::with_capacity(BLACK_HOLE_THRESHOLD + 1),
            current_loss_burst: None,
            largest_post_loss_packet: 0,
            acked_mtu: MIN_PLPMTU,
        }
    }
}

impl BlackHoleDetector {
    fn on_non_probe_acked(&mut self, pkt_num: u64, size: usize) {
        if size <= self.acked_mtu {
            return;
        }

        self.acked_mtu = size;
        self.largest_post_loss_packet = pkt_num;

        // A burst of packets smaller than one the path just carried was not
        // caused by the MTU.
        self.suspicious_loss_bursts
            .retain(|&smallest_packet_size| smallest_packet_size > size);
    }

    fn on_non_probe_lost(&mut self, pkt_num: u64, size: usize) {
        let ends_last_burst = self.current_loss_burst.is_some_and(|burst| {
            pkt_num.saturating_sub(burst.latest_non_probe) != 1
        });

        if ends_last_burst {
            self.finish_loss_burst();
        }

        self.current_loss_burst = Some(CurrentLossBurst {
            latest_non_probe: pkt_num,
            smallest_packet_size: self
                .current_loss_burst
                .map_or(size, |burst| burst.smallest_packet_size.min(size)),
        });
    }

    fn black_hole_detected(&mut self) -> bool {
        self.finish_loss_burst();

        if self.suspicious_loss_bursts.len() <= BLACK_HOLE_THRESHOLD {
            return false;
        }

        self.suspicious_loss_bursts.clear();

        true
    }

    fn finish_loss_burst(&mut self) {
        let Some(burst) = self.current_loss_burst.take() else {
            return;
        };

        // A burst holding a minimum-size packet, or one sent before a larger
        // packet that was acked, is not suspicious.
        if burst.smallest_packet_size <= MIN_PLPMTU ||
            (burst.latest_non_probe < self.largest_post_loss_packet &&
                burst.smallest_packet_size < self.acked_mtu)
        {
            return;
        }

        // A suspicious burst sent after the largest acked packet means that
        // packet no longer shows what the path carries.
        if burst.latest_non_probe > self.largest_post_loss_packet {
            self.acked_mtu = MIN_PLPMTU;
        }

        if self.suspicious_loss_bursts.len() <= BLACK_HOLE_THRESHOLD {
            self.suspicious_loss_bursts.push(burst.smallest_packet_size);
            return;
        }

        // Only the most suspicious bursts are kept, to bound memory.
        if let Some(smallest) = self
            .suspicious_loss_bursts
            .iter_mut()
            .min()
            .filter(|smallest| **smallest < burst.smallest_packet_size)
        {
            *smallest = burst.smallest_packet_size;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmtud_initial_state() {
        let pmtud = Pmtud::new(1350, 1);
        assert_eq!(pmtud.get_current_mtu(), 1200);
        assert_eq!(pmtud.get_probe_size(), 1350);
        assert!(pmtud.should_probe());
    }

    #[test]
    fn pmtud_max_probes_zero_uses_default() {
        let pmtud = Pmtud::new(1500, 0);
        assert_eq!(pmtud.max_probes, MAX_PROBES_DEFAULT);
    }

    #[test]
    fn pmtud_max_probes_set_to_provided_value() {
        let pmtud = Pmtud::new(1500, 5);
        assert_eq!(pmtud.max_probes, 5);
        assert_ne!(pmtud.max_probes, MAX_PROBES_DEFAULT);
    }

    #[test]
    fn pmtud_binary_search_algorithm() {
        let mut pmtud = Pmtud::new(1500, 1);

        // Set initial probe size to 1500
        assert_eq!(pmtud.get_probe_size(), 1500);

        // Simulate probe loss - should update to midpoint
        pmtud.failed_probe(1500);
        // Expected: 1200 + ((1500 - 1200) / 2) = 1200 + 150 = 1350
        assert_eq!(pmtud.get_probe_size(), 1350);

        // Another probe loss
        pmtud.failed_probe(1350);
        // Expected: 1200 + ((1350 - 1200) / 2) = 1200 + 75 = 1275
        assert_eq!(pmtud.get_probe_size(), 1275);

        pmtud.failed_probe(1275);
        // Expected: 1200 + ((1275 - 1200) / 2) = 1200 + 37 = 1237
        assert_eq!(pmtud.get_probe_size(), 1237);

        pmtud.failed_probe(1237);
        // Expected: 1200 + ((1237 - 1200) / 2) = 1200 + 18 = 1218
        assert_eq!(pmtud.get_probe_size(), 1218);

        pmtud.failed_probe(1218);
        // Expected: 1200 + ((1218 - 1200) / 2) = 1200 + 9 = 1209
        assert_eq!(pmtud.get_probe_size(), 1209);

        pmtud.failed_probe(1209);
        // Expected: 1200 + ((1209 - 1200) / 2) = 1200 + 4 = 1204
        assert_eq!(pmtud.get_probe_size(), 1204);

        pmtud.failed_probe(1204);
        // Expected: 1200 + ((1204 - 1200) / 2) = 1200 + 2 = 1202
        assert_eq!(pmtud.get_probe_size(), 1202);

        pmtud.failed_probe(1202);
        // Expected: 1200 + ((1202 - 1200) / 2) = 1200 + 1 = 1201
        assert_eq!(pmtud.get_probe_size(), 1201);

        pmtud.failed_probe(1201);
        // Expected: 1200 + ((1201 - 1200) / 2) = 1200 + 0 = 1200
        assert_eq!(pmtud.get_probe_size(), 1200);
    }

    #[test]
    fn pmtud_successful_probe() {
        let mut pmtud = Pmtud::new(1400, 1);

        // Simulate successful probe
        pmtud.successful_probe(1400);

        assert_eq!(pmtud.get_current_mtu(), 1400);
    }

    /// Test case for resetting the PMTUD state.
    ///
    /// This test initializes the PMTUD instance, performs a successful probe,
    /// recalculates the PMTU, and then uses the `pmtud_test_runner` function
    /// to verify the PMTU discovery process.
    #[test]
    fn test_pmtud_reset() {
        let mut pmtud = Pmtud::new(1350, 1);
        pmtud.successful_probe(1350);
        assert_eq!(pmtud.pmtu, Some(1350));
        assert!(!pmtud.should_probe());

        // Restart PMTUD and expect the state to reset
        pmtud.restart_pmtud();

        // Run the PMTUD test runner with the reset state
        pmtud_test_runner(&mut pmtud, 1237);
    }

    /// Test case for receiving a probe outside the defined supported MTU range.
    #[test]
    fn test_pmtud_errant_probe() {
        let mut pmtud = Pmtud::new(1350, 1);
        pmtud.successful_probe(1500);
        // Even though we've received a probe larger than supported
        // maximum MTU, the PMTU should still respect the configured maximum
        assert_eq!(pmtud.pmtu, Some(1350));
        assert!(!pmtud.should_probe());

        pmtud.restart_pmtud();

        // A failed probe of a value less than the minimum supported MTU
        // should stop probing
        pmtud.failed_probe(1100);
        assert_eq!(pmtud.pmtu, None);
        assert_eq!(pmtud.get_probe_size(), 1200);
        assert!(!pmtud.should_probe());
    }

    /// Test case for PMTU equal to the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly identifies
    /// when the PMTU is equal to the minimum supported MTU.
    #[test]
    fn test_pmtu_equal_to_min_supported_mtu() {
        let mut pmtud = Pmtud::new(1350, 1);
        pmtud_test_runner(&mut pmtud, 1200);
    }

    /// Test case for PMTU greater than the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly identifies
    /// when the PMTU is greater than the minimum supported MTU.
    #[test]
    fn test_pmtu_greater_than_min_supported_mtu() {
        let mut pmtud = Pmtud::new(1350, 1);
        pmtud_test_runner(&mut pmtud, 1500);
    }

    /// Test case for PMTU less than the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly handles
    /// the case when the PMTU is less than the minimum supported MTU.
    #[test]
    fn test_pmtu_less_than_min_supported_mtu() {
        let mut pmtud = Pmtud::new(1350, 1);
        pmtud_test_runner(&mut pmtud, 1100);
    }

    /// Test case for PMTU revalidation.
    ///
    /// This test verifies that the PMTU recalculation logic correctly resets
    /// the PMTUD state and identifies the correct PMTU after a failed
    /// validation probe.
    #[test]
    fn test_pmtu_revalidation() {
        let mut pmtud = Pmtud::new(1350, 1);
        pmtud.set_probe_size(1350);
        pmtud.successful_probe(1350);

        // Simulate a case where an established PMTU probe is dropped repeatedly
        pmtud.revalidate_pmtu();
        fail_probe_max_times(&mut pmtud, 1350);

        // Run the PMTUD test runner with the reset state
        pmtud_test_runner(&mut pmtud, 1250);
    }

    #[test]
    fn pmtud_revalidation_tolerates_random_packet_loss() {
        let mut pmtud = Pmtud::new(1500, MAX_PROBES_DEFAULT);

        pmtud.successful_probe(1500);
        assert_eq!(pmtud.get_pmtu(), Some(1500));

        pmtud.revalidate_pmtu();
        assert_eq!(pmtud.get_pmtu(), None);
        assert!(pmtud.largest_successful_probe_size.is_none());

        pmtud.failed_probe(1500);
        assert_eq!(pmtud.probe_failure_count, 1);
        assert!(pmtud.pmtu.is_none());

        pmtud.failed_probe(1500);
        assert_eq!(pmtud.probe_failure_count, 2);

        pmtud.successful_probe(1500);
        assert_eq!(pmtud.get_pmtu(), Some(1500));
        assert_eq!(pmtud.probe_failure_count, 0);
    }

    /// Test that when revalidating PMTU, if the revalidation probe fails,
    /// PMTUD should binary search down, not restart.
    #[test]
    fn pmtud_revalidation_failure_binary_searches_not_restarts() {
        let mut pmtud = Pmtud::new(1500, 1);

        pmtud.successful_probe(1500);
        assert_eq!(pmtud.get_pmtu(), Some(1500));

        // Revalidation clears largest_successful_probe_size
        pmtud.revalidate_pmtu();
        assert!(pmtud.largest_successful_probe_size.is_none());

        // Revalidation probe fails - should binary search down, not restart
        pmtud.failed_probe(1500);

        assert_eq!(pmtud.smallest_failed_probe_size, Some(1500));
        assert!(pmtud.largest_successful_probe_size.is_none());
        assert_eq!(pmtud.get_probe_size(), 1350); // (1200 + 1500) / 2
    }

    #[test]
    fn pmtud_tolerates_initial_packet_loss() {
        let mut pmtud = Pmtud::new(1500, MAX_PROBES_DEFAULT);

        pmtud.failed_probe(1500);
        assert_eq!(pmtud.probe_failure_count, 1);
        assert!(pmtud.smallest_failed_probe_size.is_none());

        pmtud.failed_probe(1500);
        assert_eq!(pmtud.probe_failure_count, 2);
        assert!(pmtud.smallest_failed_probe_size.is_none());

        pmtud.successful_probe(1500);
        assert_eq!(pmtud.get_pmtu(), Some(1500));
        assert_eq!(pmtud.probe_failure_count, 0);
    }

    #[test]
    fn pmtud_confirms_failure_after_max_probes() {
        let mut pmtud = Pmtud::new(1500, 1);

        pmtud.failed_probe(1500);

        assert_eq!(pmtud.smallest_failed_probe_size, Some(1500));
        assert!(pmtud.pmtu.is_none());
        assert!(pmtud.get_probe_size() < 1500);
        assert!(pmtud.get_probe_size() >= MIN_PLPMTU);
    }

    #[test]
    fn pmtud_binary_search_no_slowdown() {
        let mut pmtud = Pmtud::new(1500, 2);

        fail_probe_max_times(&mut pmtud, 1500);
        assert!(pmtud.pmtu.is_none());

        let search_size_1 = pmtud.get_probe_size();
        assert!(search_size_1 < 1500);

        pmtud.successful_probe(search_size_1);
        assert_eq!(pmtud.probe_failure_count, 0);

        let search_size_2 = pmtud.get_probe_size();
        pmtud.failed_probe(search_size_2);

        assert!(pmtud.pmtu.is_none());
        assert_eq!(pmtud.probe_failure_count, 1);
    }

    /// Test convergence to correct MTU with intermittent packet loss.
    ///
    /// Simulates a scenario where the first probe at each size fails but the
    /// second succeeds (random loss, not MTU limitation). Verifies that:
    /// 1. probe_failure_count resets to 0 on success
    /// 2. probe_failure_count resets to 0 when probe size changes
    /// 3. Algorithm converges to the correct MTU of 1337
    #[test]
    fn pmtud_convergence_with_intermittent_loss() {
        let mut pmtud = Pmtud::new(1500, 3);
        let target_mtu = 1337;

        while pmtud.get_pmtu().is_none() {
            let probe_size = pmtud.get_probe_size();

            if probe_size <= target_mtu {
                // The first probe fails due to random loss.
                pmtud.failed_probe(probe_size);
                assert_eq!(pmtud.probe_failure_count, 1);

                // The second probe succeeds.
                pmtud.successful_probe(probe_size);
                // A successful probe resets the failure count.
                assert_eq!(pmtud.probe_failure_count, 0);
            } else {
                // All probes fail because their size exceeds the MTU.
                let old_probe_size = probe_size;
                fail_probe_max_times(&mut pmtud, probe_size);

                // After the maximum failures, `probe_failure_count` resets and
                // the probe size changes.
                assert_eq!(pmtud.probe_failure_count, 0);
                if pmtud.get_pmtu().is_none() {
                    assert!(pmtud.get_probe_size() < old_probe_size);
                }
            }
        }

        assert_eq!(pmtud.get_pmtu(), Some(target_mtu));
    }

    #[test]
    fn pmtud_failure_at_min_plpmtu() {
        let mut pmtud = Pmtud::new(1500, MAX_PROBES_DEFAULT);

        pmtud.failed_probe(100);
        pmtud.failed_probe(100);
        pmtud.failed_probe(100);

        assert_eq!(pmtud.smallest_failed_probe_size, Some(MIN_PLPMTU));
    }

    #[test]
    fn pmtud_in_flight_cleared_on_all_outcomes() {
        let mut pmtud = Pmtud::new(1500, 1);

        pmtud.set_in_flight(true);
        assert!(pmtud.in_flight);

        pmtud.failed_probe(1500);
        assert!(!pmtud.in_flight);

        pmtud.set_in_flight(true);

        pmtud.successful_probe(1500);
        assert!(!pmtud.in_flight);
    }

    #[test]
    fn pmtud_update_probe_size_initial_state() {
        let mut pmtud = Pmtud::new(1500, 1);

        // Manually set probe_size to something else to verify update_probe_size
        // resets it
        pmtud.probe_size = 1200;

        // With no successful or failed probes, should reset to
        // maximum_supported_mtu
        pmtud.update_probe_size();

        assert_eq!(pmtud.probe_size, 1500);
    }

    // Test utilities

    fn fail_probe_max_times(pmtud: &mut Pmtud, size: usize) {
        for _ in 0..pmtud.max_probes {
            pmtud.failed_probe(size);
        }
    }

    /// Runs a test for the PMTUD algorithm, given a target PMTU `target_mtu`.
    ///
    /// The test iteratively sends probes until the PMTU is found or the minimum
    /// supported MTU is reached. Verifies that the PMTU is equal to the target
    /// PMTU.
    fn pmtud_test_runner(pmtud: &mut Pmtud, test_pmtu: usize) {
        // Loop until the PMTU is found or the minimum supported MTU is reached
        while pmtud.get_probe_size() >= MIN_PLPMTU {
            // Send a probe with the current probe size
            let probe_size = pmtud.get_probe_size();

            if probe_size <= test_pmtu {
                pmtud.successful_probe(probe_size);
            } else {
                fail_probe_max_times(pmtud, probe_size);
            }

            // Update the probe size based on the result
            pmtud.update_probe_size();

            // If the probe size hasn't changed and is equal to the minimum
            // supported MTU, break the loop
            if pmtud.get_probe_size() == probe_size && probe_size == MIN_PLPMTU {
                break;
            }

            // If the PMTU is found, break the loop
            if pmtud.get_pmtu().is_some() {
                break;
            }
        }

        // Verify that the PMTU is correct
        if test_pmtu < MIN_PLPMTU {
            assert_eq!(pmtud.get_pmtu(), None);
        } else if test_pmtu > pmtud.maximum_supported_mtu {
            assert_eq!(pmtud.get_pmtu(), Some(pmtud.maximum_supported_mtu));
        } else {
            assert_eq!(pmtud.get_pmtu(), Some(test_pmtu));
        }
    }

    fn lost(pkt_nums: std::ops::Range<u64>, size: usize) -> PmtudSignals {
        PmtudSignals {
            largest_acked: None,
            lost: pkt_nums.map(|pkt_num| (pkt_num, size)).collect(),
        }
    }

    fn acked(pkt_num: u64, size: usize) -> PmtudSignals {
        PmtudSignals {
            largest_acked: Some((pkt_num, size)),
            lost: Vec::new(),
        }
    }

    #[test]
    fn pmtud_black_hole_falls_back_to_minimum() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1452, 3);
        pmtud.successful_probe(1452);
        assert_eq!(pmtud.get_current_mtu(), 1452);

        // Three suspicious bursts are not enough.
        assert!(!pmtud.on_packets_settled(&lost(10..13, 1452), now));
        assert!(!pmtud.on_packets_settled(&lost(20..23, 1452), now));
        assert!(!pmtud.on_packets_settled(&lost(30..33, 1452), now));
        assert_eq!(pmtud.get_current_mtu(), 1452);

        // The fourth one is.
        assert!(pmtud.on_packets_settled(&lost(40..43, 1452), now));
        assert_eq!(pmtud.get_current_mtu(), MIN_PLPMTU);
        assert_eq!(pmtud.get_pmtu(), None);

        // The search waits out the cooldown, then probes the max again.
        pmtud.poll_search(now + BLACK_HOLE_COOLDOWN - Duration::from_secs(1));
        assert!(!pmtud.should_probe());

        pmtud.poll_search(now + BLACK_HOLE_COOLDOWN);
        assert!(pmtud.should_probe());
        assert_eq!(pmtud.get_probe_size(), 1452);
    }

    #[test]
    fn pmtud_consecutive_losses_are_one_burst() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1452, 3);
        pmtud.successful_probe(1452);

        // However many packets one round declares lost, consecutive ones are
        // a single burst.
        for burst in 0..3 {
            let start = burst * 100;
            assert!(
                !pmtud.on_packets_settled(&lost(start..start + 50, 1452), now)
            );
        }

        assert_eq!(pmtud.get_current_mtu(), 1452);
    }

    #[test]
    fn pmtud_minimum_size_losses_are_not_suspicious() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1452, 3);
        pmtud.successful_probe(1452);

        for burst in 0..10 {
            let start = burst * 10;
            assert!(!pmtud
                .on_packets_settled(&lost(start..start + 3, MIN_PLPMTU), now));
        }

        assert_eq!(pmtud.get_current_mtu(), 1452);
    }

    #[test]
    fn pmtud_large_ack_clears_earlier_bursts() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1452, 3);
        pmtud.successful_probe(1452);

        assert!(!pmtud.on_packets_settled(&lost(10..13, 1452), now));
        assert!(!pmtud.on_packets_settled(&lost(20..23, 1452), now));
        assert!(!pmtud.on_packets_settled(&lost(30..33, 1452), now));

        // A full-size packet sent after those bursts got through, so they
        // were congestion, not the MTU.
        assert!(!pmtud.on_packets_settled(&acked(35, 1452), now));

        assert!(!pmtud.on_packets_settled(&lost(40..43, 1452), now));
        assert_eq!(pmtud.get_current_mtu(), 1452);
    }

    #[test]
    fn pmtud_black_hole_at_minimum_keeps_probing() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1452, 3);

        for burst in 0..4 {
            let start = burst * 10;
            assert!(!pmtud.on_packets_settled(&lost(start..start + 3, 1300), now));
        }

        assert_eq!(pmtud.get_current_mtu(), MIN_PLPMTU);
        assert!(pmtud.should_probe());
    }

    #[test]
    fn pmtud_search_below_max_runs_again() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1500, 1);

        pmtud.failed_probe(1500);
        pmtud.successful_probe(1350);
        pmtud.failed_probe(1425);
        pmtud.successful_probe(1387);
        pmtud.successful_probe(1406);
        pmtud.successful_probe(1415);
        pmtud.successful_probe(1420);
        pmtud.successful_probe(1422);
        pmtud.successful_probe(1423);
        pmtud.successful_probe(1424);
        assert_eq!(pmtud.get_pmtu(), Some(1424));

        pmtud.poll_search(now);
        assert!(!pmtud.should_probe());

        pmtud.poll_search(now + RESEARCH_INTERVAL);
        assert!(pmtud.should_probe());
        assert_eq!(pmtud.get_probe_size(), 1500);
        assert_eq!(pmtud.get_current_mtu(), 1424);
    }

    #[test]
    fn pmtud_search_at_max_does_not_run_again() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1452, 3);
        pmtud.successful_probe(1452);

        pmtud.poll_search(now);
        pmtud.poll_search(now + RESEARCH_INTERVAL);
        assert!(!pmtud.should_probe());
    }

    #[test]
    fn pmtud_revalidate_cancels_scheduled_search() {
        let now = Instant::now();
        let mut pmtud = Pmtud::new(1500, 1);
        pmtud.successful_probe(1400);
        pmtud.poll_search(now);
        assert!(!pmtud.should_probe());

        pmtud.revalidate_pmtu();
        assert!(pmtud.should_probe());
        assert_eq!(pmtud.get_probe_size(), 1400);
    }
}
