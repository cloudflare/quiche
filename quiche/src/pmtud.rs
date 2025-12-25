/// Contains the logic to implement PMTUD. Given a maximum supported MTU,
/// finds the PMTU between the given max and [`MIN_CLIENT_INITIAL_LEN`].
use crate::MIN_CLIENT_INITIAL_LEN;

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
}

impl Pmtud {
    /// Creates new PMTUD instance.
    pub fn new(maximum_supported_mtu: usize) -> Self {
        Self {
            maximum_supported_mtu,
            probe_size: maximum_supported_mtu,
            ..Default::default()
        }
    }

    /// Indicates whether probing should continue on the connection.
    ///
    /// Checks there are no probes in flight, that a PMTU has not been
    /// found, and that the minimum supported MTU has not been reached.
    pub fn should_probe(&self) -> bool {
        !self.in_flight &&
            self.pmtu.is_none() &&
            self.smallest_failed_probe_size != Some(MIN_CLIENT_INITIAL_LEN)
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
        self.largest_successful_probe_size
            .unwrap_or(MIN_CLIENT_INITIAL_LEN)
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

                    self.restart_pmtud();

                    // Record the failed probe again after restarting PMTUD
                    // to ensure the next probe size is reduced (binary search down)
                    // instead of resetting to the maximum MTU.
                    //
                    // NOTE: `failed_probe()` internally calls `update_probe_size()`,
                    // so this is an intentional and bounded recursive call. After
                    // `restart_pmtud()` the state is reset, and re-recording the
                    // failed probe brings the PMTUD state back into a consistent
                    // configuration for the next probe without causing unbounded
                    // recursion.
                    self.failed_probe(failed_probe_size);

                    return;
                }

                // Found the PMTU
                if failed_probe_size - successful_probe_size <= 1 {
                    trace!("Found PMTU: {successful_probe_size}");

                    self.pmtu = Some(successful_probe_size);
                    self.probe_size = successful_probe_size
                } else {
                    self.probe_size =
                        (successful_probe_size + failed_probe_size) / 2
                }
            },

            // With only failed probes, binary search between the smallest failed
            // probe and the minimum supported MTU
            (Some(failed_probe_size), None) =>
                self.probe_size = (MIN_CLIENT_INITIAL_LEN + failed_probe_size) / 2,

            // As the algorithm is optimistic in that the initial probe size
            // is the maximum supported MTU, then having only a successful probe
            // means the maximum supported MTU is <= PMTU
            (None, Some(successful_probe_size)) => {
                self.pmtu = Some(successful_probe_size);
                self.probe_size = successful_probe_size
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
        let probe_size = std::cmp::max(probe_size, MIN_CLIENT_INITIAL_LEN);

        // Check if we have one instance of a failed probe so that a min
        // comparison can be made otherwise if this is the first failed
        // probe just record it
        self.smallest_failed_probe_size = self
            .smallest_failed_probe_size
            .map_or(Some(probe_size), |existing_size| {
                Some(std::cmp::min(probe_size, existing_size))
            });

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
    }

    // Checks that a probe of PMTU size can be ack'd by enabling
    // a probe on the next opportunity. If this probe is dropped
    // PMTUD will restart from a fresh state
    pub fn revalidate_pmtu(&mut self) {
        if let Some(pmtu) = self.pmtu {
            self.set_probe_size(pmtu);
            self.pmtu = None;
        };
    }
}

impl std::fmt::Debug for Pmtud {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pmtu={:?} ", self.pmtu)?;
        write!(f, "probe_size={:?} ", self.probe_size)?;
        write!(f, "should_probe={:?} ", self.should_probe())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmtud_initial_state() {
        let pmtud = Pmtud::new(1350);
        assert_eq!(pmtud.get_current_mtu(), 1200);
        assert_eq!(pmtud.get_probe_size(), 1350);
        assert!(pmtud.should_probe());
    }

    #[test]
    fn pmtud_binary_search_algorithm() {
        let mut pmtud = Pmtud::new(1500);

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
    fn pmtud_probe_lost_behavior() {
        let mut pmtud = Pmtud::new(1500);

        // Simulate probe loss
        pmtud.failed_probe(1500);

        // Should re-enable probing and adjust size
        assert!(pmtud.should_probe());
        assert_eq!(pmtud.get_probe_size(), 1350); // binary search result
        assert_eq!(pmtud.get_current_mtu(), 1200); // MTU does not
                                                   // change
    }

    #[test]
    fn pmtud_successful_probe() {
        let mut pmtud = Pmtud::new(1400);

        // Simulate successful probe
        pmtud.successful_probe(1400);

        assert_eq!(pmtud.get_current_mtu(), 1400);
    }

    #[test]
    fn pmtud_binary_search_convergence() {
        let mut pmtud = Pmtud::new(2000);

        // Simulate repeated probe losses to test convergence
        pmtud_test_runner(&mut pmtud, 1200);

        // Should converge to the minimum allowed packet size
        assert_eq!(pmtud.get_probe_size(), 1200);
    }

    /// Test case for resetting the PMTUD state.
    ///
    /// This test initializes the PMTUD instance, performs a successful probe,
    /// recalculates the PMTU, and then uses the `pmtud_test_runner` function
    /// to verify the PMTU discovery process.
    #[test]
    fn test_pmtud_reset() {
        let mut pmtud = Pmtud::new(1350);
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
        let mut pmtud = Pmtud::new(1350);
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
        let mut pmtud = Pmtud::new(1350);
        pmtud_test_runner(&mut pmtud, 1200);
    }

    /// Test case for PMTU greater than the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly identifies
    /// when the PMTU is greater than the minimum supported MTU.
    #[test]
    fn test_pmtu_greater_than_min_supported_mtu() {
        let mut pmtud = Pmtud::new(1350);
        pmtud_test_runner(&mut pmtud, 1500);
    }

    /// Test case for PMTU less than the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly handles
    /// the case when the PMTU is less than the minimum supported MTU.
    #[test]
    fn test_pmtu_less_than_min_supported_mtu() {
        let mut pmtud = Pmtud::new(1350);
        pmtud_test_runner(&mut pmtud, 1100);
    }

    /// Test case for PMTU revalidation.
    ///
    /// This test verifies that the PMTU recalculation logic correctly resets
    /// the PMTUD state and identifies the correct PMTU after a failed
    /// validation probe.
    #[test]
    fn test_pmtu_revalidation() {
        let mut pmtud = Pmtud::new(1350);
        pmtud.set_probe_size(1350);
        pmtud.successful_probe(1350);

        // Simulate a case where an a probe of an established PMTU is dropped
        pmtud.revalidate_pmtu();
        pmtud.failed_probe(1350);

        // Run the PMTUD test runner with the reset state
        pmtud_test_runner(&mut pmtud, 1250);
    }

    /// Test case for changing network conditions during PMTUD.
    ///
    /// This test simulates a scenario where network conditions change
    /// during the PMTUD process, causing inconsistent probe results.
    #[test]
    fn test_pmtud_changing_network_conditions() {
        let mut pmtud = Pmtud::new(1500);

        // Simulate a successful probe
        pmtud.successful_probe(1400);

        // Simulate a failed probe that is less than the last successful probe
        pmtud.failed_probe(1300);

        // The largest successful probe should be reset after restarting PMTUD
        assert_eq!(pmtud.largest_successful_probe_size, None);

        // The smallest failed probe should be recorded again after restarting PMTUD
        assert_eq!(pmtud.smallest_failed_probe_size, Some(1300));

        // Run the PMTUD test runner to verify handling of inconsistent results
        pmtud_test_runner(&mut pmtud, 1250);
    }

    /// Runs a test for the PMTUD algorithm, given a target PMTU `target_mtu`.
    ///
    /// The test iteratively sends probes until the PMTU is found or the minimum
    /// supported MTU is reached. Verifies that the PMTU is equal to the target
    /// PMTU.
    fn pmtud_test_runner(pmtud: &mut Pmtud, test_pmtu: usize) {
        // Loop until the PMTU is found or the minimum supported MTU is reached
        while pmtud.get_probe_size() >= MIN_CLIENT_INITIAL_LEN {
            // Send a probe with the current probe size
            let probe_size = pmtud.get_probe_size();

            if probe_size <= test_pmtu {
                pmtud.successful_probe(probe_size);
            } else {
                pmtud.failed_probe(probe_size);
            }

            // Update the probe size based on the result
            pmtud.update_probe_size();

            // If the probe size hasn't changed and is equal to the minimum
            // supported MTU, break the loop
            if pmtud.get_probe_size() == probe_size &&
                probe_size == MIN_CLIENT_INITIAL_LEN
            {
                break;
            }

            // If the PMTU is found, break the loop
            if pmtud.get_pmtu().is_some() {
                break;
            }
        }

        // Verify that the PMTU is correct
        if test_pmtu < MIN_CLIENT_INITIAL_LEN {
            assert_eq!(pmtud.get_pmtu(), None);
        } else if test_pmtu > pmtud.maximum_supported_mtu {
            assert_eq!(pmtud.get_pmtu(), Some(pmtud.maximum_supported_mtu));
        } else {
            assert_eq!(pmtud.get_pmtu(), Some(test_pmtu));
        }
    }
}
