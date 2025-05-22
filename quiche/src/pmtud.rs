/// This file contains the logic to implement PMTUD. Given a minimum supported MTU and an initial
/// probe size that marks the maximum supported MTU, finds the PMTU between the two.

#[derive(Default)]
pub struct Pmtud {
    /// The PMTU after the completion of PMTUD.
    /// Will be [`None`] if the PMTU is less than the minimum supported MTU.
    pmtu: Option<usize>,

    /// The current PMTUD probe size. The initial value is the largest supported MTU.
    probe_size: usize,

    /// The minimum supported MTU.
    minimum_supported_mtu: usize,

    /// The maximum supported MTU.
    maximum_supported_mtu: usize,

    /// The size of the smallest failed probe.
    smallest_failed_probe_size: Option<usize>,

    /// The size of the largest successful probe.
    largest_successful_probe_size: Option<usize>,

    /// Indicates if PMTUD requires continued probing.
    should_probe: bool,

    /// Indicates if a PMTUD probe is inflight.
    inflight: bool,
}

impl Pmtud {
    /// Creates new PMTUD instance.
    pub fn new(
        minimum_supported_mtu: usize, maximum_supported_mtu: usize,
    ) -> Self {
        Self {
            minimum_supported_mtu,
            maximum_supported_mtu,
            probe_size: maximum_supported_mtu,
            ..Default::default()
        }
    }

    /// Indicates whether probing should continue on the connection.
    pub fn should_probe(&self) -> bool {
        self.pmtu.is_none()
            && !(self.smallest_failed_probe_size.is_some_and(|failed_probe| {
                failed_probe == self.minimum_supported_mtu
            }))
    }

    /// Sets the PMTUD probe size.
    pub fn set_probe_size(&mut self, probe_size: usize) {
        self.maximum_supported_mtu = probe_size;
        self.probe_size = probe_size;
    }

    /// Returns the PMTUD probe size.
    pub fn get_probe_size(&mut self) -> usize {
        self.probe_size
    }

    /// Returns the largest successful PMTUD probe size if one exists, otherwise
    /// returns the minimum supported MTU.
    pub fn get_largest_succesful_probe(&mut self) -> usize {
        self.largest_successful_probe_size
            .unwrap_or(self.minimum_supported_mtu)
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
                    return self.restart_pmtud();
                }

                // Found the PMTU
                if failed_probe_size - successful_probe_size <= 1 {
                    self.pmtu = Some(successful_probe_size);
                    self.probe_size = successful_probe_size
                } else {
                    self.probe_size =
                        (successful_probe_size + failed_probe_size) / 2
                }
            },

            // With only failed probes, binary search between the smallest failed
            // probe and the minimum supported MTU
            (Some(failed_probe_size), None) => {
                self.probe_size =
                    (self.minimum_supported_mtu + failed_probe_size) / 2
            },

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

    /// Returns whether a probe is currently inflight for this connection.
    pub fn get_inflight(&mut self) -> bool {
        self.inflight
    }

    /// Sets whether a probe is currently inflight for this connection.
    pub fn set_inflight(&mut self, inflight: bool) {
        self.inflight = inflight;
    }

    /// Records a successful probe
    pub fn successful_probe(&mut self, probe_size: usize) {
        self.largest_successful_probe_size =
            std::cmp::max(Some(probe_size), self.largest_successful_probe_size);

        self.update_probe_size();
        self.inflight = false;
    }

    /// Records a failed probe
    pub fn failed_probe(&mut self, probe_size: usize) {
        // Check if we have one instance of a failed probe so that a min comparison
        // can be made otherwise if this is the first failed probe just record it
        if self.smallest_failed_probe_size.is_some() {
            self.smallest_failed_probe_size =
                std::cmp::min(Some(probe_size), self.smallest_failed_probe_size);
        } else {
            self.smallest_failed_probe_size = Some(probe_size);
        }

        self.update_probe_size();
        self.inflight = false;
    }

    // Resets PMTUD internals such that PMTUD will be recalculated
    // on the next opportunity
    pub fn restart_pmtud(&mut self) {
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
        write!(f, "should_probe={:?} ", self.should_probe)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test case for resetting the PMTUD state.
    ///
    /// This test initializes the PMTUD instance, performs a successful probe,
    /// recalculates the PMTU, and then uses the `pmtud_test_runner` function
    /// to verify the PMTU discovery process.
    #[test]
    fn test_pmtud_reset() {
        let mut search = Pmtud::new(1200, 1350);
        search.successful_probe(1350);
        assert_eq!(search.pmtu, Some(1350));
        assert!(!search.should_probe());

        // Restart PMTUD and expect the state to reset
        search.restart_pmtud();

        // Run the PMTUD test runner with the reset state
        pmtud_test_runner(search, 1237);
    }

    /// Test case for PMTU equal to the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly identifies
    /// when the PMTU is equal to the minimum supported MTU.
    #[test]
    fn test_pmtu_equal_to_min_supported_mtu() {
        let search = Pmtud::new(1200, 1350);
        pmtud_test_runner(search, 1200);
    }

    /// Test case for PMTU greater than the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly identifies
    /// when the PMTU is greater than the minimum supported MTU.
    #[test]
    fn test_pmtu_greater_than_min_supported_mtu() {
        let search = Pmtud::new(1200, 1350);
        pmtud_test_runner(search, 1500);
    }

    /// Test case for PMTU less than the minimum supported MTU.
    ///
    /// This test verifies that the PMTU discovery process correctly handles
    /// the case when the PMTU is less than the minimum supported MTU.
    #[test]
    fn test_pmtu_less_than_min_supported_mtu() {
        let search = Pmtud::new(1200, 1350);
        pmtud_test_runner(search, 1100);
    }

    /// Test case for PMTU recalculation.
    ///
    /// This test verifies that the PMTU recalculation logic correctly resets
    /// the PMTUD state and identifies the correct PMTU after recalculation.
    #[test]
    fn test_pmtu_recalculation() {
        let mut search = Pmtud::new(1200, 1350);
        search.set_probe_size(1350);
        search.successful_probe(1350);

        // Recalculate PMTU and expect the state to reset
        search.restart_pmtud();

        // Run the PMTUD test runner with the reset state
        pmtud_test_runner(search, 1250);
    }

    /// Runs a test for the PMTUD algorithm, given a target PMTU `target_mtu`.
    ///
    /// The test initializes the probe size to the maximum supported MTU and
    /// then iteratively sends probes with the current probe size until the
    /// PMTU is found or the minimum supported MTU is reached.
    ///
    /// Finally, the test verifies that the PMTU is correct by asserting that
    /// the PMTU is equal to the target PMTU.
    fn pmtud_test_runner(mut search: Pmtud, test_pmtu: usize) {
        let maximum_supported_mtu = 1350;
        let min_supported_mtu = 1200;

        // Loop until the PMTU is found or the minimum supported MTU is reached
        while search.get_probe_size() >= min_supported_mtu {
            // Send a probe with the current probe size
            let probe_size = search.get_probe_size();

            if probe_size <= test_pmtu {
                search.successful_probe(probe_size);
            } else {
                search.failed_probe(probe_size);
            }

            // Update the probe size based on the result
            search.update_probe_size();

            // If the probe size hasn't changed and is equal to the minimum
            // supported MTU, break the loop
            if search.get_probe_size() == probe_size
                && probe_size == min_supported_mtu
            {
                break;
            }

            // If the PMTU is found, break the loop
            if search.get_pmtu().is_some() {
                break;
            }
        }

        // Verify that the PMTU is correct
        if test_pmtu < min_supported_mtu {
            assert_eq!(search.get_pmtu(), None);
        } else if test_pmtu > maximum_supported_mtu {
            assert_eq!(search.get_pmtu(), Some(maximum_supported_mtu));
        } else {
            assert_eq!(search.get_pmtu(), Some(test_pmtu));
        }
    }
}
