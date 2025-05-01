/// This file contains the logic to implement PMTUD. Given a minimum supported MTU and an initial
/// probe size that marks the maximum supported MTU, finds the PMTU between the two.

#[derive(Default)]
pub struct Pmtud {
    /// The current PMTU estimate.
    estimated_pmtu: usize,

    /// The PMTU after the completion of PMTUD.
    /// Will be [`None`] if the PMTU is less than the minimum supported MTU.
    pmtu: Option<usize>,

    /// The current PMTUD probe size. The initial value is the largest supported MTU.
    probe_size: usize,

    /// The minimum supported MTU.
    minimum_supported_mtu: usize,

    /// The size of the smallest failed probe.
    last_failed_probe_size: Option<usize>,

    /// The size of the largest successful probe.
    last_successful_probe_size: Option<usize>,

    /// Indicates if PMTUD requires continued probing.
    should_probe: bool,

    /// Is PMTUD enabled.
    enabled: bool,

    /// Indicates if a PMTUD probe is inflight.
    inflight: bool,
}

impl Pmtud {
    /// Creates new PMTUD instance.
    pub fn new(minimum_supported_mtu: usize) -> Self {
        Self {
            estimated_pmtu: minimum_supported_mtu,
            minimum_supported_mtu,
            ..Default::default()
        }
    }

    /// Enables PMTUD for the connection.
    pub fn enable(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Returns enabled status for PMTUD for the connection.
    pub fn is_enabled(&mut self) -> bool {
        self.enabled
    }

    /// Indicates whether probing should continue on the connection.
    pub fn should_probe(&self) -> bool {
        self.enabled
            && self.pmtu.is_none()
            && !(self
                .last_failed_probe_size
                .is_some_and(|failed_probe| failed_probe == self.estimated_pmtu))
    }

    /// Sets the PMTUD probe size.
    pub fn set_probe_size(&mut self, probe_size: usize) {
        self.probe_size = probe_size;
    }

    /// Returns the PMTUD probe size.
    pub fn get_probe_size(&mut self) -> usize {
        self.probe_size
    }

    /// Sets the estimated PMTU.
    pub fn set_estimated_pmtu(&mut self, pmtu: usize) {
        self.estimated_pmtu = std::cmp::max(self.estimated_pmtu, pmtu);
    }

    /// Returns the estimated PMTU.
    pub fn get_estimated_pmtu(&mut self) -> usize {
        self.estimated_pmtu
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
        match (self.last_failed_probe_size, self.last_successful_probe_size) {
            // Binary search between successful and failed probes
            (Some(failed_probe_size), Some(successful_probe_size)) => {
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
            (None, None) => {},
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
        self.last_successful_probe_size =
            std::cmp::max(Some(probe_size), self.last_successful_probe_size);

        self.update_probe_size();
        self.inflight = false;
    }

    /// Records a failed probe
    pub fn failed_probe(&mut self, probe_size: usize) {
        // Check if we have one instance of a failed probe so that a min comparison
        // can be made otherwise if this is the first failed probe just record it
        if self.last_failed_probe_size.is_some() {
            self.last_failed_probe_size =
                std::cmp::min(Some(probe_size), self.last_failed_probe_size);
        } else {
            self.last_failed_probe_size = Some(probe_size);
        }

        self.update_probe_size();
        self.inflight = false;
    }
}

impl std::fmt::Debug for Pmtud {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "estimated_pmtu={:?} ", self.estimated_pmtu)?;
        write!(f, "pmtu={:?} ", self.pmtu)?;
        write!(f, "probe_size={:?} ", self.probe_size)?;
        write!(f, "should_probe={:?} ", self.should_probe)?;
        write!(f, "enable={:?} ", self.enabled)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simulate an environment where the PMTU is 1272 and ensure the
    // algorithm finds this
    #[test]
    fn test_example_pmtud() {
        let mut search = Pmtud::new(1200);

        search.failed_probe(1350);
        assert_eq!(search.get_probe_size(), 1275);

        search.failed_probe(1275);
        assert_eq!(search.get_probe_size(), 1237);

        search.successful_probe(1237);
        assert_eq!(search.get_probe_size(), 1256);

        search.successful_probe(1256);
        assert_eq!(search.get_probe_size(), 1265);

        search.successful_probe(1265);
        assert_eq!(search.get_probe_size(), 1270);

        search.successful_probe(1270);
        assert_eq!(search.get_probe_size(), 1272);

        search.successful_probe(1272);
        assert_eq!(search.get_probe_size(), 1273);

        search.failed_probe(1273);

        assert_eq!(search.pmtu, Some(1272));
        assert!(!search.should_probe());
    }

    #[test]
    fn test_pmtu_more_than_max_supported_mtu() {
        let mut search = Pmtud::new(1200);
        search.set_probe_size(1350);
        search.successful_probe(1350);
        assert_eq!(search.pmtu, Some(1350));
        assert!(!search.should_probe());
    }

    #[test]
    fn test_pmtu_less_than_min_supported_mtu() {
        let mut search = Pmtud::new(1200);
        search.set_probe_size(1350);

        search.failed_probe(1350);
        assert_eq!(search.get_probe_size(), 1275);

        search.failed_probe(1275);
        assert_eq!(search.get_probe_size(), 1237);

        search.failed_probe(1237);
        assert_eq!(search.get_probe_size(), 1218);

        search.failed_probe(1218);
        assert_eq!(search.get_probe_size(), 1209);

        search.failed_probe(1209);
        assert_eq!(search.get_probe_size(), 1204);

        search.failed_probe(1204);
        assert_eq!(search.get_probe_size(), 1202);

        search.failed_probe(1202);
        assert_eq!(search.get_probe_size(), 1201);

        search.failed_probe(1201);
        assert_eq!(search.get_probe_size(), 1200);

        search.failed_probe(1200);
        assert_eq!(search.get_probe_size(), 1200);

        // Make sure we do not continue to probe when the algorithm
        // hits the minimum supported MTU
        assert!(!search.should_probe());
    }

    #[test]
    fn test_pmtu_equal_to_min_supported_mtu() {
        let mut search = Pmtud::new(1200);
        search.set_probe_size(1350);

        search.failed_probe(1350);
        assert_eq!(search.get_probe_size(), 1275);

        search.failed_probe(1275);
        assert_eq!(search.get_probe_size(), 1237);

        search.failed_probe(1237);
        assert_eq!(search.get_probe_size(), 1218);

        search.failed_probe(1218);
        assert_eq!(search.get_probe_size(), 1209);

        search.failed_probe(1209);
        assert_eq!(search.get_probe_size(), 1204);

        search.failed_probe(1204);
        assert_eq!(search.get_probe_size(), 1202);

        search.failed_probe(1202);
        assert_eq!(search.get_probe_size(), 1201);

        search.failed_probe(1201);
        assert_eq!(search.get_probe_size(), 1200);

        search.successful_probe(1200);
        assert_eq!(search.pmtu, Some(1200));
        assert!(!search.should_probe());
    }
}
