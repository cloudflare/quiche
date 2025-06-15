use crate::MIN_CLIENT_INITIAL_LEN;

#[derive(Default)]
pub struct Pmtud {
    /// The current PMTU estimate.
    current_mtu: usize,

    /// The last PMTU probe size that was attempted.
    probe_size: usize,

    /// Whether or not a PMTU probe needs to be generated.
    should_probe: bool,

    /// Whether or not PMTUD is enabled.
    enabled: bool,
}

impl Pmtud {
    /// Creates new PMTUD instance.
    pub fn new(initial_mtu: usize) -> Self {
        // QUIC mandates packet sizes >= 1200.
        assert!(initial_mtu >= MIN_CLIENT_INITIAL_LEN);

        Self {
            current_mtu: initial_mtu,
            ..Default::default()
        }
    }

    /// Enables PMTUD for the connection.
    pub fn enable(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Whether or not PMTUD is enabled for the connection.
    pub fn is_enabled(&mut self) -> bool {
        self.enabled
    }

    /// Specifies whether PMTUD should be performed at the next opportunity,
    /// i.e., when the next packet is sent out if possible.
    ///
    /// Once Path MTU has been discovered, this may be set to false.
    pub fn set_should_probe(&mut self, should_probe: bool) {
        self.should_probe = should_probe;
    }

    /// Returns the value of the Path MTU Discovery flag.
    pub fn get_should_probe(&self) -> bool {
        self.should_probe
    }

    /// Sets the next PMTUD probe size.
    pub fn set_probe_size(&mut self, probe_size: usize) {
        self.probe_size = probe_size;
    }

    /// Returns the next PMTUD probe size.
    pub fn get_probe_size(&mut self) -> usize {
        self.probe_size
    }

    /// Sets the current discovered PMTU after a successful probe has
    /// been performed.
    pub fn set_current_mtu(&mut self, pmtu: usize) {
        self.current_mtu = pmtu;
    }

    /// Returns the discovered PMTU.
    pub fn get_current_mtu(&mut self) -> usize {
        self.current_mtu
    }

    /// Updates the PMTUD probe size based on the "Optimistic Binary" algorithm
    /// defined in <https://www.hb.fh-muenster.de/opus4/frontdoor/deliver/index/docId/14965/file/dplpmtudQuicPaper.pdf>
    pub fn update_probe_size(&mut self) {
        self.probe_size =
            self.current_mtu + ((self.probe_size - self.current_mtu) / 2);
    }

    /// Updates the PMTUD probe size when a previously sent probe has been lost.
    pub fn pmtu_probe_lost(&mut self) {
        self.update_probe_size();
        self.set_should_probe(true);
    }
}

impl std::fmt::Debug for Pmtud {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "current_mtu={:?} ", self.current_mtu)?;
        write!(f, "probe_size={:?} ", self.probe_size)?;
        write!(f, "should_probe={:?} ", self.should_probe)?;
        write!(f, "enabled={:?} ", self.enabled)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmtud_initial_state() {
        let mut pmtud = Pmtud::new(1200);

        assert_eq!(pmtud.get_current_mtu(), 1200);
        assert_eq!(pmtud.get_probe_size(), 0);
        assert!(!pmtud.get_should_probe());
        assert!(!pmtud.is_enabled());
    }

    #[test]
    fn pmtud_enable_disable() {
        let mut pmtud = Pmtud::new(1200);

        pmtud.enable(true);
        assert!(pmtud.is_enabled());

        pmtud.enable(false);
        assert!(!pmtud.is_enabled());
    }

    #[test]
    fn pmtud_probe_flag_management() {
        let mut pmtud = Pmtud::new(1200);

        // Initially should not probe
        assert!(!pmtud.get_should_probe());

        // Enable probing
        pmtud.set_should_probe(true);
        assert!(pmtud.get_should_probe());

        // Disable probing
        pmtud.set_should_probe(false);
        assert!(!pmtud.get_should_probe());
    }

    #[test]
    fn pmtud_binary_search_algorithm() {
        let mut pmtud = Pmtud::new(1200);

        // Set initial probe size to 1500
        pmtud.set_probe_size(1500);
        assert_eq!(pmtud.get_probe_size(), 1500);

        // Simulate probe loss - should update to midpoint
        pmtud.update_probe_size();
        // Expected: 1200 + ((1500 - 1200) / 2) = 1200 + 150 = 1350
        assert_eq!(pmtud.get_probe_size(), 1350);

        // Another probe loss
        pmtud.update_probe_size();
        // Expected: 1200 + ((1350 - 1200) / 2) = 1200 + 75 = 1275
        assert_eq!(pmtud.get_probe_size(), 1275);

        pmtud.update_probe_size();
        // Expected: 1200 + ((1275 - 1200) / 2) = 1200 + 37 = 1237
        assert_eq!(pmtud.get_probe_size(), 1237);

        pmtud.update_probe_size();
        // Expected: 1200 + ((1237 - 1200) / 2) = 1200 + 18 = 1218
        assert_eq!(pmtud.get_probe_size(), 1218);

        pmtud.update_probe_size();
        // Expected: 1200 + ((1218 - 1200) / 2) = 1200 + 9 = 1209
        assert_eq!(pmtud.get_probe_size(), 1209);

        pmtud.update_probe_size();
        // Expected: 1200 + ((1209 - 1200) / 2) = 1200 + 4 = 1204
        assert_eq!(pmtud.get_probe_size(), 1204);

        pmtud.update_probe_size();
        // Expected: 1200 + ((1204 - 1200) / 2) = 1200 + 2 = 1202
        assert_eq!(pmtud.get_probe_size(), 1202);

        pmtud.update_probe_size();
        // Expected: 1200 + ((1202 - 1200) / 2) = 1200 + 1 = 1201
        assert_eq!(pmtud.get_probe_size(), 1201);

        pmtud.update_probe_size();
        // Expected: 1200 + ((1201 - 1200) / 2) = 1200 + 0 = 1200
        assert_eq!(pmtud.get_probe_size(), 1200);
    }

    #[test]
    fn pmtud_probe_lost_behavior() {
        let mut pmtud = Pmtud::new(1200);
        pmtud.set_probe_size(1500);
        pmtud.set_should_probe(false);

        // Simulate probe loss
        pmtud.pmtu_probe_lost();

        // Should re-enable probing and adjust size
        assert!(pmtud.get_should_probe());
        assert_eq!(pmtud.get_probe_size(), 1350); // binary search result
        assert_eq!(pmtud.get_current_mtu(), 1200); // MTU does not change
    }

    #[test]
    fn pmtud_successful_probe() {
        let mut pmtud = Pmtud::new(1200);
        pmtud.set_probe_size(1400);

        // Simulate successful probe
        pmtud.set_current_mtu(1400);

        assert_eq!(pmtud.get_current_mtu(), 1400);
    }

    #[test]
    fn pmtud_binary_search_convergence() {
        let mut pmtud = Pmtud::new(1200);
        pmtud.set_probe_size(2000);

        // Simulate repeated probe losses to test convergence
        for _ in 0..10 {
            pmtud.update_probe_size();
        }

        // Should converge to the minimum allowed packet size
        assert_eq!(pmtud.get_probe_size(), 1200);
    }
}
