#[derive(Default)]
pub struct Pmtud {
    /// The current path MTU estimate.
    cur_size: usize,

    /// The last MTU probe size that was attempted.
    probe: usize,

    /// Indicated if Path MTU probe needs to be generated.
    next_size: bool,

    /// Check config for PMTU variable.
    enable: bool,
}

impl Pmtud {
    /// Creates new PMTUD instance.
    pub fn new(cur_size: usize) -> Self {
        Self {
            cur_size,
            ..Default::default()
        }
    }

    /// Enables Path MTU Discovery for the connection.
    pub fn enable(&mut self, enable: bool) {
        self.enable = enable;
    }

    /// Returns enable status for Path MTU Discovery for the connection.
    pub fn is_enabled(&mut self) -> bool {
        self.enable
    }

    /// Specifies whether Path MTU Discovery should be performed at the next
    /// opportunity, i.e., when the next packet is sent out if possible.
    ///
    /// Once Path MTU has been discovered, this maybe set to false.
    pub fn should_probe(&mut self, pmtu_next: bool) {
        self.next_size = pmtu_next;
    }

    /// Returns the value of the Path MTU Discovery flag.
    pub fn get_probe_status(&self) -> bool {
        self.next_size
    }

    /// Sets the next Path MTU Discovery probe size.
    pub fn set_probe_size(&mut self, pmtu_probe: usize) {
        self.probe = pmtu_probe;
    }

    /// Returns the next Path MTU Discovery probe size.
    pub fn get_probe_size(&mut self) -> usize {
        self.probe
    }

    /// Sets the current Path MTU Discovery size after a successful probe has
    /// been performed.
    pub fn set_current(&mut self, pmtu: usize) {
        self.cur_size = pmtu;
    }

    /// Returns the discovered PATH MTU size.
    pub fn get_current(&mut self) -> usize {
        self.cur_size
    }

    /// Selects path MTU probe based on the binary search algorithm.
    ///
    /// Based on the Optimistic Binary algorithm defined in:
    /// Ref: <https://www.hb.fh-muenster.de/opus4/frontdoor/deliver/index/docId/14965/file/dplpmtudQuicPaper.pdf>
    pub fn update_probe_size(&mut self) {
        self.probe = self.cur_size + ((self.probe - self.cur_size) / 2);
    }

    /// Updates probe value when the Path MTU Discovery probe is lost.
    pub fn pmtu_probe_lost(&mut self) {
        self.update_probe_size();
        self.should_probe(true);
    }
}

impl std::fmt::Debug for Pmtud {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "current={:?} ", self.cur_size)?;
        write!(f, "probe_size={:?} ", self.probe)?;
        write!(f, "continue_probing={:?} ", self.next_size)?;
        write!(f, "enable={:?} ", self.enable)?;
        Ok(())
    }
}
