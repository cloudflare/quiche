// Copyright (C) 2022, Cloudflare, Inc.
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

use crate::packet;
use crate::packet::Epoch;

const ECN_VALIDATION_COUNT: u64 = 10;
const ECN_LOSS_THRESHOLD: u64 = 3;

pub const ECN_NOT_ECT: u8 = 0;
pub const ECN_ECT1: u8 = 1;
pub const ECN_ECT0: u8 = 2;
pub const ECN_CE: u8 = 3;

#[derive(Debug)]
enum EcnState {
    /// Send up to 10 packets marked to ECT(0) or ECT(1) and move to
    /// `Validating`.
    Probing(u8),
    /// Stop sending ECN-enabled packets, but wait for possible ACK reception
    /// confirming ECN usage or disabling it.
    Validating(u8),
    /// Validation succeeded, always send ECT(0) or ECT(1) packets.
    Capable(u8),
    /// Either ECN is disabled or validation failed. No ECN-enabled packet is
    /// sent.
    Unsupported,
}

/// Structure keeping the ECN state.
#[derive(Debug)]
pub struct Ecn {
    state: EcnState,
    ecn_pkts_sent: u64,
    ecn_pkts_lost: u64,
    last_ecn_counts: [packet::EcnCounts; packet::Epoch::count()],
    enabled: bool,
    use_ect1: bool,
}

impl Ecn {
    /// Creates a new `Ecn` structure.
    pub fn new(
        enabled: bool, use_ect1: bool,
        base_ecn_counts: [packet::EcnCounts; packet::Epoch::count()],
    ) -> Ecn {
        let state = if enabled {
            let ect_value = if use_ect1 { ECN_ECT1 } else { ECN_ECT0 };
            EcnState::Probing(ect_value)
        } else {
            EcnState::Unsupported
        };
        Ecn {
            state,
            ecn_pkts_sent: 0,
            ecn_pkts_lost: 0,
            last_ecn_counts: base_ecn_counts,
            enabled,
            use_ect1,
        }
    }

    /// An endpoint thus attempts to use ECN and validates this for each new
    /// connection, when switching to a server's preferred address, and on
    /// active connection migration to a new path.
    pub fn reset(
        &mut self, base_ecn_counts: [packet::EcnCounts; packet::Epoch::count()],
    ) {
        self.state = if self.enabled {
            let ect_value = if self.use_ect1 { ECN_ECT1 } else { ECN_ECT0 };
            EcnState::Probing(ect_value)
        } else {
            EcnState::Unsupported
        };
        self.ecn_pkts_sent = 0;
        self.last_ecn_counts = base_ecn_counts;
    }

    /// Returns the ECN value to assign to the packet to send.
    ///
    /// By calling this method, we assume that the packet to be marked is
    /// actually sent. When probing a path for ECN-capability, this method may
    /// return different values if too many packets were sent (calling this
    /// method) before getting any acknowledgment ([`on_ack_received()`]).
    ///
    /// [`on_ack_received()`]: struct.Ecn.html#method.on_ack_received
    pub fn get_ecn_value_to_send(&mut self) -> u8 {
        match self.state {
            EcnState::Probing(ect_value) => {
                self.ecn_pkts_sent += 1;
                if self.ecn_pkts_sent >= ECN_VALIDATION_COUNT {
                    self.state = EcnState::Validating(ect_value);
                }
                ect_value
            },

            EcnState::Capable(ect_value) => ect_value,

            EcnState::Validating(_) | EcnState::Unsupported => ECN_NOT_ECT,
        }
    }

    /// Returns whether the next packet to send will be ECN-marked.
    pub fn is_next_sent_pkt_ecn_marked(&self) -> bool {
        matches!(self.state, EcnState::Probing(_) | EcnState::Capable(_))
    }

    /// This method should be called when we receive an ACK frame increasing the
    /// largest acknowledged packet number that acknowledged ECN-marked sent
    /// packets.
    ///
    /// This returns the number of newly acknowledged packets with ECN-CE mark.
    pub fn on_ack_received(
        &mut self, epoch: Epoch, newly_ecn_marked_acked: u64,
        ecn_counts: Option<packet::EcnCounts>,
    ) -> u64 {
        if matches!(self.state, EcnState::Unsupported) {
            return 0;
        }
        // If an ACK frame newly acknowledges a packet that the endpoint sent
        // with either the ECT(0) or ECT(1) codepoint set, ECN validation fails
        // if the corresponding ECN counts are not present in the ACK frame.
        let ecn_counts = match ecn_counts {
            Some(e) => e,
            None => {
                warn!("received ACK without ECN counts; disable ECN");
                self.state = EcnState::Unsupported;
                return 0;
            },
        };

        let last_ecn_counts = self.last_ecn_counts[epoch];

        // Validation will fail when an endpoint receives a non-zero ECN count
        // corresponding to an ECT codepoint that it never applied.
        if (self.use_ect1 && ecn_counts.ect0_count != last_ecn_counts.ect0_count) ||
            (!self.use_ect1 &&
                ecn_counts.ect1_count != last_ecn_counts.ect1_count)
        {
            warn!("received ECN count increase for unsent marking; disable ECN");
            self.state = EcnState::Unsupported;
            return 0;
        }

        // Strange reordering cases or buggy implementations may provide lower
        // ECN counts than the last remembered values. Skip their processing.
        if ecn_counts.ect0_count < last_ecn_counts.ect0_count ||
            ecn_counts.ect1_count < last_ecn_counts.ect1_count ||
            ecn_counts.ecn_ce_count < last_ecn_counts.ecn_ce_count
        {
            return 0;
        }

        // ECN validation also fails if the sum of the increase in ECT(0) and
        // ECN-CE counts is less than the number of newly acknowledged packets
        // that were originally sent with an ECT(0) marking. Similarly, ECN
        // validation fails if the sum of the increases to ECT(1) and ECN-CE
        // counts is less than the number of newly acknowledged packets sent
        // with an ECT(1) marking.
        let ecn_count_increase = ecn_counts.ect0_count -
            last_ecn_counts.ect0_count +
            ecn_counts.ect1_count -
            last_ecn_counts.ect1_count +
            ecn_counts.ecn_ce_count -
            last_ecn_counts.ecn_ce_count;
        if ecn_count_increase < newly_ecn_marked_acked {
            warn!("sum of ECN count increase lower than number of ECN-marked acked packets; disable ECN");
            self.state = EcnState::Unsupported;
            return 0;
        }

        let ecn_ce_increase =
            ecn_counts.ecn_ce_count - last_ecn_counts.ecn_ce_count;
        match self.state {
            EcnState::Probing(e) | EcnState::Validating(e) =>
                self.state = EcnState::Capable(e),
            _ => {},
        }
        self.last_ecn_counts[epoch] = ecn_counts;
        // Reset the number of lost packets.
        self.ecn_pkts_lost = 0;

        ecn_ce_increase
    }

    /// This method should be called when a non-zero number of ECN-marked sent
    /// packets were declared lost.
    pub fn on_packets_lost(
        &mut self, lost_ecn_marked_ack_eliciting_packets: u64,
    ) {
        if matches!(self.state, EcnState::Unsupported) {
            return;
        }
        self.ecn_pkts_lost += lost_ecn_marked_ack_eliciting_packets;
        if self.ecn_pkts_lost >= ECN_LOSS_THRESHOLD {
            warn!(
                "Lost {} ECN-marked packets; disable ECN",
                self.ecn_pkts_lost
            );
            self.state = EcnState::Unsupported;
        }
    }

    /// Returns the latest ECN counters.
    pub fn ecn_counts(&self) -> [packet::EcnCounts; packet::Epoch::count()] {
        self.last_ecn_counts
    }
}

#[cfg(test)]
mod tests {
    use crate::ecn::ECN_LOSS_THRESHOLD;
    use crate::packet;

    use super::Ecn;
    use super::ECN_ECT0;
    use super::ECN_ECT1;
    use super::ECN_NOT_ECT;
    use super::ECN_VALIDATION_COUNT;

    #[test]
    fn disabled_ecn() {
        let mut ecn = Ecn::new(false, false, [packet::EcnCounts::default(); 3]);
        for _ in 0..1000 {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);
        }
    }

    #[test]
    fn ecn_marked_pkt_acked_without_ecn_counts() {
        let mut ecn = Ecn::new(true, false, [packet::EcnCounts::default(); 3]);

        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT0);

        // The packet gets acknowledged, but in an ACK frame without ECN counts.
        let ce_events = ecn.on_ack_received(packet::Epoch::Application, 1, None);
        assert_eq!(ce_events, 0);
        // This disables ECN marks.
        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);
    }

    #[test]
    fn received_ecn_counts_ect1_when_marking_ect0() {
        let mut ecn_counts = [packet::EcnCounts::default(); 3];
        let mut ecn = Ecn::new(true, false, ecn_counts);

        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT0);

        // The packet gets acknowledged, but in an ACK frame increasing the ECN
        // count of an ECT different from the one being used.
        ecn_counts[packet::Epoch::Application].ect1_count += 1;
        let ce_events = ecn.on_ack_received(
            packet::Epoch::Application,
            1,
            Some(ecn_counts[packet::Epoch::Application]),
        );
        assert_eq!(ce_events, 0);
        // This disables ECN marks.
        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);
    }

    #[test]
    fn received_ecn_counts_ect0_when_marking_ect1() {
        let mut ecn_counts = [packet::EcnCounts::default(); 3];
        let mut ecn = Ecn::new(true, true, ecn_counts);

        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT1);

        // The packet gets acknowledged, but in an ACK frame increasing the ECN
        // count of an ECT different from the one being used.
        ecn_counts[packet::Epoch::Application].ect0_count += 1;
        let ce_events = ecn.on_ack_received(
            packet::Epoch::Application,
            1,
            Some(ecn_counts[packet::Epoch::Application]),
        );
        assert_eq!(ce_events, 0);
        // This disables ECN marks.
        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);
    }

    #[test]
    fn sum_of_counts_lower_than_acked_ecn_marked_pkts() {
        let mut ecn_counts = [packet::EcnCounts::default(); 3];
        let mut ecn = Ecn::new(true, false, ecn_counts);

        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT0);

        // The packet gets acknowledged, but the ACK frame increases the ECN
        // counters such that it includes a lower number of packets than the
        // numbers of ECN-marked packets actually acknowledged.
        ecn_counts[packet::Epoch::Application].ect0_count += 3;
        ecn_counts[packet::Epoch::Application].ecn_ce_count += 2;
        let ce_events = ecn.on_ack_received(
            packet::Epoch::Application,
            6,
            Some(ecn_counts[packet::Epoch::Application]),
        );
        assert_eq!(ce_events, 0);
        // This disables ECN marks.
        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);
    }

    #[test]
    fn probing_ect0_then_validated() {
        let mut ecn_counts = [packet::EcnCounts::default(); 3];
        let mut ecn = Ecn::new(true, false, ecn_counts);
        for _ in 0..ECN_VALIDATION_COUNT {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT0);
        }
        // Once we sent ECN_VALIDATION_COUNT packets, wait for any ECN
        // validation before sending ECN marks again.
        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);

        // Our first 10 packets got acked correctly. ECN should now be enabled.
        ecn_counts[packet::Epoch::Application].ect0_count += 8;
        ecn_counts[packet::Epoch::Application].ecn_ce_count += 2;
        let ce_events = ecn.on_ack_received(
            packet::Epoch::Application,
            10,
            Some(ecn_counts[packet::Epoch::Application]),
        );
        assert_eq!(ce_events, 2);
        for _ in 0..1000 {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT0);
        }
    }

    #[test]
    fn probing_ect1_then_validated() {
        let mut ecn_counts = [packet::EcnCounts::default(); 3];
        let mut ecn = Ecn::new(true, true, ecn_counts);
        for _ in 0..ECN_VALIDATION_COUNT {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT1);
        }
        // Once we sent ECN_VALIDATION_COUNT packets, wait for any ECN
        // validation before sending ECN marks again.
        assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
        assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);

        // Our first 10 packets got acked correctly. ECN should now be enabled.
        ecn_counts[packet::Epoch::Application].ect1_count += 8;
        ecn_counts[packet::Epoch::Application].ecn_ce_count += 2;
        let ce_events = ecn.on_ack_received(
            packet::Epoch::Application,
            10,
            Some(ecn_counts[packet::Epoch::Application]),
        );
        assert_eq!(ce_events, 2);
        for _ in 0..1000 {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT1);
        }
    }

    #[test]
    fn probing_ect0_but_lost_packets() {
        let mut ecn_counts = [packet::EcnCounts::default(); 3];
        let mut ecn = Ecn::new(true, false, ecn_counts);
        for _ in 0..3 {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT0);
        }
        ecn.on_packets_lost(2);

        // Our first 10 packets got acked correctly. ECN should now be enabled.
        ecn_counts[packet::Epoch::Application].ect0_count += 1;
        let ce_events = ecn.on_ack_received(
            packet::Epoch::Application,
            1,
            Some(ecn_counts[packet::Epoch::Application]),
        );
        assert_eq!(ce_events, 0);
        for _ in 0..ECN_LOSS_THRESHOLD {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), true);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_ECT0);
        }
        ecn.on_packets_lost(ECN_LOSS_THRESHOLD);
        for _ in 0..1000 {
            assert_eq!(ecn.is_next_sent_pkt_ecn_marked(), false);
            assert_eq!(ecn.get_ecn_value_to_send(), ECN_NOT_ECT);
        }
    }
}
