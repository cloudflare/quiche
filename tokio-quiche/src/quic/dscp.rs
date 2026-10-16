// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const UNMARKED: u8 = 64;

/// A six-bit Differentiated Services Code Point for outgoing UDP packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dscp(u8);

impl Dscp {
    /// Creates a DSCP value, rejecting values outside the six-bit range.
    pub const fn new(value: u8) -> Option<Self> {
        if value < UNMARKED {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the six-bit DSCP value.
    pub const fn value(self) -> u8 {
        self.0
    }

    #[cfg(any(all(target_os = "linux", not(feature = "fuzzing")), test))]
    pub(crate) const fn tos(self) -> u8 {
        self.0 << 2
    }
}

/// Per-connection DSCP shared with the QUIC I/O worker.
///
/// Clone this handle before starting the handshake and call [`Self::set`] once
/// the connection's final marking is known. `Dscp::new(0)` explicitly
/// clears an earlier marking even when the shared socket has a nonzero default;
/// `None` omits the per-packet control message.
#[derive(Clone, Debug)]
pub struct DscpHandle(Arc<AtomicU8>);

impl DscpHandle {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicU8::new(UNMARKED)))
    }

    /// Changes the DSCP used for subsequent packets on this connection.
    pub fn set(&self, dscp: Option<Dscp>) {
        // Relaxed ordering is enough; the byte synchronizes no other data.
        self.0
            .store(dscp.map_or(UNMARKED, Dscp::value), Ordering::Relaxed);
    }

    /// Returns the currently selected marking, or `None` if disabled.
    pub fn get(&self) -> Option<Dscp> {
        Dscp::new(self.0.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dscp_is_six_bits() {
        assert_eq!(Dscp::new(0).map(Dscp::tos), Some(0));
        assert_eq!(Dscp::new(34).map(Dscp::tos), Some(136));
        assert_eq!(Dscp::new(63).map(Dscp::tos), Some(252));
        assert_eq!(Dscp::new(64), None);
        assert_eq!(Dscp::new(255), None);
    }

    #[test]
    fn handles_share_only_their_own_connection() {
        let first = DscpHandle::new();
        let cloned = first.clone();
        let second = DscpHandle::new();

        assert_eq!(first.get(), None);
        assert_eq!(second.get(), None);
        second.set(Dscp::new(1));

        cloned.set(Dscp::new(28));
        assert_eq!(first.get(), Dscp::new(28));
        assert_eq!(second.get(), Dscp::new(1));

        cloned.set(Dscp::new(0));
        assert_eq!(first.get(), Dscp::new(0));
        cloned.set(None);
        assert_eq!(first.get(), None);
        assert_eq!(second.get(), Dscp::new(1));
    }
}
