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

use std::time;

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::SocketAddr;

use slab::Slab;

use crate::Error;
use crate::Result;

use crate::recovery;
use crate::recovery::HandshakeStatus;

/// The different states of the path validation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathState {
    /// The path failed its validation.
    Failed,

    /// The path exists, but no path validation has been performed.
    Unknown,

    /// The path is under validation.
    Validating,

    /// The remote address has been validated, but not the path MTU.
    ValidatingMTU,

    /// The path has been validated.
    Validated,
}

impl PathState {
    #[cfg(feature = "ffi")]
    pub fn to_c(self) -> libc::ssize_t {
        match self {
            PathState::Failed => -1,
            PathState::Unknown => 0,
            PathState::Validating => 1,
            PathState::ValidatingMTU => 2,
            PathState::Validated => 3,
        }
    }
}

/// A path-specific event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathEvent {
    /// A new network path (local address, peer address) has been seen on a
    /// received packet. Note that this event is only triggered for servers, as
    /// the client is responsible from initiating new paths. The application may
    /// then probe this new path, if desired.
    New(SocketAddr, SocketAddr),

    /// The related network path between local `SocketAddr` and peer
    /// `SocketAddr` has been validated.
    Validated(SocketAddr, SocketAddr),

    /// The related network path between local `SocketAddr` and peer
    /// `SocketAddr` failed to be validated. This network path will not be used
    /// anymore, unless the application requests probing this path again.
    FailedValidation(SocketAddr, SocketAddr),

    /// The related network path between local `SocketAddr` and peer
    /// `SocketAddr` has been closed and is now unusable on this connection.
    Closed(SocketAddr, SocketAddr),

    /// The stack observes that the Source Connection ID with the given sequence
    /// number, initially used by the peer over the first pair of `SocketAddr`s,
    /// is now reused over the second pair of `SocketAddr`s.
    ReusedSourceConnectionId(
        u64,
        (SocketAddr, SocketAddr),
        (SocketAddr, SocketAddr),
    ),

    /// The connection observed that the peer migrated over the network path
    /// denoted by the pair of `SocketAddr`, i.e., non-probing packets have been
    /// received on this network path. This is a server side only event.
    ///
    /// Note that this event is only raised if the path has been validated.
    PeerMigrated(SocketAddr, SocketAddr),
}

/// A network path on which QUIC packets can be sent.
#[derive(Debug)]
pub struct Path {
    /// The local address.
    local_addr: SocketAddr,

    /// The remote address.
    peer_addr: SocketAddr,

    /// Source CID sequence number used over that path.
    pub active_scid_seq: Option<u64>,

    /// Destination CID sequence number used over that path.
    pub active_dcid_seq: Option<u64>,

    /// The current validation state of the path.
    state: PathState,

    /// Is this path used to send non-probing packets.
    active: bool,

    /// Loss recovery and congestion control state.
    pub recovery: recovery::Recovery,

    /// Pending challenge data with the size of the packet containing them and
    /// when they were sent.
    in_flight_challenges: VecDeque<([u8; 8], usize, time::Instant)>,

    /// The maximum challenge size that got acknowledged.
    max_challenge_size: usize,

    /// Number of consecutive (spaced by at least 1 RTT) probing packets lost.
    probing_lost: usize,

    /// Last instant when a probing packet got lost.
    last_probe_lost_time: Option<time::Instant>,

    /// Received challenge data.
    received_challenges: VecDeque<[u8; 8]>,

    /// Number of packets sent on this path.
    pub sent_count: usize,

    /// Number of packets received on this path.
    pub recv_count: usize,

    /// Total number of packets sent with data retransmitted from this path.
    pub retrans_count: usize,

    /// Total number of sent bytes over this path.
    pub sent_bytes: u64,

    /// Total number of bytes received over this path.
    pub recv_bytes: u64,

    /// Total number of bytes retransmitted from this path.
    /// This counts only STREAM and CRYPTO data.
    pub stream_retrans_bytes: u64,

    /// Total number of bytes the server can send before the peer's address
    /// is verified.
    pub max_send_bytes: usize,

    /// Whether the peer's address has been verified.
    pub verified_peer_address: bool,

    /// Whether the peer has verified our address.
    pub peer_verified_local_address: bool,

    /// Does it requires sending PATH_CHALLENGE?
    challenge_requested: bool,

    /// Whether the failure of this path was notified.
    failure_notified: bool,

    /// Whether the connection tries to migrate to this path, but it still needs
    /// to be validated.
    migrating: bool,
}

impl Path {
    /// Create a new Path instance with the provided addresses, the remaining of
    /// the fields being set to their default value.
    pub fn new(
        local_addr: SocketAddr, peer_addr: SocketAddr,
        recovery_config: &recovery::RecoveryConfig, is_initial: bool,
    ) -> Self {
        let (state, active_scid_seq, active_dcid_seq) = if is_initial {
            (PathState::Validated, Some(0), Some(0))
        } else {
            (PathState::Unknown, None, None)
        };

        Self {
            local_addr,
            peer_addr,
            active_scid_seq,
            active_dcid_seq,
            state,
            active: false,
            recovery: recovery::Recovery::new_with_config(recovery_config),
            in_flight_challenges: VecDeque::new(),
            max_challenge_size: 0,
            probing_lost: 0,
            last_probe_lost_time: None,
            received_challenges: VecDeque::new(),
            sent_count: 0,
            recv_count: 0,
            retrans_count: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            stream_retrans_bytes: 0,
            max_send_bytes: 0,
            verified_peer_address: false,
            peer_verified_local_address: false,
            challenge_requested: false,
            failure_notified: false,
            migrating: false,
        }
    }

    /// Returns the local address on which this path operates.
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the peer address on which this path operates.
    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns whether the path is working (i.e., not failed).
    #[inline]
    fn working(&self) -> bool {
        self.state > PathState::Failed
    }

    /// Returns whether the path is active.
    #[inline]
    pub fn active(&self) -> bool {
        self.active && self.working() && self.active_dcid_seq.is_some()
    }

    /// Returns whether the path can be used to send non-probing packets.
    #[inline]
    pub fn usable(&self) -> bool {
        self.active() ||
            (self.state == PathState::Validated &&
                self.active_dcid_seq.is_some())
    }

    /// Returns whether the path is unused.
    #[inline]
    fn unused(&self) -> bool {
        // FIXME: we should check that there is nothing in the sent queue.
        !self.active() && self.active_dcid_seq.is_none()
    }

    /// Returns whether the path requires sending a probing packet.
    #[inline]
    pub fn probing_required(&self) -> bool {
        !self.received_challenges.is_empty() || self.validation_requested()
    }

    /// Promotes the path to the provided state only if the new state is greater
    /// than the current one.
    fn promote_to(&mut self, state: PathState) {
        if self.state < state {
            self.state = state;
        }
    }

    /// Returns whether the path is validated.
    #[inline]
    pub fn validated(&self) -> bool {
        self.state == PathState::Validated
    }

    /// Returns whether this path failed its validation.
    #[inline]
    fn validation_failed(&self) -> bool {
        self.state == PathState::Failed
    }

    // Returns whether this path is under path validation process.
    #[inline]
    pub fn under_validation(&self) -> bool {
        matches!(self.state, PathState::Validating | PathState::ValidatingMTU)
    }

    /// Requests path validation.
    #[inline]
    pub fn request_validation(&mut self) {
        self.challenge_requested = true;
    }

    /// Returns whether a validation is requested.
    #[inline]
    pub fn validation_requested(&self) -> bool {
        self.challenge_requested
    }

    pub fn on_challenge_sent(&mut self) {
        self.promote_to(PathState::Validating);
        self.challenge_requested = false;
    }

    pub fn on_challenge_received(&mut self, data: [u8; 8]) {
        self.received_challenges.push_back(data);
        self.peer_verified_local_address = true;
    }

    pub fn has_pending_challenge(&self, data: [u8; 8]) -> bool {
        self.in_flight_challenges.iter().any(|(d, ..)| *d == data)
    }

    /// Returns whether the path is now validated.
    pub fn on_response_received(&mut self, data: [u8; 8]) -> bool {
        self.verified_peer_address = true;
        self.probing_lost = 0;

        let mut challenge_size = 0;
        self.in_flight_challenges.retain(|(d, s, _)| {
            if *d == data {
                challenge_size = *s;
                false
            } else {
                true
            }
        });

        // The 4-tuple is reachable, but we didn't check Path MTU yet.
        self.promote_to(PathState::ValidatingMTU);

        self.max_challenge_size =
            std::cmp::max(self.max_challenge_size, challenge_size);

        if self.state == PathState::ValidatingMTU {
            if self.max_challenge_size >= crate::MIN_CLIENT_INITIAL_LEN {
                // Path MTU is sufficient for QUIC traffic.
                self.promote_to(PathState::Validated);
                return true;
            }

            // If the MTU was not validated, probe again.
            self.request_validation();
        }

        false
    }

    fn on_failed_validation(&mut self) {
        self.state = PathState::Failed;
        self.active = false;
    }

    #[inline]
    pub fn pop_received_challenge(&mut self) -> Option<[u8; 8]> {
        self.received_challenges.pop_front()
    }

    pub fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: time::Instant,
        is_server: bool, trace_id: &str,
    ) -> (usize, usize) {
        let (lost_packets, lost_bytes) = self.recovery.on_loss_detection_timeout(
            handshake_status,
            now,
            trace_id,
        );

        let mut lost_probe_time = None;
        self.in_flight_challenges.retain(|(_, _, sent_time)| {
            if *sent_time <= now {
                if lost_probe_time.is_none() {
                    lost_probe_time = Some(*sent_time);
                }
                false
            } else {
                true
            }
        });

        // If we lost probing packets, check if the path failed
        // validation.
        if let Some(lost_probe_time) = lost_probe_time {
            self.last_probe_lost_time = match self.last_probe_lost_time {
                Some(last) => {
                    // Count a loss if at least 1-RTT happened.
                    if lost_probe_time - last >= self.recovery.rtt() {
                        self.probing_lost += 1;
                        Some(lost_probe_time)
                    } else {
                        Some(last)
                    }
                },
                None => {
                    self.probing_lost += 1;
                    Some(lost_probe_time)
                },
            };
            // As a server, if requesting a challenge is not
            // possible due to the amplification attack, declare the
            // validation as failed.
            if self.probing_lost >= crate::MAX_PROBING_TIMEOUTS ||
                (is_server && self.max_send_bytes < crate::MIN_PROBING_SIZE)
            {
                self.on_failed_validation();
            } else {
                self.request_validation();
            }
        }

        (lost_packets, lost_bytes)
    }

    pub fn stats(&self) -> PathStats {
        PathStats {
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
            validation_state: self.state,
            active: self.active,
            recv: self.recv_count,
            sent: self.sent_count,
            lost: self.recovery.lost_count,
            retrans: self.retrans_count,
            rtt: self.recovery.rtt(),
            cwnd: self.recovery.cwnd(),
            sent_bytes: self.sent_bytes,
            recv_bytes: self.recv_bytes,
            lost_bytes: self.recovery.bytes_lost,
            stream_retrans_bytes: self.stream_retrans_bytes,
            pmtu: self.recovery.max_datagram_size(),
            delivery_rate: self.recovery.delivery_rate(),
        }
    }
}

/// An iterator over SocketAddr.
#[derive(Default)]
pub struct SocketAddrIter {
    pub(crate) sockaddrs: Vec<SocketAddr>,
}

impl Iterator for SocketAddrIter {
    type Item = SocketAddr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.sockaddrs.pop()
    }
}

impl ExactSizeIterator for SocketAddrIter {
    #[inline]
    fn len(&self) -> usize {
        self.sockaddrs.len()
    }
}

/// All path-related information.
pub struct PathMap {
    /// The paths of the connection. Each of them has an internal identifier
    /// that is used by `addrs_to_paths` and `ConnectionEntry`.
    paths: Slab<Path>,

    /// The maximum number of concurrent paths allowed.
    max_concurrent_paths: usize,

    /// The mapping from the (local `SocketAddr`, peer `SocketAddr`) to the
    /// `Path` structure identifier.
    addrs_to_paths: BTreeMap<(SocketAddr, SocketAddr), usize>,

    /// Path-specific events to be notified to the application.
    events: VecDeque<PathEvent>,

    /// Whether this manager serves a connection as a server.
    is_server: bool,
}

impl PathMap {
    /// Creates a new `PathMap` with the initial provided `path` and a
    /// capacity limit.
    pub fn new(
        mut initial_path: Path, max_concurrent_paths: usize, is_server: bool,
    ) -> Self {
        let mut paths = Slab::with_capacity(1); // most connections only have one path
        let mut addrs_to_paths = BTreeMap::new();

        let local_addr = initial_path.local_addr;
        let peer_addr = initial_path.peer_addr;

        // As it is the first path, it is active by default.
        initial_path.active = true;

        let active_path_id = paths.insert(initial_path);
        addrs_to_paths.insert((local_addr, peer_addr), active_path_id);

        Self {
            paths,
            max_concurrent_paths,
            addrs_to_paths,
            events: VecDeque::new(),
            is_server,
        }
    }

    /// Gets an immutable reference to the path identified by `path_id`. If the
    /// provided `path_id` does not identify any current `Path`, returns an
    /// [`InvalidState`].
    ///
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    #[inline]
    pub fn get(&self, path_id: usize) -> Result<&Path> {
        self.paths.get(path_id).ok_or(Error::InvalidState)
    }

    /// Gets a mutable reference to the path identified by `path_id`. If the
    /// provided `path_id` does not identify any current `Path`, returns an
    /// [`InvalidState`].
    ///
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    #[inline]
    pub fn get_mut(&mut self, path_id: usize) -> Result<&mut Path> {
        self.paths.get_mut(path_id).ok_or(Error::InvalidState)
    }

    #[inline]
    /// Gets an immutable reference to the active path with the value of the
    /// lowest identifier. If there is no active path, returns `None`.
    pub fn get_active_with_pid(&self) -> Option<(usize, &Path)> {
        self.paths.iter().find(|(_, p)| p.active())
    }

    /// Gets an immutable reference to the active path with the lowest
    /// identifier. If there is no active path, returns an [`InvalidState`].
    ///
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    #[inline]
    pub fn get_active(&self) -> Result<&Path> {
        self.get_active_with_pid()
            .map(|(_, p)| p)
            .ok_or(Error::InvalidState)
    }

    /// Gets the lowest active path identifier. If there is no active path,
    /// returns an [`InvalidState`].
    ///
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    #[inline]
    pub fn get_active_path_id(&self) -> Result<usize> {
        self.get_active_with_pid()
            .map(|(pid, _)| pid)
            .ok_or(Error::InvalidState)
    }

    /// Gets an mutable reference to the active path with the lowest identifier.
    /// If there is no active path, returns an [`InvalidState`].
    ///
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    #[inline]
    pub fn get_active_mut(&mut self) -> Result<&mut Path> {
        self.paths
            .iter_mut()
            .map(|(_, p)| p)
            .find(|p| p.active())
            .ok_or(Error::InvalidState)
    }

    /// Returns an iterator over all existing paths.
    #[inline]
    pub fn iter(&self) -> slab::Iter<Path> {
        self.paths.iter()
    }

    /// Returns a mutable iterator over all existing paths.
    #[inline]
    pub fn iter_mut(&mut self) -> slab::IterMut<Path> {
        self.paths.iter_mut()
    }

    /// Returns the number of existing paths.
    #[inline]
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Returns the `Path` identifier related to the provided `addrs`.
    #[inline]
    pub fn path_id_from_addrs(
        &self, addrs: &(SocketAddr, SocketAddr),
    ) -> Option<usize> {
        self.addrs_to_paths.get(addrs).copied()
    }

    /// Checks if creating a new path will not exceed the current `self.paths`
    /// capacity. If yes, this method tries to remove one unused path. If it
    /// fails to do so, returns [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    fn make_room_for_new_path(&mut self) -> Result<()> {
        if self.paths.len() < self.max_concurrent_paths {
            return Ok(());
        }

        let (pid_to_remove, _) = self
            .paths
            .iter()
            .find(|(_, p)| p.unused())
            .ok_or(Error::Done)?;

        let path = self.paths.remove(pid_to_remove);
        self.addrs_to_paths
            .remove(&(path.local_addr, path.peer_addr));

        self.notify_event(PathEvent::Closed(path.local_addr, path.peer_addr));

        Ok(())
    }

    /// Records the provided `Path` and returns its assigned identifier.
    ///
    /// On success, this method takes care of creating a notification to the
    /// serving application, if it serves a server-side connection.
    ///
    /// If there are already `max_concurrent_paths` currently recorded, this
    /// method tries to remove an unused `Path` first. If it fails to do so,
    /// it returns [`Done`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn insert_path(&mut self, path: Path, is_server: bool) -> Result<usize> {
        self.make_room_for_new_path()?;

        let local_addr = path.local_addr;
        let peer_addr = path.peer_addr;

        let pid = self.paths.insert(path);
        self.addrs_to_paths.insert((local_addr, peer_addr), pid);

        // Notifies the application if we are in server mode.
        if is_server {
            self.notify_event(PathEvent::New(local_addr, peer_addr));
        }

        Ok(pid)
    }

    /// Notifies a path event to the application served by the connection.
    pub fn notify_event(&mut self, ev: PathEvent) {
        self.events.push_back(ev);
    }

    /// Gets the first path event to be notified to the application.
    pub fn pop_event(&mut self) -> Option<PathEvent> {
        self.events.pop_front()
    }

    /// Notifies all failed validations to the application.
    pub fn notify_failed_validations(&mut self) {
        let validation_failed = self
            .paths
            .iter_mut()
            .filter(|(_, p)| p.validation_failed() && !p.failure_notified);

        for (_, p) in validation_failed {
            self.events.push_back(PathEvent::FailedValidation(
                p.local_addr,
                p.peer_addr,
            ));

            p.failure_notified = true;
        }
    }

    /// Finds a path candidate to be active and returns its identifier.
    pub fn find_candidate_path(&self) -> Option<usize> {
        // TODO: also consider unvalidated paths if there are no more validated.
        self.paths
            .iter()
            .find(|(_, p)| p.usable())
            .map(|(pid, _)| pid)
    }

    /// Handles the sending of PATH_CHALLENGE.
    pub fn on_challenge_sent(
        &mut self, path_id: usize, data: [u8; 8], pkt_size: usize,
        sent_time: time::Instant,
    ) -> Result<()> {
        let path = self.get_mut(path_id)?;

        path.on_challenge_sent();
        path.in_flight_challenges
            .push_back((data, pkt_size, sent_time));

        Ok(())
    }

    /// Handles incoming PATH_RESPONSE data.
    pub fn on_response_received(&mut self, data: [u8; 8]) -> Result<()> {
        let active_pid = self.get_active_path_id()?;

        let challenge_pending =
            self.iter_mut().find(|(_, p)| p.has_pending_challenge(data));

        if let Some((pid, p)) = challenge_pending {
            if p.on_response_received(data) {
                let local_addr = p.local_addr;
                let peer_addr = p.peer_addr;
                let was_migrating = p.migrating;

                p.migrating = false;

                // Notifies the application.
                self.notify_event(PathEvent::Validated(local_addr, peer_addr));

                // If this path was the candidate for migration, notifies the
                // application.
                if pid == active_pid && was_migrating {
                    self.notify_event(PathEvent::PeerMigrated(
                        local_addr, peer_addr,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Sets the path with identifier 'path_id' to be active.
    ///
    /// There can be exactly one active path on which non-probing packets can be
    /// sent. If another path is marked as active, it will be superseded by the
    /// one having `path_id` as identifier.
    ///
    /// A server should always ensure that the active path is validated. If it
    /// is already the case, it notifies the application that the connection
    /// migrated. Otherwise, it triggers a path validation and defers the
    /// notification once it is actually validated.
    pub fn set_active_path(&mut self, path_id: usize) -> Result<()> {
        let is_server = self.is_server;

        if let Ok(old_active_path) = self.get_active_mut() {
            old_active_path.active = false;
        }

        let new_active_path = self.get_mut(path_id)?;
        new_active_path.active = true;

        if is_server {
            if new_active_path.validated() {
                let local_addr = new_active_path.local_addr();
                let peer_addr = new_active_path.peer_addr();

                self.notify_event(PathEvent::PeerMigrated(local_addr, peer_addr));
            } else {
                new_active_path.migrating = true;

                // Requests path validation if needed.
                if !new_active_path.under_validation() {
                    new_active_path.request_validation();
                }
            }
        }

        Ok(())
    }

    /// Handles potential connection migration.
    pub fn on_peer_migrated(
        &mut self, new_pid: usize, disable_dcid_reuse: bool,
    ) -> Result<()> {
        let active_path_id = self.get_active_path_id()?;

        if active_path_id == new_pid {
            return Ok(());
        }

        self.set_active_path(new_pid)?;

        let no_spare_dcid = self.get_mut(new_pid)?.active_dcid_seq.is_none();

        if no_spare_dcid && !disable_dcid_reuse {
            self.get_mut(new_pid)?.active_dcid_seq =
                self.get_mut(active_path_id)?.active_dcid_seq;
        }

        Ok(())
    }
}

/// Statistics about the path of a connection.
///
/// It is part of the `Stats` structure returned by the [`stats()`] method.
///
/// [`stats()`]: struct.Connection.html#method.stats
#[derive(Clone)]
pub struct PathStats {
    /// The local address of the path.
    pub local_addr: SocketAddr,

    /// The peer address of the path.
    pub peer_addr: SocketAddr,

    /// The path validation state.
    pub validation_state: PathState,

    /// Whether the path is marked as active.
    pub active: bool,

    /// The number of QUIC packets received.
    pub recv: usize,

    /// The number of QUIC packets sent.
    pub sent: usize,

    /// The number of QUIC packets that were lost.
    pub lost: usize,

    /// The number of sent QUIC packets with retransmitted data.
    pub retrans: usize,

    /// The estimated round-trip time of the connection.
    pub rtt: time::Duration,

    /// The size of the connection's congestion window in bytes.
    pub cwnd: usize,

    /// The number of sent bytes.
    pub sent_bytes: u64,

    /// The number of received bytes.
    pub recv_bytes: u64,

    /// The number of bytes lost.
    pub lost_bytes: u64,

    /// The number of stream bytes retransmitted.
    pub stream_retrans_bytes: u64,

    /// The current PMTU for the connection.
    pub pmtu: usize,

    /// The most recent data delivery rate estimate in bytes/s.
    ///
    /// Note that this value could be inaccurate if the application does not
    /// respect pacing hints (see [`SendInfo.at`] and [Pacing] for more
    /// details).
    ///
    /// [`SendInfo.at`]: struct.SendInfo.html#structfield.at
    /// [Pacing]: index.html#pacing
    pub delivery_rate: u64,
}

impl std::fmt::Debug for PathStats {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "local_addr={:?} peer_addr={:?} ",
            self.local_addr, self.peer_addr,
        )?;
        write!(
            f,
            "validation_state={:?} active={} ",
            self.validation_state, self.active,
        )?;
        write!(
            f,
            "recv={} sent={} lost={} retrans={} rtt={:?} cwnd={}",
            self.recv, self.sent, self.lost, self.retrans, self.rtt, self.cwnd,
        )?;

        write!(
            f,
            " sent_bytes={} recv_bytes={} lost_bytes={}",
            self.sent_bytes, self.recv_bytes, self.lost_bytes,
        )?;

        write!(
            f,
            " stream_retrans_bytes={} pmtu={} delivery_rate={}",
            self.stream_retrans_bytes, self.pmtu, self.delivery_rate,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::rand;
    use crate::MIN_CLIENT_INITIAL_LEN;

    use crate::recovery::RecoveryConfig;
    use crate::Config;

    use super::*;

    #[test]
    fn path_validation_limited_mtu() {
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let client_addr_2 = "127.0.0.1:5678".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config = RecoveryConfig::from_config(&config);

        let path = Path::new(client_addr, server_addr, &recovery_config, true);
        let mut path_mgr = PathMap::new(path, 2, false);

        let probed_path =
            Path::new(client_addr_2, server_addr, &recovery_config, false);
        path_mgr.insert_path(probed_path, false).unwrap();

        let pid = path_mgr
            .path_id_from_addrs(&(client_addr_2, server_addr))
            .unwrap();
        path_mgr.get_mut(pid).unwrap().request_validation();
        assert_eq!(path_mgr.get_mut(pid).unwrap().validation_requested(), true);
        assert_eq!(path_mgr.get_mut(pid).unwrap().probing_required(), true);

        // Fake sending of PathChallenge in a packet of MIN_CLIENT_INITIAL_LEN - 1
        // bytes.
        let data = rand::rand_u64().to_be_bytes();
        path_mgr
            .on_challenge_sent(
                pid,
                data,
                MIN_CLIENT_INITIAL_LEN - 1,
                time::Instant::now(),
            )
            .unwrap();

        assert_eq!(path_mgr.get_mut(pid).unwrap().validation_requested(), false);
        assert_eq!(path_mgr.get_mut(pid).unwrap().probing_required(), false);
        assert_eq!(path_mgr.get_mut(pid).unwrap().under_validation(), true);
        assert_eq!(path_mgr.get_mut(pid).unwrap().validated(), false);
        assert_eq!(path_mgr.get_mut(pid).unwrap().state, PathState::Validating);
        assert_eq!(path_mgr.pop_event(), None);

        // Receives the response. The path is reachable, but the MTU is not
        // validated yet.
        path_mgr.on_response_received(data).unwrap();

        assert_eq!(path_mgr.get_mut(pid).unwrap().validation_requested(), true);
        assert_eq!(path_mgr.get_mut(pid).unwrap().probing_required(), true);
        assert_eq!(path_mgr.get_mut(pid).unwrap().under_validation(), true);
        assert_eq!(path_mgr.get_mut(pid).unwrap().validated(), false);
        assert_eq!(
            path_mgr.get_mut(pid).unwrap().state,
            PathState::ValidatingMTU
        );
        assert_eq!(path_mgr.pop_event(), None);

        // Fake sending of PathChallenge in a packet of MIN_CLIENT_INITIAL_LEN
        // bytes.
        let data = rand::rand_u64().to_be_bytes();
        path_mgr
            .on_challenge_sent(
                pid,
                data,
                MIN_CLIENT_INITIAL_LEN,
                time::Instant::now(),
            )
            .unwrap();

        path_mgr.on_response_received(data).unwrap();

        assert_eq!(path_mgr.get_mut(pid).unwrap().validation_requested(), false);
        assert_eq!(path_mgr.get_mut(pid).unwrap().probing_required(), false);
        assert_eq!(path_mgr.get_mut(pid).unwrap().under_validation(), false);
        assert_eq!(path_mgr.get_mut(pid).unwrap().validated(), true);
        assert_eq!(path_mgr.get_mut(pid).unwrap().state, PathState::Validated);
        assert_eq!(
            path_mgr.pop_event(),
            Some(PathEvent::Validated(client_addr_2, server_addr))
        );
    }

    #[test]
    fn multiple_probes() {
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let server_addr = "127.0.0.1:4321".parse().unwrap();

        let config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config = RecoveryConfig::from_config(&config);

        let path = Path::new(client_addr, server_addr, &recovery_config, true);
        let mut client_path_mgr = PathMap::new(path, 2, false);
        let mut server_path =
            Path::new(server_addr, client_addr, &recovery_config, false);

        let client_pid = client_path_mgr
            .path_id_from_addrs(&(client_addr, server_addr))
            .unwrap();

        // First probe.
        let data = rand::rand_u64().to_be_bytes();
        client_path_mgr
            .on_challenge_sent(
                client_pid,
                data,
                MIN_CLIENT_INITIAL_LEN,
                time::Instant::now(),
            )
            .unwrap();

        // Second probe.
        let data_2 = rand::rand_u64().to_be_bytes();
        client_path_mgr
            .on_challenge_sent(
                client_pid,
                data_2,
                MIN_CLIENT_INITIAL_LEN,
                time::Instant::now(),
            )
            .unwrap();

        assert_eq!(
            client_path_mgr
                .get(client_pid)
                .unwrap()
                .in_flight_challenges
                .len(),
            2
        );

        // If we receive multiple challenges, we can store them.
        server_path.on_challenge_received(data);
        assert_eq!(server_path.received_challenges.len(), 1);
        server_path.on_challenge_received(data_2);
        assert_eq!(server_path.received_challenges.len(), 2);

        // Response for first probe.
        client_path_mgr.on_response_received(data).unwrap();
        assert_eq!(
            client_path_mgr
                .get(client_pid)
                .unwrap()
                .in_flight_challenges
                .len(),
            1
        );

        // Response for second probe.
        client_path_mgr.on_response_received(data_2).unwrap();
        assert_eq!(
            client_path_mgr
                .get(client_pid)
                .unwrap()
                .in_flight_challenges
                .len(),
            0
        );
    }
}
