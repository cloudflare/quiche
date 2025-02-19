// Copyright (C) 2025, Cloudflare, Inc.
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

use std::future::poll_fn;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use crate::http3::driver::H3ConnectionError;
use crate::quic::QuicheConnection;

use foundations::telemetry::log;
use tokio_util::time::delay_queue::DelayQueue;
use tokio_util::time::delay_queue::{
    self,
};

/// Unified configuration parameters for
/// [H3Driver](crate::http3::driver::H3Driver)s.
#[derive(Default, Clone, Debug)]
pub struct Http3Settings {
    /// Maximum number of requests a
    /// [ServerH3Driver](crate::http3::driver::ServerH3Driver) allows per
    /// connection.
    pub max_requests_per_connection: Option<u64>,
    /// Maximum size of a single HEADERS frame, in bytes.
    pub max_header_list_size: Option<u64>,
    /// Maximum value the QPACK encoder is permitted to set for the dynamic
    /// table capcity. See <https://www.rfc-editor.org/rfc/rfc9204.html#name-maximum-dynamic-table-capac>
    pub qpack_max_table_capacity: Option<u64>,
    /// Upper bound on the number of streams that can be blocked on the QPACK
    /// decoder. See <https://www.rfc-editor.org/rfc/rfc9204.html#name-blocked-streams>
    pub qpack_blocked_streams: Option<u64>,
    /// Timeout between starting the QUIC handshake and receiving the first
    /// request on a connection. Only applicable to
    /// [ServerH3Driver](crate::http3::driver::ServerH3Driver).
    pub post_accept_timeout: Option<Duration>,
}

impl From<&Http3Settings> for quiche::h3::Config {
    fn from(value: &Http3Settings) -> Self {
        let mut config = Self::new().unwrap();

        if let Some(v) = value.max_header_list_size {
            config.set_max_field_section_size(v);
        }
        if let Some(v) = value.qpack_max_table_capacity {
            config.set_qpack_max_table_capacity(v);
        }
        if let Some(v) = value.qpack_blocked_streams {
            config.set_qpack_blocked_streams(v);
        }

        config
    }
}

/// Opaque handle to an entry in [`Http3Timeouts`].
pub(crate) struct TimeoutKey(delay_queue::Key);

pub(crate) struct Http3SettingsEnforcer {
    limits: Http3Limits,
    timeouts: Http3Timeouts,
}

impl From<&Http3Settings> for Http3SettingsEnforcer {
    fn from(value: &Http3Settings) -> Self {
        Self {
            limits: Http3Limits {
                max_requests_per_connection: value.max_requests_per_connection,
            },
            timeouts: Http3Timeouts {
                post_accept_timeout: value.post_accept_timeout,
                delay_queue: DelayQueue::new(),
            },
        }
    }
}

impl Http3SettingsEnforcer {
    /// Returns a boolean indicating whether or not the connection should be
    /// closed due to a violation of the request count limit.
    pub fn enforce_requests_limit(&self, request_count: u64) -> bool {
        if let Some(limit) = self.limits.max_requests_per_connection {
            return request_count >= limit;
        }

        false
    }

    /// Returns the configured post-accept timeout.
    pub fn post_accept_timeout(&self) -> Option<Duration> {
        self.timeouts.post_accept_timeout
    }

    /// Registers a timeout of `typ` in this [Http3SettingsEnforcer].
    pub fn add_timeout(
        &mut self, typ: Http3TimeoutType, duration: Duration,
    ) -> TimeoutKey {
        let key = self.timeouts.delay_queue.insert(typ, duration);
        TimeoutKey(key)
    }

    /// Checks whether the [Http3SettingsEnforcer] has any pending timeouts.
    /// This should be used to selectively poll `enforce_timeouts`.
    pub fn has_pending_timeouts(&self) -> bool {
        !self.timeouts.delay_queue.is_empty()
    }

    /// Checks which timeouts have expired.
    fn poll_timeouts(&mut self, cx: &mut Context) -> Poll<TimeoutCheckResult> {
        let mut changed = false;
        let mut result = TimeoutCheckResult::default();

        while let Poll::Ready(Some(exp)) =
            self.timeouts.delay_queue.poll_expired(cx)
        {
            changed |= result.set_expired(exp.into_inner());
        }

        if changed {
            return Poll::Ready(result);
        }
        Poll::Pending
    }

    /// Waits for at least one registered timeout to expire.
    ///
    /// This function will automatically call `close()` on the underlying
    /// [quiche::Connection].
    pub async fn enforce_timeouts(
        &mut self, qconn: &mut QuicheConnection,
    ) -> Result<(), H3ConnectionError> {
        let result = poll_fn(|cx| self.poll_timeouts(cx)).await;

        if result.connection_timed_out {
            log::debug!("connection timed out due to post-accept-timeout"; "scid" => ?qconn.source_id());
            qconn.close(true, quiche::h3::WireErrorCode::NoError as u64, &[])?;
        }

        Ok(())
    }

    /// Cancels a timeout that was previously registered with `add_timeout`.
    pub fn cancel_timeout(&mut self, key: TimeoutKey) {
        self.timeouts.delay_queue.remove(&key.0);
    }
}

// TODO(rmehra): explore if these should really be Options, or if we
// should enforce sane defaults
struct Http3Limits {
    max_requests_per_connection: Option<u64>,
}

struct Http3Timeouts {
    post_accept_timeout: Option<Duration>,
    delay_queue: DelayQueue<Http3TimeoutType>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Http3TimeoutType {
    PostAccept,
}

#[derive(Default, Eq, PartialEq)]
struct TimeoutCheckResult {
    connection_timed_out: bool,
}

impl TimeoutCheckResult {
    fn set_expired(&mut self, typ: Http3TimeoutType) -> bool {
        use Http3TimeoutType::*;
        let field = match typ {
            PostAccept => &mut self.connection_timed_out,
        };

        *field = true;
        true
    }
}
