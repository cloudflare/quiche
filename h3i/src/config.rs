// Copyright (C) 2024, Cloudflare, Inc.
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

//! Configuration for the h3i client.
use std::io;

#[derive(Default)]
/// Server details and QUIC connection properties.
pub struct Config {
    /// A string representing the host and port to connect to using the format
    /// `<host>:<port>`.
    pub host_port: String,
    /// If the SNI should be omitted during the TLS handshake.
    pub omit_sni: bool,
    /// Set a specific IP address to connect to, rather than use DNS resolution.
    pub connect_to: Option<String>,
    /// The source port to use when connecting to a server.
    pub source_port: u32,
    /// Whether to verify the server certificate.
    pub verify_peer: bool,
    /// The QUIC idle timeout value in milliseconds.
    pub idle_timeout: u64,
    /// Flow control limit for the connection in bytes
    pub max_data: u64,
    /// Flow control limit for locally-initiated bidirectional streams in bytes.
    pub max_stream_data_bidi_local: u64,
    /// Flow control limit for remotely-initiated bidirectional streams in
    /// bytes.
    pub max_stream_data_bidi_remote: u64,
    /// Flow control limit for unidirectional streams in bytes.
    pub max_stream_data_uni: u64,
    /// Maximum count for concurrent remotely-initiated bidirectional streams.
    pub max_streams_bidi: u64,
    /// "Maximum count for concurrent remotely-initiated unidirectional
    /// streams".
    pub max_streams_uni: u64,
    /// Receiver window limit for the connection in bytes.
    pub max_window: u64,
    /// Receiver window limit for a stream in bytes.
    pub max_stream_window: u64,
}

impl Config {
    /// Construct a new config object with default values.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_host_port(mut self, host_port: String) -> Self {
        self.host_port = host_port;
        self
    }

    pub fn omit_sni(mut self) -> Self {
        self.omit_sni = true;
        self
    }

    pub fn with_connect_to(mut self, connect_to: String) -> Self {
        self.connect_to = Some(connect_to);
        self
    }

    pub fn with_source_port(mut self, port: u32) -> Self {
        self.source_port = port;
        self
    }

    pub fn verify_peer(mut self, verify_peer: bool) -> Self {
        self.verify_peer = verify_peer;
        self
    }

    pub fn with_idle_timeout(mut self, idle_timeout: u64) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    pub fn with_max_data(mut self, max_data: u64) -> Self {
        self.max_data = max_data;
        self
    }

    pub fn with_max_stream_data_bidi_local(
        mut self, max_stream_data_bidi_local: u64,
    ) -> Self {
        self.max_stream_data_bidi_local = max_stream_data_bidi_local;
        self
    }

    pub fn with_max_stream_data_bidi_remote(
        mut self, max_stream_data_bidi_remote: u64,
    ) -> Self {
        self.max_stream_data_bidi_remote = max_stream_data_bidi_remote;
        self
    }

    pub fn with_max_stream_data_uni(mut self, max_stream_data_uni: u64) -> Self {
        self.max_stream_data_uni = max_stream_data_uni;
        self
    }

    pub fn with_max_streams_bidi(mut self, max_streams_bidi: u64) -> Self {
        self.max_streams_bidi = max_streams_bidi;
        self
    }

    pub fn with_max_streams_uni(mut self, max_streams_uni: u64) -> Self {
        self.max_streams_uni = max_streams_uni;
        self
    }

    pub fn with_max_window(mut self, max_window: u64) -> Self {
        self.max_window = max_window;
        self
    }

    pub fn with_max_stream_window(mut self, max_stream_window: u64) -> Self {
        self.max_stream_window = max_stream_window;
        self
    }

    pub fn build(self) -> Result<Self, io::Error> {
        if self.host_port.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Must provide a <host:port> to connect".to_string(),
            ));
        }

        Ok(Config {
            host_port: self.host_port,
            omit_sni: self.omit_sni,
            connect_to: self.connect_to,
            source_port: self.source_port,
            verify_peer: self.verify_peer,
            idle_timeout: self.idle_timeout,
            max_data: self.max_data,
            max_stream_data_bidi_local: self.max_stream_data_bidi_local,
            max_stream_data_bidi_remote: self.max_stream_data_bidi_remote,
            max_stream_data_uni: self.max_stream_data_uni,
            max_streams_bidi: self.max_streams_bidi,
            max_streams_uni: self.max_streams_uni,
            max_window: self.max_window,
            max_stream_window: self.max_stream_window,
        })
    }
}
