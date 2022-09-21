// Copyright (C) 2020, Cloudflare, Inc.
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

use super::common::alpns;

pub trait Args {
    fn with_docopt(docopt: &docopt::Docopt) -> Self;
}

/// Contains commons arguments for creating a quiche QUIC connection.
pub struct CommonArgs {
    pub alpns: Vec<&'static [u8]>,
    pub max_data: u64,
    pub max_window: u64,
    pub max_stream_data: u64,
    pub max_stream_window: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub idle_timeout: u64,
    pub early_data: bool,
    pub dump_packet_path: Option<String>,
    pub no_grease: bool,
    pub cc_algorithm: String,
    pub disable_hystart: bool,
    pub dgrams_enabled: bool,
    pub dgram_count: u64,
    pub dgram_data: String,
    pub max_active_cids: u64,
    pub enable_active_migration: bool,
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
}

/// Creates a new `CommonArgs` structure using the provided [`Docopt`].
///
/// The `Docopt` usage String needs to include the following:
///
/// --http-version VERSION      HTTP version to use.
/// --max-data BYTES            Connection-wide flow control limit.
/// --max-window BYTES          Connection-wide max receiver window.
/// --max-stream-data BYTES     Per-stream flow control limit.
/// --max-stream-window BYTES   Per-stream max receiver window.
/// --max-streams-bidi STREAMS  Number of allowed concurrent streams.
/// --max-streams-uni STREAMS   Number of allowed concurrent streams.
/// --dump-packets PATH         Dump the incoming packets in PATH.
/// --no-grease                 Don't send GREASE.
/// --cc-algorithm NAME         Set a congestion control algorithm.
/// --disable-hystart           Disable HyStart++.
/// --dgram-proto PROTO         DATAGRAM application protocol.
/// --dgram-count COUNT         Number of DATAGRAMs to send.
/// --dgram-data DATA           DATAGRAM data to send.
/// --max-active-cids NUM       Maximum number of active Connection IDs.
/// --enable-active-migration   Enable active connection migration.
/// --max-field-section-size BYTES  Max size of uncompressed field section.
/// --qpack-max-table-capacity BYTES  Max capacity of dynamic QPACK decoding.
/// --qpack-blocked-streams STREAMS  Limit of blocked streams while decoding.
///
/// [`Docopt`]: https://docs.rs/docopt/1.1.0/docopt/
impl Args for CommonArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let http_version = args.get_str("--http-version");
        let dgram_proto = args.get_str("--dgram-proto");
        let (alpns, dgrams_enabled) = match (http_version, dgram_proto) {
            ("HTTP/0.9", "none") => (alpns::HTTP_09.to_vec(), false),

            ("HTTP/0.9", _) =>
                panic!("Unsupported HTTP version and DATAGRAM protocol."),

            ("HTTP/3", "none") => (alpns::HTTP_3.to_vec(), false),

            ("HTTP/3", "oneway") => (alpns::HTTP_3.to_vec(), true),

            ("all", "none") => (
                [alpns::HTTP_3.as_slice(), &alpns::HTTP_09]
                    .concat()
                    .to_vec(),
                false,
            ),

            // SiDuck is it's own application protocol.
            (_, "siduck") => (alpns::SIDUCK.to_vec(), true),

            (..) => panic!("Unsupported HTTP version and DATAGRAM protocol."),
        };

        let dgram_count = args.get_str("--dgram-count");
        let dgram_count = dgram_count.parse::<u64>().unwrap();

        let dgram_data = args.get_str("--dgram-data").to_string();

        let max_data = args.get_str("--max-data");
        let max_data = max_data.parse::<u64>().unwrap();

        let max_window = args.get_str("--max-window");
        let max_window = max_window.parse::<u64>().unwrap();

        let max_stream_data = args.get_str("--max-stream-data");
        let max_stream_data = max_stream_data.parse::<u64>().unwrap();

        let max_stream_window = args.get_str("--max-stream-window");
        let max_stream_window = max_stream_window.parse::<u64>().unwrap();

        let max_streams_bidi = args.get_str("--max-streams-bidi");
        let max_streams_bidi = max_streams_bidi.parse::<u64>().unwrap();

        let max_streams_uni = args.get_str("--max-streams-uni");
        let max_streams_uni = max_streams_uni.parse::<u64>().unwrap();

        let idle_timeout = args.get_str("--idle-timeout");
        let idle_timeout = idle_timeout.parse::<u64>().unwrap();

        let early_data = args.get_bool("--early-data");

        let dump_packet_path = if args.get_str("--dump-packets") != "" {
            Some(args.get_str("--dump-packets").to_string())
        } else {
            None
        };

        let no_grease = args.get_bool("--no-grease");

        let cc_algorithm = args.get_str("--cc-algorithm");

        let disable_hystart = args.get_bool("--disable-hystart");

        let max_active_cids = args.get_str("--max-active-cids");
        let max_active_cids = max_active_cids.parse::<u64>().unwrap();

        let enable_active_migration = args.get_bool("--enable-active-migration");

        let max_field_section_size =
            if args.get_str("--max-field-section-size") != "" {
                Some(
                    args.get_str("--max-field-section-size")
                        .parse::<u64>()
                        .unwrap(),
                )
            } else {
                None
            };

        let qpack_max_table_capacity =
            if args.get_str("--qpack-max-table-capacity") != "" {
                Some(
                    args.get_str("--qpack-max-table-capacity")
                        .parse::<u64>()
                        .unwrap(),
                )
            } else {
                None
            };

        let qpack_blocked_streams =
            if args.get_str("--qpack-blocked-streams") != "" {
                Some(
                    args.get_str("--qpack-blocked-streams")
                        .parse::<u64>()
                        .unwrap(),
                )
            } else {
                None
            };

        CommonArgs {
            alpns,
            max_data,
            max_window,
            max_stream_data,
            max_stream_window,
            max_streams_bidi,
            max_streams_uni,
            idle_timeout,
            early_data,
            dump_packet_path,
            no_grease,
            cc_algorithm: cc_algorithm.to_string(),
            disable_hystart,
            dgrams_enabled,
            dgram_count,
            dgram_data,
            max_active_cids,
            enable_active_migration,
            max_field_section_size,
            qpack_max_table_capacity,
            qpack_blocked_streams,
        }
    }
}

impl Default for CommonArgs {
    fn default() -> Self {
        CommonArgs {
            alpns: alpns::HTTP_3.to_vec(),
            max_data: 10000000,
            max_window: 25165824,
            max_stream_data: 1000000,
            max_stream_window: 16777216,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            idle_timeout: 30000,
            early_data: false,
            dump_packet_path: None,
            no_grease: false,
            cc_algorithm: "cubic".to_string(),
            disable_hystart: false,
            dgrams_enabled: false,
            dgram_count: 0,
            dgram_data: "quack".to_string(),
            max_active_cids: 2,
            enable_active_migration: false,
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        }
    }
}

pub const CLIENT_USAGE: &str = "Usage:
  quiche-client [options] URL...
  quiche-client -h | --help

Options:
  --method METHOD          Use the given HTTP request method [default: GET].
  --body FILE              Send the given file as request body.
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-window BYTES       Connection-wide max receiver window [default: 25165824].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --max-stream-window BYTES   Per-stream max receiver window [default: 16777216].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT   Idle timeout in milliseconds [default: 30000].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --http-version VERSION   HTTP version to use [default: all].
  --early-data             Enable sending early data.
  --dgram-proto PROTO      DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT      Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA        Data to send for certain types of DATAGRAM application protocol [default: quack].
  --dump-packets PATH      Dump the incoming packets as files in the given directory.
  --dump-responses PATH    Dump response payload as files in the given directory.
  --dump-json              Dump response headers and payload to stdout in JSON format.
  --max-json-payload BYTES  Per-response payload limit when dumping JSON [default: 10000].
  --connect-to ADDRESS     Override ther server's address.
  --no-verify              Don't verify server's certificate.
  --no-grease              Don't send GREASE.
  --cc-algorithm NAME      Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart        Disable HyStart++.
  --max-active-cids NUM    The maximum number of active Connection IDs we can support [default: 2].
  --enable-active-migration   Enable active connection migration.
  --perform-migration      Perform connection migration on another source port.
  -H --header HEADER ...   Add a request header.
  -n --requests REQUESTS   Send the given number of identical requests [default: 1].
  --send-priority-update   Send HTTP/3 priority updates if the query string params 'u' or 'i' are present in URLs
  --max-field-section-size BYTES    Max size of uncompressed field section. Default is unlimited.
  --qpack-max-table-capacity BYTES  Max capacity of dynamic QPACK decoding.. Any value other that 0 is currently unsupported.
  --qpack-blocked-streams STREAMS   Limit of blocked streams while decoding. Any value other that 0 is currently unsupported.
  --session-file PATH      File used to cache a TLS session for resumption.
  --source-port PORT       Source port to use when connecting to the server [default: 0].
  -h --help                Show this screen.
";

/// Application-specific arguments that compliment the `CommonArgs`.
pub struct ClientArgs {
    pub version: u32,
    pub dump_response_path: Option<String>,
    pub dump_json: Option<usize>,
    pub urls: Vec<url::Url>,
    pub reqs_cardinal: u64,
    pub req_headers: Vec<String>,
    pub no_verify: bool,
    pub body: Option<Vec<u8>>,
    pub method: String,
    pub connect_to: Option<String>,
    pub session_file: Option<String>,
    pub source_port: u16,
    pub perform_migration: bool,
    pub send_priority_update: bool,
}

impl Args for ClientArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let version = args.get_str("--wire-version");
        let version = u32::from_str_radix(version, 16).unwrap();

        let dump_response_path = if args.get_str("--dump-responses") != "" {
            Some(args.get_str("--dump-responses").to_string())
        } else {
            None
        };

        let dump_json = args.get_bool("--dump-json");
        let dump_json = if dump_json {
            let max_payload = args.get_str("--max-json-payload");
            let max_payload = max_payload.parse::<usize>().unwrap();
            Some(max_payload)
        } else {
            None
        };

        // URLs (can be multiple).
        let urls: Vec<url::Url> = args
            .get_vec("URL")
            .into_iter()
            .map(|x| url::Url::parse(x).unwrap())
            .collect();

        // Request headers (can be multiple).
        let req_headers = args
            .get_vec("--header")
            .into_iter()
            .map(|x| x.to_string())
            .collect();

        let reqs_cardinal = args.get_str("--requests");
        let reqs_cardinal = reqs_cardinal.parse::<u64>().unwrap();

        let no_verify = args.get_bool("--no-verify");

        let body = if args.get_bool("--body") {
            std::fs::read(args.get_str("--body")).ok()
        } else {
            None
        };

        let method = args.get_str("--method").to_string();

        let connect_to = if args.get_bool("--connect-to") {
            Some(args.get_str("--connect-to").to_string())
        } else {
            None
        };

        let session_file = if args.get_bool("--session-file") {
            Some(args.get_str("--session-file").to_string())
        } else {
            None
        };

        let source_port = args.get_str("--source-port");
        let source_port = source_port.parse::<u16>().unwrap();

        let perform_migration = args.get_bool("--perform-migration");

        let send_priority_update = args.get_bool("--send-priority-update");

        ClientArgs {
            version,
            dump_response_path,
            dump_json,
            urls,
            reqs_cardinal,
            req_headers,
            no_verify,
            body,
            method,
            connect_to,
            session_file,
            source_port,
            perform_migration,
            send_priority_update,
        }
    }
}

impl Default for ClientArgs {
    fn default() -> Self {
        ClientArgs {
            version: 0xbabababa,
            dump_response_path: None,
            dump_json: None,
            urls: vec![],
            req_headers: vec![],
            reqs_cardinal: 1,
            no_verify: false,
            body: None,
            method: "GET".to_string(),
            connect_to: None,
            session_file: None,
            source_port: 0,
            perform_migration: false,
            send_priority_update: false,
        }
    }
}

pub const SERVER_USAGE: &str = "Usage:
  quiche-server [options]
  quiche-server -h | --help

Options:
  --listen <addr>             Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>               TLS certificate path [default: src/bin/cert.crt]
  --key <file>                TLS certificate key path [default: src/bin/cert.key]
  --root <dir>                Root directory [default: src/bin/root/]
  --index <name>              The file that will be used as index [default: index.html].
  --name <str>                Name of the server [default: quic.tech]
  --max-data BYTES            Connection-wide flow control limit [default: 10000000].
  --max-window BYTES          Connection-wide max receiver window [default: 25165824].
  --max-stream-data BYTES     Per-stream flow control limit [default: 1000000].
  --max-stream-window BYTES   Per-stream max receiver window [default: 16777216].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT      Idle timeout in milliseconds [default: 30000].
  --dump-packets PATH         Dump the incoming packets as files in the given directory.
  --early-data                Enable receiving early data.
  --no-retry                  Disable stateless retry.
  --no-grease                 Don't send GREASE.
  --http-version VERSION      HTTP version to use [default: all].
  --dgram-proto PROTO         DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT         Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA           Data to send for certain types of DATAGRAM application protocol [default: brrr].
  --cc-algorithm NAME         Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart           Disable HyStart++.
  --max-active-cids NUM       The maximum number of active Connection IDs we can support [default: 2].
  --enable-active-migration   Enable active connection migration.
  --max-field-section-size BYTES    Max size of uncompressed HTTP/3 field section. Default is unlimited.
  --qpack-max-table-capacity BYTES  Max capacity of QPACK dynamic table decoding. Any value other that 0 is currently unsupported.
  --qpack-blocked-streams STREAMS   Limit of streams that can be blocked while decoding. Any value other that 0 is currently unsupported.
  --disable-gso               Disable GSO (linux only).
  -h --help                   Show this screen.
";

// Application-specific arguments that compliment the `CommonArgs`.
pub struct ServerArgs {
    pub listen: String,
    pub no_retry: bool,
    pub root: String,
    pub index: String,
    pub cert: String,
    pub key: String,
    pub disable_gso: bool,
}

impl Args for ServerArgs {
    fn with_docopt(docopt: &docopt::Docopt) -> Self {
        let args = docopt.parse().unwrap_or_else(|e| e.exit());

        let listen = args.get_str("--listen").to_string();
        let no_retry = args.get_bool("--no-retry");
        let root = args.get_str("--root").to_string();
        let index = args.get_str("--index").to_string();
        let cert = args.get_str("--cert").to_string();
        let key = args.get_str("--key").to_string();
        let disable_gso = args.get_bool("--disable-gso");

        ServerArgs {
            listen,
            no_retry,
            root,
            index,
            cert,
            key,
            disable_gso,
        }
    }
}
