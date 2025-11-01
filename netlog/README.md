# netlog

The netlog crate is a reverse-engineered deserializer for the Chrome
[netlog] format. It supports QUIC and HTTP(/2 and /3) events.

## Overview

Chromium-based browsers allow users to enable detailed logging, netlog,
which is useful for debugging interoperability or performance issues. A
netlog file uses a kind of line-delimited JSON format. The first line
contains "constants", which are specific to the version of the software used
to generate the log. These constants are used for a form of compressed
encoding for the netlog events that appear on each subsequent newline.

This crate supports parsing a netlog file and converting a subset of netlog
events into Rust structures, via Serde.

## Example usage

Assuming a netlog file name of `chrome-net-export-log-error.json`, the first
task is to create a `BufReader` for the file and initialize the netlog
constants.

```rust
use netlog::read_netlog_constants;
use std::fs::File;
use std::io::BufReader;

let mut reader =
    BufReader::new(File::open("chrome-net-export-log-error.json").unwrap());

let constants = read_netlog_constants(&mut reader).unwrap();
```

Then move on to parsing the netlog file until the end.

```rust
use netlog::read_netlog_record;
use netlog::EventHeader;
use netlog::h2::Http2SessionEvent;
use netlog::quic::QuicSessionEvent;
// The second line of a netlog is `"events" [`, which can be skipped over.
read_netlog_record(&mut reader);

while let Some(record) = read_netlog_record(&mut reader) {
    let res: Result<EventHeader, serde_json::Error> =
        serde_json::from_slice(&record);

    match res {
        Ok(mut event_hdr) => {
            event_hdr.populate_strings(&constants);
            event_hdr.time_num = event_hdr.time.parse::<u64>().unwrap();

            // Netlogs can hold many different sessions.
            // Application might want to track these separately
            if event_hdr.phase_string == "PHASE_BEGIN" {
                match event_hdr.ty_string.as_str() {
                    "HTTP2_SESSION" => {
                        let ev: Http2SessionEvent =
                            serde_json::from_slice(&record).unwrap();
                        // Handle new session event ...
                    },
                    "QUIC_SESSION" => {
                        let ev: QuicSessionEvent =
                            serde_json::from_slice(&record).unwrap();
                        // Handle new session event ...
                    },

                    // Ignore others
                    _ => (),
                }
            }

            // Try to parse other events.
            if let Some(ev) = netlog::parse_event(&event_hdr, &record) {
                // Handle parsed event.
            }
        },

        Err(e) => {
            println!("Error deserializing: {}", e);
            println!("input value {}", String::from_utf8_lossy(&record));
        },
    }
}
```

[netlog]: (https://www.chromium.org/developers/design-documents/network-stack/netlog/)
