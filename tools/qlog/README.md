The qlog crate is an implementation of the [qlog main schema] and [qlog QUIC and
HTTP/3 events] that attempts to closely follow the format of the qlog
[TypeScript schema]. This is just a data model and no support is provided for
logging IO, applications can decide themselves the most appropriate method.

The crate uses Serde for conversion between Rust and JSON.

[qlog main schema]: https://tools.ietf.org/html/draft-marx-qlog-main-schema
[qlog QUIC and HTTP/3 events]: https://quiclog.github.io/internet-drafts/draft-marx-qlog-event-definitions-quic-h3
[TypeScript schema]: https://github.com/quiclog/qlog/blob/master/TypeScript/draft-01/QLog.ts

Getting Started
---------------

### Creating a trace

A typical application needs a single qlog trace that it appends QUIC and/or
HTTP/3 events to:

```rust
let trace = Trace {
    vantage_point: VantagePoint {
        name: "Example client",
        ty: VantagePointType::Client,
        flow: None,
    },
    title: Some("Example qlog trace".to_string()),
    description: Some("Example qlog trace description".to_string()),
    configuration: Some(Configuration {
        time_offset: Some("0".to_string()),
        time_units: Some(TimeUnits::Ms),
        original_uris: None,
    }),
    common_fields: None,
    event_fields: vec![
        "relative_time".to_string(),
        "category".to_string(),
        "event".to_string(),
        "data".to_string(),
    ],
    events: Vec::new(),
};

```

### Adding events

Qlog Events are added to `qlog::Trace.events`. Utility method are provided for
the various types of QUIC and HTTP/3 events. The following example demonstrates
how to log a QUIC packet containing a single Crypto frame, it uses the
`push_transport_event()` and `QuicFrame::crypto()` methods to capture a
PacketSent event and its EventData.

```rust
trace.push_transport_event(
    "0".to_string(),
    TransportEventType::PacketSent,
    EventData::PacketSent {
        raw_encrypted: None,
        raw_decrypted: None,
        packet_type: PacketType::Initial,
        header: PacketHeader {
            packet_number: "0".to_string(),
            packet_size: Some(1251),
            payload_length: Some(1224),
            version: Some("0xff000018".to_string()),
            scil: Some("8".to_string()),
            dcil: Some("8".to_string()),
            scid: Some("7e37e4dcc6682da8".to_string()),
            dcid: Some("36ce104eee50101c".to_string()),
        },
        frames: Some(vec![
            QuicFrame::crypto(
                "0".to_string(),
                "1000".to_string(),
            )
        ]),
        is_coalesced: None,
    },
);
```

### Serializing

Simply:

```rust
serde_json::to_string_pretty(&trace).unwrap();
```

which would generate the following:

```
{
  "vantage_point": {
    "name": "Example client",
    "type": "client"
  },
  "title": "Example qlog trace",
  "description": "Example qlog trace description",
  "configuration": {
    "time_units": "ms",
    "time_offset": "0"
  },
  "event_fields": [
    "relative_time",
    "category",
    "event",
    "data"
  ],
  "events": [
    [
      "0",
      "transport",
      "packet_sent",
      {
        "packet_type": "initial",
        "header": {
          "packet_number": "0",
          "packet_size": 1251,
          "payload_length": 1224,
          "version": "0xff000018",
          "scil": "8",
          "dcil": "8",
          "scid": "7e37e4dcc6682da8",
          "dcid": "36ce104eee50101c"
        },
        "frames": [
          {
            "frame_type": "crypto",
            "offset": "0",
            "length": "100",
          }
        ]
      }
    ]
  ]
}
```
