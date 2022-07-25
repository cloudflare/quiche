The qlog crate is an implementation of the qlog [main logging schema],
[QUIC event definitions], and [HTTP/3 and QPACK event definitions].
The crate provides a qlog data model that can be used for traces with
events. It supports serialization and deserialization but defers logging IO
choices to applications.

The crate uses Serde for conversion between Rust and JSON.

[main logging schema]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema
[QUIC event definitions]:
https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-quic-events.html
[HTTP/3 and QPACK event definitions]:
https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-h3-events.html

Overview
--------
qlog is a hierarchical logging format, with a rough structure of:

* Log
  * Trace(s)
    * Event(s)

In practice, a single QUIC connection maps to a single Trace file with one
or more Events. Applications can decide whether to combine Traces from
different connections into the same Log.

## Buffered Traces with standard JSON

A [`Trace`] is a single JSON object. It contains metadata such as the
[`VantagePoint`] of capture and the [`Configuration`], and protocol event
data in the [`Event`] array.

JSON Traces allow applications to appends events to them before eventually
being serialized as a complete JSON object.

### Creating a Trace

```rust
let mut trace = qlog::Trace::new(
    qlog::VantagePoint {
        name: Some("Example client".to_string()),
        ty: qlog::VantagePointType::Client,
        flow: None,
    },
    Some("Example qlog trace".to_string()),
    Some("Example qlog trace description".to_string()),
    Some(qlog::Configuration {
        time_offset: Some(0.0),
        original_uris: None,
    }),
    None,
);
```

### Adding events to a Trace

Qlog `Event` objects are added to `qlog::Trace.events`.

The following example demonstrates how to log a qlog QUIC `packet_sent` event
containing a single Crypto frame. It constructs the necessary elements of the
[`Event`], then appends it to the trace with [`push_event()`].

```rust
let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];

let pkt_hdr = qlog::events::quic::PacketHeader::new(
    qlog::events::quic::PacketType::Initial,
    0,                         // packet_number
    None,                      // flags
    None,                      // token
    None,                      // length
    Some(0x00000001),          // version
    Some(&scid),
    Some(&dcid),
);

let frames = vec![qlog::events::quic::QuicFrame::Crypto {
    offset: 0,
    length: 0,
}];

let raw = qlog::events::RawInfo {
    length: Some(1251),
    payload_length: Some(1224),
    data: None,
};

let event_data =
     qlog::events::EventData::PacketSent(qlog::events::quic::PacketSent {
         header: pkt_hdr,
         frames: Some(frames),
         is_coalesced: None,
         retry_token: None,
         stateless_reset_token: None,
         supported_versions: None,
         raw: Some(raw),
         datagram_id: None,
     });

trace.push_event(qlog::events::Event::with_time(0.0, event_data));
```

### Serializing

The qlog crate has only been tested with `serde_json`, however other serializer
targets might work.

For example, serializing the trace created above:

```rust
serde_json::to_string_pretty(&trace).unwrap();
```

would generate the following:

```
{
  "vantage_point": {
    "name": "Example client",
    "type": "client"
  },
  "title": "Example qlog trace",
  "description": "Example qlog trace description",
  "configuration": {
    "time_offset": 0.0
  },
  "events": [
    {
      "time": 0.0,
      "name": "transport:packet_sent",
      "data": {
        "header": {
          "packet_type": "initial",
          "packet_number": 0,
          "version": "1",
          "scil": 8,
          "dcil": 8,
          "scid": "7e37e4dcc6682da8",
          "dcid": "36ce104eee50101c"
        },
        "raw": {
          "length": 1251,
          "payload_length": 1224
        },
        "frames": [
          {
            "frame_type": "crypto",
            "offset": 0,
            "length": 0
          }
        ]
      }
    }
  ]
}
```

## Streaming Traces JSON Text Sequences (JSON-SEQ)

To help support streaming serialization of qlogs,
draft-ietf-quic-qlog-main-schema-01 introduced support for RFC 7464 JSON
Text Sequences (JSON-SEQ). The qlog crate supports this format and provides
utilities that aid streaming.

A [`TraceSeq`] contains metadata such as the [`VantagePoint`] of capture and
the [`Configuration`]. However, protocol event data is handled as separate
lines containing a record separator character, a serialized [`Event`], and a
newline.

### Creating a TraceSeq

``` rust
let mut trace = qlog::TraceSeq::new(
    qlog::VantagePoint {
        name: Some("Example client".to_string()),
        ty: qlog::VantagePointType::Client,
        flow: None,
    },
    Some("Example qlog trace".to_string()),
    Some("Example qlog trace description".to_string()),
    Some(qlog::Configuration {
        time_offset: Some(0.0),
        original_uris: None,
    }),
    None,
);
```

Create an object with the [`Write`] trait:
```
let mut file = std::fs::File::create("foo.sqlog").unwrap();
```

Create a [`QlogStreamer`] and start serialization to foo.sqlog
using [`start_log()`]:

```rust
let mut streamer = qlog::QlogStreamer::new(
    qlog::QLOG_VERSION.to_string(),
    Some("Example qlog".to_string()),
    Some("Example qlog description".to_string()),
    None,
    std::time::Instant::now(),
    trace,
    qlog::EventImportance::Base,
    Box::new(file),
);

streamer.start_log().ok();
```

### Adding simple events

Once logging has started you can stream events. Simple events can be written in
one step using [`add_event()`]:

```rust
let event_data = qlog::events::EventData::MetricsUpdated(
    qlog::events::quic::MetricsUpdated {
        min_rtt: Some(1.0),
        smoothed_rtt: Some(1.0),
        latest_rtt: Some(1.0),
        rtt_variance: Some(1.0),
        pto_count: Some(1),
        congestion_window: Some(1234),
        bytes_in_flight: Some(5678),
        ssthresh: None,
        packets_in_flight: None,
        pacing_rate: None,
    },
);

let event = qlog::events::Event::with_time(0.0, event_data);
streamer.add_event(event).ok();
```

### Adding events with frames
Some events contain optional arrays of QUIC frames. If the event has
`Some(Vec<QuicFrame>)`, even if it is empty, the streamer enters a frame
serializing mode that must be finalized before other events can be logged.

In this example, a `PacketSent` event is created with an empty frame array and
frames are written out later:

```rust
let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];

let pkt_hdr = qlog::events::quic::PacketHeader::with_type(
    qlog::events::quic::PacketType::OneRtt,
    0,
    Some(0x00000001),
    Some(&scid),
    Some(&dcid),
);

let event_data =
    qlog::events::EventData::PacketSent(qlog::events::quic::PacketSent {
      header: pkt_hdr,
      frames: Some(vec![]),
      is_coalesced: None,
      retry_token: None,
      stateless_reset_token: None,
      supported_versions: None,
      raw: None,
      datagram_id: None,
};

let event = qlog::events::Event::with_time(0.0, event_data);

streamer.add_event(event).ok();
```

In this example, the frames contained in the QUIC packet
are PING and PADDING. Each frame is written using the
[`add_frame()`] method. Frame writing is concluded with
[`finish_frames()`].

```rust
let ping = qlog::events::quic::QuicFrame::Ping;
let padding = qlog::events::quic::QuicFrame::Padding;

streamer.add_frame(ping, false).ok();
streamer.add_frame(padding, false).ok();

streamer.finish_frames().ok();
```

Once all events have been written, the log
can be finalized with [`finish_log()`]:

```rust
streamer.finish_log().ok();
```

### Serializing

Serialization to JSON occurs as methods on the [`QlogStreamer`]
are called. No additional steps are required.

[`Trace`]: struct.Trace.html
[`TraceSeq`]: struct.TraceSeq.html
[`VantagePoint`]: struct.VantagePoint.html
[`Configuration`]: struct.Configuration.html
[`qlog::Trace.events`]: struct.Trace.html#structfield.events
[`push_event()`]: struct.Trace.html#method.push_event
[`packet_sent_min()`]: event/struct.Event.html#method.packet_sent_min
[`QuicFrame::crypto()`]: enum.QuicFrame.html#variant.Crypto
[`QlogStreamer`]: struct.QlogStreamer.html
[`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
[`start_log()`]: struct.QlogStreamer.html#method.start_log
[`add_event()`]: struct.QlogStreamer.html#method.add_event
[`add_frame()`]: struct.QlogStreamer.html#method.add_frame
[`finish_frames()`]: struct.QlogStreamer.html#method.finish_frames
[`finish_log()`]: struct.QlogStreamer.html#method.finish_log