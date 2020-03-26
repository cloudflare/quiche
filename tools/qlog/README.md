The qlog crate is an implementation of the [qlog main schema] and [qlog QUIC and
HTTP/3 events] that attempts to closely follow the format of the qlog
[TypeScript schema]. This is just a data model and no support is provided for
logging IO, applications can decide themselves the most appropriate method.

The crate uses Serde for conversion between Rust and JSON.

[qlog main schema]: https://tools.ietf.org/html/draft-marx-qlog-main-schema
[qlog QUIC and HTTP/3 events]: https://quiclog.github.io/internet-drafts/draft-marx-qlog-event-definitions-quic-h3
[TypeScript schema]: https://github.com/quiclog/qlog/blob/master/TypeScript/draft-01/QLog.ts

Overview
--------
qlog is a hierarchical logging format, with a rough structure of:

* Log
  * Trace(s)
    * Event(s)

In practice, a single QUIC connection maps to a single Trace file with one
or more Events. Applications can decide whether to combine Traces from
different connections into the same Log.

## Traces

A [`Trace`] contains metadata such as the [`VantagePoint`] of capture and
the [`Configuration`] of the `Trace`.

A very important part of the `Trace` is the definition of `event_fields`. A
qlog Event is a vector of [`EventField`]; this provides great flexibility to
log events with any number of `EventFields` in any order. The `event_fields`
property describes the format of event logging and it is important that
events comply with that format. Failing to do so it going to cause problems
for qlog analysis tools. For information is available at
https://tools.ietf.org/html/draft-marx-qlog-main-schema-01#section-3.3.4

In order to make using qlog a bit easier, this crate expects a qlog Event to
consist of the following EventFields in the following order:
[`EventField::RelativeTime`], [`EventField::Category`],
[`EventField::Event`] and [`EventField::Data`]. A set of methods are
provided to assist in creating a Trace and appending events to it in this
format.

## Writing out logs
As events occur during the connection, the application appends them to the
trace. The qlog crate supports two modes of writing logs: the buffered mode
stores everything in memory and requires the application to serialize and write
the output, the streaming mode progressively writes serialized JSON output to a
writer designated by the application.

Buffered Mode
---------------

Create the trace:

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
        time_offset: Some("0".to_string()),
        time_units: Some(qlog::TimeUnits::Ms),
        original_uris: None,
    }),
    None,
);
```

### Adding events

Qlog Events are added to `qlog::Trace.events`.

It is recommended to use the provided utility methods to append semantically
valid events to a trace. However, there is nothing preventing you from
creating the events manually.

The following example demonstrates how to log a QUIC packet
containing a single Crypto frame. It uses the [`QuicFrame::crypto()`],
[`packet_sent_min()`] and [`push_event()`] methods to create and log a
PacketSent event and its EventData.

```rust
let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];

let pkt_hdr = qlog::PacketHeader::new(
    0,
    Some(1251),
    Some(1224),
    Some(0xff00001b),
    Some(b"7e37e4dcc6682da8"),
    Some(&dcid),
);

let frames =
    vec![qlog::QuicFrame::crypto("0".to_string(), "1000".to_string())];

let event = qlog::event::Event::packet_sent_min(
    qlog::PacketType::Initial,
    pkt_hdr,
    Some(frames),
);

trace.push_event(std::time::Duration::new(0, 0), event);
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
          "version": "0xff00001b",
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

Streaming Mode
---------------

Create the trace:

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
        time_offset: Some("0".to_string()),
        time_units: Some(qlog::TimeUnits::Ms),
        original_uris: None,
    }),
    None,
);
```

Create an object with the [`Write`] trait:

```rust
let mut file = std::fs::File::create("foo.qlog").unwrap();
```

Create a [`QlogStreamer`] and start serialization to foo.qlog
using [`start_log()`]:

```rust
let mut streamer = qlog::QlogStreamer::new(
    qlog::QLOG_VERSION.to_string(),
    Some("Example qlog".to_string()),
    Some("Example qlog description".to_string()),
    None,
    std::time::Instant::now(),
    trace,
    Box::new(file),
);

streamer.start_log().ok();

```

### Adding simple events

Once logging has started you can stream events. Simple events can be written in
one step using [`add_event()`]:

```rust
let event = qlog::event::Event::metrics_updated_min();
streamer.add_event(event).ok();
```

### Adding events with frames
Some events contain optional arrays of QUIC frames. If the event has
`Some(Vec<QuicFrame>)`, even if it is empty, the streamer enters a frame
serializing mode that must be finalized before other events can be logged.

In this example, a PacketSent event is created with an empty frame array and
frames are written out later:

```rust
let qlog_pkt_hdr = qlog::PacketHeader::with_type(
    qlog::PacketType::OneRtt,
    0,
    Some(1251),
    Some(1224),
    Some(0xff00001b),
    Some(b"7e37e4dcc6682da8"),
    Some(b"36ce104eee50101c"),
);

let event = qlog::event::Event::packet_sent_min(
    qlog::PacketType::OneRtt,
    qlog_pkt_hdr,
    Some(Vec::new()),
);

streamer.add_event(event).ok();

```

In this example, the frames contained in the QUIC packet
are PING and PADDING. Each frame is written using the
[`add_frame()`] method. Frame writing is concluded with
[`finish_frames()`].

```rust
let ping = qlog::QuicFrame::ping();
let padding = qlog::QuicFrame::padding();

streamer.add_frame(ping, false).ok();
streamer.add_frame(padding, false).ok();

streamer.finish_frames().ok();
```

Once all events have have been written, the log
can be finalized with [`finish_log()`]:

```rust
streamer.finish_log().ok();
```

### Serializing

Serialization to JSON occurs as methods on the [`QlogStreamer`]
are called. No additional steps are required.

[`Trace`]: struct.Trace.html
[`VantagePoint`]: struct.VantagePoint.html
[`Configuration`]: struct.Configuration.html
[`EventField`]: enum.EventField.html
[`EventField::RelativeTime`]: enum.EventField.html#variant.RelativeTime
[`EventField::Category`]: enum.EventField.html#variant.Category
[`EventField::Type`]: enum.EventField.html#variant.Type
[`EventField::Data`]: enum.EventField.html#variant.Data
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