h3i consists of an interactive command-line tool and library for low-level HTTP/3
debugging and testing.

HTTP/3 ([RFC 9114]) is the wire format for HTTP semantics ([RFC 9110]). The RFCs
contain a range of requirements about how Request or Response messages are
generated, serialized, sent, received, parsed, and consumed. QUIC ([RFC 900])
streams are used for these messages along with other control and QPACK ([RFC
9204]) header compression instructions.

h3i provides a highly configurable HTTP/3 client that can bend RFC rules in
order to test the behavior of servers. QUIC streams can be opened, fin'd,
stopped or reset at any point in time. HTTP/3 frames can be sent on any stream,
in any order, containing user-controlled content (both legal and illegal).

**Note**: Please note that h3i is _not_ intended to be a production HTTP/3
client, and we currently have no plans to make it one. Use it in production at
your own risk!

# Command-line Tool

The command-line tool is intended to be used for ad-hoc interactive
exploration of HTTP/3 server behavior.

For example, to interactively test https://cloudflare-quic.com:

```
cargo run cloudflare-quic.com
```

This opens an interactive prompt that walks the user through constructing a
number of `Action`s, such as sending an HTTP/3 HEADERS frame, that are queued
and then sent to the server in sequence. The available options are

- `headers` - an HTTP/3 HEADERS frame, with mandatory pseudo headers
- `headers_no_pseudo` - an HTTP/3 HEADER frame, with no mandatory pseudo headers
- `data` - an HTTP/3 DATA frame
- `settings` - an HTTP/3 SETTINGS frame
- `goaway` - an HTTP/3 GOAWAY frame
- `priority_update` - an HTTP/3 PRIORITY_UPDATE frame
- `push_promise` - an HTTP/3 PUSH_PROMISE frame
- `cancel_push` - an HTTP/3 CANCEL_PUSH frame
- `max_push_id` - an HTTP/3 MAX_PUSH_ID frame
- `grease` - an HTTP/3 GREASE frame
- `extension_frame` - an HTTP/3 extension frame
- `open_uni_stream` - opens an HTTP/3 unidirectional stream with a type
- `stream_bytes` - send arbitrary data on a stream
- `reset_stream` - resets a uni or bidi stream
- `stop_sending` - stops a bidi stream
- `connection_close` - closes the QUIC connection
- `flush_packets` - force a QUIC packet flush, to emit any buffered actions
- `commit` - finish action input, open the connection and execute all actions
- `wait` - specify a client-side wait, in order to provide some delay between action emits
- `quit` - quit without opening a connection

To send two HTTP/3 requests, would require the sequence `headers` and `commit`:

![h3i-demo](h3i-demo.gif)

By default, the client prints some information about the QUIC connection state,
transmitted/received frames, and stream lifecycle. Additional information can be
printed using the `RUST_LOG=trace` environment variable, which will emit a
JSON-serialized [ConnectionSummary](#ConnectionSummary). If the `QLOGDIR`
environment variable is provided, then a qlog file containing the full details
of QUIC and HTTP/3 will be written.

In some cases, it can be useful to ignore server name resolution and connect to
a server at a specific IP address, using the indicated SNI. The `--connect-to`
option can be used to specificy the desired IP and port.

## Record and Replay

By default, h3i records all of the actions to a [qlog] file
`<timestamp>-qlog.sqlog`. This can be replayed against the same server, or a
different server, using the `--qlog-input` option. For example:

```
cargo run cloudflare-quic.com --qlog-input <timestamp>-qlog.sqlog
cargo run blog.cloudflare.com --qlog-input <timestamp>-qlog.sqlog
```

Note that `:authority` or `host` headers may need to be re-written to match the target server, depending on the use case.

The file uses a custom qlog schema that augments the [QUIC schema] and [HTTP/3
schema].

# Library

h3i is also provided as a library, which allows programmatic control over HTTP/3 client behavior. This is useful for writing test cases.

The key components of the library are actions, client runner, connection summary, and stream map.

## Actions

Actions are small operations such as sending HTTP/3 frames or managing QUIC streams. Each independent use case for h3i requires its own collection of Actions, that h3i iterates over in sequence and executes.

To emulate the CLI example from above, all that is required is a single action:


```rust
// The set of request headers
let headers = headers: vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"cloudflare-quic.com"),
            Header::new(b":path", b"/"),
            Header::new(b"user-agent", b"h3i")
        ];

let send_headers_action = send_headers_frame(0, true, headers);

let actions = vec![send_headers_action];
```

## Client runner

Applications using the library can invoke the client runner via sync_client::connect(). This requires a set of configuration parameters and an actions vector.

```rust
let config = pub struct Config {
    host_port: "cloudflare-quic.com",
    .. // other fields omitted for brevity
};

let summary = sync_client::connect(&config, &actions);
```

## ConnectionSummary

This is the core "output" struct. It "summarizes" the connection by providing a view into what was received on each stream (see `StreamMap` below). It also includes statistics about the connection and the QUIC paths that comprises the connection. Lastly, it includes details as to _why_ the connection closed: a timeout, a peer or local error, etc.

### StreamMap

The `StreamMap` is the second core struct in the library. It is a map of received frames keyed on stream ID, together with a variety of helper methods to check or validate them.

These frames are of type H3iFrame, which abstract or wrap Quiche's own `quiche::h3::Frame` type to make them easier to work with. For example, the `H3iFrame::Headers` variant contains a headers list without QPACK encoding, making it easy to read or validate. Some frames have no additional features; these are simply wrapped in the `H3iFrame::QuicheH3` variant.

# Inspiration

h3i has been inspired by several other tools and techniques used across the HTTP and QUIC ecosystem:

* [h2i](https://pkg.go.dev/golang.org/x/net/http2/h2i) - an interactive console debugger for HTTP/2. Provided as part of the Go HTTP/2 implementation

* [h2spec](https://github.com/summerwind/h2spec) - a conformance testing tool for
HTTP/2. Written and maintained by Moto Ishizawa.

* [h3spec](https://github.com/kazu-yamamoto/h3spec) - a conformance testing tool
for QUIC and HTTP/3. Written and maintained by Kazu Yamamato.

[RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
[RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110.html
[RFC 9114]: https://www.rfc-editor.org/rfc/rfc9114.html
[RFC 9204]: https://www.rfc-editor.org/rfc/rfc9204.html
[qlog]: https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/
[QUIC schema]: https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events
[HTTP/3 schema]: https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-h3-events

