![quiche](quiche.svg)

[![crates.io](https://img.shields.io/crates/v/quiche.svg)](https://crates.io/crates/quiche)
[![docs.rs](https://docs.rs/quiche/badge.svg)](https://docs.rs/quiche)
[![license](https://img.shields.io/github/license/cloudflare/quiche.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![build](https://travis-ci.com/cloudflare/quiche.svg?branch=master)](https://travis-ci.com/cloudflare/quiche)

[quiche] is an implementation of the QUIC transport protocol and HTTP/3 as
specified by the [IETF]. It provides a low level API for processing QUIC packets
and handling connection state. The application is responsible for providing I/O
(e.g. sockets handling) as well as an event loop with support for timers.

Note that it is very experimental and unstable software, and many features are
still in development. Refer to the [Status](#status) section to see what is
currently implemented.

A live QUIC server based on quiche is available at ``https://quic.tech:4433/``
to be used for experimentation.

For more information on how quiche came about and some insights into its design
you can read a [post] on Cloudflare's (where this library is used in production)
blog that goes into some more detail.

[quiche]: https://docs.quic.tech/quiche/
[ietf]: https://quicwg.org/
[post]: https://blog.cloudflare.com/enjoy-a-slice-of-quic-and-rust/

Status
------

* [x] QUIC draft-18
* [x] Version Negotiation
* [x] TLS 1.3 handshake (using BoringSSL)
* [x] Stream API
* [x] Flow control
* [x] Connection close
* [x] Loss detection and recovery
* [x] Congestion control
* [ ] Key update
* [x] Stateless retry
* [x] Unidirectional streams
* [ ] Session resumption
* [ ] 0-RTT
* [ ] Stateless reset
* [ ] Connection migration
* [x] QPACK static table decoding
* [x] QPACK static table encoding
* [ ] QPACK dynamic table decoding
* [ ] QPACK dynamic table encoding
* [ ] HTTP/3 request/response

Getting Started
---------------

The first step in establishing a QUIC connection using quiche is creating a
configuration object:

```rust
let config = quiche::Config::new(quiche::VERSION_DRAFT18).unwrap();
```

This is shared among multiple connections and can be used to configure a
QUIC endpoint.

Now a connection can be created, for clients the [`connect()`] utility
function can be used, while [`accept()`] is for servers:

```rust
// Client connection.
let conn = quiche::connect(Some(&server_name), &scid, &mut config).unwrap();

// Server connection.
let conn = quiche::accept(&scid, None, &mut config).unwrap();
```

Using the connection's [`recv()`] method the application can process
incoming packets from the network that belong to that connection:

```rust
let read = socket.recv(&mut buf).unwrap();

let read = match conn.recv(&mut buf[..read]) {
    Ok(v)  => v,

    Err(quiche::Error::Done) => {
        // Done reading.
        # return;
    },

    Err(e) => {
        // An error occurred, handle it.
        # return;
    },
};
```

Outgoing packet are generated using the connection's [`send()`] method
instead:

```rust
let write = match conn.send(&mut out) {
    Ok(v) => v,

    Err(quiche::Error::Done) => {
        // Done writing.
        # return;
    },

    Err(e) => {
        // An error occurred, handle it.
        # return;
    },
};

socket.send(&out[..write]).unwrap();
```

When packets are sent, the application is responsible for maintaining a timer
to react to time-based connection events. The timer expiration can be
obtained using the connection's [`timeout()`] method.

```rust
let timeout = conn.timeout();
```

The application is responsible for providing a timer implementation, which
can be specific to the operating system or networking framework used. When
a timer expires, the connection's [`on_timeout()`] method should be called,
after which additional packets might need to be sent on the network:

```rust
// Timeout expired, do something.
conn.on_timeout();

let write = match conn.send(&mut out) {
    Ok(v) => v,

    Err(quiche::Error::Done) => {
        // Done writing.
        # return;
    },

    Err(e) => {
        // An error occurred, handle it.
        # return;
    },
};

socket.send(&out[..write]).unwrap();
```

After some back and forth, the connection will complete its handshake and
will be ready for sending or receiving application data:

```rust
if conn.is_established() {
    // Handshake completed, send some data on stream 0.
    conn.stream_send(0, b"hello", true);
}
```

[`connect()`]: https://docs.quic.tech/quiche/fn.connect.html
[`accept()`]: https://docs.quic.tech/quiche/fn.accept.html
[`recv()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.recv
[`send()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.send
[`timeout()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.timeout
[`on_timeout()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.on_timeout

Have a look at the [examples/] directory for more complete examples on how to use
the quiche API, including examples on how to use quiche in C/C++ applications
(see below for more information).

[examples/]: examples/

Calling quiche from C/C++
-------------------------

quiche exposes a [thin C API] on top of the Rust API that can be used to more
easily integrate quiche into C/C++ applications (as well as in other languages
that allow calling C APIs via some form of FFI). The C API follows the same
design of the Rust one, modulo the constraints imposed by the C language itself.

When running ``cargo build``, a static library called ``libquiche.a`` will be
built automatically alongside the Rust one. This is fully stand-alone and can
be linked directly into C/C++ applications.

[thin C API]: https://github.com/cloudflare/quiche/blob/master/include/quiche.h

Building
--------

The first step after cloning the git repo is updating the git submodules:

```bash
 $ git submodule update --init
```

You can now build quiche using cargo:

```bash
 $ cargo build --examples
```

As well as run its tests:

```bash
 $ cargo test
```

Note that [BoringSSL], used to implement QUIC's cryptographic handshake based on
TLS, needs to be built and linked to quiche. This is done automatically when
building quiche using cargo, but requires the `cmake` and `go` commands to be
available during the build process.

In alternative you can use your own custom build of BoringSSL by configuring
the BoringSSL directory with the ``QUICHE_BSSL_PATH`` environment variable:

```bash
 $ QUICHE_BSSL_PATH="/path/to/boringssl" cargo build --examples
```

[BoringSSL]: https://boringssl.googlesource.com/boringssl/

Copyright
---------

Copyright (C) 2018, Cloudflare, Inc.

Copyright (C) 2018, Alessandro Ghedini

See [COPYING] for the license.

[COPYING]: https://github.com/cloudflare/quiche/tree/master/COPYING
