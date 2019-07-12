![quiche](quiche.svg)

[![crates.io](https://img.shields.io/crates/v/quiche.svg)](https://crates.io/crates/quiche)
[![docs.rs](https://docs.rs/quiche/badge.svg)](https://docs.rs/quiche)
[![license](https://img.shields.io/github/license/cloudflare/quiche.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![build](https://travis-ci.com/cloudflare/quiche.svg?branch=master)](https://travis-ci.com/cloudflare/quiche)

[quiche] is an implementation of the QUIC transport protocol and HTTP/3 as
specified by the [IETF]. It provides a low level API for processing QUIC packets
and handling connection state. The application is responsible for providing I/O
(e.g. sockets handling) as well as an event loop with support for timers.

A live QUIC server based on quiche is available at ``https://quic.tech:4433/``
to be used for experimentation.

For more information on how quiche came about and some insights into its design
you can read a [post] on Cloudflare's (where this library is used in production)
blog that goes into some more detail.

[quiche]: https://docs.quic.tech/quiche/
[ietf]: https://quicwg.org/
[post]: https://blog.cloudflare.com/enjoy-a-slice-of-quic-and-rust/

Getting Started
---------------

### Connection setup

The first step in establishing a QUIC connection using quiche is creating a
configuration object:

```rust
let config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
```

This is shared among multiple connections and can be used to configure a
QUIC endpoint.

On the client-side the [`connect()`] utility function can be used to create
a new connection, while [`accept()`] is for servers:

```rust
// Client connection.
let conn = quiche::connect(Some(&server_name), &scid, &mut config)?;

// Server connection.
let conn = quiche::accept(&scid, None, &mut config)?;
```

### Handling incoming packets

Using the connection's [`recv()`] method the application can process
incoming packets that belong to that connection from the network:

```rust
loop {
    let read = socket.recv(&mut buf).unwrap();

    let read = match conn.recv(&mut buf[..read]) {
        Ok(v) => v,

        Err(quiche::Error::Done) => {
            // Done reading.
            break;
        },

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };
}
```

### Generating outgoing packets

Outgoing packet are generated using the connection's [`send()`] method
instead:

```rust
loop {
    let write = match conn.send(&mut out) {
        Ok(v) => v,

        Err(quiche::Error::Done) => {
            // Done writing.
            break;
        },

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };

    socket.send(&out[..write]).unwrap();
}
```

When packets are sent, the application is responsible for maintaining a
timer to react to time-based connection events. The timer expiration can be
obtained using the connection's [`timeout()`] method.

```rust
let timeout = conn.timeout();
```

The application is responsible for providing a timer implementation, which
can be specific to the operating system or networking framework used. When
a timer expires, the connection's [`on_timeout()`] method should be called,
after which additional packets might need to be sent on the network:

```rust
// Timeout expired, handle it.
conn.on_timeout();

// Send more packets as needed after timeout.
loop {
    let write = match conn.send(&mut out) {
        Ok(v) => v,

        Err(quiche::Error::Done) => {
            // Done writing.
            break;
        },

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };

    socket.send(&out[..write]).unwrap();
}
```

### Sending and receiving stream data

After some back and forth, the connection will complete its handshake and
will be ready for sending or receiving application data.

Data can be sent on a stream by using the [`stream_send()`] method:

```rust
if conn.is_established() {
    // Handshake completed, send some data on stream 0.
    conn.stream_send(0, b"hello", true)?;
}
```

The application can check whether there are any readable streams by using
the connection's [`readable()`] method, which returns an iterator over all
the streams that have outstanding data to read.

The [`stream_recv()`] method can then be used to retrieve the application
data from the readable stream:

```rust
if conn.is_established() {
    // Iterate over readable streams.
    let streams: Vec<u64> = conn.readable().collect();

    for stream_id in streams {
        // Stream is readable, read until there's no more data.
        while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
            println!("Got {} bytes on stream {}", read, stream_id);
        }
    }
}
```

### HTTP/3

The quiche [HTTP/3 module] provides a high level API for sending and
receiving HTTP requests and responses on top of the QUIC transport protocol.

[`connect()`]: https://docs.quic.tech/quiche/fn.connect.html
[`accept()`]: https://docs.quic.tech/quiche/fn.accept.html
[`recv()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.recv
[`send()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.send
[`timeout()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.timeout
[`on_timeout()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.on_timeout
[`stream_send()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.stream_send
[`readable()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.readable
[`stream_recv()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.stream_recv
[HTTP/3 module]: https://docs.quic.tech/quiche/h3/index.html

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

quiche requires Rust 1.35 or later to build. The latest stable Rust release can
be installed using [rustup](https://rustup.rs/).

Once the Rust build environment is setup, the quiche source code can be fetched
using git:

```bash
 $ git clone --recursive https://github.com/cloudflare/quiche
```

and then built using cargo:

```bash
 $ cargo build --examples
```

cargo can also be used to run the testsuite:

```bash
 $ cargo test
```

Note that [BoringSSL], which is used to implement QUIC's cryptographic handshake
based on TLS, needs to be built and linked to quiche. This is done automatically
when building quiche using cargo, but requires the `cmake` and `go` commands to
be available during the build process.

In alternative you can use your own custom build of BoringSSL by configuring
the BoringSSL directory with the ``QUICHE_BSSL_PATH`` environment variable:

```bash
 $ QUICHE_BSSL_PATH="/path/to/boringssl" cargo build --examples
```

[BoringSSL]: https://boringssl.googlesource.com/boringssl/

### Building for Android

To build quiche for Android, you need the following:

- Install Android NDK (13b or higher), using Android Studio or directly.
- Set `ANDROID_NDK_HOME` environment variable to NDK path, e.g. using bash:

```bash
 $ export ANDROID_NDK_HOME=/usr/local/share/android-ndk
```

- Install the Rust toolchain for Android architectures:

```bash
 $ rustup target add aarch64-linux-android arm-linux-androideabi armv7-linux-androideabi i686-linux-android
```

Then, to prepare the cross-compiling toolchain, run the following command:

```bash
 $ tools/setup_android.sh
```

It will create a standalone toolchain for arm64/arm/x86 architectures under the
`$TOOLCHAIN_DIR/arch` directory. If you didn't set `TOOLCHAIN_DIR` environment
variable, the current directory will be used. Note that the minimum API level is
21 for all target architectures.

After it run successfully, run the following script to build libquiche:

```bash
 $ tools/build_android.sh
```

It will build binaries for aarch64, armv7 and i686. You can pass parameters to
this script for cargo build. For example if you want to build a release binary
with verbose logs, do the following:

```bash
 $ tools/build_android.sh --release -vv
```

### Building for iOS

To build quiche for iOS, you need the following:

- Install Xcode command-line tools. You can install them with Xcode or with the
  following command:

```bash
 $ xcode-select --install
```

- Install the Rust toolchain for iOS architectures:

```bash
 $ rustup target add aarch64-apple-ios armv7-apple-ios armv7s-apple-ios x86_64-apple-ios i386-apple-ios
```

- Install `cargo-lipo`:

```bash
 $ cargo install cargo-lipo
```

To build libquiche, run the following command:

```bash
 $ cargo lipo
```

or

```bash
 $ cargo lipo --release
```

Copyright
---------

Copyright (C) 2018, Cloudflare, Inc.

Copyright (C) 2018, Alessandro Ghedini

See [COPYING] for the license.

[COPYING]: https://github.com/cloudflare/quiche/tree/master/COPYING
