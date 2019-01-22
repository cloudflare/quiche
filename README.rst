.. image:: quiche.png

.. image:: https://travis-ci.com/cloudflare/quiche.svg
  :target: https://travis-ci.com/cloudflare/quiche

quiche_ is an implementation of the QUIC transport protocol as specified by
the IETF_. It provides a low level API for processing QUIC packets and
handling connection state. The application is responsible for providing I/O
(e.g. sockets handling) as well as an event loop with support for timers.

A live QUIC server based on quiche is available at ``https://quic.tech:4433/``
to be used for experimentation.

Note that it is very experimental and unstable software, and many features are
still in development.

For more information on how quiche came about and some insights into its design
you can read a post_ on Cloudflare's (where this library is used in production)
blog that goes into some more detail.

.. _quiche: https://docs.quic.tech/quiche/
.. _ietf: https://quicwg.org/
.. _post: https://blog.cloudflare.com/enjoy-a-slice-of-quic-and-rust/

Status
------

* [x] QUIC draft-17
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

Getting Started
---------------

The first step in establishing a QUIC connection using quiche, is creating a
configuration object:

.. code-block:: rust

   let mut config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();

This is shared among multiple connections and can be used to configure a QUIC
endpoint.

Now a connection can be created, for clients the ``quiche::connect()`` utility
function can be used, while ``quiche::accept()`` is for servers:

.. code-block:: rust

   // Client connection.
   let mut conn = quiche::connect(Some(&server_name), &scid, &mut config).unwrap();

   // Server connection.
   let mut conn = quiche::accept(&scid, None, &mut config).unwrap();

Using the connection's ``recv()`` method the application can process incoming
packets from the network that belong to that connection:

.. code-block:: rust

   let read = socket.recv(&mut buf).unwrap();

   let read = match conn.recv(&mut buf[..read]) {
       Ok(v)  => v,

       Err(quiche::Error::Done) => {
           // Done reading.
       },

       Err(e) => {
           // An error occurred, handle it.
       },
   };

Outgoing packet are generated using the connection's ``send()`` method instead:

.. code-block:: rust

   let write = match conn.send(&mut out) {
       Ok(v) => v,

       Err(quiche::Error::Done) => {
           // Done writing.
       },

       Err(e) => {
           // An error occurred, handle it.
       },
   };

   socket.send(&out[..write]).unwrap();

When packets are sent, the application is responsible for maintainig a timer
to react to time-based connection events. The timer expiration can be obtained
using the connection's ``timeout()`` method.

.. code-block:: rust

   let timeout = conn.timeout();
   timer.set(timeout); // This needs to be implemented by the application.

The application is responsible for providing a timer implementation, which can
be specific to the operating system or networking framework used. When a timer
expires, the connection's ``on_timeout()`` method should be called, after which
additional packets might need to be sent on the network:

.. code-block:: rust

   // Timeout expired, do something.
   conn.on_timeout();

   // Send additional packets on the network.
   let write = match conn.send(&mut out) {
       Ok(v) => v,

       Err(quiche::Error::Done) => {
           // Done writing.
       },

       Err(e) => {
           // An error occurred, handle it.
       },
   };

   socket.send(&out[..write]).unwrap();

After some back and forth, the connection will complete its handshake and will
be ready for sending or receiving application data:

.. code-block:: rust

   if conn.is_established() {
       // Handshake completed, send some data on steadm 0.
       conn.stream_send(0, b"hello", true);
   }

Have a look at the examples_ directory for more complete examples
on how to use the quiche API (both from Rust and from C via its FFI API).

.. _examples: examples/

Building
--------

You can build quiche using cargo:

.. code-block:: bash

   $ cargo build --examples

As well as run its tests:

.. code-block:: bash

   $ cargo test

Note that BoringSSL_, used to implement QUIC's cryptographic handshake based on
TLS, needs to be built and linked to quiche. This is done automatically when
building quiche using cargo, but requires the `cmake` and `go` commands to be
available during the build process.

In alternative you can use your own custom build of BoringSSL by configuring
the BoringSSL directory with the ``QUICHE_BSSL_PATH`` environment variable:

.. code-block:: bash

   $ QUICHE_BSSL_PATH="/path/to/boringssl" cargo build --examples

.. _BoringSSL: https://boringssl.googlesource.com/boringssl/

Copyright
---------

Copyright (C) 2018, Cloudflare, Inc.

Copyright (C) 2018, Alessandro Ghedini

See COPYING_ for the license.

.. _COPYING: https://github.com/cloudflare/quiche/tree/master/COPYING
