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

.. _quiche: https://docs.quic.tech/quiche/
.. _ietf: https://quicwg.org/

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
