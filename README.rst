quiche
======

.. image:: https://travis-ci.org/ghedo/quiche.svg
  :target: https://travis-ci.org/ghedo/quiche

quiche_ is an implementation of the QUIC transport protocol as specified by
the IETF_. It provides a low level API for processing QUIC packets and
handling connection state, while leaving I/O (including dealing with sockets)
to the application.

A live QUIC server based on quiche is available at ``https://quic.tech:4433/``
to be used for experimentation.

Note that it is very experimental and unstable software, and many features are
still in development.

.. _quiche: https://ghedo.github.io/quiche
.. _ietf: https://quicwg.org/

Status
------

* [x] QUIC draft-15
* [x] Version Negotiation
* [x] TLS 1.3 handshake (using BoringSSL)
* [x] Stream API
* [x] Flow control
* [ ] Unidirectional streams
* [ ] Loss detection and recovery
* [ ] Congestion control
* [ ] Connection close
* [ ] Stateless retry
* [ ] 0-RTT

Building
--------

quiche uses BoringSSL_ to implement QUIC's cryptographic handshake based on
TLS. To download and build it you can use the ``get_bssl.sh`` script provided
in the repository:

.. code-block:: bash

   $ util/get_bssl.sh

You can now build quiche using cargo:

.. code-block:: bash

   $ cargo build --examples

As well as run its tests:

.. code-block:: bash

   $ cargo test

In alternative you can use your own custom build of BoringSSL by configuring
the directory containing ``libcrypto.a`` and ``libssl.a`` with the
``QUICHE_BSSL_PATH`` environment variable:

.. code-block:: bash

   $ QUICHE_BSSL_PATH="/path/to/boringssl" cargo build --examples

.. _BoringSSL: https://boringssl.googlesource.com/boringssl/

Copyright
---------

Copyright (C) 2018 Alessandro Ghedini <alessandro@ghedini.me>

See COPYING_ for the license.

.. _COPYING: https://github.com/ghedo/quiche/tree/master/COPYING
