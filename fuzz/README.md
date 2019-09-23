This crate provides fuzzers based on [libfuzzer](https://llvm.org/docs/LibFuzzer.html).

Available fuzzers:

* packet\_recv\_client: Processes a single incoming packet (including frames) at
  a time from the client side.

* packet\_recv\_server: Processes a single incoming packet (including frames) at
  a time from the server side.

* qpack\_decode: Parses a single QPACK header block at a time.
