This crate provides fuzzers based on [honggfuzz](https://docs.rs/honggfuzz/).

Available fuzzers:

* recv\_packet\_client: Processes a single incoming packet (including frames) at
  a time from the client side.

* recv\_packet\_server: Processes a single incoming packet (including frames) at
  a time from the server side.

Refer to the [honggfuzz](https://docs.rs/honggfuzz/) documentation for more
information on how to run the fuzzers.
