This crate provides fuzzers based on [libfuzzer](https://llvm.org/docs/LibFuzzer.html).

Available fuzzers:

* packet\_recv\_client: Processes a single incoming packet (including frames) at
  a time from the client side.

* packet\_recv\_server: Processes a single incoming packet (including frames) at
  a time from the server side.

* qpack\_decode: Parses a single QPACK header block at a time.

## Generating seeds

Run `tools/gen_fuzz_seeds.sh` from the root of the repository.

## Generating code coverage

Run the following command from the root of the repository:

```
$ cargo +nightly fuzz coverage <target> fuzz/corpus/<target>
```

Where `<target>` is one of the fuzzers listed above.

An HTML report can be generated using `llvm-cov`. Note that the same version as
the one used by `cargo-fuzz` must be used. If installing the
`llvm-tools-preview` component using `rustup`, `llvm-cov` can be found somewhere
under `~/.rustup/toolchains` (or wherever the toolchains are installed).

For example:

```
$ ~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov show --ignore-filename-regex='cargo/registry' --ignore-filename-regex='/rustc' --show-instantiations --show-line-counts-or-regions --Xdemangler=rustfilt --instr-profile /home/ghedo/devel/quiche/fuzz/coverage/packet_recv_server/coverage.profdata /home/ghedo/devel/quiche/target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/packet_recv_server --format=html --output-dir "/tmp/cov"
```

The `index.html` file under `/tmp/cov` can then be opened in a browser to view
the report.

## Start run on Mayhem

Build and publish the fuzzing Docker image:

```
make docker-fuzz docker-fuzz-publish
```

Then run the following command under `fuzz/mayhem/`:

```
$ mayhem run --all <target>
```

Where `<target>` is one of the fuzzers listed above.

## Sync test cases from Mayhem

Run the following command under `fuzz/mayhem/`:

```
$ mayhem sync <target>
```

Where `<target>` is one of the fuzzers listed above.

Then minimize the inputs:

```
$ cargo +nightly fuzz cmin -Oa <target>
```
