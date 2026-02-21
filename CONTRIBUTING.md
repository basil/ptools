# Contributing

We welcome contributions! To contribute:

1. Fork the repository.
2. Create your feature or bugfix branch and make changes.
3. Add tests for your code.
4. Open a pull request.

## Building and Testing

Build all binaries and example applications:

```shell
cargo build
```

Run the tests:

```shell
cargo test
```

The integration tests in `tests/` spawn example applications from the `examples/`
directory as target processes for the ptools to inspect. These example binaries
are compiled automatically by `cargo test`. Each example program sets up some
state, signals to the test that it is ready to be inspected, and then waits to
be killed by the test process.

## Manual Pages

Manual pages are generated during the build by `build.rs` and written to
`target/man/`. After building, you can view them with:

```shell
man target/man/pargs.1
```

## Linters

The CI build runs the following linters. Run them locally before submitting a
pull request:

**Rust formatting** ([rustfmt](https://github.com/rust-lang/rustfmt)):

```shell
cargo fmt --all -- --check
```

To auto-fix formatting issues, omit `-- --check`:

```shell
cargo fmt --all
```

**Clippy** ([rust-clippy](https://github.com/rust-lang/rust-clippy)):

```shell
cargo clippy --all-targets --all-features
```

**Markdown linting**
([markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2)),
configured by `.markdownlint.json`:

```shell
markdownlint-cli2
```

## Code Coverage

The CI build workflow collects and prints coverage results by default on every run.

For local coverage collection without extra Rust components, you can run:

```shell
$ rm -rf target/coverage && mkdir -p target/coverage
$ RUSTFLAGS='-C instrument-coverage' cargo build --bins --examples
$ RUSTFLAGS='-C instrument-coverage' \
  LLVM_PROFILE_FILE='target/coverage/ptools-%p-%m.profraw' \
  cargo test --tests
$ llvm-profdata merge -sparse target/coverage/*.profraw -o target/coverage/ptools.profdata
$ llvm-cov report --ignore-filename-regex='/(\.cargo/registry|rustc)/' \
  --instr-profile=target/coverage/ptools.profdata \
  target/debug/pargs --object target/debug/pauxv --object target/debug/pcred \
  --object target/debug/penv --object target/debug/pfiles \
  --object target/debug/plgrp --object target/debug/prun \
  --object target/debug/psig --object target/debug/pstop \
  --object target/debug/ptree --object target/debug/pwait
$ llvm-cov export --format=lcov \
  --instr-profile=target/coverage/ptools.profdata \
  target/debug/pargs --object target/debug/pauxv --object target/debug/pcred \
  --object target/debug/penv --object target/debug/pfiles \
  --object target/debug/plgrp --object target/debug/prun \
  --object target/debug/psig --object target/debug/pstop \
  --object target/debug/ptree --object target/debug/pwait > target/coverage/lcov.info
```

The integration tests in `tests/` execute ptools binaries via
`tests/common::run_ptool`, so make sure the `target/debug/<tool>` binaries are
instrumented (the `cargo build --bins` step above does that).

`tests/pfiles_test::pfiles_resolves_socket_metadata_for_target_net_namespace` is
an end-to-end regression check for socket resolution across network namespaces.
It uses `unshare --net` to run an example process in a separate net namespace
and verifies `pfiles` still resolves socket metadata via `/proc/<pid>/net/*`. In
environments where unprivileged net namespace creation is blocked, the test
self-skips and prints the reason.

## Reporting Issues

Please report bugs or request features via the [GitHub Issues
page](https://github.com/basil/ptools/issues).
