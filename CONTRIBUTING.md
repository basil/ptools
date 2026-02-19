# Contributing

We welcome contributions! To contribute:

1. Fork the repository.
2. Create your feature or bugfix branch and make changes.
3. Add tests for your code.
4. Open a pull request.

## Code Coverage

The CI build workflow collects and prints coverage results by default on every run.

For local coverage collection without extra Rust components, you can run:

```shell
$ rm -rf target/coverage && mkdir -p target/coverage
$ RUSTFLAGS='-C instrument-coverage' cargo build --bins
$ RUSTFLAGS='-C instrument-coverage' \
  LLVM_PROFILE_FILE='target/coverage/ptools-%p-%m.profraw' \
  cargo test --tests
$ llvm-profdata merge -sparse target/coverage/*.profraw -o target/coverage/ptools.profdata
$ llvm-cov report --ignore-filename-regex='/(\.cargo/registry|rustc)/' \
  --instr-profile=target/coverage/ptools.profdata \
  target/debug/pargs --object target/debug/penv --object target/debug/pfiles \
  --object target/debug/pflags --object target/debug/prun \
  --object target/debug/psig --object target/debug/pstop \
  --object target/debug/ptree --object target/debug/pwait
$ llvm-cov export --format=lcov --instr-profile=target/coverage/ptools.profdata \
  target/debug/pargs --object target/debug/penv --object target/debug/pfiles \
  --object target/debug/pflags --object target/debug/prun \
  --object target/debug/psig --object target/debug/pstop \
  --object target/debug/ptree --object target/debug/pwait > target/coverage/lcov.info
```

The integration tests in `tests/` execute ptools binaries via
`tests/common::run_ptool`, so make sure the `target/debug/<tool>` binaries are
instrumented (the `cargo build --bins` step above does that).

`tests/pfiles_test::pfiles_resolves_socket_metadata_for_target_net_namespace` is an
end-to-end regression check for socket resolution across network namespaces. It
uses `unshare --net` to run an example process in a separate net namespace and
verifies `pfiles` still resolves socket metadata via `/proc/<pid>/net/*`. In
environments where unprivileged net namespace creation is blocked, the test
self-skips and prints the reason.

## Reporting Issues

Please report bugs or request features via the [GitHub Issues
page](https://github.com/basil/ptools/issues).
