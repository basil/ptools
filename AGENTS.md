# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on
this project.

## Build & Test

From [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
cargo build                              # Build all binaries and examples
cargo test                               # Run all tests
cargo fmt --all -- --check               # Check formatting
cargo clippy --all-targets --all-features  # Lint
```

The integration tests spawn example programs from `examples/` as target
processes. The tests locate these example binaries via `find_exec()` in
`tests/common/mod.rs`, which expects them to already be built in the Cargo
output directory. You must build before running tests:

```bash
cargo build              # Build binaries and examples first
cargo test               # Then run the tests
```

Running `cargo test` alone may fail if the example binaries have not been
built yet.

You can also run individual tools directly:

```bash
./target/debug/ptree 1
./target/debug/pfiles $$
```

## Architecture Overview

`ptools` is a collection of Linux command-line utilities for inspecting process
state, inspired by the Solaris/illumos tools of the same name. Each tool is a
separate binary in `src/bin/`. All tools work on both live processes (via
`/proc`) and core dumps (via `systemd-coredump` journal entries), sharing the
same parsing logic through a common library.

### Directory layout

```text
src/
  lib.rs              Library root; re-exports the public API
  bin/                One binary per tool (pargs.rs, pfiles.rs, ptree.rs, ...)
  proc/               Process handle layer (parsing and structured access)
    mod.rs            ProcHandle, resolve_operand(), Error
    auxv.rs           Auxiliary vector parsing
    cred.rs           Credential parsing and UID/GID resolution
    fd.rs             File descriptor structures and classification
    net.rs            Socket metadata and peer process resolution
    numa.rs           NUMA node and CPU affinity
    pidfd.rs          pidfd utilities
    signal.rs         Signal set parsing
  source/             Data source abstraction
    mod.rs            ProcSource trait
    live.rs           Live process backend (reads /proc)
    coredump.rs       Coredump backend (reads systemd journal + ELF notes)
  display.rs          Shared formatting helpers
examples/             Example programs used as test targets
tests/                Integration tests
  common/mod.rs       Test utilities (run_ptool, ReadySignal, etc.)
build.rs              Man page generation (roff)
```

## Conventions & Patterns

### Three-layer architecture

The codebase is organized into three layers with strict dependency rules:

1. **Source layer** (`src/source/`): Abstracts where process data comes from.
   The `ProcSource` trait provides a uniform interface; `LiveProcess` reads
   `/proc/[pid]/...` while `CoredumpSource` reads from journal entries and ELF
   notes. This layer must never write to stdout/stderr. Only the process handle
   layer consumes it.

2. **Process handle layer** (`src/proc/`): Parses raw data from the source
   layer into typed Rust structures. The central type is `ProcHandle`, an
   opaque handle through which all process queries flow. This layer must never
   write to stdout/stderr; non-fatal diagnostics are accumulated in a warnings
   vector. Types here should not implement `Display` (except `Error`).
   Never format output in this layer -- it provides structured data only.
   All output formatting belongs in the presentation/display layer.

3. **Presentation/display layer** (`src/display.rs` and `src/bin/*.rs`):
   Formats structured data from the proc-handle layer for terminal output.
   Shared formatting lives in `display.rs`; tool-specific formatting lives in
   each binary. This layer must never consume the source layer directly.

### Error handling

Tools should recover from errors and continue producing useful output.
Debugging tools are expected to run on systems in unusual states, so do not
panic on procfs inconsistencies. Assert only on purely internal invariants.
Warnings are accumulated in `ProcHandle` and drained by binaries to stderr.

### Command-line parsing

All tools use `lexopt` for argument parsing. No heavy framework (clap,
structopt) is used.

### Test framework and example programs

Integration tests live in `tests/` and use a common helper module
(`tests/common/mod.rs`). The typical pattern:

1. An **example program** in `examples/` sets up the process state to be
   inspected (opens files, sets signal handlers, creates threads, etc.).
2. The example reads `PTOOLS_TEST_READY_FILE` from its environment, creates
   that file to signal readiness, then loops until killed.
3. The **test** calls `common::run_ptool()`, which spawns the example, waits
   for the ready signal, runs the tool against the example's PID, kills the
   example, and returns the tool's output.
4. The test asserts on the captured stdout/stderr.

To add a new test:

- If you need a new target process state, add an example in `examples/` that
  follows the ready-signal convention (read `PTOOLS_TEST_READY_FILE`, create
  the file when ready, loop forever).
- Add a test file in `tests/` (or add a `#[test]` function to an existing
  one). Use `common::run_ptool()` to drive the tool.
- Remember to run `cargo build` before `cargo test` so that the example
  binaries are available.
- New functionality is expected to have corresponding tests.
