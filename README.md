# ptools

This repository contains a collection of Linux utilities for inspecting the
state of processes, inspired by the tools of the same name on Solaris/illumos.

## Getting Started

Install from [crates.io](https://crates.io/crates/ptools):

```shell
cargo install ptools
```

Alternatively, download the latest `.deb` or `.rpm` package from the [GitHub
Releases page](https://github.com/basil/ptools/releases).

On Debian/Ubuntu:

```shell
sudo apt install ./ptools_*.deb
```

On Fedora and other RPM-based distributions:

```shell
sudo dnf install ./ptools-*.rpm
```

## Why ptools?

Linux already has a number of mechanisms which can be used to inspect the state
of processes (the `/proc` filesystem, `ps`, `lsof`, etc.). Why add a new set of
tools?

The main advantage of `ptools` is consistency. The utilities provided by `ptools`
are consistently named and have a consistent interface. Also, significantly,
they can be run against core dumps where applicable, providing a uniform way to
examine live processes and core dumps. This is very useful for those who rely
heavily on core dumps to do postmortem debugging. The goal of this project is to
make this same consistent debugging experience available on Linux.

## Current State

The following table lists all Solaris/illumos ptools and their status in this
project. Tools provided by [procps-ng](https://gitlab.com/procps-ng/procps),
[glibc](https://www.gnu.org/software/libc/), or
[python-linux-procfs](https://git.kernel.org/pub/scm/libs/python/python-linux-procfs/python-linux-procfs.git/)
are not reimplemented here, as these packages are widely available on Linux
distributions and already provide equivalent functionality. There are a number
of commands available on Solaris/illumos which have not
been implemented here yet, perhaps most notably `pstack`. Also, support
for examining core dumps has not yet been implemented.

| Command        | Description                                           | Status                       |
| -------------- | ----------------------------------------------------- | ---------------------------- |
| `pargs(1)`     | Print process arguments                               | ✅ Implemented               |
| `pauxv(1)`     | Print process auxiliary vector                        | ✅ Implemented               |
| `pcred(1)`     | Print process credentials                             | ✅ Implemented               |
| `penv(1)`      | Print process environment variables                   | ✅ Implemented               |
| `pfiles(1)`    | Print information for all open files in each process  | ✅ Implemented               |
| `pflags(1)`    | Print process status flags                            | ➡️ See `python-linux-procfs` |
| `pgrep(1)`     | Find processes by name                                | ➡️ See `procps-ng`           |
| `pkill(1)`     | Signal processes by name                              | ➡️ See `procps-ng`           |
| `pldd(1)`      | Print process dynamic libraries                       | ➡️ See `glibc`               |
| `plgrp(1)`     | Display home NUMA node and thread affinities          | ✅ Implemented               |
| `plimit(1)`    | Get or set process resource limits                    | 🔲 Not yet implemented       |
| `plockstat(1)` | Print lock statistics                                 | 🔲 Not yet implemented       |
| `pmadvise(1)`  | Apply advice about memory to a process                | 🔲 Not yet implemented       |
| `pmap(1)`      | Print process address maps                            | ➡️ See `procps-ng`           |
| `ppgsz(1)`     | Set preferred page size                               | 🔲 Not yet implemented       |
| `ppriv(1)`     | Print or modify process privilege sets and attributes | 🔲 Not yet implemented       |
| `preap(1)`     | Force a defunct process to be reaped                  | 🔲 Not yet implemented       |
| `prun(1)`      | Set stopped processes running with `SIGCONT`          | ✅ Implemented               |
| `psecflags(1)` | Print or modify process security flags                | 🔲 Not yet implemented       |
| `psig(1)`      | Print process signal actions                          | ✅ Implemented               |
| `pstack(1)`    | Print process call stack                              | 🔲 Not yet implemented       |
| `pstop(1)`     | Stop processes with `SIGSTOP`                         | ✅ Implemented               |
| `ptime(1)`     | Time a process using microstate accounting            | 🔲 Not yet implemented       |
| `ptree(1)`     | Print process trees                                   | ✅ Implemented               |
| `pwait(1)`     | Wait for processes to terminate                       | ✅ Implemented               |
| `pwdx(1)`      | Print the current working directory of the process    | ➡️ See `procps-ng`           |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on contributing.

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.
