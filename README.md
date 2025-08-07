# ptools

This repository contains a collection of Linux utilities for inspecting the
state of processes, inspired by the tools of the same name on Solaris/illumos.

## Getting Started

To build `ptools`, run the following commands on an Ubuntu 24.04 or newer
system:

```shell
$ git clone https://github.com/basil/ptools.git
$ cd ptools/
$ curl https://sh.rustup.rs -sSf | sh
$ cargo build
```

You can run the utilities from the `target/debug` directory, for example:

```shell
$ ./target/debug/ptree 1
```

To install `ptools` system-wide:

```shell
$ cargo install cargo-deb
$ cargo deb
$ sudo apt install ./target/debian/ptools_0.1.0_amd64.deb
```

## Why ptools?

Linux already has a number of mechanisms which can be used to inspect the state
of processes (the `/proc` filesystem, `ps`, `lsof`, etc.). Why add a new set of
tools?

The main advantage of ptools is consistency. The utilities provided by ptools
are consistently named and have a consistent interface. Also, significantly,
they can be run against core dumps where applicable, providing a uniform way to
examine live processes and core dumps. This is very useful for those who rely
heavily on core dumps to do postmortem debugging. The goal of this project is to
make this same consistent debugging experience available on Linux.

## Current State

The following utilities are currently available:

| Command     | Description                                                                                      |
| ----------- | ------------------------------------------------------------------------------------------------ |
| `pfiles(1)` | Show the open files and sockets of the process, as well as their corresponding file descriptors |
| `pargs(1)`  | Show the command line arguments passed to the process                                           |
| `penv(1)`   | Show the environment of the process                                                             |
| `ptree(1)`  | Show the process tree containing the process                                                    |

There are a number of other commands available on Solaris/illumos which have not
been implemented here yet, perhaps most notably `pstack`. Also, support for
examining core dumps has not yet been implemented.

## Contributing

We welcome contributions! To contribute:

1. Fork the repository.
2. Create your feature or bugfix branch and make changes.
3. Add tests for your code.
4. Open a pull request.

## Reporting Issues

Please report bugs or request features via the [GitHub Issues
page](https://github.com/basil/ptools/issues).

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.
