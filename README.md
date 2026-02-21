# ptools

[![Crates.io](https://img.shields.io/crates/v/ptools)](https://crates.io/crates/ptools)
[![License](https://img.shields.io/crates/l/ptools)](LICENSE)
[![Build](https://github.com/basil/ptools/actions/workflows/build.yml/badge.svg)](https://github.com/basil/ptools/actions/workflows/build.yml)

This repository contains a collection of Linux utilities for inspecting the
state of processes, inspired by the tools of the same name on Solaris/illumos.

## Motivation

Linux already has a number of mechanisms which can be used to inspect the state
of processes (the `/proc` filesystem, `ps`, `lsof`, etc.). Why add a new set of
tools?

The main advantage of `ptools` is consistency. The utilities provided by `ptools`
are consistently named and have a consistent interface. Also, significantly,
they can be run against core dumps where applicable, providing a uniform way to
examine live processes and core dumps. This is very useful for those who rely
heavily on core dumps to do postmortem debugging. The goal of this project is to
make this same consistent debugging experience available on Linux.

For more information, see Dave Pacheco’s article [“illumos tools for observing
processes”](https://www.davepacheco.net/blog/2012/illumos-tools-for-observing-processes/).

## Getting Started

Install from [crates.io](https://crates.io/crates/ptools):

```shell
cargo install ptools
```

Alternatively, download the latest `.deb` or `.rpm` package from the [GitHub
Releases page](https://github.com/basil/ptools/releases).

On Debian/Ubuntu:

```shell
# Debian/Ubuntu
sudo apt install ./ptools_*.deb

# Fedora/RHEL
sudo dnf install ./ptools-*.rpm
```

## Examples

`pfiles(1)` shows you every file descriptor a process has open (similar to
`lsof`, but for a specific process). This includes details on regular files
(including offset, which is great for checking on programs that scan through
large files) and sockets. For more information about this use case, see Chris
Siebenmann’s [“In praise of Solaris’s pfiles command”](https://utcc.utoronto.ca/~cks/space/blog/solaris/PfilesPraise).

```text
$ pfiles $(pgrep example)
45909: /bin/example
  Current soft rlimit: 1024 file descriptors
  Current hard rlimit: 524288 file descriptors
  Current umask: 022
   0: S_IFCHR mode:0600 dev:0,27 ino:4 uid:1000 gid:5 rdev:136,1
      O_RDWR
      /dev/pts/1
      offset: 0
   1: S_IFCHR mode:0600 dev:0,27 ino:4 uid:1000 gid:5 rdev:136,1
      O_RDWR
      /dev/pts/1
      offset: 0
   2: S_IFCHR mode:0600 dev:0,27 ino:4 uid:1000 gid:5 rdev:136,1
      O_RDWR
      /dev/pts/1
      offset: 0
   3: S_IFREG mode:0644 dev:252,0 ino:58197644 uid:0 gid:0 size:19
      O_RDONLY|O_CLOEXEC
      /etc/locale.conf
      offset: 19
   4: S_IFSOCK mode:0777 dev:0,9 ino:25978 uid:0 gid:0 size:0
      O_RDWR|O_CLOEXEC|O_NONBLOCK
        sockname: AF_INET 0.0.0.0  port: 22
        SOCK_STREAM
        SO_REUSEADDR,SO_ACCEPTCONN,SO_SNDBUF(16384),SO_RCVBUF(131072)
        congestion control: cubic
        state: TCP_LISTEN
   5: S_IFSOCK mode:0777 dev:0,9 ino:25980 uid:0 gid:0 size:0
      O_RDWR|O_CLOEXEC|O_NONBLOCK
        sockname: AF_INET6 ::  port: 22
        SOCK_STREAM
        SO_REUSEADDR,SO_ACCEPTCONN,SO_SNDBUF(16384),SO_RCVBUF(131072)
        congestion control: cubic
        state: TCP_LISTEN
```

`ptree(1)` shows you a process tree for the whole system or for a given
process or user:

```text
$ ptree 1
1  /usr/lib/systemd/systemd --switched-root --system --deserialize=47
  1333  /usr/lib/systemd/systemd-journald
  1370  /usr/lib/systemd/systemd-udevd
  3620  /usr/lib/systemd/systemd --user
    6184  /usr/bin/qterminal
      45909  /bin/zsh
```

`pargs(1)` prints the arguments a process was started with:

```text
$ pargs $(pgrep Xwayland)
3866:   Xwayland :0 -rootless -core -listenfd 55 -listenfd 56 -displayfd 98 -wm 95
argv[0]: Xwayland
argv[1]: :0
argv[2]: -rootless
argv[3]: -core
argv[4]: -listenfd
argv[5]: 55
argv[6]: -listenfd
argv[7]: 56
argv[8]: -displayfd
argv[9]: 98
argv[10]: -wm
argv[11]: 95
```

`penv(1)` prints the environment variables a process was started with:

```text
$ penv $(pgrep Xwayland)
3866:   Xwayland :0 -rootless -core -listenfd 55 -listenfd 56 -displayfd 98 -wm 95
envp[0]: SHELL=/bin/zsh
envp[1]: GTK_IM_MODULE=wayland
envp[2]: XDG_BACKEND=wayland
envp[3]: XDG_CONFIG_DIRS=/etc:/etc/xdg:/usr/share
envp[4]: XDG_SESSION_PATH=/org/freedesktop/DisplayManager/Session1
```

`pauxv(1)` prints the process’s auxiliary vector:

```text
$ pauxv $(pgrep sshd)
2785:   sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
AT_SYSINFO_EHDR 0x00007fa1fe8b7000
AT_MINSIGSTKSZ  0x0000000000000d30
AT_HWCAP        0x00000000178bfbff FPU | VME | DE | PSE | TSC | MSR | PAE | MCE | CX8 | APIC | SEP | MTRR | PGE | MCA | CMOV | PAT | PSE36 | CLFSH | MMX | FXSR | SSE | SSE2 | HTT
AT_PAGESZ       0x0000000000001000
AT_CLKTCK       0x0000000000000064
AT_PHDR         0x000056161562a040
AT_PHENT        0x0000000000000038
AT_PHNUM        0x000000000000000d
AT_BASE         0x00007fa1fe8b9000
AT_FLAGS        0x0000000000000000
AT_ENTRY        0x000056161562fc90
AT_UID          0x0000000000000000 0(root)
AT_EUID         0x0000000000000000 0(root)
AT_GID          0x0000000000000000 0(root)
AT_EGID         0x0000000000000000 0(root)
AT_SECURE       0x0000000000000000
AT_RANDOM       0x00007fff1cf31ff9
AT_HWCAP2       0x0000000000000002 FSGSBASE
AT_EXECFN       0x00007fff1cf32fe9 /usr/sbin/sshd
AT_PLATFORM     0x00007fff1cf32009 x86_64
AT_RSEQ_FEATURE_SIZE 0x000000000000001c
AT_RSEQ_ALIGN   0x0000000000000020
```

`psig(1)` shows what signals a process is catching:

```text
$ psig 1
1:      /usr/lib/systemd/systemd --switched-root --system --deserialize=47
HUP       default       blocked
INT       default       blocked
QUIT      caught
ILL       caught
TRAP      default
ABRT      caught
BUS       caught
FPE       caught
KILL      default
USR1      default       blocked
SEGV      caught
USR2      default       blocked
PIPE      ignored
ALRM      default
TERM      default       blocked
```

## Current State

The following table lists all Solaris/illumos ptools and their status in this
project. Tools provided by [procps-ng](https://gitlab.com/procps-ng/procps),
[glibc](https://www.gnu.org/software/libc/), or
[python-linux-procfs](https://git.kernel.org/pub/scm/libs/python/python-linux-procfs/python-linux-procfs.git/)
are not reimplemented here, as these packages are widely available on Linux
distributions and already provide equivalent functionality. There are a number
of commands available on Solaris/illumos which have not
been implemented here yet, perhaps most notably `pstack(1)`. Also, support
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
