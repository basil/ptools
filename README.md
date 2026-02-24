# ptools

[![Crates.io](https://img.shields.io/crates/v/ptools)](https://crates.io/crates/ptools)
[![License](https://img.shields.io/crates/l/ptools)](LICENSE)
[![Build](https://github.com/basil/ptools/actions/workflows/build.yml/badge.svg)](https://github.com/basil/ptools/actions/workflows/build.yml)

`ptools` is a collection of Linux utilities for inspecting the state of
processes, inspired by the tools of the same name on Solaris/illumos.

## Motivation

Linux already has a number of mechanisms which can be used to inspect the state
of processes (the `/proc` filesystem, `ps(1)`, `lsof(1)`, etc.). Why add
a new set of tools?

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

## Examples

`pstack(1)` shows you thread stack traces for the processes you give it. This is
incredibly useful as a first step for figuring out what a program is doing when
it’s slow or not responsive.

```text
$ pstack $$
97060:  /bin/zsh
0x00007f46d0d31c5e __internal_syscall_cancel+0x7e
0x00007f46d0d31c84 __syscall_cancel+0x14
0x00007f46d0cdd525 __sigsuspend+0x25
0x000055a071737dad zwaitjob+0x5cd
0x000055a071737e8f waitjobs+0x2f
0x000055a07170c682 execpline.lto_priv.0+0xba2
0x000055a07170dbfe execlist+0x52e
0x000055a07170e4ce execode+0xae
0x000055a07172d532 loop+0x792
0x000055a0717350e6 zsh_main+0x5a6
0x000055a0716e1d0d main+0xd
0x00007f46d0cc65b5 __libc_start_call_main+0x75
0x00007f46d0cc6668 __libc_start_main@@GLIBC_2.34+0x88
0x000055a0716e1d35 _start+0x25
```

If DWARF debug information is installed, you can use verbose mode to
find source code information (file and line number), values of arguments
passed to functions, and inlined function frames.

```text
$ pstack -v $$
194145: /bin/zsh
0x00007f7a7e2aec5e __internal_syscall_cancel(a1=140728959537968, a2=8, a3=0, a4=0, a5=0, a6=0, nr=130)+0x7e (cancellation.c:64)
0x00007f7a7e2aec84 __syscall_cancel(nr=130)+0x14 (cancellation.c:75)
0x00007f7a7e25a525 __sigsuspend()+0x25 (sigsuspend.c:26)
0x000055cbe14bfdad zwaitjob()+0x5cd (signals.c:393)
0x000055cbe14bfe8f waitjobs()+0x2f (jobs.c:1702)
0x000055cbe1494682 execpline.lto_priv.0()+0xba2 (exec.c:1785)
0x000055cbe1495bfe execlist()+0x52e (exec.c:1444)
0x000055cbe14964ce execode()+0xae (exec.c:1221)
0x000055cbe14b5532 loop()+0x792 (init.c:212)
0x000055cbe14bd0e6 zsh_main()+0x5a6 (init.c:1794)
0x000055cbe1469d0d main()+0xd (main.c:93)
0x00007f7a7e2435b5 __libc_start_call_main(main=0x55cbe1469d00, argc=1, argv=0x7ffe03a49cf8)+0x75 (libc_start_call_main.h:58)
0x00007f7a7e243668 __libc_start_main@@GLIBC_2.34(main=0x55cbe1469d00, argc=1, argv=0x7ffe03a49cf8, stack_end=0x7ffe03a49ce8)+0x88 (libc-start.c:360)
0x000055cbe1469d35 _start()+0x25 (main.c:93)
```

`pfiles(1)` shows you every file descriptor a process has open (similar to
`lsof`, but for a specific process). This includes details on regular files
(including offset, which is great for checking on programs that scan through
large files) and sockets. For more information, see Chris Siebenmann’s article
[“In praise of Solaris’s `pfiles` command”](https://utcc.utoronto.ca/~cks/space/blog/solaris/PfilesPraise).

```text
$ pfiles $(pgrep example)
2785: sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
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
3866: Xwayland :0 -rootless -core -listenfd 55 -listenfd 56 -displayfd 98 -wm 95
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
3866: Xwayland :0 -rootless -core -listenfd 55 -listenfd 56 -displayfd 98 -wm 95
envp[0]: SHELL=/bin/zsh
envp[1]: GTK_IM_MODULE=wayland
envp[2]: XDG_BACKEND=wayland
envp[3]: XDG_CONFIG_DIRS=/etc:/etc/xdg:/usr/share
envp[4]: XDG_SESSION_PATH=/org/freedesktop/DisplayManager/Session1
```

`pauxv(1)` prints the process’s auxiliary vector:

```text
$ pauxv $(pgrep sshd)
2785: sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
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
1: /usr/lib/systemd/systemd --switched-root --system --deserialize=47
HUP       default blocked
INT       default blocked
QUIT      caught
ILL       caught
TRAP      default
ABRT      caught
BUS       caught
FPE       caught
KILL      default
USR1      default blocked
SEGV      caught
USR2      default blocked
PIPE      ignored
ALRM      default
TERM      default blocked
```

## Core Dump Support

Core dump support is available for `pargs(1)`, `pauxv(1)`, `pcred(1)`,
`penv(1)`, `pfiles(1)`, and `psig(1)` via `systemd-coredump(8)` extended
attributes and journal metadata. Even when a core file has been removed by
`systemd-tmpfiles(8)` or by storage limits, process metadata can often still
be retrieved from the `systemd-coredump(8)` journal entry; use
`coredumpctl list <name> -F COREDUMP_FILENAME` to find the path and pass it
to any of these tools.

## Current State

The following table lists all Solaris/illumos ptools and their status in this
project. Tools provided by [procps-ng](https://gitlab.com/procps-ng/procps),
[glibc](https://www.gnu.org/software/libc/), or
[python-linux-procfs](https://git.kernel.org/pub/scm/libs/python/python-linux-procfs/python-linux-procfs.git/)
are not reimplemented here, as these packages are widely available on Linux
distributions and already provide equivalent functionality. There are a number
of commands available on Solaris/illumos which have not
been implemented here yet.

| Command                                                       | Description                                           | Status                       |
| ------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------- |
| [`pargs(1)`](https://illumos.org/man/1/pargs)                 | Print process arguments                               | ✅ Implemented               |
| [`pauxv(1)`](https://illumos.org/man/1/pauxv)                 | Print process auxiliary vector                        | ✅ Implemented               |
| [`pcred(1)`](https://illumos.org/man/1/pcred)                 | Print process credentials                             | ✅ Implemented               |
| [`penv(1)`](https://illumos.org/man/1/penv)                   | Print process environment variables                   | ✅ Implemented               |
| [`pfiles(1)`](https://illumos.org/man/1/pfiles)               | Print information for all open files in each process  | ✅ Implemented               |
| [`pflags(1)`](https://illumos.org/man/1/pflags)               | Print process status flags                            | ➡️ See `python-linux-procfs` |
| [`pgrep(1)`](https://illumos.org/man/1/pgrep)                 | Find processes by name                                | ➡️ See `procps-ng`           |
| [`pkill(1)`](https://illumos.org/man/1/pkill)                 | Signal processes by name                              | ➡️ See `procps-ng`           |
| [`pldd(1)`](https://illumos.org/man/1/pldd)                   | Print process dynamic libraries                       | ➡️ See `glibc`               |
| [`plgrp(1)`](https://illumos.org/man/1/plgrp)                 | Print current NUMA node and thread CPU affinities     | ✅ Implemented               |
| [`plimit(1)`](https://illumos.org/man/1/plimit)               | Get or set process resource limits                    | 🔲 Not yet implemented       |
| [`plockstat(1)`](https://illumos.org/man/8/plockstat)         | Print lock statistics                                 | 🔲 Not yet implemented       |
| [`pmadvise(1)`](https://illumos.org/man/1/pmadvise)           | Apply advice about memory to a process                | 🔲 Not yet implemented       |
| [`pmap(1)`](https://illumos.org/man/1/pmap)                   | Print process address maps                            | ➡️ See `procps-ng`           |
| [`ppgsz(1)`](https://illumos.org/man/1/ppgsz)                 | Set preferred page size                               | 🔲 Not yet implemented       |
| [`ppriv(1)`](https://illumos.org/man/1/ppriv)                 | Print or modify process privilege sets and attributes | 🔲 Not yet implemented       |
| [`preap(1)`](https://illumos.org/man/1/preap)                 | Force a defunct process to be reaped                  | 🔲 Not yet implemented       |
| [`prun(1)`](https://illumos.org/man/1/prun)                   | Set stopped processes running with `SIGCONT`          | ✅ Implemented               |
| [`psecflags(1)`](https://illumos.org/man/1/psecflags)         | Print or modify process security flags                | 🔲 Not yet implemented       |
| [`psig(1)`](https://illumos.org/man/1/psig)                   | Print process signal actions                          | ✅ Implemented               |
| [`pstack(1)`](https://illumos.org/man/1/pstack)               | Print process call stack                              | ✅ Implemented               |
| [`pstop(1)`](https://illumos.org/man/1/pstop)                 | Stop processes with `SIGSTOP`                         | ✅ Implemented               |
| [`ptime(1)`](https://illumos.org/man/1/ptime)                 | Time a process using microstate accounting            | 🔲 Not yet implemented       |
| [`ptree(1)`](https://illumos.org/man/1/ptree)                 | Print process trees                                   | ✅ Implemented               |
| [`pwait(1)`](https://illumos.org/man/1/pwait)                 | Wait for processes to terminate                       | ✅ Implemented               |
| [`pwdx(1)`](https://illumos.org/man/1/pwdx)                   | Print the current working directory of the process    | ➡️ See `procps-ng`           |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on contributing.

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.
