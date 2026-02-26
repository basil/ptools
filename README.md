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

## Prerequisites

`ptools` requires `libdw` (from elfutils) and `libsystemd` at run time.

**Ubuntu/Debian:**

```shell
sudo apt-get install libdw1 libsystemd0
```

**Fedora:**

```shell
sudo dnf install elfutils-libs systemd-libs
```

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
31903: /bin/zsh
0x00007fc764b24c5e __internal_syscall_cancel+0x7e
0x00007fc764b24c84 __syscall_cancel+0x14
0x00007fc764ad0525 __sigsuspend+0x25
0x000055bec2e64dad zwaitjob+0x5cd
0x000055bec2e64e8f waitjobs+0x2f
0x000055bec2e39682 execpline.lto_priv.0+0xba2
0x000055bec2e3abfe execlist+0x52e
0x000055bec2e3b4ce execode+0xae
0x000055bec2e5a532 loop+0x792
0x000055bec2e620e6 zsh_main+0x5a6
0x000055bec2e0ed0d main+0xd
0x00007fc764ab95b5 __libc_start_call_main+0x75
0x00007fc764ab9668 __libc_start_main@@GLIBC_2.34+0x88
0x000055bec2e0ed35 _start+0x25
```

If DWARF debug information is installed, you can use `-v` to show source code
locations (file and line number) and inlined function frames.

```text
$ pstack -v $(pgrep firefox)
27981: /usr/lib64/firefox/firefox
0x00007fa051e879a2 __syscall_cancel_arch+0x32 (syscall_cancel.S:56)
0x00007fa051e7bc3c __internal_syscall_cancel+0x5c (cancellation.c:49)
0x00007fa051e7c2ac __futex_abstimed_wait_common+0x7c (futex-internal.c:57)
0x00007fa051e7e97e pthread_cond_wait@@GLIBC_2.3.2+0x14e (pthread_cond_wait.c:421)
0x000055894a58616b mozilla::detail::ConditionVariableImpl::wait+0x1b (ConditionVariable_posix.cpp:104)
0x00007fa03b98067a mozilla::ThreadEventQueue::GetEvent+0xea (CondVar.h:58)
0x00007fa03b995d5d nsThread::ProcessNextEvent+0x18d (nsThread.cpp:1125)
0x00007fa03b9964a1 NS_ProcessNextEvent+0x41 (nsThreadUtils.cpp:461)
0x00007fa03c1cb39b mozilla::ipc::MessagePumpForNonMainThreads::Run+0xcb (MessagePump.cpp:329)
0x00007fa03c179b94 MessageLoop::RunInternal+0x54 (message_loop.cc:368)
0x00007fa03c179b94 MessageLoop::RunHandler [inlined] (message_loop.cc:361)
0x00007fa03c179b94 MessageLoop::Run [inlined] (message_loop.cc:343)
0x00007fa03b99cfd6 nsThread::ThreadFunc+0xd6 (nsThread.cpp:373)
0x00007fa0522fee63 _pt_root+0x103
0x000055894a5558ec set_alt_signal_stack_and_start+0xec (pthread_create_interposer.cpp:81)
0x00007fa051e7f464 start_thread+0x2e4 (pthread_create.c:448)
0x00007fa051f025ec __clone3+0x2c (clone3.S:78)
```

`pfiles(1)` shows you every file descriptor a process has open (similar to
`lsof(1)`, but for a specific process). This includes details on regular files
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
1  /usr/lib/systemd/systemd --switched-root --system --deserialize=48
  1427  /usr/lib/systemd/systemd-journald
  1451  /usr/lib/systemd/systemd-userdbd
    32574  systemd-userwork: waiting...
    32873  systemd-userwork: waiting...
    34264  systemd-userwork: waiting...
  1465  /usr/lib/systemd/systemd-udevd
  2439  /usr/lib/systemd/systemd-oomd
  2440  /usr/lib/systemd/systemd-resolved
  2441  /usr/bin/auditd
```

`pargs(1)` prints the arguments a process was started with:

```text
$ pargs $(pgrep Xwayland)
3978: Xwayland :0 -rootless -core -listenfd 55 -listenfd 56 -displayfd 98 -wm 95
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
3978: Xwayland :0 -rootless -core -listenfd 55 -listenfd 56 -displayfd 98 -wm 95
envp[0]: SHELL=/bin/zsh
envp[1]: GTK_IM_MODULE=wayland
envp[2]: XDG_BACKEND=wayland
envp[3]: XDG_CONFIG_DIRS=/etc:/etc/xdg:/usr/share
envp[4]: XDG_SESSION_PATH=/org/freedesktop/DisplayManager/Session1
```

`pauxv(1)` prints the process’s auxiliary vector:

```text
$ pauxv $(pgrep sshd)
2887: sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
AT_SYSINFO_EHDR 0x00007fca98be9000
AT_MINSIGSTKSZ  0x0000000000000d30
AT_HWCAP        0x00000000178bfbff FPU | VME | DE | PSE | TSC | MSR | PAE | MCE | CX8 | APIC | SEP | MTRR | PGE | MCA | CMOV | PAT | PSE36 | CLFSH | MMX | FXSR | SSE | SSE2 | HTT
AT_PAGESZ       0x0000000000001000
AT_CLKTCK       0x0000000000000064
AT_PHDR         0x00005626e0d9a040
AT_PHENT        0x0000000000000038
AT_PHNUM        0x000000000000000d
AT_BASE         0x00007fca98beb000
AT_FLAGS        0x0000000000000000
AT_ENTRY        0x00005626e0d9fc90
AT_UID          0x0000000000000000 0(root)
AT_EUID         0x0000000000000000 0(root)
AT_GID          0x0000000000000000 0(root)
AT_EGID         0x0000000000000000 0(root)
AT_SECURE       0x0000000000000000
AT_RANDOM       0x00007ffd97c8b079
AT_HWCAP2       0x0000000000000002 FSGSBASE
AT_EXECFN       0x00007ffd97c8cfe9 /usr/bin/sshd
AT_PLATFORM     0x00007ffd97c8b089
AT_RSEQ_FEATURE_SIZE 0x000000000000001c
AT_RSEQ_ALIGN   0x0000000000000020
```

`psig(1)` shows what signals a process is catching:

```text
$ psig 1
1: /usr/lib/systemd/systemd --switched-root --system --deserialize=48
HUP       blocked,default
INT       blocked,default
QUIT      caught
ILL       caught
TRAP      default
ABRT      caught
BUS       caught
FPE       caught
KILL      default
USR1      blocked,default
SEGV      caught
USR2      blocked,default
PIPE      ignored
ALRM      default
TERM      blocked,default
STKFLT    default
CLD       blocked,default
CONT      default
STOP      default
TSTP      default
TTIN      default
TTOU      default
URG       default
XCPU      default
XFSZ      default
VTALRM    default
PROF      default
WINCH     blocked,default
POLL      default
PWR       blocked,default
SYS       default
SIG32     default
SIG33     default
```

## `ptrace(2)` Permissions

`pstack(1)` attaches to target processes using the `ptrace(2)` system call.
Some distributions, notably Ubuntu, ship with the Yama Linux Security Module
enabled and `kernel.yama.ptrace_scope` set to `1` by default. This restricts
`ptrace(2)` to parent-child relationships only, meaning `pstack` cannot attach
to arbitrary same-user processes unless it is run as root.

You can check the current setting with:

```shell
cat /proc/sys/kernel/yama/ptrace_scope
```

The values are:

| Value | Meaning                                                                    |
| ----- | -------------------------------------------------------------------------- |
| 0     | Classic `ptrace(2)` permissions (any process can trace same-uid processes) |
| 1     | Restricted to parent-child relationships only                              |
| 2     | Admin-only (`CAP_SYS_PTRACE` required)                                     |
| 3     | No `ptrace(2)` allowed at all                                              |

To allow `pstack(1)` to trace same-user processes without root, set the classic
behavior:

```shell
sudo sysctl kernel.yama.ptrace_scope=0
```

Alternatively, simply run `pstack(1)` with `sudo(1)`.

Fedora ships with `ptrace_scope` set to `0` by default, so `pstack(1)` works
against same-user processes without any additional configuration.

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
| [`plimit(1)`](https://illumos.org/man/1/plimit)               | Get or set process resource limits                    | ✅ Implemented (read-only)   |
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
| [`ptime(1)`](https://illumos.org/man/1/ptime)                 | Time a process using microstate accounting            | ✅ Implemented               |
| [`ptree(1)`](https://illumos.org/man/1/ptree)                 | Print process trees                                   | ✅ Implemented               |
| [`pwait(1)`](https://illumos.org/man/1/pwait)                 | Wait for processes to terminate                       | ✅ Implemented               |
| [`pwdx(1)`](https://illumos.org/man/1/pwdx)                   | Print the current working directory of the process    | ➡️ See `procps-ng`           |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on contributing.

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.
