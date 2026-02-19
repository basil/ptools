use roff::{bold, roman, Roff};
use std::fs;
use std::path::Path;

struct Example<'a> {
    title: &'a str,
    description: &'a str,
    code: &'a str,
}

struct ManPage<'a> {
    name: &'a str,
    about: &'a str,
    description: &'a str,
    synopsis: &'a str,
    options: &'a [(&'a str, &'a str)],
    examples: &'a [Example<'a>],
    exit_status: &'a str,
    files: &'a str,
    see_also: &'a str,
    warnings: &'a str,
}

const DEFAULT_EXIT_STATUS: &str =
    "0 on success, non-zero if an error occurs (such as no such process, \
     permission denied, or invalid option).";

const DEFAULT_FILES: &str = "/proc/pid/*\tProcess information and control files.";

fn render_man_page(page: &ManPage, out_dir: &Path) {
    let version = env!("CARGO_PKG_VERSION");
    let upper_name = page.name.to_uppercase();
    let date_version = format!("{} {}", page.name, version);
    let mut roff = Roff::default();
    roff.control("TH", [upper_name.as_str(), "1", date_version.as_str()]);
    roff.control("SH", ["NAME"]);
    roff.text([roman(format!("{} - {}", page.name, page.about))]);
    roff.control("SH", ["SYNOPSIS"]);
    roff.text([bold(page.name), roman(format!(" {}", page.synopsis))]);
    roff.control("SH", ["DESCRIPTION"]);
    roff.text([roman(page.description)]);
    if !page.options.is_empty() {
        roff.control("SH", ["OPTIONS"]);
        for (flag, help) in page.options {
            roff.control("TP", []);
            roff.text([bold(*flag)]);
            roff.text([roman(*help)]);
        }
    }
    if !page.examples.is_empty() {
        roff.control("SH", ["EXAMPLES"]);
        for example in page.examples {
            roff.text([bold(example.title)]);
            roff.text([roman(example.description)]);
            roff.control("sp", [] as [&str; 0]);
            roff.control("nf", [] as [&str; 0]);
            roff.control("RS", ["4"]);
            for line in example.code.lines() {
                roff.text([roman(line)]);
            }
            roff.control("RE", [] as [&str; 0]);
            roff.control("fi", [] as [&str; 0]);
        }
    }
    if !page.exit_status.is_empty() {
        roff.control("SH", ["EXIT STATUS"]);
        roff.text([roman(page.exit_status)]);
    }
    if !page.files.is_empty() {
        roff.control("SH", ["FILES"]);
        for line in page.files.lines() {
            if let Some((path, desc)) = line.split_once('\t') {
                roff.control("TP", []);
                roff.text([roman(path)]);
                roff.text([roman(desc)]);
            } else {
                roff.text([roman(line)]);
            }
        }
    }
    if !page.warnings.is_empty() {
        roff.control("SH", ["WARNINGS"]);
        roff.text([roman(page.warnings)]);
    }
    if !page.see_also.is_empty() {
        roff.control("SH", ["SEE ALSO"]);
        roff.text([roman(page.see_also)]);
    }
    fs::write(out_dir.join(format!("{}.1", page.name)), roff.to_roff()).unwrap();
}

fn main() {
    let out_dir = Path::new("target/man");
    fs::create_dir_all(out_dir).unwrap();

    render_man_page(
        &ManPage {
            name: "pargs",
            about: "print process arguments",
            description: "Examine a target process and print arguments, environment variables \
                          and values, or the process auxiliary vector. \
                          The pauxv command is equivalent to running pargs(1) with the -x option. \
                          The penv command is equivalent to running pargs(1) with the -e option.",
            synopsis: "[-l] [-a|--args] [-e|--env] [-x|--auxv] PID...",
            options: &[
                (
                    "-l",
                    "Display the arguments as a single command line. The command line is \
                     printed in a manner suitable for interpretation by /bin/sh.",
                ),
                (
                    "-a, --args",
                    "Print process arguments as contained in /proc/pid/cmdline (default).",
                ),
                (
                    "-e, --env",
                    "Print process environment variables and values as contained in \
                     /proc/pid/environ.",
                ),
                (
                    "-x, --auxv",
                    "Print the process auxiliary vector as contained in /proc/pid/auxv.",
                ),
            ],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "pauxv(1), penv(1), pflags(1), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "pauxv",
            about: "print process auxiliary vector",
            description: "Examine a target process and print the auxiliary vector. \
                          This command is equivalent to running pargs(1) with the -x option.",
            synopsis: "PID...",
            options: &[],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "pargs(1), penv(1), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "penv",
            about: "print process environment variables",
            description: "Examine a target process and print environment variables and values. \
                          This command is equivalent to running pargs(1) with the -e option.",
            synopsis: "PID...",
            options: &[],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "pargs(1), pauxv(1), environ(7), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "pfiles",
            about: "report open file information",
            description: "Print fstat(2) and fcntl(2) information for all open files in each \
                          process. For network endpoints, provide local address information and \
                          peer address information when connected. For sockets, provide the \
                          socket type, socket options, and send and receive buffer sizes. Also \
                          print a path to the file when that information is available from \
                          /proc/pid/fd. This is not necessarily the same name used to open the \
                          file. In addition, print the current soft and hard RLIMIT_NOFILE \
                          limits and the process umask. See proc(5) for more information.",
            synopsis: "[-n] PID...",
            options: &[(
                "-n",
                "Set non-verbose mode. Do not display verbose information for each file \
                 descriptor. Instead, limit output to the information that the process \
                 would retrieve by applying fstat(2) to each of its file descriptors.",
            )],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "fstat(2), fcntl(2), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "psig",
            about: "list process signal actions",
            description: "List the signal actions and handlers of each process. For each \
                          signal, print whether the signal is caught, ignored, or handled by \
                          default, and whether the signal is blocked or pending. Real-time \
                          signals (SIGRTMIN through SIGRTMAX) are also displayed. Use \
                          pflags(1) to see more information about currently pending signals \
                          and signal masks.",
            synopsis: "PID...",
            options: &[],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "kill(1), pflags(1), signal(7), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "pflags",
            about: "print process status flags",
            description: "Print the data model, process flags, pending and held signals, \
                          and other status information for each process or specified threads \
                          in each process. For each thread, print its state, current system \
                          call (if any), and signal mask. If a thread has a non-empty signal \
                          mask, it will be printed.",
            synopsis: "PID[/TID]...",
            options: &[],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "psig(1), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "pstop",
            about: "stop processes",
            description: "Stop each process by sending SIGSTOP.",
            synopsis: "PID...",
            options: &[],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "prun(1), kill(1), proc(5)",
            warnings: "A process can do nothing while it is stopped. Stopping a heavily \
                       used process in a production environment, even for a short amount of \
                       time, can cause severe bottlenecks and even hangs of dependent \
                       processes, causing them to be unavailable to users. Because of this, \
                       stopping a process in a production environment should be avoided.",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "prun",
            about: "set stopped processes running",
            description: "Set running each process by sending SIGCONT (the inverse of pstop(1)).",
            synopsis: "PID...",
            options: &[],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "pstop(1), kill(1), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "pwait",
            about: "wait for processes to terminate",
            description: "Wait for all of the specified processes to terminate. Unlike \
                          wait(1), the target processes do not need to be children of \
                          the calling process.",
            synopsis: "[-v] PID...",
            options: &[(
                "-v",
                "Verbose. Reports terminations to standard output. When the target \
                 process is a child of the calling process, the wait status is also \
                 displayed.",
            )],
            examples: &[],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "wait(1), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    render_man_page(
        &ManPage {
            name: "ptree",
            about: "print process trees",
            description: "Print process trees containing the specified pids or users, with \
                          child processes indented from their respective parent processes. An \
                          argument of all digits is taken to be a process ID; otherwise it is \
                          assumed to be a user login name. The default is all processes.",
            synopsis: "[-ag] [pid|user]...",
            options: &[
                (
                    "-a, --all",
                    "All. Print all processes, including children of process ID 0.",
                ),
                (
                    "-g, --graph",
                    "Use line drawing characters. If the current locale is a UTF-8 \
                     locale, the UTF-8 line drawing characters are used, otherwise \
                     ASCII line drawing characters are used.",
                ),
            ],
            examples: &[
                Example {
                    title: "Example 1 Using ptree",
                    description: "The following example prints the process tree \
                                  (including children of process 0) for processes \
                                  which match the command name ssh:",
                    code: "\
$ ptree -a `pgrep ssh`
        1  /sbin/init
          100909  /usr/bin/sshd
            569150  /usr/bin/sshd
              569157  /usr/bin/sshd
                569159  -bash
                  569171  bash
                    569173  /usr/bin/bash
                      569193  bash",
                },
                Example {
                    title: "Example 2",
                    description: "The following example prints the process tree \
                                  (including children of process 0) for processes \
                                  which match the command name ssh with ASCII line \
                                  drawing characters:",
                    code: "\
$ ptree -ag `pgrep ssh`
        1  /sbin/init
        `-100909  /usr/bin/sshd
          `-569150  /usr/bin/sshd
            `-569157  /usr/bin/sshd
              `-569159  -bash
                `-569171  bash
                  `-569173  /usr/bin/bash
                    `-569193  bash",
                },
            ],
            exit_status: DEFAULT_EXIT_STATUS,
            files: DEFAULT_FILES,
            see_also: "pargs(1), pgrep(1), ps(1), proc(5)",
            warnings: "",
        },
        out_dir,
    );

    println!("cargo:rerun-if-changed=build.rs");
}
