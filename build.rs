use roff::{bold, roman, Roff};
use std::fs;
use std::path::Path;

fn render_man_page(
    name: &str,
    about: &str,
    description: &str,
    synopsis: &str,
    options: &[(&str, &str)],
    out_dir: &Path,
) {
    let version = env!("CARGO_PKG_VERSION");
    let upper_name = name.to_uppercase();
    let date_version = format!("{name} {version}");
    let mut roff = Roff::default();
    roff.control("TH", [upper_name.as_str(), "1", date_version.as_str()]);
    roff.control("SH", ["NAME"]);
    roff.text([roman(format!("{name} - {about}"))]);
    roff.control("SH", ["SYNOPSIS"]);
    roff.text([bold(name), roman(format!(" {synopsis}"))]);
    roff.control("SH", ["DESCRIPTION"]);
    roff.text([roman(description)]);
    if !options.is_empty() {
        roff.control("SH", ["OPTIONS"]);
        for (flag, help) in options {
            roff.control("TP", []);
            roff.text([bold(*flag)]);
            roff.text([roman(*help)]);
        }
    }
    fs::write(out_dir.join(format!("{name}.1")), roff.to_roff()).unwrap();
}

fn main() {
    let out_dir = Path::new("target/man");
    fs::create_dir_all(out_dir).unwrap();

    render_man_page(
        "pargs",
        "Print process arguments",
        "Examine a target process and print arguments, environment variables and values, \
         or the process auxiliary vector.",
        "[-l] [-a|--args] [-e|--env] [-x|--auxv] PID...",
        &[
            (
                "-l",
                "Display the arguments as a single command line, suitable for \
                 interpretation by /bin/sh.",
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
        out_dir,
    );

    render_man_page(
        "penv",
        "Print process environment variables",
        "Examine a target process and print environment variables and values.",
        "PID...",
        &[],
        out_dir,
    );

    render_man_page(
        "pfiles",
        "Print information for all open files in each process",
        "Print fstat(2) and fcntl(2) information for all open files in each process. \
         For network endpoints, provide local address information and peer address \
         information when connected. For sockets, provide the socket type, socket options, \
         and send and receive buffer sizes. Also print a path to the file when that \
         information is available from /proc/pid/fd. Do not assume this is the same name \
         used to open the file. See proc(5) for more information.",
        "[-n] PID...",
        &[(
            "-n",
            "Set non-verbose mode. Do not display verbose information for each file \
             descriptor. Instead, limit output to the information that the process would \
             retrieve by applying fstat(2) to each of its file descriptors.",
        )],
        out_dir,
    );

    render_man_page(
        "psig",
        "Print process signal actions",
        "Print the signal actions and handlers of each process.",
        "PID...",
        &[],
        out_dir,
    );

    render_man_page(
        "pflags",
        "Print process status flags",
        "Print the process status flags, the pending and held signals, and other status \
         information for each process or specified threads in each process. If a thread \
         has a non-empty signal mask, it will be printed.",
        "PID[/TID]...",
        &[],
        out_dir,
    );

    render_man_page(
        "pstop",
        "Stop processes with SIGSTOP",
        "Stop each process by sending SIGSTOP.",
        "PID...",
        &[],
        out_dir,
    );

    render_man_page(
        "prun",
        "Set stopped processes running with SIGCONT",
        "Set running each process by sending SIGCONT (the inverse of pstop).",
        "PID...",
        &[],
        out_dir,
    );

    render_man_page(
        "pwait",
        "Wait for processes to terminate",
        "Wait for all of the specified processes to terminate.",
        "[-v] PID...",
        &[("-v", "Verbose. Reports terminations to standard output.")],
        out_dir,
    );

    render_man_page(
        "ptree",
        "Print process trees",
        "Print process trees containing the specified pids or users, with child processes \
         indented from their respective parent processes. Treat an argument of all digits \
         as a process ID (PID); otherwise, treat it as a user login name. Default to all \
         processes.",
        "[-a|--all] [pid|user]...",
        &[(
            "-a, --all",
            "All. Print all processes, including children of process ID 0.",
        )],
        out_dir,
    );

    println!("cargo:rerun-if-changed=build.rs");
}
