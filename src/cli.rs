use clap::Parser;

#[derive(Parser)]
#[command(
    name = "pargs",
    version,
    about = "Print process arguments",
    long_about = "Examine a target process and print arguments, environment variables and values, \
or the process auxiliary vector.",
    trailing_var_arg = true
)]
pub struct PargsCli {
    /// Display arguments as command line
    ///
    /// Display the arguments as a single command line. Print the command line in
    /// a manner suitable for interpretation by /bin/sh.
    #[arg(short = 'l')]
    pub line: bool,

    /// Print process arguments
    ///
    /// Print process arguments as contained in /proc/pid/cmdline (default).
    #[arg(short = 'a', long = "args")]
    pub args: bool,

    /// Print process environment variables
    ///
    /// Print process environment variables and values as contained in
    /// /proc/pid/environ.
    #[arg(short = 'e', long = "env")]
    pub env: bool,

    /// Print process auxiliary vector
    ///
    /// Print the process auxiliary vector as contained in /proc/pid/auxv.
    #[arg(short = 'x', long = "auxv")]
    pub auxv: bool,

    /// Process ID (PID)
    ///
    /// A list of process IDs (PIDs)
    #[arg(value_name = "PID", required = true, num_args = 1.., value_parser = clap::value_parser!(u64).range(1..))]
    pub pid: Vec<u64>,
}

#[derive(Parser)]
#[command(
    name = "penv",
    version,
    about = "Print process environment variables",
    long_about = "Examine a target process and print environment variables and values.",
    trailing_var_arg = true
)]
pub struct PenvCli {
    /// Process ID (PID)
    ///
    /// A list of process IDs (PIDs)
    #[arg(value_name = "PID", required = true, num_args = 1.., value_parser = clap::value_parser!(u64).range(1..))]
    pub pid: Vec<u64>,
}

#[derive(Parser)]
#[command(
    name = "pfiles",
    version,
    about = "Print information for all open files in each process",
    long_about = "Print fstat(2) and fcntl(2) information for all open files in each process. \
For network endpoints, provide local address information and peer address information when \
connected. For sockets, provide the socket type, socket options, and send and receive buffer \
sizes. Also print a path to the file when that information is available from /proc/pid/fd. \
Do not assume this is the same name used to open the file. See proc(5) for more information.",
    trailing_var_arg = true
)]
pub struct PfilesCli {
    /// Set non-verbose mode
    ///
    /// Set non-verbose mode. Do not display verbose information for each file
    /// descriptor. Instead, limit output to the information that the process would retrieve by
    /// applying fstat(2) to each of its file descriptors.
    #[arg(short = 'n')]
    pub non_verbose: bool,

    /// Process ID (PID)
    ///
    /// A list of process IDs (PIDs)
    #[arg(value_name = "PID", required = true, num_args = 1.., value_parser = clap::value_parser!(u64).range(1..))]
    pub pid: Vec<u64>,
}

#[derive(Parser)]
#[command(
    name = "psig",
    version,
    about = "Print process signal actions",
    long_about = "Print the signal actions and handlers of each process.",
    trailing_var_arg = true
)]
pub struct PsigCli {
    /// Process ID (PID)
    ///
    /// A list of process IDs (PIDs)
    #[arg(value_name = "PID", required = true, num_args = 1.., value_parser = clap::value_parser!(u64).range(1..))]
    pub pid: Vec<u64>,
}

#[derive(Parser)]
#[command(
    name = "pflags",
    version,
    about = "Print process status flags",
    long_about = "Print the process status flags, the pending and held signals, \
and other status information for each process or specified threads in each process. \
If a thread has a non-empty signal mask, it will be printed.",
    trailing_var_arg = true
)]
pub struct PflagsCli {
    /// Process ID, optionally with thread ID
    ///
    /// A list of process IDs, optionally qualified with a thread ID
    /// (e.g. 1234 or 1234/5)
    #[arg(value_name = "PID[/TID]", required = true, num_args = 1..)]
    pub pid: Vec<String>,
}

#[derive(Parser)]
#[command(
    name = "ptree",
    version,
    about = "Print process trees",
    long_about = "Print process trees containing the specified pids or users, with child processes \
indented from their respective parent processes. Treat an argument of all digits as a process \
ID (PID); otherwise, treat it as a user login name. Default to all processes."
)]
pub struct PtreeCli {
    /// Include children of PID 0
    ///
    /// All. Print all processes, including children of process ID 0.
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Process ID (PID) or username
    ///
    /// A list of process IDs (PIDs) or usernames
    #[arg(value_name = "pid|user", num_args = 0..)]
    pub target: Vec<String>,
}
