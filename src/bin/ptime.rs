//
//   Copyright (c) 2026 Basil Crow
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

use std::ffi::CString;
use std::process;

use nix::errno::Errno;
use nix::sys::signal::sigprocmask;
use nix::sys::signal::SigHandler;
use nix::sys::signal::SigSet;
use nix::sys::signal::SigmaskHow;
use nix::sys::signal::Signal;
use nix::sys::signal::{self};
use nix::sys::wait::WaitStatus;
use nix::time::clock_gettime;
use nix::time::ClockId;
use nix::unistd::execvp;
use nix::unistd::fork;
use nix::unistd::sysconf;
use nix::unistd::ForkResult;
use nix::unistd::Pid;
use nix::unistd::SysconfVar;
use ptools::proc::ProcHandle;

enum Args {
    Run { command: String, argv: Vec<CString> },
    Snapshot { pids: Vec<u64> },
}

fn print_usage() {
    eprintln!("Usage: ptime command [arg]...");
    eprintln!("       ptime -p pidlist");
    eprintln!("Time a command, or display timing statistics for existing processes.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p pidlist       Display timing statistics for the specified PIDs");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut command = None;
    let mut argv_os = Vec::new();
    let mut parser = lexopt::Parser::from_env();
    let mut snapshot_mode = false;
    let mut pids = Vec::new();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("ptime: {e}");
        process::exit(1);
    }) {
        match arg {
            Short('h') | Long("help") if command.is_none() && !snapshot_mode => {
                print_usage();
                process::exit(0);
            }
            Short('V') | Long("version") if command.is_none() && !snapshot_mode => {
                println!("ptime {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            Short('p') if command.is_none() && !snapshot_mode => {
                snapshot_mode = true;
            }
            Value(val) if snapshot_mode => {
                let s = val.to_string_lossy();
                for part in s.split([',', ' ', '\t']) {
                    if part.is_empty() {
                        continue;
                    }
                    match part.parse::<u64>() {
                        Ok(pid) if pid >= 1 && pid <= i32::MAX as u64 => pids.push(pid),
                        _ => {
                            eprintln!("ptime: invalid PID '{part}'");
                            process::exit(1);
                        }
                    }
                }
            }
            Value(val) => {
                command = Some(val.to_string_lossy().into_owned());
                argv_os.push(val);
                // Collect remaining args verbatim -- they belong to the child.
                if let Ok(raw) = parser.raw_args() {
                    argv_os.extend(raw);
                }
            }
            _ => {
                eprintln!("ptime: unexpected argument: {arg:?}");
                process::exit(1);
            }
        }
    }

    if snapshot_mode {
        if pids.is_empty() {
            eprintln!("ptime: at least one PID required with -p");
            process::exit(1);
        }
        return Args::Snapshot { pids };
    }

    let command = match command {
        Some(c) => c,
        None => {
            eprintln!("ptime: command required");
            process::exit(1);
        }
    };

    let argv: Vec<CString> = argv_os
        .into_iter()
        .map(|os| {
            CString::new(os.into_encoded_bytes()).unwrap_or_else(|_| {
                eprintln!("ptime: argument contains interior NUL byte");
                process::exit(1);
            })
        })
        .collect();

    Args::Run { command, argv }
}

/// Format nanoseconds as a human-readable time string.
///
/// `precision` controls the number of fractional digits (1-9).
///
/// - `< 60s`:  `S.fff`
/// - `< 1h`:   `M:SS.fff`
/// - `>= 1h`:  `H:MM:SS.fff`
fn fmt_ns(ns: u128, precision: u32) -> String {
    let divisor = 10u128.pow(9 - precision);
    // Round to the requested precision instead of truncating.
    let rounded_ns = ns.saturating_add(divisor / 2) / divisor * divisor;
    let total_secs = rounded_ns / 1_000_000_000;
    let frac = rounded_ns % 1_000_000_000;
    let scaled = frac / divisor;

    if total_secs < 60 {
        format!("{}.{:0>w$}", total_secs, scaled, w = precision as usize)
    } else if total_secs < 3600 {
        let m = total_secs / 60;
        let s = total_secs % 60;
        format!("{}:{:02}.{:0>w$}", m, s, scaled, w = precision as usize)
    } else {
        let h = total_secs / 3600;
        let m = (total_secs % 3600) / 60;
        let s = total_secs % 60;
        format!(
            "{}:{:02}:{:02}.{:0>w$}",
            h,
            m,
            s,
            scaled,
            w = precision as usize
        )
    }
}

/// Determine the display precision for clock-tick-based values.
///
/// Given `clk_tck` (e.g. 100 for a 10ms tick), returns the number of
/// meaningful fractional digits when the tick count is converted to seconds.
///
/// For tick rates with terminating decimal fractions (factors only 2 and 5),
/// return the exact terminating precision, capped at nanoseconds.
/// For non-terminating fractions (e.g. HZ=300), return a bounded precision
/// based on the order of magnitude of one tick so we do not imply nanosecond
/// precision from tick counters.
fn tick_precision(clk_tck: u128) -> u32 {
    if clk_tck == 0 {
        return 0;
    }

    let mut d = clk_tck;
    let mut twos = 0u32;
    let mut fives = 0u32;

    while d.is_multiple_of(2) {
        twos += 1;
        d /= 2;
    }
    while d.is_multiple_of(5) {
        fives += 1;
        d /= 5;
    }

    // 1/clk_tck is a terminating decimal only if the denominator has no
    // prime factors other than 2 and 5.
    if d == 1 {
        return twos.max(fives).min(9);
    }

    // Non-terminating decimal tick size: choose a practical precision based
    // on tick order of magnitude, capped to nanoseconds.
    let mut digits = 0u32;
    let mut p10 = 1u128;
    while p10 < clk_tck && digits < 9 {
        digits += 1;
        p10 *= 10;
    }
    digits
}

fn pct(part: u128, total: u128) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64 * 100.0
    }
}

struct TimingLine {
    indent: usize,
    label: &'static str,
    time_str: String,
    pct: Option<f64>,
}

fn print_timings(col: usize, lines: &[TimingLine]) -> bool {
    let has_low_precision = lines.iter().any(|l| l.time_str.ends_with('*'));

    // Align on the decimal point so fractional digits of different
    // precisions don't shift the dot column.
    let max_int_w = lines
        .iter()
        .map(|l| l.time_str.find('.').unwrap_or(l.time_str.len()))
        .max()
        .unwrap_or(0);
    let max_time_w = lines
        .iter()
        .map(|l| {
            let dot = l.time_str.find('.').unwrap_or(l.time_str.len());
            (max_int_w - dot) + l.time_str.len()
        })
        .max()
        .unwrap_or(0);
    for line in lines {
        let dot = line.time_str.find('.').unwrap_or(line.time_str.len());
        let time = format!("{:>w$}{}", "", line.time_str, w = max_int_w - dot);
        let prefix = format!("{:indent$}{}", "", line.label, indent = line.indent);
        if let Some(p) = line.pct {
            eprintln!("{prefix:<col$} {time:<max_time_w$}  {p:>5.1}%");
        } else {
            eprintln!("{prefix:<col$} {time}");
        }
    }

    has_low_precision
}

/// Thin wrapper around `libc::wait4` returning nix types.
///
/// Combines `waitpid` and `getrusage(RUSAGE_CHILDREN)` into a single
/// syscall so the resource usage is atomically associated with the
/// reaped child.
fn wait4(pid: Pid, options: libc::c_int) -> Result<(WaitStatus, libc::rusage), Errno> {
    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::wait4(pid.as_raw(), &mut status, options, &mut rusage) };
    match res {
        -1 => Err(Errno::last()),
        0 => Ok((WaitStatus::StillAlive, rusage)),
        pid => {
            let ws = WaitStatus::from_raw(Pid::from_raw(pid), status).map_err(|_| Errno::EINVAL)?;
            Ok((ws, rusage))
        }
    }
}

fn run_command(command: String, argv: Vec<CString>) {
    // Block SIGCHLD before fork so the child becomes a zombie (preserving
    // /proc/<pid>) until we explicitly reap it.
    let mut sigchld_set = SigSet::empty();
    sigchld_set.add(Signal::SIGCHLD);
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&sigchld_set), None).unwrap_or_else(|e| {
        eprintln!("ptime: sigprocmask: {e}");
        process::exit(1);
    });

    // Ignore SIGINT/SIGQUIT/SIGTERM before fork so there is no window
    // where a signal could kill the parent between fork and the ignore
    // calls.  The child resets to defaults before exec.
    unsafe {
        signal::signal(Signal::SIGINT, SigHandler::SigIgn).ok();
        signal::signal(Signal::SIGQUIT, SigHandler::SigIgn).ok();
        signal::signal(Signal::SIGTERM, SigHandler::SigIgn).ok();
    }

    // Capture wall-clock time immediately before fork so that
    // real reflects the child's lifetime, not our setup.
    let start = clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap_or_else(|e| {
        eprintln!("ptime: clock_gettime: {e}");
        process::exit(1);
    });

    // SAFETY: We are single-threaded at this point and exec immediately in
    // the child, so fork is safe.
    let child_pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Restore default signal dispositions so the child behaves
            // normally, then unblock SIGCHLD (exec preserves the mask).
            unsafe {
                signal::signal(Signal::SIGINT, SigHandler::SigDfl).ok();
                signal::signal(Signal::SIGQUIT, SigHandler::SigDfl).ok();
                signal::signal(Signal::SIGTERM, SigHandler::SigDfl).ok();
            }
            if let Err(e) = sigprocmask(SigmaskHow::SIG_UNBLOCK, Some(&sigchld_set), None) {
                eprintln!("ptime: sigprocmask: {e}");
                unsafe { libc::_exit(1) };
            }
            let _ = execvp(&argv[0], &argv);
            let err = Errno::last();
            eprintln!("ptime: cannot execute {command}: {err}");
            unsafe { libc::_exit(if err == Errno::ENOENT { 127 } else { 126 }) };
        }
        Ok(ForkResult::Parent { child }) => child,
        Err(e) => {
            eprintln!("ptime: fork: {e}");
            process::exit(1);
        }
    };

    // Wait for SIGCHLD, read schedstat from the zombie, then reap.
    // Loop in case the child is merely stopped (SIGCHLD is also sent
    // for stop/continue events).
    let (status, run_time_ns, wait_time_ns, rusage, end) = loop {
        if let Err(e) = sigchld_set.wait() {
            if e == Errno::EINTR {
                continue;
            }
            eprintln!("ptime: sigwait: {e}");
            process::exit(1);
        }

        // Capture wall-clock time immediately after SIGCHLD so that
        // real reflects the child's lifetime, not our bookkeeping.
        let end = clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap_or_else(|e| {
            eprintln!("ptime: clock_gettime: {e}");
            process::exit(1);
        });

        // Read schedstat while the zombie still has a /proc entry.
        let handle = ProcHandle::from_pid(child_pid.as_raw() as u64);
        let run = handle.run_time_ns().ok();
        let wait = handle.wait_time_ns().ok();

        // Reap with wait4 to get status + rusage atomically.
        // Use WNOHANG so we can loop back if this SIGCHLD was for a
        // non-terminal state change rather than process exit.
        match wait4(child_pid, libc::WNOHANG) {
            Ok((WaitStatus::StillAlive, _))
            | Ok((WaitStatus::Stopped(..), _))
            | Ok((WaitStatus::Continued(..), _)) => continue,
            Ok((s, ru)) => break (s, run, wait, ru, end),
            Err(e) => {
                eprintln!("ptime: wait4: {e}");
                process::exit(1);
            }
        }
    };

    let (exit_code, death_sig) = match status {
        WaitStatus::Exited(_, code) => (code, None),
        WaitStatus::Signaled(_, sig, _) => (128 + sig as i32, Some(sig)),
        _ => (1, None),
    };

    // Skip timing output if the command could not be executed.
    if exit_code == 126 || exit_code == 127 {
        process::exit(exit_code);
    }

    let real_ns = ((end.tv_sec() - start.tv_sec()) as i128 * 1_000_000_000
        + (end.tv_nsec() - start.tv_nsec()) as i128) as u128;

    let user_ns =
        rusage.ru_utime.tv_sec as u128 * 1_000_000_000 + rusage.ru_utime.tv_usec as u128 * 1_000;
    let sys_ns =
        rusage.ru_stime.tv_sec as u128 * 1_000_000_000 + rusage.ru_stime.tv_usec as u128 * 1_000;

    if let (Some(cpu_ns), Some(lat_ns)) = (run_time_ns, wait_time_ns) {
        let cpu_ns = cpu_ns as u128;
        let lat_ns = lat_ns as u128;
        let slp_ns = real_ns.saturating_sub(cpu_ns).saturating_sub(lat_ns);
        let has_low_precision = print_timings(
            8,
            &[
                TimingLine {
                    indent: 0,
                    label: "real",
                    time_str: fmt_ns(real_ns, 9),
                    pct: Some(pct(real_ns, real_ns)),
                },
                TimingLine {
                    indent: 2,
                    label: "cpu",
                    time_str: fmt_ns(cpu_ns, 9),
                    pct: Some(pct(cpu_ns, real_ns)),
                },
                TimingLine {
                    indent: 4,
                    label: "user",
                    time_str: format!("{}*", fmt_ns(user_ns, 6)),
                    pct: None,
                },
                TimingLine {
                    indent: 4,
                    label: "sys",
                    time_str: format!("{}*", fmt_ns(sys_ns, 6)),
                    pct: None,
                },
                TimingLine {
                    indent: 2,
                    label: "lat",
                    time_str: fmt_ns(lat_ns, 9),
                    pct: Some(pct(lat_ns, real_ns)),
                },
                TimingLine {
                    indent: 2,
                    label: "slp",
                    time_str: fmt_ns(slp_ns, 9),
                    pct: Some(pct(slp_ns, real_ns)),
                },
            ],
        );
        if has_low_precision {
            eprintln!();
            eprintln!("* Lower-precision source");
        }
    } else {
        let has_low_precision = print_timings(
            6,
            &[
                TimingLine {
                    indent: 0,
                    label: "real",
                    time_str: fmt_ns(real_ns, 9),
                    pct: None,
                },
                TimingLine {
                    indent: 2,
                    label: "user",
                    time_str: format!("{}*", fmt_ns(user_ns, 6)),
                    pct: None,
                },
                TimingLine {
                    indent: 2,
                    label: "sys",
                    time_str: format!("{}*", fmt_ns(sys_ns, 6)),
                    pct: None,
                },
            ],
        );
        if has_low_precision {
            eprintln!();
            eprintln!("* Lower-precision source");
        }
    }

    // Re-raise the death signal so the shell sees a proper signal death.
    if let Some(sig) = death_sig {
        unsafe {
            signal::signal(sig, SigHandler::SigDfl).ok();
        }
        signal::raise(sig).ok();
    }

    process::exit(exit_code);
}

fn snapshot(pids: Vec<u64>) {
    let clk_tck = match sysconf(SysconfVar::CLK_TCK) {
        Ok(Some(val)) => val as u128,
        _ => {
            eprintln!("ptime: failed to get CLK_TCK");
            process::exit(1);
        }
    };

    let boottime = match clock_gettime(ClockId::CLOCK_BOOTTIME) {
        Ok(ts) => ts.tv_sec() as u128 * 1_000_000_000 + ts.tv_nsec() as u128,
        Err(e) => {
            eprintln!("ptime: clock_gettime: {e}");
            process::exit(1);
        }
    };

    let mut failed = false;
    let mut show_star_legend = false;

    for (i, pid) in pids.iter().enumerate() {
        if i > 0 {
            eprintln!();
        }

        let handle = ProcHandle::from_pid(*pid);

        let starttime = match handle.starttime() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ptime: cannot examine {pid}: {e}");
                failed = true;
                continue;
            }
        };

        let (user_ns, sys_ns, time_prec) = match (handle.utime_us(), handle.stime_us()) {
            (Ok(u), Ok(s)) => (u as u128 * 1_000, s as u128 * 1_000, 6),
            _ => {
                let utime = match handle.utime() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("ptime: cannot examine {pid}: {e}");
                        failed = true;
                        continue;
                    }
                };
                let stime = match handle.stime() {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("ptime: cannot examine {pid}: {e}");
                        failed = true;
                        continue;
                    }
                };
                (
                    utime as u128 * 1_000_000_000 / clk_tck,
                    stime as u128 * 1_000_000_000 / clk_tck,
                    tick_precision(clk_tck),
                )
            }
        };

        let run_time_ns = handle.run_time_ns().ok();
        let wait_time_ns = handle.wait_time_ns().ok();

        ptools::display::print_proc_summary_from(&handle);

        let real_ns = boottime - (starttime as u128 * 1_000_000_000 / clk_tck);

        let prec = tick_precision(clk_tck);

        if let (Some(cpu_ns), Some(lat_ns)) = (run_time_ns, wait_time_ns) {
            let cpu_ns = cpu_ns as u128;
            let lat_ns = lat_ns as u128;
            let slp_ns = real_ns.saturating_sub(cpu_ns).saturating_sub(lat_ns);
            show_star_legend |= print_timings(
                8,
                &[
                    TimingLine {
                        indent: 0,
                        label: "real",
                        time_str: format!("{}*", fmt_ns(real_ns, prec)),
                        pct: Some(pct(real_ns, real_ns)),
                    },
                    TimingLine {
                        indent: 2,
                        label: "cpu",
                        time_str: fmt_ns(cpu_ns, 9),
                        pct: Some(pct(cpu_ns, real_ns)),
                    },
                    TimingLine {
                        indent: 4,
                        label: "user",
                        time_str: format!("{}*", fmt_ns(user_ns, time_prec)),
                        pct: None,
                    },
                    TimingLine {
                        indent: 4,
                        label: "sys",
                        time_str: format!("{}*", fmt_ns(sys_ns, time_prec)),
                        pct: None,
                    },
                    TimingLine {
                        indent: 2,
                        label: "lat",
                        time_str: fmt_ns(lat_ns, 9),
                        pct: Some(pct(lat_ns, real_ns)),
                    },
                    TimingLine {
                        indent: 2,
                        label: "slp",
                        time_str: format!("{}*", fmt_ns(slp_ns, prec)),
                        pct: Some(pct(slp_ns, real_ns)),
                    },
                ],
            );
        } else {
            show_star_legend |= print_timings(
                6,
                &[
                    TimingLine {
                        indent: 0,
                        label: "real",
                        time_str: format!("{}*", fmt_ns(real_ns, prec)),
                        pct: None,
                    },
                    TimingLine {
                        indent: 2,
                        label: "user",
                        time_str: format!("{}*", fmt_ns(user_ns, time_prec)),
                        pct: None,
                    },
                    TimingLine {
                        indent: 2,
                        label: "sys",
                        time_str: format!("{}*", fmt_ns(sys_ns, time_prec)),
                        pct: None,
                    },
                ],
            );
        }
    }

    if show_star_legend {
        eprintln!();
        eprintln!("* Lower-precision source");
    }

    if failed {
        process::exit(1);
    }
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    match args {
        Args::Run { command, argv } => run_command(command, argv),
        Args::Snapshot { pids } => snapshot(pids),
    }
}
