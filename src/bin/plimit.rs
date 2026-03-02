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

use std::process::exit;

use nix::sys::resource::Resource;
use ptools::model::limits::Limit;
use ptools::model::limits::LimitValue;
use ptools::proc::ProcHandle;

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnitMode {
    Default,
    Kbytes,
    Mbytes,
}

struct Args {
    unit_mode: UnitMode,
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: plimit [-km] [pid | core]...");
    eprintln!("Get process resource limits.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -k             Display file/memory sizes in kilobytes");
    eprintln!("  -m             Display file/memory sizes in megabytes");
    eprintln!("  -h, --help     Print help");
    eprintln!("  -V, --version  Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        unit_mode: UnitMode::Default,
        operands: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("plimit: {e}");
        exit(2);
    }) {
        match arg {
            Short('k') => {
                args.unit_mode = UnitMode::Kbytes;
            }
            Short('m') => {
                args.unit_mode = UnitMode::Mbytes;
            }
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("plimit {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Value(val) => {
                args.operands.push(val.to_string_lossy().into_owned());
            }
            _ => {
                eprintln!("plimit: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    if args.operands.is_empty() {
        eprintln!("plimit: at least one PID or core required");
        exit(2);
    }
    args
}

/// Return the display unit and whether to scale byte values.
fn display_unit(kernel_unit: &str, mode: UnitMode) -> &str {
    match (kernel_unit, mode) {
        ("bytes", UnitMode::Kbytes) => "kilobytes",
        ("bytes", UnitMode::Mbytes) => "megabytes",
        ("files", _) => "descriptors",
        ("us", _) => "microseconds",
        _ => kernel_unit,
    }
}

fn convert_value(val: LimitValue, kernel_unit: Option<&str>, mode: UnitMode) -> LimitValue {
    match val {
        LimitValue::Value(v) => LimitValue::Value(match (kernel_unit, mode) {
            (Some("bytes"), UnitMode::Kbytes) => v / 1024,
            (Some("bytes"), UnitMode::Mbytes) => v / 1_048_576,
            _ => v,
        }),
        LimitValue::Unlimited => LimitValue::Unlimited,
    }
}

fn display_name(resource: Resource) -> &'static str {
    match resource {
        Resource::RLIMIT_CPU => "time",
        Resource::RLIMIT_FSIZE => "file",
        Resource::RLIMIT_DATA => "data",
        Resource::RLIMIT_STACK => "stack",
        Resource::RLIMIT_CORE => "coredump",
        Resource::RLIMIT_NOFILE => "nofiles",
        Resource::RLIMIT_AS => "vmemory",
        Resource::RLIMIT_RSS => "rss",
        Resource::RLIMIT_NPROC => "nproc",
        Resource::RLIMIT_MEMLOCK => "memlock",
        Resource::RLIMIT_LOCKS => "locks",
        Resource::RLIMIT_SIGPENDING => "sigpending",
        Resource::RLIMIT_MSGQUEUE => "msgqueue",
        Resource::RLIMIT_NICE => "nice",
        Resource::RLIMIT_RTPRIO => "rtprio",
        Resource::RLIMIT_RTTIME => "rttime",
        _ => "unknown",
    }
}

fn format_row(resource: Resource, limit: &Limit, mode: UnitMode) -> (String, String, String) {
    let name = display_name(resource);
    let unit = limit.unit.as_deref().map(|u| display_unit(u, mode));
    let label = match unit {
        Some(u) if !u.is_empty() => format!("{name} ({u})"),
        _ => name.to_string(),
    };
    let soft = convert_value(limit.soft, limit.unit.as_deref(), mode);
    let hard = convert_value(limit.hard, limit.unit.as_deref(), mode);
    (label, soft.to_string(), hard.to_string())
}

fn print_limits(handle: &ProcHandle, mode: UnitMode) -> std::io::Result<()> {
    let limits = handle.resource_limits().map_err(|e| {
        eprintln!("plimit: {}: {}", handle.pid(), e);
        e
    })?;

    let rows: Vec<(String, String, String)> = limits
        .iter()
        .map(|(resource, limit)| format_row(resource, limit, mode))
        .collect();

    // Compute column widths from header labels and data.
    let res_w = rows
        .iter()
        .map(|(l, _, _)| l.len())
        .max()
        .unwrap_or(0)
        .max("RESOURCE".len());
    let cur_w = rows
        .iter()
        .map(|(_, s, _)| s.len())
        .max()
        .unwrap_or(0)
        .max("CURRENT".len());
    let max_w = rows
        .iter()
        .map(|(_, _, h)| h.len())
        .max()
        .unwrap_or(0)
        .max("MAXIMUM".len());

    ptools::display::print_proc_summary_from(handle);
    println!(
        "{:<res_w$}  {:>cur_w$}  {:>max_w$}",
        "RESOURCE", "CURRENT", "MAXIMUM"
    );
    for (label, soft, hard) in &rows {
        println!("{label:<res_w$}  {soft:>cur_w$}  {hard:>max_w$}");
    }

    Ok(())
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    let mut error = false;
    let mut first = true;
    for operand in &args.operands {
        if ptools::proc::is_non_pid_proc_path(operand) {
            continue;
        }
        if !first {
            println!();
        }
        first = false;
        let handle = match ptools::proc::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("plimit: {e}");
                error = true;
                continue;
            }
        };
        if print_limits(&handle, args.unit_mode).is_err() {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
