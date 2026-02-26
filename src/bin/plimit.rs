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

use ptools::{ProcHandle, ResourceLimit, RlimitVal};

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

fn convert_value(val: RlimitVal, kernel_unit: &str, mode: UnitMode) -> RlimitVal {
    val.map(|v| match (kernel_unit, mode) {
        ("bytes", UnitMode::Kbytes) => v / 1024,
        ("bytes", UnitMode::Mbytes) => v / 1_048_576,
        _ => v,
    })
}

fn fmt_val(val: RlimitVal) -> String {
    match val {
        None => "unlimited".to_string(),
        Some(v) => v.to_string(),
    }
}

fn display_name(kernel_name: &str) -> &str {
    match kernel_name {
        "Max cpu time" => "time",
        "Max file size" => "file",
        "Max data size" => "data",
        "Max stack size" => "stack",
        "Max core file size" => "coredump",
        "Max open files" => "nofiles",
        "Max address space" => "vmemory",
        "Max resident set" => "rss",
        "Max processes" => "nproc",
        "Max locked memory" => "memlock",
        "Max file locks" => "locks",
        "Max pending signals" => "sigpending",
        "Max msgqueue size" => "msgqueue",
        "Max nice priority" => "nice",
        "Max realtime priority" => "rtprio",
        "Max realtime timeout" => "rttime",
        other => other,
    }
}

fn format_row(rl: &ResourceLimit, mode: UnitMode) -> (String, String, String) {
    let name = display_name(&rl.name);
    let unit = display_unit(&rl.unit, mode);
    let label = if unit.is_empty() {
        name.to_string()
    } else {
        format!("{name} ({unit})")
    };
    let soft = convert_value(rl.soft, &rl.unit, mode);
    let hard = convert_value(rl.hard, &rl.unit, mode);
    (label, fmt_val(soft), fmt_val(hard))
}

fn print_limits(handle: &ProcHandle, mode: UnitMode) -> Result<(), ptools::Error> {
    let limits = handle.resource_limits().map_err(|e| {
        eprintln!("plimit: {}: {}", handle.pid(), e);
        e
    })?;

    let rows: Vec<(String, String, String)> =
        limits.iter().map(|rl| format_row(rl, mode)).collect();

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

    ptools::print_proc_summary_from(handle);
    println!(
        "{:<res_w$}  {:>cur_w$}  {:>max_w$}",
        "RESOURCE", "CURRENT", "MAXIMUM"
    );
    for (label, soft, hard) in &rows {
        println!("{:<res_w$}  {:>cur_w$}  {:>max_w$}", label, soft, hard);
    }

    Ok(())
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    let mut error = false;
    let mut first = true;
    for operand in &args.operands {
        if !first {
            println!();
        }
        first = false;
        let handle = match ptools::resolve_operand(operand) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("plimit: {e}");
                error = true;
                continue;
            }
        };
        for w in handle.drain_warnings() {
            eprintln!("{w}");
        }
        if print_limits(&handle, args.unit_mode).is_err() {
            error = true;
        }
    }
    if error {
        exit(1);
    }
}
