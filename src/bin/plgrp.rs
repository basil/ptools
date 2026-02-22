//
//   Copyright 2026 Basil Crow
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

use std::process;

use nix::sched::{sched_getaffinity, CpuSet};
use nix::unistd::Pid;

use ptools::{cpu_to_node, numa_node_cpus, numa_online_nodes, ProcHandle};

/// Get the CPU affinity mask for a thread.
fn get_thread_affinity(tid: u64) -> Option<CpuSet> {
    sched_getaffinity(Pid::from_raw(tid as i32)).ok()
}

struct NodeList {
    nodes: Vec<u32>,
    had_bad_nodes: bool,
}

/// Parse a node list string that may contain IDs, ranges, and keywords.
/// Warns on stderr for each non-online node (matching Solaris behavior).
fn parse_node_list(s: &str) -> Result<NodeList, String> {
    let online = numa_online_nodes()?;
    let mut result = Vec::new();
    let mut had_bad_nodes = false;

    for part in s.split(',') {
        let part = part.trim();
        match part {
            "all" | "leaves" => {
                result.extend_from_slice(&online);
            }
            "root" => {
                if online.contains(&0) {
                    result.push(0);
                }
            }
            _ => {
                if let Some((start, end)) = part.split_once('-') {
                    let start: u32 = start
                        .trim()
                        .parse()
                        .map_err(|e| format!("invalid node '{}': {}", start.trim(), e))?;
                    let end: u32 = end
                        .trim()
                        .parse()
                        .map_err(|e| format!("invalid node '{}': {}", end.trim(), e))?;
                    if start > end {
                        return Err(format!("invalid range {}-{}", start, end));
                    }
                    for n in start..=end {
                        if online.contains(&n) {
                            result.push(n);
                        } else {
                            eprintln!("plgrp: bad node {}", n);
                            had_bad_nodes = true;
                        }
                    }
                } else {
                    let n: u32 = part
                        .parse()
                        .map_err(|e| format!("invalid node '{}': {}", part, e))?;
                    if online.contains(&n) {
                        result.push(n);
                    } else {
                        eprintln!("plgrp: bad node {}", n);
                        had_bad_nodes = true;
                    }
                }
            }
        }
    }

    result.sort();
    result.dedup();
    Ok(NodeList {
        nodes: result,
        had_bad_nodes,
    })
}

/// Check whether a thread's affinity includes any CPU on the given node.
fn thread_has_affinity_for_node(affinity: &CpuSet, node: u32) -> bool {
    let Ok(cpus) = numa_node_cpus(node) else {
        return false;
    };
    cpus.iter()
        .any(|&cpu| affinity.is_set(cpu as usize).unwrap_or(false))
}

/// Check whether a list of allowed CPUs includes any CPU on the given node.
fn cpus_include_node(allowed: &[u32], node: u32) -> bool {
    let Ok(cpus) = numa_node_cpus(node) else {
        return false;
    };
    cpus.iter().any(|cpu| allowed.contains(cpu))
}

struct Args {
    affinity_nodes: Option<Vec<u32>>,
    had_bad_nodes: bool,
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: plgrp [-a node_list] [pid[/tid] | core] ...");
    eprintln!("Display home NUMA node and thread affinities.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -a node_list     Show affinity for the specified nodes");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        affinity_nodes: None,
        had_bad_nodes: false,
        operands: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("plgrp: {e}");
        process::exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                process::exit(0);
            }
            Short('V') | Long("version") => {
                println!("plgrp {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            Short('a') => {
                let val = parser.value().unwrap_or_else(|e| {
                    eprintln!("plgrp: -a requires a node list: {e}");
                    process::exit(2);
                });
                let node_str = val.to_string_lossy();
                match parse_node_list(&node_str) {
                    Ok(node_list) => {
                        args.had_bad_nodes = node_list.had_bad_nodes;
                        args.affinity_nodes = Some(node_list.nodes);
                    }
                    Err(e) => {
                        eprintln!("plgrp: invalid node list: {e}");
                        process::exit(2);
                    }
                }
            }
            Value(val) => {
                args.operands.push(val.to_string_lossy().into_owned());
            }
            _ => {
                eprintln!("plgrp: unexpected argument: {arg:?}");
                process::exit(2);
            }
        }
    }

    if args.operands.is_empty() {
        eprintln!("plgrp: at least one pid[/tid] or core required");
        process::exit(2);
    }
    args
}

fn print_thread(handle: &ProcHandle, tid: u64, affinity_nodes: &Option<Vec<u32>>) -> bool {
    let pid = handle.pid();
    let home = if handle.is_core() {
        "?".to_string()
    } else {
        match handle.thread_cpu(tid) {
            Some(cpu) => cpu_to_node(cpu)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string()),
            None => {
                eprintln!("plgrp: cannot read CPU for {}/{}", pid, tid);
                return false;
            }
        }
    };

    let pid_tid = format!("{}/{}", pid, tid);
    if let Some(nodes) = affinity_nodes {
        let aff_str: String = if handle.is_core() {
            let allowed = handle.thread_affinity(tid);
            nodes
                .iter()
                .map(|&n| {
                    let label = match &allowed {
                        Some(cpus) if cpus_include_node(cpus, n) => "bound",
                        Some(_) => "none",
                        None => "?",
                    };
                    format!("{}/{}", n, label)
                })
                .collect::<Vec<_>>()
                .join(",")
        } else {
            let affinity = get_thread_affinity(tid);
            nodes
                .iter()
                .map(|&n| {
                    let label = match &affinity {
                        Some(cpuset) if thread_has_affinity_for_node(cpuset, n) => "bound",
                        Some(_) => "none",
                        None => "?",
                    };
                    format!("{}/{}", n, label)
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        println!("{:>14}  {:>4}  {}", pid_tid, home, aff_str);
    } else {
        println!("{:>14}  {:>4}", pid_tid, home);
    }
    true
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    if args.affinity_nodes.is_some() {
        println!("{:>14}  {:>4}  AFFINITY", "PID/TID", "HOME");
    } else {
        println!("{:>14}  {:>4}", "PID/TID", "HOME");
    }

    let mut error = false;
    for operand in &args.operands {
        let (handle, tid) = match ptools::resolve_operand_with_tid(operand) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("plgrp: {e}");
                error = true;
                continue;
            }
        };
        for w in handle.warnings() {
            eprintln!("{w}");
        }
        if let Some(tid) = tid {
            if !print_thread(&handle, tid, &args.affinity_nodes) {
                error = true;
            }
        } else {
            let tids = handle.tids();
            if tids.is_empty() {
                eprintln!("plgrp: cannot read threads for PID {}", handle.pid());
                error = true;
                continue;
            }
            // Warn if the process had more threads than are available.
            if let Some(n) = handle.thread_count() {
                if n > tids.len() {
                    eprintln!(
                        "warning: process had {} threads but only {} available; \
                         output may be incomplete",
                        n,
                        tids.len()
                    );
                }
            }
            for tid in tids {
                if !print_thread(&handle, tid, &args.affinity_nodes) {
                    error = true;
                }
            }
        }
    }

    if args.had_bad_nodes {
        process::exit(2);
    }
    if error {
        process::exit(1);
    }
}
