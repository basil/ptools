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

use std::collections::BTreeSet;
use std::process;

use nix::sched::sched_getaffinity;
use nix::unistd::Pid;
use ptools::proc::numa::cpu_to_node;
use ptools::proc::numa::node_affinity;
use ptools::proc::numa::numa_online_nodes;
use ptools::proc::numa::NodeAffinity;
use ptools::proc::ProcHandle;

/// Format a sorted slice of node IDs, collapsing consecutive runs into ranges.
///
/// For example, `[0, 1, 2, 5, 7, 8]` becomes `"0-2,5,7-8"`.
fn format_node_list(nodes: &[u32]) -> String {
    if nodes.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut start = nodes[0];
    let mut end = nodes[0];

    for &n in &nodes[1..] {
        if n == end + 1 {
            end = n;
        } else {
            if end > start + 1 {
                parts.push(format!("{start}-{end}"));
            } else if end > start {
                parts.push(format!("{start},{end}"));
            } else {
                parts.push(format!("{start}"));
            }
            start = n;
            end = n;
        }
    }

    if end > start + 1 {
        parts.push(format!("{start}-{end}"));
    } else if end > start {
        parts.push(format!("{start},{end}"));
    } else {
        parts.push(format!("{start}"));
    }

    parts.join(",")
}

/// Get the CPU affinity mask for a thread via syscall.
fn get_thread_affinity(tid: u64) -> Option<BTreeSet<usize>> {
    let mask = sched_getaffinity(Pid::from_raw(tid as i32)).ok()?;
    let set = (0..nix::sched::CpuSet::count())
        .filter(|&i| mask.is_set(i).unwrap_or(false))
        .collect();
    Some(set)
}

/// Format affinities for display, grouping nodes by affinity level and
/// collapsing consecutive node IDs into ranges.
///
/// Example output: `0-2/all,3/some,4-7/none`
fn format_affinity(nodes: &[u32], affinity: &Option<BTreeSet<usize>>) -> String {
    let Some(cpuset) = affinity else {
        let list = format_node_list(nodes);
        return if list.is_empty() {
            String::new()
        } else {
            format!("{list}/?")
        };
    };

    let mut all = Vec::new();
    let mut some = Vec::new();
    let mut none = Vec::new();

    for &n in nodes {
        match node_affinity(cpuset, n) {
            NodeAffinity::All => all.push(n),
            NodeAffinity::Some => some.push(n),
            NodeAffinity::None => none.push(n),
        }
    }

    let mut parts = Vec::new();
    if !all.is_empty() {
        parts.push(format!("{}/all", format_node_list(&all)));
    }
    if !some.is_empty() {
        parts.push(format!("{}/some", format_node_list(&some)));
    }
    if !none.is_empty() {
        parts.push(format!("{}/none", format_node_list(&none)));
    }

    parts.join(",")
}

struct NodeList {
    nodes: Vec<u32>,
    had_bad_nodes: bool,
}

/// Parse a node list string that may contain IDs, ranges, and keywords.
/// Warns on stderr for each non-online node (matching Solaris behavior).
fn parse_node_list(s: &str) -> std::io::Result<NodeList> {
    let online = numa_online_nodes()?;
    let mut result = Vec::new();
    let mut had_bad_nodes = false;

    for part in s.split(',') {
        let part = part.trim();
        match part {
            "all" | "leaves" => {
                result.extend(online.iter().copied());
            }
            "root" => {
                return Err(std::io::Error::other(
                    "Error parsing node 'root': Linux NUMA nodes have no hierarchy; use 'all' instead",
                ));
            }
            _ => {
                if let Some((start, end)) = part.split_once('-') {
                    let start: u32 = start.trim().parse().map_err(|e| {
                        std::io::Error::other(format!(
                            "Error parsing node '{}': {}",
                            start.trim(),
                            e,
                        ))
                    })?;
                    let end: u32 = end.trim().parse().map_err(|e| {
                        std::io::Error::other(
                            format!("Error parsing node '{}': {}", end.trim(), e,),
                        )
                    })?;
                    if start > end {
                        return Err(std::io::Error::other(format!(
                            "Error parsing range {start}-{end}: start > end",
                        )));
                    }
                    for n in start..=end {
                        if online.contains(&n) {
                            result.push(n);
                        } else {
                            eprintln!("plgrp: bad node {n}");
                            had_bad_nodes = true;
                        }
                    }
                } else {
                    let n: u32 = part.parse().map_err(|e| {
                        std::io::Error::other(format!("Error parsing node '{part}': {e}"))
                    })?;
                    if online.contains(&n) {
                        result.push(n);
                    } else {
                        eprintln!("plgrp: bad node {n}");
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

struct Args {
    affinity_nodes: Option<Vec<u32>>,
    had_bad_nodes: bool,
    operands: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: plgrp [-a node_list] [pid[/tid] | core] ...");
    eprintln!("Display current NUMA node and thread CPU affinities.");
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

fn print_thread(
    handle: &ProcHandle,
    tid: u64,
    affinity_nodes: &Option<Vec<u32>>,
) -> std::io::Result<()> {
    let pid = handle.pid();
    let node = if handle.is_core() {
        "?".to_string()
    } else {
        match handle.thread_cpu(tid) {
            Ok(cpu) => cpu_to_node(cpu)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string()),
            Err(e) => {
                eprintln!("plgrp: cannot read CPU for {pid}/{tid}");
                return Err(e);
            }
        }
    };

    let pid_tid = format!("{pid}/{tid}");
    if let Some(nodes) = affinity_nodes {
        let affinity = if handle.is_core() {
            handle.thread_affinity(tid).ok()
        } else {
            get_thread_affinity(tid)
        };
        let aff_str = format_affinity(nodes, &affinity);
        println!("{pid_tid:>14}  {node:>4}  {aff_str}");
    } else {
        println!("{pid_tid:>14}  {node:>4}");
    }
    Ok(())
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    if args.affinity_nodes.is_some() {
        println!("{:>14}  {:>4}  AFFINITY", "PID/TID", "NODE");
    } else {
        println!("{:>14}  {:>4}", "PID/TID", "NODE");
    }

    let mut error = false;
    for operand in &args.operands {
        if ptools::proc::is_non_pid_proc_path(operand) {
            continue;
        }
        let (handle, tid) = match ptools::proc::resolve_operand_with_tid(operand) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("plgrp: {e}");
                error = true;
                continue;
            }
        };
        if let Some(tid) = tid {
            if print_thread(&handle, tid, &args.affinity_nodes).is_err() {
                error = true;
            }
        } else {
            let tids = match handle.tids() {
                Ok(t) => t,
                Err(_) => {
                    eprintln!("plgrp: cannot read threads for PID {}", handle.pid());
                    error = true;
                    continue;
                }
            };
            if tids.is_empty() {
                eprintln!("plgrp: cannot read threads for PID {}", handle.pid());
                error = true;
                continue;
            }
            // Warn if the process had more threads than are available.
            if let Ok(n) = handle.thread_count() {
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
                if print_thread(&handle, tid, &args.affinity_nodes).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_node_list_single() {
        assert_eq!(format_node_list(&[3]), "3");
    }

    #[test]
    fn format_node_list_consecutive_range() {
        assert_eq!(format_node_list(&[0, 1, 2, 3]), "0-3");
    }

    #[test]
    fn format_node_list_two_consecutive() {
        assert_eq!(format_node_list(&[4, 5]), "4,5");
    }

    #[test]
    fn format_node_list_mixed() {
        assert_eq!(format_node_list(&[0, 1, 2, 5, 7, 8]), "0-2,5,7,8");
    }

    #[test]
    fn format_node_list_empty() {
        assert_eq!(format_node_list(&[]), "");
    }

    #[test]
    fn format_node_list_gaps() {
        assert_eq!(format_node_list(&[0, 2, 4]), "0,2,4");
    }
}
