//
//   Copyright 2018 Delphix
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

use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::process::exit;

use nix::unistd::User;

nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);

fn pid_width() -> usize {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|max| max.to_string().len())
        .unwrap_or(7)
}

fn terminal_width() -> Option<usize> {
    if let Ok(cols) = std::env::var("COLUMNS") {
        if let Ok(w) = cols.parse::<usize>() {
            if w > 0 {
                return Some(w);
            }
        }
    }
    unsafe {
        let mut ws = std::mem::MaybeUninit::<libc::winsize>::uninit();
        tiocgwinsz(libc::STDOUT_FILENO, ws.as_mut_ptr()).ok()?;
        let ws = ws.assume_init();
        if ws.ws_col > 0 {
            Some(ws.ws_col as usize)
        } else {
            None
        }
    }
}

struct GraphChars {
    last: &'static str,
    non_last: &'static str,
    pipe: &'static str,
    space: &'static str,
}

const UTF8_GRAPH: GraphChars = GraphChars {
    last: "└─",
    non_last: "├─",
    pipe: "│ ",
    space: "  ",
};

const ASCII_GRAPH: GraphChars = GraphChars {
    last: "`-",
    non_last: "|-",
    pipe: "| ",
    space: "  ",
};

fn is_utf8_locale() -> bool {
    for var in &["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                return val.to_ascii_lowercase().contains("utf-8")
                    || val.to_ascii_lowercase().contains("utf8");
            }
        }
    }
    false
}

fn graph_chars() -> &'static GraphChars {
    if is_utf8_locale() {
        &UTF8_GRAPH
    } else {
        &ASCII_GRAPH
    }
}

// Loop over all the processes listed in /proc/, find the parent of each one, and build a map from
// child to parent and a map from parent to children. There doesn't seem to be a more efficient way
// of doing this reliably.
type ProcMaps = (HashMap<u64, u64>, HashMap<u64, Vec<u64>>, HashMap<u64, u32>);

fn build_proc_maps() -> Result<ProcMaps, Box<dyn Error>> {
    let mut child_map = HashMap::new(); // Map of pid to pids of children
    let mut parent_map = HashMap::new(); // Map of pid to pid of parent
    let mut uid_map = HashMap::new(); // Map of pid to effective uid
    let mut starttime_map: HashMap<u64, u64> = HashMap::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let filename = entry.file_name();
        if let Some(pid) = filename.to_str().and_then(|s| s.parse::<u64>().ok()) {
            let handle = ptools::proc::ProcHandle::from_pid(pid);
            let ppid = match handle.ppid() {
                Ok(ppid) => ppid,
                // Proc probably exited before we could read its status
                Err(_) => continue,
            };
            let euid = match handle.euid() {
                Ok(euid) => euid,
                Err(e) => {
                    eprintln!("ptree: {e}");
                    continue;
                }
            };
            if let Ok(st) = handle.starttime() {
                starttime_map.insert(pid, st);
            }
            child_map.entry(ppid).or_insert(vec![]).push(pid);
            parent_map.insert(pid, ppid);
            uid_map.insert(pid, euid);
        }
    }

    // Sort children by start time (ties broken by pid)
    for children in child_map.values_mut() {
        children.sort_unstable_by_key(|pid| {
            (starttime_map.get(pid).copied().unwrap_or(u64::MAX), *pid)
        });
    }

    Ok((parent_map, child_map, uid_map))
}

struct PrintOpts<'a> {
    graph: Option<&'a GraphChars>,
    max_width: Option<usize>,
    pid_width: usize,
}

/// Walk up the parent chain for `pid`, returning the chain root-first.
/// Stops when the parent's parent is PID 0 (same boundary as the old
/// `print_parents`).
fn ancestor_chain(pid: u64, parent_map: &HashMap<u64, u64>) -> Vec<u64> {
    let mut chain = vec![pid];
    let mut cur = pid;
    while let Some(&ppid) = parent_map.get(&cur) {
        // Stop before adding ancestors whose parent is PID 0.
        let ppid_parent = parent_map.get(&ppid).copied().unwrap_or(0);
        if ppid_parent == 0 {
            break;
        }
        chain.push(ppid);
        cur = ppid;
    }
    chain.reverse();
    chain
}

/// Build the pruned children map and group roots for a set of target PIDs.
/// Returns `(pruned_children, sorted_roots)`.
fn build_merged_groups(
    targets: &HashSet<u64>,
    parent_map: &HashMap<u64, u64>,
    child_map: &HashMap<u64, Vec<u64>>,
) -> (HashMap<u64, Vec<u64>>, Vec<u64>) {
    let mut pruned_children: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut root_set: HashSet<u64> = HashSet::new();

    for &pid in targets {
        let chain = ancestor_chain(pid, parent_map);
        if let Some(&root) = chain.first() {
            root_set.insert(root);
        }
        // Insert edges from the chain into pruned_children.
        for window in chain.windows(2) {
            let parent = window[0];
            let child = window[1];
            let children = pruned_children.entry(parent).or_default();
            if !children.contains(&child) {
                children.push(child);
            }
        }
    }

    // Sort each pruned_children entry to match child_map ordering.
    for (parent, children) in pruned_children.iter_mut() {
        if let Some(full_children) = child_map.get(parent) {
            children.sort_by_key(|c| {
                full_children
                    .iter()
                    .position(|fc| fc == c)
                    .unwrap_or(usize::MAX)
            });
        }
    }

    // Sort roots by minimum target PID reachable from each root.
    let mut roots: Vec<u64> = root_set.into_iter().collect();
    roots.sort_by_key(|root| {
        targets
            .iter()
            .filter(|t| {
                let chain = ancestor_chain(**t, parent_map);
                chain.first() == Some(root)
            })
            .min()
            .copied()
            .unwrap_or(*root)
    });

    (pruned_children, roots)
}

struct MergedTreeCtx<'a> {
    pruned_children: &'a HashMap<u64, Vec<u64>>,
    targets: &'a HashSet<u64>,
    child_map: &'a HashMap<u64, Vec<u64>>,
    opts: &'a PrintOpts<'a>,
}

fn print_merged_tree(
    pid: u64,
    ctx: &MergedTreeCtx,
    indent_level: u64,
    cont: &mut Vec<bool>,
    is_last: bool,
) {
    print_ptree_line(pid, indent_level, ctx.opts, cont, is_last);

    if ctx.targets.contains(&pid) {
        // Target PID: show its full subtree.
        if let Some(children) = ctx.child_map.get(&pid) {
            let mut printed = HashSet::new();
            for (i, child) in children.iter().enumerate() {
                let child_is_last = i == children.len() - 1;
                cont.push(!child_is_last);
                print_children(
                    ctx.child_map,
                    *child,
                    indent_level + 1,
                    ctx.opts,
                    cont,
                    child_is_last,
                    &mut printed,
                );
                cont.pop();
            }
        }
    } else if let Some(children) = ctx.pruned_children.get(&pid) {
        // Ancestor-only node: only recurse into pruned branches.
        for (i, child) in children.iter().enumerate() {
            let child_is_last = i == children.len() - 1;
            cont.push(!child_is_last);
            print_merged_tree(*child, ctx, indent_level + 1, cont, child_is_last);
            cont.pop();
        }
    }
}

fn print_all_trees(child_map: &HashMap<u64, Vec<u64>>, opts: &PrintOpts) {
    let mut printed = HashSet::new();
    if let Some(root_children) = child_map.get(&0) {
        for pid in root_children {
            let mut cont = Vec::new();
            print_children(child_map, *pid, 0, opts, &mut cont, true, &mut printed);
        }
    }
}

fn print_children(
    child_map: &HashMap<u64, Vec<u64>>,
    pid: u64,
    indent_level: u64,
    opts: &PrintOpts,
    cont: &mut Vec<bool>,
    is_last: bool,
    printed: &mut HashSet<u64>,
) {
    print_ptree_line(pid, indent_level, opts, cont, is_last);
    printed.insert(pid);
    if let Some(children) = child_map.get(&pid) {
        for (i, child) in children.iter().enumerate() {
            let child_is_last = i == children.len() - 1;
            cont.push(!child_is_last);
            print_children(
                child_map,
                *child,
                indent_level + 1,
                opts,
                cont,
                child_is_last,
                printed,
            );
            cont.pop();
        }
    }
}

fn print_ptree_line(pid: u64, indent_level: u64, opts: &PrintOpts, cont: &[bool], is_last: bool) {
    use std::fmt::Write;

    let mut line = String::new();
    match opts.graph {
        Some(g) if indent_level > 0 => {
            for c in cont.iter().take(indent_level as usize - 1) {
                if *c {
                    line.push_str(g.pipe);
                } else {
                    line.push_str(g.space);
                }
            }
            if is_last {
                line.push_str(g.last);
            } else {
                line.push_str(g.non_last);
            }
        }
        _ => {
            for _ in 0..indent_level {
                line.push_str("  ");
            }
        }
    }
    let _ = write!(line, "{pid:<width$}  ", width = opts.pid_width);
    let handle = ptools::proc::ProcHandle::from_pid(pid);
    line.push_str(&ptools::display::cmd_summary_from(&handle));
    if let Some(w) = opts.max_width {
        if let Some((idx, _)) = line.char_indices().nth(w) {
            line.truncate(idx);
        }
    }
    println!("{line}");
}

fn pids_for_user(username: &str, uid_map: &HashMap<u64, u32>) -> Result<Vec<u64>, Box<dyn Error>> {
    let uid = match User::from_name(username)?.map(|u| u.uid.as_raw()) {
        Some(uid) => uid,
        None => {
            return Err(From::from(std::io::Error::other(format!(
                "Error parsing username: No such user '{username}'",
            ))))
        }
    };

    let mut pids = uid_map
        .iter()
        .filter_map(|(pid, euid)| if *euid == uid { Some(*pid) } else { None })
        .collect::<Vec<u64>>();
    pids.sort_unstable();
    Ok(pids)
}

struct Args {
    all: bool,
    graph: bool,
    wrap: bool,
    target: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: ptree [-agw] [pid|user]...");
    eprintln!("Print process trees. A /proc/pid path may be used in place of a PID.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -a, --all        Include children of PID 0");
    eprintln!("  -g, --graph      Use line drawing characters");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
    eprintln!("  -w, --wrap       Allow output lines to wrap");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        all: false,
        graph: false,
        wrap: false,
        target: Vec::new(),
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next().unwrap_or_else(|e| {
        eprintln!("ptree: {e}");
        exit(2);
    }) {
        match arg {
            Short('h') | Long("help") => {
                print_usage();
                exit(0);
            }
            Short('V') | Long("version") => {
                println!("ptree {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            Short('a') | Long("all") => args.all = true,
            Short('g') | Long("graph") => args.graph = true,
            Short('w') | Long("wrap") => args.wrap = true,
            Value(val) => {
                args.target.push(val.to_string_lossy().into_owned());
            }
            _ => {
                eprintln!("ptree: unexpected argument: {arg:?}");
                exit(2);
            }
        }
    }

    args
}

fn main() {
    ptools::reset_sigpipe();
    let args = parse_args();

    let (parent_map, child_map, uid_map) = match build_proc_maps() {
        Ok(maps) => maps,
        Err(e) => {
            eprintln!("ptree: error building parent/child maps: {e}");
            exit(1);
        }
    };

    let opts = PrintOpts {
        graph: if args.graph {
            Some(graph_chars())
        } else {
            None
        },
        max_width: if args.wrap { None } else { terminal_width() },
        pid_width: pid_width(),
    };

    let mut error = false;
    if !args.target.is_empty() {
        // Phase 1: Collect all target PIDs.
        let mut target_pids = Vec::new();
        for target in &args.target {
            if let Ok(pid) = target.parse::<u64>() {
                if pid == 0 {
                    eprintln!("ptree: PID must be > 0: {pid}");
                    error = true;
                    continue;
                }
                if !parent_map.contains_key(&pid) {
                    eprintln!("ptree: no such pid {pid}");
                    error = true;
                    continue;
                }
                target_pids.push(pid);
                continue;
            }
            if let Some(pid) = ptools::proc::parse_proc_path(target) {
                if !parent_map.contains_key(&pid) {
                    eprintln!("ptree: no such pid {pid}");
                    error = true;
                    continue;
                }
                target_pids.push(pid);
                continue;
            }
            if target.starts_with("/proc/") {
                continue; // non-PID /proc path from shell expansion
            }

            match pids_for_user(target, &uid_map) {
                Ok(pids) => {
                    for pid in pids {
                        if parent_map.contains_key(&pid) {
                            target_pids.push(pid);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("ptree: {e}");
                    error = true;
                }
            }
        }

        // Deduplicate while preserving order.
        let mut seen = HashSet::new();
        target_pids.retain(|pid| seen.insert(*pid));

        // Phase 2: Build merged groups.
        let target_set: HashSet<u64> = target_pids.iter().copied().collect();
        let (pruned_children, roots) = build_merged_groups(&target_set, &parent_map, &child_map);

        // Phase 3: Print merged trees.
        let ctx = MergedTreeCtx {
            pruned_children: &pruned_children,
            targets: &target_set,
            child_map: &child_map,
            opts: &opts,
        };
        for root in &roots {
            let mut cont = Vec::new();
            print_merged_tree(*root, &ctx, 0, &mut cont, true);
        }
    } else if args.all {
        print_all_trees(&child_map, &opts);
    } else if let Some(children) = child_map.get(&1) {
        let mut printed = HashSet::new();
        for pid in children {
            let mut cont = Vec::new();
            print_children(&child_map, *pid, 0, &opts, &mut cont, true, &mut printed);
        }
    }
    if error {
        exit(1);
    }
}
