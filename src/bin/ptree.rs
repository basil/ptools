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

use nix::libc;
use ptools::ParseError;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::process::exit;

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
            let handle = ptools::ProcHandle::from_pid(pid);
            let ppid = match handle.ppid() {
                Ok(ppid) => ppid,
                // Proc probably exited before we could read its status
                Err(_) => continue,
            };
            let euid = match handle.euid() {
                Ok(euid) => euid,
                Err(e) => {
                    eprintln!("{}", e);
                    continue;
                }
            };
            if let Some(st) = handle.starttime() {
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

fn print_tree(
    pid: u64,
    parent_map: &HashMap<u64, u64>,
    child_map: &HashMap<u64, Vec<u64>>,
    graph: Option<&GraphChars>,
) -> bool {
    let mut cont = Vec::new();
    let indent_level = if pid == 1 {
        0
    } else {
        if !parent_map.contains_key(&pid) {
            eprintln!("No such pid {}", pid);
            return false;
        }
        print_parents(parent_map, pid, graph, &mut cont)
    };
    print_children(child_map, pid, indent_level, graph, &mut cont, true);
    true
}

fn print_all_trees(child_map: &HashMap<u64, Vec<u64>>, graph: Option<&GraphChars>) {
    if let Some(root_children) = child_map.get(&0) {
        for pid in root_children {
            let mut cont = Vec::new();
            print_children(child_map, *pid, 0, graph, &mut cont, true);
        }
    }
}

// Returns the current indentation level
fn print_parents(
    parent_map: &HashMap<u64, u64>,
    pid: u64,
    graph: Option<&GraphChars>,
    cont: &mut Vec<bool>,
) -> u64 {
    let ppid = match parent_map.get(&pid) {
        Some(ppid) => *ppid,
        // Some child process listed 'pid' as its parent, but 'pid' exited before we could read its
        // parent. The child of 'pid' will have been re-parented, and the new parent will be 'init'.
        // It's actually a bit more complicated (see find_new_reaper() in the kernel), and there is
        // one case we might want to handle better: when a child is re-parented to another thread in
        // the thread group.
        None => 1,
    };

    // We've reached the top of the process tree. Don't bother printing the parent if the parent
    // is pid 1. Typically pid 1 didn't really start the process in question.
    if ppid == 1 {
        return 0;
    }

    let indent_level = print_parents(parent_map, ppid, graph, cont);
    print_ptree_line(ppid, indent_level, graph, cont, true);
    // Ancestor path is a single chain, no siblings to continue
    cont.push(false);
    indent_level + 1
}

fn print_children(
    child_map: &HashMap<u64, Vec<u64>>,
    pid: u64,
    indent_level: u64,
    graph: Option<&GraphChars>,
    cont: &mut Vec<bool>,
    is_last: bool,
) {
    print_ptree_line(pid, indent_level, graph, cont, is_last);
    if let Some(children) = child_map.get(&pid) {
        for (i, child) in children.iter().enumerate() {
            let child_is_last = i == children.len() - 1;
            cont.push(!child_is_last);
            print_children(
                child_map,
                *child,
                indent_level + 1,
                graph,
                cont,
                child_is_last,
            );
            cont.pop();
        }
    }
}

fn print_ptree_line(
    pid: u64,
    indent_level: u64,
    graph: Option<&GraphChars>,
    cont: &[bool],
    is_last: bool,
) {
    match graph {
        Some(g) if indent_level > 0 => {
            for c in cont.iter().take(indent_level as usize - 1) {
                if *c {
                    print!("{}", g.pipe);
                } else {
                    print!("{}", g.space);
                }
            }
            if is_last {
                print!("{}", g.last);
            } else {
                print!("{}", g.non_last);
            }
        }
        _ => {
            for _ in 0..indent_level {
                print!("  ");
            }
        }
    }
    print!("{}  ", pid);
    let handle = ptools::ProcHandle::from_pid(pid);
    ptools::print_cmd_summary_from(&handle);
}

fn lookup_uid_by_username(username: &str) -> Result<Option<u32>, Box<dyn Error>> {
    let c_username = std::ffi::CString::new(username)?;
    // SAFETY: getpwnam returns a pointer to a static struct or null.
    let pw = unsafe { libc::getpwnam(c_username.as_ptr()) };
    if pw.is_null() {
        return Ok(None);
    }
    Ok(Some(unsafe { (*pw).pw_uid }))
}

fn pids_for_user(username: &str, uid_map: &HashMap<u64, u32>) -> Result<Vec<u64>, Box<dyn Error>> {
    let uid = match lookup_uid_by_username(username)? {
        Some(uid) => uid,
        None => {
            return Err(From::from(ParseError::new(
                "username",
                &format!("No such user '{}'", username),
            )))
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
    target: Vec<String>,
}

fn print_usage() {
    eprintln!("Usage: ptree [-ag] [pid|user]...");
    eprintln!("Print process trees.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -a, --all        Include children of PID 0");
    eprintln!("  -g, --graph      Use line drawing characters");
    eprintln!("  -h, --help       Print help");
    eprintln!("  -V, --version    Print version");
}

fn parse_args() -> Args {
    use lexopt::prelude::*;

    let mut args = Args {
        all: false,
        graph: false,
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
            eprintln!("Error building parent/child maps: {}", e);
            exit(1);
        }
    };

    let graph = if args.graph {
        Some(graph_chars())
    } else {
        None
    };

    let mut error = false;
    if !args.target.is_empty() {
        let mut printed = HashSet::new();
        for target in &args.target {
            if let Ok(pid) = target.parse::<u64>() {
                if pid == 0 {
                    eprintln!("PID must be > 0: {}", pid);
                    error = true;
                    continue;
                }
                if printed.insert(pid) && !print_tree(pid, &parent_map, &child_map, graph) {
                    error = true;
                }
                continue;
            }

            match pids_for_user(target, &uid_map) {
                Ok(pids) => {
                    for pid in pids {
                        if printed.insert(pid) && !print_tree(pid, &parent_map, &child_map, graph) {
                            error = true;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    error = true;
                }
            }
        }
    } else if args.all {
        print_all_trees(&child_map, graph);
    } else {
        print_tree(1, &parent_map, &child_map, graph);
    }
    if error {
        exit(1);
    }
}
