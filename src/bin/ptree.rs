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

use ptools::ParseError;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
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

// Info parsed from /proc/[pid]/status
struct ProcStat {
    pid: u64,
    fields: HashMap<String, String>,
}

impl ProcStat {
    // What is the stability of 'status' vs 'stat'? Is parsing this more likely to break? Overall,
    // 'stat' seems better designed for parsing, _except_ ...
    //
    // The fields in /proc/[pid]/stat are separated by spaces. Unfortunately, the second field is
    // the command, which can contain spaces. Without knowing what the command is beforehand, we
    // can't parse this file reliably. We can read the command from /proc/[pid]/comm,
    // so we know exactly what to expect, but that would be a pain.
    //
    fn read(pid: u64) -> Result<Self, Box<dyn Error>> {
        // /proc/[pid]/status contains lines of the form
        //
        //    Name:   bash
        //    Umask:  0022
        //    State:  S (sleeping)
        //    ...

        let status_file = ProcStat::status_file(pid);
        let fields = BufReader::new(File::open(&status_file)?)
            .lines()
            .map(|s| {
                let s: String = s?;
                let substrs = s.splitn(2, ":").collect::<Vec<&str>>();
                if substrs.len() < 2 {
                    Err(ParseError::in_file(
                        "status",
                        &format!(
                            "Fewer fields than expected in line '{}' of file {}",
                            s, status_file
                        ),
                    ))?;
                }
                let key = substrs[0].to_string();
                let value = substrs[1].trim().to_string();
                Ok((key, value))
            })
            .collect::<Result<HashMap<String, String>, Box<dyn Error>>>()?;

        Ok(ProcStat {
            pid: pid,
            fields: fields,
        })
    }

    fn status_file(pid: u64) -> String {
        format!("/proc/{}/status", pid)
    }

    fn get_field(&self, field: &str) -> Result<&str, Box<dyn Error>> {
        match self.fields.get(field) {
            Some(val) => Ok(val),
            None => Err(From::from(ParseError::in_file(
                "status",
                &format!(
                    "Missing expected field '{}' in file {}",
                    field,
                    ProcStat::status_file(self.pid)
                ),
            ))),
        }
    }

    fn ppid(&self) -> Result<u64, Box<dyn Error>> {
        Ok(self.get_field("PPid")?.parse()?)
    }

    fn euid(&self) -> Result<u32, Box<dyn Error>> {
        let fields = self
            .get_field("Uid")?
            .split_whitespace()
            .collect::<Vec<&str>>();
        if fields.len() < 2 {
            return Err(From::from(ParseError::in_file(
                "status",
                &format!(
                    "Uid field in {} had fewer fields than expected",
                    ProcStat::status_file(self.pid)
                ),
            )));
        }
        Ok(fields[1].parse::<u32>()?)
    }
}

// Loop over all the processes listed in /proc/, find the parent of each one, and build a map from
// child to parent and a map from parent to children. There doesn't seem to be a more efficient way
// of doing this reliably.
fn build_proc_maps(
) -> Result<(HashMap<u64, u64>, HashMap<u64, Vec<u64>>, HashMap<u64, u32>), Box<dyn Error>> {
    let mut child_map = HashMap::new(); // Map of pid to pids of children
    let mut parent_map = HashMap::new(); // Map of pid to pid of parent
    let mut uid_map = HashMap::new(); // Map of pid to effective uid

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let filename = entry.file_name();
        if let Some(pid) = filename.to_str().and_then(|s| s.parse::<u64>().ok()) {
            let proc_stat = match ProcStat::read(pid) {
                Ok(proc_stat) => proc_stat,
                // Proc probably exited before we could read its status
                Err(_) => continue,
            };
            let ppid = match proc_stat.ppid() {
                Ok(ppid) => ppid,
                Err(e) => {
                    eprintln!("{}", e.to_string());
                    continue;
                }
            };
            let euid = match proc_stat.euid() {
                Ok(euid) => euid,
                Err(e) => {
                    eprintln!("{}", e.to_string());
                    continue;
                }
            };
            child_map.entry(ppid).or_insert(vec![]).push(pid);
            parent_map.insert(pid, ppid);
            uid_map.insert(pid, euid);
        }
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
        print_parents(&parent_map, pid, graph, &mut cont)
    };
    print_children(&child_map, pid, indent_level, graph, &mut cont, true);
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
    return indent_level + 1;
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
            for i in 0..(indent_level as usize - 1) {
                if cont[i] {
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
    ptools::print_cmd_summary(pid);
}

fn lookup_uid_by_username(username: &str) -> Result<Option<u32>, Box<dyn Error>> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields = line.split(':').collect::<Vec<&str>>();
        if fields.len() < 3 {
            continue;
        }
        if fields[0] != username {
            continue;
        }
        let uid = fields[2].parse::<u32>()?;
        return Ok(Some(uid));
    }
    Ok(None)
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
                if printed.insert(pid) {
                    if !print_tree(pid, &parent_map, &child_map, graph) {
                        error = true;
                    }
                }
                continue;
            }

            match pids_for_user(target, &uid_map) {
                Ok(pids) => {
                    for pid in pids {
                        if printed.insert(pid) {
                            if !print_tree(pid, &parent_map, &child_map, graph) {
                                error = true;
                            }
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
