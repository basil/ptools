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

use clap::{command, value_parser, Arg};
use ptools::ParseError;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::exit;

// TODO Allow a user to be specified in ptree

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
}

// Loop over all the processes listed in /proc/, find the parent of each one, and build a map from
// child to parent and a map from parent to children. There doesn't seem to be a more efficient way
// of doing this reliably.
fn build_proc_maps() -> Result<(HashMap<u64, u64>, HashMap<u64, Vec<u64>>), Box<dyn Error>> {
    let mut child_map = HashMap::new(); // Map of pid to pids of children
    let mut parent_map = HashMap::new(); // Map of pid to pid of parent

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let filename = entry.file_name();
        if let Some(pid) = filename.to_str().and_then(|s| s.parse::<u64>().ok()) {
            let ppid = match ProcStat::read(pid) {
                Ok(proc_stat) => match proc_stat.ppid() {
                    Ok(ppid) => ppid,
                    Err(e) => {
                        eprintln!("{}", e.to_string());
                        continue;
                    }
                },
                // Proc probably exited before we could read its status
                Err(_) => continue,
            };
            child_map.entry(ppid).or_insert(vec![]).push(pid);
            parent_map.insert(pid, ppid);
        }
    }

    Ok((parent_map, child_map))
}

fn print_tree(pid: u64, parent_map: &HashMap<u64, u64>, child_map: &HashMap<u64, Vec<u64>>) {
    let indent_level = if pid == 1 {
        0
    } else {
        if !parent_map.contains_key(&pid) {
            eprintln!("No such pid {}", pid);
            return;
        }
        print_parents(&parent_map, pid)
    };
    print_children(&child_map, pid, indent_level);
}

// Returns the current indentation level
fn print_parents(parent_map: &HashMap<u64, u64>, pid: u64) -> u64 {
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

    let indent_level = print_parents(parent_map, ppid);
    print_ptree_line(ppid, indent_level);
    return indent_level + 1;
}

fn print_children(child_map: &HashMap<u64, Vec<u64>>, pid: u64, indent_level: u64) {
    print_ptree_line(pid, indent_level);
    if let Some(children) = child_map.get(&pid) {
        for child in children.iter() {
            print_children(child_map, *child, indent_level + 1);
        }
    }
}

fn print_ptree_line(pid: u64, indent_level: u64) {
    for _ in 0..indent_level {
        print!("  ");
    }
    print!("{}  ", pid);
    ptools::print_cmd_summary(pid);
}

fn main() {
    let matches = command!()
        .about("Print process trees")
        .arg(
            Arg::new("pid")
                .value_name("PID")
                .help("Process ID (PID)")
                .num_args(0..)
                .value_parser(value_parser!(u64).range(1..)),
        )
        .get_matches();

    let (parent_map, child_map) = match build_proc_maps() {
        Ok(maps) => maps,
        Err(e) => {
            eprintln!("Error building parent/child maps: {}", e);
            exit(1);
        }
    };

    if let Some(pids) = matches.get_many::<u64>("pid") {
        for pid in pids {
            print_tree(*pid, &parent_map, &child_map);
        }
    } else {
        // TODO Should we print all processes here, including kernel threads? Is there any way this
        // could miss userspace processes?
        print_tree(1, &parent_map, &child_map);
    }
}
