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

use clap::{command, value_parser, Arg, ArgAction};
use std::io::{BufRead, BufReader};

fn print_args(pid: u64) {
    if let Some(file) = ptools::open_or_warn(&format!("/proc/{}/cmdline", pid)) {
        ptools::print_proc_summary(pid);

        for (i, bytes) in BufReader::new(file).split('\0' as u8).enumerate() {
            match &bytes {
                Ok(bytes) => {
                    let arg = String::from_utf8_lossy(bytes);
                    println!("argv[{}]: {}", i, arg);
                }
                Err(e) => {
                    eprint!("Error reading args: {}", e)
                }
            }
        }
    }
}

fn main() {
    let matches = command!()
        .about("Print process arguments")
        .trailing_var_arg(true)
        .arg(
            Arg::new("args")
                .short('a')
                .long("args")
                .help("Print process arguments")
                .action(ArgAction::SetTrue),
        )
        // We have a separate penv command, but keep this option for compatibility with Solaris
        .arg(
            Arg::new("env")
                .short('e')
                .long("env")
                .help("Print process environment variables")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("pid")
                .value_name("PID")
                .help("Process ID (PID)")
                .num_args(1..)
                .required(true)
                .value_parser(value_parser!(u64).range(1..)),
        )
        .get_matches();

    let do_print_args = matches.get_flag("args");
    let do_print_env = matches.get_flag("env");
    let want_args = do_print_args || !do_print_env;

    for pid in matches.get_many::<u64>("pid").unwrap() {
        if want_args {
            print_args(*pid);
        }
        if do_print_env {
            ptools::print_env(*pid);
        }
    }
}
