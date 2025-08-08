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

use getopts::{Options, ParsingStyle};
use std::env;
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

fn pargs_main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    let opts = {
        let mut opts = Options::new();
        opts.optflag("a", "", "Print command line args to process");
        // We have a separate penv command, but keep this option for compatibility with Solaris
        opts.optflag("e", "", "Print environement variables of process");
        opts.optflag("h", "help", "print this help message");
        opts.parsing_style(ParsingStyle::StopAtFirstFree);
        opts
    };

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprint!("{}\n", e.to_string());
            ptools::usage_err(program, opts);
        }
    };

    if matches.opt_present("h") {
        ptools::usage(program, opts);
    }

    if matches.free.len() == 0 {
        ptools::usage_err(program, opts);
    }

    let do_print_args = matches.opt_present("a");
    let do_print_env = matches.opt_present("e");

    for arg in &matches.free {
        if let Some(pid) = ptools::parse_pid(arg) {
            if do_print_args || !do_print_env {
                print_args(pid);
            }

            if do_print_env {
                ptools::print_env(pid);
            }
        }
    }
}

fn main() {
    pargs_main();
}
