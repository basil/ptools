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

fn main() {
    let matches = command!()
        .about("Print process environment variables")
        .long_about("Examine a target process and print environment variables and values.")
        .trailing_var_arg(true)
        .arg(
            Arg::new("pid")
                .value_name("PID")
                .help("Process ID (PID)")
                .long_help("A list of process IDs (PIDs)")
                .num_args(1..)
                .required(true)
                .value_parser(value_parser!(u64).range(1..)),
        )
        .get_matches();

    for pid in matches.get_many::<u64>("pid").unwrap() {
        ptools::print_env(*pid);
    }
}
