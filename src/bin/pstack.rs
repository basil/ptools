//
//   Copyright (c) 2017 Steven Fackler
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

use std::env;
use std::process;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        eprintln!("Usage: {} <pid>", args[0]);
        process::exit(1);
    }

    let pid = match args[1].parse() {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("error parsing PID: {}", e);
            process::exit(1);
        }
    };

    let process = match ptools::stack::trace(pid) {
        Ok(threads) => threads,
        Err(e) => {
            eprintln!("error tracing threads: {}", e);
            process::exit(1);
        }
    };

    for thread in process.threads() {
        println!(
            "thread {} - {}",
            thread.id(),
            thread.name().unwrap_or("<unknown>")
        );
        for frame in thread.frames() {
            match frame.symbol() {
                Some(symbol) => println!(
                    "{:#016x} - {} + {:#x}",
                    frame.ip(),
                    symbol.name(),
                    symbol.offset(),
                ),
                None => println!("{:#016x} - ???", frame.ip()),
            }
        }
        println!();
    }
}
