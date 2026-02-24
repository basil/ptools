//
//   Copyright (c) 2017 Steven Fackler
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

pub use crate::dw::dwfl::Error;
use crate::dw::dwfl::{Callbacks, FindDebuginfo, FindElf, ProcessTracker};
use std::fs;
use std::sync::LazyLock;

use super::{Frame, Symbol, Thread, TraceOptions};

static CALLBACKS: LazyLock<Callbacks> =
    LazyLock::new(|| Callbacks::new(FindElf::TRACKER_LINUX_PROC, FindDebuginfo::STANDARD));

pub struct State(ProcessTracker<'static>);

impl State {
    pub fn new() -> Result<State, Error> {
        Ok(State(ProcessTracker::new(&CALLBACKS)?))
    }

    pub fn trace(&self, pid: u32, options: &TraceOptions) -> Result<Vec<Thread>, Error> {
        let mut dwfl = self.0.attach_process(pid)?;
        let mut threads = vec![];

        dwfl.threads(|thread| {
            let tid = thread.tid();
            let name = if options.thread_names {
                let path = format!("/proc/{}/task/{}/comm", pid, tid);
                fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
            } else {
                None
            };

            let mut frames = vec![];
            thread.frames(|frame| {
                let mut is_signal = false;
                let ip = frame.pc(Some(&mut is_signal))?;

                let mut symbol = None;
                if options.symbols {
                    let signal_adjust = if is_signal { 0 } else { 1 };

                    if let Ok(i) = frame
                        .thread()
                        .dwfl()
                        .addr_module(ip - signal_adjust)
                        .and_then(|module| module.addr_info(ip - signal_adjust))
                    {
                        symbol = Some(Symbol {
                            name: i.name().to_string_lossy().into_owned(),
                            offset: i.offset() + signal_adjust,
                            address: i.bias() + i.symbol().value(),
                            size: i.symbol().size(),
                        });
                    }
                }

                frames.push(Frame {
                    ip,
                    is_signal,
                    symbol,
                });

                Ok(())
            })?;

            threads.push(Thread {
                id: tid,
                name,
                frames,
            });
            Ok(())
        })?;

        Ok(threads)
    }
}
