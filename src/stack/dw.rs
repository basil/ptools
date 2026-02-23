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

pub use crate::dw::dwfl::Error;
use crate::dw::dwfl::{Callbacks, Dwfl, FindDebuginfo, FindElf};
use std::sync::LazyLock;

use super::{Frame, Symbol, TraceOptions, TracedThread};

static CALLBACKS: LazyLock<Callbacks> =
    LazyLock::new(|| Callbacks::new(FindElf::LINUX_PROC, FindDebuginfo::STANDARD));

pub struct State(Dwfl<'static>);

impl State {
    pub fn new(pid: u32) -> Result<State, Error> {
        let mut dwfl = Dwfl::begin(&CALLBACKS)?;
        dwfl.report().linux_proc(pid)?;
        dwfl.linux_proc_attach(pid, true)?;
        Ok(State(dwfl))
    }
}

impl TracedThread {
    pub fn dump_inner(
        &self,
        dwfl: &mut State,
        options: &TraceOptions,
        frames: &mut Vec<Frame>,
    ) -> Result<(), Error> {
        dwfl.0.thread_frames(self.id, |frame| {
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
        })
    }
}
