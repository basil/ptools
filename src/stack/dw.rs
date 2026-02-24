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
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::LazyLock;

use super::{Frame, Symbol, TraceOptions, TracedThread};

unsafe extern "C" {
    fn __cxa_demangle(
        mangled_name: *const c_char,
        output_buffer: *mut c_char,
        length: *mut libc::size_t,
        status: *mut c_int,
    ) -> *mut c_char;
}

/// Demangle a GNU v3 ABI C++ symbol name, returning `None` if the name is not
/// mangled or demangling fails.
fn demangle(name: &str) -> Option<String> {
    // Require GNU v3 ABI by the "_Z" prefix, matching elfutils stack.c behavior.
    if !name.starts_with("_Z") {
        return None;
    }
    let mangled = CString::new(name).ok()?;
    let mut status: c_int = -1;
    let demangled = unsafe {
        __cxa_demangle(
            mangled.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut status,
        )
    };
    if status != 0 {
        return None;
    }
    let result = unsafe { CStr::from_ptr(demangled) }
        .to_string_lossy()
        .into_owned();
    unsafe { libc::free(demangled.cast()) };
    Some(result)
}

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
                    let raw_name = i.name().to_string_lossy().into_owned();
                    let name = if options.demangle {
                        demangle(&raw_name).unwrap_or(raw_name)
                    } else {
                        raw_name
                    };
                    symbol = Some(Symbol {
                        name,
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
