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
use std::os::unix::io::AsRawFd;
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

static CORE_CALLBACKS: LazyLock<Callbacks> =
    LazyLock::new(|| Callbacks::new(FindElf::BUILD_ID, FindDebuginfo::STANDARD));

struct OwnedElf(*mut crate::dw_sys::Elf);

impl Drop for OwnedElf {
    fn drop(&mut self) {
        unsafe {
            crate::dw_sys::elf_end(self.0);
        }
    }
}

struct CoreResources {
    _elf: OwnedElf,     // dropped first
    _fd: std::fs::File, // dropped second (keeps fd alive while elf uses it)
}

pub struct State {
    dwfl: Dwfl<'static>,
    _core: Option<CoreResources>, // dropped after dwfl
}

impl State {
    pub fn new(pid: u32) -> Result<State, Error> {
        let mut dwfl = Dwfl::begin(&CALLBACKS)?;
        dwfl.report().linux_proc(pid)?;
        dwfl.linux_proc_attach(pid, true)?;
        Ok(State { dwfl, _core: None })
    }

    pub fn new_core(fd: std::fs::File) -> Result<State, Error> {
        unsafe {
            crate::dw_sys::elf_version(1); // EV_CURRENT
        }

        let elf_ptr = unsafe {
            crate::dw_sys::elf_begin(
                fd.as_raw_fd(),
                crate::dw_sys::ELF_C_READ_MMAP,
                std::ptr::null_mut(),
            )
        };
        if elf_ptr.is_null() {
            return Err(Error::new());
        }
        let elf = OwnedElf(elf_ptr);

        let mut dwfl = Dwfl::begin(&CORE_CALLBACKS)?;
        unsafe {
            dwfl.report().core_file(elf.0)?;
            dwfl.core_file_attach(elf.0)?;
        }

        Ok(State {
            dwfl,
            _core: Some(CoreResources { _elf: elf, _fd: fd }),
        })
    }

    pub fn pid(&self) -> u32 {
        self.dwfl.pid()
    }

    pub fn trace_threads(
        &mut self,
        options: &TraceOptions,
        thread_name: &dyn Fn(u32) -> Option<String>,
    ) -> Vec<super::Thread> {
        let mut threads = Vec::new();
        let result = self.dwfl.threads(|thread_ref| {
            let tid = thread_ref.tid();
            let mut frames = Vec::new();
            let frame_result = thread_ref.frames(|frame| {
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
            });
            if let Err(e) = frame_result {
                eprintln!("error tracing thread {}: {}", tid, e);
            }
            let name = if options.thread_names {
                thread_name(tid)
            } else {
                None
            };
            threads.push(super::Thread {
                id: tid,
                name,
                frames,
            });
            Ok(())
        });
        if let Err(e) = result {
            eprintln!("error enumerating threads: {}", e);
        }
        threads
    }
}

impl TracedThread {
    pub fn dump_inner(
        &self,
        dwfl: &mut State,
        options: &TraceOptions,
        frames: &mut Vec<Frame>,
    ) -> Result<(), Error> {
        dwfl.dwfl.thread_frames(self.id, |frame| {
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
