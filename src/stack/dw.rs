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
use crate::dw::dwfl::{Callbacks, Dwfl, FindDebuginfo, FindElf, ModuleRef};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::os::unix::io::AsRawFd;
use std::sync::LazyLock;

use super::{Frame, SourceLocation, Symbol, TraceOptions, TracedThread};

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

/// Get the linkage name or plain name of a DWARF DIE, matching elfutils die_name().
///
/// Checks DW_AT_MIPS_linkage_name, DW_AT_linkage_name, then dwarf_diename().
unsafe fn die_name(die: *mut crate::dw_sys::Dwarf_Die) -> Option<String> {
    let mut attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();

    let mut name = crate::dw_sys::dwarf_formstring(crate::dw_sys::dwarf_attr_integrate(
        die,
        crate::dw_sys::DW_AT_MIPS_linkage_name,
        &mut attr,
    ));
    if name.is_null() {
        name = crate::dw_sys::dwarf_formstring(crate::dw_sys::dwarf_attr_integrate(
            die,
            crate::dw_sys::DW_AT_linkage_name,
            &mut attr,
        ));
    }
    if name.is_null() {
        name = crate::dw_sys::dwarf_diename(die);
    }
    if name.is_null() {
        None
    } else {
        Some(CStr::from_ptr(name).to_string_lossy().into_owned())
    }
}

/// Get the call-site source location from DW_AT_call_file/DW_AT_call_line on a DIE.
unsafe fn call_site_source(
    cudie: *mut crate::dw_sys::Dwarf_Die,
    die: *mut crate::dw_sys::Dwarf_Die,
) -> Option<SourceLocation> {
    let mut files: *mut crate::dw_sys::Dwarf_Files = std::ptr::null_mut();
    if crate::dw_sys::dwarf_getsrcfiles(cudie, &mut files, std::ptr::null_mut()) != 0 {
        return None;
    }

    let mut attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();
    let mut val: crate::dw_sys::Dwarf_Word = 0;

    let attr_ptr = crate::dw_sys::dwarf_attr(die, crate::dw_sys::DW_AT_call_file, &mut attr);
    if attr_ptr.is_null() || crate::dw_sys::dwarf_formudata(attr_ptr, &mut val) != 0 {
        return None;
    }

    let file_ptr = crate::dw_sys::dwarf_filesrc(
        files,
        val as libc::size_t,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if file_ptr.is_null() {
        return None;
    }
    let file = CStr::from_ptr(file_ptr).to_string_lossy().into_owned();

    let mut line = 0i32;
    let attr_ptr = crate::dw_sys::dwarf_attr(die, crate::dw_sys::DW_AT_call_line, &mut attr);
    if !attr_ptr.is_null() && crate::dw_sys::dwarf_formudata(attr_ptr, &mut val) == 0 {
        line = val as i32;
    }

    Some(SourceLocation { file, line })
}

fn is_function_tag(tag: c_int) -> bool {
    tag == crate::dw_sys::DW_TAG_subprogram
        || tag == crate::dw_sys::DW_TAG_inlined_subroutine
        || tag == crate::dw_sys::DW_TAG_entry_point
}

/// Process a single physical frame into one or more logical frames (expanding inlines).
fn process_frame(
    module: Option<&ModuleRef>,
    ip: u64,
    is_signal: bool,
    pc_adjusted: u64,
    signal_adjust: u64,
    options: &TraceOptions,
    frames: &mut Vec<Frame>,
) {
    // Try inline expansion first
    if options.inlines {
        if let Some(m) = module {
            if let Some(inline_frames) =
                expand_inlines(m, ip, is_signal, pc_adjusted, signal_adjust, options)
            {
                frames.extend(inline_frames);
                return;
            }
        }
    }

    // Fallback: single frame with regular info
    let mut symbol = None;
    if options.symbols {
        if let Some(Ok(i)) = module.map(|m| m.addr_info(pc_adjusted)) {
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

    let mut module_name = None;
    if options.module {
        module_name = module
            .and_then(|m| m.name())
            .map(|n| n.to_string_lossy().into_owned());
    }

    let mut source = None;
    if options.source {
        if let Some(src) = module.and_then(|m| m.getsrc(pc_adjusted)) {
            let file = src.file().to_string_lossy().into_owned();
            let line = src.line();
            source = Some(SourceLocation { file, line });
        }
    }

    frames.push(Frame {
        ip,
        is_signal,
        is_inline: false,
        symbol,
        module: module_name,
        source,
    });
}

/// Expand a physical frame into multiple logical frames using DWARF inline info.
///
/// Returns `None` if DWARF info is not available or the PC is not inside any
/// inlined subroutine (in which case the caller should fall back to a single frame).
fn expand_inlines(
    module: &ModuleRef,
    ip: u64,
    is_signal: bool,
    pc_adjusted: u64,
    signal_adjust: u64,
    options: &TraceOptions,
) -> Option<Vec<Frame>> {
    let (mut cudie, bias) = module.addrdie(pc_adjusted)?;
    let (scopes_ptr, nscopes) = module.getscopes(&mut cudie, pc_adjusted - bias)?;

    // Find the innermost function-like DIE and its name.
    let mut innermost_die = None;
    let mut debug_name = None;
    unsafe {
        for i in 0..nscopes as usize {
            let scope = scopes_ptr.add(i);
            let tag = crate::dw_sys::dwarf_tag(scope);
            if is_function_tag(tag) {
                debug_name = die_name(scope);
                if debug_name.is_some() {
                    innermost_die = Some(*scope);
                }
                break;
            }
        }
        libc::free(scopes_ptr.cast());
    }

    let mut die = innermost_die?;
    let raw_name = debug_name?;

    // Get the parent scope chain from the innermost DIE.
    let mut parent_scopes_ptr: *mut crate::dw_sys::Dwarf_Die = std::ptr::null_mut();
    let nparent = unsafe { crate::dw_sys::dwarf_getscopes_die(&mut die, &mut parent_scopes_ptr) };
    if nparent <= 0 {
        return None;
    }

    let module_name = if options.module {
        module.name().map(|n| n.to_string_lossy().into_owned())
    } else {
        None
    };

    // Get symbol info from the ELF symbol table for offset/address/size.
    let sym_info = if options.symbols {
        module.addr_info(pc_adjusted).ok()
    } else {
        None
    };

    let mut result = Vec::new();
    let mut has_inlines = false;

    unsafe {
        // Check if there are any inlined_subroutine scopes in the parent chain.
        // If not, return None so the caller uses normal (non-inline) processing.
        for i in 1..nparent as usize {
            let scope = parent_scopes_ptr.add(i);
            let tag = crate::dw_sys::dwarf_tag(scope);
            if tag == crate::dw_sys::DW_TAG_inlined_subroutine {
                has_inlines = true;
                break;
            }
            if tag == crate::dw_sys::DW_TAG_subprogram {
                break;
            }
        }

        if !has_inlines {
            libc::free(parent_scopes_ptr.cast());
            return None;
        }

        // Frame 0: the innermost function (actual source location)
        let name = if options.demangle {
            demangle(&raw_name).unwrap_or(raw_name)
        } else {
            raw_name
        };

        let symbol = if options.symbols {
            Some(Symbol {
                name: name.clone(),
                offset: sym_info.as_ref().map_or(0, |i| i.offset() + signal_adjust),
                address: sym_info
                    .as_ref()
                    .map_or(0, |i| i.bias() + i.symbol().value()),
                size: sym_info.as_ref().map_or(0, |i| i.symbol().size()),
            })
        } else {
            None
        };

        let mut source = None;
        if options.source {
            if let Some(src) = module.getsrc(pc_adjusted) {
                let file = src.file().to_string_lossy().into_owned();
                let line = src.line();
                source = Some(SourceLocation { file, line });
            }
        }

        result.push(Frame {
            ip,
            is_signal,
            is_inline: false,
            symbol,
            module: module_name.clone(),
            source,
        });

        // Walk parent scopes for inlined callers.
        let mut last_scope = parent_scopes_ptr; // scopes[0] == the innermost die
        for i in 1..nparent as usize {
            let scope = parent_scopes_ptr.add(i);
            let tag = crate::dw_sys::dwarf_tag(scope);
            if !is_function_tag(tag) {
                continue;
            }

            let scope_name = die_name(scope);
            let name = match scope_name {
                Some(n) => {
                    if options.demangle {
                        demangle(&n).unwrap_or(n)
                    } else {
                        n
                    }
                }
                None => "???".to_string(),
            };

            let symbol = if options.symbols {
                Some(Symbol {
                    name,
                    offset: 0,
                    address: 0,
                    size: 0,
                })
            } else {
                None
            };

            let source = if options.source {
                call_site_source(&mut cudie, last_scope)
            } else {
                None
            };

            result.push(Frame {
                ip,
                is_signal: false,
                is_inline: true,
                symbol,
                module: module_name.clone(),
                source,
            });

            if tag == crate::dw_sys::DW_TAG_subprogram {
                break;
            }

            last_scope = scope;
        }

        libc::free(parent_scopes_ptr.cast());
    }

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

                let signal_adjust = if is_signal { 0 } else { 1 };
                let pc_adjusted = ip - signal_adjust;
                let module = frame.thread().dwfl().addr_module(pc_adjusted).ok();

                process_frame(
                    module,
                    ip,
                    is_signal,
                    pc_adjusted,
                    signal_adjust,
                    options,
                    &mut frames,
                );

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

            let signal_adjust = if is_signal { 0 } else { 1 };
            let pc_adjusted = ip - signal_adjust;
            let module = frame.thread().dwfl().addr_module(pc_adjusted).ok();

            process_frame(
                module,
                ip,
                is_signal,
                pc_adjusted,
                signal_adjust,
                options,
                frames,
            );

            Ok(())
        })
    }
}
