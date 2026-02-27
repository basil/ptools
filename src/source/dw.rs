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

//! Internal dwfl session management for stack frame walking.
//!
//! This module encapsulates all interactions with libdw/libdwfl within the
//! source layer.  It is `pub(super)` -- visible only within the `source`
//! module, so no dwfl types or ELF pointers leak to the rest of the crate.

pub(super) use crate::dw::dwfl::Dwfl;
use crate::dw::dwfl::{Callbacks, FindDebuginfo, FindElf, ModuleRef};
use crate::stack::{Frame, SourceLocation, Symbol, TraceOptions};
use std::cell::RefCell;
use std::ffi::CStr;
use std::os::raw::c_int;
use std::sync::{Arc, LazyLock};

use nix::libc;

use super::elf::CoreElf;

// ---------------------------------------------------------------------------
// Dwfl session constructors
// ---------------------------------------------------------------------------

static CALLBACKS: LazyLock<Callbacks> =
    LazyLock::new(|| Callbacks::new(FindElf::LINUX_PROC, FindDebuginfo::STANDARD));

static CORE_CALLBACKS: LazyLock<Callbacks> =
    LazyLock::new(|| Callbacks::new(FindElf::BUILD_ID, FindDebuginfo::STANDARD));

/// Create a dwfl session for a core dump.
///
/// # Safety
///
/// The returned `Dwfl` borrows from `core_elf` internally (via the raw ELF
/// pointer).  The caller must ensure that the `CoreElf` outlives the `Dwfl`.
unsafe fn create_dwfl_core(core_elf: &CoreElf) -> Result<Dwfl<'static>, crate::dw::dwfl::Error> {
    let elf_ptr = core_elf.as_elf_ptr();
    let mut dwfl = Dwfl::begin(&CORE_CALLBACKS)?;
    dwfl.report().core_file(elf_ptr)?;
    dwfl.core_file_attach(elf_ptr)?;
    Ok(dwfl)
}

/// Owns a dwfl session together with the `CoreElf` it borrows from.
///
/// # Drop ordering
///
/// `dwfl` is declared before `_core_elf` so Rust drops it first.
/// This is critical because the dwfl session holds a raw pointer into
/// the ELF data owned by `CoreElf`.
pub(super) struct CoreDwfl {
    dwfl: RefCell<Dwfl<'static>>,
    _core_elf: Arc<CoreElf>,
}

impl CoreDwfl {
    pub(super) fn new(core_elf: Arc<CoreElf>) -> Result<Self, crate::dw::dwfl::Error> {
        // SAFETY: `core_elf` is moved into `_core_elf` below, and `dwfl` is
        // declared before `_core_elf` so it is dropped first -- guaranteeing
        // the `CoreElf` outlives the `Dwfl`.
        let dwfl = unsafe { create_dwfl_core(&core_elf)? };
        Ok(CoreDwfl {
            dwfl: RefCell::new(dwfl),
            _core_elf: core_elf,
        })
    }

    pub(super) fn pid(&self) -> u32 {
        self.dwfl.borrow().pid()
    }

    pub(super) fn collect_tids(&self) -> Result<Vec<u64>, crate::dw::dwfl::Error> {
        collect_tids(&mut self.dwfl.borrow_mut())
    }

    pub(super) fn walk_thread_frames(
        &self,
        tid: u32,
        options: &TraceOptions,
    ) -> Result<Vec<Frame>, crate::dw::dwfl::Error> {
        walk_thread_frames(&mut self.dwfl.borrow_mut(), tid, options)
    }
}

/// Create a dwfl session for a live process.
///
/// The process's threads must already be ptrace-stopped before calling
/// `walk_thread_frames`.
pub(super) fn create_dwfl_live(pid: u32) -> Result<Dwfl<'static>, crate::dw::dwfl::Error> {
    let mut dwfl = Dwfl::begin(&CALLBACKS)?;
    dwfl.report().linux_proc(pid)?;
    dwfl.linux_proc_attach(pid, true)?;
    Ok(dwfl)
}

// ---------------------------------------------------------------------------
// Thread enumeration (core dumps)
// ---------------------------------------------------------------------------

/// Collect all thread IDs from the dwfl session.
pub(super) fn collect_tids(dwfl: &mut Dwfl<'static>) -> Result<Vec<u64>, crate::dw::dwfl::Error> {
    let mut tids = Vec::new();
    dwfl.threads(|thread_ref| {
        tids.push(thread_ref.tid() as u64);
        Ok(())
    })?;
    Ok(tids)
}

// ---------------------------------------------------------------------------
// Frame walking
// ---------------------------------------------------------------------------

/// Walk and symbolize frames for one thread.
pub(super) fn walk_thread_frames(
    dwfl: &mut Dwfl<'static>,
    tid: u32,
    options: &TraceOptions,
) -> Result<Vec<Frame>, crate::dw::dwfl::Error> {
    let mut frames = Vec::new();
    dwfl.thread_frames(tid, |frame| {
        let mut is_signal = false;
        let ip = frame.pc(Some(&mut is_signal))?;

        let signal_adjust = if is_signal { 0 } else { 1 };
        let lookup_pc = frame_lookup_pc(ip, is_signal);
        let pc_adjusted = lookup_pc.unwrap_or(ip);
        let module = lookup_pc.and_then(|pc| frame.thread().dwfl().addr_module(pc).ok());

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
    })?;
    Ok(frames)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Demangle a C++ or Rust symbol name, returning `None` if the name is not
/// mangled or demangling fails.
fn demangle(name: &str) -> Option<String> {
    // Try C++ Itanium ABI demangling (_Z prefix).
    if name.starts_with("_Z") {
        if let Ok(sym) = cpp_demangle::Symbol::new(name) {
            let opts = cpp_demangle::DemangleOptions::new().no_params();
            if let Ok(s) = sym.demangle_with_options(&opts) {
                return Some(s);
            }
        }
    }
    // Try Rust symbol demangling (_R prefix for v0, _ZN...E for legacy).
    let demangled = rustc_demangle::try_demangle(name).ok()?;
    // Alternate format omits the hash suffix.
    Some(format!("{:#}", demangled))
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

fn frame_lookup_pc(ip: u64, is_signal: bool) -> Option<u64> {
    if is_signal {
        Some(ip)
    } else {
        ip.checked_sub(1)
    }
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
    if options.max_frames > 0 && frames.len() >= options.max_frames {
        return;
    }

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
    // We reuse the scopes array from dwarf_getscopes directly: starting from
    // the function DIE index, the remaining entries are exactly the parent
    // scope chain. This avoids calling dwarf_getscopes_die which would do
    // another expensive full-CU tree walk.
    let mut func_scope_idx = None;
    let mut debug_name = None;
    unsafe {
        for i in 0..nscopes as usize {
            let scope = scopes_ptr.add(i);
            let tag = crate::dw_sys::dwarf_tag(scope);
            if is_function_tag(tag) {
                debug_name = die_name(scope);
                if debug_name.is_some() {
                    func_scope_idx = Some(i);
                }
                break;
            }
        }
    }

    let (func_idx, raw_name) = match (func_scope_idx, debug_name) {
        (Some(idx), Some(name)) => (idx, name),
        _ => {
            unsafe { libc::free(scopes_ptr.cast()) };
            return None;
        }
    };

    let parent_scopes_ptr = unsafe { scopes_ptr.add(func_idx) };
    let nparent = nscopes - func_idx as c_int;

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
            libc::free(scopes_ptr.cast());
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

        libc::free(scopes_ptr.cast());
    }

    Some(result)
}
