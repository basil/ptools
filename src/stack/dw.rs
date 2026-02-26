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
use crate::dw::dwfl::{Callbacks, Dwfl, FindDebuginfo, FindElf, FrameRef, ModuleRef};
use std::ffi::CStr;
use std::os::raw::c_int;
use std::sync::LazyLock;

use super::{Argument, Frame, FrameArgs, SourceLocation, Symbol, TraceOptions, TracedThread};

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

/// Result of evaluating a DWARF location expression.
struct LocationResult {
    value: u64,
    is_value: bool, // true = the value itself, false = memory address to read from
}

/// Evaluate a simple DWARF location expression using frame registers.
#[allow(non_upper_case_globals)]
fn eval_location(
    ops: *mut crate::dw_sys::Dwarf_Op,
    nops: usize,
    frame: &FrameRef,
) -> Option<LocationResult> {
    use crate::dw_sys::*;

    if nops == 0 {
        return None;
    }

    let mut stack: Vec<u64> = Vec::new();
    let mut is_value = false;

    unsafe {
        for i in 0..nops {
            let op = &*ops.add(i);
            let atom = op.atom;

            match atom {
                DW_OP_addr => {
                    stack.push(op.number);
                }
                DW_OP_reg0..=DW_OP_reg31 => {
                    let regno = (atom - DW_OP_reg0) as u32;
                    stack.push(frame.reg(regno)?);
                    is_value = true;
                }
                DW_OP_regx => {
                    stack.push(frame.reg(op.number as u32)?);
                    is_value = true;
                }
                DW_OP_breg0..=DW_OP_breg31 => {
                    let regno = (atom - DW_OP_breg0) as u32;
                    let regval = frame.reg(regno)?;
                    stack.push(regval.wrapping_add(op.number));
                }
                DW_OP_bregx => {
                    let regval = frame.reg(op.number as u32)?;
                    stack.push(regval.wrapping_add(op.number2));
                }
                DW_OP_fbreg => {
                    // Frame base - approximate with CFA (RBP-based or RSP-based)
                    // On x86_64, CFA is typically RSP at call site or RBP+16
                    // Try CFA register (register 7 = RSP on x86_64, but CFA
                    // isn't directly a register). Use RBP+16 as common approximation.
                    let rbp = frame.reg(6)?; // RBP
                    let cfa = rbp.wrapping_add(16);
                    stack.push(cfa.wrapping_add(op.number));
                }
                DW_OP_call_frame_cfa => {
                    let rbp = frame.reg(6)?; // RBP
                    let cfa = rbp.wrapping_add(16);
                    stack.push(cfa);
                }
                DW_OP_stack_value => {
                    is_value = true;
                }
                DW_OP_piece => {
                    // Composite location - just use what we have
                    break;
                }
                DW_OP_deref => {
                    // Would need memory read - skip for now
                    return None;
                }
                DW_OP_plus_uconst => {
                    let top = stack.pop()?;
                    stack.push(top.wrapping_add(op.number));
                }
                DW_OP_constu | DW_OP_const1u | DW_OP_const2u | DW_OP_const4u | DW_OP_const8u => {
                    stack.push(op.number);
                }
                DW_OP_consts | DW_OP_const1s | DW_OP_const2s | DW_OP_const4s | DW_OP_const8s => {
                    stack.push(op.number);
                }
                _ => {
                    // Unsupported operation
                    return None;
                }
            }
        }
    }

    stack
        .last()
        .map(|&value| LocationResult { value, is_value })
}

/// Chase through type modifiers (const, volatile, typedef, etc.) to the underlying type.
unsafe fn peel_type(die: *mut crate::dw_sys::Dwarf_Die) -> Option<crate::dw_sys::Dwarf_Die> {
    let mut result = std::mem::zeroed::<crate::dw_sys::Dwarf_Die>();
    if crate::dw_sys::dwarf_peel_type(die, &mut result) == 0 {
        Some(result)
    } else {
        None
    }
}

/// Check if a DWARF type DIE (after peeling) is a char type (1-byte signed/unsigned char).
unsafe fn is_char_type(die: &mut crate::dw_sys::Dwarf_Die) -> bool {
    let tag = crate::dw_sys::dwarf_tag(die);
    if tag != crate::dw_sys::DW_TAG_base_type {
        return false;
    }
    let size = crate::dw_sys::dwarf_bytesize(die);
    if size != 1 {
        return false;
    }
    let mut attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();
    let mut encoding: crate::dw_sys::Dwarf_Word = 0;
    let attr_ptr = crate::dw_sys::dwarf_attr(die, crate::dw_sys::DW_AT_encoding, &mut attr);
    if attr_ptr.is_null() || crate::dw_sys::dwarf_formudata(attr_ptr, &mut encoding) != 0 {
        return false;
    }
    matches!(
        encoding as u32,
        crate::dw_sys::DW_ATE_signed_char
            | crate::dw_sys::DW_ATE_unsigned_char
            | crate::dw_sys::DW_ATE_signed
            | crate::dw_sys::DW_ATE_unsigned
            | crate::dw_sys::DW_ATE_UTF
    )
}

/// Check if a pointer/reference type points to a char type.
unsafe fn points_to_char(type_die: &mut crate::dw_sys::Dwarf_Die) -> bool {
    let mut attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();
    let ta = crate::dw_sys::dwarf_attr(type_die, crate::dw_sys::DW_AT_type, &mut attr);
    if ta.is_null() {
        return false;
    }
    let mut pointee = std::mem::zeroed::<crate::dw_sys::Dwarf_Die>();
    if crate::dw_sys::dwarf_formref_die(ta, &mut pointee).is_null() {
        return false;
    }
    // Peel through const/volatile/typedef
    let mut peeled = peel_type(&mut pointee).unwrap_or(pointee);
    is_char_type(&mut peeled)
}

/// Read a NUL-terminated string from process memory.
///
/// Returns the string (truncated to 256 chars with "..." if longer).
fn read_remote_string(addr: u64, read_mem: &dyn Fn(u64, &mut [u8]) -> bool) -> Option<String> {
    const MAX_DISPLAY: usize = 256;
    if addr == 0 {
        return None;
    }
    // Read one extra byte to detect truncation.
    let mut buf = vec![0u8; MAX_DISPLAY + 1];
    if !read_mem(addr, &mut buf) {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let (slice, truncated) = if end > MAX_DISPLAY {
        (&buf[..MAX_DISPLAY], true)
    } else {
        (&buf[..end], false)
    };
    let mut s = String::from_utf8_lossy(slice).into_owned();
    if truncated {
        s.push_str("...");
    }
    Some(s)
}

/// Format a value based on DWARF type information.
unsafe fn format_value(
    raw_bytes: &[u8],
    type_die: &mut crate::dw_sys::Dwarf_Die,
    read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
) -> String {
    let tag = crate::dw_sys::dwarf_tag(type_die);

    match tag {
        crate::dw_sys::DW_TAG_base_type => {
            let mut attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();
            let mut encoding: crate::dw_sys::Dwarf_Word = 0;
            let attr_ptr =
                crate::dw_sys::dwarf_attr(type_die, crate::dw_sys::DW_AT_encoding, &mut attr);
            if attr_ptr.is_null() || crate::dw_sys::dwarf_formudata(attr_ptr, &mut encoding) != 0 {
                return format!("{:#x}", u64_from_bytes(raw_bytes));
            }

            match encoding as u32 {
                crate::dw_sys::DW_ATE_signed | crate::dw_sys::DW_ATE_signed_char => {
                    match raw_bytes.len() {
                        1 => format!("{}", raw_bytes[0] as i8),
                        2 => format!("{}", i16::from_ne_bytes(raw_bytes[..2].try_into().unwrap())),
                        4 => format!("{}", i32::from_ne_bytes(raw_bytes[..4].try_into().unwrap())),
                        8 => format!("{}", i64::from_ne_bytes(raw_bytes[..8].try_into().unwrap())),
                        _ => format!("{:#x}", u64_from_bytes(raw_bytes)),
                    }
                }
                crate::dw_sys::DW_ATE_unsigned | crate::dw_sys::DW_ATE_unsigned_char => {
                    match raw_bytes.len() {
                        1 => format!("{}", raw_bytes[0]),
                        2 => format!("{}", u16::from_ne_bytes(raw_bytes[..2].try_into().unwrap())),
                        4 => format!("{}", u32::from_ne_bytes(raw_bytes[..4].try_into().unwrap())),
                        8 => format!("{}", u64::from_ne_bytes(raw_bytes[..8].try_into().unwrap())),
                        _ => format!("{:#x}", u64_from_bytes(raw_bytes)),
                    }
                }
                crate::dw_sys::DW_ATE_boolean => {
                    if raw_bytes.iter().any(|&b| b != 0) {
                        "true".to_string()
                    } else {
                        "false".to_string()
                    }
                }
                crate::dw_sys::DW_ATE_float => match raw_bytes.len() {
                    4 => format!("{}", f32::from_ne_bytes(raw_bytes[..4].try_into().unwrap())),
                    8 => format!("{}", f64::from_ne_bytes(raw_bytes[..8].try_into().unwrap())),
                    _ => format!("{:#x}", u64_from_bytes(raw_bytes)),
                },
                _ => format!("{:#x}", u64_from_bytes(raw_bytes)),
            }
        }
        crate::dw_sys::DW_TAG_pointer_type
        | crate::dw_sys::DW_TAG_reference_type
        | crate::dw_sys::DW_TAG_rvalue_reference_type => {
            let ptr_val = u64_from_bytes(raw_bytes);
            if points_to_char(type_die) {
                if let Some(s) = read_remote_string(ptr_val, read_mem) {
                    return format!("\"{s}\"");
                }
            }
            format!("{ptr_val:#x}")
        }
        crate::dw_sys::DW_TAG_enumeration_type => {
            // Show as integer
            match raw_bytes.len() {
                1 => format!("{}", raw_bytes[0] as i8),
                2 => format!("{}", i16::from_ne_bytes(raw_bytes[..2].try_into().unwrap())),
                4 => format!("{}", i32::from_ne_bytes(raw_bytes[..4].try_into().unwrap())),
                8 => format!("{}", i64::from_ne_bytes(raw_bytes[..8].try_into().unwrap())),
                _ => format!("{:#x}", u64_from_bytes(raw_bytes)),
            }
        }
        _ => format!("{:#x}", u64_from_bytes(raw_bytes)),
    }
}

fn u64_from_bytes(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = bytes.len().min(8);
    if cfg!(target_endian = "big") {
        buf[8 - len..].copy_from_slice(&bytes[..len]);
    } else {
        buf[..len].copy_from_slice(&bytes[..len]);
    }
    u64::from_ne_bytes(buf)
}

/// Collect function arguments from DWARF debug info for a frame.
fn collect_args(
    module: &ModuleRef,
    pc_adjusted: u64,
    frame: &FrameRef,
    read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
) -> FrameArgs {
    let Some((mut cudie, bias)) = module.addrdie(pc_adjusted) else {
        return FrameArgs::NoDebugInfo;
    };
    let Some((scopes_ptr, nscopes)) = module.getscopes(&mut cudie, pc_adjusted - bias) else {
        return FrameArgs::NoDebugInfo;
    };

    // Find the innermost function DIE
    let mut func_die = None;
    unsafe {
        for i in 0..nscopes as usize {
            let scope = scopes_ptr.add(i);
            let tag = crate::dw_sys::dwarf_tag(scope);
            if is_function_tag(tag) {
                func_die = Some(*scope);
                break;
            }
        }
        libc::free(scopes_ptr.cast());
    }

    let Some(mut fdie) = func_die else {
        return FrameArgs::NoDebugInfo;
    };

    // Check for abstract_origin (for inlined/optimized functions, the params
    // are on the abstract origin DIE)
    unsafe {
        let mut attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();
        let attr_ptr =
            crate::dw_sys::dwarf_attr(&mut fdie, crate::dw_sys::DW_AT_abstract_origin, &mut attr);
        if !attr_ptr.is_null() {
            let mut origin = std::mem::zeroed::<crate::dw_sys::Dwarf_Die>();
            if !crate::dw_sys::dwarf_formref_die(attr_ptr, &mut origin).is_null() {
                fdie = origin;
            }
        }
    }

    let mut args = Vec::new();

    unsafe {
        // Iterate children of the function DIE
        let mut child = std::mem::zeroed::<crate::dw_sys::Dwarf_Die>();
        if crate::dw_sys::dwarf_child(&mut fdie, &mut child) != 0 {
            return FrameArgs::Args(args);
        }

        loop {
            let tag = crate::dw_sys::dwarf_tag(&mut child);
            if tag == crate::dw_sys::DW_TAG_formal_parameter {
                if let Some(arg) = collect_one_arg(&mut child, frame, read_mem, pc_adjusted - bias)
                {
                    args.push(arg);
                }
            }
            // Stop at unspecified_parameters (variadic ...)
            if tag == crate::dw_sys::DW_TAG_unspecified_parameters {
                break;
            }

            let mut sib = std::mem::zeroed::<crate::dw_sys::Dwarf_Die>();
            if crate::dw_sys::dwarf_siblingof(&mut child, &mut sib) != 0 {
                break;
            }
            child = sib;
        }
    }

    FrameArgs::Args(args)
}

/// Collect a single formal parameter argument.
unsafe fn collect_one_arg(
    param_die: &mut crate::dw_sys::Dwarf_Die,
    frame: &FrameRef,
    read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
    pc: u64,
) -> Option<Argument> {
    // Get parameter name
    let name_ptr = crate::dw_sys::dwarf_diename(param_die);
    let name = if name_ptr.is_null() {
        return None;
    } else {
        CStr::from_ptr(name_ptr).to_string_lossy().into_owned()
    };

    // Get DW_AT_location
    let mut attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();
    let loc_attr =
        crate::dw_sys::dwarf_attr_integrate(param_die, crate::dw_sys::DW_AT_location, &mut attr);
    if loc_attr.is_null() {
        // Try DW_AT_const_value as fallback
        let cv_attr = crate::dw_sys::dwarf_attr_integrate(
            param_die,
            crate::dw_sys::DW_AT_const_value,
            &mut attr,
        );
        if cv_attr.is_null() {
            return None;
        }
        let mut val: crate::dw_sys::Dwarf_Word = 0;
        if crate::dw_sys::dwarf_formudata(cv_attr, &mut val) == 0 {
            return Some(Argument {
                name,
                value: format!("{val}"),
            });
        }
        let mut sval: crate::dw_sys::Dwarf_Sword = 0;
        if crate::dw_sys::dwarf_formsdata(cv_attr, &mut sval) == 0 {
            return Some(Argument {
                name,
                value: format!("{sval}"),
            });
        }
        return None;
    }

    // Evaluate location for the current PC
    let mut ops: *mut crate::dw_sys::Dwarf_Op = std::ptr::null_mut();
    let mut nops: libc::size_t = 0;
    let nlocs = crate::dw_sys::dwarf_getlocation_addr(loc_attr, pc, &mut ops, &mut nops, 1);
    if nlocs <= 0 || ops.is_null() || nops == 0 {
        return None;
    }

    let loc = eval_location(ops, nops, frame)?;

    // Get the type DIE
    let mut type_attr = std::mem::zeroed::<crate::dw_sys::Dwarf_Attribute>();
    let ta =
        crate::dw_sys::dwarf_attr_integrate(param_die, crate::dw_sys::DW_AT_type, &mut type_attr);
    if ta.is_null() {
        // No type info, just show raw value
        return Some(Argument {
            name,
            value: format!("{:#x}", loc.value),
        });
    }

    let mut type_die = std::mem::zeroed::<crate::dw_sys::Dwarf_Die>();
    if crate::dw_sys::dwarf_formref_die(ta, &mut type_die).is_null() {
        return Some(Argument {
            name,
            value: format!("{:#x}", loc.value),
        });
    }

    // Peel through typedefs/const/volatile to base type
    let mut peeled = peel_type(&mut type_die).unwrap_or(type_die);

    // Get type size
    let byte_size = crate::dw_sys::dwarf_bytesize(&mut peeled);
    let size = if byte_size > 0 {
        byte_size as usize
    } else {
        8 // default pointer size
    };

    if loc.is_value {
        // The value is directly in loc.value
        let bytes = loc.value.to_ne_bytes();
        let n = size.min(8);
        let used = if cfg!(target_endian = "big") {
            &bytes[8 - n..]
        } else {
            &bytes[..n]
        };
        let value = format_value(used, &mut peeled, read_mem);
        Some(Argument { name, value })
    } else {
        // loc.value is an address - read from process memory
        let mut buf = vec![0u8; size];
        if read_mem(loc.value, &mut buf) {
            let value = format_value(&buf, &mut peeled, read_mem);
            Some(Argument { name, value })
        } else {
            Some(Argument {
                name,
                value: format!("{:#x}", loc.value),
            })
        }
    }
}

/// Process a single physical frame into one or more logical frames (expanding inlines).
#[allow(clippy::too_many_arguments)]
fn process_frame(
    module: Option<&ModuleRef>,
    ip: u64,
    is_signal: bool,
    pc_adjusted: u64,
    signal_adjust: u64,
    options: &TraceOptions,
    frame: &FrameRef,
    read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
    frames: &mut Vec<Frame>,
) {
    if options.max_frames > 0 && frames.len() >= options.max_frames {
        return;
    }

    // Try inline expansion first
    if options.inlines {
        if let Some(m) = module {
            if let Some(inline_frames) = expand_inlines(
                m,
                ip,
                is_signal,
                pc_adjusted,
                signal_adjust,
                options,
                frame,
                read_mem,
            ) {
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

    let args = if options.args {
        if let Some(m) = module {
            Some(collect_args(m, pc_adjusted, frame, read_mem))
        } else {
            Some(FrameArgs::NoDebugInfo)
        }
    } else {
        None
    };

    frames.push(Frame {
        ip,
        is_signal,
        is_inline: false,
        symbol,
        module: module_name,
        source,
        args,
    });
}

/// Expand a physical frame into multiple logical frames using DWARF inline info.
///
/// Returns `None` if DWARF info is not available or the PC is not inside any
/// inlined subroutine (in which case the caller should fall back to a single frame).
#[allow(clippy::too_many_arguments)]
fn expand_inlines(
    module: &ModuleRef,
    ip: u64,
    is_signal: bool,
    pc_adjusted: u64,
    signal_adjust: u64,
    options: &TraceOptions,
    frame: &FrameRef,
    read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
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

        let args = if options.args {
            Some(collect_args(module, pc_adjusted, frame, read_mem))
        } else {
            None
        };

        result.push(Frame {
            ip,
            is_signal,
            is_inline: false,
            symbol,
            module: module_name.clone(),
            source,
            args,
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

            let args = if options.args {
                Some(FrameArgs::Args(vec![]))
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
                args,
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

static CALLBACKS: LazyLock<Callbacks> =
    LazyLock::new(|| Callbacks::new(FindElf::LINUX_PROC, FindDebuginfo::STANDARD));

static CORE_CALLBACKS: LazyLock<Callbacks> =
    LazyLock::new(|| Callbacks::new(FindElf::BUILD_ID, FindDebuginfo::STANDARD));

pub struct State {
    dwfl: Dwfl<'static>,
}

impl State {
    pub fn new(pid: u32) -> Result<State, Error> {
        let mut dwfl = Dwfl::begin(&CALLBACKS)?;
        dwfl.report().linux_proc(pid)?;
        dwfl.linux_proc_attach(pid, true)?;
        Ok(State { dwfl })
    }

    /// # Safety
    ///
    /// `elf_ptr` must remain valid for the lifetime of the returned `State`.
    pub unsafe fn new_core(elf_ptr: *mut crate::dw_sys::Elf) -> Result<State, Error> {
        let mut dwfl = Dwfl::begin(&CORE_CALLBACKS)?;
        dwfl.report().core_file(elf_ptr)?;
        dwfl.core_file_attach(elf_ptr)?;
        Ok(State { dwfl })
    }

    pub fn pid(&self) -> u32 {
        self.dwfl.pid()
    }

    pub fn trace_threads_each(
        &mut self,
        options: &TraceOptions,
        thread_name: &dyn Fn(u32) -> Option<String>,
        read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
        each: &mut dyn FnMut(super::Thread),
        handle: &crate::ProcHandle,
    ) {
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
                    frame,
                    read_mem,
                    &mut frames,
                );

                Ok(())
            });
            if let Err(e) = frame_result {
                handle.push_warning(format!("error tracing thread {}: {}", tid, e));
            }
            let name = if options.thread_names {
                thread_name(tid)
            } else {
                None
            };
            each(super::Thread {
                id: tid,
                name,
                frames,
            });
            Ok(())
        });
        if let Err(e) = result {
            handle.push_warning(format!("error enumerating threads: {}", e));
        }
    }
}

impl TracedThread {
    pub fn dump_inner(
        &self,
        dwfl: &mut State,
        options: &TraceOptions,
        read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
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
                frame,
                read_mem,
                frames,
            );

            Ok(())
        })
    }
}
