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

use foreign_types::{ForeignTypeRef, Opaque};
use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_int;
use std::ptr;

use super::super::elf::Symbol;
use super::Error;

/// A reference to a module.
pub struct ModuleRef(Opaque);

unsafe impl ForeignTypeRef for ModuleRef {
    type CType = crate::dw_sys::Dwfl_Module;
}

impl ModuleRef {
    /// Returns the module name (e.g. the shared library path).
    pub fn name(&self) -> Option<&CStr> {
        unsafe {
            let name = crate::dw_sys::dwfl_module_info(
                self.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if name.is_null() {
                None
            } else {
                Some(CStr::from_ptr(name))
            }
        }
    }

    /// Returns source file and line number for an address, if available.
    pub fn getsrc(&self, addr: u64) -> Option<SourceLine<'_>> {
        unsafe {
            let line = crate::dw_sys::dwfl_module_getsrc(self.as_ptr(), addr);
            if line.is_null() {
                return None;
            }
            let mut lineno: libc::c_int = 0;
            let file = crate::dw_sys::dwfl_lineinfo(
                line,
                ptr::null_mut(),
                &mut lineno,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if file.is_null() {
                return None;
            }
            Some(SourceLine {
                file: CStr::from_ptr(file),
                line: lineno,
                _module: PhantomData,
            })
        }
    }

    /// Returns the name of the containing the address.
    pub fn addr_name(&self, addr: u64) -> Result<&CStr, Error> {
        unsafe {
            let ptr = crate::dw_sys::dwfl_module_addrname(self.as_ptr(), addr);
            if ptr.is_null() {
                Err(Error::new())
            } else {
                Ok(CStr::from_ptr(ptr))
            }
        }
    }

    /// Returns the CU DIE and bias for an address in this module.
    ///
    /// The returned `Dwarf_Die` is the compilation unit DIE that covers `addr`.
    /// The bias is the relocation offset applied to the module.
    pub fn addrdie(&self, addr: u64) -> Option<(crate::dw_sys::Dwarf_Die, u64)> {
        unsafe {
            let mut bias: crate::dw_sys::Dwarf_Addr = 0;
            let result = crate::dw_sys::dwfl_module_addrdie(self.as_ptr(), addr, &mut bias);
            if result.is_null() {
                None
            } else {
                Some((*result, bias))
            }
        }
    }

    /// Returns the DWARF scopes (DIEs) containing the given PC within this
    /// module's compilation unit DIE.
    ///
    /// Returns the scope array and its length on success. The caller must
    /// free the returned pointer with `libc::free`.
    pub fn getscopes(
        &self,
        cudie: &mut crate::dw_sys::Dwarf_Die,
        pc: u64,
    ) -> Option<(*mut crate::dw_sys::Dwarf_Die, c_int)> {
        unsafe {
            let mut scopes: *mut crate::dw_sys::Dwarf_Die = ptr::null_mut();
            let n = crate::dw_sys::dwarf_getscopes(cudie, pc, &mut scopes);
            if n <= 0 {
                None
            } else {
                Some((scopes, n))
            }
        }
    }

    /// Returns information about the symbol containing the address.
    pub fn addr_info(&self, addr: u64) -> Result<AddrInfo<'_>, Error> {
        unsafe {
            let mut offset = 0;
            let mut sym = mem::zeroed::<crate::dw_sys::GElf_Sym>();
            let mut bias = 0;

            let ptr = crate::dw_sys::dwfl_module_addrinfo(
                self.as_ptr(),
                addr,
                &mut offset,
                &mut sym,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut bias,
            );

            if ptr.is_null() {
                Err(Error::new())
            } else {
                Ok(AddrInfo {
                    name: ptr,
                    offset,
                    sym: Symbol(sym),
                    bias,
                    _module: PhantomData,
                })
            }
        }
    }
}

/// Information about a symbol.
pub struct AddrInfo<'a> {
    name: *const libc::c_char,
    offset: u64,
    sym: Symbol,
    bias: u64,
    _module: PhantomData<&'a ModuleRef>,
}

/// Source file and line number for an address.
pub struct SourceLine<'a> {
    file: &'a CStr,
    line: libc::c_int,
    _module: PhantomData<&'a ModuleRef>,
}

impl<'a> SourceLine<'a> {
    /// Returns the source file path.
    pub fn file(&self) -> &'a CStr {
        self.file
    }

    /// Returns the line number, or 0 if unknown.
    pub fn line(&self) -> i32 {
        self.line
    }
}

impl<'a> AddrInfo<'a> {
    /// Returns the name of the symbol.
    pub fn name(&self) -> &'a CStr {
        // SAFETY: The pointer comes from dwfl_module_addrinfo and remains valid
        // for the lifetime of the module, which outlives 'a.
        unsafe { CStr::from_ptr(self.name) }
    }

    /// Returns the offset of the address from the base of the symbol.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the (unadjusted) symbol itself.
    pub fn symbol(&self) -> &Symbol {
        &self.sym
    }

    /// Returns the offset of the symbol's address to where it was loaded in memory.
    pub fn bias(&self) -> u64 {
        self.bias
    }
}
