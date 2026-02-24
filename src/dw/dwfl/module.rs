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
use std::ptr;

use super::super::elf::Symbol;
use super::Error;

/// A reference to a module.
pub struct ModuleRef(Opaque);

unsafe impl ForeignTypeRef for ModuleRef {
    type CType = crate::dw_sys::Dwfl_Module;
}

impl ModuleRef {
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
