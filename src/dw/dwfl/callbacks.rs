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

use libc::{c_char, c_int, c_void};
use std::ptr;

/// Callbacks used to configure the behavior of a `Dwfl`.
pub struct Callbacks(crate::dw_sys::Dwfl_Callbacks);

unsafe impl Sync for Callbacks {}
unsafe impl Send for Callbacks {}

impl Callbacks {
    /// Creates a new callback set.
    ///
    /// The find_elf and find_debuginfo callbacks are required. The section address callback and debuginfo_path
    /// value are initialized to NULL.
    pub fn new(find_elf: FindElf, find_debuginfo: FindDebuginfo) -> Callbacks {
        Callbacks(crate::dw_sys::Dwfl_Callbacks {
            find_elf: Some(find_elf.0),
            find_debuginfo: Some(find_debuginfo.0),
            section_address: None,
            debuginfo_path: ptr::null_mut(),
        })
    }

    /// Returns the pointer representation of the callbacks.
    pub fn as_ptr(&self) -> *mut crate::dw_sys::Dwfl_Callbacks {
        &self.0 as *const _ as *mut _
    }
}

/// The callback responsible for locating the ELF images of a process.
#[derive(Copy, Clone)]
pub struct FindElf(
    unsafe extern "C" fn(
        *mut crate::dw_sys::Dwfl_Module,
        *mut *mut c_void,
        *const c_char,
        crate::dw_sys::Dwarf_Addr,
        *mut *mut c_char,
        *mut *mut crate::dw_sys::Elf,
    ) -> c_int,
);

impl FindElf {
    /// A standard callback used with `Register::linux_proc`.
    pub const LINUX_PROC: FindElf = FindElf(crate::dw_sys::dwfl_linux_proc_find_elf);

    /// A callback that caches Elf lookups via a `ProcessTracker`.
    pub const TRACKER_LINUX_PROC: FindElf =
        FindElf(crate::dw_sys::dwflst_tracker_linux_proc_find_elf);
}

/// The callback responsible for locating the debuginfo of a process.
#[derive(Copy, Clone)]
pub struct FindDebuginfo(
    unsafe extern "C" fn(
        *mut crate::dw_sys::Dwfl_Module,
        *mut *mut c_void,
        *const c_char,
        crate::dw_sys::Dwarf_Addr,
        *const c_char,
        *const c_char,
        crate::dw_sys::GElf_Word,
        *mut *mut c_char,
    ) -> c_int,
);

impl FindDebuginfo {
    /// The standard callback.
    pub const STANDARD: FindDebuginfo = FindDebuginfo(crate::dw_sys::dwfl_standard_find_debuginfo);
}
