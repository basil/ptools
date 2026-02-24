//
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

use libc::{c_char, c_int, c_void, pid_t};

use super::super::*;
use super::libdwfl::{Dwfl, Dwfl_Callbacks, Dwfl_Module};

pub enum Dwflst_Process_Tracker {}

extern "C" {
    pub fn dwflst_tracker_begin(callbacks: *const Dwfl_Callbacks) -> *mut Dwflst_Process_Tracker;

    pub fn dwflst_tracker_dwfl_begin(tracker: *mut Dwflst_Process_Tracker) -> *mut Dwfl;

    pub fn dwflst_tracker_find_pid(
        tracker: *mut Dwflst_Process_Tracker,
        pid: pid_t,
        callback: Option<
            unsafe extern "C" fn(
                tracker: *mut Dwflst_Process_Tracker,
                pid: pid_t,
                arg: *mut c_void,
            ) -> *mut Dwfl,
        >,
        arg: *mut c_void,
    ) -> *mut Dwfl;

    pub fn dwflst_tracker_linux_proc_find_elf(
        mod_: *mut Dwfl_Module,
        userdata: *mut *mut c_void,
        module_name: *const c_char,
        base: Dwarf_Addr,
        file_name: *mut *mut c_char,
        elfp: *mut *mut Elf,
    ) -> c_int;

    pub fn dwflst_tracker_end(tracker: *mut Dwflst_Process_Tracker);
}
