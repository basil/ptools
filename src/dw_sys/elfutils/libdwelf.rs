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

use libc::{c_char, c_void, size_t, ssize_t};

use super::super::*;

pub enum Dwelf_Strtab {}
pub enum Dwelf_Strent {}

extern "C" {
    pub fn dwelf_elf_gnu_debuglink(elf: *mut Elf, crc: *mut GElf_Word) -> *const c_char;

    pub fn dwelf_dwarf_gnu_debugaltlink(
        dwarf: *mut Dwarf,
        namep: *mut *const c_char,
        build_idp: *mut *const c_void,
    ) -> ssize_t;

    pub fn dwelf_elf_gnu_build_id(elf: *mut Elf, build_idp: *mut *const c_void) -> ssize_t;

    pub fn dwelf_scn_gnu_compressed_size(scn: *mut Elf_Scn) -> ssize_t;

    pub fn dwelf_strtab_init(nullstr: bool) -> *mut Dwelf_Strtab;

    pub fn dwelf_strtab_add(st: *mut Dwelf_Strtab, str: *const c_char) -> *mut Dwelf_Strent;

    pub fn dwelf_strtab_add_len(
        st: *mut Dwelf_Strtab,
        str: *const c_char,
        len: size_t,
    ) -> *mut Dwelf_Strent;

    pub fn dwelf_strtab_finalize(st: *mut Dwelf_Strtab, data: *mut Elf_Data) -> *mut Elf_Data;

    pub fn dwelf_strent_str(se: *mut Dwelf_Strent) -> *const c_char;

    pub fn dwelf_strtab_free(st: *mut Dwelf_Strtab);
}
