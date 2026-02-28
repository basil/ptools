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

use libc::c_int;
use libc::c_long;
use libc::c_uint;
use libc::c_void;
use libc::size_t;
use libc::Elf32_Word;
use libc::Elf64_Addr;
use libc::Elf64_Chdr;
use libc::Elf64_Ehdr;
use libc::Elf64_Half;
use libc::Elf64_Off;
use libc::Elf64_Phdr;
use libc::Elf64_Rel;
use libc::Elf64_Rela;
use libc::Elf64_Shdr;
use libc::Elf64_Sword;
use libc::Elf64_Sxword;
use libc::Elf64_Sym;
use libc::Elf64_Word;
use libc::Elf64_Xword;

use super::super::Elf;
use super::super::Elf_Data;
use super::super::Elf_Scn;
use super::super::Elf_Type;

pub type GElf_Half = Elf64_Half;
pub type GElf_Word = Elf64_Word;
pub type GElf_Sword = Elf64_Sword;
pub type GElf_Xword = Elf64_Xword;
pub type GElf_Sxword = Elf64_Sxword;
pub type GElf_Addr = Elf64_Addr;
pub type GElf_Off = Elf64_Off;
pub type GElf_Ehdr = Elf64_Ehdr;
pub type GElf_Shdr = Elf64_Shdr;
pub type GElf_Section = Elf64_Half;
pub type GElf_Sym = Elf64_Sym;
pub type GElf_Rel = Elf64_Rel;
pub type GElf_Rela = Elf64_Rela;
pub type GElf_Phdr = Elf64_Phdr;
pub type GElf_Chdr = Elf64_Chdr;
pub type GElf_Versym = Elf64_Half;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GElf_Dyn {
    pub d_tag: Elf64_Sxword,
    pub d_un: Elf64_Xword,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GElf_Nhdr {
    pub n_namesz: Elf64_Word,
    pub n_descsz: Elf64_Word,
    pub n_type: Elf64_Word,
}

extern "C" {
    pub fn gelf_getclass(__elf: *mut Elf) -> c_int;

    pub fn gelf_fsize(
        __elf: *mut Elf,
        __type: Elf_Type,
        __count: size_t,
        __version: c_uint,
    ) -> size_t;

    pub fn gelf_getehdr(__elf: *mut Elf, __dest: *mut GElf_Ehdr) -> *mut GElf_Ehdr;

    pub fn gelf_update_ehdr(__elf: *mut Elf, __src: *mut GElf_Ehdr) -> c_int;

    pub fn gelf_newehdr(__elf: *mut Elf, __class: c_int) -> *mut c_void;

    pub fn gelf_offscn(__elf: *mut Elf, __offset: GElf_Off) -> *mut Elf_Scn;

    pub fn gelf_getshdr(__scn: *mut Elf_Scn, __dst: *mut GElf_Shdr) -> *mut GElf_Shdr;

    pub fn gelf_update_shdr(__scn: *mut Elf_Scn, __src: *mut GElf_Shdr) -> c_int;

    pub fn gelf_getphdr(__elf: *mut Elf, __ndx: c_int, __dst: *mut GElf_Phdr) -> *mut GElf_Phdr;

    pub fn gelf_update_phdr(__elf: *mut Elf, __ndx: c_int, __src: *mut GElf_Phdr) -> c_int;

    pub fn gelf_newphdr(__elf: *mut Elf, __phnum: size_t) -> *mut c_void;

    pub fn gelf_getchdr(__scn: *mut Elf_Scn, __dst: *mut GElf_Chdr) -> *mut GElf_Chdr;

    pub fn gelf_xlatetom(
        __elf: *mut Elf,
        __dest: *mut Elf_Data,
        __src: *const Elf_Data,
        __encode: c_uint,
    ) -> *mut Elf_Data;

    pub fn gelf_xlatetof(
        __elf: *mut Elf,
        __dest: *mut Elf_Data,
        __src: *const Elf_Data,
        __encode: c_uint,
    ) -> *mut Elf_Data;

    pub fn gelf_getrel(__data: *mut Elf_Data, __ndx: c_int, __dst: *mut GElf_Rel) -> *mut GElf_Rel;

    pub fn gelf_getrela(
        __data: *mut Elf_Data,
        __ndx: c_int,
        __dst: *mut GElf_Rela,
    ) -> *mut GElf_Rela;

    pub fn gelf_update_rel(__dst: *mut Elf_Data, __ndx: c_int, __src: *mut GElf_Rel) -> c_int;

    pub fn gelf_update_rela(__dst: *mut Elf_Data, __ndx: c_int, __src: *mut GElf_Rela) -> c_int;

    pub fn gelf_getsym(__data: *mut Elf_Data, __ndx: c_int, __dst: *mut GElf_Sym) -> *mut GElf_Sym;

    pub fn gelf_update_sym(__data: *mut Elf_Data, __ndx: c_int, __src: *mut GElf_Sym) -> c_int;

    pub fn gelf_getsymshndx(
        __symdata: *mut Elf_Data,
        __shndxdata: *mut Elf_Data,
        __ndx: c_int,
        __sym: *mut GElf_Sym,
        __xshndx: *mut Elf32_Word,
    ) -> *mut GElf_Sym;

    pub fn gelf_update_symshndx(
        __symdata: *mut Elf_Data,
        __shndxdata: *mut Elf_Data,
        __ndx: c_int,
        __sym: *mut GElf_Sym,
        __xshndx: Elf32_Word,
    ) -> c_int;

    pub fn gelf_getdyn(__data: *mut Elf_Data, __ndx: c_int, __dst: *mut GElf_Dyn) -> *mut GElf_Dyn;

    pub fn gelf_update_dyn(__dst: *mut Elf_Data, __ndx: c_int, __src: *mut GElf_Dyn) -> c_int;

    pub fn gelf_getversym(
        __data: *mut Elf_Data,
        __ndx: c_int,
        __dst: *mut GElf_Versym,
    ) -> *mut GElf_Versym;

    pub fn gelf_update_versym(
        __data: *mut Elf_Data,
        __ndx: c_int,
        __src: *mut GElf_Versym,
    ) -> c_int;

    pub fn gelf_getnote(
        __data: *mut Elf_Data,
        __offset: size_t,
        __result: *mut GElf_Nhdr,
        __name_offset: *mut size_t,
        __desc_offset: *mut size_t,
    ) -> size_t;

    pub fn gelf_checksum(__elf: *mut Elf) -> c_long;
}
