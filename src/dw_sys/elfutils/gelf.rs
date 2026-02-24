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

use libc::{
    Elf64_Addr, Elf64_Half, Elf64_Off, Elf64_Phdr, Elf64_Shdr, Elf64_Sxword, Elf64_Sym, Elf64_Word,
    Elf64_Xword,
};

pub type GElf_Word = Elf64_Word;
pub type GElf_Addr = Elf64_Addr;
pub type GElf_Phdr = Elf64_Phdr;
pub type GElf_Shdr = Elf64_Shdr;
pub type GElf_Sxword = Elf64_Sxword;
pub type GElf_Sym = Elf64_Sym;
pub type GElf_Off = Elf64_Off;
pub type GElf_Xword = Elf64_Xword;
pub type GElf_Half = Elf64_Half;
