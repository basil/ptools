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

#![allow(bad_style)]

pub use self::elfutils::*;
pub use self::libelf::*;

macro_rules! c_enum {
    ($name:ident { $($variant:ident = $value:expr,)*}) => {
        pub type $name = libc::c_uint;

        $(
            pub const $variant: $name = $value;
        )*
    }
}

mod dwarf;
mod elfutils;
mod libelf;
