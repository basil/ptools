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

//! DWFL types.

use libc::c_int;

pub use self::callbacks::*;
pub use self::error::*;
pub use self::frame::*;
pub use self::handle::*;
pub use self::module::*;
pub use self::thread::*;

mod callbacks;
mod error;
mod frame;
mod handle;
mod module;
mod thread;

fn cvt(r: c_int) -> Result<(), Error> {
    if r == 0 {
        Ok(())
    } else {
        Err(Error::new())
    }
}
