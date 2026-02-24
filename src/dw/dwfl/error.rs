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
use std::borrow::Cow;
use std::error;
use std::ffi::CStr;
use std::fmt;

/// A error returned by DWFL APIs.
pub struct Error(c_int);

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Error")
            .field("code", &self.0)
            .field("message", &self.as_str())
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.as_str(), fmt)
    }
}

impl error::Error for Error {}

impl Error {
    pub(crate) fn new() -> Error {
        unsafe { Error(crate::dw_sys::dwfl_errno()) }
    }

    fn as_str(&self) -> Cow<'_, str> {
        unsafe {
            let s = crate::dw_sys::dwfl_errmsg(self.0);
            if s.is_null() {
                "unknown error".into()
            } else {
                CStr::from_ptr(s).to_string_lossy()
            }
        }
    }
}
