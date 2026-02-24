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
use std::ptr;

use super::{Error, ThreadRef};

/// A reference to a stack frame.
pub struct FrameRef(Opaque);

unsafe impl ForeignTypeRef for FrameRef {
    type CType = crate::dw_sys::Dwfl_Frame;
}

impl FrameRef {
    /// Returns a reference to the thread corresponding to this frame.
    pub fn thread(&self) -> &ThreadRef {
        unsafe {
            let ptr = crate::dw_sys::dwfl_frame_thread(self.as_ptr());
            ThreadRef::from_ptr(ptr)
        }
    }

    /// Returns the address of the instruction pointer at this frame.
    ///
    /// If provided, `is_activation` parameter will be set to true if this frame is an "activation" (i.e. signal) frame,
    /// and false otherwise.
    pub fn pc(&self, is_activation: Option<&mut bool>) -> Result<u64, Error> {
        unsafe {
            let mut pc = 0;
            let isactivation = is_activation.map_or(ptr::null_mut(), |b| b as *mut bool);
            if crate::dw_sys::dwfl_frame_pc(self.as_ptr(), &mut pc, isactivation) {
                Ok(pc)
            } else {
                Err(Error::new())
            }
        }
    }

    /// Returns the value of a register at this frame.
    pub fn reg(&self, regno: u32) -> Option<u64> {
        unsafe {
            let mut val: crate::dw_sys::Dwarf_Word = 0;
            if crate::dw_sys::dwfl_frame_reg(self.as_ptr(), regno, &mut val) == 0 {
                Some(val)
            } else {
                None
            }
        }
    }
}
