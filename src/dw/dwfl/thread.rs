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

use std::any::Any;
use std::panic::AssertUnwindSafe;
use std::panic::{self};

use foreign_types::ForeignTypeRef;
use foreign_types::Opaque;
use libc::c_int;
use libc::c_void;

use super::cvt;
use super::DwflRef;
use super::Error;
use super::FrameRef;

/// A reference to a thread.
pub struct ThreadRef(Opaque);

unsafe impl ForeignTypeRef for ThreadRef {
    type CType = crate::dw_sys::Dwfl_Thread;
}

impl ThreadRef {
    /// Returns the base session associated with this thread.
    pub fn dwfl(&self) -> &DwflRef<'_> {
        unsafe {
            let ptr = crate::dw_sys::dwfl_thread_dwfl(self.as_ptr());
            DwflRef::from_ptr(ptr)
        }
    }

    /// Returns the thread's ID.
    pub fn tid(&self) -> u32 {
        unsafe { crate::dw_sys::dwfl_thread_tid(self.as_ptr()) as u32 }
    }

    /// Iterates through the frames of the thread.
    ///
    /// The callback will be invoked for each stack frame of the thread in turn.
    pub fn frames<F>(&mut self, callback: F) -> Result<(), Error>
    where
        F: FnMut(&mut FrameRef) -> Result<(), Error>,
    {
        unsafe {
            let mut state = CallbackState {
                callback,
                panic: None,
                error: None,
            };
            let r = crate::dw_sys::dwfl_thread_getframes(
                self.as_ptr(),
                Some(frames_cb::<F>),
                &mut state as *mut _ as *mut c_void,
            );

            if let Some(payload) = state.panic {
                panic::resume_unwind(payload);
            }
            if let Some(e) = state.error {
                return Err(e);
            }

            cvt(r)
        }
    }
}

struct CallbackState<F> {
    callback: F,
    panic: Option<Box<dyn Any + Send>>,
    error: Option<Error>,
}

unsafe extern "C" fn frames_cb<F>(frame: *mut crate::dw_sys::Dwfl_Frame, arg: *mut c_void) -> c_int
where
    F: FnMut(&mut FrameRef) -> Result<(), Error>,
{
    let state = &mut *(arg as *mut CallbackState<F>);
    let frame = FrameRef::from_ptr_mut(frame);

    match panic::catch_unwind(AssertUnwindSafe(|| (state.callback)(frame))) {
        Ok(Ok(())) => crate::dw_sys::DWARF_CB_OK,
        Ok(Err(e)) => {
            state.error = Some(e);
            crate::dw_sys::DWARF_CB_ABORT
        }
        Err(e) => {
            state.panic = Some(e);
            crate::dw_sys::DWARF_CB_ABORT
        }
    }
}
