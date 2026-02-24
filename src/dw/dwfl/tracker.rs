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

use foreign_types::ForeignTypeRef;
use libc::pid_t;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr;

use super::{cvt, Callbacks, DwflRef, Error};

/// A process tracker that caches Elf data across multiple libdwfl sessions.
///
/// The callbacks must outlive the tracker, as libdwfl stores a pointer to them.
pub struct ProcessTracker<'a> {
    ptr: *mut crate::dw_sys::Dwflst_Process_Tracker,
    _callbacks: PhantomData<&'a Callbacks>,
}

impl<'a> ProcessTracker<'a> {
    /// Creates a new process tracker with the specified callbacks.
    ///
    /// The callbacks must remain at a stable address for the lifetime of the
    /// tracker (e.g. a `static` or `LazyLock`).
    pub fn new(callbacks: &'a Callbacks) -> Result<ProcessTracker<'a>, Error> {
        unsafe {
            let ptr = crate::dw_sys::dwflst_tracker_begin(callbacks.as_ptr());
            if ptr.is_null() {
                Err(Error::new())
            } else {
                Ok(ProcessTracker {
                    ptr,
                    _callbacks: PhantomData,
                })
            }
        }
    }

    /// Creates a Dwfl for the given PID, reports its modules, ends the report,
    /// and attaches to the process.
    pub fn attach_process(&self, pid: u32) -> Result<TrackerDwfl<'_>, Error> {
        unsafe {
            let dwfl = crate::dw_sys::dwflst_tracker_dwfl_begin(self.ptr);
            if dwfl.is_null() {
                return Err(Error::new());
            }

            let r = crate::dw_sys::dwfl_linux_proc_report(dwfl, pid as pid_t);
            if r < 0 {
                return Err(Error::new());
            }

            let r = crate::dw_sys::dwfl_report_end(dwfl, None, ptr::null_mut());
            if r != 0 {
                return Err(Error::new());
            }

            cvt(crate::dw_sys::dwfl_linux_proc_attach(
                dwfl,
                pid as pid_t,
                false,
            ))?;

            Ok(TrackerDwfl {
                ptr: dwfl,
                _marker: PhantomData,
            })
        }
    }
}

impl Drop for ProcessTracker<'_> {
    fn drop(&mut self) {
        unsafe {
            crate::dw_sys::dwflst_tracker_end(self.ptr);
        }
    }
}

/// A Dwfl session owned by a `ProcessTracker`.
///
/// Unlike `Dwfl`, this is not independently freed — it is cleaned up when the
/// owning tracker is dropped.
pub struct TrackerDwfl<'a> {
    ptr: *mut crate::dw_sys::Dwfl,
    _marker: PhantomData<&'a ProcessTracker<'a>>,
}

impl<'a> Deref for TrackerDwfl<'a> {
    type Target = DwflRef<'a>;

    fn deref(&self) -> &DwflRef<'a> {
        unsafe { DwflRef::from_ptr(self.ptr) }
    }
}

impl<'a> DerefMut for TrackerDwfl<'a> {
    fn deref_mut(&mut self) -> &mut DwflRef<'a> {
        unsafe { DwflRef::from_ptr_mut(self.ptr) }
    }
}
