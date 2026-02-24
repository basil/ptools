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

//! Thread stack traces of remote processes.

use libc::{
    c_void, pid_t, ptrace, waitpid, ESRCH, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH,
    PTRACE_INTERRUPT, PTRACE_SEIZE, SIGSTOP, WIFSTOPPED, WSTOPSIG, __WALL,
};
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::ptr;
use std::result;

#[path = "dw.rs"]
mod imp;

/// The result type returned by methods in this crate.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
enum ErrorInner {
    Io(io::Error),
    Unwind(imp::Error),
}

/// The error type returned by methods in this crate.
#[derive(Debug)]
pub struct Error(ErrorInner);

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ErrorInner::Io(ref e) => fmt::Display::fmt(e, fmt),
            ErrorInner::Unwind(ref e) => fmt::Display::fmt(e, fmt),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.0 {
            ErrorInner::Io(ref e) => Some(e),
            ErrorInner::Unwind(ref e) => Some(e),
        }
    }
}

/// Information about a remote process.
#[derive(Debug, Clone)]
pub struct Process {
    id: u32,
    threads: Vec<Thread>,
}

impl Process {
    /// Returns the process's ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns information about the threads of the process.
    pub fn threads(&self) -> &[Thread] {
        &self.threads
    }
}

/// Information about a thread of a remote process.
#[derive(Debug, Clone)]
pub struct Thread {
    id: u32,
    name: Option<String>,
    frames: Vec<Frame>,
}

impl Thread {
    /// Returns the thread's ID.
    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the thread's name, if known.
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the frames of the stack trace representing the state of the thread.
    #[inline]
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }
}

/// A function argument with its name and formatted value.
#[derive(Debug, Clone)]
pub struct Argument {
    name: String,
    value: String,
}

impl Argument {
    /// Returns the argument name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the formatted argument value.
    #[inline]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Argument information for a stack frame.
#[derive(Debug, Clone)]
pub enum FrameArgs {
    /// No DWARF debug info available for this frame.
    NoDebugInfo,
    /// Debug info available; contains resolved arguments (may be empty).
    Args(Vec<Argument>),
}

/// Information about a stack frame of a remote process.
#[derive(Debug, Clone)]
pub struct Frame {
    ip: u64,
    is_signal: bool,
    is_inline: bool,
    symbol: Option<Symbol>,
    module: Option<String>,
    source: Option<SourceLocation>,
    args: Option<FrameArgs>,
}

impl Frame {
    /// Returns the instruction pointer of the frame.
    #[inline]
    pub fn ip(&self) -> u64 {
        self.ip
    }

    /// Determines if the frame is from a signal handler.
    #[inline]
    pub fn is_signal(&self) -> bool {
        self.is_signal
    }

    /// Determines if the frame represents an inlined function call.
    #[inline]
    pub fn is_inline(&self) -> bool {
        self.is_inline
    }

    /// Returns information about the symbol corresponding to this frame's instruction pointer, if known.
    #[inline]
    pub fn symbol(&self) -> Option<&Symbol> {
        self.symbol.as_ref()
    }

    /// Returns the module (shared library) containing this frame, if available.
    #[inline]
    pub fn module(&self) -> Option<&str> {
        self.module.as_deref()
    }

    /// Returns the source file and line number for this frame, if available.
    #[inline]
    pub fn source(&self) -> Option<&SourceLocation> {
        self.source.as_ref()
    }

    /// Returns argument information for this frame, if args collection was enabled.
    #[inline]
    pub fn args(&self) -> Option<&FrameArgs> {
        self.args.as_ref()
    }
}

/// Source file and line number for a stack frame.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    file: String,
    line: i32,
}

impl SourceLocation {
    /// Returns the source file path.
    #[inline]
    pub fn file(&self) -> &str {
        &self.file
    }

    /// Returns the line number.
    #[inline]
    pub fn line(&self) -> i32 {
        self.line
    }
}

/// Information about the symbol corresponding to a stack frame.
#[derive(Debug, Clone)]
pub struct Symbol {
    name: String,
    offset: u64,
    address: u64,
    size: u64,
}

impl Symbol {
    /// Returns the name of the procedure.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the offset of the instruction pointer from the symbol's starting address.
    #[inline]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the starting address of the symbol.
    #[inline]
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the size of the symbol.
    #[inline]
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// A convenience wrapper over `TraceOptions` which returns a maximally verbose trace.
pub fn trace(handle: &crate::ProcHandle) -> Result<Process> {
    TraceOptions::new()
        .thread_names(true)
        .symbols(true)
        .demangle(true)
        .trace(handle)
}

/// Options controlling the behavior of tracing.
#[derive(Debug, Clone)]
pub struct TraceOptions {
    snapshot: bool,
    thread_names: bool,
    symbols: bool,
    demangle: bool,
    module: bool,
    source: bool,
    inlines: bool,
    args: bool,
    ptrace_attach: bool,
    tid: Option<u32>,
    max_frames: usize,
}

impl Default for TraceOptions {
    fn default() -> TraceOptions {
        TraceOptions {
            snapshot: false,
            thread_names: false,
            symbols: false,
            demangle: false,
            module: false,
            source: false,
            inlines: false,
            args: false,
            ptrace_attach: true,
            tid: None,
            max_frames: 0,
        }
    }
}

impl TraceOptions {
    /// Returns a new `TraceOptions` with default settings.
    pub fn new() -> TraceOptions {
        TraceOptions::default()
    }

    /// If set, the threads of the process will be traced in a consistent snapshot.
    ///
    /// A snapshot-mode trace ensures a consistent view of all threads, but requires that all
    /// threads be paused for the entire duration of the trace.
    ///
    /// Defaults to `false`.
    pub fn snapshot(&mut self, snapshot: bool) -> &mut TraceOptions {
        self.snapshot = snapshot;
        self
    }

    /// If set, the names of the process's threads will be recorded.
    ///
    /// Defaults to `false`.
    pub fn thread_names(&mut self, thread_names: bool) -> &mut TraceOptions {
        self.thread_names = thread_names;
        self
    }

    /// If set, information about the symbol at each frame will be recorded.
    ///
    /// Defaults to `false`.
    pub fn symbols(&mut self, symbols: bool) -> &mut TraceOptions {
        self.symbols = symbols;
        self
    }

    /// If set, C++ symbol names will be demangled.
    ///
    /// Only effective when `symbols` is also enabled. Defaults to `false`.
    pub fn demangle(&mut self, demangle: bool) -> &mut TraceOptions {
        self.demangle = demangle;
        self
    }

    /// If set, the module (shared library) file path will be recorded for each frame.
    ///
    /// Defaults to `false`.
    pub fn module(&mut self, module: bool) -> &mut TraceOptions {
        self.module = module;
        self
    }

    /// If set, source file and line number information will be recorded for each frame.
    ///
    /// Requires debug information to be available. Defaults to `false`.
    pub fn source(&mut self, source: bool) -> &mut TraceOptions {
        self.source = source;
        self
    }

    /// If set, inlined function frames will be shown using DWARF debuginfo.
    ///
    /// When a function is inlined at a call site, additional frames are emitted
    /// for each level of inlining. Requires debug information. Defaults to `false`.
    pub fn inlines(&mut self, inlines: bool) -> &mut TraceOptions {
        self.inlines = inlines;
        self
    }

    /// If set, function argument names and values will be collected from DWARF debug info.
    ///
    /// Requires debug information. Defaults to `false`.
    pub fn args(&mut self, args: bool) -> &mut TraceOptions {
        self.args = args;
        self
    }

    /// If set, `pstack` will automatically attach to threads via ptrace.
    ///
    /// If disabled, the calling process must already be attached to all traced threads, and the
    /// threads must be in the stopped state.
    ///
    /// Defaults to `true`.
    pub fn ptrace_attach(&mut self, ptrace_attach: bool) -> &mut TraceOptions {
        self.ptrace_attach = ptrace_attach;
        self
    }

    /// If set, only the specified thread will be traced.
    ///
    /// When tracing a live process, this avoids attaching to every thread
    /// just to discard all but one.
    ///
    /// Defaults to `None` (trace all threads).
    pub fn tid(&mut self, tid: u32) -> &mut TraceOptions {
        self.tid = Some(tid);
        self
    }

    /// Sets the maximum number of frames to collect per thread.
    ///
    /// When set to a non-zero value, the backend stops symbolizing frames once
    /// the limit is reached, avoiding expensive DWARF lookups for frames that
    /// would be discarded.
    ///
    /// Defaults to `0` (unlimited).
    pub fn max_frames(&mut self, max_frames: usize) -> &mut TraceOptions {
        self.max_frames = max_frames;
        self
    }

    /// Traces the threads of the specified process.
    pub fn trace(&self, handle: &crate::ProcHandle) -> Result<Process> {
        let pid = handle.pid() as u32;
        let mut threads = Vec::new();
        self.trace_each(handle, |thread| threads.push(thread))?;
        Ok(Process { id: pid, threads })
    }

    /// Traces the threads of the specified process, calling `each` per thread.
    pub fn trace_each<F>(&self, handle: &crate::ProcHandle, mut each: F) -> Result<()>
    where
        F: FnMut(Thread),
    {
        let pid = handle.pid() as u32;
        let mut state = imp::State::new(pid).map_err(|e| Error(ErrorInner::Unwind(e)))?;

        if self.snapshot {
            self.trace_snapshot_each(handle, pid, &mut state, &mut each)?;
        } else {
            self.trace_rolling_each(handle, pid, &mut state, &mut each)?;
        }

        Ok(())
    }

    /// Traces the threads captured in a core dump file.
    ///
    /// The `ProcHandle` provides the core-file ELF data and is used to
    /// resolve the main thread's name via systemd-coredump metadata
    /// (`COREDUMP_COMM`).
    pub fn trace_core(&self, handle: &crate::ProcHandle) -> Result<Process> {
        let mut pid = 0;
        let mut threads = Vec::new();
        self.trace_core_each(handle, |p| pid = p, |thread| threads.push(thread))?;
        Ok(Process { id: pid, threads })
    }

    /// Traces the threads captured in a core dump file, calling `each` per thread.
    ///
    /// `header` is called with the core pid before any threads are streamed.
    pub fn trace_core_each<H, F>(
        &self,
        handle: &crate::ProcHandle,
        header: H,
        mut each: F,
    ) -> Result<()>
    where
        H: FnOnce(u32),
        F: FnMut(Thread),
    {
        let elf_ptr = handle.core_elf_ptr().ok_or_else(|| {
            Error(ErrorInner::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProcHandle has no core file",
            )))
        })?;
        // SAFETY: `handle.source` owns the Arc<CoreElf> backing `elf_ptr`.
        // `state` does not escape this function.
        let mut state =
            unsafe { imp::State::new_core(elf_ptr) }.map_err(|e| Error(ErrorInner::Unwind(e)))?;
        let pid = state.pid();
        header(pid);
        let comm = handle.comm().ok();
        let read_mem = |addr: u64, buf: &mut [u8]| -> bool { handle.read_memory(addr, buf) };
        state.trace_threads_each(
            self,
            &|tid| {
                if tid == pid {
                    comm.clone()
                } else {
                    None
                }
            },
            &read_mem,
            &mut each,
            handle,
        );
        Ok(())
    }

    fn trace_snapshot_each<F>(
        &self,
        handle: &crate::ProcHandle,
        pid: u32,
        state: &mut imp::State,
        each: &mut F,
    ) -> Result<()>
    where
        F: FnMut(Thread),
    {
        let read_mem = |addr: u64, buf: &mut [u8]| -> bool { handle.read_memory(addr, buf) };

        if let Some(tid) = self.tid {
            let thread = if self.ptrace_attach {
                TracedThread::attach(tid)
            } else {
                TracedThread::traced(tid)
            };
            let thread = match thread {
                Ok(thread) => thread,
                Err(ref e) if e.raw_os_error() == Some(ESRCH) => {
                    handle.push_warning(format!("error attaching to thread {}: {}", tid, e));
                    return Ok(());
                }
                Err(e) => return Err(Error(ErrorInner::Io(e))),
            };
            each(thread.info(pid, state, self, &read_mem, handle));
            return Ok(());
        }

        for t in snapshot_threads(pid, self.ptrace_attach, handle)?.iter() {
            each(t.info(pid, state, self, &read_mem, handle));
        }
        Ok(())
    }

    fn trace_rolling_each<F>(
        &self,
        handle: &crate::ProcHandle,
        pid: u32,
        state: &mut imp::State,
        each: &mut F,
    ) -> Result<()>
    where
        F: FnMut(Thread),
    {
        let read_mem = |addr: u64, buf: &mut [u8]| -> bool { handle.read_memory(addr, buf) };

        if let Some(tid) = self.tid {
            let thread = if self.ptrace_attach {
                TracedThread::attach(tid)
            } else {
                TracedThread::traced(tid)
            };
            let thread = match thread {
                Ok(thread) => thread,
                Err(ref e) if e.raw_os_error() == Some(ESRCH) => {
                    handle.push_warning(format!("error attaching to thread {}: {}", tid, e));
                    return Ok(());
                }
                Err(e) => return Err(Error(ErrorInner::Io(e))),
            };
            each(thread.info(pid, state, self, &read_mem, handle));
            return Ok(());
        }

        each_thread(pid, |tid| {
            let thread = if self.ptrace_attach {
                TracedThread::attach(tid)
            } else {
                TracedThread::traced(tid)
            };
            let thread = match thread {
                Ok(thread) => thread,
                Err(ref e) if e.raw_os_error() == Some(ESRCH) => {
                    handle.push_warning(format!("error attaching to thread {}: {}", tid, e));
                    return Ok(());
                }
                Err(e) => return Err(Error(ErrorInner::Io(e))),
            };

            each(thread.info(pid, state, self, &read_mem, handle));
            Ok(())
        })
    }
}

fn snapshot_threads(
    pid: u32,
    ptrace_attach: bool,
    handle: &crate::ProcHandle,
) -> Result<BTreeSet<TracedThread>> {
    let mut threads = BTreeSet::new();

    // new threads may be created while we're in the process of stopping them all, so loop a couple
    // of times to hopefully converge
    for _ in 0..5 {
        let prev = threads.len();
        add_threads(&mut threads, pid, ptrace_attach, handle)?;
        if prev == threads.len() {
            break;
        }
    }

    Ok(threads)
}

fn add_threads(
    threads: &mut BTreeSet<TracedThread>,
    pid: u32,
    ptrace_attach: bool,
    handle: &crate::ProcHandle,
) -> Result<()> {
    each_thread(pid, |tid| {
        if !threads.contains(&tid) {
            let thread = if ptrace_attach {
                TracedThread::attach(tid)
            } else {
                TracedThread::traced(tid)
            };
            let thread = match thread {
                Ok(thread) => thread,
                // ESRCH just means the thread died in the middle of things, which is fine
                Err(e) => {
                    if e.raw_os_error() == Some(ESRCH) {
                        handle.push_warning(format!("error attaching to thread {}: {}", tid, e));
                        return Ok(());
                    } else {
                        return Err(Error(ErrorInner::Io(e)));
                    }
                }
            };
            threads.insert(thread);
        }

        Ok(())
    })
}

fn each_thread<F>(pid: u32, mut f: F) -> Result<()>
where
    F: FnMut(u32) -> Result<()>,
{
    let dir = format!("/proc/{}/task", pid);
    for entry in fs::read_dir(dir).map_err(|e| Error(ErrorInner::Io(e)))? {
        let entry = entry.map_err(|e| Error(ErrorInner::Io(e)))?;

        if let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            f(tid)?;
        }
    }
    Ok(())
}

struct TracedThread {
    id: u32,
    // True if TraceOptions::ptrace_attach was true (default value)
    // It means that Drop should perform detach
    should_detach: bool,
}

impl Drop for TracedThread {
    fn drop(&mut self) {
        if self.should_detach {
            unsafe {
                ptrace(
                    PTRACE_DETACH,
                    self.id as pid_t,
                    ptr::null_mut::<c_void>(),
                    ptr::null_mut::<c_void>(),
                );
            }
        }
    }
}

// these need to be manually implemented to only work off of id so the borrow impl works
impl PartialOrd for TracedThread {
    fn partial_cmp(&self, other: &TracedThread) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TracedThread {
    fn cmp(&self, other: &TracedThread) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialEq for TracedThread {
    fn eq(&self, other: &TracedThread) -> bool {
        self.id == other.id
    }
}

impl Eq for TracedThread {}

impl Borrow<u32> for TracedThread {
    fn borrow(&self) -> &u32 {
        &self.id
    }
}

impl TracedThread {
    fn attach(pid: u32) -> io::Result<TracedThread> {
        unsafe {
            let ret = ptrace(
                PTRACE_SEIZE,
                pid as pid_t,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            );
            if ret != 0 {
                let e = io::Error::last_os_error();
                // ptrace returns ESRCH if PTRACE_SEIZE isn't supported for some reason
                if e.raw_os_error() == Some(ESRCH) {
                    return TracedThread::new_fallback(pid);
                }

                return Err(e);
            }

            let thread = TracedThread {
                id: pid,
                should_detach: true,
            };

            let ret = ptrace(
                PTRACE_INTERRUPT,
                pid as pid_t,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }

            let mut status = 0;
            while waitpid(pid as pid_t, &mut status, __WALL) < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }

            if !WIFSTOPPED(status) {
                return Err(io::Error::other(format!(
                    "unexpected wait status {}",
                    status
                )));
            }

            Ok(thread)
        }
    }

    /// Creates `TracedThread` without attaching to process. Should not be used, if pid is not
    /// traced by current process
    fn traced(pid: u32) -> io::Result<TracedThread> {
        Ok(TracedThread {
            id: pid,
            should_detach: false,
        })
    }

    fn new_fallback(pid: u32) -> io::Result<TracedThread> {
        unsafe {
            let ret = ptrace(
                PTRACE_ATTACH,
                pid as pid_t,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }

            let thread = TracedThread {
                id: pid,
                should_detach: true,
            };

            let mut status = 0;
            loop {
                let ret = waitpid(pid as pid_t, &mut status, __WALL);
                if ret < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }

                    continue;
                }

                if !WIFSTOPPED(status) {
                    return Err(io::Error::other(format!(
                        "unexpected wait status {}",
                        status
                    )));
                }

                let sig = WSTOPSIG(status);
                if sig == SIGSTOP {
                    return Ok(thread);
                }

                let ret = ptrace(
                    PTRACE_CONT,
                    pid as pid_t,
                    ptr::null_mut::<c_void>(),
                    sig as *const c_void,
                );
                if ret != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }

    fn info(
        &self,
        pid: u32,
        state: &mut imp::State,
        options: &TraceOptions,
        read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
        handle: &crate::ProcHandle,
    ) -> Thread {
        let name = if options.thread_names {
            self.name(pid, handle)
        } else {
            None
        };

        let frames = self.dump(state, options, read_mem, handle);

        Thread {
            id: self.id,
            name,
            frames,
        }
    }

    fn dump(
        &self,
        state: &mut imp::State,
        options: &TraceOptions,
        read_mem: &dyn Fn(u64, &mut [u8]) -> bool,
        handle: &crate::ProcHandle,
    ) -> Vec<Frame> {
        let mut frames = vec![];

        if let Err(e) = self.dump_inner(state, options, read_mem, &mut frames) {
            handle.push_warning(format!("error tracing thread {}: {}", self.id, e));
        }

        frames
    }

    fn name(&self, pid: u32, handle: &crate::ProcHandle) -> Option<String> {
        let path = format!("/proc/{}/task/{}/comm", pid, self.id);
        let mut name = vec![];
        match File::open(path).and_then(|mut f| f.read_to_end(&mut name)) {
            Ok(_) => Some(String::from_utf8_lossy(&name).trim().to_string()),
            Err(e) => {
                handle.push_warning(format!("error getting name for thread {}: {}", self.id, e));
                None
            }
        }
    }
}
