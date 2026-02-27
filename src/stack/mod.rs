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
use std::fs::{self, File};
use std::io::{self, Read};
use std::ptr;

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

/// Information about a stack frame of a remote process.
#[derive(Debug, Clone)]
pub struct Frame {
    pub(crate) ip: u64,
    pub(crate) is_signal: bool,
    pub(crate) is_inline: bool,
    pub(crate) symbol: Option<Symbol>,
    pub(crate) module: Option<String>,
    pub(crate) source: Option<SourceLocation>,
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
}

/// Source file and line number for a stack frame.
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub(crate) file: String,
    pub(crate) line: i32,
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
    pub(crate) name: String,
    pub(crate) offset: u64,
    pub(crate) address: u64,
    pub(crate) size: u64,
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
pub fn trace(handle: &crate::ProcHandle) -> io::Result<Process> {
    TraceOptions::new()
        .thread_names(true)
        .symbols(true)
        .demangle(true)
        .trace(handle)
}

/// Options controlling the behavior of tracing.
#[derive(Debug, Clone)]
pub struct TraceOptions {
    pub(crate) snapshot: bool,
    pub(crate) thread_names: bool,
    pub(crate) symbols: bool,
    pub(crate) demangle: bool,
    pub(crate) module: bool,
    pub(crate) source: bool,
    pub(crate) inlines: bool,
    pub(crate) ptrace_attach: bool,
    pub(crate) tid: Option<u32>,
    pub(crate) max_frames: usize,
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
    pub fn trace(&self, handle: &crate::ProcHandle) -> io::Result<Process> {
        let pid = handle.pid() as u32;
        let mut threads = Vec::new();
        self.trace_each(handle, |thread| threads.push(thread))?;
        Ok(Process { id: pid, threads })
    }

    /// Traces the threads of the specified process, calling `each` per thread.
    pub fn trace_each<F>(&self, handle: &crate::ProcHandle, mut each: F) -> io::Result<()>
    where
        F: FnMut(Thread),
    {
        let pid = handle.pid() as u32;

        if let Some(tid) = self.tid {
            if let Some(thread) = open_thread_or_warn(tid, self.ptrace_attach, handle)? {
                each(thread.info(pid, self, handle));
            }
            return Ok(());
        }

        if self.snapshot {
            self.trace_snapshot_each(handle, pid, &mut each)?;
        } else {
            self.trace_rolling_each(handle, pid, &mut each)?;
        }

        Ok(())
    }

    /// Traces the threads captured in a core dump file.
    ///
    /// The `ProcHandle` provides the core-file ELF data and is used to
    /// resolve the main thread's name via systemd-coredump metadata
    /// (`COREDUMP_COMM`).
    pub fn trace_core(&self, handle: &crate::ProcHandle) -> io::Result<Process> {
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
    ) -> io::Result<()>
    where
        H: FnOnce(u32),
        F: FnMut(Thread),
    {
        if !handle.is_core() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ProcHandle has no core file",
            ));
        }
        let pid = handle.pid() as u32;
        header(pid);
        let comm = handle.comm().ok();
        let tids = handle.tids().map_err(|e| match e {
            crate::proc::Error::Io(e) => e,
            crate::proc::Error::Parse(msg) => io::Error::other(msg),
        })?;
        for tid in tids {
            let tid32 = tid as u32;
            if self.tid.is_some_and(|f| f != tid32) {
                continue;
            }
            let frames = handle.trace_thread(tid32, self);
            let name = if self.thread_names {
                if tid32 == pid {
                    comm.clone()
                } else {
                    None
                }
            } else {
                None
            };
            each(Thread {
                id: tid32,
                name,
                frames,
            });
        }
        Ok(())
    }

    fn trace_snapshot_each<F>(
        &self,
        handle: &crate::ProcHandle,
        pid: u32,
        each: &mut F,
    ) -> io::Result<()>
    where
        F: FnMut(Thread),
    {
        for t in snapshot_threads(pid, self.ptrace_attach, handle)?.iter() {
            each(t.info(pid, self, handle));
        }
        Ok(())
    }

    fn trace_rolling_each<F>(
        &self,
        handle: &crate::ProcHandle,
        pid: u32,
        each: &mut F,
    ) -> io::Result<()>
    where
        F: FnMut(Thread),
    {
        each_thread(pid, |tid| {
            if let Some(thread) = open_thread_or_warn(tid, self.ptrace_attach, handle)? {
                each(thread.info(pid, self, handle));
            }
            Ok(())
        })
    }
}

fn open_thread_or_warn(
    tid: u32,
    ptrace_attach: bool,
    handle: &crate::ProcHandle,
) -> io::Result<Option<TracedThread>> {
    let thread = if ptrace_attach {
        TracedThread::attach(tid)
    } else {
        TracedThread::traced(tid)
    };
    match thread {
        Ok(thread) => Ok(Some(thread)),
        Err(ref e) if e.raw_os_error() == Some(ESRCH) => {
            handle.push_warning(format!("error attaching to thread {}: {}", tid, e));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn snapshot_threads(
    pid: u32,
    ptrace_attach: bool,
    handle: &crate::ProcHandle,
) -> io::Result<BTreeSet<TracedThread>> {
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
) -> io::Result<()> {
    each_thread(pid, |tid| {
        if !threads.contains(&tid) {
            if let Some(thread) = open_thread_or_warn(tid, ptrace_attach, handle)? {
                threads.insert(thread);
            }
        }
        Ok(())
    })
}

fn each_thread<F>(pid: u32, mut f: F) -> io::Result<()>
where
    F: FnMut(u32) -> io::Result<()>,
{
    let dir = format!("/proc/{}/task", pid);
    for entry in fs::read_dir(dir)? {
        let entry = entry?;

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

    fn info(&self, pid: u32, options: &TraceOptions, handle: &crate::ProcHandle) -> Thread {
        let name = if options.thread_names {
            self.name(pid, handle)
        } else {
            None
        };

        let frames = handle.trace_thread(self.id, options);

        Thread {
            id: self.id,
            name,
            frames,
        }
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
