//
//   Copyright (c) 2017 Steven Fackler
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

//! Thread stack traces of remote processes.

use std::error;
use std::fmt;
use std::result;

#[path = "dw.rs"]
mod imp;

/// The result type returned by methods in this crate.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
enum ErrorInner {
    Unwind(imp::Error),
}

/// The error type returned by methods in this crate.
#[derive(Debug)]
pub struct Error(ErrorInner);

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ErrorInner::Unwind(ref e) => fmt::Display::fmt(e, fmt),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match self.0 {
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

/// Information about a stack frame of a remote process.
#[derive(Debug, Clone)]
pub struct Frame {
    ip: u64,
    is_signal: bool,
    symbol: Option<Symbol>,
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

    /// Returns information about the symbol corresponding to this frame's instruction pointer, if known.
    #[inline]
    pub fn symbol(&self) -> Option<&Symbol> {
        self.symbol.as_ref()
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
pub fn trace(pid: u32) -> Result<Process> {
    TraceOptions::new()
        .thread_names(true)
        .symbols(true)
        .trace(pid)
}

/// Options controlling the behavior of tracing.
#[derive(Debug, Clone, Default)]
pub struct TraceOptions {
    thread_names: bool,
    symbols: bool,
}

impl TraceOptions {
    /// Returns a new `TraceOptions` with default settings.
    pub fn new() -> TraceOptions {
        TraceOptions::default()
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

    /// Traces the threads of the specified process.
    pub fn trace(&self, pid: u32) -> Result<Process> {
        let state = imp::State::new().map_err(|e| Error(ErrorInner::Unwind(e)))?;
        let threads = state
            .trace(pid, self)
            .map_err(|e| Error(ErrorInner::Unwind(e)))?;
        Ok(Process { id: pid, threads })
    }
}
