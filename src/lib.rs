//
//   Copyright 2018 Delphix
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

use nix::sys::signal::signal;
use nix::sys::signal::SigHandler;
use nix::sys::signal::Signal;

pub mod display;
#[allow(dead_code)]
mod dw;
#[allow(dead_code)]
mod dw_sys;
pub mod model;
pub mod proc;
mod source;
pub mod stack;

// TODO Handle unprintable characters in anything we need to print and non-UTF8 in any input
// TODO Test against 32-bit target processes

// Error handling philosophy: in general these tools should try to recover from errors and continue
// to produce useful output. Debugging tools, much more so than other tools, are expected to be run
// on systems which are in unusual and bad states. Indeed, this is when they are most useful. Note
// that this mainly refers to situations where info on the system doesn't match our expectations.
// For instance, if we expect a particular field in /proc/[pid]/status to have a particular value,
// and it doesn't, we shouldn't panic. On the other hand, we should feel free to assert that some
// purely internal invariant holds, and panic if it doesn't.

/// Reset SIGPIPE to the default behavior (terminate the process) so that
/// writing to a closed pipe exits silently instead of panicking.  Rust
/// overrides the default to SIG_IGN, which causes `println!` to panic
/// with "Broken pipe" when stdout is a pipe whose reader has closed.
pub fn reset_sigpipe() {
    // SAFETY: Restoring the default signal disposition is always safe.
    unsafe {
        signal(Signal::SIGPIPE, SigHandler::SigDfl).ok();
    }
}
