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

mod display;
mod proc;

// Re-export public API at crate root.
pub use display::{
    print_auxv_from, print_cmd_summary_from, print_env_from, print_proc_summary_from,
};
pub use proc::cred::{resolve_gid, resolve_uid, ProcCred};
pub use proc::fd::{
    address_family_from_sockprotoname, AnonFileType, FdStat, FileDescriptor, FileType, OpenFlags,
    PosixFileType,
};
pub use proc::net::{PeerProcess, SockType, Socket, TcpInfo, TcpState};
pub use proc::numa::{cpu_to_node, numa_online_nodes, CpuSet};
pub use proc::signal::{signal_name, SignalSet};
pub use proc::{
    resolve_operand, resolve_operand_with_tid, Error, ProcHandle, ProcessState, Rlimit, RlimitVal,
    SignalMasks,
};

use nix::libc;

// TODO Add support for handling core dumps
// TODO Handle unprintable characters in anything we need to print and non-UTF8 in any input
// TODO Test against 32-bit processes

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
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}
