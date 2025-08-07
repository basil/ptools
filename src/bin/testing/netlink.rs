//
//   Copyright 2019 Delphix
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

use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use nix::unistd::getpid;

use std::fs::File;
use std::os::fd::AsRawFd;

extern crate nix;

fn main() {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::empty(),
        Some(SockProtocol::NetlinkRoute),
    )
    .unwrap();

    let pid = getpid().as_raw() as u32;
    let netlink_addr = NetlinkAddr::new(pid, 0);

    bind(fd.as_raw_fd(), &netlink_addr).unwrap();

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create("/tmp/ptools-test-ready").unwrap();

    // Wait for the parent finish running the ptool and then kill us.
    loop {}
}

