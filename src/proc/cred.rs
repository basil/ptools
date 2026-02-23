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

use nix::libc;

use super::Error;

/// Process credentials parsed from /proc/[pid]/status
pub struct ProcCred {
    pub euid: u32,
    pub ruid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub egid: u32,
    pub rgid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub groups: Vec<u32>,
}

/// Parse credentials from the text of /proc/[pid]/status.
pub(crate) fn parse_cred(status: &str) -> Result<ProcCred, Error> {
    let mut uid_fields = None;
    let mut gid_fields = None;
    let mut groups = Vec::new();

    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key {
                "Uid" => {
                    let fields: Vec<u32> = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if fields.len() >= 4 {
                        uid_fields = Some((fields[0], fields[1], fields[2], fields[3]));
                    }
                }
                "Gid" => {
                    let fields: Vec<u32> = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if fields.len() >= 4 {
                        gid_fields = Some((fields[0], fields[1], fields[2], fields[3]));
                    }
                }
                "Groups" => {
                    groups = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                }
                _ => {}
            }
        }
    }

    let (ruid, euid, suid, fsuid) =
        uid_fields.ok_or_else(|| Error::in_file("status", "missing Uid"))?;
    let (rgid, egid, sgid, fsgid) =
        gid_fields.ok_or_else(|| Error::in_file("status", "missing Gid"))?;

    Ok(ProcCred {
        euid,
        ruid,
        suid,
        fsuid,
        egid,
        rgid,
        sgid,
        fsgid,
        groups,
    })
}

pub fn resolve_uid(uid: u32) -> Option<String> {
    // SAFETY: getpwuid returns a pointer to a static struct or null.
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: pw_name is a valid C string if pw is non-null.
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    name.to_str().ok().map(str::to_string)
}

pub fn resolve_gid(gid: u32) -> Option<String> {
    // SAFETY: getgrgid returns a pointer to a static struct or null.
    let gr = unsafe { libc::getgrgid(gid) };
    if gr.is_null() {
        return None;
    }
    // SAFETY: gr_name is a valid C string if gr is non-null.
    let name = unsafe { std::ffi::CStr::from_ptr((*gr).gr_name) };
    name.to_str().ok().map(str::to_string)
}
