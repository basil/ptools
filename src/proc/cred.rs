use nix::libc;

use super::Error;

/// Process credentials parsed from /proc/[pid]/status
pub struct ProcCred {
    pub euid: u32,
    pub ruid: u32,
    pub suid: u32,
    pub egid: u32,
    pub rgid: u32,
    pub sgid: u32,
    pub groups: Vec<u32>,
}

/// Parse credentials from the text of /proc/[pid]/status.
pub fn parse_cred(status: &str) -> Result<ProcCred, Error> {
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
                    if fields.len() >= 3 {
                        uid_fields = Some((fields[0], fields[1], fields[2]));
                    }
                }
                "Gid" => {
                    let fields: Vec<u32> = value
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if fields.len() >= 3 {
                        gid_fields = Some((fields[0], fields[1], fields[2]));
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

    let (ruid, euid, suid) = uid_fields.ok_or_else(|| Error::in_file("status", "missing Uid"))?;
    let (rgid, egid, sgid) = gid_fields.ok_or_else(|| Error::in_file("status", "missing Gid"))?;

    Ok(ProcCred {
        euid,
        ruid,
        suid,
        egid,
        rgid,
        sgid,
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
