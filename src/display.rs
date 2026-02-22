use std::io::ErrorKind;

use nix::libc;

use crate::proc::auxv::{aux_key_name, decode_hwcap, is_gid_auxv_key, is_uid_auxv_key, read_auxv};
use crate::proc::cred::{resolve_gid, resolve_uid};
use crate::proc::ProcHandle;

pub fn print_env_from(handle: &ProcHandle) -> bool {
    // This contains the environ as it was when the proc was started. To get the current
    // environment, we need to inspect its memory to find out how it has changed. POSIX defines a
    // char **__environ symbol that we will need to find. Unfortunately, inspecting the memory of
    // another process is not typically permitted, even if the process is owned by the same user. See
    // /etc/sysctl.d/10-ptrace.conf for details.
    //
    // TODO Long term, we might want to print the current environment if we can, and print a warning
    // + the contents of /proc/[pid]/environ if we can't
    let vars = match handle.environ() {
        Ok(vars) => vars,
        Err(e) => {
            eprintln!("Error opening /proc/{}/environ: {}", handle.pid(), e);
            return false;
        }
    };

    print_proc_summary_from(handle);

    for (i, (key, value)) in vars.iter().enumerate() {
        println!(
            "envp[{}]: {}={}",
            i,
            key.to_string_lossy(),
            value.to_string_lossy()
        );
    }
    true
}

pub fn print_env(pid: u64) -> bool {
    print_env_from(&ProcHandle::from_pid(pid))
}

#[allow(clippy::unnecessary_cast)]
pub fn print_auxv_from(handle: &ProcHandle) -> bool {
    if let Ok(auxv) = read_auxv(handle) {
        print_proc_summary_from(handle);
        for (key, value) in auxv {
            if key == libc::AT_EXECFN as u64 {
                let s = handle
                    .exe()
                    .ok()
                    .and_then(|p| p.to_str().map(str::to_string))
                    .unwrap_or_default();
                println!("{:<15} 0x{:016x} {}", aux_key_name(key), value, s);
            } else if let Some(flags) = decode_hwcap(key, value) {
                println!("{:<15} 0x{:016x} {}", aux_key_name(key), value, flags);
            } else if is_uid_auxv_key(key) {
                if let Some(name) = resolve_uid(value as u32) {
                    println!(
                        "{:<15} 0x{:016x} {}({})",
                        aux_key_name(key),
                        value,
                        value,
                        name
                    );
                } else {
                    println!("{:<15} 0x{:016x}", aux_key_name(key), value);
                }
            } else if is_gid_auxv_key(key) {
                if let Some(name) = resolve_gid(value as u32) {
                    println!(
                        "{:<15} 0x{:016x} {}({})",
                        aux_key_name(key),
                        value,
                        value,
                        name
                    );
                } else {
                    println!("{:<15} 0x{:016x}", aux_key_name(key), value);
                }
            } else {
                println!("{:<15} 0x{:016x}", aux_key_name(key), value);
            }
        }
        true
    } else {
        false
    }
}

pub fn print_auxv(pid: u64) -> bool {
    print_auxv_from(&ProcHandle::from_pid(pid))
}

pub fn print_proc_summary_from(handle: &ProcHandle) {
    print!("{}:\t", handle.pid());
    print_cmd_summary_from(handle);
}

// Print the pid and a summary of command line arguments on a single line.
pub fn print_proc_summary(pid: u64) {
    print_proc_summary_from(&ProcHandle::from_pid(pid));
}

pub fn print_cmd_summary_from(handle: &ProcHandle) {
    match handle.argv() {
        Ok(args) if !args.is_empty() => {
            let summary: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
            println!("{}", summary.join(" "));
        }
        Ok(_) => {
            // Empty cmdline — fall back to comm name.
            let is_zombie = handle.state() == Some('Z');
            match handle.comm() {
                Ok(ref comm) if !comm.is_empty() => {
                    print!("{}", comm);
                    if is_zombie {
                        print!(" <defunct>");
                    }
                    println!();
                }
                Ok(_) => println!("<unknown>"),
                Err(ref e) if e.kind() == ErrorKind::NotFound => {
                    println!("<exited>");
                }
                Err(_) => println!("<unknown>"),
            }
        }
        Err(ref e) if e.kind() == ErrorKind::NotFound => {
            println!("<exited>");
        }
        Err(e) => {
            println!("<error reading cmdline>");
            eprintln!("{}", e);
        }
    }
}

// Print a summary of command line arguments on a single line.
pub fn print_cmd_summary(pid: u64) {
    print_cmd_summary_from(&ProcHandle::from_pid(pid));
}
