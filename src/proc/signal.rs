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

use std::collections::BTreeSet;
use std::io;

use nix::sys::signal::Signal;

/// Parse a hex signal mask (e.g. from `SigIgn`) into a `BTreeSet<usize>` of
/// 1-indexed signal numbers.
pub(crate) fn parse_signal_set(hex: &str) -> io::Result<BTreeSet<usize>> {
    let trimmed = hex.trim();
    if trimmed.is_empty() {
        return Err(super::parse_error("signal mask", "empty"));
    }

    let mut set = BTreeSet::new();
    for (nibble_idx, ch) in trimmed.bytes().rev().enumerate() {
        let nibble = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => 10 + (ch - b'a'),
            b'A'..=b'F' => 10 + (ch - b'A'),
            _ => {
                return Err(super::parse_error(
                    "signal mask",
                    &format!("invalid hex digit '{}'", ch as char),
                ));
            }
        };

        for bit in 0..4 {
            if (nibble & (1 << bit)) != 0 {
                let sig = nibble_idx * 4 + bit as usize + 1;
                set.insert(sig);
            }
        }
    }

    Ok(set)
}

/// Compute the intersection of per-thread blocked masks.
pub(crate) fn intersect_blocked_masks(masks: &[BTreeSet<usize>]) -> BTreeSet<usize> {
    let Some(first) = masks.first() else {
        return BTreeSet::new();
    };
    if masks.len() == 1 {
        return first.clone();
    }
    masks[1..].iter().fold(first.clone(), |acc, m| &acc & m)
}

/// Return a human-readable name for the given signal number.
///
/// Standard signals (SIGHUP, SIGINT, etc.) are returned as short names
/// like `"HUP"`, `"INT"`. Real-time signals are formatted relative to
/// `rtmin`/`rtmax` (e.g. `"RTMIN"`, `"RTMIN+1"`, `"RTMAX"`).
pub fn signal_name(sig: usize, rtmin: usize, rtmax: usize) -> String {
    if (rtmin..=rtmax).contains(&sig) {
        if sig == rtmin {
            return "RTMIN".to_string();
        }
        if sig == rtmax {
            return "RTMAX".to_string();
        }
        return format!("RTMIN+{}", sig - rtmin);
    }

    match Signal::try_from(sig as i32) {
        Ok(Signal::SIGHUP) => "HUP".to_string(),
        Ok(Signal::SIGINT) => "INT".to_string(),
        Ok(Signal::SIGQUIT) => "QUIT".to_string(),
        Ok(Signal::SIGILL) => "ILL".to_string(),
        Ok(Signal::SIGTRAP) => "TRAP".to_string(),
        Ok(Signal::SIGABRT) => "ABRT".to_string(),
        Ok(Signal::SIGBUS) => "BUS".to_string(),
        Ok(Signal::SIGFPE) => "FPE".to_string(),
        Ok(Signal::SIGKILL) => "KILL".to_string(),
        Ok(Signal::SIGUSR1) => "USR1".to_string(),
        Ok(Signal::SIGSEGV) => "SEGV".to_string(),
        Ok(Signal::SIGUSR2) => "USR2".to_string(),
        Ok(Signal::SIGPIPE) => "PIPE".to_string(),
        Ok(Signal::SIGALRM) => "ALRM".to_string(),
        Ok(Signal::SIGTERM) => "TERM".to_string(),
        Ok(Signal::SIGSTKFLT) => "STKFLT".to_string(),
        Ok(Signal::SIGCHLD) => "CLD".to_string(),
        Ok(Signal::SIGCONT) => "CONT".to_string(),
        Ok(Signal::SIGSTOP) => "STOP".to_string(),
        Ok(Signal::SIGTSTP) => "TSTP".to_string(),
        Ok(Signal::SIGTTIN) => "TTIN".to_string(),
        Ok(Signal::SIGTTOU) => "TTOU".to_string(),
        Ok(Signal::SIGURG) => "URG".to_string(),
        Ok(Signal::SIGXCPU) => "XCPU".to_string(),
        Ok(Signal::SIGXFSZ) => "XFSZ".to_string(),
        Ok(Signal::SIGVTALRM) => "VTALRM".to_string(),
        Ok(Signal::SIGPROF) => "PROF".to_string(),
        Ok(Signal::SIGWINCH) => "WINCH".to_string(),
        Ok(Signal::SIGIO) => "POLL".to_string(),
        Ok(Signal::SIGPWR) => "PWR".to_string(),
        Ok(Signal::SIGSYS) => "SYS".to_string(),
        _ => format!("SIG{sig}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_mask() {
        let set = parse_signal_set("0000000000000000").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn parse_single_signal() {
        // Bit 0 of nibble 0 -> signal 1 (SIGHUP)
        let set = parse_signal_set("0000000000000001").unwrap();
        assert!(set.contains(&1));
        assert!(!set.contains(&2));
    }

    #[test]
    fn parse_multiple_signals() {
        // 0x3 = bits 0,1 -> signals 1,2
        let set = parse_signal_set("0000000000000003").unwrap();
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(!set.contains(&3));
    }

    #[test]
    fn parse_error_on_empty() {
        assert!(parse_signal_set("").is_err());
    }

    #[test]
    fn parse_error_on_invalid_hex() {
        assert!(parse_signal_set("xyz").is_err());
    }

    #[test]
    fn iter_yields_set_signals() {
        // 0x5 = bits 0,2 -> signals 1,3
        let set = parse_signal_set("5").unwrap();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn max_signal_empty() {
        let set: BTreeSet<usize> = BTreeSet::new();
        assert_eq!(set.last().copied().unwrap_or(0), 0);
    }

    #[test]
    fn intersect_single_mask() {
        let mask = parse_signal_set("3").unwrap(); // signals 1,2
        let result = intersect_blocked_masks(std::slice::from_ref(&mask));
        assert_eq!(result, mask);
    }

    #[test]
    fn intersect_two_masks() {
        let a = parse_signal_set("7").unwrap(); // signals 1,2,3
        let b = parse_signal_set("5").unwrap(); // signals 1,3
        let result = intersect_blocked_masks(&[a, b]);
        assert!(result.contains(&1));
        assert!(!result.contains(&2));
        assert!(result.contains(&3));
    }

    #[test]
    fn intersect_empty_list() {
        let result = intersect_blocked_masks(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn signal_name_standard() {
        assert_eq!(signal_name(1, 34, 64), "HUP");
        assert_eq!(signal_name(9, 34, 64), "KILL");
    }

    #[test]
    fn signal_name_rt() {
        assert_eq!(signal_name(34, 34, 64), "RTMIN");
        assert_eq!(signal_name(35, 34, 64), "RTMIN+1");
        assert_eq!(signal_name(64, 34, 64), "RTMAX");
    }
}
