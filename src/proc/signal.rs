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

use nix::sys::signal::Signal;

/// A set of signal numbers, parsed from a kernel hex mask.
///
/// Analogous to [`super::numa::CpuSet`] but for signal numbers.
/// Internally stored as a boolean vector indexed by signal number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignalSet {
    signals: Vec<bool>,
}

impl SignalSet {
    /// Whether the given signal number is a member of this set.
    pub fn contains(&self, sig: usize) -> bool {
        sig < self.signals.len() && self.signals[sig]
    }

    /// Whether the set contains no signals.
    pub fn is_empty(&self) -> bool {
        !self.signals.iter().any(|&b| b)
    }

    /// The highest signal number representable by this set (the length of the
    /// underlying storage minus one). Returns 0 for an empty set.
    pub fn max_signal(&self) -> usize {
        self.signals.len().saturating_sub(1)
    }

    /// Iterate over the signal numbers that are set.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.signals
            .iter()
            .enumerate()
            .filter_map(|(i, &set)| if set { Some(i) } else { None })
    }
}

/// Parse a hex signal mask (e.g. from `SigIgn`) into a [`SignalSet`].
pub(crate) fn parse_signal_set(hex: &str) -> Result<SignalSet, super::Error> {
    let trimmed = hex.trim();
    if trimmed.is_empty() {
        return Err(super::Error::parse("signal mask", "empty"));
    }

    let mut bits = vec![false; 1];
    for (nibble_idx, ch) in trimmed.bytes().rev().enumerate() {
        let nibble = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => 10 + (ch - b'a'),
            b'A'..=b'F' => 10 + (ch - b'A'),
            _ => {
                return Err(super::Error::parse(
                    "signal mask",
                    &format!("invalid hex digit '{}'", ch as char),
                ));
            }
        };

        for bit in 0..4 {
            if (nibble & (1 << bit)) == 0 {
                continue;
            }
            let sig = nibble_idx * 4 + bit as usize + 1;
            if sig >= bits.len() {
                bits.resize(sig + 1, false);
            }
            bits[sig] = true;
        }
    }

    Ok(SignalSet { signals: bits })
}

/// Compute the intersection of per-thread blocked masks.
pub(crate) fn intersect_blocked_masks(masks: &[SignalSet]) -> SignalSet {
    let Some(first) = masks.first() else {
        return SignalSet::default();
    };
    // If there's only one thread, just return its mask directly.
    if masks.len() == 1 {
        return first.clone();
    }
    let max_len = masks.iter().map(|m| m.signals.len()).max().unwrap_or(0);
    let mut result = vec![false; max_len];
    for (i, slot) in result.iter_mut().enumerate().take(max_len) {
        *slot = masks.iter().all(|m| i < m.signals.len() && m.signals[i]);
    }
    SignalSet { signals: result }
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
        _ => format!("SIG{}", sig),
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
        assert!(set.contains(1));
        assert!(!set.contains(2));
    }

    #[test]
    fn parse_multiple_signals() {
        // 0x3 = bits 0,1 -> signals 1,2
        let set = parse_signal_set("0000000000000003").unwrap();
        assert!(set.contains(1));
        assert!(set.contains(2));
        assert!(!set.contains(3));
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
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn max_signal_empty() {
        let set = SignalSet::default();
        assert_eq!(set.max_signal(), 0);
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
        assert!(result.contains(1));
        assert!(!result.contains(2));
        assert!(result.contains(3));
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
