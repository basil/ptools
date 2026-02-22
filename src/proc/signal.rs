use nix::libc;

/// A set of signal numbers, parsed from a kernel hex mask.
///
/// Analogous to [`super::numa::CpuSet`] but for signal numbers.
/// Internally stored as a boolean vector indexed by signal number.
#[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Default)]
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
pub fn parse_signal_set(hex: &str) -> Result<SignalSet, String> {
    let trimmed = hex.trim();
    if trimmed.is_empty() {
        return Err("empty signal mask".to_string());
    }

    let mut bits = vec![false; 1];
    for (nibble_idx, ch) in trimmed.bytes().rev().enumerate() {
        let nibble = match ch {
            b'0'..=b'9' => ch - b'0',
            b'a'..=b'f' => 10 + (ch - b'a'),
            b'A'..=b'F' => 10 + (ch - b'A'),
            _ => {
                return Err(format!("invalid hex digit '{}'", ch as char));
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
pub fn intersect_blocked_masks(masks: &[SignalSet]) -> SignalSet {
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

    match sig as i32 {
        libc::SIGHUP => "HUP".to_string(),
        libc::SIGINT => "INT".to_string(),
        libc::SIGQUIT => "QUIT".to_string(),
        libc::SIGILL => "ILL".to_string(),
        libc::SIGTRAP => "TRAP".to_string(),
        libc::SIGABRT => "ABRT".to_string(),
        libc::SIGBUS => "BUS".to_string(),
        libc::SIGFPE => "FPE".to_string(),
        libc::SIGKILL => "KILL".to_string(),
        libc::SIGUSR1 => "USR1".to_string(),
        libc::SIGSEGV => "SEGV".to_string(),
        libc::SIGUSR2 => "USR2".to_string(),
        libc::SIGPIPE => "PIPE".to_string(),
        libc::SIGALRM => "ALRM".to_string(),
        libc::SIGTERM => "TERM".to_string(),
        libc::SIGSTKFLT => "STKFLT".to_string(),
        libc::SIGCHLD => "CLD".to_string(),
        libc::SIGCONT => "CONT".to_string(),
        libc::SIGSTOP => "STOP".to_string(),
        libc::SIGTSTP => "TSTP".to_string(),
        libc::SIGTTIN => "TTIN".to_string(),
        libc::SIGTTOU => "TTOU".to_string(),
        libc::SIGURG => "URG".to_string(),
        libc::SIGXCPU => "XCPU".to_string(),
        libc::SIGXFSZ => "XFSZ".to_string(),
        libc::SIGVTALRM => "VTALRM".to_string(),
        libc::SIGPROF => "PROF".to_string(),
        libc::SIGWINCH => "WINCH".to_string(),
        libc::SIGIO => "POLL".to_string(),
        libc::SIGPWR => "PWR".to_string(),
        libc::SIGSYS => "SYS".to_string(),
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
        // Bit 0 of nibble 0 → signal 1 (SIGHUP)
        let set = parse_signal_set("0000000000000001").unwrap();
        assert!(set.contains(1));
        assert!(!set.contains(2));
    }

    #[test]
    fn parse_multiple_signals() {
        // 0x3 = bits 0,1 → signals 1,2
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
        // 0x5 = bits 0,2 → signals 1,3
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
