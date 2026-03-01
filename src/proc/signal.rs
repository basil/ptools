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

//! Signal mask parsing: per-thread blocked mask collection and intersection.

use std::collections::BTreeSet;
use std::io;

use super::ProcHandle;
use crate::model;

impl ProcHandle {
    /// Parse signal masks (SigIgn/SigCgt/SigBlk/SigPnd/ShdPnd) from status.
    /// The blocked mask is the intersection across all threads.
    pub fn signal_masks(&self) -> io::Result<model::status::Status> {
        let mut status = self.source.read_status()?;

        // Compute blocked mask as intersection across all threads.
        // Falls back to main thread's SigBlk if /proc/[pid]/task/ is unreadable.
        status.sig_blk = self
            .thread_blocked_masks()
            .map(|masks| intersect_blocked_masks(&masks))
            .or(status.sig_blk);

        Ok(status)
    }

    /// Per-thread blocked masks (SigBlk from each thread's status).
    fn thread_blocked_masks(&self) -> Option<Vec<BTreeSet<usize>>> {
        let tids = self.source.list_tids().ok()?;

        // Warn if the source reports fewer threads than actually existed.
        if let Ok(status) = self.source.read_status() {
            if let Some(n) = status.threads {
                if n > tids.len() {
                    eprintln!(
                        "warning: process had {} threads but only {} available; \
                         blocked masks may be incomplete",
                        n,
                        tids.len()
                    );
                }
            }
        }

        let tid_count = tids.len();
        let mut masks = Vec::new();
        for tid in tids {
            let Ok(status) = self.source.read_tid_status(tid) else {
                continue;
            };
            if let Some(sig_blk) = status.sig_blk {
                masks.push(sig_blk);
            }
        }

        if !masks.is_empty() && masks.len() < tid_count {
            eprintln!(
                "warning: read blocked mask for {} of {} threads; \
                 blocked-signal intersection may be incomplete",
                masks.len(),
                tid_count
            );
        }

        if masks.is_empty() {
            None
        } else {
            Some(masks)
        }
    }
}

/// Compute the intersection of per-thread blocked masks.
fn intersect_blocked_masks(masks: &[BTreeSet<usize>]) -> BTreeSet<usize> {
    let Some(first) = masks.first() else {
        return BTreeSet::new();
    };
    masks[1..].iter().fold(first.clone(), |acc, m| {
        acc.intersection(m).copied().collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::status::parse_signal_mask;

    #[test]
    fn intersect_single_mask() {
        let mask = parse_signal_mask("3").unwrap(); // signals 1,2
        let result = intersect_blocked_masks(std::slice::from_ref(&mask));
        assert_eq!(result, mask);
    }

    #[test]
    fn intersect_two_masks() {
        let a = parse_signal_mask("7").unwrap(); // signals 1,2,3
        let b = parse_signal_mask("5").unwrap(); // signals 1,3
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
}
