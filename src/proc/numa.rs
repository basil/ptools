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

/// Affinity relationship between a CPU set and a NUMA node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAffinity {
    /// All CPUs on the node are in the affinity mask.
    All,
    /// Some but not all CPUs on the node are in the affinity mask.
    Some,
    /// No CPUs on the node are in the affinity mask.
    None,
}

/// Check whether a CPU set includes any CPU belonging to the given NUMA node.
pub fn includes_node(cpuset: &BTreeSet<u32>, node: u32) -> bool {
    let Ok(node_cpus) = numa_node_cpus(node) else {
        return false;
    };
    node_cpus.iter().any(|cpu| cpuset.contains(cpu))
}

/// Return the affinity relationship between a CPU set and a NUMA node.
pub fn node_affinity(cpuset: &BTreeSet<u32>, node: u32) -> NodeAffinity {
    let Ok(node_cpus) = numa_node_cpus(node) else {
        return NodeAffinity::None;
    };
    let total = node_cpus.len();
    if total == 0 {
        return NodeAffinity::None;
    }
    let matching = node_cpus.iter().filter(|cpu| cpuset.contains(cpu)).count();
    if matching == 0 {
        NodeAffinity::None
    } else if matching == total {
        NodeAffinity::All
    } else {
        NodeAffinity::Some
    }
}

/// Parse a kernel list-format string like "0-3,5,7-8" into a `BTreeSet<u32>`.
pub(crate) fn parse_list_format(s: &str) -> io::Result<BTreeSet<u32>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut cpus = BTreeSet::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u32 = start.trim().parse().map_err(|e| {
                super::parse_error(&format!("range start '{}'", start.trim()), &format!("{e}"))
            })?;
            let end: u32 = end.trim().parse().map_err(|e| {
                super::parse_error(&format!("range end '{}'", end.trim()), &format!("{e}"))
            })?;
            if start > end {
                return Err(super::parse_error(
                    &format!("range {start}-{end}"),
                    "start > end",
                ));
            }
            cpus.extend(start..=end);
        } else {
            let val: u32 = part
                .parse()
                .map_err(|e| super::parse_error(&format!("value '{part}'"), &format!("{e}")))?;
            cpus.insert(val);
        }
    }
    Ok(cpus)
}

/// Return the list of online NUMA nodes from `/sys/devices/system/node/online`.
pub fn numa_online_nodes() -> io::Result<BTreeSet<u32>> {
    let content = std::fs::read_to_string("/sys/devices/system/node/online")
        .map_err(|e| io::Error::other(format!("failed to read NUMA online nodes: {e}")))?;
    parse_list_format(&content)
}

/// Return the set of online CPUs from `/sys/devices/system/cpu/online`.
fn online_cpus() -> io::Result<BTreeSet<u32>> {
    let content = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .map_err(|e| io::Error::other(format!("failed to read online CPUs: {e}")))?;
    parse_list_format(&content)
}

/// Return the set of online CPUs belonging to a given NUMA node.
///
/// This intersects the node's CPU list with the set of online CPUs so that
/// offline CPUs do not skew affinity comparisons against `sched_getaffinity`,
/// which only reports online CPUs.
pub(crate) fn numa_node_cpus(node: u32) -> io::Result<BTreeSet<u32>> {
    let path = format!("/sys/devices/system/node/node{node}/cpulist");
    let content = std::fs::read_to_string(&path)
        .map_err(|e| io::Error::other(format!("failed to read {path}: {e}")))?;
    let node_cpus = parse_list_format(&content)?;
    let online = online_cpus()?;
    Ok(node_cpus.intersection(&online).copied().collect())
}

/// Determine which NUMA node a given CPU belongs to.
pub fn cpu_to_node(cpu: u32) -> Option<u32> {
    let nodes = numa_online_nodes().ok()?;
    for &node in &nodes {
        if let Ok(cpus) = numa_node_cpus(node) {
            if cpus.contains(&cpu) {
                return Some(node);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_format_single() {
        let set = parse_list_format("5").unwrap();
        assert!(set.contains(&5));
        assert!(!set.contains(&4));
    }

    #[test]
    fn parse_list_format_range() {
        let set = parse_list_format("0-3").unwrap();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn parse_list_format_mixed() {
        let set = parse_list_format("0-2,5,7-8").unwrap();
        assert_eq!(
            set.iter().copied().collect::<Vec<_>>(),
            vec![0, 1, 2, 5, 7, 8]
        );
    }

    #[test]
    fn parse_list_format_empty() {
        let set = parse_list_format("").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn parse_list_format_deduplicates() {
        let set = parse_list_format("1,1,2").unwrap();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn parse_list_format_invalid_range() {
        assert!(parse_list_format("5-2").is_err());
    }
}
