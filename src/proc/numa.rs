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
use std::path::Path;

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

/// Return the affinity relationship between a CPU set and a NUMA node.
pub fn node_affinity(cpuset: &BTreeSet<usize>, node: u32) -> NodeAffinity {
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

/// Return the list of online NUMA nodes from `/sys/devices/system/node/online`.
pub fn numa_online_nodes() -> io::Result<BTreeSet<u32>> {
    let path = Path::new("/sys/devices/system/node/online");
    let content = std::fs::read_to_string(path)?;
    Ok(crate::model::status::parse_cpuset_list(&content)?
        .into_iter()
        .map(|n| n as u32)
        .collect())
}

/// Return the set of online CPUs from `/sys/devices/system/cpu/online`.
fn online_cpus() -> io::Result<BTreeSet<usize>> {
    let path = Path::new("/sys/devices/system/cpu/online");
    let content = std::fs::read_to_string(path)?;
    crate::model::status::parse_cpuset_list(&content)
}

/// Return the set of online CPUs belonging to a given NUMA node.
///
/// This intersects the node's CPU list with the set of online CPUs so that
/// offline CPUs do not skew affinity comparisons against `sched_getaffinity`,
/// which only reports online CPUs.
fn numa_node_cpus(node: u32) -> io::Result<BTreeSet<usize>> {
    let path_str = format!("/sys/devices/system/node/node{node}/cpulist");
    let path = Path::new(&path_str);
    let content = std::fs::read_to_string(path)?;
    let node_cpus = crate::model::status::parse_cpuset_list(&content)?;
    let online = online_cpus()?;
    Ok(node_cpus.intersection(&online).copied().collect())
}

/// Determine which NUMA node a given CPU belongs to.
pub fn cpu_to_node(cpu: u32) -> Option<u32> {
    let nodes = numa_online_nodes().ok()?;
    for &node in &nodes {
        if let Ok(cpus) = numa_node_cpus(node) {
            if cpus.contains(&(cpu as usize)) {
                return Some(node);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::model::status::parse_cpuset_list;

    #[test]
    fn parse_cpuset_list_single() {
        let set = parse_cpuset_list("5").unwrap();
        assert!(set.contains(&5));
        assert!(!set.contains(&4));
    }

    #[test]
    fn parse_cpuset_list_range() {
        let set = parse_cpuset_list("0-3").unwrap();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn parse_cpuset_list_mixed() {
        let set = parse_cpuset_list("0-2,5,7-8").unwrap();
        assert_eq!(
            set.iter().copied().collect::<Vec<_>>(),
            vec![0, 1, 2, 5, 7, 8]
        );
    }

    #[test]
    fn parse_cpuset_list_empty() {
        let set = parse_cpuset_list("").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn parse_cpuset_list_deduplicates() {
        let set = parse_cpuset_list("1,1,2").unwrap();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn parse_cpuset_list_invalid_range() {
        assert!(parse_cpuset_list("5-2").is_err());
    }
}
