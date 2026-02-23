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

/// A set of CPU IDs, stored as a sorted, deduplicated vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuSet {
    cpus: Vec<u32>,
}

impl CpuSet {
    pub fn contains(&self, cpu: u32) -> bool {
        self.cpus.binary_search(&cpu).is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.cpus.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.cpus.iter().copied()
    }

    /// Return the intersection of two sorted CPU sets.
    pub fn intersection(&self, other: &CpuSet) -> CpuSet {
        let mut cpus = Vec::new();
        let (mut i, mut j) = (0, 0);
        while i < self.cpus.len() && j < other.cpus.len() {
            match self.cpus[i].cmp(&other.cpus[j]) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    cpus.push(self.cpus[i]);
                    i += 1;
                    j += 1;
                }
            }
        }
        CpuSet { cpus }
    }

    /// Check whether this set includes any CPU belonging to the given NUMA node.
    pub fn includes_node(&self, node: u32) -> bool {
        let Ok(node_cpus) = numa_node_cpus(node) else {
            return false;
        };
        let result = node_cpus.iter().any(|cpu| self.contains(cpu));
        result
    }

    /// Return the affinity relationship between this CPU set and a NUMA node.
    pub fn node_affinity(&self, node: u32) -> NodeAffinity {
        let Ok(node_cpus) = numa_node_cpus(node) else {
            return NodeAffinity::None;
        };
        let total = node_cpus.iter().count();
        if total == 0 {
            return NodeAffinity::None;
        }
        let matching = node_cpus.iter().filter(|&cpu| self.contains(cpu)).count();
        if matching == 0 {
            NodeAffinity::None
        } else if matching == total {
            NodeAffinity::All
        } else {
            NodeAffinity::Some
        }
    }
}

impl From<nix::sched::CpuSet> for CpuSet {
    fn from(nix_set: nix::sched::CpuSet) -> Self {
        let mut cpus = Vec::new();
        for i in 0..nix::sched::CpuSet::count() {
            if nix_set.is_set(i).unwrap_or(false) {
                cpus.push(i as u32);
            }
        }
        CpuSet { cpus }
    }
}

/// Parse a kernel list-format string like "0-3,5,7-8" into a `CpuSet`.
pub(crate) fn parse_list_format(s: &str) -> Result<CpuSet, super::Error> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(CpuSet { cpus: Vec::new() });
    }
    let mut cpus = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u32 = start.trim().parse().map_err(|e| {
                super::Error::parse(
                    &format!("range start '{}'", start.trim()),
                    &format!("{}", e),
                )
            })?;
            let end: u32 = end.trim().parse().map_err(|e| {
                super::Error::parse(&format!("range end '{}'", end.trim()), &format!("{}", e))
            })?;
            if start > end {
                return Err(super::Error::parse(
                    &format!("range {}-{}", start, end),
                    "start > end",
                ));
            }
            cpus.extend(start..=end);
        } else {
            let val: u32 = part.parse().map_err(|e| {
                super::Error::parse(&format!("value '{}'", part), &format!("{}", e))
            })?;
            cpus.push(val);
        }
    }
    cpus.sort();
    cpus.dedup();
    Ok(CpuSet { cpus })
}

/// Return the list of online NUMA nodes from `/sys/devices/system/node/online`.
pub fn numa_online_nodes() -> Result<CpuSet, super::Error> {
    let content = std::fs::read_to_string("/sys/devices/system/node/online")
        .map_err(|e| super::Error::Parse(format!("failed to read NUMA online nodes: {}", e)))?;
    parse_list_format(&content)
}

/// Return the set of online CPUs from `/sys/devices/system/cpu/online`.
fn online_cpus() -> Result<CpuSet, super::Error> {
    let content = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .map_err(|e| super::Error::Parse(format!("failed to read online CPUs: {}", e)))?;
    parse_list_format(&content)
}

/// Return the set of online CPUs belonging to a given NUMA node.
///
/// This intersects the node's CPU list with the set of online CPUs so that
/// offline CPUs do not skew affinity comparisons against `sched_getaffinity`,
/// which only reports online CPUs.
pub(crate) fn numa_node_cpus(node: u32) -> Result<CpuSet, super::Error> {
    let path = format!("/sys/devices/system/node/node{}/cpulist", node);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| super::Error::Parse(format!("failed to read {}: {}", path, e)))?;
    let node_cpus = parse_list_format(&content)?;
    let online = online_cpus()?;
    Ok(node_cpus.intersection(&online))
}

/// Format a sorted slice of node IDs, collapsing consecutive runs into ranges.
///
/// For example, `[0, 1, 2, 5, 7, 8]` becomes `"0-2,5,7-8"`.
pub fn format_node_list(nodes: &[u32]) -> String {
    if nodes.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut start = nodes[0];
    let mut end = nodes[0];

    for &n in &nodes[1..] {
        if n == end + 1 {
            end = n;
        } else {
            if end > start + 1 {
                parts.push(format!("{}-{}", start, end));
            } else if end > start {
                parts.push(format!("{},{}", start, end));
            } else {
                parts.push(format!("{}", start));
            }
            start = n;
            end = n;
        }
    }

    if end > start + 1 {
        parts.push(format!("{}-{}", start, end));
    } else if end > start {
        parts.push(format!("{},{}", start, end));
    } else {
        parts.push(format!("{}", start));
    }

    parts.join(",")
}

/// Determine which NUMA node a given CPU belongs to.
pub fn cpu_to_node(cpu: u32) -> Option<u32> {
    let nodes = numa_online_nodes().ok()?;
    for node in nodes.iter() {
        if let Ok(cpus) = numa_node_cpus(node) {
            if cpus.contains(cpu) {
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
        assert!(set.contains(5));
        assert!(!set.contains(4));
    }

    #[test]
    fn parse_list_format_range() {
        let set = parse_list_format("0-3").unwrap();
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn parse_list_format_mixed() {
        let set = parse_list_format("0-2,5,7-8").unwrap();
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![0, 1, 2, 5, 7, 8]);
    }

    #[test]
    fn parse_list_format_empty() {
        let set = parse_list_format("").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn parse_list_format_deduplicates() {
        let set = parse_list_format("1,1,2").unwrap();
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn parse_list_format_invalid_range() {
        assert!(parse_list_format("5-2").is_err());
    }

    #[test]
    fn format_node_list_single() {
        assert_eq!(format_node_list(&[3]), "3");
    }

    #[test]
    fn format_node_list_consecutive_range() {
        assert_eq!(format_node_list(&[0, 1, 2, 3]), "0-3");
    }

    #[test]
    fn format_node_list_two_consecutive() {
        assert_eq!(format_node_list(&[4, 5]), "4,5");
    }

    #[test]
    fn format_node_list_mixed() {
        assert_eq!(format_node_list(&[0, 1, 2, 5, 7, 8]), "0-2,5,7,8");
    }

    #[test]
    fn format_node_list_empty() {
        assert_eq!(format_node_list(&[]), "");
    }

    #[test]
    fn format_node_list_gaps() {
        assert_eq!(format_node_list(&[0, 2, 4]), "0,2,4");
    }
}
