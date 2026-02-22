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

    /// Check whether this set includes any CPU belonging to the given NUMA node.
    pub fn includes_node(&self, node: u32) -> bool {
        let Ok(node_cpus) = numa_node_cpus(node) else {
            return false;
        };
        let result = node_cpus.iter().any(|cpu| self.contains(cpu));
        result
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
pub fn parse_list_format(s: &str) -> Result<CpuSet, super::Error> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(CpuSet { cpus: Vec::new() });
    }
    let mut cpus = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u32 = start.trim().parse().map_err(|e| {
                super::Error::Parse(format!("invalid range start '{}': {}", start.trim(), e))
            })?;
            let end: u32 = end.trim().parse().map_err(|e| {
                super::Error::Parse(format!("invalid range end '{}': {}", end.trim(), e))
            })?;
            if start > end {
                return Err(super::Error::Parse(format!(
                    "invalid range {}-{}",
                    start, end
                )));
            }
            cpus.extend(start..=end);
        } else {
            let val: u32 = part
                .parse()
                .map_err(|e| super::Error::Parse(format!("invalid value '{}': {}", part, e)))?;
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

/// Return the set of CPUs belonging to a given NUMA node.
pub fn numa_node_cpus(node: u32) -> Result<CpuSet, super::Error> {
    let path = format!("/sys/devices/system/node/node{}/cpulist", node);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| super::Error::Parse(format!("failed to read {}: {}", path, e)))?;
    parse_list_format(&content)
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
}
