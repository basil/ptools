/// Parse a kernel list-format string like "0-3,5,7-8" into a sorted Vec of values.
pub fn parse_list_format(s: &str) -> Result<Vec<u32>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let start: u32 = start
                .trim()
                .parse()
                .map_err(|e| format!("invalid range start '{}': {}", start.trim(), e))?;
            let end: u32 = end
                .trim()
                .parse()
                .map_err(|e| format!("invalid range end '{}': {}", end.trim(), e))?;
            if start > end {
                return Err(format!("invalid range {}-{}", start, end));
            }
            result.extend(start..=end);
        } else {
            let val: u32 = part
                .parse()
                .map_err(|e| format!("invalid value '{}': {}", part, e))?;
            result.push(val);
        }
    }
    result.sort();
    result.dedup();
    Ok(result)
}

/// Return the list of online NUMA nodes from `/sys/devices/system/node/online`.
pub fn numa_online_nodes() -> Result<Vec<u32>, String> {
    let content = std::fs::read_to_string("/sys/devices/system/node/online")
        .map_err(|e| format!("failed to read NUMA online nodes: {}", e))?;
    parse_list_format(&content)
}

/// Return the list of CPUs belonging to a given NUMA node.
pub fn numa_node_cpus(node: u32) -> Result<Vec<u32>, String> {
    let path = format!("/sys/devices/system/node/node{}/cpulist", node);
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {}", path, e))?;
    parse_list_format(&content)
}

/// Determine which NUMA node a given CPU belongs to.
pub fn cpu_to_node(cpu: u32) -> Option<u32> {
    let nodes = numa_online_nodes().ok()?;
    for node in nodes {
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
        assert_eq!(parse_list_format("5").unwrap(), vec![5]);
    }

    #[test]
    fn parse_list_format_range() {
        assert_eq!(parse_list_format("0-3").unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn parse_list_format_mixed() {
        assert_eq!(
            parse_list_format("0-2,5,7-8").unwrap(),
            vec![0, 1, 2, 5, 7, 8]
        );
    }

    #[test]
    fn parse_list_format_empty() {
        assert_eq!(parse_list_format("").unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn parse_list_format_deduplicates() {
        assert_eq!(parse_list_format("1,1,2").unwrap(), vec![1, 2]);
    }

    #[test]
    fn parse_list_format_invalid_range() {
        assert!(parse_list_format("5-2").is_err());
    }
}
