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

use std::path::Path;
use std::path::PathBuf;

use nix::sys::stat::SFlag;

/// Flat classification of what an open file descriptor points at.
///
/// Replaces the former `FileType` / `PosixFileType` / `AnonFileType` /
/// `LinkFileType` hierarchy.  Every variant lives at the top level so
/// match arms are single-level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FDTarget {
    // Filesystem-backed -- carry the path
    Regular(PathBuf),
    Directory(PathBuf),
    SymLink(PathBuf),
    BlockDevice(PathBuf),
    CharDevice(PathBuf),
    Fifo(PathBuf),

    // Inode-identified
    Socket(u64),
    Pipe(u64),
    Net(u64),

    // Anonymous inode types
    Epoll,
    EventFd,
    SignalFd,
    TimerFd,
    Inotify,
    PidFd,

    Memfd(String),
    UnknownAnon(String),

    /// Some other fd type with an inode (e.g. `fuse:[12345]`).
    Other(String, u64),
    Unknown,
}

/// Parse an inode from a `"type:[inode]"` string like `"socket:[12345]"`.
fn parse_bracket_inode(s: &str) -> Option<(&str, u64)> {
    let (tag, rest) = s.split_once(":[")?;
    let ino_str = rest.strip_suffix(']')?;
    let ino = ino_str.parse::<u64>().ok()?;
    Some((tag, ino))
}

/// Extract a socket inode from a `"socket:[12345]"` link without
/// allocating.  Used by the system-wide scan in [`list_socket_owners`]
/// to avoid constructing a full [`FDTarget`] for every fd.
pub fn parse_socket_inode(link: &str) -> Option<u64> {
    let (tag, ino) = parse_bracket_inode(link)?;
    (tag == "socket").then_some(ino)
}

fn parse_memfd(link: &str) -> Option<&str> {
    let name = link.strip_prefix("/memfd:")?;
    Some(name.strip_suffix(" (deleted)").unwrap_or(name))
}

impl FDTarget {
    /// Classify an anon-inode link text like `"anon_inode:[eventfd]"`.
    fn classify_anon(link: &str) -> Self {
        let rest = link.strip_prefix("anon_inode:").unwrap_or(link);
        let name = rest
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(rest);

        match name {
            "eventpoll" => Self::Epoll,
            "eventfd" => Self::EventFd,
            "signalfd" => Self::SignalFd,
            "timerfd" => Self::TimerFd,
            "inotify" => Self::Inotify,
            "pidfd" => Self::PidFd,
            other => Self::UnknownAnon(other.to_string()),
        }
    }

    /// From `stat(2)` mode bits, inode, and the fd symlink text.
    pub fn from_stat(mode: u32, ino: u64, link: &str) -> Self {
        let masked = mode & SFlag::S_IFMT.bits();
        if masked == 0 {
            return Self::from_link(link);
        }

        match SFlag::from_bits_truncate(masked) {
            SFlag::S_IFREG => match parse_memfd(link) {
                Some(name) => Self::Memfd(name.to_string()),
                None => Self::Regular(PathBuf::from(link)),
            },
            SFlag::S_IFDIR => Self::Directory(PathBuf::from(link)),
            SFlag::S_IFLNK => Self::SymLink(PathBuf::from(link)),
            SFlag::S_IFBLK => Self::BlockDevice(PathBuf::from(link)),
            SFlag::S_IFCHR => Self::CharDevice(PathBuf::from(link)),
            SFlag::S_IFIFO => {
                // A FIFO from stat could be a named pipe (path) or anonymous pipe.
                // If the link looks like "pipe:[ino]", treat as anonymous pipe.
                if let Some(("pipe", link_ino)) = parse_bracket_inode(link) {
                    Self::Pipe(link_ino)
                } else {
                    Self::Fifo(PathBuf::from(link))
                }
            }
            SFlag::S_IFSOCK => Self::Socket(ino),
            _ => Self::Unknown,
        }
    }

    /// From the `/proc/[pid]/fd/<n>` symlink text alone (used when
    /// `stat()` is unavailable, e.g. coredumps).
    pub fn from_link(link: &str) -> Self {
        if link.starts_with("anon_inode:") {
            return Self::classify_anon(link);
        }

        if let Some((tag, ino)) = parse_bracket_inode(link) {
            return match tag {
                "socket" => Self::Socket(ino),
                "pipe" => Self::Pipe(ino),
                "net" => Self::Net(ino),
                other => Self::Other(other.to_string(), ino),
            };
        }

        if let Some(name) = parse_memfd(link) {
            return Self::Memfd(name.to_string());
        }

        // If it looks like an absolute path, guess Regular.
        if link.starts_with('/') {
            return Self::Regular(PathBuf::from(link));
        }

        Self::Unknown
    }

    /// Path carried by filesystem-backed variants.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Regular(p)
            | Self::Directory(p)
            | Self::SymLink(p)
            | Self::BlockDevice(p)
            | Self::CharDevice(p)
            | Self::Fifo(p) => Some(p),
            _ => None,
        }
    }

    /// Inode for inode-identified variants.
    pub fn inode(&self) -> Option<u64> {
        match self {
            Self::Socket(ino) | Self::Pipe(ino) | Self::Net(ino) | Self::Other(_, ino) => {
                Some(*ino)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nix::sys::stat::SFlag;

    use super::FDTarget;

    #[test]
    fn classify_anon_inode_supports_kernel_formats() {
        assert_eq!(
            FDTarget::from_link("anon_inode:[eventpoll]"),
            FDTarget::Epoll
        );
        assert_eq!(FDTarget::from_link("anon_inode:inotify"), FDTarget::Inotify);
    }

    #[test]
    fn classify_preserves_memfd_detection() {
        assert_eq!(
            FDTarget::from_stat(SFlag::S_IFREG.bits(), 0, "/memfd:name"),
            FDTarget::Memfd("name".to_string())
        );
        assert_eq!(
            FDTarget::from_link("/memfd:name (deleted)"),
            FDTarget::Memfd("name".to_string())
        );
    }

    #[test]
    fn classify_distinguishes_named_and_unnamed_pipes() {
        assert_eq!(
            FDTarget::from_stat(SFlag::S_IFIFO.bits(), 0, "pipe:[123]"),
            FDTarget::Pipe(123)
        );
        assert_eq!(
            FDTarget::from_stat(SFlag::S_IFIFO.bits(), 0, "/tmp/a[1]"),
            FDTarget::Fifo(PathBuf::from("/tmp/a[1]"))
        );
    }
}
