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

//! Initial stack discovery of args and environment.
//!
//! On Linux, the kernel's `create_elf_tables` places these items on the
//! initial process stack (from high to low addresses):
//!
//! ```text
//!   [string data: argv strings, environ strings, AT_EXECFN string]
//!   AT_RANDOM (16 random bytes)
//!   AT_PLATFORM string (NUL-terminated)
//!   AT_BASE_PLATFORM string (NUL-terminated, if present)
//!   [alignment padding]
//!   auxv[N]  = { AT_NULL, 0 }
//!   auxv[N-1]
//!   ...
//!   auxv[0]
//!   NULL                    <-- environ terminator
//!   envp[M-1]
//!   ...
//!   envp[0]
//!   NULL                    <-- argv terminator
//!   argv[argc-1]
//!   ...
//!   argv[0]
//!   argc
//! ```
//!
//! This module scans downward from `AT_RANDOM` (which sits just above
//! the auxv) to locate the auxv array's `AT_NULL` terminator, then
//! walks backward to recover `argc`, `argv[]`, and `environ[]`.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt;

use super::ProcSource;
use crate::model::auxv::Auxv;
use crate::model::auxv::AuxvType;

/// Maximum total entries (argv or environ) to prevent runaway reads.
const MAX_ENTRIES: usize = 1_000_000;

/// Maximum scan window (in word-sized steps) when searching downward
/// from AT_RANDOM for the AT_NULL terminator.  Only needs to cover the
/// 16 random bytes, AT_PLATFORM strings, alignment padding, and the
/// auxv array itself -- a few KiB at most.
const MAX_SCAN_STEPS: usize = 8192;

/// Number of words to read per bulk chunk.
const CHUNK_WORDS: usize = 512;

pub(super) struct InitialStack {
    pub args: Vec<OsString>,
    pub env: Vec<OsString>,
    /// Maps initial-stack string addresses to their values, so that
    /// `read_environ_from_symbol` can skip re-reading env entries that
    /// still point into the initial stack.
    pub string_cache: HashMap<u64, OsString>,
}

fn overflow() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "arithmetic overflow in initial stack walk",
    )
}

/// Read the initial args, environment, and auxv strings from the process
/// stack layout.
///
/// Uses the auxiliary vector to locate the auxv array in memory, then
/// walks backward to find argv and environ pointer arrays.  Also reads
/// the string values at `AT_EXECFN`, `AT_PLATFORM`, and
/// `AT_BASE_PLATFORM` addresses.
pub(super) fn read_initial_stack(source: &dyn ProcSource) -> io::Result<InitialStack> {
    let auxv = source.read_auxv()?;
    let ws = source.word_size() as u64;

    let auxv_val = |typ| {
        auxv.0
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, v)| *v)
            .filter(|&v| v != 0)
    };

    // AT_RANDOM sits just above the auxv array, so the scan distance
    // to AT_NULL is minimal (a few KiB).
    let scan_start = auxv_val(AuxvType::Random)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "AT_RANDOM not found in auxv"))?;

    // Align scan_start down to word boundary.
    let scan_start = scan_start & !(ws - 1);

    let auxv_end = find_auxv_null_addr(source, &auxv, scan_start, ws)?;

    // Compute auxv_base: N entries before AT_NULL.
    let entry_size = 2 * ws;
    let auxv_base = auxv_end
        .checked_sub(auxv.0.len() as u64 * entry_size)
        .ok_or_else(overflow)?;

    verify_auxv_base(source, &auxv, auxv_base)?;

    // auxv_base - word_size should be the NULL terminator of environ[].
    let environ_null = auxv_base.checked_sub(ws).ok_or_else(overflow)?;
    let null_check = source.read_words(environ_null, 1)?[0];
    if null_check != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected NULL environ terminator",
        ));
    }

    // Walk backward to collect environ pointers (stops at argv NULL terminator).
    let (env_ptrs, argv_null) =
        collect_pointers_backward(source, environ_null, ws, |val, _| val == 0)?;

    // Walk backward to collect argv pointers (stops at argc sentinel).
    let (argv_ptrs, _) =
        collect_pointers_backward(source, argv_null, ws, |val, count| val == count as u64)?;

    // Dereference all string pointers in one bulk read.
    let all_ptrs: Vec<u64> = argv_ptrs
        .iter()
        .chain(env_ptrs.iter())
        .copied()
        .chain(auxv_val(AuxvType::ExecFn))
        .chain(auxv_val(AuxvType::Platform))
        .chain(auxv_val(AuxvType::BasePlatform))
        .collect();

    let page_size = auxv_val(AuxvType::PageSz).unwrap_or(4096) as usize;
    let string_cache = bulk_read_strings(source, &all_ptrs, page_size)?;

    let args = argv_ptrs.iter().map(|p| string_cache[p].clone()).collect();
    let env = env_ptrs.iter().map(|p| string_cache[p].clone()).collect();

    Ok(InitialStack {
        args,
        env,
        string_cache,
    })
}

/// Scan downward from `scan_start` to find the AT_NULL (0, 0) entry that
/// terminates the auxv array.
///
/// Reads words in bulk chunks to minimize syscalls.  Validates each
/// candidate by checking that the entry before it matches the last
/// known auxv entry.
fn find_auxv_null_addr(
    source: &dyn ProcSource,
    auxv: &Auxv,
    scan_start: u64,
    ws: u64,
) -> io::Result<u64> {
    let entry_size = 2 * ws;
    let top_addr = scan_start.checked_add(ws).ok_or_else(overflow)?;
    let mut chunk_hi = top_addr;
    let mut pairs_checked: usize = 0;

    while pairs_checked < MAX_SCAN_STEPS {
        let remaining = MAX_SCAN_STEPS - pairs_checked;
        // N words yield N-1 candidate pairs.
        let n_words = (remaining + 1).min(CHUNK_WORDS);
        let chunk_lo = chunk_hi
            .checked_sub((n_words as u64 - 1) * ws)
            .ok_or_else(overflow)?;

        let words = source.read_words(chunk_lo, n_words)?;

        // Scan pairs from high to low.
        let n_pairs = n_words - 1;
        for j in (0..n_pairs).rev() {
            if words[j] == 0 && words[j + 1] == 0 {
                let candidate = chunk_lo + j as u64 * ws;
                if is_real_auxv_null(source, auxv, candidate, entry_size, &words, j)? {
                    return Ok(candidate);
                }
            }
        }

        pairs_checked += n_pairs;
        // Next chunk overlaps by one word so boundary-straddling pairs
        // are not missed.
        chunk_hi = chunk_lo;
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "could not locate AT_NULL terminator in memory",
    ))
}

/// Check that the auxv entry immediately before `candidate` matches the
/// last known entry in `auxv`, confirming this is the real AT_NULL.
///
/// Uses the already-fetched `chunk` data when the previous entry falls
/// within the chunk (i.e. `chunk_index >= 2`), avoiding an extra read.
fn is_real_auxv_null(
    source: &dyn ProcSource,
    auxv: &Auxv,
    candidate: u64,
    entry_size: u64,
    chunk: &[u64],
    chunk_index: usize,
) -> io::Result<bool> {
    let Some(&(ref expected_type, expected_value)) = auxv.0.last() else {
        // Empty auxv -- the AT_NULL is the only entry.
        return Ok(true);
    };

    let (prev_type_raw, prev_val) = if chunk_index >= 2 {
        (chunk[chunk_index - 2], chunk[chunk_index - 1])
    } else {
        let prev = candidate.checked_sub(entry_size).ok_or_else(overflow)?;
        let w = source.read_words(prev, 2)?;
        (w[0], w[1])
    };

    Ok(AuxvType::from(prev_type_raw) == *expected_type && prev_val == expected_value)
}

/// Verify that the first auxv entry at `auxv_base` matches expectations.
fn verify_auxv_base(source: &dyn ProcSource, auxv: &Auxv, auxv_base: u64) -> io::Result<()> {
    if let Some(&(ref expected_type, expected_value)) = auxv.0.first() {
        let first = source.read_words(auxv_base, 2)?;
        if AuxvType::from(first[0]) != *expected_type || first[1] != expected_value {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auxv base verification failed",
            ));
        }
    }
    Ok(())
}

/// Walk backward from `above` collecting pointer-sized words into a vector.
///
/// Stops when `is_sentinel(word_value, count_so_far)` returns true.
/// Returns the collected pointers (in forward order) and the address of
/// the sentinel word.
fn collect_pointers_backward(
    source: &dyn ProcSource,
    above: u64,
    ws: u64,
    is_sentinel: impl Fn(u64, usize) -> bool,
) -> io::Result<(Vec<u64>, u64)> {
    let mut ptrs = Vec::new();
    let mut walk_hi = above;

    loop {
        let max_words = CHUNK_WORDS.min(MAX_ENTRIES + 1 - ptrs.len());
        let chunk_lo = walk_hi
            .checked_sub(max_words as u64 * ws)
            .ok_or_else(overflow)?;
        let words = source.read_words(chunk_lo, max_words)?;

        for j in (0..max_words).rev() {
            if is_sentinel(words[j], ptrs.len()) {
                let sentinel_addr = chunk_lo + j as u64 * ws;
                ptrs.reverse();
                return Ok((ptrs, sentinel_addr));
            }
            if ptrs.len() >= MAX_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pointer array too large",
                ));
            }
            ptrs.push(words[j]);
        }

        walk_hi = chunk_lo;
    }
}

/// Dereference a set of string pointers via chunked bulk reads.
///
/// Sorts pointers by address so a single large read typically covers the
/// entire initial stack string region.  Returns a map from address to
/// string value.
fn bulk_read_strings(
    source: &dyn ProcSource,
    ptrs: &[u64],
    page_size: usize,
) -> io::Result<HashMap<u64, OsString>> {
    // Linux limits each argv/environ string to PAGE_SIZE * 32 bytes;
    // double it for good measure.
    let max_string_len = page_size * 64;

    // The total argv+environ string data on the initial stack is bounded
    // by ARG_MAX.  On Linux with the default 8 MiB stack limit,
    // sysconf(_SC_ARG_MAX) returns 2 MiB (512 * PAGE_SIZE).  Double it
    // as a generous maximum span to prevent runaway allocations when the
    // stack walk produces garbage pointers.
    let max_span = page_size * 1024;

    let mut sorted: Vec<u64> = ptrs.to_vec();
    sorted.sort_unstable();

    let mut results = Vec::with_capacity(sorted.len());
    let mut buf = Vec::<u8>::new();
    let mut buf_start: u64 = 0;

    for &ptr in &sorted {
        // Refill buffer if this pointer is not covered.
        let off = ptr.wrapping_sub(buf_start) as usize;
        if buf.is_empty() || off >= buf.len() {
            buf_start = ptr;
            let tail = sorted
                .last()
                .unwrap()
                .checked_sub(ptr)
                .ok_or_else(overflow)? as usize;
            if tail > max_span {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "initial stack string span too large",
                ));
            }
            let read_len = tail.checked_add(max_string_len).ok_or_else(overflow)?;
            buf.resize(read_len, 0);
            let n = source.read_memory(buf_start, &mut buf)?;
            buf.truncate(n);
        }

        let off = (ptr - buf_start) as usize;
        let s = if off < buf.len() {
            if let Some(nul) = buf[off..].iter().position(|&b| b == 0) {
                OsString::from(OsStr::from_bytes(&buf[off..off + nul]))
            } else {
                // String truncated at chunk boundary; fall back.
                source.read_cstring(ptr)?
            }
        } else {
            source.read_cstring(ptr)?
        };
        results.push(s);
    }

    Ok(sorted.into_iter().zip(results).collect())
}
