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

pub mod auxv;
pub mod fd;
pub mod fdinfo;
pub mod limits;
pub mod net;
pub mod schedstat;
pub mod stat;
pub mod status;

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::{self};
use std::path::Path;

// ---------------------------------------------------------------------------
// Model parsing traits
// ---------------------------------------------------------------------------

/// A type that can be parsed from a [`Read`] source.
pub trait FromRead: Sized {
    fn from_read(reader: impl Read) -> io::Result<Self>;

    fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path.as_ref())?;
        Self::from_read(file)
    }
}

/// A type that can be parsed line-by-line from a [`BufRead`] source.
pub trait FromBufRead: Sized {
    fn from_buf_read(reader: impl BufRead) -> io::Result<Self>;

    fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path.as_ref())?;
        Self::from_buf_read(BufReader::new(file))
    }
}
