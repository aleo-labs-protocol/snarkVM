// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

/// Returns the 32-byte SHA3-256 checksum of the given source code in string format.
pub(crate) fn source_code_checksum<N: Network>(source: &str) -> [U8<N>; 32] {
    let mut keccak = TinySha3::v256();
    keccak.update(source.as_bytes());

    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    hash.map(U8::new)
}

impl<N: Network> ProgramCore<N> {
    /// Returns the checksum of the program.
    ///
    /// The checksum is a 32-byte hash of the program's source code in string format.
    /// This ensures a strict definition of program equivalence, useful for program upgradability.
    pub fn to_checksum(&self) -> [U8<N>; 32] {
        source_code_checksum(&self.to_string())
    }
}
