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

use snarkvm_algorithms::snark::varuna::{VarunaVersion, proof_size as varuna_proof_size};

use super::*;

mod bytes;
mod parse;
mod serialize;

#[derive(Clone, PartialEq, Eq)]
pub struct Proof<N: Network> {
    /// The proof.
    proof: varuna::Proof<N::PairingCurve>,
}

impl<N: Network> Proof<N> {
    /// Initializes a new proof.
    pub const fn new(proof: varuna::Proof<N::PairingCurve>) -> Self {
        Self { proof }
    }
}

impl<N: Network> Deref for Proof<N> {
    type Target = varuna::Proof<N::PairingCurve>;

    fn deref(&self) -> &Self::Target {
        &self.proof
    }
}

/// Computes the size in bytes of the proof as produced by
/// `Proof::write_le` without needing to receive the proof itself.
///
/// *Arguments*:
///  - `batch_sizes`: the batch sizes of the circuits and instances being
///    proved.
///  - `varuna_version`: the version of Varuna being used
///  - `hiding`: indicates whether the proof system is run in ZK mode
///
/// *Returns*:
///  - `Ok(size)` for `VarunaVersion::V2` and `VarunaVersion::V3`, where `size` is the size of the proof
///    in bytes.
///  - `Err` for `VarunaVersion::V1`.
pub fn proof_size<N: Network>(
    batch_sizes: &[usize],
    varuna_version: VarunaVersion,
    hiding_mode: bool,
) -> Result<usize> {
    // The extra 1 byte comes from the serialised version number
    varuna_proof_size::<N::PairingCurve>(batch_sizes, varuna_version, hiding_mode).map(|size| 1 + size)
}
