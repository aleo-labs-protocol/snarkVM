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

use crate::CurrentNetwork;

use console::{
    account::{Address, PrivateKey},
    prelude::*,
};
use snarkvm_ledger_block::Block;
use snarkvm_utilities::load_or_build_fixture;

/// A genesis private key and the genesis block that it signs.
type GenesisFixture = (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>);

/// Returns the genesis fixture of the running binary, which `build` builds from `seed`.
///
/// The processes of one binary share the fixture through the file `<binary>.<extension>`.
/// The file holds the size and the modification time of the binary and the seed,
/// so a rebuilt binary or another seed builds a new fixture.
/// If the file cannot be used, every process builds its own fixture.
/// `build` must return the same fixture for the same seed in every process,
/// and its genesis block must be a beacon block.
pub fn load_or_build_genesis_fixture(
    extension: &str,
    seed: u64,
    build: impl FnOnce(u64) -> GenesisFixture,
) -> GenesisFixture {
    load_or_build_fixture(extension, &seed.to_le_bytes(), is_signed_beacon, || build(seed))
}

/// Returns `true` if the private key signed the block as a beacon.
fn is_signed_beacon((private_key, block): &GenesisFixture) -> bool {
    let authority = block.authority();
    authority.is_beacon() && Address::try_from(private_key).is_ok_and(|address| address == authority.to_address())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sample_genesis_block_and_components, sample_genesis_private_key};

    #[test]
    fn test_only_the_signer_is_valid() {
        let rng = &mut TestRng::default();
        let (block, _, private_key) = sample_genesis_block_and_components(rng);
        assert_eq!(private_key, sample_genesis_private_key(rng));
        assert!(is_signed_beacon(&(private_key, block.clone())));

        let other_private_key = PrivateKey::<CurrentNetwork>::new(rng).expect("Failed to sample a private key");
        assert_ne!(other_private_key, private_key);
        assert!(!is_signed_beacon(&(other_private_key, block)));
    }
}
