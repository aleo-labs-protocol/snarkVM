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

    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn test_invalid_genesis_file_is_rebuilt() {
        let rng = &mut TestRng::default();
        let (block, _, private_key) = sample_genesis_block_and_components(rng);
        assert_eq!(private_key, sample_genesis_private_key(rng));
        let fixture = (private_key, block.clone());
        let fixture_bytes = fixture.to_bytes_le().expect("Failed to serialize the fixture");

        let extension = "test-invalid-genesis-fixture";
        let path = std::env::current_exe().expect("Failed to find the test binary").with_added_extension(extension);
        let _ = fs::remove_file(&path);
        let builds = AtomicUsize::new(0);
        let load = || {
            load_or_build_genesis_fixture(extension, 1, |_| {
                builds.fetch_add(1, Ordering::Relaxed);
                fixture.clone()
            })
        };

        // The first call builds the fixture and writes the file. The second call reads the file.
        assert_eq!(load(), fixture);
        assert_eq!(load(), fixture);
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        let bytes = fs::read(&path).expect("Failed to read the fixture file");
        let stamp = &bytes[..bytes.len() - fixture_bytes.len()];

        // A block that the private key did not sign, and bytes of the same length that do not parse.
        let other_private_key = PrivateKey::<CurrentNetwork>::new(rng).expect("Failed to sample a private key");
        assert_ne!(other_private_key, private_key);
        let other_bytes = (other_private_key, block).to_bytes_le().expect("Failed to serialize the fixture");
        let garbage = vec![0xff; fixture_bytes.len()];
        for (expected_builds, invalid) in [(2, other_bytes), (3, garbage)] {
            fs::write(&path, [stamp, &invalid[..]].concat()).expect("Failed to write the fixture file");
            assert_eq!(load(), fixture);
            assert_eq!(builds.load(Ordering::Relaxed), expected_builds);
            assert_eq!(fs::read(&path).expect("Failed to read the fixture file"), bytes);
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_added_extension("lock"));
    }
}
