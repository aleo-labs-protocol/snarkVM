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

pub mod chain_builder;
pub use chain_builder::TestChainBuilder;

use crate::{Block, Ledger};
use aleo_std::StorageMode;
use console::{
    account::{Address, PrivateKey, ViewKey},
    network::MainnetV0,
    prelude::*,
};

use snarkvm_circuit::AleoV0;
use snarkvm_ledger_store::{ConsensusStore, helpers::memory::ConsensusMemory};
use snarkvm_synthesizer::vm::VM;

use std::{
    fs,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::UNIX_EPOCH,
};

pub use snarkvm_ledger_test_helpers::*;

pub type CurrentNetwork = MainnetV0;
pub type CurrentAleo = AleoV0;

#[cfg(not(feature = "rocks"))]
pub type CurrentLedger = Ledger<CurrentNetwork, snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>>;
#[cfg(feature = "rocks")]
pub type CurrentLedger = Ledger<CurrentNetwork, snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>>;

#[cfg(not(feature = "rocks"))]
pub type LedgerType = snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>;
#[cfg(feature = "rocks")]
pub type LedgerType = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>;

#[cfg(not(feature = "rocks"))]
pub type CurrentConsensusStore =
    ConsensusStore<CurrentNetwork, snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>>;
#[cfg(feature = "rocks")]
pub type CurrentConsensusStore =
    ConsensusStore<CurrentNetwork, snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>>;

#[cfg(not(feature = "rocks"))]
pub type CurrentConsensusStorage = snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>;
#[cfg(feature = "rocks")]
pub type CurrentConsensusStorage = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>;

pub struct TestEnv {
    pub ledger: CurrentLedger,
    pub private_key: PrivateKey<CurrentNetwork>,
    pub view_key: ViewKey<CurrentNetwork>,
    pub address: Address<CurrentNetwork>,
}

/// Returns a new ledger on the genesis block of the genesis fixture, and the genesis private key.
///
/// Every call returns the same genesis private key and genesis block.
/// The test environment does not depend on `_rng`, and `_rng` is not advanced.
pub fn sample_test_env(_rng: &mut (impl Rng + CryptoRng)) -> TestEnv {
    let (private_key, genesis) = genesis_fixture();
    let view_key = ViewKey::try_from(private_key).unwrap();
    let address = Address::try_from(private_key).unwrap();
    // Sample the ledger.
    let ledger = load_ledger(genesis.clone());
    // Return the test environment.
    TestEnv { ledger, private_key: *private_key, view_key, address }
}

/// Returns a new ledger on a new genesis block, which `private_key` signs.
pub fn sample_ledger(private_key: PrivateKey<CurrentNetwork>, rng: &mut (impl Rng + CryptoRng)) -> CurrentLedger {
    // Initialize the store.
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    // Create a genesis block.
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();
    // Initialize the ledger.
    load_ledger(genesis)
}

/// Returns a new ledger on `genesis`.
fn load_ledger(genesis: Block<CurrentNetwork>) -> CurrentLedger {
    // Initialize the ledger with the genesis block.
    let ledger = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();
    // Ensure the genesis block is correct.
    assert_eq!(genesis, ledger.get_block(0).unwrap());
    // Return the ledger.
    ledger
}

/// The seed of the RNG that builds the genesis fixture.
const GENESIS_FIXTURE_SEED: u64 = 1_779_120_457;

/// Returns the genesis private key and the genesis block that it signs.
///
/// The test processes of one binary share the fixture through a file beside the binary.
fn genesis_fixture() -> &'static (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    static INSTANCE: OnceLock<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> = OnceLock::new();
    INSTANCE.get_or_init(|| match genesis_fixture_path_and_stamp() {
        Ok((path, stamp)) => load_or_build_genesis_fixture(&path, &stamp),
        Err(_) => build_genesis_fixture(),
    })
}

/// Builds the genesis fixture from an RNG with a fixed seed.
fn build_genesis_fixture() -> (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    let rng = &mut TestRng::from_seed(GENESIS_FIXTURE_SEED);
    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).expect("Failed to sample the genesis private key");
    // The genesis block does not depend on the storage of the VM that builds it.
    let store = ConsensusStore::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::open(StorageMode::new_test(None))
        .expect("Failed to open the consensus store");
    let vm = VM::from(store).expect("Failed to initialize the VM");
    // Create a genesis block.
    let block = vm.genesis_beacon(&private_key, rng).expect("Failed to build the genesis block");
    (private_key, block)
}

/// Returns the path of the genesis fixture file of the running binary, and the stamp of that binary.
///
/// The stamp holds the size and the modification time of the binary.
fn genesis_fixture_path_and_stamp() -> io::Result<(PathBuf, Vec<u8>)> {
    let binary = std::env::current_exe()?;
    let metadata = fs::metadata(&binary)?;
    let modified = metadata.modified()?.duration_since(UNIX_EPOCH).map_err(io::Error::other)?;
    let mut stamp = Vec::with_capacity(24);
    stamp.extend_from_slice(&metadata.len().to_le_bytes());
    stamp.extend_from_slice(&modified.as_nanos().to_le_bytes());
    Ok((binary.with_added_extension("ledger-genesis"), stamp))
}

/// Reads the genesis fixture at `path`, or builds the fixture and writes it to `path`.
///
/// An exclusive lock on the sibling `.lock` file lets one process build the fixture while the others wait.
/// A file that cannot be read or parsed, or that holds a different stamp, is rebuilt and overwritten.
fn load_or_build_genesis_fixture(path: &Path, stamp: &[u8]) -> (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    if let Some(fixture) = read_genesis_fixture(path, stamp) {
        return fixture;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path.with_added_extension("lock"))
        .and_then(|file| file.lock().map(|()| file));
    // Without the lock, the fixture is built but not written.
    let Ok(lock) = lock else {
        return build_genesis_fixture();
    };
    // Another process may have written the fixture while this process waited for the lock.
    if let Some(fixture) = read_genesis_fixture(path, stamp) {
        return fixture;
    }
    let fixture = build_genesis_fixture();
    // A failed write leaves the file for a later process to rebuild.
    let _ = write_genesis_fixture(path, stamp, &fixture);
    drop(lock);
    fixture
}

/// Reads the genesis fixture at `path`, if the file holds a valid fixture with the given stamp.
fn read_genesis_fixture(path: &Path, stamp: &[u8]) -> Option<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> {
    genesis_fixture_from_bytes(&fs::read(path).ok()?, stamp)
}

/// Writes the genesis fixture to `path` through a temporary file and a rename.
fn write_genesis_fixture(
    path: &Path,
    stamp: &[u8],
    fixture: &(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>),
) -> io::Result<()> {
    let temporary_path = path.with_added_extension("tmp");
    fs::write(&temporary_path, genesis_fixture_to_bytes(stamp, fixture)?)?;
    fs::rename(temporary_path, path)
}

/// Returns the stamp, followed by the bytes of the genesis private key and the genesis block.
fn genesis_fixture_to_bytes(
    stamp: &[u8],
    fixture: &(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>),
) -> io::Result<Vec<u8>> {
    let mut bytes = stamp.to_vec();
    fixture.write_le(&mut bytes)?;
    Ok(bytes)
}

/// Parses the output of `genesis_fixture_to_bytes`.
///
/// Returns `None` if the bytes hold a different stamp, fail to parse, have trailing bytes,
/// or hold a block that the private key did not sign.
fn genesis_fixture_from_bytes(
    bytes: &[u8],
    stamp: &[u8],
) -> Option<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> {
    let mut reader = bytes.strip_prefix(stamp)?;
    let (private_key, block) = <(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)>::read_le(&mut reader).ok()?;
    let authority = block.authority();
    let is_signer = authority.is_beacon() && Address::try_from(&private_key).ok()? == authority.to_address();
    (reader.is_empty() && is_signer).then_some((private_key, block))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_fixture_cache_hit_matches_miss() {
        let path = std::env::temp_dir().join(format!("snarkvm-ledger-genesis-fixture-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let stamp = b"stamp";

        // The file does not exist yet, so this call builds the fixture and writes the file.
        let miss = load_or_build_genesis_fixture(&path, stamp);
        // This call reads the file that the previous call wrote.
        let hit = read_genesis_fixture(&path, stamp).expect("The fixture file is valid");
        let bytes = fs::read(&path).expect("Failed to read the fixture file");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_added_extension("lock"));

        assert_eq!(miss, hit);
        assert_eq!(bytes, genesis_fixture_to_bytes(stamp, &miss).expect("Failed to serialize the fixture"));
        // The fixture of this process comes from a separate build, in this process or in another one.
        assert_eq!(&miss, genesis_fixture());
    }

    #[test]
    fn test_genesis_fixture_rejects_invalid_bytes() {
        let stamp = b"stamp";
        let fixture = genesis_fixture();
        let (private_key, block) = fixture;
        let bytes = genesis_fixture_to_bytes(stamp, fixture).expect("Failed to serialize the fixture");
        assert!(genesis_fixture_from_bytes(&bytes, stamp).is_some());

        // A different stamp.
        assert!(genesis_fixture_from_bytes(&bytes, b"stamq").is_none());
        // Missing bytes.
        assert!(genesis_fixture_from_bytes(&[], stamp).is_none());
        assert!(genesis_fixture_from_bytes(stamp, stamp).is_none());
        assert!(genesis_fixture_from_bytes(&bytes[..bytes.len() - 1], stamp).is_none());
        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(genesis_fixture_from_bytes(&extended, stamp).is_none());
        // Bytes that do not encode a fixture.
        let mut garbage = stamp.to_vec();
        garbage.resize(bytes.len(), 0xff);
        assert!(genesis_fixture_from_bytes(&garbage, stamp).is_none());
        // A private key that did not sign the block.
        let other_private_key =
            PrivateKey::<CurrentNetwork>::new(&mut TestRng::default()).expect("Failed to sample a private key");
        assert_ne!(other_private_key, *private_key);
        let other_bytes = genesis_fixture_to_bytes(stamp, &(other_private_key, block.clone()))
            .expect("Failed to serialize the fixture");
        assert!(genesis_fixture_from_bytes(&other_bytes, stamp).is_none());
    }

    #[test]
    fn test_sample_test_env_does_not_advance_rng() {
        let rng = &mut TestRng::fixed(1);
        let TestEnv { ledger, private_key, .. } = sample_test_env(rng);
        assert_eq!(rng.random::<u64>(), TestRng::fixed(1).random::<u64>());
        // The test environment holds the genesis fixture.
        let (fixture_private_key, fixture_block) = genesis_fixture();
        assert_eq!(private_key, *fixture_private_key);
        assert_eq!(ledger.get_block(0).expect("Failed to get the genesis block"), *fixture_block);
    }
}
