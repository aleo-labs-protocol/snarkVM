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

#![cfg(feature = "rocks")]

use snarkvm_console::{network::MainnetV0, prelude::TestRng};
use snarkvm_ledger_store::{BlockStore, helpers::rocksdb::BlockDB};

use aleo_std::StorageMode;
use std::{env, path::PathBuf, process::Command};

type CurrentNetwork = MainnetV0;

/// The env variable instructing the (re-invoked) test binary to act as the primary instance.
const PRIMARY_ROLE_VAR: &str = "SNARKVM_SECONDARY_TEST_PRIMARY_ROLE";
/// The env variable containing the path to the primary instance.
const PRIMARY_PATH_VAR: &str = "SNARKVM_SECONDARY_TEST_PRIMARY_PATH";

/// Runs the primary instance in a separate process, as only one database may be open per process.
fn run_primary(primary_path: &PathBuf, role: &str) {
    let status = Command::new(env::current_exe().unwrap())
        .args(["test_secondary_catches_up_with_primary", "--exact", "--nocapture"])
        .env(PRIMARY_ROLE_VAR, role)
        .env(PRIMARY_PATH_VAR, primary_path)
        .status()
        .unwrap();
    assert!(status.success(), "The primary instance failed while performing '{role}'");
}

#[test]
fn test_secondary_catches_up_with_primary() {
    // Act as the primary instance if instructed to.
    if let Ok(role) = env::var(PRIMARY_ROLE_VAR) {
        let primary_path = PathBuf::from(env::var(PRIMARY_PATH_VAR).unwrap());
        let block_store =
            BlockStore::<CurrentNetwork, BlockDB<_>>::open(StorageMode::Custom(primary_path, None)).unwrap();

        if role == "insert" {
            let block = snarkvm_ledger_test_helpers::sample_genesis_block(&mut TestRng::default());
            block_store.insert(&block).unwrap();
        }

        return;
    }

    let primary_dir = tempfile::tempdir().unwrap();
    let secondary_dir = tempfile::tempdir().unwrap();
    let primary_path = primary_dir.path().to_owned();

    // Create the (empty) primary instance.
    run_primary(&primary_path, "create");

    // Open the secondary instance.
    let storage_mode = StorageMode::Custom(primary_path.clone(), Some(secondary_dir.path().to_owned()));
    let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode).unwrap();
    assert_eq!(block_store.max_height(), None);

    // Insert a block using the primary instance.
    run_primary(&primary_path, "insert");

    // The block is not visible to the secondary instance before it catches up.
    assert_eq!(block_store.max_height(), None);

    // Catch up with the primary instance.
    block_store.catch_up_with_primary().unwrap();

    // The block is now readable from the secondary instance.
    assert_eq!(block_store.max_height(), Some(0));
    let block_hash = block_store.get_block_hash(0).unwrap().unwrap();
    let block = block_store.get_block(&block_hash).unwrap().unwrap();
    assert_eq!(block.height(), 0);
    assert_eq!(block.hash(), block_hash);

    // The secondary instance is read-only.
    assert!(block_store.insert(&block).is_err());

    // The block tree is not cached in either instance's directory.
    drop(block_store);
    assert!(!primary_path.join("block_tree").exists());
    assert!(!secondary_dir.path().join("block_tree").exists());
}
