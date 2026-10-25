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

#[cfg(feature = "test")]
use super::*;
use crate::vm::test_helpers::sample_vm;

use snarkvm_ledger_store::helpers::{Map, MapRead, memory::MemoryMap};

/// Verifies that `prune_rocksdb_state` removes precisely the requested keys from a map
/// while leaving all other entries intact.  This test uses an in-memory map so that no
/// cryptographic parameter download is required.
#[test]
fn test_prune_rocksdb_state_removes_keys() {
    // Create a VM whose sequential-operation queue we will use.
    let vm = sample_vm();

    // Populate an in-memory map with ten entries keyed by u32.
    let map = MemoryMap::<u32, String>::default();
    for i in 0u32..10 {
        map.insert(i, format!("value_{i}")).unwrap();
    }

    // Prune keys 0..5 via the sequential queue.
    let result = vm.prune_rocksdb_state(map.clone(), 0u32..5).unwrap();
    assert!(
        matches!(result, crate::vm::SequentialOperationResult::PruneRocksDBState(Ok(()))),
        "expected pruning to succeed"
    );

    // Keys 0-4 must have been removed.
    for i in 0u32..5 {
        assert!(!map.contains_key_confirmed(&i).unwrap(), "key {i} should have been pruned but is still present");
    }

    // Keys 5-9 must still be present.
    for i in 5u32..10 {
        assert!(map.contains_key_confirmed(&i).unwrap(), "key {i} should still be present but was incorrectly pruned");
    }
}

/// Verifies that authority data (signatures, batch certificates, and transmissions)
/// can be pruned from the block store for rounds older than a given threshold, while
/// all transaction data remains intact.
///
/// # Test overview
/// 1. Create a VM and add five blocks (heights 1-5; each carrying a beacon authority
///    signature).
/// 2. Treat blocks with height <= 3 as "too old" (simulating "older than 100 rounds").
/// 3. Prune the `authority_map` for those blocks via `prune_rocksdb_state`.
/// 4. Assert that:
///    - Authority entries for blocks 1-3 are gone.
///    - Authority entries for blocks 4-5 are still present.
///    - All transaction IDs remain accessible in the store.
#[cfg(feature = "test")]
#[test]
fn test_prune_authority_data_while_keeping_transactions() {
    use crate::vm::test_helpers::{sample_genesis_block, sample_genesis_private_key, sample_next_block};

    let rng = &mut TestRng::default();

    // Initialize the VM with a genesis block.
    let private_key = sample_genesis_private_key(rng);
    let genesis = sample_genesis_block(rng);
    let vm = sample_vm();
    vm.add_next_block(&genesis).unwrap();

    // Add five blocks, each carrying only a beacon authority signature.
    const NUM_BLOCKS: u32 = 5;
    let mut block_hashes = vec![];
    for _ in 0..NUM_BLOCKS {
        let block = sample_next_block(&vm, &private_key, &[], rng).unwrap();
        block_hashes.push(block.hash());
        vm.add_next_block(&block).unwrap();
    }

    // Sanity check: all authority entries are present before pruning.
    let block_store = vm.block_store();
    for hash in &block_hashes {
        assert!(
            block_store.authority_map().contains_key_confirmed(hash).unwrap(),
            "expected authority entry to be present for block {hash}"
        );
    }

    // Collect all transaction IDs present in the added blocks before pruning.
    let mut all_tx_ids = vec![];
    for hash in &block_hashes {
        if let Some(txs) = block_store.get_block_transactions(hash).unwrap() {
            all_tx_ids.extend(txs.transaction_ids().copied());
        }
    }

    // Define the pruning threshold: blocks with height <= 3 are considered "old".
    const PRUNE_HEIGHT_THRESHOLD: u32 = 3;

    // Collect block hashes for the "old" blocks (heights 1-3).
    let old_block_hashes: Vec<_> =
        (1..=PRUNE_HEIGHT_THRESHOLD).filter_map(|h| block_store.get_block_hash(h).ok().flatten()).collect();
    assert_eq!(old_block_hashes.len(), PRUNE_HEIGHT_THRESHOLD as usize);

    // Clone the authority map so the pruning closure can take ownership of it.
    let authority_map = block_store.authority_map().clone();

    // Prune authority data for old blocks via the sequential operation queue.
    let result = vm.prune_rocksdb_state(authority_map, old_block_hashes.clone()).unwrap();
    assert!(
        matches!(result, crate::vm::SequentialOperationResult::PruneRocksDBState(Ok(()))),
        "expected authority pruning to succeed"
    );

    // Verify that authority entries for old blocks have been removed.
    for hash in &old_block_hashes {
        assert!(
            !block_store.authority_map().contains_key_confirmed(hash).unwrap(),
            "expected authority entry to be absent after pruning for block {hash}"
        );
    }

    // Verify that authority entries for the remaining (newer) blocks are still present.
    let new_block_hashes: Vec<_> = ((PRUNE_HEIGHT_THRESHOLD + 1)..=NUM_BLOCKS)
        .filter_map(|h| block_store.get_block_hash(h).ok().flatten())
        .collect();
    for hash in &new_block_hashes {
        assert!(
            block_store.authority_map().contains_key_confirmed(hash).unwrap(),
            "expected authority entry to remain intact for block {hash}"
        );
    }

    // Verify that all transaction IDs are still accessible — transactions must not be pruned.
    for tx_id in &all_tx_ids {
        assert!(
            block_store.contains_transaction_id(tx_id).unwrap(),
            "expected transaction {tx_id} to still be present after authority pruning"
        );
    }
}
