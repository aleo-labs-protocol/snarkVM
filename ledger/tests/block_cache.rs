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

//! Integration tests for the ledger block cache functionality.

use snarkvm_ledger::{
    Ledger,
    test_helpers::{CurrentConsensusStore, CurrentLedger, CurrentNetwork, LedgerType},
};
use snarkvm_ledger_store::StorageMode;

use snarkvm_console::{account::PrivateKey, prelude::*};
use snarkvm_synthesizer::vm::VM;

/// Tests that the block cache is properly initialized with existing blocks from storage.
#[test]
fn test_block_cache_initialization() {
    let rng = &mut TestRng::default();

    // Initialize a ledger without block cache and add some blocks.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    const NUM_BLOCKS: u32 = 15; // More than cache size (10) to test initialization logic

    // Generate some block in the storage.
    let temp_ledger = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();
    for _ in 1..=NUM_BLOCKS {
        let transactions = vec![];
        let block =
            temp_ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], transactions, rng).unwrap();
        temp_ledger.advance_to_next_block(&block).unwrap();
    }

    // Now load a new ledger and ensure that the block cache is correclty populated.
    let ledger = Ledger::<CurrentNetwork, LedgerType>::load(genesis.clone(), StorageMode::new_test(None)).unwrap();

    // Verify that recent blocks can be retrieved quickly (should be in cache).
    let latest_height = ledger.latest_height();

    // Test retrieval of the 10 most recent blocks (should be in cache).
    for height in (latest_height.saturating_sub(9))..=latest_height {
        let block = ledger.get_block(height).unwrap();
        assert_eq!(block.height(), height);
    }

    // Test retrieval of older blocks (should not be in cache but still accessible).
    for height in 0..=(latest_height.saturating_sub(10)) {
        let block = ledger.get_block(height).unwrap();
        assert_eq!(block.height(), height);
    }
}

/// Tests cache hit and miss behavior when retrieving blocks.
#[test]
fn test_block_cache_hit_miss_behavior() {
    let rng = &mut TestRng::default();

    // Create a ledger with block cache enabled.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    let ledger = Ledger::<CurrentNetwork, LedgerType>::load(genesis.clone(), StorageMode::new_test(None)).unwrap();

    let cache_size = ledger.block_cache_size().expect("No cache size found");
    assert!(cache_size > 0, "Cache size is 0");

    // Add blocks to fill and exceed the cache.
    let mut block_hashes = vec![genesis.hash()];

    for _ in 1..=(cache_size + 5) {
        let transactions = vec![];
        let block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], transactions, rng).unwrap();
        let block_hash = block.hash();
        ledger.advance_to_next_block(&block).unwrap();
        block_hashes.push(block_hash);
    }

    let latest_height = ledger.latest_height();

    // Test cache hits: Recent blocks should be fast to retrieve.
    for height in (latest_height.saturating_sub(cache_size - 1))..=latest_height {
        let start = std::time::Instant::now();
        let block = ledger.get_block(height).unwrap();
        let duration = start.elapsed();

        assert_eq!(block.height(), height);
        assert_eq!(block.hash(), block_hashes[height as usize]);

        // Recent blocks should be retrieved quickly from cache.
        // This is a rough performance check - exact timing depends on system.
        assert!(duration.as_micros() < 1000, "Block {height} retrieval took too long: {duration:?}");
    }

    // Test cache misses: Older blocks should still be accessible but may be slower.
    for height in 0..=(latest_height.saturating_sub(cache_size)) {
        let block = ledger.get_block(height).unwrap();

        assert_eq!(block.height(), height);
        assert_eq!(block.hash(), block_hashes[height as usize]);
    }
}

/// Tests that the cache properly evicts old blocks when new ones are added.
#[test]
fn test_block_cache_eviction() {
    let rng = &mut TestRng::default();

    // Create a ledger with block cache enabled.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    let ledger = Ledger::<CurrentNetwork, LedgerType>::load(genesis.clone(), StorageMode::new_test(None)).unwrap();

    // Add exactly 10 blocks to fill the cache.
    for i in 1..=10 {
        let transactions = vec![];
        let block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], transactions, rng).unwrap();
        ledger.advance_to_next_block(&block).unwrap();

        // Verify the block was added correctly.
        assert_eq!(ledger.latest_height(), i);
    }

    // At this point, cache should contain blocks 1-10 (genesis block 0 may or may not be cached).
    let initial_height = ledger.latest_height();

    // Add 5 more blocks, which should cause eviction of the oldest cached blocks.
    for i in 1..=5 {
        let transactions = vec![];
        let block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], transactions, rng).unwrap();
        ledger.advance_to_next_block(&block).unwrap();

        assert_eq!(ledger.latest_height(), initial_height + i);
    }

    let final_height = ledger.latest_height();

    // Verify that all blocks are still accessible, regardless of cache state.
    for height in 0..=final_height {
        let block = ledger.get_block(height).unwrap();
        assert_eq!(block.height(), height);
    }

    // Verify that the most recent 10 blocks should be the fastest to access.
    let cache_start = final_height.saturating_sub(9);
    for height in cache_start..=final_height {
        let start = std::time::Instant::now();
        let _block = ledger.get_block(height).unwrap();
        let duration = start.elapsed();

        // Recent blocks should be retrieved quickly from cache.
        assert!(duration.as_micros() < 1000, "Cached block {height} retrieval took too long: {duration:?}");
    }
}

/// Tests performance comparison between ledgers with and without block cache.
#[test]
fn test_block_cache_performance_comparison() {
    let rng = &mut TestRng::default();

    // Create two identical ledgers: one with cache, one without.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Create a common genesis block for both ledgers.
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    // Ledger without cache.
    let ledger_no_cache = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();

    // Ledger with cache.
    let ledger_with_cache =
        Ledger::<CurrentNetwork, LedgerType>::load(genesis.clone(), StorageMode::new_test(None)).unwrap();

    // Add the same blocks to both ledgers.
    const NUM_BLOCKS: u32 = 20;
    for _ in 1..=NUM_BLOCKS {
        let transactions = vec![];

        // Add to non-cached ledger.
        let block = ledger_no_cache
            .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], transactions.clone(), rng)
            .unwrap();
        ledger_no_cache.advance_to_next_block(&block).unwrap();

        // Add the same block to cached ledger.
        ledger_with_cache.advance_to_next_block(&block).unwrap();
    }

    // Test retrieval performance for recent blocks (should be cached).
    let latest_height = ledger_with_cache.latest_height();
    let test_heights: Vec<u32> = (latest_height.saturating_sub(9)..=latest_height).collect();

    // Measure performance without cache.
    let start_no_cache = std::time::Instant::now();
    for &height in &test_heights {
        let _block = ledger_no_cache.get_block(height).unwrap();
    }
    let duration_no_cache = start_no_cache.elapsed();

    // Measure performance with cache.
    let start_with_cache = std::time::Instant::now();
    for &height in &test_heights {
        let _block = ledger_with_cache.get_block(height).unwrap();
    }
    let duration_with_cache = start_with_cache.elapsed();

    // Cache should provide some performance benefit for recent blocks.
    // Note: In memory storage, the difference might be minimal, but with RocksDB it should be more significant.
    println!("No cache: {duration_no_cache:?}, With cache: {duration_with_cache:?}");

    // Verify both ledgers return the same blocks.
    for height in 0..=latest_height {
        let block_no_cache = ledger_no_cache.get_block(height).unwrap();
        let block_with_cache = ledger_with_cache.get_block(height).unwrap();
        assert_eq!(block_no_cache.hash(), block_with_cache.hash(), "different block hashes at height {height}");
        assert_eq!(block_no_cache.height(), block_with_cache.height());
    }
}

/// Tests cache behavior during block advancement operations.
#[test]
fn test_block_cache_during_advancement() {
    let rng = &mut TestRng::default();

    // Create a ledger with block cache enabled.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    let ledger = Ledger::<CurrentNetwork, LedgerType>::load(genesis.clone(), StorageMode::new_test(None)).unwrap();

    // Test cache behavior during sequential block additions.
    const NUM_BLOCKS: u32 = 25; // Exceeds cache size to test eviction
    let mut added_blocks = vec![genesis];

    for i in 1..=NUM_BLOCKS {
        let transactions = vec![];
        let block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], transactions, rng).unwrap();

        // Test that we can retrieve the current latest block before advancement.
        let current_latest = ledger.get_block(ledger.latest_height()).unwrap();
        assert_eq!(current_latest.height(), i - 1);

        // Advance to the next block.
        ledger.advance_to_next_block(&block).unwrap();
        added_blocks.push(block.clone());

        // Test that the new block is immediately available.
        let new_latest = ledger.get_block(ledger.latest_height()).unwrap();
        assert_eq!(new_latest.height(), i);
        assert_eq!(new_latest.hash(), block.hash());

        // Test that previous blocks are still accessible.
        if i >= 10 {
            // Test both cached and potentially non-cached blocks.
            let recent_block = ledger.get_block(i - 5).unwrap();
            assert_eq!(recent_block.height(), i - 5);

            if i >= 15 {
                let older_block = ledger.get_block(i - 15).unwrap();
                assert_eq!(older_block.height(), i - 15);
            }
        }
    }

    // Final verification: all blocks should be accessible.
    for (expected_height, expected_block) in added_blocks.iter().enumerate() {
        let retrieved_block = ledger.get_block(expected_height as u32).unwrap();
        assert_eq!(retrieved_block.hash(), expected_block.hash());
        assert_eq!(retrieved_block.height(), expected_height as u32);
    }

    // Test batch retrieval of recent blocks (should leverage cache).
    let latest_height = ledger.latest_height();
    let recent_heights: Vec<u32> = (latest_height.saturating_sub(9)..=latest_height).collect();

    let start = std::time::Instant::now();
    let recent_blocks = ledger.get_blocks(recent_heights[0]..recent_heights[recent_heights.len() - 1] + 1).unwrap();
    let duration = start.elapsed();

    assert_eq!(recent_blocks.len(), recent_heights.len());
    for (block, &expected_height) in recent_blocks.iter().zip(&recent_heights) {
        assert_eq!(block.height(), expected_height);
    }

    // Recent block retrieval should be fast.
    assert!(duration.as_millis() < 100, "Batch retrieval of recent blocks took too long: {duration:?}");
}
