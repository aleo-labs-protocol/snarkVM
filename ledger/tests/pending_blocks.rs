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

mod helpers;
use helpers::{BlockOptions, CurrentNetwork, LedgerType, TestChainBuilder};

use snarkvm_ledger::{CheckBlockError, Ledger};

use aleo_std::StorageMode;
use snarkvm_utilities::TestRng;

#[test]
fn test_preprocess_block() {
    let rng = &mut TestRng::default();

    let mut builder = TestChainBuilder::new(4, rng);

    // Construct the ledger.
    let ledger = Ledger::<CurrentNetwork, LedgerType<CurrentNetwork>>::load(
        builder.genesis_block().clone(),
        StorageMode::new_test(None),
    )
    .unwrap();

    // Generate a bunch of blocks that do not contain votes
    let mut pending_blocks = vec![];

    for block in builder.generate_blocks_with_opts(5, &BlockOptions { skip_votes: true, ..Default::default() }, rng) {
        if !pending_blocks.is_empty() {
            // We shoud only be able to pre-process a pending block if the previous
            // blocks are applied to the ledger or in the pending set
            assert!(ledger.check_block_subdag(block.clone(), &[]).is_err());
        }

        let pending_block = ledger.check_block_subdag(block, &pending_blocks).unwrap();
        pending_blocks.push(pending_block);
    }

    // Now, create a "vote block" that contains sufficient votes to the previous leader block
    let vote_block = builder.generate_block(rng);
    assert!(ledger.check_next_block(&vote_block, rng).is_err());

    for pending in pending_blocks.into_iter() {
        let block = ledger.check_block_content(pending, rng).expect("Pending block should be accepted");
        assert!(ledger.advance_to_next_block(&block).is_ok());
    }

    // Now the commit block should be accepted
    assert!(ledger.check_next_block(&vote_block, rng).is_ok());
    assert!(ledger.advance_to_next_block(&vote_block).is_ok());
}

#[test]
fn test_check_block_error_display() {
    // Test that CheckBlockError implements Display correctly
    let error = CheckBlockError::<CurrentNetwork>::InvalidHash;
    let display_string = format!("{error}");
    assert_eq!(display_string, "Block has invalid hash");

    let error = CheckBlockError::<CurrentNetwork>::InvalidHeight { expected: 5, actual: 3 };
    let display_string = format!("{error}");
    assert!(display_string.contains("Expected 5"));
    assert!(display_string.contains("got 3"));
}

#[test]
fn test_prefix_with_duplicate_block_error() {
    let rng = &mut TestRng::default();
    let mut builder = TestChainBuilder::new(4, rng);

    // Construct the ledger.
    let ledger = Ledger::<CurrentNetwork, LedgerType<CurrentNetwork>>::load(
        builder.genesis_block().clone(),
        StorageMode::new_test(None),
    )
    .unwrap();

    // Generate a block
    let block1 = builder.generate_block(rng);

    // Add block1 to ledger
    ledger.advance_to_next_block(&block1).unwrap();

    // Generate another block
    let block2 = builder.generate_block(rng);

    // So instead, test that we can't check a block with empty prefix when it's not the next block

    // Generate one more block to skip block2
    let block3 = builder.generate_block(rng);

    // Try to check block3 without having block2 in prefix
    // This will fail with InvalidHeight
    let result = ledger.check_block_subdag(block3.clone(), &[]);
    assert!(matches!(result, Err(CheckBlockError::InvalidHeight { expected: 2, actual: 3 })));

    // Check that the check succeeds when block2 is in the prefix
    let block2 = ledger.check_block_subdag(block2, &[]).unwrap();

    // The check should still fail without the prefix.
    let result = ledger.check_block_subdag(block3.clone(), &[]);
    assert!(matches!(result, Err(CheckBlockError::InvalidHeight { expected: 2, actual: 3 })));

    // But succeed with the prefix.
    let block3 = ledger.check_block_subdag(block3, std::slice::from_ref(&block2)).unwrap();

    // Create a forth block
    let block4 = builder.generate_block(rng);

    // Test a prefix that contains block2 twice.
    let result = ledger.check_block_subdag(block4.clone(), &[block2.clone(), block2.clone(), block3.clone()]);
    assert!(matches!(result, Err(CheckBlockError::InvalidPrefix { index: 1, .. })));
    let CheckBlockError::InvalidPrefix { error, .. } = result.unwrap_err() else { unreachable!() };
    assert!(matches!(*error, CheckBlockError::InvalidHeight { expected: 3, actual: 2 }));

    // Test a prefix that misses block 2.
    let result = ledger.check_block_subdag(block4.clone(), &[block3]);
    assert!(matches!(result, Err(CheckBlockError::InvalidPrefix { index: 0, .. })));
    let CheckBlockError::InvalidPrefix { error, .. } = result.unwrap_err() else { unreachable!() };
    assert!(matches!(*error, CheckBlockError::InvalidHeight { expected: 2, actual: 3 }));
}

/// Regression test for the bug where `check_block_subdag_atomicity` used the raw ledger
/// tip round as `latest_round` instead of the last prefix block's round when a non-empty
/// prefix was provided.
#[test]
fn test_atomicity_check_uses_prefix_latest_block() {
    let rng = &mut TestRng::default();
    let mut builder = TestChainBuilder::new(4, rng);

    // External ledger starts at genesis and is never explicitly advanced in this test.
    let ledger = Ledger::<CurrentNetwork, LedgerType<CurrentNetwork>>::load(
        builder.genesis_block().clone(),
        StorageMode::new_test(None),
    )
    .unwrap();

    // Identify the elected leader at round 2 and exclude them from block 1.
    // This guarantees their certificate at round 2 is absent from block 1's subdag,
    // making it a late-arriving *leader* certificate that will appear in block 2's subdag.
    let skip_idx = builder.get_leader_index(2).expect("Leader not found for round 2");
    let block1 =
        builder.generate_block_with_opts(&BlockOptions { skip_nodes: vec![skip_idx], ..Default::default() }, rng);

    // Pre-process block 1 against the external ledger (still at genesis) so it can
    // be used as a prefix when validating block 2.
    let pending_block1 = ledger.check_block_subdag(block1, &[]).unwrap();

    // Generate block 2 with all validators participating.  The previously skipped
    // validator's certificates for rounds ≤ block1.anchor_round are now included in
    // block 2's subdag as late-arriving entries.
    let block2 = builder.generate_block(rng);

    // Block 2 must be accepted with block 1 as the prefix while the external ledger
    // is still at genesis.  This would fail before the fix because the atomicity check
    // incorrectly used genesis's round (0) instead of block 1's anchor round, causing it
    // to flag the late-arriving leader cert at round 2 as a protocol violation.
    ledger.check_block_subdag(block2, &[pending_block1]).unwrap();
}

#[test]
fn test_check_block_content_invalid_height() {
    let rng = &mut TestRng::default();
    let mut builder = TestChainBuilder::new(4, rng);

    // Construct the ledger.
    let ledger = Ledger::<CurrentNetwork, LedgerType<CurrentNetwork>>::load(
        builder.genesis_block().clone(),
        StorageMode::new_test(None),
    )
    .unwrap();

    // Generate two blocks
    let blocks = builder.generate_blocks_with_opts(2, &BlockOptions { skip_votes: true, ..Default::default() }, rng);
    let block1 = blocks[0].clone();

    // Check block1 and get pending block
    let pending1 = ledger.check_block_subdag(block1.clone(), &[]).unwrap();

    // Advance ledger with block1
    let verified1 = ledger.check_block_content(pending1.clone(), rng).unwrap();
    ledger.advance_to_next_block(&verified1).unwrap();

    // Now try to check_block_content on pending1 again
    // This should fail because the ledger has already advanced
    let result = ledger.check_block_content(pending1, rng);

    assert!(matches!(result, Err(CheckBlockError::InvalidHeight { expected: 2, actual: 1 })));
}
