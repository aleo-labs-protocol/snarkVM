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

//! Block-level compute spend limits for quorum blocks (`Authority::Quorum`).

use super::*;

/// Quorum blocks pass `block_spend_limit` into [`FinalizeGlobalState`] via
/// `Authority::Quorum(subdag).spend_limit(height)` (see `VM::add_next_block_inner`).
///
/// `Subdag::spend_limit` is `total_certificate_count * BatchHeader::batch_spend_limit(height)`.
/// Using a limit of `compute_spend` for one `credits.aleo/transfer_public` execution models a
/// quorum block whose DAG-derived ceiling equals a single such transaction; a second identical
/// execution must then be aborted during speculation.
#[test]
fn test_quorum_block_spend_limit_aborts_excess_transactions() {
    let rng = &mut TestRng::default();

    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = sample_vm_at_height(v16_height, rng);
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::<CurrentNetwork>::try_from(&caller_private_key).unwrap();

    let block_hash = vm.block_store().get_block_hash(vm.block_store().max_height().unwrap()).unwrap().unwrap();
    let previous_block = vm.block_store().get_block(&block_hash).unwrap().unwrap();
    let next_block_height = previous_block.height().saturating_add(1);

    let transfer_inputs = |amount: &str| {
        [Value::<CurrentNetwork>::from_str(&caller_address.to_string()).unwrap(), Value::from_str(amount).unwrap()]
    };

    let transaction_0 = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            transfer_inputs("1u64").iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let execution_0 = transaction_0.execution().unwrap();
    let consensus_version = CurrentNetwork::CONSENSUS_VERSION(next_block_height).unwrap();
    let (_, cost_details) = execution_cost(vm.process(), execution_0, consensus_version).unwrap();
    let compute_per_transfer = execute_compute_cost_in_microcredits(cost_details, consensus_version);

    let transaction_1 = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            transfer_inputs("1u64").iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    assert_eq!(
        execute_compute_cost_in_microcredits(
            execution_cost(vm.process(), transaction_1.execution().unwrap(), consensus_version).unwrap().1,
            consensus_version,
        ),
        compute_per_transfer,
        "both transfers must have identical synthesis cost for this scenario"
    );

    let next_timestamp = previous_block.timestamp().saturating_add(CurrentNetwork::BLOCK_TIME as i64);
    let next_timestamp = (next_block_height
        >= CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default())
    .then_some(next_timestamp);

    let finalize_state = FinalizeGlobalState::from(
        previous_block.round().saturating_add(1),
        next_block_height,
        next_timestamp,
        [0u8; 32],
        Some(compute_per_transfer),
        None,
    );

    let (ratifications, confirmed_transactions, aborted_transaction_ids, _finalize_operations) = vm
        .speculate(
            finalize_state,
            CurrentNetwork::BLOCK_TIME as i64,
            None,
            Vec::new(),
            &Solutions::from(None),
            [transaction_0.clone(), transaction_1.clone()].iter(),
            rng,
        )
        .unwrap();

    assert_eq!(ratifications.len(), 0);
    assert_eq!(confirmed_transactions.num_accepted(), 1);
    assert_eq!(confirmed_transactions.num_rejected(), 0);

    assert_eq!(aborted_transaction_ids.len(), 1);
    assert_eq!(aborted_transaction_ids[0], transaction_1.id());
}
