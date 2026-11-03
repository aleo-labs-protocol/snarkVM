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

/// Tests that "dynamic" cannot be used as a struct name at V14.
#[test]
fn test_restricted_keyword_dynamic_struct_name() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let program = Program::from_str(
        r"
program dynamic_struct_test.aleo;

struct dynamic:
    amount as u64;

function test:
    input r0 as u64.private;
    cast r0 into r1 as dynamic;
    output r1 as dynamic.private;
",
    )
    .unwrap();

    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}

/// Tests that "dynamic" cannot be used as a function name at V14.
#[test]
fn test_restricted_keyword_dynamic_function_name() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let program = Program::from_str(
        r"
program dynamic_function_test.aleo;

function dynamic:
    input r0 as u64.private;
    output r0 as u64.private;
",
    )
    .unwrap();

    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}

/// Tests that "dynamic" cannot be used as a record name at V14.
/// Note: The record is declared but not used in the function body to avoid
/// parser ambiguity with `dynamic.record` being parsed as `RegisterType::DynamicRecord`.
/// This is not a vulnerability because "dynamic" is restricted as a keyword at V14,
/// preventing any deployed program from using it as a record name.
#[test]
fn test_restricted_keyword_dynamic_record_name() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let program = Program::from_str(
        r"
program dynamic_record_test.aleo;

record dynamic:
    owner as address.private;
    amount as u64.private;

function test:
    input r0 as u64.private;
    output r0 as u64.private;
",
    )
    .unwrap();

    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}

/// Tests that "dynamic" cannot be used as a mapping name at V14.
#[test]
fn test_restricted_keyword_dynamic_mapping_name() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let program = Program::from_str(
        r"
program dynamic_mapping_test.aleo;

mapping dynamic:
    key as address.public;
    value as u64.public;

function test:
    input r0 as address.public;
    async test r0 into r1;
    output r1 as dynamic_mapping_test.aleo/test.future;

finalize test:
    input r0 as address.public;
    set 0u64 into dynamic[r0];
",
    )
    .unwrap();

    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}

/// Tests that "dynamic" cannot be used as a record entry name at V14.
#[test]
fn test_restricted_keyword_dynamic_record_entry_name() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let program = Program::from_str(
        r"
program dynamic_entry_test.aleo;

record token:
    owner as address.private;
    dynamic as u64.private;

function mint:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;
",
    )
    .unwrap();

    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}

/// Tests that "dynamic" cannot be used as a struct member name at V14.
#[test]
fn test_restricted_keyword_dynamic_struct_member_name() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let program = Program::from_str(
        r"
program dynamic_member_test.aleo;

struct data:
    dynamic as u64;

function test:
    input r0 as u64.private;
    cast r0 into r1 as data;
    output r1 as data.private;
",
    )
    .unwrap();

    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}
