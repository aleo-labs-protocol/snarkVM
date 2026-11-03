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

use console::{
    network::Network,
    prelude::ToBitsRaw,
    program::{Literal, Plaintext},
    types::{Scalar, U64},
};

// A minimal program that uses `commit.bhp256.raw`. Used for version-gate testing.
const COMMIT_BHP256_RAW_PROGRAM: &str = r"
program commit_bhp256_raw_test.aleo;

function run:
    input r0 as field.public;
    input r1 as scalar.public;
    commit.bhp256.raw r0 r1 into r2 as field;
    output r2 as field.public;

constructor:
    assert.eq true true;
";

// A program for testing the additive homomorphism property of `commit.ped128.raw`:
//   commit(a, r1) + commit(b, r2) == expected
//
// Both the function body and the finalize block verify this assertion independently.
// Inputs are u64 values (64 bits) which fit within PED128's 128-bit generator window;
// note that field inputs (254 bits) would exceed that limit.
const PED128_RAW_HOMOMORPHISM_PROGRAM: &str = r"
program test_ped128_raw_homomorphism.aleo;

function check_homomorphism:
    input r0 as u64.public;
    input r1 as u64.public;
    input r2 as scalar.public;
    input r3 as scalar.public;
    input r4 as group.public;
    commit.ped128.raw r0 r2 into r5 as group;
    commit.ped128.raw r1 r3 into r6 as group;
    add r5 r6 into r7;
    assert.eq r7 r4;
    async check_homomorphism r0 r1 r2 r3 r4 into r8;
    output r8 as test_ped128_raw_homomorphism.aleo/check_homomorphism.future;

finalize check_homomorphism:
    input r0 as u64.public;
    input r1 as u64.public;
    input r2 as scalar.public;
    input r3 as scalar.public;
    input r4 as group.public;
    commit.ped128.raw r0 r2 into r5 as group;
    commit.ped128.raw r1 r3 into r6 as group;
    add r5 r6 into r7;
    assert.eq r7 r4;

constructor:
    assert.eq true true;
";

// Tests that deploying a program with `commit.*.raw` instructions is aborted before
// `ConsensusVersion::V15` and accepted at `V15`.
#[test]
fn test_deploy_commit_raw_before_and_at_v15() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Start one block before V15 so that after adding the (rejected) block we are
    // exactly at V15 and can deploy the same program successfully.
    let v15_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15).unwrap();
    let vm = sample_vm_at_height(v15_height - 1, rng);

    let program = Program::from_str(COMMIT_BHP256_RAW_PROGRAM).unwrap();

    // Deployment before V15 should be rejected by verification.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    assert!(vm.check_transaction(&deployment, None, rng).is_err(), "Deployment before V15 should be rejected");

    // Advance to V15 by adding an empty block.
    let block = sample_next_block(&vm, &caller_private_key, &[], rng).unwrap();
    vm.add_next_block(&block).unwrap();

    // We should now be at V15.
    assert_eq!(vm.block_store().current_block_height(), v15_height);

    // Deployment at V15 should succeed.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Deployment at V15 should be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// Tests the additive homomorphism property of `commit.ped128.raw`:
//   commit(a, r1) + commit(b, r2) == commit(a + b, r1 + r2)
//
// The expected group value is computed natively and passed into the program. Both
// the function body and the finalize block independently verify the assertion.
#[test]
fn test_ped128_raw_additive_homomorphism() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM at V15 so that `commit.ped128.raw` programs can be deployed.
    let v15_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15).unwrap();
    let vm = sample_vm_at_height(v15_height, rng);

    // Deploy the homomorphism test program.
    let program = Program::from_str(PED128_RAW_HOMOMORPHISM_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Program deployment should succeed at V15");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Generate random inputs for the homomorphism test. We use u64 values which fit within PED128's 128-bit generator window;
    let a = U64::new(u32::rand(rng) as u64);
    let b = U64::new(u32::rand(rng) as u64);
    let r1: Scalar<CurrentNetwork> = Scalar::rand(rng);
    let r2: Scalar<CurrentNetwork> = Scalar::rand(rng);

    // Compute commit(a, r1) and commit(b, r2) natively using the raw bit representation.
    let a_bits = Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::U64(a))).to_bits_raw_le();
    let b_bits = Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::U64(b))).to_bits_raw_le();
    let c1 = CurrentNetwork::commit_to_group_ped128(&a_bits, &r1).unwrap();
    let c2 = CurrentNetwork::commit_to_group_ped128(&b_bits, &r2).unwrap();
    let expected = c1 + c2;

    // Verify the homomorphism holds natively before testing it in-program:
    //   commit(a, r1) + commit(b, r2) == commit(a + b, r1 + r2)
    let ab_bits = (a + b).to_bits_le();
    let r_sum = r1 + r2;
    let c_direct = CurrentNetwork::commit_to_group_ped128(&ab_bits, &r_sum).unwrap();
    assert_eq!(expected, c_direct, "Additive homomorphism property should hold natively");

    // Execute the program, which asserts the same property in both function and finalize.
    let execution = vm
        .execute(
            &caller_private_key,
            ("test_ped128_raw_homomorphism.aleo", "check_homomorphism"),
            [
                Value::Plaintext(Plaintext::from(Literal::U64(a))),
                Value::Plaintext(Plaintext::from(Literal::U64(b))),
                Value::Plaintext(Plaintext::from(Literal::Scalar(r1))),
                Value::Plaintext(Plaintext::from(Literal::Scalar(r2))),
                Value::Plaintext(Plaintext::from(Literal::Group(expected))),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(
        block.transactions().num_accepted(),
        1,
        "Homomorphism assertion should pass in both function and finalize"
    );
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}
