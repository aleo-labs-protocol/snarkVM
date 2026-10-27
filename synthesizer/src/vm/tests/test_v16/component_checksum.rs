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

use console::program::{Identifier, Plaintext, ProgramID, Value};

// The constructor pins the checksum of `foo`: on the first deploy it records `foo/checksum` in a
// mapping, and on every subsequent upgrade it asserts that the (immutable) recorded checksum still
// matches the current `foo`. Because the constructor cannot change after the first deploy, this
// freezes `foo` for the lifetime of the program even as other functions are added or changed.
const PINNED_CONSTRUCTOR: &str = r"
constructor:
    branch.neq edition 0u16 to rest;
    set foo/checksum into pinned[true];
    branch.eq true true to end;
    position rest;
    get pinned[true] into r0;
    assert.eq r0 foo/checksum;
    position end;";

// The body of `foo` shared by `program_v0` and `program_v1`: a simple passthrough.
const FOO_UNCHANGED: &str = r"    input r0 as u64.public;
    output r0 as u64.public;";

// A different body for `foo` (its input and output types are preserved so the upgrade still passes the
// structural checks), so its checksum no longer matches the pinned value.
const FOO_CHANGED: &str = r"    input r0 as u64.public;
    add r0 r0 into r1;
    output r1 as u64.public;";

// The body of `bar`: a simple passthrough.
const BAR_UNCHANGED: &str = r"    input r0 as u64.public;
    output r0 as u64.public;";

// A different body for `bar` (its input and output types are preserved), so its checksum changes.
const BAR_CHANGED: &str = r"    input r0 as u64.public;
    add r0 r0 into r1;
    output r1 as u64.public;";

// Builds `test_checksum.aleo` with the given `foo` body, optionally adding a second function `bar` with
// the given body.
fn program(foo: &str, bar: Option<&str>) -> Program<CurrentNetwork> {
    let bar = match bar {
        Some(bar) => format!("\nfunction bar:\n{bar}\n"),
        None => String::new(),
    };
    Program::from_str(&format!(
        r"
program test_checksum.aleo;

mapping pinned:
    key as boolean.public;
    value as [u8; 32u32].public;

function foo:
{foo}
{bar}{PINNED_CONSTRUCTOR}"
    ))
    .unwrap()
}

// Returns the checksum of `foo` within the given program.
fn foo_checksum(program: &Program<CurrentNetwork>) -> [console::types::U8<CurrentNetwork>; 32] {
    program.get_function(&Identifier::from_str("foo").unwrap()).unwrap().to_checksum()
}

// Returns the checksum of `bar` within the given program.
fn bar_checksum(program: &Program<CurrentNetwork>) -> [console::types::U8<CurrentNetwork>; 32] {
    program.get_function(&Identifier::from_str("bar").unwrap()).unwrap().to_checksum()
}

// A simple positive check of the checksum's semantics, without a VM: it is deterministic, ignores
// other functions in the program, and changes when the function's body changes.
#[test]
fn test_checksum_is_deterministic_and_body_sensitive() {
    let v0 = program(FOO_UNCHANGED, None);
    let v1 = program(FOO_UNCHANGED, Some(BAR_UNCHANGED));
    let v2 = program(FOO_CHANGED, Some(BAR_UNCHANGED));

    // The checksum is deterministic.
    assert_eq!(foo_checksum(&v0), foo_checksum(&v0));
    // Adding an unrelated function (`bar`) does not change `foo`'s checksum.
    assert_eq!(foo_checksum(&v0), foo_checksum(&v1));
    // Changing `foo`'s body changes its checksum.
    assert_ne!(foo_checksum(&v0), foo_checksum(&v2));
}

// A program that records the checksum of a function, a closure, and a view, to verify that
// `<name>/checksum` resolves each component kind by name and loads exactly its `to_checksum`.
fn all_kinds_program() -> Program<CurrentNetwork> {
    Program::from_str(
        r"
program test_checksum_kinds.aleo;

mapping checksums:
    key as u8.public;
    value as [u8; 32u32].public;

closure cls:
    input r0 as u64;
    add r0 r0 into r1;
    output r1 as u64;

function foo:
    input r0 as u64.public;
    output r0 as u64.public;

view vw:
    output 0u64 as u64.public;

constructor:
    set foo/checksum into checksums[0u8];
    set cls/checksum into checksums[1u8];
    set vw/checksum into checksums[2u8];
",
    )
    .unwrap()
}

// This test verifies that `<name>/checksum` works for a function, a closure, and a view, and that
// each recorded value equals the corresponding component's `to_checksum`.
#[test]
fn test_checksum_resolves_function_closure_and_view() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V16 height.
    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v16_height, rng);

    // Deploy the program, whose constructor records all three checksums.
    let program = all_kinds_program();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();

    // The expected checksum of each component.
    let expected_fn = program.get_function(&Identifier::from_str("foo").unwrap()).unwrap().to_checksum();
    let expected_cls = program.closures().get(&Identifier::from_str("cls").unwrap()).unwrap().to_checksum();
    let expected_view = program.views().get(&Identifier::from_str("vw").unwrap()).unwrap().to_checksum();

    // Verify each recorded value matches.
    for (key, expected) in [(0u8, expected_fn), (1u8, expected_cls), (2u8, expected_view)] {
        let stored = vm
            .finalize_store()
            .get_value_confirmed(
                ProgramID::from_str("test_checksum_kinds.aleo").unwrap(),
                Identifier::from_str("checksums").unwrap(),
                &Plaintext::from_str(&format!("{key}u8")).unwrap(),
            )
            .unwrap();
        let Some(Value::Plaintext(stored)) = stored else {
            panic!("Expected a plaintext value in 'checksums[{key}u8]'");
        };
        assert_eq!(Plaintext::from(expected), stored, "checksum mismatch for key {key}");
    }
}

// This test verifies that `<name>/checksum` pins a function across upgrades: the program may grow
// (adding `bar`) as long as `foo` is unchanged, but an upgrade that changes `foo` is rejected.
#[test]
fn test_checksum_pin_across_upgrade() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V16 height.
    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v16_height, rng);

    // Deploy v0, which records `foo`'s checksum on first deploy.
    let v0 = program(FOO_UNCHANGED, None);
    let deployment = vm.deploy(&caller_private_key, &v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify the pinned checksum matches `foo`'s actual checksum.
    let expected = Plaintext::from(foo_checksum(&v0));
    let stored = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("test_checksum.aleo").unwrap(),
            Identifier::from_str("pinned").unwrap(),
            &Plaintext::from_str("true").unwrap(),
        )
        .unwrap();
    let Some(Value::Plaintext(stored)) = stored else {
        panic!("Expected a plaintext value in 'pinned'");
    };
    assert_eq!(expected, stored);

    // `bar` does not exist in v0, so its checksum is absent from the program's Stack.
    let bar = Identifier::from_str("bar").unwrap();
    assert!(vm.process().get_stack("test_checksum.aleo").unwrap().component_checksum(&bar).is_err());

    // Upgrade with `foo` unchanged (adding `bar`). The pinned checksum still matches, so it is accepted.
    let v1 = program(FOO_UNCHANGED, Some(BAR_UNCHANGED));
    let deployment = vm.deploy(&caller_private_key, &v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();

    // After the upgrade, `bar`'s checksum is present in the program's Stack and matches `bar`'s checksum.
    let stack = vm.process().get_stack("test_checksum.aleo").unwrap();
    assert_eq!(stack.component_checksum(&bar).unwrap(), &bar_checksum(&v1));

    // Upgrade with `foo` changed. The pinned checksum no longer matches, so the constructor's
    // assertion fails and the upgrade is rejected.
    let v2 = program(FOO_CHANGED, Some(BAR_UNCHANGED));
    let deployment = vm.deploy(&caller_private_key, &v2, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    vm.add_next_block(&block).unwrap();
}

// This test verifies that when `bar` is changed across an upgrade, its checksum is updated in the
// program's Stack. `foo` is left unchanged so the constructor's pin still holds and the upgrade is accepted.
#[test]
fn test_checksum_bar_updated_in_stack_on_upgrade() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V16 height.
    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v16_height, rng);

    // Deploy v0 with `bar`.
    let v0 = program(FOO_UNCHANGED, Some(BAR_UNCHANGED));
    let deployment = vm.deploy(&caller_private_key, &v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();

    // The Stack records `bar`'s original checksum.
    let bar = Identifier::from_str("bar").unwrap();
    let stack = vm.process().get_stack("test_checksum.aleo").unwrap();
    assert_eq!(stack.component_checksum(&bar).unwrap(), &bar_checksum(&v0));

    // Upgrade with `bar` changed (and `foo` unchanged, so the pin still holds).
    let v1 = program(FOO_UNCHANGED, Some(BAR_CHANGED));
    let deployment = vm.deploy(&caller_private_key, &v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();

    // The Stack now records `bar`'s new checksum, which differs from the original.
    let stack = vm.process().get_stack("test_checksum.aleo").unwrap();
    assert_eq!(stack.component_checksum(&bar).unwrap(), &bar_checksum(&v1));
    assert_ne!(bar_checksum(&v0), bar_checksum(&v1));
}

// A minimal program that uses `<name>/checksum` in its constructor.
fn simple_checksum_program() -> Program<CurrentNetwork> {
    Program::from_str(
        r"
program test_checksum_gate.aleo;

mapping checksums:
    key as u8.public;
    value as [u8; 32u32].public;

function foo:
    input r0 as u64.public;
    output r0 as u64.public;

constructor:
    set foo/checksum into checksums[0u8];
",
    )
    .unwrap()
}

// This test verifies that a program using `<name>/checksum` cannot be deployed before V16.
#[test]
fn test_checksum_rejected_pre_v16() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    let program = simple_checksum_program();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V15 height (pre-V16).
    let v15_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v15_height, rng);

    // The deployment is rejected by verification because the component checksum is not allowed before V16.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    assert!(vm.check_transaction(&deployment, None, rng).is_err());
}

// A program that references `<name>/checksum` from inside a view's output operand. Views are a V15
// feature, so the pre-V16 gate must look inside them too, otherwise this would bypass it.
fn view_checksum_program() -> Program<CurrentNetwork> {
    Program::from_str(
        r"
program test_checksum_view.aleo;

function foo:
    input r0 as u64.public;
    output r0 as u64.public;

view foo_checksum:
    output foo/checksum as [u8; 32u32].public;

constructor:
    assert.eq true true;
",
    )
    .unwrap()
}

// This test verifies that a component checksum hidden in a view is still rejected before V16, i.e. the
// pre-V16 gate scans view commands and outputs (regression test for the view-scan gap).
#[test]
fn test_checksum_in_view_rejected_pre_v16() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    let program = view_checksum_program();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V15 height (pre-V16, but views are allowed).
    let v15_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v15_height, rng);

    // The deployment is rejected by verification, since the view carries a V16-only operand.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    assert!(vm.check_transaction(&deployment, None, rng).is_err());
}

// This test verifies that the same view-based program is accepted at V16.
#[test]
fn test_checksum_in_view_accepted_at_v16() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    let program = view_checksum_program();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V16 height.
    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v16_height, rng);

    // The deployment is accepted.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();
}

// A program whose constructor references a `<name>/checksum` for a name that is not a component.
fn dangling_checksum_program() -> Program<CurrentNetwork> {
    Program::from_str(
        r"
program test_checksum_dangling.aleo;

mapping checksums:
    key as u8.public;
    value as [u8; 32u32].public;

function foo:
    input r0 as u64.public;
    output r0 as u64.public;

constructor:
    set nonexistent/checksum into checksums[0u8];
",
    )
    .unwrap()
}

// This test verifies that a component checksum referencing a name that is not a function, closure, or
// view is rejected at deployment, rather than deploying successfully and failing on every execution.
#[test]
fn test_checksum_dangling_reference_rejected() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    let program = dangling_checksum_program();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V16 height.
    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v16_height, rng);

    // The dangling reference is caught during deployment (at synthesis) or, failing that, by verification.
    if let Ok(deployment) = vm.deploy(&caller_private_key, &program, None, 0, None, rng) {
        assert!(vm.check_transaction(&deployment, None, rng).is_err());
    }
}

// A program whose view output references a `<name>/checksum` for a name that is not a component.
fn dangling_view_checksum_program() -> Program<CurrentNetwork> {
    Program::from_str(
        r"
program test_checksum_dangling_view.aleo;

function foo:
    input r0 as u64.public;
    output r0 as u64.public;

view bad:
    output nonexistent/checksum as [u8; 32u32].public;

constructor:
    assert.eq true true;
",
    )
    .unwrap()
}

// This test verifies that a dangling component checksum in a view output operand is also rejected at
// deployment, not just one in a command operand.
#[test]
fn test_checksum_dangling_reference_in_view_output_rejected() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    let program = dangling_view_checksum_program();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V16 height.
    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v16_height, rng);

    // The dangling reference is caught during deployment (at synthesis) or, failing that, by verification.
    if let Ok(deployment) = vm.deploy(&caller_private_key, &program, None, 0, None, rng) {
        assert!(vm.check_transaction(&deployment, None, rng).is_err());
    }
}
