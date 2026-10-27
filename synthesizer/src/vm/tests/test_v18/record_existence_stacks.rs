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

// Tests that ensure_records_exist receives the necessary stacks both when executing/proving a
// transaction and when verifying one. The only stack ensure_records_exist tries to access other
// than the stacks of the programs corresponding to each of the transitions in the execution are
// the stacks of external closures called by any of the transitions.
#[test]
fn test_external_closure_stack_fetching() -> Result<()> {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let lib_program = Program::from_str(
        r"
        program ext_closure_lib.aleo;

        closure add_values:
            input r0 as u64;
            input r1 as u64;
            add r0 r1 into r2;
            output r2 as u64;

        function noop:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    let caller_program = Program::from_str(
        r"
        import ext_closure_lib.aleo;

        program ext_closure_caller.aleo;

        function call_external_closure:
            input r0 as u64.private;
            input r1 as u64.private;
            call ext_closure_lib.aleo/add_values r0 r1 into r2;
            output r2 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Initialize the VM at V18.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18)?, rng);

    // Deploy the library program.
    let transaction = vm.deploy(&caller_private_key, &lib_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);

    // Deploy the caller program.
    let transaction = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);

    // Execute the caller's function, which calls the external closure. This must succeed.
    let inputs = [Value::from_str("7u64")?, Value::from_str("35u64")?];
    let transaction = vm.execute(
        &caller_private_key,
        ("ext_closure_caller.aleo", "call_external_closure"),
        inputs.iter(),
        None,
        0,
        None,
        rng,
    )?;

    // Verify the public output matches the expected sum (7 + 35 = 42).
    let expected = Plaintext::from_str("42u64")?;
    match &transaction.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected),
        other => panic!("Expected public output, got: {other:?}"),
    }

    // The transaction must verify (and be accepted in a block).
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    Ok(())
}
