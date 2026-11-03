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

use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_ledger_block::{Input, Output, Transition};

// Re-encodes the transition's record/external-record input at `index` as its `*WithDynamicID`
// variant, using an arbitrary dynamic ID. The dynamic ID is never validated before the checks
// under test fire, so any field element suffices to build the forgery.
fn forge_input(
    transition: &Transition<CurrentNetwork>,
    index: usize,
    dynamic_id: Field<CurrentNetwork>,
) -> Transition<CurrentNetwork> {
    let mut inputs = transition.inputs().to_vec();
    let forged = match &inputs[index] {
        Input::Record(serial_number, tag) => Input::RecordWithDynamicID(*serial_number, *tag, dynamic_id),
        Input::ExternalRecord(id) => Input::ExternalRecordWithDynamicID(*id, dynamic_id),
        other => panic!("cannot forge a dynamic-ID input from {other}"),
    };
    inputs[index] = forged;
    rebuild(transition, inputs, transition.outputs().to_vec())
}

// Re-encodes the transition's record/external-record output at `index` as its `*WithDynamicID`
// variant, using an arbitrary dynamic ID.
fn forge_output(
    transition: &Transition<CurrentNetwork>,
    index: usize,
    dynamic_id: Field<CurrentNetwork>,
) -> Transition<CurrentNetwork> {
    let mut outputs = transition.outputs().to_vec();
    let forged = match &outputs[index] {
        Output::Record(commitment, checksum, record, sender) => {
            Output::RecordWithDynamicID(*commitment, *checksum, record.clone(), *sender, dynamic_id)
        }
        Output::ExternalRecord(id) => Output::ExternalRecordWithDynamicID(*id, dynamic_id),
        other => panic!("cannot forge a dynamic-ID output from {other}"),
    };
    outputs[index] = forged;
    rebuild(transition, transition.inputs().to_vec(), outputs)
}

// Reconstructs a transition with the given (possibly forged) inputs and outputs.
fn rebuild(
    transition: &Transition<CurrentNetwork>,
    inputs: Vec<Input<CurrentNetwork>>,
    outputs: Vec<Output<CurrentNetwork>>,
) -> Transition<CurrentNetwork> {
    Transition::new(
        *transition.program_id(),
        *transition.function_name(),
        inputs,
        outputs,
        *transition.tpk(),
        *transition.tcm(),
        *transition.scm(),
    )
    .unwrap()
}

// Returns the index of the (single) transition executing `function_name`.
fn transition_index(transitions: &[Transition<CurrentNetwork>], function_name: &str) -> usize {
    transitions
        .iter()
        .position(|transition| transition.function_name().to_string() == function_name)
        .unwrap_or_else(|| panic!("no transition for function '{function_name}'"))
}

// Builds an honest execution for `program_id/function_name`, applies `forge` to its transitions,
// wraps the result in a fully-formed transaction (valid proof against the VM state root and a valid
// public fee), and returns the outcome of `vm.check_transaction`.
//
// Returns `Ok(())` if the transaction was rejected with an error containing every string in
// `expected`; otherwise returns `Err` describing why the forgery was *not* rejected as expected.
#[allow(clippy::too_many_arguments)]
fn forge_and_check(
    vm: &VM<CurrentNetwork, LedgerType>,
    process: &Process<CurrentNetwork>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    program_id: &ProgramID<CurrentNetwork>,
    function_name: &str,
    inputs: &[Value<CurrentNetwork>],
    expected: &[&str],
    forge: impl FnOnce(&mut Vec<Transition<CurrentNetwork>>),
    rng: &mut TestRng,
) -> Result<(), String> {
    let function_name = Identifier::<CurrentNetwork>::from_str(function_name).unwrap();
    let locator = format!("{program_id}/{function_name}");

    // Build the honest execution with the standalone process (the fabricated/minted records need
    // not exist on the ledger, and `process::execute` does not run the record-existence check).
    let authorization =
        process.authorize::<CurrentAleo, _>(caller_private_key, program_id, function_name, inputs.iter(), rng).unwrap();
    let (_response, trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

    // Forge the honest transitions.
    let mut transitions = trace.transitions().to_vec();
    forge(&mut transitions);

    // Prove against the VM's current state root so the execution proof is otherwise well-formed.
    let global_state_root = vm.block_store().current_state_root();
    let proving_tasks = trace.transition_tasks().values().cloned().collect::<Vec<_>>();
    let (_root, proof) = Trace::<CurrentNetwork>::prove_batch::<CurrentAleo, _>(
        &locator,
        VarunaVersion::V2,
        proving_tasks,
        &[],
        &[],
        global_state_root,
        rng,
    )
    .unwrap();

    // Assemble the forged transaction with a valid public fee.
    let execution = Execution::from(transitions.into_iter(), global_state_root, Some(proof)).unwrap();
    let execution_id = execution.to_execution_id().unwrap();
    let (base_fee, _) = execution_cost(vm.process(), &execution, ConsensusVersion::V20).unwrap();
    let fee_authorization = vm.authorize_fee_public(caller_private_key, base_fee, 0, execution_id, rng).unwrap();
    let fee = vm.execute_fee_authorization(fee_authorization, None, rng).unwrap();
    let transaction = Transaction::from_execution(execution, Some(fee)).unwrap();

    // Check the forged transaction and confirm it is rejected for the expected reason.
    match vm.check_transaction(&transaction, None, rng) {
        Ok(()) => Err("transaction was accepted".to_string()),
        Err(error) => {
            let error = error.to_string();
            let missing: Vec<&str> = expected.iter().copied().filter(|substring| !error.contains(substring)).collect();
            match missing.is_empty() {
                true => Ok(()),
                false => Err(format!("rejected, but the error is missing {missing:?}: {error}")),
            }
        }
    }
}

// Checks that the `*WithDynamicID` input/output variants are rejected when they should not appear
// due to the call's static/dynamic nature.
#[test]
fn test_dynamic_id_variant_checks() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let address = Address::try_from(&caller_private_key).unwrap();

    // issuer.aleo mints and consumes its own `ticket` record.
    let issuer = Program::<CurrentNetwork>::from_str(
        r"
        program issuer.aleo;

        record ticket:
            owner as address.private;
            amount as u64.public;

        function mint:
            input r0 as address.private;
            input r1 as u64.public;
            cast r0 r1 into r2 as ticket.record;
            output r2 as ticket.record;

        function consume:
            input r0 as ticket.record;
            assert.eq r0.owner r0.owner;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // checker.aleo works with issuer's `ticket` as an external record.
    let checker = Program::<CurrentNetwork>::from_str(
        r"
        import issuer.aleo;

        program checker.aleo;

        function check_ticket:
            input r0 as issuer.aleo/ticket.record;
            input r1 as address.private;
            lt r0.amount 1000u64 into r2;
            assert.eq r2 true;

        function produce_external:
            input r0 as address.private;
            input r1 as u64.public;
            call issuer.aleo/mint r0 r1 into r2;
            output r2 as issuer.aleo/ticket.record;

        function forward:
            input r0 as issuer.aleo/ticket.record;
            assert.eq true true;
            output r0 as issuer.aleo/ticket.record;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // top.aleo mints a ticket and then statically calls into checker.aleo. Minting the ticket here
    // (rather than taking it as an external-record input) keeps the honest execution valid under
    // the record-existence check, isolating the variant check for the non-root scenarios.
    let top = Program::<CurrentNetwork>::from_str(
        r"
        import issuer.aleo;
        import checker.aleo;

        program top.aleo;

        function mint_and_check:
            input r0 as address.private;
            input r1 as u64.public;
            call issuer.aleo/mint r0 r1 into r2;
            call checker.aleo/check_ticket r2 r0;

        function mint_and_forward:
            input r0 as address.private;
            input r1 as u64.public;
            call issuer.aleo/mint r0 r1 into r2;
            call checker.aleo/forward r2 into r3;
            output r3 as issuer.aleo/ticket.record;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Initialize the VM at V20 and deploy the three programs.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V20).unwrap(), rng);
    for program in [&issuer, &checker, &top] {
        let deployment = vm.deploy(&caller_private_key, program, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);
    }

    // A standalone process mirroring the deployed programs, used to build the honest executions.
    let process = crate::Process::<CurrentNetwork>::load().unwrap();
    for program in [&issuer, &checker, &top] {
        process.lock().add_program(program).unwrap();
    }

    // A fabricated ticket record (owned by the caller) for the root-call record-input scenarios.
    let amount = 42u64;
    let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
        "{{ owner: {address}.private, amount: {amount}u64.public, _nonce: 0group.public, _version: 1u8.public }}"
    ))
    .unwrap();
    let record_value = Value::<CurrentNetwork>::Record(record);
    let address_value = Value::<CurrentNetwork>::from_str(&address.to_string()).unwrap();
    let amount_value = Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap();

    // An arbitrary dynamic ID for the forged variants (never validated before the checks fire).
    let dynamic_id = Field::<CurrentNetwork>::from_str("12345field").unwrap();

    let mut failures = Vec::new();
    let mut check = |scenario: &str, result: Result<(), String>| {
        if let Err(reason) = result {
            failures.push(format!("{scenario}: {reason}"));
        }
    };

    // --- Root-call scenarios (must be rejected by the strict variant check). ---

    // Input::ExternalRecordWithDynamicID to the root call.
    check(
        "root external-record input",
        forge_and_check(
            &vm,
            &process,
            &caller_private_key,
            checker.id(),
            "check_ticket",
            &[record_value.clone(), address_value.clone()],
            &["Incorrect input variant", "external_record_with_dynamic_id", "issuer.aleo/ticket.record"],
            |transitions| {
                let index = transitions.len() - 1;
                transitions[index] = forge_input(&transitions[index], 0, dynamic_id);
            },
            rng,
        ),
    );

    // Input::RecordWithDynamicID to the root call.
    check(
        "root record input",
        forge_and_check(
            &vm,
            &process,
            &caller_private_key,
            issuer.id(),
            "consume",
            std::slice::from_ref(&record_value),
            &["Incorrect input variant", "record_with_dynamic_id", "ticket.record"],
            |transitions| {
                let index = transitions.len() - 1;
                transitions[index] = forge_input(&transitions[index], 0, dynamic_id);
            },
            rng,
        ),
    );

    // Output::ExternalRecordWithDynamicID from the root call.
    check(
        "root external-record output",
        forge_and_check(
            &vm,
            &process,
            &caller_private_key,
            checker.id(),
            "produce_external",
            &[address_value.clone(), amount_value.clone()],
            &["Incorrect output variant", "external_record_with_dynamic_id", "issuer.aleo/ticket.record"],
            |transitions| {
                let index = transitions.len() - 1;
                transitions[index] = forge_output(&transitions[index], 0, dynamic_id);
            },
            rng,
        ),
    );

    // Output::RecordWithDynamicID from the root call.
    check(
        "root record output",
        forge_and_check(
            &vm,
            &process,
            &caller_private_key,
            issuer.id(),
            "mint",
            &[address_value.clone(), amount_value.clone()],
            &["Incorrect output variant", "record_with_dynamic_id", "ticket.record"],
            |transitions| {
                let index = transitions.len() - 1;
                transitions[index] = forge_output(&transitions[index], 0, dynamic_id);
            },
            rng,
        ),
    );

    // --- Non-root static-call scenarios (rejected by the per-child static-call variant check). ---

    // Input::ExternalRecordWithDynamicID smuggled into a statically-called (non-root) transition.
    // No translation should occur here (the call is static), so a plain Input::ExternalRecord is
    // what a valid execution carries.
    check(
        "non-root external-record input",
        forge_and_check(
            &vm,
            &process,
            &caller_private_key,
            top.id(),
            "mint_and_check",
            &[address_value.clone(), amount_value.clone()],
            &["Incorrect input variant"],
            |transitions| {
                let index = transition_index(transitions, "check_ticket");
                transitions[index] = forge_input(&transitions[index], 0, dynamic_id);
            },
            rng,
        ),
    );

    // Output::ExternalRecordWithDynamicID smuggled out of a statically-called (non-root) transition.
    // No translation should occur here (the call is static), so a plain Output::ExternalRecord is
    // what a valid execution carries.
    check(
        "non-root external-record output",
        forge_and_check(
            &vm,
            &process,
            &caller_private_key,
            top.id(),
            "mint_and_forward",
            &[address_value.clone(), amount_value.clone()],
            &["Incorrect output variant"],
            |transitions| {
                let index = transition_index(transitions, "forward");
                transitions[index] = forge_output(&transitions[index], 0, dynamic_id);
            },
            rng,
        ),
    );

    assert!(failures.is_empty(), "the following forgeries were not rejected as expected:\n  {}", failures.join("\n  "));
}
