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

/// A program whose `constant_output` function returns its input as a `.constant` output, and whose `private_output`
/// function returns its input as a `.private` output.
const CALLEE: &str = r"
program constant_callee.aleo;

function constant_output:
    input r0 as boolean.private;
    output r0 as boolean.constant;

function private_output:
    input r0 as boolean.private;
    output r0 as boolean.private;

constructor:
    assert.eq true true;
";

/// The error that deployment verification returns for a static call to `constant_callee.aleo/constant_output`.
const REJECTION: &str = "calls 'constant_callee.aleo/constant_output', which has a constant output";

/// Returns a program named `{name}.aleo` that imports `constant_callee.aleo`, with `body` as the body of `foo`.
fn caller(name: &str, body: &str) -> Result<Program<CurrentNetwork>> {
    Program::from_str(&format!(
        r"
import constant_callee.aleo;

program {name}.aleo;

function foo:
    input r0 as boolean.private;
{body}
constructor:
    assert.eq true true;
"
    ))
}

/// Returns the body of `foo` that calls `constant_callee.aleo/{callee}` and branches on its output.
fn calling(callee: &str) -> String {
    format!(
        "    call constant_callee.aleo/{callee} r0 into r1;\n    ternary r1 1u8 0u8 into r2;\n    output r2 as u8.private;\n"
    )
}

/// Returns the consensus version that `check_transaction` applies to the next transaction.
fn next_consensus_version(vm: &VM<CurrentNetwork, LedgerType>) -> Result<ConsensusVersion> {
    CurrentNetwork::CONSENSUS_VERSION(vm.block_store().current_block_height())
}

// A program deployed before V23 with a static call to a function with a constant output still executes from V23.
// From V23, an upgrade of that program is rejected while it keeps the call, and accepted once it drops the call. From
// V23, a new program with such a call is rejected, and a new program with a static call to a function without
// constant outputs is accepted.
#[test]
#[ignore = "slow: merge lines"]
fn test_static_call_to_constant_output_across_v23() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key();

    // Start one block before V22, so that the callee is deployed in the V22 block and the caller is checked at V22.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V22)? - 1, rng);

    let tx = vm.deploy(&caller_private_key, &Program::from_str(CALLEE)?, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Before V23, the caller's circuit depends on the value that synthesis samples for the constant output. The
    // validators sample it with a seed derived from the deployment, which is fixed by the program and the owner. So
    // only some programs with such a call can be deployed, and each attempt below uses a new program name.
    assert_eq!(next_consensus_version(&vm)?, ConsensusVersion::V22);
    let mut accepted = None;
    for attempt in 0..32 {
        let name = format!("calls_constant_{attempt}");
        let tx = vm.deploy(&caller_private_key, &caller(&name, &calling("constant_output"))?, None, 0, None, rng)?;
        match vm.check_transaction(&tx, None, rng) {
            Ok(()) => {
                accepted = Some((name, tx));
                break;
            }
            Err(error) => assert!(!error.to_string().contains(REJECTION), "unexpected error: {error}"),
        }
    }
    let (name, tx) = accepted.expect("a deployment of the caller must be accepted before V23");
    let program_id = format!("{name}.aleo");
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // The verifying key of `foo` fixes the value of the constant output, so an execution is accepted only if the
    // callee returns that value. The callee returns its input, so one of `true` and `false` is accepted.
    assert_eq!(next_consensus_version(&vm)?, ConsensusVersion::V23);
    let mut executions = Vec::new();
    for input in ["true", "false"] {
        let inputs = [Value::<CurrentNetwork>::from_str(input)?];
        let result = vm
            .execute(&caller_private_key, (program_id.as_str(), "foo"), inputs.iter(), None, 0, None, rng)
            .map_err(|error| anyhow!("{error}"))
            .and_then(|tx| vm.check_transaction(&tx, None, rng).map(|()| tx));
        match result {
            Ok(tx) => executions.push(tx),
            Err(error) => assert!(!error.to_string().contains(REJECTION), "unexpected error: {error}"),
        }
    }
    assert_eq!(executions.len(), 1, "exactly one value of the constant output must be accepted");
    add_and_test_with_costs(&vm, &caller_private_key, None, &executions, rng);

    let tx = vm.deploy(&caller_private_key, &caller(&name, &calling("constant_output"))?, None, 0, None, rng)?;
    let error = vm.check_transaction(&tx, None, rng).unwrap_err().to_string();
    assert!(error.contains(REJECTION), "unexpected error: {error}");

    let upgrade = caller(&name, "    ternary r0 1u8 0u8 into r1;\n    output r1 as u8.private;\n")?;
    let tx = vm.deploy(&caller_private_key, &upgrade, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);
    assert_eq!(*vm.process().get_stack(program_id.as_str())?.program_edition(), 1);

    let program = caller("calls_constant", &calling("constant_output"))?;
    let tx = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let error = vm.check_transaction(&tx, None, rng).unwrap_err().to_string();
    assert!(error.contains(REJECTION), "unexpected error: {error}");

    let tx =
        vm.deploy(&caller_private_key, &caller("calls_private", &calling("private_output"))?, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);
    let inputs = [Value::<CurrentNetwork>::from_str("true")?];
    let tx = vm.execute(&caller_private_key, ("calls_private.aleo", "foo"), inputs.iter(), None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    Ok(())
}
