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

#[macro_use]
extern crate criterion;

use snarkvm_synthesizer_process::{Assignments, CallStack, Process, Stack};
use snarkvm_synthesizer_program::{Program, StackTrait};

use criterion::Criterion;
use snarkvm_circuit::AleoV0;
use snarkvm_console::{
    account::{Address, PrivateKey},
    network::{MainnetV0, prelude::*},
    program::{Identifier, ProgramID, Request, Value},
};
use snarkvm_utilities::TestRng;
use std::{str::FromStr, time::Duration};

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

fn prepare_check_deployment<N: Network, A: snarkvm_circuit::Aleo<Network = N>>(
    c: &mut Criterion,
    stack: &Stack<N>,
    private_key: &PrivateKey<N>,
    function_name: Identifier<N>,
    inputs: &[Value<N>],
    rng: &mut TestRng,
) {
    // Retrieve the program.
    let program = stack.program();
    // Get the program ID.
    let program_id = *program.id();
    // Retrieve the input types.
    let input_types = program.get_function(&function_name).unwrap().input_types();
    // Retrieve the 'program_checksum', if the program has a constructor.
    let program_checksum = match program.contains_constructor() {
        true => Some(stack.program_checksum_as_field().unwrap()),
        false => None,
    };
    // Sample 'root_tvk'.
    let root_tvk = None;
    // Set 'is_root' to true. In particular, this guarantees self.caller is set to self.signer.
    let is_root = true;
    // Compute the request.
    let request = Request::sign(
        private_key,
        program_id,
        function_name,
        inputs.iter(),
        &input_types,
        root_tvk,
        is_root,
        program_checksum,
        false,
        rng,
    )
    .unwrap();
    // Initialize the assignments.
    let assignments = Assignments::<N>::default();
    // Initialize the call stack.
    let call_stack = CallStack::CheckDeployment(vec![request], *private_key, assignments.clone(), None, None, None);

    // Benchmark synthesis of the circuit.
    c.bench_function(&format!("CheckDeployment for {function_name}"), |b| {
        b.iter(|| {
            let _response = stack.execute_function::<A, _>(call_stack.clone(), None, None, rng).unwrap();
        })
    });
}

fn transfer_private(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    // Initialize a new caller account.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller = Address::try_from(&private_key).unwrap();

    // Construct a new process.
    let process = Process::load().unwrap();
    // Retrieve the stack.
    let stack = process.get_stack(ProgramID::from_str("credits.aleo").unwrap()).unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("transfer_private").unwrap();

    // Declare the inputs.
    let r0 = Value::from_str(&format!(
        "{{ owner: {caller}.private, microcredits: 1_500_000_000_000_000_u64.private, _nonce: {}.public }}",
        snarkvm_console::types::Group::<CurrentNetwork>::zero()
    ))
    .unwrap();
    let r1 = Value::<CurrentNetwork>::from_str(&format!("{caller}")).unwrap();
    let r2 = Value::<CurrentNetwork>::from_str("1_500_000_000_000_000_u64").unwrap();

    // Compute the assignment.
    prepare_check_deployment::<_, CurrentAleo>(c, &stack, &private_key, function_name, &[r0, r1, r2], rng);
}

fn transfer_public(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    // Initialize a new caller account.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller = Address::try_from(&private_key).unwrap();

    // Construct a new process.
    let process = Process::load().unwrap();
    // Retrieve the stack.
    let stack = process.get_stack(ProgramID::from_str("credits.aleo").unwrap()).unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("transfer_public").unwrap();

    // Declare the inputs.
    let r0 = Value::<CurrentNetwork>::from_str(&format!("{caller}")).unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("1_500_000_000_000_000_u64").unwrap();

    // Compute the assignment.
    prepare_check_deployment::<_, CurrentAleo>(c, &stack, &private_key, function_name, &[r0, r1], rng);
}

fn large_program(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Construct a new process.
    let process = Process::load().unwrap();
    // Create the program.
    let program = Program::from_str(
        r"
program synthesis_overload.aleo;
function do:
    input r0 as [[u128; 32u32]; 2u32].private;
    hash.sha3_256 r0 into r1 as field;
    output r1 as field.public;",
    )
    .unwrap();
    // Create the stack.
    let stack = Stack::new(&process, &program).unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("do").unwrap();

    // Declare the inputs.
    let r0 = Value::<CurrentNetwork>::from_str("[[1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128], [1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128, 1u128]]").unwrap();

    // Compute the assignment.
    prepare_check_deployment::<_, CurrentAleo>(c, &stack, &private_key, function_name, &[r0], rng);
}

criterion_group! {
    name = check_deployment;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(10));
    targets = large_program, transfer_private, transfer_public
}
criterion_main!(check_deployment);
