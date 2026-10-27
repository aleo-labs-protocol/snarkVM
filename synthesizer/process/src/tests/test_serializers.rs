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

use crate::{CallStack, Process, Trace};
use circuit::network::AleoV0;
use console::{
    account::PrivateKey,
    network::{MainnetV0, prelude::*},
    program::{Address, ArrayType, Identifier, LiteralType, Locator, PlaintextType, RegisterType, U32, Value},
};
use snarkvm_synthesizer_program::{Program, StackTrait};

#[cfg(feature = "locktick")]
use locktick::parking_lot::RwLock;
#[cfg(not(feature = "locktick"))]
use parking_lot::RwLock;
use rayon::prelude::*;
use std::sync::Arc;

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

#[test]
fn test_serialize_deserialize_equivalence() {
    // Number of iterations to run for each type.
    const ITERATIONS: usize = 10;

    // A helper function to define the program.
    fn construct_program(
        variant: &str,
        src_type: PlaintextType<CurrentNetwork>,
        bits_type: ArrayType<CurrentNetwork>,
    ) -> Program<CurrentNetwork> {
        Program::<CurrentNetwork>::from_str(&format!(
            r"
program test.aleo;

function test_serde_equivalence:
    input r0 as {src_type}.private;
    serialize.{variant} r0 ({src_type}) into r1 ({bits_type});
    deserialize.{variant} r1 ({bits_type}) into r2 ({src_type});
    assert.eq r0 r2;
    "
        ))
        .unwrap()
    }

    // A helper function defining the types to be tested.
    fn test_types(is_raw: bool) -> Vec<PlaintextType<CurrentNetwork>> {
        let mut types = vec![
            PlaintextType::Literal(LiteralType::Address),
            PlaintextType::Literal(LiteralType::Boolean),
            PlaintextType::Literal(LiteralType::Field),
            PlaintextType::Literal(LiteralType::Group),
            PlaintextType::Literal(LiteralType::I8),
            PlaintextType::Literal(LiteralType::I16),
            PlaintextType::Literal(LiteralType::I32),
            PlaintextType::Literal(LiteralType::I64),
            PlaintextType::Literal(LiteralType::I128),
            PlaintextType::Literal(LiteralType::U8),
            PlaintextType::Literal(LiteralType::U16),
            PlaintextType::Literal(LiteralType::U32),
            PlaintextType::Literal(LiteralType::U64),
            PlaintextType::Literal(LiteralType::U128),
            PlaintextType::Literal(LiteralType::Scalar),
            PlaintextType::Literal(LiteralType::Identifier),
            PlaintextType::Array(ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(8)]).unwrap()),
        ];

        // Add additional types for the raw variant.
        if is_raw {
            types.push(PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(32)]).unwrap(),
            ));
            types.push(PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(64)]).unwrap(),
            ))
        }

        types
    }

    // A helper function to run tests for a given variant (either raw or not).
    fn run_test(type_: PlaintextType<CurrentNetwork>, is_raw: bool, iterations: usize) {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Load the process.
        let process = Process::<CurrentNetwork>::load().unwrap();

        // Structs are not supported.
        let fail_get_struct = |_: &Identifier<CurrentNetwork>| bail!("structs are not supported");
        let fail_get_external_struct = |_: &Locator<CurrentNetwork>| bail!("structs are not supported");

        // Get the bits type.
        let num_bits = match is_raw {
            true => type_.size_in_bits_raw(&fail_get_struct, &fail_get_external_struct).unwrap(),
            false => type_.size_in_bits(&fail_get_struct, &fail_get_external_struct).unwrap(),
        };
        let num_bits = u32::try_from(num_bits).unwrap();
        let bits_type = ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(num_bits)]).unwrap();

        // Sample the program.
        let variant = if is_raw { "bits.raw" } else { "bits" };
        let program = construct_program(variant, type_.clone(), bits_type.clone());

        // Add the program to the process.
        process.lock().add_program(&program).unwrap();

        // Get the stack.
        let stack = process.get_stack(program.id()).unwrap();

        // Sample a private key.
        let private_key = PrivateKey::new(rng).unwrap();

        // Get the function name.
        let function_name = Identifier::from_str("test_serde_equivalence").unwrap();

        // Run the test for a desired number of iterations.
        for _ in 0..iterations {
            // Sample the plaintext.
            let plaintext = stack.sample_plaintext(&type_, rng).unwrap();

            // Get the bits of the plaintext.
            let bits = match is_raw {
                false => plaintext.to_bits_le(),
                true => plaintext.to_bits_raw_le(),
            };

            // Check that the number of bits matches.
            assert_eq!(bits.len(), num_bits as usize, "The number of bits does not match the expected size");

            // Construct the inputs.
            let inputs = [Value::Plaintext(plaintext.clone())];

            // Generate an authorization.
            let authorization =
                stack.authorize::<CurrentAleo, _>(&private_key, function_name, inputs.iter(), rng).unwrap();

            // Evaluate the function.
            let res_eval = stack.evaluate_function::<CurrentAleo, _>(
                CallStack::evaluate(authorization.replicate()).unwrap(),
                None,
                None,
                rng,
            );
            let eval_is_ok = res_eval.is_ok();

            // Execute the function.
            let trace = Trace::new();
            let translations = Arc::new(RwLock::new(Vec::new()));
            let res_exec = stack.execute_function::<CurrentAleo, _>(
                CallStack::execute(authorization.replicate(), Arc::new(RwLock::new(trace)), translations).unwrap(),
                None,
                None,
                rng,
            );
            let exec_is_ok = res_exec.is_ok() || <CurrentAleo as circuit::Environment>::is_satisfied();

            // Check that either all operations succeeded.
            assert!(
                eval_is_ok && exec_is_ok,
                "The results of the evaluation and execution should either all succeed or all fail"
            );
            // Reset the circuit.
            <CurrentAleo as circuit::Environment>::reset();
        }
    }

    // Run the tests for both variants.
    for is_raw in [false, true] {
        test_types(is_raw).into_par_iter().for_each(|type_| {
            run_test(type_, is_raw, ITERATIONS);
        })
    }
}

#[test]
fn test_value_size_in_bits() {
    const ITERATIONS: usize = 1000;

    // Load a process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Define a program .
    let program0 = Program::<CurrentNetwork>::from_str(
        r"
program test0.aleo;

struct A:
    one as field;
    two as u8;
    three as signature;

struct B:
    one as [scalar; 32u32];
    two as [A; 4u32];

record credits:
    owner as address.private;
    microcredits as u64.private;

record C:
    owner as address.private;
    data as [u8; 16u32].private;
    amount as u32.private;
    ayyy as A.private;
    bees as [B; 2u32].private;

function dummy:
    input r0 as A.public;
    input r1 as B.public;
    async dummy r0 r1 into r2;
    output r2 as test0.aleo/dummy.future;
finalize dummy:
    input r0 as A.public;
    input r1 as B.public;
    assert.eq r0.one r1.two[0u32].one;
    ",
    )
    .unwrap();

    // Add the program to the process.
    process.lock().add_program(&program0).unwrap();

    // Define a program with data types that we want to test.
    let program1 = Program::<CurrentNetwork>::from_str(
        r"
import test0.aleo;

program test1.aleo;

struct A:
    one as field;
    two as u8;
    three as signature;

struct B:
    one as [scalar; 32u32];
    two as [A; 4u32];

record credits:
    owner as address.private;
    microcredits as u64.private;

record C:
    owner as address.private;
    data as [u8; 16u32].private;
    amount as u32.private;
    ayyy as A.private;
    bees as [B; 2u32].private;

function dummy:
    input r0 as A.public;
    input r1 as B.public;
    async dummy r0 r1 into r2;
    output r2 as test1.aleo/dummy.future;
finalize dummy:
    input r0 as A.public;
    input r1 as B.public;
    assert.eq r0.one r1.two[0u32].one;
    ",
    )
    .unwrap();

    // Add the program to the process.
    process.lock().add_program(&program1).unwrap();

    // Get the stack.
    let stack = process.get_stack(program1.id()).unwrap();

    // A helper function to get a struct declaration.
    let get_struct = |id: &Identifier<CurrentNetwork>| stack.program().get_struct(id).cloned();

    // A helper function to get an external struct declaration.
    let get_external_struct = |locator: &Locator<CurrentNetwork>| {
        stack.get_external_stack(locator.program_id())?.program().get_struct(locator.resource()).cloned()
    };

    // A helper to get a record declaration.
    let get_record = |identifier: &Identifier<CurrentNetwork>| stack.program().get_record(identifier).cloned();

    // A helper to get an external record declaration.
    let get_external_record = |locator: &Locator<CurrentNetwork>| {
        stack.get_external_stack(locator.program_id())?.program().get_record(locator.resource()).cloned()
    };

    // A helper to get the argument types of a future.
    let get_future = |locator: &Locator<CurrentNetwork>| {
        Ok(match stack.program_id() == locator.program_id() {
            true => stack
                .program()
                .get_function_ref(locator.resource())?
                .finalize_logic()
                .ok_or_else(|| anyhow!("'{locator}' does not have a finalize scope"))?
                .input_types(),
            false => stack
                .get_external_stack(locator.program_id())?
                .program()
                .get_function_ref(locator.resource())?
                .finalize_logic()
                .ok_or_else(|| anyhow!("Failed to find function '{locator}'"))?
                .input_types(),
        })
    };

    // Define the types we want to test.
    let types = [
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Address)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Boolean)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Field)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::I8)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Group)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::I16)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::I32)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::I64)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::I128)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::U8)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::U16)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::U32)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::U64)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::U128)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Scalar)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Identifier)),
        RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Signature)),
        RegisterType::Plaintext(PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(8)]).unwrap(),
        )),
        RegisterType::Plaintext(PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::Field), vec![U32::new(17)]).unwrap(),
        )),
        RegisterType::Plaintext(PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::Signature), vec![U32::new(45)]).unwrap(),
        )),
        RegisterType::Plaintext(PlaintextType::Struct(Identifier::from_str("A").unwrap())),
        RegisterType::Plaintext(PlaintextType::Struct(Identifier::from_str("B").unwrap())),
        RegisterType::Plaintext(PlaintextType::ExternalStruct(Locator::from_str("test0.aleo/A").unwrap())),
        RegisterType::Plaintext(PlaintextType::ExternalStruct(Locator::from_str("test0.aleo/B").unwrap())),
        RegisterType::Plaintext(PlaintextType::Array(
            ArrayType::new(PlaintextType::Struct(Identifier::from_str("A").unwrap()), vec![U32::new(3)]).unwrap(),
        )),
        RegisterType::Plaintext(PlaintextType::Array(
            ArrayType::new(PlaintextType::Struct(Identifier::from_str("B").unwrap()), vec![U32::new(2)]).unwrap(),
        )),
        RegisterType::Plaintext(PlaintextType::Array(
            ArrayType::new(PlaintextType::ExternalStruct(Locator::from_str("test0.aleo/A").unwrap()), vec![U32::new(
                3,
            )])
            .unwrap(),
        )),
        RegisterType::Plaintext(PlaintextType::Array(
            ArrayType::new(PlaintextType::ExternalStruct(Locator::from_str("test0.aleo/B").unwrap()), vec![U32::new(
                2,
            )])
            .unwrap(),
        )),
        RegisterType::Record(Identifier::from_str("credits").unwrap()),
        RegisterType::Record(Identifier::from_str("C").unwrap()),
        RegisterType::ExternalRecord(Locator::from_str("test0.aleo/credits").unwrap()),
        RegisterType::ExternalRecord(Locator::from_str("test0.aleo/C").unwrap()),
        RegisterType::Future(Locator::from_str("test1.aleo/dummy").unwrap()),
    ];

    for is_raw in [false, true] {
        types.iter().for_each(|type_| {
            // Initialize an RNG.
            let rng = &mut TestRng::default();

            for i in 0..ITERATIONS {
                println!("Testing type '{type_}' (is_raw: {is_raw}, iteration: {i})");

                // Get the size in bits.
                let size_in_bits = match is_raw {
                    true => type_
                        .size_in_bits_raw(
                            &get_struct,
                            &get_external_struct,
                            &get_record,
                            &get_external_record,
                            &get_future,
                        )
                        .unwrap(),
                    false => type_
                        .size_in_bits(&get_struct, &get_external_struct, &get_record, &get_external_record, &get_future)
                        .unwrap(),
                };

                // Sample the value.
                let value = stack.sample_value(&Address::rand(rng), type_, rng).unwrap();

                // Get the bits of the plaintext.
                let bits = match is_raw {
                    false => value.to_bits_le(),
                    true => value.to_bits_raw_le(),
                };

                // Check that the number of bits matches the expected size.
                if bits.len() != size_in_bits {
                    println!("Expected size in bits: {size_in_bits}, Actual size in bits: {}", bits.len());
                }
                assert_eq!(bits.len(), size_in_bits);
            }
        })
    }
}
