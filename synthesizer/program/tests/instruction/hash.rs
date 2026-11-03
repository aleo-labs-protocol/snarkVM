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

use crate::helpers::sample::{sample_finalize_registers, sample_registers, shared_process};

use circuit::{AleoV0, Eject};
use console::{
    network::MainnetV0,
    prelude::*,
    program::{ArrayType, Identifier, LiteralType, Plaintext, PlaintextType, Register, U32, Value},
};
use snarkvm_synthesizer_process::Stack;
use snarkvm_synthesizer_program::{
    HashBHP256,
    HashBHP256Raw,
    HashBHP512,
    HashBHP512Raw,
    HashBHP768,
    HashBHP768Raw,
    HashBHP1024,
    HashBHP1024Raw,
    HashInstruction,
    HashKeccak256,
    HashKeccak256Native,
    HashKeccak256NativeRaw,
    HashKeccak256Raw,
    HashKeccak384,
    HashKeccak384Native,
    HashKeccak384NativeRaw,
    HashKeccak384Raw,
    HashKeccak512,
    HashKeccak512Native,
    HashKeccak512NativeRaw,
    HashKeccak512Raw,
    HashPED64,
    HashPED64Raw,
    HashPED128,
    HashPED128Raw,
    HashPSD2,
    HashPSD2Raw,
    HashPSD4,
    HashPSD4Raw,
    HashPSD8,
    HashPSD8Raw,
    HashSha3_256,
    HashSha3_256Native,
    HashSha3_256NativeRaw,
    HashSha3_256Raw,
    HashSha3_384,
    HashSha3_384Native,
    HashSha3_384NativeRaw,
    HashSha3_384Raw,
    HashSha3_512,
    HashSha3_512Native,
    HashSha3_512NativeRaw,
    HashSha3_512Raw,
    HashVariant,
    Opcode,
    Operand,
    Program,
    RegistersCircuit as _,
    RegistersTrait as _,
};

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

const ITERATIONS: usize = 2;

fn sample_valid_input_types<N: Network, R: CryptoRng + Rng>(
    variant: HashVariant,
    rng: &mut R,
) -> Vec<PlaintextType<N>> {
    match variant {
        HashVariant::HashKeccak256Native
        | HashVariant::HashKeccak384Native
        | HashVariant::HashKeccak512Native
        | HashVariant::HashSha3_256Native
        | HashVariant::HashSha3_384Native
        | HashVariant::HashSha3_512Native
        | HashVariant::HashKeccak256NativeRaw
        | HashVariant::HashKeccak384NativeRaw
        | HashVariant::HashKeccak512NativeRaw
        | HashVariant::HashSha3_256NativeRaw
        | HashVariant::HashSha3_384NativeRaw
        | HashVariant::HashSha3_512NativeRaw => (0..10)
            .map(|_| {
                let length = rng.random_range(1..=(CurrentNetwork::LATEST_MAX_ARRAY_ELEMENTS() / 8)) * 8;
                PlaintextType::Array(
                    ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(
                        u32::try_from(length).unwrap(),
                    )])
                    .unwrap(),
                )
            })
            .collect(),
        HashVariant::HashKeccak256Raw
        | HashVariant::HashKeccak384Raw
        | HashVariant::HashKeccak512Raw
        | HashVariant::HashSha3_256Raw
        | HashVariant::HashSha3_384Raw
        | HashVariant::HashSha3_512Raw => vec![
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Address), vec![U32::new(8)]).unwrap(),
            ),
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Field), vec![U32::new(8)]).unwrap(),
            ),
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Group), vec![U32::new(8)]).unwrap(),
            ),
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
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Scalar), vec![U32::new(8)]).unwrap(),
            ),
        ],
        _ => vec![
            PlaintextType::Literal(LiteralType::Address),
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
        ],
    }
}

/// **Attention**: When changing this, also update in `src/logic/instruction/hash.rs`.
fn sample_valid_destination_types<N: Network>(variant: HashVariant) -> Vec<PlaintextType<N>> {
    match variant {
        HashVariant::HashKeccak256Native
        | HashVariant::HashKeccak256NativeRaw
        | HashVariant::HashSha3_256Native
        | HashVariant::HashSha3_256NativeRaw => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(256)]).unwrap(),
        )],
        HashVariant::HashKeccak384Native
        | HashVariant::HashKeccak384NativeRaw
        | HashVariant::HashSha3_384Native
        | HashVariant::HashSha3_384NativeRaw => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(384)]).unwrap(),
        )],
        HashVariant::HashKeccak512Native
        | HashVariant::HashKeccak512NativeRaw
        | HashVariant::HashSha3_512Native
        | HashVariant::HashSha3_512NativeRaw => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(512)]).unwrap(),
        )],
        _ => vec![
            PlaintextType::Literal(LiteralType::Address),
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
        ],
    }
}

/// Samples the stack. Note: Do not replicate this for real program use, it is insecure.
#[allow(clippy::type_complexity)]
fn sample_stack(
    opcode: Opcode,
    type_: &PlaintextType<CurrentNetwork>,
    mode: circuit::Mode,
    destination_type: &PlaintextType<CurrentNetwork>,
) -> Result<(Stack<CurrentNetwork>, Vec<Operand<CurrentNetwork>>, Register<CurrentNetwork>)> {
    // Initialize the opcode.
    let opcode = opcode.to_string();

    // Initialize the function name.
    let function_name = Identifier::<CurrentNetwork>::from_str("run")?;

    // Initialize the registers.
    let r0 = Register::Locator(0);
    let r1 = Register::Locator(1);

    // Initialize the program.
    let program = Program::from_str(&format!(
        "program testing.aleo;
            function {function_name}:
                input {r0} as {type_}.{mode};
                {opcode} {r0} into {r1} as {destination_type};
                async {function_name} {r0} into r2;
                output r2 as testing.aleo/{function_name}.future;
            finalize {function_name}:
                input {r0} as {type_}.public;
                {opcode} {r0} into {r1} as {destination_type};
        "
    ))?;

    // Initialize the operands.
    let operands = vec![Operand::Register(r0)];

    // Initialize the stack.
    let stack = Stack::new(shared_process(), &program)?;

    Ok((stack, operands, r1))
}

fn check_hash<const VARIANT: u8>(
    operation: impl FnOnce(
        Vec<Operand<CurrentNetwork>>,
        Register<CurrentNetwork>,
        PlaintextType<CurrentNetwork>,
    ) -> HashInstruction<CurrentNetwork, VARIANT>,
    opcode: Opcode,
    input_type: &PlaintextType<CurrentNetwork>,
    mode: &circuit::Mode,
    destination_type: &PlaintextType<CurrentNetwork>,
) {
    println!("Checking '{opcode}' for '{input_type}.{mode}'");

    // Initialize the stack.
    let (stack, operands, destination) = sample_stack(opcode, input_type, *mode, destination_type).unwrap();

    // Sample the input.
    let input = stack.sample_plaintext(input_type, &mut TestRng::default()).unwrap();

    // Initialize the operation.
    let operation = operation(operands, destination.clone(), destination_type.clone());
    // Initialize the function name.
    let function_name = Identifier::from_str("run").unwrap();
    // Initialize a destination operand.
    let destination_operand = Operand::Register(destination);

    // Attempt to evaluate the valid operand case.
    let mut evaluate_registers =
        sample_registers(&stack, &function_name, &[(Value::Plaintext(input.clone()), None)]).unwrap();
    let result_a = operation.evaluate(&stack, &mut evaluate_registers);

    // Attempt to execute the valid operand case.
    let mut execute_registers =
        sample_registers(&stack, &function_name, &[(Value::Plaintext(input.clone()), Some(*mode))]).unwrap();
    let result_b = operation.execute::<CurrentAleo>(&stack, &mut execute_registers);

    // Attempt to finalize the valid operand case.
    let mut finalize_registers = sample_finalize_registers(&stack, &function_name, &[input]).unwrap();
    let result_c = operation.finalize(&stack, None, &mut finalize_registers);

    // Check that either all operations failed, or all operations succeeded.
    let all_failed = result_a.is_err() && result_b.is_err() && result_c.is_err();
    let all_succeeded = result_a.is_ok() && result_b.is_ok() && result_c.is_ok();
    assert!(
        all_failed || all_succeeded,
        "The results of the evaluation, execution, and finalization should either all succeed or all fail"
    );

    // If all operations succeeded, check that the outputs are consistent.
    if all_succeeded {
        // Retrieve the output of evaluation.
        let output_a = evaluate_registers.load(&stack, &destination_operand).unwrap();

        // Retrieve the output of execution.
        let output_b = execute_registers.load_circuit(&stack, &destination_operand).unwrap();

        // Retrieve the output of finalization.
        let output_c = finalize_registers.load(&stack, &destination_operand).unwrap();

        // Check that the outputs are consistent.
        assert_eq!(output_a, output_b.eject_value(), "The results of the evaluation and execution are inconsistent");
        assert_eq!(output_a, output_c, "The results of the evaluation and finalization are inconsistent");

        // Check that the output type is consistent with the declared type.
        match (VARIANT, output_a) {
            (0..=32, Value::Plaintext(Plaintext::Literal(literal, _))) => {
                assert_eq!(
                    &PlaintextType::Literal(literal.to_type()),
                    destination_type,
                    "The output type is inconsistent with the declared type"
                );
            }
            (33..=44, Value::Plaintext(plaintext)) => {
                // Check that the plaintext is a bit array.
                let Ok(bit_array) = plaintext.as_bit_array() else {
                    panic!("The output type is inconsistent with the declared type");
                };
                // Get the destination type.
                let PlaintextType::Array(array_type) = &destination_type else {
                    panic!("The output type is inconsistent with the declared type");
                };
                // Check that the lengths match.
                assert_eq!(
                    bit_array.len(),
                    **array_type.length() as usize,
                    "The output type is inconsistent with the declared type"
                );
            }

            _ => unreachable!("The output type is inconsistent with the declared type"),
        }
    }

    // Reset the circuit.
    <CurrentAleo as circuit::Environment>::reset();
}

macro_rules! test_hash {
        ($name: tt, $hash:ident, $iterations:expr) => {
            paste::paste! {
                #[test]
                fn [<test _ $name _ is _ consistent>]() {
                    // Initialize the operation.
                    let operation = |operands, destination, destination_type| $hash::<CurrentNetwork>::new(operands, destination, destination_type).unwrap();
                    // Initialize the opcode.
                    let opcode = $hash::<CurrentNetwork>::opcode();

                    // Prepare the rng.
                    let rng = &mut TestRng::default();

                    // Prepare the test.
                    let modes = [circuit::Mode::Public, circuit::Mode::Private];

                    for _ in 0..$iterations {
                        for input_type in sample_valid_input_types(HashVariant::$hash, rng) {
                            for mode in modes.iter() {
                                for destination_type in sample_valid_destination_types(HashVariant::$hash) {
                                    check_hash(
                                        operation,
                                        opcode,
                                        &input_type,
                                        mode,
                                        &destination_type,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        };
    }

test_hash!(hash_bhp256, HashBHP256, ITERATIONS);
test_hash!(hash_bhp512, HashBHP512, ITERATIONS);
test_hash!(hash_bhp768, HashBHP768, ITERATIONS);
test_hash!(hash_bhp1024, HashBHP1024, ITERATIONS);

test_hash!(hash_bhp256_raw, HashBHP256Raw, ITERATIONS);
test_hash!(hash_bhp512_raw, HashBHP512Raw, ITERATIONS);
test_hash!(hash_bhp768_raw, HashBHP768Raw, ITERATIONS);
test_hash!(hash_bhp1024_raw, HashBHP1024Raw, ITERATIONS);

test_hash!(hash_keccak256, HashKeccak256, 2);
test_hash!(hash_keccak384, HashKeccak384, 1);
test_hash!(hash_keccak512, HashKeccak512, 1);

test_hash!(hash_keccak256_raw, HashKeccak256Raw, 2);
test_hash!(hash_keccak384_raw, HashKeccak384Raw, 1);
test_hash!(hash_keccak512_raw, HashKeccak512Raw, 1);

test_hash!(hash_psd2, HashPSD2, ITERATIONS);
test_hash!(hash_psd4, HashPSD4, ITERATIONS);
test_hash!(hash_psd8, HashPSD8, ITERATIONS);

test_hash!(hash_psd2_raw, HashPSD2Raw, ITERATIONS);
test_hash!(hash_psd4_raw, HashPSD4Raw, ITERATIONS);
test_hash!(hash_psd8_raw, HashPSD8Raw, ITERATIONS);

test_hash!(hash_sha3_256, HashSha3_256, 2);
test_hash!(hash_sha3_384, HashSha3_384, 1);
test_hash!(hash_sha3_512, HashSha3_512, 1);

test_hash!(hash_sha3_256_raw, HashSha3_256Raw, 2);
test_hash!(hash_sha3_384_raw, HashSha3_384Raw, 1);
test_hash!(hash_sha3_512_raw, HashSha3_512Raw, 1);

test_hash!(hash_keccak256_native, HashKeccak256Native, 2);
test_hash!(hash_keccak384_native, HashKeccak384Native, 1);
test_hash!(hash_keccak512_native, HashKeccak512Native, 1);

test_hash!(hash_sha3_256_native, HashSha3_256Native, 2);
test_hash!(hash_sha3_384_native, HashSha3_384Native, 1);
test_hash!(hash_sha3_512_native, HashSha3_512Native, 1);

test_hash!(hash_keccak256_native_raw, HashKeccak256NativeRaw, 2);
test_hash!(hash_keccak384_native_raw, HashKeccak384NativeRaw, 1);
test_hash!(hash_keccak512_native_raw, HashKeccak512NativeRaw, 1);

test_hash!(hash_sha3_256_native_raw, HashSha3_256NativeRaw, 2);
test_hash!(hash_sha3_384_native_raw, HashSha3_384NativeRaw, 1);
test_hash!(hash_sha3_512_native_raw, HashSha3_512NativeRaw, 1);

// Note this test must be explicitly written, instead of using the macro, because HashPED64 fails on certain input types.
#[test]
fn test_hash_ped64_is_consistent() {
    // Prepare the test.
    let modes = [circuit::Mode::Public, circuit::Mode::Private];

    macro_rules! check_hash {
        ($operation:tt) => {
            for _ in 0..ITERATIONS {
                let input_types = [
                    PlaintextType::Literal(LiteralType::Boolean),
                    PlaintextType::Literal(LiteralType::I8),
                    PlaintextType::Literal(LiteralType::I16),
                    PlaintextType::Literal(LiteralType::I32),
                    PlaintextType::Literal(LiteralType::U8),
                    PlaintextType::Literal(LiteralType::U16),
                    PlaintextType::Literal(LiteralType::U32),
                ];
                for input_type in input_types.iter() {
                    for mode in modes.iter() {
                        for destination_type in sample_valid_destination_types(HashVariant::$operation) {
                            check_hash(
                                |operands, destination, destination_type| {
                                    $operation::<CurrentNetwork>::new(operands, destination, destination_type).unwrap()
                                },
                                $operation::<CurrentNetwork>::opcode(),
                                input_type,
                                mode,
                                &destination_type,
                            );
                        }
                    }
                }
            }
        };
    }
    check_hash!(HashPED64);
    check_hash!(HashPED64Raw);
}

// Note this test must be explicitly written, instead of using the macro, because HashPED128 fails on certain input types.
#[test]
fn test_hash_ped128_is_consistent() {
    // Prepare the test.
    let modes = [circuit::Mode::Public, circuit::Mode::Private];

    macro_rules! check_hash {
        ($operation:tt) => {
            for _ in 0..ITERATIONS {
                let input_types = [
                    PlaintextType::Literal(LiteralType::Boolean),
                    PlaintextType::Literal(LiteralType::I8),
                    PlaintextType::Literal(LiteralType::I16),
                    PlaintextType::Literal(LiteralType::I32),
                    PlaintextType::Literal(LiteralType::I64),
                    PlaintextType::Literal(LiteralType::U8),
                    PlaintextType::Literal(LiteralType::U16),
                    PlaintextType::Literal(LiteralType::U32),
                    PlaintextType::Literal(LiteralType::U64),
                ];
                for input_type in input_types.iter() {
                    for mode in modes.iter() {
                        for destination_type in sample_valid_destination_types(HashVariant::$operation) {
                            check_hash(
                                |operands, destination, destination_type| {
                                    $operation::<CurrentNetwork>::new(operands, destination, destination_type).unwrap()
                                },
                                $operation::<CurrentNetwork>::opcode(),
                                input_type,
                                mode,
                                &destination_type,
                            );
                        }
                    }
                }
            }
        };
    }
    check_hash!(HashPED128);
    check_hash!(HashPED128Raw);
}
