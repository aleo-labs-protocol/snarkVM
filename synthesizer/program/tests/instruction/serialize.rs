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
    program::{ArrayType, Identifier, LiteralType, Locator, PlaintextType, Register, U32, Value},
};
use snarkvm_synthesizer_process::Stack;
use snarkvm_synthesizer_program::{
    Opcode,
    Operand,
    Program,
    RegistersCircuit as _,
    RegistersTrait as _,
    SerializeBits,
    SerializeBitsRaw,
    SerializeInstruction,
    SerializeVariant,
};

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

const ITERATIONS: usize = 2;

/// Samples the stack. Note: Do not replicate this for real program use, it is insecure.
#[allow(clippy::type_complexity)]
fn sample_stack(
    opcode: Opcode,
    type_: &PlaintextType<CurrentNetwork>,
    bits: &ArrayType<CurrentNetwork>,
    mode: circuit::Mode,
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
                {opcode} {r0} ({type_}) into {r1} ({bits});
                async {function_name} {r0} into r2;
                output r2 as testing.aleo/{function_name}.future;
            finalize {function_name}:
                input {r0} as {type_}.public;
                {opcode} {r0} ({type_}) into {r1} ({bits});
        "
    ))?;

    // Initialize the operands.
    let operands = vec![Operand::Register(r0)];

    // Initialize the stack.
    let stack = Stack::new(shared_process(), &program, ConsensusVersion::latest())?;

    Ok((stack, operands, r1))
}

fn check_serialize<const VARIANT: u8>(
    operation: impl FnOnce(
        Vec<Operand<CurrentNetwork>>,
        PlaintextType<CurrentNetwork>,
        Register<CurrentNetwork>,
        ArrayType<CurrentNetwork>,
    ) -> SerializeInstruction<CurrentNetwork, VARIANT>,
    opcode: Opcode,
    type_: &PlaintextType<CurrentNetwork>,
    mode: &circuit::Mode,
    iterations: usize,
) {
    // Initalize an RNG.
    let rng = &mut TestRng::default();

    // Struct definitions are not supported.
    let fail_get_struct = |_: &Identifier<CurrentNetwork>| bail!("structs are not supported");
    let fail_get_external_struct = |_: &Locator<CurrentNetwork>| bail!("structs are not supported");

    // Get the size in bits.
    let size_in_bits = match VARIANT {
        0 => type_.size_in_bits(&fail_get_struct, &fail_get_external_struct).unwrap(),
        1 => type_.size_in_bits_raw(&fail_get_struct, &fail_get_external_struct).unwrap(),
        _ => panic!("Invalid 'serialize' variant"),
    };
    let size_in_bits = u32::try_from(size_in_bits).unwrap();

    println!("Checking '{opcode}' for '{type_}.{mode}' to [boolean; {size_in_bits}u32]");

    // Construct the array type.
    let bits_type = ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(size_in_bits)]).unwrap();

    // Initialize the stack.
    let (stack, operands, destination) = sample_stack(opcode, type_, &bits_type, *mode).unwrap();

    // Initialize the operation.
    let operation = operation(operands, type_.clone(), destination.clone(), bits_type);
    // Initialize the function name.
    let function_name = Identifier::from_str("run").unwrap();
    // Initialize a destination operand.
    let destination_operand = Operand::Register(destination);

    // Run the test for a desired number of iterations.
    for _ in 0..iterations {
        // Sample the plaintext.
        let plaintext = stack.sample_plaintext(type_, rng).unwrap();

        // Get the bits of the plaintext.
        let bits = match VARIANT {
            0 => plaintext.to_bits_le(),
            1 => plaintext.to_bits_raw_le(),
            _ => panic!("Invalid 'serialize' variant"),
        };

        // Check that the number of bits matches.
        assert_eq!(bits.len(), size_in_bits as usize, "The number of bits does not match the expected size");

        // Attempt to evaluate the valid operand case.
        let mut evaluate_registers =
            sample_registers(&stack, &function_name, &[(Value::Plaintext(plaintext.clone()), None)]).unwrap();
        let result_a = operation.evaluate(&stack, &mut evaluate_registers);

        // Attempt to execute the valid operand case.
        let mut execute_registers =
            sample_registers(&stack, &function_name, &[(Value::Plaintext(plaintext.clone()), Some(*mode))]).unwrap();
        let result_b = operation.execute::<CurrentAleo>(&stack, &mut execute_registers);

        // Attempt to finalize the valid operand case.
        let mut finalize_registers = sample_finalize_registers(&stack, &function_name, &[plaintext]).unwrap();
        let result_c = operation.finalize(&stack, None, &mut finalize_registers);

        // The input is a valid plaintext, so all operations must succeed.
        // Execution only succeeds if its circuit is also satisfied.
        let eval_is_ok = result_a.is_ok();
        let exec_is_ok = result_b.is_ok() && <CurrentAleo as circuit::Environment>::is_satisfied();
        let finalize_is_ok = result_c.is_ok();
        assert!(
            eval_is_ok && exec_is_ok && finalize_is_ok,
            "The evaluation ({eval_is_ok}), execution ({exec_is_ok}), and finalization ({finalize_is_ok}) should all succeed"
        );

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
        match output_a {
            Value::Plaintext(plaintext) => {
                // Check that the plaintext is a bit array.
                let Ok(bit_array) = plaintext.as_bit_array() else {
                    panic!("The output type is inconsistent with the declared type");
                };
                // Check that the lengths match.
                assert_eq!(
                    bit_array.len(),
                    size_in_bits as usize,
                    "The output type is inconsistent with the declared type"
                );
            }
            _ => unreachable!("The output type is inconsistent with the declared type"),
        }
        // Reset the circuit.
        <CurrentAleo as circuit::Environment>::reset();
    }
}

// Get the types to be tested.
fn test_types(variant: SerializeVariant) -> Vec<PlaintextType<CurrentNetwork>> {
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
    if variant == SerializeVariant::ToBitsRaw {
        types.push(PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(32)]).unwrap(),
        ))
    }

    types
}

macro_rules! test_serialize {
        ($name: tt, $serialize:ident, $variant:ident, $iterations:expr) => {
            paste::paste! {
                #[test]
                fn [<test _ $name _ is _ consistent>]() {
                    // Initialize the operation.
                    let operation = |operands, operand_type, destination, destination_type| $serialize::<CurrentNetwork>::new(operands, operand_type, destination, destination_type).unwrap();
                    // Initialize the opcode.
                    let opcode = $serialize::<CurrentNetwork>::opcode();

                    // Prepare the test.
                    let modes = [circuit::Mode::Public, circuit::Mode::Private];

                    for mode in modes.iter() {
                        for type_ in test_types(SerializeVariant::$variant).iter() {
                            check_serialize(
                                operation,
                                opcode,
                                type_,
                                mode,
                                $iterations
                            );
                        }
                    }
                }
            }
        };
    }

test_serialize!(serialize_bits, SerializeBits, ToBits, ITERATIONS);
test_serialize!(serialize_bits_raw, SerializeBitsRaw, ToBitsRaw, ITERATIONS);

#[test]
fn test_serialize_rejects_wrong_destination_length() {
    // Struct definitions are not supported.
    let fail_get_struct = |_: &Identifier<CurrentNetwork>| bail!("structs are not supported");
    let fail_get_external_struct = |_: &Locator<CurrentNetwork>| bail!("structs are not supported");

    // Returns a program that serializes `type_` into `function_bits` bits in the function scope
    // and into `finalize_bits` bits in the finalize scope.
    let program =
        |opcode: Opcode, type_: &PlaintextType<CurrentNetwork>, function_bits: usize, finalize_bits: usize| {
            Program::<CurrentNetwork>::from_str(&format!(
                "program testing.aleo;
            function run:
                input r0 as {type_}.public;
                {opcode} r0 ({type_}) into r1 ([boolean; {function_bits}u32]);
                async run r0 into r2;
                output r2 as testing.aleo/run.future;
            finalize run:
                input r0 as {type_}.public;
                {opcode} r0 ({type_}) into r1 ([boolean; {finalize_bits}u32]);
            "
            ))
            .unwrap()
        };

    for (variant, opcode) in [
        (SerializeVariant::ToBits, SerializeBits::<CurrentNetwork>::opcode()),
        (SerializeVariant::ToBitsRaw, SerializeBitsRaw::<CurrentNetwork>::opcode()),
    ] {
        for type_ in test_types(variant.clone()) {
            // Get the size in bits.
            let size_in_bits = match variant {
                SerializeVariant::ToBits => type_.size_in_bits(&fail_get_struct, &fail_get_external_struct).unwrap(),
                SerializeVariant::ToBitsRaw => {
                    type_.size_in_bits_raw(&fail_get_struct, &fail_get_external_struct).unwrap()
                }
            };

            // Check that the correct length is accepted.
            let correct = program(opcode, &type_, size_in_bits, size_in_bits);
            assert!(
                Stack::new(shared_process(), &correct, ConsensusVersion::latest()).is_ok(),
                "'{opcode}' should accept '{type_}' as {size_in_bits} bits"
            );

            // Check that a wrong length is rejected in either scope.
            let wrong_lengths = [size_in_bits - 1, size_in_bits + 1].into_iter().filter(|length| *length > 0);
            for wrong_bits in wrong_lengths {
                for (function_bits, finalize_bits) in [(wrong_bits, size_in_bits), (size_in_bits, wrong_bits)] {
                    let wrong = program(opcode, &type_, function_bits, finalize_bits);
                    let error = Stack::new(shared_process(), &wrong, ConsensusVersion::latest())
                        .err()
                        .unwrap_or_else(|| panic!("'{opcode}' should reject '{type_}' as {wrong_bits} bits"));
                    assert!(
                        format!("{error:?}").contains("does not match the destination"),
                        "'{opcode}' rejected '{type_}' as {wrong_bits} bits for an unexpected reason: {error:?}"
                    );
                }
            }
        }
    }
}
