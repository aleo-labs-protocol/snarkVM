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

include!("../helpers/macros.rs");

use crate::helpers::sample::{sample_finalize_registers, sample_registers, shared_process};

use circuit::AleoV0;
use console::{
    network::MainnetV0,
    prelude::*,
    program::{Identifier, Literal, LiteralType, Plaintext, Register, Value},
};
use snarkvm_synthesizer_process::Stack;
use snarkvm_synthesizer_program::{
    IsEq,
    IsInstruction,
    IsNeq,
    Opcode,
    Operand,
    Program,
    RegistersCircuit as _,
    RegistersTrait as _,
};

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

const ITERATIONS: usize = 25;

/// Samples the stack. Note: Do not replicate this for real program use, it is insecure.
/// Panics if the program fails to parse or the process fails to load, so any error comes from `Stack::new`.
#[allow(clippy::type_complexity)]
fn sample_stack(
    opcode: Opcode,
    type_a: LiteralType,
    type_b: LiteralType,
    mode_a: circuit::Mode,
    mode_b: circuit::Mode,
) -> Result<(Stack<CurrentNetwork>, Vec<Operand<CurrentNetwork>>, Register<CurrentNetwork>)> {
    // Initialize the opcode.
    let opcode = opcode.to_string();

    // Initialize the function name.
    let function_name = Identifier::<CurrentNetwork>::from_str("run")?;

    // Initialize the registers.
    let r0 = Register::Locator(0);
    let r1 = Register::Locator(1);
    let r2 = Register::Locator(2);

    // Initialize the program.
    let program = Program::from_str(&format!(
        "program testing.aleo;
            function {function_name}:
                input {r0} as {type_a}.{mode_a};
                input {r1} as {type_b}.{mode_b};
                {opcode} {r0} {r1} into {r2};
                async {function_name} {r0} {r1} into r3;
                output r3 as testing.aleo/{function_name}.future;

            finalize {function_name}:
                input {r0} as {type_a}.public;
                input {r1} as {type_b}.public;
                {opcode} {r0} {r1} into {r2};
        "
    ))
    .unwrap();

    // Initialize the operands.
    let operand_a = Operand::Register(r0);
    let operand_b = Operand::Register(r1);
    let operands = vec![operand_a, operand_b];

    // Initialize the stack.
    let stack = Stack::new(shared_process(), &program)?;

    Ok((stack, operands, r2))
}

fn check_is<const VARIANT: u8>(
    operation: impl FnOnce(Vec<Operand<CurrentNetwork>>, Register<CurrentNetwork>) -> IsInstruction<CurrentNetwork, VARIANT>,
    opcode: Opcode,
    literal_a: &Literal<CurrentNetwork>,
    literal_b: &Literal<CurrentNetwork>,
    mode_a: &circuit::Mode,
    mode_b: &circuit::Mode,
) {
    use circuit::Eject;

    println!("Checking '{opcode}' for '{literal_a}.{mode_a}' and '{literal_b}.{mode_b}'");

    // Initialize the types.
    let type_a = literal_a.to_type();
    let type_b = literal_b.to_type();
    assert_eq!(type_a, type_b, "The two literals must be the *same* type for this test");

    // Initialize the stack.
    let (stack, operands, destination) = sample_stack(opcode, type_a, type_b, *mode_a, *mode_b).unwrap();
    // Initialize the operation.
    let operation = operation(operands, destination.clone());
    // Initialize the function name.
    let function_name = Identifier::from_str("run").unwrap();
    // Initialize a destination operand.
    let destination_operand = Operand::Register(destination);

    /* First, check the operation *succeeds* when both operands are `literal_a.mode_a`. */
    {
        // Attempt to compute the valid operand case.
        let values = [
            (Value::Plaintext(Plaintext::from(literal_a)), None),
            (Value::Plaintext(Plaintext::from(literal_a)), None),
        ];
        let mut registers = sample_registers(&stack, &function_name, &values).unwrap();
        operation.evaluate(&stack, &mut registers).unwrap();

        // Retrieve the output.
        let output_a = registers.load_literal(&stack, &destination_operand).unwrap();

        // Ensure the output is correct.
        if let Literal::Boolean(output_a) = output_a {
            match VARIANT {
                0 => assert!(*output_a, "Instruction '{operation}' failed (console): {literal_a} {literal_a}"),
                1 => assert!(
                    !*output_a,
                    "Instruction '{operation}' should have failed (console): {literal_a} {literal_a}"
                ),
                _ => panic!("Found an invalid 'is' variant in the test"),
            }
        } else {
            panic!("The output must be a boolean (console)");
        }

        // Attempt to compute the valid operand case.
        let values = [
            (Value::Plaintext(Plaintext::from(literal_a)), Some(*mode_a)),
            (Value::Plaintext(Plaintext::from(literal_a)), Some(*mode_a)),
        ];
        let mut registers = sample_registers(&stack, &function_name, &values).unwrap();
        operation.execute::<CurrentAleo>(&stack, &mut registers).unwrap();

        // Retrieve the output.
        let output_b = registers.load_literal_circuit(&stack, &destination_operand).unwrap();

        // Ensure the output is correct.
        if let circuit::Literal::Boolean(output_b) = output_b {
            match VARIANT {
                0 => assert!(
                    output_b.eject_value(),
                    "Instruction '{operation}' failed (circuit): {literal_a}.{mode_a} {literal_a}.{mode_a}"
                ),
                1 => assert!(
                    !output_b.eject_value(),
                    "Instruction '{operation}' should have failed (circuit): {literal_a}.{mode_a} {literal_a}.{mode_a}"
                ),
                _ => panic!("Found an invalid 'is' variant in the test"),
            }
        } else {
            panic!("The output must be a boolean (circuit)");
        }

        // Ensure the circuit is satisfied.
        match VARIANT {
            0 => assert!(
                <CurrentAleo as circuit::Environment>::is_satisfied(),
                "Instruction '{operation}' should be satisfied (circuit): {literal_a}.{mode_a} {literal_a}.{mode_a}"
            ),
            1 => assert!(
                <CurrentAleo as circuit::Environment>::is_satisfied(),
                "Instruction '{operation}' should be satisfied (circuit): {literal_a}.{mode_a} {literal_a}.{mode_a}"
            ),
            _ => panic!("Found an invalid 'is' variant in the test"),
        }

        // Reset the circuit.
        <CurrentAleo as circuit::Environment>::reset();

        // Attempt to finalize the valid operand case.
        let mut registers = sample_finalize_registers(&stack, &function_name, &[
            Plaintext::from(literal_a),
            Plaintext::from(literal_a),
        ])
        .unwrap();
        operation.finalize(&stack, None, &mut registers).unwrap();

        // Retrieve the output.
        let output_c = registers.load_literal(&stack, &destination_operand).unwrap();

        // Ensure the output is correct.
        if let Literal::Boolean(output_c) = output_c {
            match VARIANT {
                0 => assert!(*output_c, "Instruction '{operation}' failed (finalize): {literal_a} {literal_a}"),
                1 => assert!(
                    !*output_c,
                    "Instruction '{operation}' should have failed (finalize): {literal_a} {literal_a}"
                ),
                _ => panic!("Found an invalid 'is' variant in the test"),
            }
        } else {
            panic!("The output must be a boolean (finalize)");
        }
    }
    /* Next, check the mismatching literals *fail*. */
    if literal_a != literal_b {
        // Attempt to compute the valid operand case.
        let values = [
            (Value::Plaintext(Plaintext::from(literal_a)), None),
            (Value::Plaintext(Plaintext::from(literal_b)), None),
        ];
        let mut registers = sample_registers(&stack, &function_name, &values).unwrap();
        operation.evaluate(&stack, &mut registers).unwrap();

        // Retrieve the output.
        let output_a = registers.load_literal(&stack, &destination_operand).unwrap();

        // Ensure the output is correct.
        if let Literal::Boolean(output_a) = output_a {
            match VARIANT {
                0 => assert!(
                    !*output_a,
                    "Instruction '{operation}' should have failed (console): {literal_a} {literal_b}"
                ),
                1 => assert!(*output_a, "Instruction '{operation}' failed (console): {literal_a} {literal_b}"),
                _ => panic!("Found an invalid 'is' variant in the test"),
            }
        } else {
            panic!("The output must be a boolean (console)");
        }

        // Attempt to compute the valid operand case.
        let values = [
            (Value::Plaintext(Plaintext::from(literal_a)), Some(*mode_a)),
            (Value::Plaintext(Plaintext::from(literal_b)), Some(*mode_b)),
        ];
        let mut registers = sample_registers(&stack, &function_name, &values).unwrap();
        operation.execute::<CurrentAleo>(&stack, &mut registers).unwrap();

        // Retrieve the output.
        let output_b = registers.load_literal_circuit(&stack, &destination_operand).unwrap();

        // Ensure the output is correct.
        if let circuit::Literal::Boolean(output_b) = output_b {
            match VARIANT {
                0 => assert!(
                    !output_b.eject_value(),
                    "Instruction '{operation}' failed (circuit): {literal_a}.{mode_a} {literal_b}.{mode_b}"
                ),
                1 => assert!(
                    output_b.eject_value(),
                    "Instruction '{operation}' should have failed (circuit): {literal_a}.{mode_a} {literal_b}.{mode_b}"
                ),
                _ => panic!("Found an invalid 'is' variant in the test"),
            }
        } else {
            panic!("The output must be a boolean (circuit)");
        }

        // Ensure the circuit is correct.
        match VARIANT {
            0 => assert!(
                <CurrentAleo as circuit::Environment>::is_satisfied(),
                "Instruction '{operation}' should be satisfied (circuit): {literal_a}.{mode_a} {literal_b}.{mode_b}"
            ),
            1 => assert!(
                <CurrentAleo as circuit::Environment>::is_satisfied(),
                "Instruction '{operation}' should be satisfied (circuit): {literal_a}.{mode_a} {literal_b}.{mode_b}"
            ),
            _ => panic!("Found an invalid 'is' variant in the test"),
        }

        // Reset the circuit.
        <CurrentAleo as circuit::Environment>::reset();

        // Attempt to finalize the valid operand case.
        let mut registers = sample_finalize_registers(&stack, &function_name, &[
            Plaintext::from(literal_a),
            Plaintext::from(literal_b),
        ])
        .unwrap();
        operation.finalize(&stack, None, &mut registers).unwrap();

        // Retrieve the output.
        let output_c = registers.load_literal(&stack, &destination_operand).unwrap();

        // Ensure the output is correct.
        if let Literal::Boolean(output_c) = output_c {
            match VARIANT {
                0 => assert!(
                    !*output_c,
                    "Instruction '{operation}' should have failed (finalize): {literal_a} {literal_b}"
                ),
                1 => assert!(*output_c, "Instruction '{operation}' failed (finalize): {literal_a} {literal_b}"),
                _ => panic!("Found an invalid 'is' variant in the test"),
            }
        } else {
            panic!("The output must be a boolean (finalize)");
        }
    }
}

fn check_is_fails(
    opcode: Opcode,
    literal_a: &Literal<CurrentNetwork>,
    literal_b: &Literal<CurrentNetwork>,
    mode_a: &circuit::Mode,
    mode_b: &circuit::Mode,
) {
    // Initialize the types.
    let type_a = literal_a.to_type();
    let type_b = literal_b.to_type();
    assert_ne!(type_a, type_b, "The two literals must be *different* types for this test");

    // Ensure the stack rejects the mismatched types.
    let Err(error) = sample_stack(opcode, type_a, type_b, *mode_a, *mode_b) else {
        panic!("Stack should have failed to initialize for: {opcode} {type_a}.{mode_a} {type_b}.{mode_b}")
    };
    let error = format!("{error:#}");
    assert!(
        error.contains(&format!("Instruction '{opcode}' expects inputs of the same type")),
        "Unexpected error for: {opcode} {type_a}.{mode_a} {type_b}.{mode_b}: {error}"
    );
}

#[test]
fn test_is_eq_succeeds() {
    // Initialize the operation.
    let operation = |operands, destination| IsEq::<CurrentNetwork>::new(operands, destination).unwrap();
    // Initialize the opcode.
    let opcode = IsEq::<CurrentNetwork>::opcode();

    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    for _ in 0..ITERATIONS {
        let literals_a = sample_literals!(CurrentNetwork, &mut rng);
        let literals_b = sample_literals!(CurrentNetwork, &mut rng);
        for (literal_a, literal_b) in literals_a.iter().zip_eq(literals_b.iter()) {
            for mode_a in &modes_a {
                for mode_b in &modes_b {
                    // Check the operation.
                    check_is(operation, opcode, literal_a, literal_b, mode_a, mode_b);
                }
            }
        }
    }
}

#[test]
fn test_is_eq_fails() {
    // Initialize the opcode.
    let opcode = IsEq::<CurrentNetwork>::opcode();

    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    let literals_a = sample_literals!(CurrentNetwork, &mut rng);
    let literals_b = sample_literals!(CurrentNetwork, &mut rng);
    for literal_a in &literals_a {
        for literal_b in &literals_b {
            if literal_a.to_type() != literal_b.to_type() {
                for mode_a in &modes_a {
                    for mode_b in &modes_b {
                        // Check the operation fails.
                        check_is_fails(opcode, literal_a, literal_b, mode_a, mode_b);
                    }
                }
            }
        }
    }
}

#[test]
fn test_is_neq_succeeds() {
    // Initialize the operation.
    let operation = |operands, destination| IsNeq::<CurrentNetwork>::new(operands, destination).unwrap();
    // Initialize the opcode.
    let opcode = IsNeq::<CurrentNetwork>::opcode();

    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    for _ in 0..ITERATIONS {
        let literals_a = sample_literals!(CurrentNetwork, &mut rng);
        let literals_b = sample_literals!(CurrentNetwork, &mut rng);
        for (literal_a, literal_b) in literals_a.iter().zip_eq(literals_b.iter()) {
            for mode_a in &modes_a {
                for mode_b in &modes_b {
                    // Check the operation.
                    check_is(operation, opcode, literal_a, literal_b, mode_a, mode_b);
                }
            }
        }
    }
}

#[test]
fn test_is_neq_fails() {
    // Initialize the opcode.
    let opcode = IsNeq::<CurrentNetwork>::opcode();

    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    let literals_a = sample_literals!(CurrentNetwork, &mut rng);
    let literals_b = sample_literals!(CurrentNetwork, &mut rng);
    for literal_a in &literals_a {
        for literal_b in &literals_b {
            if literal_a.to_type() != literal_b.to_type() {
                for mode_a in &modes_a {
                    for mode_b in &modes_b {
                        // Check the operation fails.
                        check_is_fails(opcode, literal_a, literal_b, mode_a, mode_b);
                    }
                }
            }
        }
    }
}
