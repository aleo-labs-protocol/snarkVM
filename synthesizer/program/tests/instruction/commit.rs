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

use circuit::{AleoV0, Eject};
use console::{
    network::MainnetV0,
    prelude::*,
    program::{Identifier, Literal, LiteralType, Plaintext, Register, Value},
};
use snarkvm_synthesizer_process::Stack;
use snarkvm_synthesizer_program::{
    CommitBHP256,
    CommitBHP256Raw,
    CommitBHP512,
    CommitBHP512Raw,
    CommitBHP768,
    CommitBHP768Raw,
    CommitBHP1024,
    CommitBHP1024Raw,
    CommitInstruction,
    CommitPED64,
    CommitPED64Raw,
    CommitPED128,
    CommitPED128Raw,
    Opcode,
    Operand,
    Program,
    RegistersCircuit as _,
    RegistersTrait as _,
};

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

const ITERATIONS: usize = 2;

/// **Attention**: When changing this, also update in `src/logic/instruction/commit.rs`.
fn valid_destination_types() -> &'static [LiteralType] {
    &[LiteralType::Address, LiteralType::Field, LiteralType::Group]
}

/// Samples the stack. Note: Do not replicate this for real program use, it is insecure.
#[allow(clippy::type_complexity)]
fn sample_stack(
    opcode: Opcode,
    type_a: LiteralType,
    type_b: LiteralType,
    mode_a: circuit::Mode,
    mode_b: circuit::Mode,
    destination_type: LiteralType,
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
                {opcode} {r0} {r1} into {r2} as {destination_type};
                async {function_name} {r0} {r1} into r3;
                output r3 as testing.aleo/{function_name}.future;

            finalize {function_name}:
                input {r0} as {type_a}.public;
                input {r1} as {type_b}.public;
                {opcode} {r0} {r1} into {r2} as {destination_type};
        "
    ))?;

    // Initialize the operands.
    let operand_a = Operand::Register(r0);
    let operand_b = Operand::Register(r1);
    let operands = vec![operand_a, operand_b];

    // Initialize the stack.
    let stack = Stack::new(shared_process(), &program)?;

    Ok((stack, operands, r2))
}

fn check_commit<const VARIANT: u8>(
    operation: impl FnOnce(
        Vec<Operand<CurrentNetwork>>,
        Register<CurrentNetwork>,
        LiteralType,
    ) -> CommitInstruction<CurrentNetwork, VARIANT>,
    opcode: Opcode,
    literal_a: &Literal<CurrentNetwork>,
    literal_b: &Literal<CurrentNetwork>,
    mode_a: &circuit::Mode,
    mode_b: &circuit::Mode,
    destination_type: LiteralType,
) {
    println!("Checking '{opcode}' for '{literal_a}.{mode_a}' and '{literal_b}.{mode_b}'");

    // Initialize the types.
    let type_a = literal_a.to_type();
    let type_b = literal_b.to_type();

    // Initialize the stack.
    let (stack, operands, destination) =
        sample_stack(opcode, type_a, type_b, *mode_a, *mode_b, destination_type).unwrap();
    // Initialize the operation.
    let operation = operation(operands, destination.clone(), destination_type);
    // Initialize the function name.
    let function_name = Identifier::from_str("run").unwrap();
    // Initialize a destination operand.
    let destination_operand = Operand::Register(destination);

    // Attempt to evaluate the valid operand case.
    let values =
        [(Value::Plaintext(Plaintext::from(literal_a)), None), (Value::Plaintext(Plaintext::from(literal_b)), None)];
    let mut evaluate_registers = sample_registers(&stack, &function_name, &values).unwrap();
    let result_a = operation.evaluate(&stack, &mut evaluate_registers);

    // Attempt to execute the valid operand case.
    let values = [
        (Value::Plaintext(Plaintext::from(literal_a)), Some(*mode_a)),
        (Value::Plaintext(Plaintext::from(literal_b)), Some(*mode_b)),
    ];
    let mut execute_registers = sample_registers(&stack, &function_name, &values).unwrap();
    let result_b = operation.execute::<CurrentAleo>(&stack, &mut execute_registers);

    // Attempt to finalize the valid operand case.
    let mut finalize_registers =
        sample_finalize_registers(&stack, &function_name, &[Plaintext::from(literal_a), Plaintext::from(literal_b)])
            .unwrap();
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
        match output_a {
            Value::Plaintext(Plaintext::Literal(literal, _)) => {
                assert_eq!(
                    literal.to_type(),
                    destination_type,
                    "The output type is inconsistent with the declared type"
                );
            }
            _ => unreachable!("The output type is inconsistent with the declared type"),
        }
    }

    // Reset the circuit.
    <CurrentAleo as circuit::Environment>::reset();
}

macro_rules! test_commit {
        ($name: tt, $commit:ident) => {
            paste::paste! {
                #[test]
                fn [<test _ $name _ is _ consistent>]() {
                    // Initialize the operation.
                    let operation = |operands, destination, destination_type| $commit::<CurrentNetwork>::new(operands, destination, destination_type).unwrap();
                    // Initialize the opcode.
                    let opcode = $commit::<CurrentNetwork>::opcode();

                    // Prepare the rng.
                    let mut rng = TestRng::default();

                   // Prepare the test.
                    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
                    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

                    for _ in 0..ITERATIONS {
                        let literals_a = sample_literals!(CurrentNetwork, &mut rng);
                        let literals_b = vec![console::program::Literal::Scalar(console::types::Scalar::rand(&mut rng))];

                        for literal_a in &literals_a {
                            for literal_b in &literals_b {
                                for mode_a in &modes_a {
                                    for mode_b in &modes_b {
                                        for destination_type in valid_destination_types() {
                                            check_commit(operation, opcode, literal_a, literal_b, mode_a, mode_b, *destination_type);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };
    }

test_commit!(commit_bhp256, CommitBHP256);
test_commit!(commit_bhp512, CommitBHP512);
test_commit!(commit_bhp768, CommitBHP768);
test_commit!(commit_bhp1024, CommitBHP1024);

test_commit!(commit_bhp256_raw, CommitBHP256Raw);
test_commit!(commit_bhp512_raw, CommitBHP512Raw);
test_commit!(commit_bhp768_raw, CommitBHP768Raw);
test_commit!(commit_bhp1024_raw, CommitBHP1024Raw);

// Note this test must be explicitly written, instead of using the macro, because CommitPED64 and CommitToGroupPED64 fails on certain input types.
#[test]
fn test_commit_ped64_is_consistent() {
    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    macro_rules! check_commit {
        ($operation:tt) => {
            for _ in 0..ITERATIONS {
                let literals_a = [
                    Literal::Boolean(console::types::Boolean::rand(&mut rng)),
                    Literal::I8(console::types::I8::rand(&mut rng)),
                    Literal::I16(console::types::I16::rand(&mut rng)),
                    Literal::I32(console::types::I32::rand(&mut rng)),
                    Literal::U8(console::types::U8::rand(&mut rng)),
                    Literal::U16(console::types::U16::rand(&mut rng)),
                    Literal::U32(console::types::U32::rand(&mut rng)),
                ];
                let literals_b = vec![Literal::Scalar(console::types::Scalar::rand(&mut rng))];
                for literal_a in &literals_a {
                    for literal_b in &literals_b {
                        for mode_a in &modes_a {
                            for mode_b in &modes_b {
                                for destination_type in valid_destination_types() {
                                    check_commit(
                                        |operands, destination, destination_type| {
                                            $operation::<CurrentNetwork>::new(operands, destination, destination_type)
                                                .unwrap()
                                        },
                                        $operation::<CurrentNetwork>::opcode(),
                                        literal_a,
                                        literal_b,
                                        mode_a,
                                        mode_b,
                                        *destination_type,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        };
    }
    check_commit!(CommitPED64);
}

// Note this test must be explicitly written, instead of using the macro, because CommitPED128 and CommitToGroupPED64 fails on certain input types.
#[test]
fn test_commit_ped128_is_consistent() {
    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    macro_rules! check_commit {
        ($operation:tt) => {
            for _ in 0..ITERATIONS {
                let literals_a = [
                    Literal::Boolean(console::types::Boolean::rand(&mut rng)),
                    Literal::I8(console::types::I8::rand(&mut rng)),
                    Literal::I16(console::types::I16::rand(&mut rng)),
                    Literal::I32(console::types::I32::rand(&mut rng)),
                    Literal::I64(console::types::I64::rand(&mut rng)),
                    Literal::U8(console::types::U8::rand(&mut rng)),
                    Literal::U16(console::types::U16::rand(&mut rng)),
                    Literal::U32(console::types::U32::rand(&mut rng)),
                    Literal::U64(console::types::U64::rand(&mut rng)),
                ];
                let literals_b = vec![Literal::Scalar(console::types::Scalar::rand(&mut rng))];
                for literal_a in &literals_a {
                    for literal_b in &literals_b {
                        for mode_a in &modes_a {
                            for mode_b in &modes_b {
                                for destination_type in valid_destination_types() {
                                    check_commit(
                                        |operands, destination, destination_type| {
                                            $operation::<CurrentNetwork>::new(operands, destination, destination_type)
                                                .unwrap()
                                        },
                                        $operation::<CurrentNetwork>::opcode(),
                                        literal_a,
                                        literal_b,
                                        mode_a,
                                        mode_b,
                                        *destination_type,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        };
    }
    check_commit!(CommitPED128);
}

// Note this test must be explicitly written, instead of using the macro, because CommitPED64Raw fails on certain input types.
#[test]
fn test_commit_ped64_raw_is_consistent() {
    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    macro_rules! check_commit {
        ($operation:tt) => {
            for _ in 0..ITERATIONS {
                let literals_a = [
                    Literal::Boolean(console::types::Boolean::rand(&mut rng)),
                    Literal::I8(console::types::I8::rand(&mut rng)),
                    Literal::I16(console::types::I16::rand(&mut rng)),
                    Literal::I32(console::types::I32::rand(&mut rng)),
                    Literal::U8(console::types::U8::rand(&mut rng)),
                    Literal::U16(console::types::U16::rand(&mut rng)),
                    Literal::U32(console::types::U32::rand(&mut rng)),
                ];
                let literals_b = vec![Literal::Scalar(console::types::Scalar::rand(&mut rng))];
                for literal_a in &literals_a {
                    for literal_b in &literals_b {
                        for mode_a in &modes_a {
                            for mode_b in &modes_b {
                                for destination_type in valid_destination_types() {
                                    check_commit(
                                        |operands, destination, destination_type| {
                                            $operation::<CurrentNetwork>::new(operands, destination, destination_type)
                                                .unwrap()
                                        },
                                        $operation::<CurrentNetwork>::opcode(),
                                        literal_a,
                                        literal_b,
                                        mode_a,
                                        mode_b,
                                        *destination_type,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        };
    }
    check_commit!(CommitPED64Raw);
}

// Note this test must be explicitly written, instead of using the macro, because CommitPED128Raw fails on certain input types.
#[test]
fn test_commit_ped128_raw_is_consistent() {
    // Prepare the rng.
    let mut rng = TestRng::default();

    // Prepare the test.
    let modes_a = [circuit::Mode::Public, circuit::Mode::Private];
    let modes_b = [circuit::Mode::Public, circuit::Mode::Private];

    macro_rules! check_commit {
        ($operation:tt) => {
            for _ in 0..ITERATIONS {
                let literals_a = [
                    Literal::Boolean(console::types::Boolean::rand(&mut rng)),
                    Literal::I8(console::types::I8::rand(&mut rng)),
                    Literal::I16(console::types::I16::rand(&mut rng)),
                    Literal::I32(console::types::I32::rand(&mut rng)),
                    Literal::I64(console::types::I64::rand(&mut rng)),
                    Literal::U8(console::types::U8::rand(&mut rng)),
                    Literal::U16(console::types::U16::rand(&mut rng)),
                    Literal::U32(console::types::U32::rand(&mut rng)),
                    Literal::U64(console::types::U64::rand(&mut rng)),
                ];
                let literals_b = vec![Literal::Scalar(console::types::Scalar::rand(&mut rng))];
                for literal_a in &literals_a {
                    for literal_b in &literals_b {
                        for mode_a in &modes_a {
                            for mode_b in &modes_b {
                                for destination_type in valid_destination_types() {
                                    check_commit(
                                        |operands, destination, destination_type| {
                                            $operation::<CurrentNetwork>::new(operands, destination, destination_type)
                                                .unwrap()
                                        },
                                        $operation::<CurrentNetwork>::opcode(),
                                        literal_a,
                                        literal_b,
                                        mode_a,
                                        mode_b,
                                        *destination_type,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        };
    }
    check_commit!(CommitPED128Raw);
}
