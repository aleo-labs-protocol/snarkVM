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

mod destination;
pub use destination::*;

mod instruction_set;
pub use instruction_set::*;

mod instruction_type;
pub use instruction_type::*;

mod operand;
pub use operand::*;

mod register;
pub use register::*;

mod register_table;
pub use register_table::*;

use console::{
    network::Network,
    prelude::{FromBytes, ToBytes},
    program::LiteralType,
};
use snarkvm_synthesizer_program::Instruction;
use snarkvm_utilities::choose_weighted_legacy;

use anyhow::Result;
use indexmap::IndexSet;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::{collections::HashMap, str::FromStr};

/// The number of instructions to sample.
const NUM_INSTRUCTIONS: usize = 100;
/// Instruction count of the longest sequence.
const NUM_SEQUENCE_INSTRUCTIONS: usize = 4;

/// Samples instructions for the given epoch.
pub(crate) fn sample_instructions<N: Network>(
    epoch_hash: N::BlockHash,
    register_table: &mut RegisterTable,
) -> Result<IndexSet<Instruction<N>>> {
    // Initialize the RNG from the lower 64 bits of the epoch hash.
    let lower = u64::from_bytes_le(&epoch_hash.to_bytes_le()?[0..8])?;
    let mut rng = ChaChaRng::seed_from_u64(lower);

    // Initialize storage for the instructions.
    let mut instructions = IndexSet::with_capacity(NUM_INSTRUCTIONS);

    // Initialize the instruction set weights.
    let instruction_set_weights = instruction_set::<N>();

    // Initialize a counter for opcodes in the program.
    let mut opcode_count = 0;

    'outer: for _ in 0..NUM_INSTRUCTIONS {
        // Ensure that we do not exceed the instruction count limit in the middle of a sequence.
        if opcode_count > NUM_INSTRUCTIONS.saturating_sub(NUM_SEQUENCE_INSTRUCTIONS) {
            break;
        }

        // Initialize the instruction and selected literals.
        let sequence = choose_weighted_legacy(&instruction_set_weights, |(_, weight)| *weight, &mut rng).0.clone();

        // Initialize a cache for the ephemeral registers.
        // This is a mapping from the locator to the one assigned to it in the instruction sequence.
        let mut cache_ephemeral = HashMap::<u16, PuzzleRegister>::new();

        // Initialize the constructed sequence.
        let mut constructed_sequence = Vec::with_capacity(sequence.len());

        for (instruction_type, instruction_operands, instruction_destinations) in sequence {
            // Retrieve the number of operands required by the instruction type.
            let num_operands = instruction_type.num_operands();

            // Check if the number of operands is correct.
            if num_operands != instruction_operands.len() {
                match cfg!(debug_assertions) {
                    true => panic!("Invalid number of operands for {instruction_type}"),
                    false => eprintln!("Invalid number of operands for {instruction_type}"),
                }
                // Move to the next instruction type.
                continue 'outer;
            }

            // Check that the instruction is not a `branch`.
            if matches!(instruction_type, PuzzleInstructionType::BranchEq | PuzzleInstructionType::BranchNeq) {
                match cfg!(debug_assertions) {
                    true => panic!("Branch instructions are not allowed."),
                    false => eprintln!("Branch instructions are not allowed."),
                }
                // Move to the next instruction type.
                continue 'outer;
            }

            // Initialize the operands.
            let mut operands = Vec::new();

            // Initialize a cache for the literal types.
            let mut cache_types = HashMap::<LiteralType, usize>::new();

            // Construct the corresponding operand for each literal.
            for operand in &instruction_operands {
                match operand {
                    // If the operand is a literal, use the it directly.
                    PuzzleOperand::Literal(literal) => operands.push(literal.to_string()),
                    // If the operand is an ephemeral register, use the one defined in the instruction sequence.
                    PuzzleOperand::Ephemeral(_, index) => {
                        // Retrieve the ephemeral register.
                        let Some(locator) = cache_ephemeral.get(index) else {
                            match cfg!(debug_assertions) {
                                true => panic!("Ephemeral cache does not contain a register for index {index}"),
                                false => eprintln!("Ephemeral cache does not contain a register for index {index}"),
                            }
                            // Move to the next instruction type.
                            continue 'outer;
                        };
                        // Insert the operand into the operands.
                        operands.push(locator.to_string());
                    }
                    // If the operand is an input register, select the appropriate one from the register table.
                    PuzzleOperand::Input(literal_type, index) => {
                        // Retrieve the input register.
                        let Some(register) = register_table.get_input_at_index(literal_type, *index as usize) else {
                            match cfg!(debug_assertions) {
                                true => panic!("Register table does not contain input {literal_type} at index {index}"),
                                false => {
                                    eprintln!("Register table does not contain input {literal_type} at index {index}")
                                }
                            }
                            // Move to the next instruction type.
                            continue 'outer;
                        };

                        // Insert the operand into the operands.
                        operands.push(register.to_string());
                    }
                    // If the operand is a register, select one from the register table.
                    PuzzleOperand::Register(literal_type) => {
                        // Check if the register table contains the literal type.
                        if !register_table.contains_key(literal_type) {
                            match cfg!(debug_assertions) {
                                true => panic!("Register table does not contain {literal_type}"),
                                false => eprintln!("Register table does not contain {literal_type}"),
                            }
                            // Move to the next instruction type.
                            continue 'outer;
                        }

                        // Retrieve the offset, incrementing if it exists, and otherwise initializing to zero.
                        let offset = *cache_types.entry(*literal_type).and_modify(|offset| *offset += 1).or_insert(0);

                        // Retrieve the registers for the literal type.
                        let Ok(register) = register_table.get_k_th_last_register(literal_type, offset) else {
                            match cfg!(debug_assertions) {
                                true => panic!("Failed to retrieve registers for {literal_type} at offset {offset}"),
                                false => {
                                    eprintln!("Failed to retrieve registers for {literal_type} at offset {offset}")
                                }
                            }
                            // Move to the next instruction type.
                            continue 'outer;
                        };

                        // Insert the operand into the operands.
                        operands.push(register.to_string());
                    }
                    // If the operand is a register, with an explicit offset, get the appropriate register from the table.
                    PuzzleOperand::RegisterOffset(literal_type, offset) => {
                        // Check if the register table contains the literal type.
                        if !register_table.contains_key(literal_type) {
                            match cfg!(debug_assertions) {
                                true => panic!("Register table does not contain {literal_type}"),
                                false => eprintln!("Register table does not contain {literal_type}"),
                            }
                            // Move to the next instruction type.
                            continue 'outer;
                        }

                        // Retrieve the k-th last register for the literal type.
                        let Ok(register) = register_table.get_k_th_last_register(literal_type, *offset as usize) else {
                            match cfg!(debug_assertions) {
                                true => panic!("Failed to retrieve register for {literal_type} at offset {offset}"),
                                false => eprintln!("Failed to retrieve register for {literal_type} at offset {offset}"),
                            }
                            // Move to the next instruction type.
                            continue 'outer;
                        };

                        // Insert the operand into the operands.
                        operands.push(register.to_string());
                    }
                }
            }

            // Initialize the destinations.
            let mut destinations = IndexSet::new();

            for destination in &instruction_destinations {
                // Get the next register locator.
                let locator = match register_table.get_next_locator() {
                    Ok(register_locator) => register_locator,
                    Err(e) => {
                        match cfg!(debug_assertions) {
                            true => panic!("Failed to retrieve next register locator - {e}"),
                            false => eprintln!("Failed to retrieve next register locator - {e}"),
                        }
                        // Move to the next instruction type.
                        continue 'outer;
                    }
                };
                // Initialize the destination register.
                let register = PuzzleRegister::new_locator(locator);

                match destination {
                    // If the destination is an ephemeral register, insert it into the cache.
                    PuzzleDestination::Ephemeral(_, index) => {
                        cache_ephemeral.insert(*index, register);
                    }
                    // If the destination is a register, insert it into the register table.
                    PuzzleDestination::Register(literal_type) => {
                        if let Err(e) = register_table.insert(*literal_type, register) {
                            match cfg!(debug_assertions) {
                                true => panic!("Failed to insert register into register table - {e}"),
                                false => eprintln!("Failed to insert register into register table - {e}"),
                            }
                            // Move to the next instruction type.
                            continue 'outer;
                        }
                    }
                }
                destinations.insert(register);
            }

            // Construct the instruction string.
            let mut instruction_string = instruction_type.opcode().to_string();
            instruction_string.push(' ');
            instruction_string.push_str(&operands.join(" "));
            instruction_string.push_str(" into ");
            instruction_string.push_str(
                &destinations.iter().map(|destination| format!("{destination}")).collect::<Vec<_>>().join(" "),
            );
            // If the instruction is a cast, commit or hash, append the target type.
            if matches!(
                instruction_type,
                PuzzleInstructionType::Cast
                    | PuzzleInstructionType::CastLossy
                    | PuzzleInstructionType::CommitBhp256
                    | PuzzleInstructionType::CommitBhp512
                    | PuzzleInstructionType::CommitBhp768
                    | PuzzleInstructionType::CommitBhp1024
                    | PuzzleInstructionType::CommitPed64
                    | PuzzleInstructionType::CommitPed128
                    | PuzzleInstructionType::HashBhp256
                    | PuzzleInstructionType::HashBhp512
                    | PuzzleInstructionType::HashBhp768
                    | PuzzleInstructionType::HashBhp1024
                    | PuzzleInstructionType::HashKeccak256
                    | PuzzleInstructionType::HashKeccak384
                    | PuzzleInstructionType::HashKeccak512
                    | PuzzleInstructionType::HashPed64
                    | PuzzleInstructionType::HashPed128
                    | PuzzleInstructionType::HashPsd2
                    | PuzzleInstructionType::HashPsd4
                    | PuzzleInstructionType::HashPsd8
                    | PuzzleInstructionType::HashSha3256
                    | PuzzleInstructionType::HashSha3384
                    | PuzzleInstructionType::HashSha3512
            ) {
                // Check that there is at least one destination.
                if instruction_destinations.is_empty() {
                    match cfg!(debug_assertions) {
                        true => panic!("No destination for the `cast`, `commit`, or `hash` instruction"),
                        false => eprintln!("No destination for the `cast`, `commit`, or `hash` instruction"),
                    }
                    // Move to the next instruction type.
                    continue 'outer;
                }
                // Check the the first destination is a register.
                match instruction_destinations[0] {
                    PuzzleDestination::Ephemeral(literal_type, _) | PuzzleDestination::Register(literal_type) => {
                        instruction_string.push_str(&format!(" as {literal_type}"));
                    }
                }
            }
            instruction_string.push(';');

            // Attempt to parse the instruction.
            let Ok(instruction) = Instruction::<N>::from_str(&instruction_string) else {
                match cfg!(debug_assertions) {
                    true => panic!("Failed to parse instruction: {instruction_string}"),
                    false => eprintln!("Failed to parse instruction: {instruction_string}"),
                }
                // Move to the next instruction type.
                continue 'outer;
            };

            // Check that the instruction is not already contained in the instructions.
            if instructions.contains(&instruction) {
                match cfg!(debug_assertions) {
                    true => panic!("Duplicate instruction: {instruction_string}"),
                    false => eprintln!("Duplicate instruction: {instruction_string}"),
                }
                // Move to the next instruction type.
                continue 'outer;
            }

            // Add the instruction to the constructed sequence.
            constructed_sequence.push(instruction);
        }
        // Add the constructed sequence to the instructions.
        // This is done to ensure that partial sequences are not added to the instructions.
        // Note that we already check that the instructions are unique.
        for instruction in constructed_sequence {
            instructions.insert(instruction);
            opcode_count += 1;
        }
    }

    Ok(instructions)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::synthesis::helpers::register_table::tests::{NUM_INPUTS, NUM_PREAMBLE_INSTRUCTIONS};

    use console::{prelude::TestRng, program::Identifier};
    use snarkvm_synthesizer_program::Program;

    use rand::RngExt;

    type CurrentNetwork = console::network::MainnetV0;

    const ITERATIONS: u64 = 25;

    #[test]
    fn test_sample_instructions() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample the epoch hash.
            let epoch_hash = rng.random();

            // Initialize the register table.
            let mut register_table = RegisterTable::new();
            // Sample the instructions.
            let instructions = sample_instructions::<CurrentNetwork>(epoch_hash, &mut register_table).unwrap();

            // Define the minimum instruction length.
            let min = NUM_INSTRUCTIONS.saturating_sub(NUM_SEQUENCE_INSTRUCTIONS);
            // Define the maximum instruction length.
            let max = NUM_INSTRUCTIONS;

            // Check that the number of instructions is within the expected range.
            assert!(
                (min..=max).contains(&instructions.len()),
                "Expected {} instructions to be in the range {min}..={max}",
                instructions.len()
            );
        }
    }

    #[test]
    fn test_sample_program() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample the epoch hash.
            let epoch_hash = rng.random();

            // Initialize the register table.
            let mut register_table = RegisterTable::new();
            // Sample the instructions.
            let instructions = sample_instructions::<CurrentNetwork>(epoch_hash, &mut register_table).unwrap();

            // Construct the program inputs, as a string.
            let input_string = register_table.input_block().to_string();

            // Construct the program instructions, as a string.
            let mut instruction_string = String::new();
            for instruction in instructions.iter() {
                instruction_string.push_str(&format!("    {instruction}\n"));
            }

            // Construct the program string.
            let program_string = format!(r"program puzzle.aleo;function synthesize:{input_string}{instruction_string}");

            // Construct the program.
            let program = Program::<CurrentNetwork>::from_str(&program_string).unwrap();

            // Get the function.
            let function = program.get_function_ref(&Identifier::from_str("synthesize").unwrap()).unwrap();

            // Check that the number of inputs is correct.
            assert_eq!(function.inputs().len(), NUM_INPUTS, "Update me if the design is changed.");

            // Check that the number of instructions is within the expected range.
            let min = NUM_PREAMBLE_INSTRUCTIONS + NUM_INSTRUCTIONS.saturating_sub(NUM_SEQUENCE_INSTRUCTIONS);
            let max = NUM_PREAMBLE_INSTRUCTIONS + NUM_INSTRUCTIONS;
            assert!(
                (min..=max).contains(&function.instructions().len()),
                "Expected {} instructions to be in the range {min}..={max}",
                function.instructions().len()
            );
        }
    }

    #[test]
    fn test_sample_instructions_is_deterministic() {
        for seed in 0..ITERATIONS {
            let mut rng = TestRng::fixed(seed);

            // Sample the epoch hash.
            let epoch_hash = rng.random();

            // Initialize the register table.
            let mut register_table = RegisterTable::new();
            // Sample the instructions.
            let instructions_1 = sample_instructions::<CurrentNetwork>(epoch_hash, &mut register_table).unwrap();

            for _ in 0..ITERATIONS {
                // Initialize the register table.
                let mut register_table = RegisterTable::new();
                // Sample the instructions.
                let instructions_2 = sample_instructions::<CurrentNetwork>(epoch_hash, &mut register_table).unwrap();

                // Check that the instructions are the same.
                assert_eq!(instructions_1, instructions_2);
            }
        }
    }
}
