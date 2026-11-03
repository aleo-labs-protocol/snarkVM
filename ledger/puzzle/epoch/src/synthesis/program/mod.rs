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

mod construct_inputs;
mod to_leaves;
mod to_r1cs;

use crate::synthesis::helpers::*;
use circuit::{Mode, environment::R1CS};
use console::{
    account::PrivateKey,
    network::Network,
    prelude::{Itertools, ToBits as TBits, Uniform, Zero},
    program::{Field, Identifier, Literal, LiteralType, Value},
};
use snarkvm_synthesizer_process::{CallStack, Process, Registers, Stack};
use snarkvm_synthesizer_program::{Instruction, Program, RegistersCircuit as _, StackTrait};

use aleo_std::prelude::{finish, lap, timer};
use anyhow::{Result, anyhow, bail, ensure};
use rand::RngExt;
use rand_chacha::ChaChaRng;
use std::{
    fmt::{self, Debug, Formatter},
    ops::Deref,
    str::FromStr,
};

/// The arity of the Merkle tree.
const ARITY: u8 = 8;

#[derive(Clone)]
pub struct EpochProgram<N: Network> {
    /// The program stack for the epoch.
    stack: Stack<N>,
    /// The register table.
    register_table: RegisterTable,
    /// The epoch hash.
    epoch_hash: N::BlockHash,
}

impl<N: Network> Debug for EpochProgram<N> {
    /// Formats the epoch program for debugging.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochProgram")
            .field("epoch_hash", &self.epoch_hash)
            .field("program", self.stack.program())
            .finish()
    }
}

impl<N: Network> PartialEq for EpochProgram<N> {
    /// Returns `true` if the epoch programs are equal.
    fn eq(&self, other: &Self) -> bool {
        self.epoch_hash == other.epoch_hash && self.stack.program() == other.stack.program()
    }
}

impl<N: Network> Eq for EpochProgram<N> {}

impl<N: Network> EpochProgram<N> {
    /// Initializes a new epoch program, given an epoch.
    ///
    /// This method deterministically synthesizes a new program.
    pub fn new(epoch_hash: N::BlockHash) -> Result<Self> {
        // Initialize the register table.
        let mut register_table = RegisterTable::new();

        // Construct the program inputs, as a string.
        let input_string = register_table.input_block().to_string();

        // Sample the instructions from the given epoch.
        let instructions = sample_instructions::<N>(epoch_hash, &mut register_table)?;
        debug_assert!(!instructions.is_empty());
        // Construct the program instructions, as a string.
        let mut instruction_string = String::new();
        for instruction in &instructions {
            instruction_string.push_str(&format!("    {instruction}\n"));
        }

        // Construct the program string.
        let program_string = format!(
            r"program puzzle.aleo;

function synthesize:
{input_string}
{instruction_string}
"
        );

        // Construct the program.
        let program = Program::from_str(&program_string)?;

        // Initialize a new process.
        let process = Process::<N>::load()?;
        // Initialize the stack with the synthesis challenge program.
        let stack = Stack::new(&process, &program)?;

        Ok(Self { stack, register_table, epoch_hash })
    }
}

impl<N: Network> EpochProgram<N> {
    /// Returns the program stack.
    #[inline]
    pub const fn stack(&self) -> &Stack<N> {
        &self.stack
    }

    /// Returns the register table.
    #[inline]
    pub const fn register_table(&self) -> &RegisterTable {
        &self.register_table
    }

    /// Returns the epoch.
    #[inline]
    pub const fn epoch_hash(&self) -> N::BlockHash {
        self.epoch_hash
    }

    /// Returns the instructions for the program.
    #[inline]
    pub fn instructions(&self) -> Result<&[Instruction<N>]> {
        Ok(self.stack.program().get_function_ref(&Identifier::from_str("synthesize")?)?.instructions())
    }
}

impl<N: Network> Deref for EpochProgram<N> {
    type Target = Program<N>;

    fn deref(&self) -> &Self::Target {
        self.stack.program()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::prelude::TestRng;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_new_is_deterministic() {
        let mut rng = TestRng::default();

        // Initialize a random epoch hash.
        let epoch_hash = rng.random();
        // Initialize a new epoch program.
        let epoch_program_0 = EpochProgram::<CurrentNetwork>::new(epoch_hash).unwrap();
        // Initialize a new epoch program.
        let epoch_program_1 = EpochProgram::<CurrentNetwork>::new(epoch_hash).unwrap();
        // Ensure the epoch program matches.
        assert_eq!(epoch_program_0, epoch_program_1);
    }

    #[test]
    fn test_instructions_succeeds() {
        let mut rng = TestRng::default();

        // Initialize a random epoch hash.
        let epoch_hash = rng.random();
        // Initialize a new epoch program.
        let epoch_program = EpochProgram::<CurrentNetwork>::new(epoch_hash).unwrap();
        // Retrieve the instructions.
        let instructions = epoch_program.instructions().unwrap();
        // Ensure the instructions are not empty.
        assert!(!instructions.is_empty());
    }
}
