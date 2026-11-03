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

mod bytes;
mod parse;

use crate::Command;

use console::{
    network::prelude::*,
    program::{Identifier, Register},
};

use std::collections::HashMap;

#[derive(Clone, PartialEq, Eq)]
pub struct ConstructorCore<N: Network> {
    /// The commands, in order of execution.
    commands: Vec<Command<N>>,
    /// The number of write commands.
    num_writes: u16,
    /// A mapping from `Position`s to their index in `commands`.
    positions: HashMap<Identifier<N>, usize>,
}

impl<N: Network> ConstructorCore<N> {
    /// Returns the constructor commands.
    pub fn commands(&self) -> &[Command<N>] {
        &self.commands
    }

    /// Returns the number of write commands.
    pub const fn num_writes(&self) -> u16 {
        self.num_writes
    }

    /// Returns the mapping of `Position`s to their index in `commands`.
    pub const fn positions(&self) -> &HashMap<Identifier<N>, usize> {
        &self.positions
    }

    /// Returns whether this constructor refers to an external struct.
    pub fn contains_external_struct(&self) -> bool {
        self.commands.iter().any(|command| command.contains_external_struct())
    }

    /// Returns `true` if the constructor commands contain a string type.
    pub fn contains_string_type(&self) -> bool {
        self.commands.iter().any(|command| command.contains_string_type())
    }

    /// Returns `true` if the constructor contains an identifier type in its cast types.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        for command in &self.commands {
            if command.contains_identifier_type()? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns `true` if the constructor contains an array type with a size that exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        self.commands.iter().any(|command| command.exceeds_max_array_size(max_array_size))
    }
}

impl<N: Network> ConstructorCore<N> {
    /// Adds the given command to constructor.
    ///
    /// # Errors
    /// This method will halt if the maximum number of commands has been reached.
    #[inline]
    pub fn add_command(&mut self, command: Command<N>) -> Result<()> {
        // Ensure the maximum number of commands has not been exceeded.
        ensure!(self.commands.len() < N::MAX_COMMANDS, "Cannot add more than {} commands", N::MAX_COMMANDS);
        // Ensure the number of write commands has not been exceeded.
        if command.is_write() {
            ensure!(
                self.num_writes < N::LATEST_MAX_WRITES(),
                "Cannot add more than {} 'set' & 'remove' commands",
                N::LATEST_MAX_WRITES()
            );
        }

        // Ensure the command is not an async instruction.
        ensure!(!command.is_async(), "Forbidden operation: Constructor cannot invoke an 'async' instruction");
        // Ensure the command is not a call instruction.
        ensure!(!command.is_call(), "Forbidden operation: Constructor cannot invoke a 'call'");
        // Ensure the command does not operate on a record (cast-to-record or `get.record.dynamic`).
        ensure!(!command.is_instruction_for_record(), "Forbidden operation: Constructor cannot operate on records");
        // Ensure the command is not an await command.
        ensure!(!command.is_await(), "Forbidden operation: Constructor cannot 'await'");

        // Check the destination registers.
        for register in command.destinations() {
            // Ensure the destination register is a locator.
            ensure!(matches!(register, Register::Locator(..)), "Destination register must be a locator");
        }

        // Check if the command is a branch command.
        if let Some(position) = command.branch_to() {
            // Ensure the branch target does not reference an earlier position.
            ensure!(!self.positions.contains_key(position), "Cannot branch to an earlier position '{position}'");
        }

        // Check if the command is a position command.
        if let Some(position) = command.position() {
            // Ensure the position is not yet defined.
            ensure!(!self.positions.contains_key(position), "Cannot redefine position '{position}'");
            // Ensure that there are less than `u8::MAX` positions.
            ensure!(self.positions.len() < N::MAX_POSITIONS, "Cannot add more than {} positions", N::MAX_POSITIONS);
            // Insert the position.
            self.positions.insert(*position, self.commands.len());
        }

        // Check if the command is a write command.
        if command.is_write() {
            // Increment the number of write commands.
            self.num_writes += 1;
        }

        // Insert the command.
        self.commands.push(command);
        Ok(())
    }
}

impl<N: Network> TypeName for ConstructorCore<N> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "constructor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Command, Constructor};

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_add_command() {
        // Initialize a new constructor instance.
        let mut constructor = Constructor::<CurrentNetwork> {
            commands: Default::default(),
            num_writes: 0,
            positions: Default::default(),
        };

        // Ensure that a command can be added.
        let command = Command::<CurrentNetwork>::from_str("add r0 r1 into r2;").unwrap();
        assert!(constructor.add_command(command).is_ok());

        // Ensure that adding more than the maximum number of commands will fail.
        for i in 3..CurrentNetwork::MAX_COMMANDS * 2 {
            let command = Command::<CurrentNetwork>::from_str(&format!("add r0 r1 into r{i};")).unwrap();

            match constructor.commands.len() < CurrentNetwork::MAX_COMMANDS {
                true => assert!(constructor.add_command(command).is_ok()),
                false => assert!(constructor.add_command(command).is_err()),
            }
        }

        // Ensure that adding more than the maximum number of writes will fail.

        // Initialize a new constructor instance.
        let mut constructor = Constructor::<CurrentNetwork> {
            commands: Default::default(),
            num_writes: 0,
            positions: Default::default(),
        };

        for _ in 0..CurrentNetwork::LATEST_MAX_WRITES() * 2 {
            let command = Command::<CurrentNetwork>::from_str("remove object[r0];").unwrap();

            match constructor.commands.len() < CurrentNetwork::LATEST_MAX_WRITES() as usize {
                true => assert!(constructor.add_command(command).is_ok()),
                false => assert!(constructor.add_command(command).is_err()),
            }
        }
    }

    #[test]
    fn test_add_command_duplicate_positions() {
        // Initialize a new constructor instance.
        let mut constructor =
            Constructor { commands: Default::default(), num_writes: 0, positions: Default::default() };

        // Ensure that a command can be added.
        let command = Command::<CurrentNetwork>::from_str("position start;").unwrap();
        assert!(constructor.add_command(command.clone()).is_ok());

        // Ensure that adding a duplicate position will fail.
        assert!(constructor.add_command(command).is_err());

        // Helper method to convert a number to a unique string.
        #[allow(clippy::cast_possible_truncation)]
        fn to_unique_string(mut n: usize) -> String {
            let mut s = String::new();
            while n > 0 {
                s.push((b'A' + (n % 26) as u8) as char);
                n /= 26;
            }
            s.chars().rev().collect::<String>()
        }

        // Ensure that adding more than the maximum number of positions will fail.
        for i in 1..u8::MAX as usize * 2 {
            let position = to_unique_string(i);
            println!("position: {position}");
            let command = Command::<CurrentNetwork>::from_str(&format!("position {position};")).unwrap();

            match constructor.commands.len() < u8::MAX as usize {
                true => assert!(constructor.add_command(command).is_ok()),
                false => assert!(constructor.add_command(command).is_err()),
            }
        }
    }
}
