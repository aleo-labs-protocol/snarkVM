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

use crate::Command;

mod input;
pub use input::*;

mod output;
pub use output::*;

mod bytes;
mod parse;

use console::{
    network::{error, prelude::*},
    program::{FinalizeType, Identifier, Register},
};

use indexmap::IndexSet;
use std::collections::HashMap;

/// A view function: a top-level, externally-callable, read-only block that returns typed values.
///
/// Views share the finalize command set (so they can `get`, `get.or_use`, `contains` against
/// mappings), but cannot mutate state, schedule futures, or call other functions.
#[derive(Clone, PartialEq, Eq)]
pub struct ViewCore<N: Network> {
    /// The name of the view function.
    name: Identifier<N>,
    /// The input statements, added in order of the input registers.
    inputs: IndexSet<Input<N>>,
    /// The commands, in order of execution.
    commands: Vec<Command<N>>,
    /// The output statements, in order of the desired output.
    outputs: IndexSet<Output<N>>,
    /// A mapping from `Position`s to their index in `commands`.
    positions: HashMap<Identifier<N>, usize>,
}

impl<N: Network> ViewCore<N> {
    /// Initializes a new view function with the given name.
    pub fn new(name: Identifier<N>) -> Self {
        Self {
            name,
            inputs: IndexSet::new(),
            commands: Vec::new(),
            outputs: IndexSet::new(),
            positions: HashMap::new(),
        }
    }

    /// Returns the name of the view function.
    pub const fn name(&self) -> &Identifier<N> {
        &self.name
    }

    /// Returns the checksum of the view.
    ///
    /// The checksum is a 32-byte hash of the view's source code in string format.
    /// This ensures a strict definition of view equivalence, useful for program upgradability.
    pub fn to_checksum(&self) -> [console::types::U8<N>; 32] {
        crate::to_checksum::source_code_checksum(&self.to_string())
    }

    /// Returns the view inputs.
    pub const fn inputs(&self) -> &IndexSet<Input<N>> {
        &self.inputs
    }

    /// Returns the view input types.
    pub fn input_types(&self) -> Vec<FinalizeType<N>> {
        self.inputs.iter().map(|input| input.finalize_type()).cloned().collect()
    }

    /// Returns the view commands.
    pub fn commands(&self) -> &[Command<N>] {
        &self.commands
    }

    /// Returns the view outputs.
    pub const fn outputs(&self) -> &IndexSet<Output<N>> {
        &self.outputs
    }

    /// Returns the view output types.
    pub fn output_types(&self) -> Vec<FinalizeType<N>> {
        self.outputs.iter().map(|output| output.finalize_type()).cloned().collect()
    }

    /// Returns the mapping of `Position`s to their index in `commands`.
    pub const fn positions(&self) -> &HashMap<Identifier<N>, usize> {
        &self.positions
    }

    /// Returns `true` if the view contains an array type with a size that exceeds the given maximum.
    /// Mirrors `Finalize::exceeds_max_array_size` and additionally walks `outputs`, since views
    /// declare typed outputs.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        self.inputs.iter().any(|input| {
            matches!(input.finalize_type(), FinalizeType::Plaintext(p) if p.exceeds_max_array_size(max_array_size))
        }) || self.commands.iter().any(|command| command.exceeds_max_array_size(max_array_size))
            || self.outputs.iter().any(|output| {
                matches!(output.finalize_type(), FinalizeType::Plaintext(p) if p.exceeds_max_array_size(max_array_size))
            })
    }

    /// Returns `true` if the view refers to an external struct in its inputs, body, or outputs.
    pub fn contains_external_struct(&self) -> bool {
        self.inputs
            .iter()
            .any(|input| matches!(input.finalize_type(), FinalizeType::Plaintext(p) if p.contains_external_struct()))
            || self
                .commands
                .iter()
                .any(|command| matches!(command, Command::Instruction(inst) if inst.contains_external_struct()))
            || self.outputs.iter().any(
                |output| matches!(output.finalize_type(), FinalizeType::Plaintext(p) if p.contains_external_struct()),
            )
    }

    /// Returns `true` if the view contains a string type. Mirrors `Finalize::contains_string_type`
    /// and additionally walks `outputs`.
    pub fn contains_string_type(&self) -> bool {
        self.inputs
            .iter()
            .any(|input| matches!(input.finalize_type(), FinalizeType::Plaintext(p) if p.contains_string_type()))
            || self.commands.iter().any(|command| command.contains_string_type())
            || self
                .outputs
                .iter()
                .any(|output| matches!(output.finalize_type(), FinalizeType::Plaintext(p) if p.contains_string_type()))
    }
}

impl<N: Network> ViewCore<N> {
    /// Adds the input statement to the view.
    #[inline]
    fn add_input(&mut self, input: Input<N>) -> Result<()> {
        // Ensure there are no commands or outputs in memory.
        ensure!(self.commands.is_empty(), "Cannot add inputs after commands have been added");
        ensure!(self.outputs.is_empty(), "Cannot add inputs after outputs have been added");

        // Ensure the maximum number of inputs has not been exceeded.
        ensure!(self.inputs.len() < N::MAX_INPUTS, "Cannot add more than {} inputs", N::MAX_INPUTS);
        // Ensure the input statement was not previously added.
        ensure!(!self.inputs.contains(&input), "Cannot add duplicate input statement");

        // Views are externally-callable; futures and dynamic futures are not meaningful here.
        ensure!(
            matches!(input.finalize_type(), FinalizeType::Plaintext(..)),
            "View inputs must be plaintext (futures are forbidden)"
        );

        // Ensure the input register is a locator.
        ensure!(matches!(input.register(), Register::Locator(..)), "Input register must be a locator");

        self.inputs.insert(input);
        Ok(())
    }

    /// Adds the given command to the view.
    #[inline]
    pub fn add_command(&mut self, command: Command<N>) -> Result<()> {
        // Ensure there are no outputs already.
        ensure!(self.outputs.is_empty(), "Cannot add commands after outputs have been added");

        // Ensure the maximum number of commands has not been exceeded.
        ensure!(self.commands.len() < N::MAX_COMMANDS, "Cannot add more than {} commands", N::MAX_COMMANDS);

        // Reject any state-mutating or non-deterministic command.
        ensure!(!command.is_write(), "Forbidden operation: view functions cannot use 'set' or 'remove'");
        ensure!(!command.is_async(), "Forbidden operation: view functions cannot invoke an 'async' instruction");
        ensure!(!command.is_await(), "Forbidden operation: view functions cannot 'await' a future");
        ensure!(!command.is_call(), "Forbidden operation: view functions cannot 'call' another function");
        ensure!(!command.is_instruction_for_record(), "Forbidden operation: view functions cannot operate on records");
        // `rand.chacha` is only meaningful with finalize global state.
        ensure!(!command.is_rand_chacha(), "Forbidden operation: view functions cannot use 'rand.chacha'");

        // Check the destination registers.
        for register in command.destinations() {
            ensure!(matches!(register, Register::Locator(..)), "Destination register must be a locator");
        }

        // Branch target validation.
        if let Some(position) = command.branch_to() {
            ensure!(!self.positions.contains_key(position), "Cannot branch to an earlier position '{position}'");
        }

        if let Some(position) = command.position() {
            ensure!(!self.positions.contains_key(position), "Cannot redefine position '{position}'");
            ensure!(self.positions.len() < N::MAX_POSITIONS, "Cannot add more than {} positions", N::MAX_POSITIONS);
            self.positions.insert(*position, self.commands.len());
        }

        self.commands.push(command);
        Ok(())
    }

    /// Adds the output statement to the view.
    #[inline]
    fn add_output(&mut self, output: Output<N>) -> Result<()> {
        // Ensure the maximum number of outputs has not been exceeded.
        ensure!(self.outputs.len() < N::MAX_OUTPUTS, "Cannot add more than {} outputs", N::MAX_OUTPUTS);

        // Views return plaintext only.
        ensure!(
            matches!(output.finalize_type(), FinalizeType::Plaintext(..)),
            "View outputs must be plaintext (futures are forbidden)"
        );

        self.outputs.insert(output);
        Ok(())
    }
}

impl<N: Network> TypeName for ViewCore<N> {
    #[inline]
    fn type_name() -> &'static str {
        "view"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_add_input() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let input = Input::<CurrentNetwork>::from_str("input r0 as field.public;").unwrap();
        assert!(view.add_input(input.clone()).is_ok());
        assert!(view.add_input(input).is_err());
    }

    #[test]
    fn test_reject_set_command() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("set 1u64 into balances[0u64];").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("'set' or 'remove'"));
    }

    #[test]
    fn test_reject_remove_command() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("remove balances[0u64];").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("'set' or 'remove'"));
    }

    #[test]
    fn test_reject_rand_chacha() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("rand.chacha into r0 as u64;").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("rand.chacha"));
    }

    #[test]
    fn test_reject_await_command() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("await r0;").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("'await'"));
    }

    #[test]
    fn test_reject_call_instruction() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("call foo r0 into r1;").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("'call'"));
    }

    #[test]
    fn test_reject_cast_to_record() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd =
            Command::<CurrentNetwork>::from_str("cast r0.owner r0.token_amount into r1 as token.record;").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("operate on records"));
    }

    #[test]
    fn test_reject_cast_to_dynamic_record() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("cast r0 into r1 as dynamic.record;").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("operate on records"));
    }

    #[test]
    fn test_reject_get_record_dynamic() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("get.record.dynamic r0.x into r1 as bool;").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("operate on records"));
    }

    #[test]
    fn test_reject_async_instruction() {
        let name = Identifier::from_str("view_core_test").unwrap();
        let mut view = ViewCore::<CurrentNetwork>::new(name);

        let cmd = Command::<CurrentNetwork>::from_str("async foo r0 r1 into r3;").unwrap();
        let err = view.add_command(cmd).unwrap_err();
        assert!(err.to_string().contains("'async'"));
    }
}
