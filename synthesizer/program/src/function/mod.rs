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

mod input;
use input::*;

mod output;
use output::*;

mod bytes;
mod parse;

use crate::{Instruction, finalize::FinalizeCore};
use console::{
    network::prelude::*,
    program::{Identifier, Register, ValueType},
    types::U8,
};

use indexmap::IndexSet;

#[derive(Clone, PartialEq, Eq)]
pub struct FunctionCore<N: Network> {
    /// The name of the function.
    name: Identifier<N>,
    /// The input statements, added in order of the input registers.
    /// Input assignments are ensured to match the ordering of the input statements.
    inputs: IndexSet<Input<N>>,
    /// The instructions, in order of execution.
    instructions: Vec<Instruction<N>>,
    /// The output statements, in order of the desired output.
    outputs: IndexSet<Output<N>>,
    /// The optional finalize logic.
    finalize_logic: Option<FinalizeCore<N>>,
}

impl<N: Network> FunctionCore<N> {
    /// Initializes a new function with the given name.
    pub fn new(name: Identifier<N>) -> Self {
        Self { name, inputs: IndexSet::new(), instructions: Vec::new(), outputs: IndexSet::new(), finalize_logic: None }
    }

    /// Returns the name of the function.
    pub const fn name(&self) -> &Identifier<N> {
        &self.name
    }

    /// Returns the function inputs.
    pub const fn inputs(&self) -> &IndexSet<Input<N>> {
        &self.inputs
    }

    /// Returns the function input types.
    pub fn input_types(&self) -> Vec<ValueType<N>> {
        self.inputs.iter().map(|input| input.value_type()).cloned().collect()
    }

    /// Returns the function instructions.
    pub fn instructions(&self) -> &[Instruction<N>] {
        &self.instructions
    }

    /// Returns the function outputs.
    pub const fn outputs(&self) -> &IndexSet<Output<N>> {
        &self.outputs
    }

    /// Returns the function output types.
    pub fn output_types(&self) -> Vec<ValueType<N>> {
        self.outputs.iter().map(|output| output.value_type()).cloned().collect()
    }

    /// Returns the function finalize logic.
    pub const fn finalize_logic(&self) -> Option<&FinalizeCore<N>> {
        self.finalize_logic.as_ref()
    }

    /// Returns whether this function refers to an external struct.
    pub fn contains_external_struct(&self) -> bool {
        self.inputs.iter().any(|input| input.value_type().contains_external_struct())
            || self.outputs.iter().any(|output| output.value_type().contains_external_struct())
            || self.instructions.iter().any(|instruction| instruction.contains_external_struct())
            || self.finalize_logic.iter().any(|finalize| finalize.contains_external_struct())
    }

    /// Returns `true` if the function contains a string type.
    pub fn contains_string_type(&self) -> bool {
        self.input_types().iter().any(|input| input.contains_string_type())
            || self.output_types().iter().any(|output| output.contains_string_type())
            || self.instructions.iter().any(|instruction| instruction.contains_string_type())
            || self.finalize_logic.as_ref().map(|finalize| finalize.contains_string_type()).unwrap_or(false)
    }

    /// Returns `true` if the function contains an identifier type in its inputs, outputs, instructions, or finalize logic.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        for input in self.input_types() {
            if input.contains_identifier_type()? {
                return Ok(true);
            }
        }
        for output in self.output_types() {
            if output.contains_identifier_type()? {
                return Ok(true);
            }
        }
        // Check instruction-level types (e.g., cast destination types).
        for instruction in &self.instructions {
            if instruction.contains_identifier_type()? {
                return Ok(true);
            }
        }
        if let Some(finalize) = &self.finalize_logic
            && finalize.contains_identifier_type()?
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Returns `true` if the function scope contains an array type with a size that exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        self.inputs.iter().any(|input| input.value_type().exceeds_max_array_size(max_array_size))
            || self.outputs.iter().any(|output| output.value_type().exceeds_max_array_size(max_array_size))
            || self.instructions.iter().any(|instruction| instruction.exceeds_max_array_size(max_array_size))
            || self.finalize_logic.iter().any(|finalize| finalize.exceeds_max_array_size(max_array_size))
    }
}

impl<N: Network> FunctionCore<N> {
    /// Adds the input statement to the function.
    ///
    /// # Errors
    /// This method will halt if there are instructions or output statements already.
    /// This method will halt if the maximum number of inputs has been reached.
    /// This method will halt if the input statement was previously added.
    /// This method will halt if a finalize logic has been added.
    #[inline]
    fn add_input(&mut self, input: Input<N>) -> Result<()> {
        // Ensure there are no instructions or output statements in memory.
        ensure!(self.instructions.is_empty(), "Cannot add inputs after instructions have been added");
        ensure!(self.outputs.is_empty(), "Cannot add inputs after outputs have been added");

        // Ensure the maximum number of inputs has not been exceeded.
        ensure!(self.inputs.len() < N::MAX_INPUTS, "Cannot add more than {} inputs", N::MAX_INPUTS);
        // Ensure the input statement was not previously added.
        ensure!(!self.inputs.contains(&input), "Cannot add duplicate input statement");

        // Ensure a finalize logic has not been added.
        ensure!(self.finalize_logic.is_none(), "Cannot add instructions after finalize logic has been added");

        // Ensure the input register is a locator.
        ensure!(matches!(input.register(), Register::Locator(..)), "Input register must be a locator");

        // Insert the input statement.
        self.inputs.insert(input);
        Ok(())
    }

    /// Adds the given instruction to the function.
    ///
    /// # Errors
    /// This method will halt if there are output statements already.
    /// This method will halt if the maximum number of instructions has been reached.
    /// This method will halt if a finalize logic has been added.
    #[inline]
    pub fn add_instruction(&mut self, instruction: Instruction<N>) -> Result<()> {
        // Ensure that there are no output statements in memory.
        ensure!(self.outputs.is_empty(), "Cannot add instructions after outputs have been added");

        // Ensure the maximum number of instructions has not been exceeded.
        ensure!(
            self.instructions.len() < N::MAX_INSTRUCTIONS,
            "Cannot add more than {} instructions",
            N::MAX_INSTRUCTIONS
        );

        // Ensure a finalize logic has not been added.
        ensure!(self.finalize_logic.is_none(), "Cannot add instructions after finalize logic has been added");

        // Ensure the destination register is a locator.
        for register in instruction.destinations() {
            ensure!(matches!(register, Register::Locator(..)), "Destination register must be a locator");
        }

        // Insert the instruction.
        self.instructions.push(instruction);
        Ok(())
    }

    /// Adds the output statement to the function.
    ///
    /// # Errors
    /// This method will halt if the maximum number of outputs has been reached.
    /// This method will halt if a finalize logic has been added.
    #[inline]
    fn add_output(&mut self, output: Output<N>) -> Result<()> {
        // Ensure the maximum number of outputs has not been exceeded.
        ensure!(self.outputs.len() < N::MAX_OUTPUTS, "Cannot add more than {} outputs", N::MAX_OUTPUTS);
        // Ensure the output statement was not previously added.
        ensure!(!self.outputs.contains(&output), "Cannot add duplicate output statement");

        // Ensure that the finalize logic has not been added.
        ensure!(self.finalize_logic.is_none(), "Cannot add instructions after finalize logic has been added");

        // Insert the output statement.
        self.outputs.insert(output);
        Ok(())
    }

    /// Adds the finalize scope to the function.
    ///
    /// # Errors
    /// This method will halt if a finalize scope has already been added.
    /// This method will halt if name in the finalize scope does not match the function name.
    /// This method will halt if the maximum number of finalize inputs has been reached.
    /// This method will halt if the number of finalize operands does not match the number of finalize inputs.
    #[inline]
    fn add_finalize(&mut self, finalize: FinalizeCore<N>) -> Result<()> {
        // Ensure there is no finalize scope in memory.
        ensure!(self.finalize_logic.is_none(), "Cannot add multiple finalize scopes to function '{}'", self.name);
        // Ensure the finalize scope name matches the function name.
        ensure!(*finalize.name() == self.name, "Finalize scope name must match function name '{}'", self.name);
        // Ensure the number of finalize inputs has not been exceeded.
        ensure!(finalize.inputs().len() <= N::MAX_INPUTS, "Cannot add more than {} inputs to finalize", N::MAX_INPUTS);

        // Insert the finalize scope.
        self.finalize_logic = Some(finalize);
        Ok(())
    }

    /// Returns the checksum of the function.
    ///
    /// The checksum is a 32-byte hash of the function's source code in string format.
    /// This ensures a strict definition of function equivalence, useful for program upgradability.
    pub fn to_checksum(&self) -> [U8<N>; 32] {
        crate::to_checksum::source_code_checksum(&self.to_string())
    }
}

impl<N: Network> TypeName for FunctionCore<N> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "function"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Function, Instruction};

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_add_input() {
        // Initialize a new function instance.
        let name = Identifier::from_str("function_core_test").unwrap();
        let mut function = Function::<CurrentNetwork>::new(name);

        // Ensure that an input can be added.
        let input = Input::<CurrentNetwork>::from_str("input r0 as field.private;").unwrap();
        assert!(function.add_input(input.clone()).is_ok());

        // Ensure that adding a duplicate input will fail.
        assert!(function.add_input(input).is_err());

        // Ensure that adding more than the maximum number of inputs will fail.
        for i in 1..CurrentNetwork::MAX_INPUTS * 2 {
            let input = Input::<CurrentNetwork>::from_str(&format!("input r{i} as field.private;")).unwrap();

            match function.inputs.len() < CurrentNetwork::MAX_INPUTS {
                true => assert!(function.add_input(input).is_ok()),
                false => assert!(function.add_input(input).is_err()),
            }
        }
    }

    #[test]
    fn test_add_instruction() {
        // Initialize a new function instance.
        let name = Identifier::from_str("function_core_test").unwrap();
        let mut function = Function::<CurrentNetwork>::new(name);

        // Ensure that an instruction can be added.
        let instruction = Instruction::<CurrentNetwork>::from_str("add r0 r1 into r2;").unwrap();
        assert!(function.add_instruction(instruction).is_ok());

        // Ensure that adding more than the maximum number of instructions will fail.
        for i in 3..CurrentNetwork::MAX_INSTRUCTIONS * 2 {
            let instruction = Instruction::<CurrentNetwork>::from_str(&format!("add r0 r1 into r{i};")).unwrap();

            match function.instructions.len() < CurrentNetwork::MAX_INSTRUCTIONS {
                true => assert!(function.add_instruction(instruction).is_ok()),
                false => assert!(function.add_instruction(instruction).is_err()),
            }
        }
    }

    #[test]
    fn test_add_output() {
        // Initialize a new function instance.
        let name = Identifier::from_str("function_core_test").unwrap();
        let mut function = Function::<CurrentNetwork>::new(name);

        // Ensure that an output can be added.
        let output = Output::<CurrentNetwork>::from_str("output r0 as field.private;").unwrap();
        assert!(function.add_output(output).is_ok());

        // Ensure that adding more than the maximum number of outputs will fail.
        for i in 1..CurrentNetwork::MAX_OUTPUTS * 2 {
            let output = Output::<CurrentNetwork>::from_str(&format!("output r{i} as field.private;")).unwrap();

            match function.outputs.len() < CurrentNetwork::MAX_OUTPUTS {
                true => assert!(function.add_output(output).is_ok()),
                false => assert!(function.add_output(output).is_err()),
            }
        }
    }
}
