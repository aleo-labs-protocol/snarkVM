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

use super::*;

impl<N: Network> FromBytes for ClosureCore<N> {
    /// Reads the closure from a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the closure name.
        let name = Identifier::<N>::read_le(&mut reader)?;

        // Read the inputs.
        let num_inputs = u16::read_le(&mut reader)?;
        if num_inputs.is_zero() {
            return Err(error("Failed to deserialize a closure: needs at least one input".to_string()));
        }
        if num_inputs > u16::try_from(N::MAX_INPUTS).map_err(error)? {
            return Err(error(format!("Failed to deserialize a closure: too many inputs ({num_inputs})")));
        }
        let mut inputs = Vec::with_capacity(num_inputs as usize);
        for _ in 0..num_inputs {
            inputs.push(Input::read_le(&mut reader)?);
        }

        // Read the instructions.
        let num_instructions = u32::read_le(&mut reader)?;
        if num_instructions.is_zero() {
            return Err(error("Failed to deserialize a closure: needs at least one instruction".to_string()));
        }
        if num_instructions > u32::try_from(N::MAX_INSTRUCTIONS).map_err(error)? {
            return Err(error(format!("Failed to deserialize a closure: too many instructions ({num_instructions})")));
        }
        // Cap the reservation: the count is attacker-supplied, and the elements behind
        // it may not exist.
        let mut instructions = Vec::with_capacity((num_instructions as usize).min(1024));
        for _ in 0..num_instructions {
            instructions.push(Instruction::read_le(&mut reader)?);
        }

        // Read the outputs.
        let num_outputs = u16::read_le(&mut reader)?;
        if num_outputs > u16::try_from(N::MAX_OUTPUTS).map_err(error)? {
            return Err(error(format!("Failed to deserialize a closure: too many outputs ({num_outputs})")));
        }
        let mut outputs = Vec::with_capacity(num_outputs as usize);
        for _ in 0..num_outputs {
            outputs.push(Output::read_le(&mut reader)?);
        }

        // Initialize a new closure.
        let mut closure = Self::new(name);
        inputs.into_iter().try_for_each(|input| closure.add_input(input)).map_err(error)?;
        instructions.into_iter().try_for_each(|instruction| closure.add_instruction(instruction)).map_err(error)?;
        outputs.into_iter().try_for_each(|output| closure.add_output(output)).map_err(error)?;

        Ok(closure)
    }
}

impl<N: Network> ToBytes for ClosureCore<N> {
    /// Writes the closure to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the closure name.
        self.name.write_le(&mut writer)?;

        // Write the number of inputs for the closure.
        let num_inputs = self.inputs.len();
        match 0 < num_inputs && num_inputs <= N::MAX_INPUTS {
            true => u16::try_from(num_inputs).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_inputs} inputs as bytes"))),
        }

        // Write the inputs.
        for input in self.inputs.iter() {
            input.write_le(&mut writer)?;
        }

        // Write the number of instructions for the closure.
        let num_instructions = self.instructions.len();
        match 0 < num_instructions && num_instructions <= N::MAX_INSTRUCTIONS {
            true => u32::try_from(num_instructions).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_instructions} instructions as bytes"))),
        }

        // Write the instructions.
        for instruction in self.instructions.iter() {
            instruction.write_le(&mut writer)?;
        }

        // Write the number of outputs for the closure.
        let num_outputs = self.outputs.len();
        match num_outputs <= N::MAX_OUTPUTS {
            true => u16::try_from(num_outputs).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_outputs} outputs as bytes"))),
        }

        // Write the outputs.
        for output in self.outputs.iter() {
            output.write_le(&mut writer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Closure;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_closure_bytes() -> Result<()> {
        let closure_string = r"
closure main:
    input r0 as field;
    input r1 as field;
    add r0 r1 into r2;
    add r0 r1 into r3;
    add r0 r1 into r4;
    add r0 r1 into r5;
    add r0 r1 into r6;
    add r0 r1 into r7;
    add r0 r1 into r8;
    add r0 r1 into r9;
    add r0 r1 into r10;
    add r0 r1 into r11;
    output r11 as field;";

        let expected = Closure::<CurrentNetwork>::from_str(closure_string)?;
        let expected_bytes = expected.to_bytes_le()?;
        println!("String size: {:?}, Bytecode size: {:?}", closure_string.len(), expected_bytes.len());

        let candidate = Closure::<CurrentNetwork>::from_bytes_le(&expected_bytes)?;
        assert_eq!(expected.to_string(), candidate.to_string());
        assert_eq!(expected_bytes, candidate.to_bytes_le()?);
        Ok(())
    }
}
