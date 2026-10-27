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

impl<N: Network> FromBytes for FinalizeCore<N> {
    /// Reads the finalize from a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the associated function name.
        let name = Identifier::<N>::read_le(&mut reader)?;

        // Read the inputs.
        let num_inputs = u16::read_le(&mut reader)?;
        if num_inputs > u16::try_from(N::MAX_INPUTS).map_err(error)? {
            return Err(error(format!("Failed to deserialize finalize: too many inputs ({num_inputs})")));
        }
        let mut inputs = Vec::with_capacity(num_inputs as usize);
        for _ in 0..num_inputs {
            inputs.push(Input::read_le(&mut reader)?);
        }

        // Read the commands.
        let num_commands = u16::read_le(&mut reader)?;
        if num_commands.is_zero() {
            return Err(error("Failed to deserialize finalize: needs at least one command".to_string()));
        }
        if num_commands > u16::try_from(N::MAX_COMMANDS).map_err(error)? {
            return Err(error(format!("Failed to deserialize finalize: too many commands ({num_commands})")));
        }
        // Cap the reservation: the count is attacker-supplied, and the elements behind
        // it may not exist.
        let mut commands = Vec::with_capacity((num_commands as usize).min(1024));
        for _ in 0..num_commands {
            commands.push(Command::read_le(&mut reader)?);
        }

        // Initialize a new finalize.
        let mut finalize = Self::new(name);
        inputs.into_iter().try_for_each(|input| finalize.add_input(input)).map_err(error)?;
        commands.into_iter().try_for_each(|command| finalize.add_command(command)).map_err(error)?;

        Ok(finalize)
    }
}

impl<N: Network> ToBytes for FinalizeCore<N> {
    /// Writes the finalize to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the associated function name.
        self.name.write_le(&mut writer)?;

        // Write the number of inputs for the finalize.
        let num_inputs = self.inputs.len();
        match num_inputs <= N::MAX_INPUTS {
            true => u16::try_from(num_inputs).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_inputs} inputs as bytes"))),
        }

        // Write the inputs.
        for input in self.inputs.iter() {
            input.write_le(&mut writer)?;
        }

        // Write the number of commands for the finalize.
        let num_commands = self.commands.len();
        match 0 < num_commands && num_commands <= N::MAX_COMMANDS {
            true => u16::try_from(num_commands).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_commands} commands as bytes"))),
        }

        // Write the commands.
        for command in self.commands.iter() {
            command.write_le(&mut writer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finalize;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_finalize_bytes() -> Result<()> {
        let finalize_string = r"
finalize main:
    input r0 as field.public;
    input r1 as field.public;
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
    get accounts[r0] into r12;
    get accounts[r1] into r13;";

        let expected = Finalize::<CurrentNetwork>::from_str(finalize_string)?;
        let expected_bytes = expected.to_bytes_le()?;
        println!("String size: {:?}, Bytecode size: {:?}", finalize_string.len(), expected_bytes.len());

        let candidate = Finalize::<CurrentNetwork>::from_bytes_le(&expected_bytes)?;
        assert_eq!(expected.to_string(), candidate.to_string());
        assert_eq!(expected_bytes, candidate.to_bytes_le()?);
        Ok(())
    }
}
