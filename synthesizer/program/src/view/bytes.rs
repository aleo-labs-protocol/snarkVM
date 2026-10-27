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

impl<N: Network> FromBytes for ViewCore<N> {
    /// Reads the view function from a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the view function name.
        let name = Identifier::<N>::read_le(&mut reader)?;

        // Read the inputs.
        let num_inputs = u16::read_le(&mut reader)?;
        if num_inputs > u16::try_from(N::MAX_INPUTS).map_err(error)? {
            return Err(error(format!("Failed to deserialize view: too many inputs ({num_inputs})")));
        }
        let mut inputs = Vec::with_capacity(num_inputs as usize);
        for _ in 0..num_inputs {
            inputs.push(Input::read_le(&mut reader)?);
        }

        // Read the commands. Zero commands are permitted (passthrough / no-op views).
        let num_commands = u16::read_le(&mut reader)?;
        if num_commands > u16::try_from(N::MAX_COMMANDS).map_err(error)? {
            return Err(error(format!("Failed to deserialize view: too many commands ({num_commands})")));
        }
        // Cap the reservation: the count is attacker-supplied, and the elements behind
        // it may not exist.
        let mut commands = Vec::with_capacity((num_commands as usize).min(1024));
        for _ in 0..num_commands {
            commands.push(Command::read_le(&mut reader)?);
        }

        // Read the outputs. Zero outputs are permitted (guard views).
        let num_outputs = u16::read_le(&mut reader)?;
        if num_outputs > u16::try_from(N::MAX_OUTPUTS).map_err(error)? {
            return Err(error(format!("Failed to deserialize view: too many outputs ({num_outputs})")));
        }
        let mut outputs = Vec::with_capacity(num_outputs as usize);
        for _ in 0..num_outputs {
            outputs.push(Output::read_le(&mut reader)?);
        }

        // Initialize a new view.
        let mut view = Self::new(name);
        inputs.into_iter().try_for_each(|input| view.add_input(input)).map_err(error)?;
        commands.into_iter().try_for_each(|command| view.add_command(command)).map_err(error)?;
        outputs.into_iter().try_for_each(|output| view.add_output(output)).map_err(error)?;

        Ok(view)
    }
}

impl<N: Network> ToBytes for ViewCore<N> {
    /// Writes the view function to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the view function name.
        self.name.write_le(&mut writer)?;

        // Write the number of inputs.
        let num_inputs = self.inputs.len();
        match num_inputs <= N::MAX_INPUTS {
            true => u16::try_from(num_inputs).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_inputs} inputs as bytes"))),
        }
        for input in self.inputs.iter() {
            input.write_le(&mut writer)?;
        }

        // Write the number of commands. Zero commands are permitted (passthrough / no-op views).
        let num_commands = self.commands.len();
        match num_commands <= N::MAX_COMMANDS {
            true => u16::try_from(num_commands).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_commands} commands as bytes"))),
        }
        for command in self.commands.iter() {
            command.write_le(&mut writer)?;
        }

        // Write the number of outputs. Zero outputs are permitted (guard views).
        let num_outputs = self.outputs.len();
        match num_outputs <= N::MAX_OUTPUTS {
            true => u16::try_from(num_outputs).map_err(error)?.write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_outputs} outputs as bytes"))),
        }
        for output in self.outputs.iter() {
            output.write_le(&mut writer)?;
        }

        Ok(())
    }
}
