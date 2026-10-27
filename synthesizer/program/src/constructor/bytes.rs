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

impl<N: Network> FromBytes for ConstructorCore<N> {
    /// Reads the constructor from a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the commands.
        let num_commands = u16::read_le(&mut reader)?;
        if num_commands.is_zero() {
            return Err(error("Failed to deserialize constructor: needs at least one command"));
        }
        if num_commands > u16::try_from(N::MAX_COMMANDS).map_err(error)? {
            return Err(error(format!("Failed to deserialize constructor: too many commands ({num_commands})")));
        }
        // Cap the reservation: the count is attacker-supplied, and the elements behind
        // it may not exist.
        let mut commands = Vec::with_capacity((num_commands as usize).min(1024));
        for _ in 0..num_commands {
            commands.push(Command::read_le(&mut reader)?);
        }
        // Initialize a new constructor.
        let mut constructor = Self { commands: Default::default(), num_writes: 0, positions: Default::default() };
        commands.into_iter().try_for_each(|command| constructor.add_command(command)).map_err(error)?;

        Ok(constructor)
    }
}

impl<N: Network> ToBytes for ConstructorCore<N> {
    /// Writes the constructor to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the number of commands for the constructor.
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
    use crate::Constructor;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_constructor_bytes() -> Result<()> {
        let constructor_string = r"
constructor:
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

        let expected = Constructor::<CurrentNetwork>::from_str(constructor_string)?;
        let expected_bytes = expected.to_bytes_le()?;
        println!("String size: {:?}, Bytecode size: {:?}", constructor_string.len(), expected_bytes.len());

        let candidate = Constructor::<CurrentNetwork>::from_bytes_le(&expected_bytes)?;
        assert_eq!(expected.to_string(), candidate.to_string());
        assert_eq!(expected_bytes, candidate.to_bytes_le()?);
        Ok(())
    }
}
