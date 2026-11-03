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

mod await_;
pub use await_::*;

mod branch;
pub use branch::*;

mod contains;
pub use contains::*;

mod get;
pub use get::*;

mod get_or_use;
pub use get_or_use::*;

mod rand_chacha;
pub use crate::command::rand_chacha::*;

mod remove;
pub use remove::*;

mod position;
pub use position::*;

mod set;
pub use set::*;

use crate::{
    CastType,
    FinalizeOperation,
    FinalizeRegistersState,
    FinalizeStoreTrait,
    Instruction,
    Operand,
    StackTrait,
};
use console::{
    network::{error, prelude::*},
    program::{Identifier, Register},
};
use snarkvm_synthesizer_error::FinalizeError;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Command<N: Network> {
    /// Evaluates the instruction.
    Instruction(Instruction<N>),
    /// Awaits the result of a future.
    Await(Await<N>),
    /// Returns true if the `key` operand is present in `mapping`, and stores the result into `destination`.
    Contains(Contains<N>),
    /// Resolves the `program` and `mapping` operands, returns true if the `key` operand is present in the `mapping`, and stores the result into `destination`.
    ContainsDynamic(ContainsDynamic<N>),
    /// Gets the value stored at the `key` operand in `mapping` and stores the result into `destination`.
    Get(Get<N>),
    /// Resolves the `program` and `mapping` operands, gets the value stored at the `key` operand in `mapping`, and stores the result into `destination`.
    GetDynamic(GetDynamic<N>),
    /// Gets the value stored at the `key` operand in `mapping` and stores the result into `destination`.
    /// If the key is not present, `default` is stored into `destination`.
    GetOrUse(GetOrUse<N>),
    /// Resolves the `program` and `mapping` operands, gets the value stored at the `key` operand in `mapping`, and stores the result into `destination`.
    /// If the key is not present, `default` is stored into `destination`.
    GetOrUseDynamic(GetOrUseDynamic<N>),
    /// Generates a random value using the `rand.chacha` command and stores the result into `destination`.
    RandChaCha(RandChaCha<N>),
    /// Removes the (`key`, `value`) entry from the `mapping`.
    Remove(Remove<N>),
    /// Sets the value stored at the `key` operand in the `mapping` to `value`.
    Set(Set<N>),
    /// Jumps to the `position`, if `first` equals `second`.
    BranchEq(BranchEq<N>),
    /// Jumps to the `position`, if `first` does **not** equal `second`.
    BranchNeq(BranchNeq<N>),
    /// Indicates a position to which the program can branch to.
    Position(Position<N>),
}

impl<N: Network> Command<N> {
    /// Returns `true` if the command is an async instruction.
    pub fn is_async(&self) -> bool {
        matches!(self, Command::Instruction(Instruction::Async(_)))
    }

    /// Returns `true` if the command is an await command.
    #[inline]
    pub fn is_await(&self) -> bool {
        matches!(self, Command::Await(_))
    }

    /// Returns `true` if the command is a call instruction.
    pub fn is_call(&self) -> bool {
        matches!(self, Command::Instruction(Instruction::Call(_) | Instruction::CallDynamic(_)))
    }

    /// Returns `true` if the command is specifically a dynamic call instruction.
    pub fn is_dynamic_call(&self) -> bool {
        matches!(self, Command::Instruction(Instruction::CallDynamic(_)))
    }

    /// Returns `true` if the command is a cast-to-record instruction. Covers all three
    /// record cast variants: static `record`, `external_record`, and `dynamic.record`.
    pub fn is_cast_to_record(&self) -> bool {
        matches!(
            self,
            Command::Instruction(Instruction::Cast(cast))
                if matches!(
                    cast.cast_type(),
                    CastType::Record(_) | CastType::ExternalRecord(_) | CastType::DynamicRecord
                )
        )
    }

    /// Returns `true` if the command is a `get.record.dynamic` instruction.
    pub fn is_get_record_dynamic(&self) -> bool {
        matches!(self, Command::Instruction(Instruction::GetRecordDynamic(_)))
    }

    /// Returns `true` if the command operates on a record value, either by creating one via
    /// `cast` (static, external, or dynamic) or by reading one via `get.record.dynamic`.
    pub fn is_instruction_for_record(&self) -> bool {
        self.is_cast_to_record() || self.is_get_record_dynamic()
    }

    /// Returns `true` if the command is a `rand.chacha` command.
    pub fn is_rand_chacha(&self) -> bool {
        matches!(self, Command::RandChaCha(_))
    }

    /// Returns `true` if the command is a write operation.
    pub fn is_write(&self) -> bool {
        matches!(self, Command::Set(_) | Command::Remove(_))
    }

    /// Returns the branch target, if the command is a branch command.
    /// Otherwise, returns `None`.
    pub fn branch_to(&self) -> Option<&Identifier<N>> {
        match self {
            Command::BranchEq(branch_eq) => Some(branch_eq.position()),
            Command::BranchNeq(branch_neq) => Some(branch_neq.position()),
            _ => None,
        }
    }

    /// Returns the position name, if the command is a position command.
    /// Otherwise, returns `None`.
    pub fn position(&self) -> Option<&Identifier<N>> {
        match self {
            Command::Position(position) => Some(position.name()),
            _ => None,
        }
    }

    /// Returns the destination registers of the command.
    pub fn destinations(&self) -> Vec<Register<N>> {
        match self {
            Command::Instruction(instruction) => instruction.destinations(),
            Command::Contains(contains) => vec![contains.destination().clone()],
            Command::ContainsDynamic(contains) => vec![contains.destination().clone()],
            Command::Get(get) => vec![get.destination().clone()],
            Command::GetDynamic(get) => vec![get.destination().clone()],
            Command::GetOrUse(get_or_use) => vec![get_or_use.destination().clone()],
            Command::GetOrUseDynamic(get_or_use) => vec![get_or_use.destination().clone()],
            Command::RandChaCha(rand_chacha) => vec![rand_chacha.destination().clone()],
            Command::Await(_)
            | Command::BranchEq(_)
            | Command::BranchNeq(_)
            | Command::Position(_)
            | Command::Remove(_)
            | Command::Set(_) => vec![],
        }
    }

    /// Returns the operands of the command.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        match self {
            Command::Instruction(c) => c.operands(),
            Command::Await(c) => c.operands(),
            Command::Contains(c) => c.operands(),
            Command::ContainsDynamic(c) => c.operands(),
            Command::Get(c) => c.operands(),
            Command::GetDynamic(c) => c.operands(),
            Command::GetOrUse(c) => c.operands(),
            Command::GetOrUseDynamic(c) => c.operands(),
            Command::RandChaCha(c) => c.operands(),
            Command::Remove(c) => c.operands(),
            Command::Set(c) => c.operands(),
            Command::BranchEq(c) => c.operands(),
            Command::BranchNeq(c) => c.operands(),
            Command::Position(_) => Default::default(),
        }
    }

    /// Finalizes the command.
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        store: &dyn FinalizeStoreTrait<N>,
        registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<Option<FinalizeOperation<N>>, FinalizeError> {
        match self {
            // Finalize the instruction, and return no finalize operation.
            Command::Instruction(instruction) => instruction.finalize(stack, Some(store), registers).map(|_| None),
            // `await` commands are processed by the caller of this method.
            Command::Await(_) => Err(FinalizeError::Anyhow(anyhow!("`await` commands cannot be finalized directly."))),
            // Finalize the 'contains' command, and return no finalize operation.
            Command::Contains(contains) => contains.finalize(stack, store, registers).map(|_| None).map_err(Into::into),
            // Finalize the `contains.dynamic` command, and return no finalize operation.
            Command::ContainsDynamic(contains_dynamic) => {
                contains_dynamic.finalize(stack, store, registers).map(|_| None).map_err(Into::into)
            }
            // Finalize the 'get' command, and return no finalize operation.
            Command::Get(get) => get.finalize(stack, store, registers).map(|_| None).map_err(Into::into),
            // Finalize the `get.dynamic` and return no finalize operation.
            Command::GetDynamic(get_dynamic) => {
                get_dynamic.finalize(stack, store, registers).map(|_| None).map_err(Into::into)
            }
            // Finalize the 'get.or_use' command, and return no finalize operation.
            Command::GetOrUse(get_or_use) => {
                get_or_use.finalize(stack, store, registers).map(|_| None).map_err(Into::into)
            }
            // Finalize the `get.or_use.dynamic` command, and return no finalize operation.
            Command::GetOrUseDynamic(get_or_use_dynamic) => {
                get_or_use_dynamic.finalize(stack, store, registers).map(|_| None).map_err(Into::into)
            }
            // Finalize the `rand.chacha` command, and return no finalize operation.
            Command::RandChaCha(rand_chacha) => {
                rand_chacha.finalize(stack, registers).map(|_| None).map_err(Into::into)
            }
            // Finalize the 'remove' command, and return the finalize operation.
            Command::Remove(remove) => remove.finalize(stack, store, registers).map_err(Into::into),
            // Finalize the 'set' command, and return the finalize operation.
            Command::Set(set) => set.finalize(stack, store, registers).map(Some).map_err(Into::into),
            // 'branch.eq' and 'branch.neq' commands are processed by the caller of this method.
            Command::BranchEq(_) | Command::BranchNeq(_) => {
                Err(FinalizeError::Anyhow(anyhow!("`branch` commands cannot be finalized directly.")))
            }
            // Finalize the `position` command, and return no finalize operation.
            Command::Position(position) => position.finalize().map(|_| None).map_err(Into::into),
        }
    }

    /// Returns whether this commands refers to an external struct.
    pub fn contains_external_struct(&self) -> bool {
        match self {
            Command::Instruction(c) => c.contains_external_struct(),
            Command::Await(c) => c.contains_external_struct(),
            Command::Contains(c) => c.contains_external_struct(),
            // `contains.dynamic` always produces a boolean result and has no type fields that could reference external structs.
            Command::ContainsDynamic(_) => false,
            Command::Get(c) => c.contains_external_struct(),
            Command::GetDynamic(c) => c.destination_type().contains_external_struct(),
            Command::GetOrUse(c) => c.contains_external_struct(),
            Command::GetOrUseDynamic(c) => c.destination_type().contains_external_struct(),
            Command::RandChaCha(c) => c.contains_external_struct(),
            Command::Remove(c) => c.contains_external_struct(),
            Command::Set(c) => c.contains_external_struct(),
            Command::BranchEq(c) => c.contains_external_struct(),
            Command::BranchNeq(c) => c.contains_external_struct(),
            Command::Position(c) => c.contains_external_struct(),
        }
    }

    /// Returns `true` if the command contains a string type.
    pub fn contains_string_type(&self) -> bool {
        self.operands().iter().any(|operand| operand.contains_string_type())
    }

    /// Returns `true` if the command contains an identifier type in its cast type.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        match self {
            Command::Instruction(instruction) => instruction.contains_identifier_type(),
            _ => Ok(false),
        }
    }

    /// Returns `true` if the command contains an array type with a size that exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        match self {
            Command::Instruction(instruction) => instruction.exceeds_max_array_size(max_array_size),
            _ => false,
        }
    }
}

impl<N: Network> FromBytes for Command<N> {
    /// Reads the command from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the variant.
        let variant = u8::read_le(&mut reader)?;
        match variant {
            // Read the instruction.
            0 => Ok(Self::Instruction(Instruction::read_le(&mut reader)?)),
            // Read the `await` operation.
            1 => Ok(Self::Await(Await::read_le(&mut reader)?)),
            // Read the `contains` operation.
            2 => Ok(Self::Contains(Contains::read_le(&mut reader)?)),
            // Read the `get` operation.
            3 => Ok(Self::Get(Get::read_le(&mut reader)?)),
            // Read the `get.or_use` operation.
            4 => Ok(Self::GetOrUse(GetOrUse::read_le(&mut reader)?)),
            // Read the `rand.chacha` operation.
            5 => Ok(Self::RandChaCha(RandChaCha::read_le(&mut reader)?)),
            // Read the `remove` operation.
            6 => Ok(Self::Remove(Remove::read_le(&mut reader)?)),
            // Read the `set` operation.
            7 => Ok(Self::Set(Set::read_le(&mut reader)?)),
            // Read the `branch.eq` command.
            8 => Ok(Self::BranchEq(BranchEq::read_le(&mut reader)?)),
            // Read the `branch.neq` command.
            9 => Ok(Self::BranchNeq(BranchNeq::read_le(&mut reader)?)),
            // Read the `position` command.
            10 => Ok(Self::Position(Position::read_le(&mut reader)?)),
            // Read the `contains.dynamic` command.
            11 => Ok(Self::ContainsDynamic(ContainsDynamic::read_le(&mut reader)?)),
            // Read the `get.dynamic` command.
            12 => Ok(Self::GetDynamic(GetDynamic::read_le(&mut reader)?)),
            // Read the `get.or_use.dynamic` command.
            13 => Ok(Self::GetOrUseDynamic(GetOrUseDynamic::read_le(&mut reader)?)),
            // Invalid variant.
            14.. => Err(error(format!("Invalid command variant: {variant}"))),
        }
    }
}

impl<N: Network> ToBytes for Command<N> {
    /// Writes the command to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Instruction(instruction) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the instruction.
                instruction.write_le(&mut writer)
            }
            Self::Await(await_) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the `await` operation.
                await_.write_le(&mut writer)
            }
            Self::Contains(contains) => {
                // Write the variant.
                2u8.write_le(&mut writer)?;
                // Write the `contains` operation.
                contains.write_le(&mut writer)
            }
            Self::Get(get) => {
                // Write the variant.
                3u8.write_le(&mut writer)?;
                // Write the `get` operation.
                get.write_le(&mut writer)
            }
            Self::GetOrUse(get_or_use) => {
                // Write the variant.
                4u8.write_le(&mut writer)?;
                // Write the defaulting `get` operation.
                get_or_use.write_le(&mut writer)
            }
            Self::RandChaCha(rand_chacha) => {
                // Write the variant.
                5u8.write_le(&mut writer)?;
                // Write the `rand.chacha` operation.
                rand_chacha.write_le(&mut writer)
            }
            Self::Remove(remove) => {
                // Write the variant.
                6u8.write_le(&mut writer)?;
                // Write the remove.
                remove.write_le(&mut writer)
            }
            Self::Set(set) => {
                // Write the variant.
                7u8.write_le(&mut writer)?;
                // Write the set.
                set.write_le(&mut writer)
            }
            Self::BranchEq(branch_eq) => {
                // Write the variant.
                8u8.write_le(&mut writer)?;
                // Write the `branch.eq` command.
                branch_eq.write_le(&mut writer)
            }
            Self::BranchNeq(branch_neq) => {
                // Write the variant.
                9u8.write_le(&mut writer)?;
                // Write the `branch.neq` command.
                branch_neq.write_le(&mut writer)
            }
            Self::Position(position) => {
                // Write the variant.
                10u8.write_le(&mut writer)?;
                // Write the position command.
                position.write_le(&mut writer)
            }
            Self::ContainsDynamic(contains_dynamic) => {
                // Write the variant.
                11u8.write_le(&mut writer)?;
                // Write the `contains.dynamic` command.
                contains_dynamic.write_le(&mut writer)
            }
            Self::GetDynamic(get_dynamic) => {
                // Write the variant.
                12u8.write_le(&mut writer)?;
                // Write the `get.dynamic` command.
                get_dynamic.write_le(&mut writer)
            }
            Self::GetOrUseDynamic(get_or_use_dynamic) => {
                // Write the variant.
                13u8.write_le(&mut writer)?;
                // Write the `get.or_use.dynamic` command.
                get_or_use_dynamic.write_le(&mut writer)
            }
        }
    }
}

impl<N: Network> Parser for Command<N> {
    /// Parses the string into the command.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the command.
        // Note that the order of the parsers is important.
        alt((
            map(Await::parse, |await_| Self::Await(await_)),
            map(ContainsDynamic::parse, |contains_dynamic| Self::ContainsDynamic(contains_dynamic)),
            map(Contains::parse, |contains| Self::Contains(contains)),
            map(GetOrUseDynamic::parse, |get_or_use_dynamic| Self::GetOrUseDynamic(get_or_use_dynamic)),
            map(GetOrUse::parse, |get_or_use| Self::GetOrUse(get_or_use)),
            map(GetDynamic::parse, |get_dynamic| Self::GetDynamic(get_dynamic)),
            map(Get::parse, |get| Self::Get(get)),
            map(RandChaCha::parse, |rand_chacha| Self::RandChaCha(rand_chacha)),
            map(Remove::parse, |remove| Self::Remove(remove)),
            map(Set::parse, |set| Self::Set(set)),
            map(BranchEq::parse, |branch_eq| Self::BranchEq(branch_eq)),
            map(BranchNeq::parse, |branch_neq| Self::BranchNeq(branch_neq)),
            map(Position::parse, |position| Self::Position(position)),
            map(Instruction::parse, |instruction| Self::Instruction(instruction)),
        ))(string)
    }
}

impl<N: Network> FromStr for Command<N> {
    type Err = Error;

    /// Parses the string into the command.
    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for Command<N> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Command<N> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Instruction(instruction) => Display::fmt(instruction, f),
            Self::Await(await_) => Display::fmt(await_, f),
            Self::Contains(contains) => Display::fmt(contains, f),
            Self::ContainsDynamic(contains_dynamic) => Display::fmt(contains_dynamic, f),
            Self::Get(get) => Display::fmt(get, f),
            Self::GetDynamic(get_dynamic) => Display::fmt(get_dynamic, f),
            Self::GetOrUse(get_or_use) => Display::fmt(get_or_use, f),
            Self::GetOrUseDynamic(get_or_use_dynamic) => Display::fmt(get_or_use_dynamic, f),
            Self::RandChaCha(rand_chacha) => Display::fmt(rand_chacha, f),
            Self::Remove(remove) => Display::fmt(remove, f),
            Self::Set(set) => Display::fmt(set, f),
            Self::BranchEq(branch_eq) => Display::fmt(branch_eq, f),
            Self::BranchNeq(branch_neq) => Display::fmt(branch_neq, f),
            Self::Position(position) => Display::fmt(position, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_command_bytes() {
        // Decrement
        let expected = "decrement object[r0] by r1;";
        Command::<CurrentNetwork>::parse(expected).unwrap_err();

        // Instruction
        let expected = "add r0 r1 into r2;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // Increment
        let expected = "increment object[r0] by r1;";
        Command::<CurrentNetwork>::parse(expected).unwrap_err();

        // Await
        let expected = "await r1;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // Contains
        let expected = "contains object[r0] into r1;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // ContainsDynamic
        let expected = "contains.dynamic r0 r1 r2[r3] into r4;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // Get
        let expected = "get object[r0] into r1;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // GetDynamic
        let expected = "get.dynamic r0 r1 r2[r3] into r4 as field;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // GetOr
        let expected = "get.or_use object[r0] r1 into r2;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // GetOrDynamic
        let expected = "get.or_use.dynamic r0 r1 r2[r3] r4 into r5 as credits;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // RandChaCha
        let expected = "rand.chacha into r1 as field;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // RandChaCha
        let expected = "rand.chacha r0 r1 into r2 as group;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // Remove
        let expected = "remove object[r0];";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // Set
        let expected = "set r0 into object[r1];";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // BranchEq
        let expected = "branch.eq r0 r1 to exit;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // BranchNeq
        let expected = "branch.neq r2 r3 to start;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());

        // Position
        let expected = "position exit;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        let bytes = command.to_bytes_le().unwrap();
        assert_eq!(command, Command::from_bytes_le(&bytes).unwrap());
    }

    #[test]
    fn test_command_parse() {
        // Decrement
        let expected = "decrement object[r0] by r1;";
        Command::<CurrentNetwork>::parse(expected).unwrap_err();

        // Instruction
        let expected = "add r0 r1 into r2;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::Instruction(Instruction::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // Increment
        let expected = "increment object[r0] by r1;";
        Command::<CurrentNetwork>::parse(expected).unwrap_err();

        // Contains
        let expected = "contains object[r0] into r1;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::Contains(Contains::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // ContainsDynamic
        let expected = "contains.dynamic r0 r1 r2[r3] into r4;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::ContainsDynamic(ContainsDynamic::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // Get
        let expected = "get object[r0] into r1;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::Get(Get::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // GetDynamic
        let expected = "get.dynamic r0 r1 r2[r3] into r4 as u8;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::GetDynamic(GetDynamic::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // GetOr
        let expected = "get.or_use object[r0] r1 into r2;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::GetOrUse(GetOrUse::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // GetOrDynamic
        let expected = "get.or_use.dynamic r0 r1 r2[r3] r4 into r5 as Foo;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::GetOrUseDynamic(GetOrUseDynamic::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // RandChaCha
        let expected = "rand.chacha into r1 as field;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::RandChaCha(RandChaCha::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // RandChaCha
        let expected = "rand.chacha r0 r1 into r2 as group;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::RandChaCha(RandChaCha::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // Remove
        let expected = "remove object[r0];";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::Remove(Remove::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // Set
        let expected = "set r0 into object[r1];";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::Set(Set::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // BranchEq
        let expected = "branch.eq r0 r1 to exit;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::BranchEq(BranchEq::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // BranchNeq
        let expected = "branch.neq r2 r3 to start;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::BranchNeq(BranchNeq::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());

        // Position
        let expected = "position exit;";
        let command = Command::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(Command::Position(Position::from_str(expected).unwrap()), command);
        assert_eq!(expected, command.to_string());
    }
}
