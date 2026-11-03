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

use console::{
    network::prelude::*,
    program::{Identifier, Literal, ProgramID, Register},
    types::{Group, U32},
};

/// The `Operand` enum represents the options for an operand in an instruction.
/// This enum is designed to for instructions such as `add {Register} {Literal} into {Register}`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Operand<N: Network> {
    /// The operand is a literal.
    Literal(Literal<N>),
    /// The operand is a register.
    Register(Register<N>),
    /// The operand is the program ID.
    ProgramID(ProgramID<N>),
    /// The operand is the signer address.
    /// Note: This variant is only accessible in the `function` scope.
    Signer,
    /// The operand is the caller address.
    /// Note: This variant is only accessible in the `function` scope.
    Caller,
    /// The operand is the block height.
    /// Note: This variant is only accessible in the `finalize` scope.
    BlockHeight,
    /// The operand is the block timestamp.
    /// Note: This variant is only accessible in the `finalize` scope.
    BlockTimestamp,
    /// The operand is the network ID.
    /// Note: This variant is only accessible in the `finalize` scope.
    NetworkID,
    /// The operand is the first group base for the Aleo signature and encryption schemes.
    AleoGenerator,
    /// The operand is the group bases for the Aleo signature and encryption schemes.
    AleoGeneratorPowers(Option<U32<N>>),
    /// The operand is the program checksum.
    /// If no program ID is specified, the checksum is for the current program.
    /// If a program ID is specified, the checksum is for an external program.
    Checksum(Option<ProgramID<N>>),
    /// The operand is the program edition.
    /// If no program ID is specified, the edition is for the current program.
    /// If a program ID is specified, the edition is for an external program.
    Edition(Option<ProgramID<N>>),
    /// The operand is the program owner.
    /// If no program ID is specified, the owner is for the current program.
    /// If a program ID is specified, the owner is for an external program.
    ProgramOwner(Option<ProgramID<N>>),
    /// The operand is the checksum of a named program component (a function, closure, or view).
    /// If no program ID is specified, the component is in the current program.
    /// If a program ID is specified, the component is in an external program.
    ComponentChecksum(Option<ProgramID<N>>, Identifier<N>),
}

impl<N: Network> From<Literal<N>> for Operand<N> {
    /// Initializes a new operand from a literal.
    #[inline]
    fn from(literal: Literal<N>) -> Self {
        Operand::Literal(literal)
    }
}

impl<N: Network> From<&Literal<N>> for Operand<N> {
    /// Initializes a new operand from a reference to a literal.
    #[inline]
    fn from(literal: &Literal<N>) -> Self {
        Operand::Literal(literal.clone())
    }
}

impl<N: Network> From<Register<N>> for Operand<N> {
    /// Initializes a new operand from a register.
    #[inline]
    fn from(register: Register<N>) -> Self {
        Operand::Register(register)
    }
}

impl<N: Network> From<&Register<N>> for Operand<N> {
    /// Initializes a new operand from a reference to a register.
    #[inline]
    fn from(register: &Register<N>) -> Self {
        Operand::Register(register.clone())
    }
}

impl<N: Network> Operand<N> {
    /// Returns `true` if the operand contains a string type.
    pub fn contains_string_type(&self) -> bool {
        matches!(self, Self::Literal(Literal::String(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_operand_from_literal() -> Result<()> {
        let literal = Literal::from_str("1field")?;
        let expected = Operand::<CurrentNetwork>::Literal(literal.clone());

        let operand = Operand::<CurrentNetwork>::from(literal);
        assert_eq!(expected, operand);
        Ok(())
    }

    #[test]
    fn test_operand_from_register() -> Result<()> {
        let register = Register::from_str("r0")?;
        let expected = Operand::<CurrentNetwork>::Register(register.clone());

        let operand = Operand::<CurrentNetwork>::from(register);
        assert_eq!(expected, operand);
        Ok(())
    }

    #[test]
    fn test_operand_from_register_member() -> Result<()> {
        let register = Register::from_str("r0.owner")?;
        let expected = Operand::<CurrentNetwork>::Register(register.clone());

        let operand = Operand::<CurrentNetwork>::from(register);
        assert_eq!(expected, operand);
        Ok(())
    }
}
