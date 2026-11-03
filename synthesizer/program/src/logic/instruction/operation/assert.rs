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

use crate::{
    FinalizeRegistersState,
    FinalizeStoreTrait,
    Opcode,
    Operand,
    RegistersCircuit,
    RegistersTrait,
    StackTrait,
    register_types_equivalent,
};
use console::{
    network::prelude::*,
    program::{Register, RegisterType},
};
use snarkvm_synthesizer_error::*;

/// Asserts two operands are equal to each other.
pub type AssertEq<N> = AssertInstruction<N, { Variant::AssertEq as u8 }>;
/// Asserts two operands are **not** equal to each other.
pub type AssertNeq<N> = AssertInstruction<N, { Variant::AssertNeq as u8 }>;

enum Variant {
    AssertEq,
    AssertNeq,
}

/// Asserts an operation on two operands.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AssertInstruction<N: Network, const VARIANT: u8> {
    /// The operands.
    operands: Vec<Operand<N>>,
}

impl<N: Network, const VARIANT: u8> AssertInstruction<N, VARIANT> {
    /// Initializes a new `assert` instruction.
    #[inline]
    pub fn new(operands: Vec<Operand<N>>) -> Result<Self> {
        // Sanity check that the operands is exactly two inputs.
        ensure!(operands.len() == 2, "Assert instructions must have two operands");
        // Return the instruction.
        Ok(Self { operands })
    }

    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        match VARIANT {
            0 => Opcode::Assert("assert.eq"),
            1 => Opcode::Assert("assert.neq"),
            _ => panic!("Invalid 'assert' instruction opcode"),
        }
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that the operands is exactly two inputs.
        debug_assert!(self.operands.len() == 2, "Assert operations must have two operands");
        // Return the operands.
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![]
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

impl<N: Network, const VARIANT: u8> AssertInstruction<N, VARIANT> {
    /// Evaluates the instruction.
    pub fn evaluate(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersTrait<N>,
    ) -> Result<(), EvalError> {
        // Ensure the number of operands is correct.
        if self.operands.len() != 2 {
            return Err(anyhow!(
                "Instruction '{}' expects 2 operands, found {} operands",
                Self::opcode(),
                self.operands.len()
            )
            .into());
        }

        // Retrieve the inputs.
        let input_a = registers.load(stack, &self.operands[0])?;
        let input_b = registers.load(stack, &self.operands[1])?;

        // Assert the inputs.
        match VARIANT {
            0 => {
                if input_a != input_b {
                    return Err(AssertError::Eq { lhs: format!("{input_a}"), rhs: format!("{input_b}") }.into());
                }
            }
            1 => {
                if input_a == input_b {
                    return Err(AssertError::Neq { lhs: format!("{input_a}"), rhs: format!("{input_b}") }.into());
                }
            }
            _ => return Err(AssertError::Invalid { variant: VARIANT }.into()),
        }
        Ok(())
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<(), ExecError> {
        // Ensure the number of operands is correct.
        if self.operands.len() != 2 {
            return Err(anyhow!(
                "Instruction '{}' expects 2 operands, found {} operands",
                Self::opcode(),
                self.operands.len()
            )
            .into());
        }

        // Retrieve the inputs.
        let input_a = registers.load_circuit(stack, &self.operands[0])?;
        let input_b = registers.load_circuit(stack, &self.operands[1])?;

        // Assert the inputs.
        match VARIANT {
            0 => A::assert(input_a.is_equal(&input_b))?,
            1 => A::assert(input_a.is_not_equal(&input_b))?,
            _ => return Err(anyhow!("Invalid 'assert' variant: {VARIANT}").into()),
        }
        Ok(())
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<(), FinalizeError> {
        self.evaluate(stack, registers)?;
        Ok(())
    }

    /// Returns the output type from the given program and input types.
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        if input_types.len() != 2 {
            bail!("Instruction '{}' expects 2 inputs, found {} inputs", Self::opcode(), input_types.len())
        }
        // Ensure the operands have equivalent types.
        if !register_types_equivalent(stack, &input_types[0], stack, &input_types[1])? {
            bail!(
                "Instruction '{}' expects inputs of equivalent types. Found inputs of type '{}' and '{}'",
                Self::opcode(),
                input_types[0],
                input_types[1]
            )
        }
        // Ensure the number of operands is correct.
        if self.operands.len() != 2 {
            bail!("Instruction '{}' expects 2 operands, found {} operands", Self::opcode(), self.operands.len())
        }

        match VARIANT {
            0 | 1 => Ok(vec![]),
            _ => bail!("Invalid 'assert' variant: {VARIANT}"),
        }
    }
}

impl<N: Network, const VARIANT: u8> Parser for AssertInstruction<N, VARIANT> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the first operand from the string.
        let (string, first) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the second operand from the string.
        let (string, second) = Operand::parse(string)?;

        Ok((string, Self { operands: vec![first, second] }))
    }
}

impl<N: Network, const VARIANT: u8> FromStr for AssertInstruction<N, VARIANT> {
    type Err = Error;

    /// Parses a string into an operation.
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

impl<N: Network, const VARIANT: u8> Debug for AssertInstruction<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for AssertInstruction<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is 2.
        if self.operands.len() != 2 {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{}", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, " {operand}"))
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for AssertInstruction<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(2);
        // Read the operands.
        for _ in 0..2 {
            operands.push(Operand::read_le(&mut reader)?);
        }

        // Return the operation.
        Ok(Self { operands })
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for AssertInstruction<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is 2.
        if self.operands.len() != 2 {
            return Err(error(format!("The number of operands must be 2, found {}", self.operands.len())));
        }
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, assert) = AssertEq::<CurrentNetwork>::parse("assert.eq r0 r1").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(assert.operands.len(), 2, "The number of operands is incorrect");
        assert_eq!(assert.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(assert.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");

        let (string, assert) = AssertNeq::<CurrentNetwork>::parse("assert.neq r0 r1").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(assert.operands.len(), 2, "The number of operands is incorrect");
        assert_eq!(assert.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(assert.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
    }
}
