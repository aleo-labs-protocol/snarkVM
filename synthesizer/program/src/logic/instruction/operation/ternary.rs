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

use std::collections::HashSet;

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
    program::{Identifier, Literal, LiteralType, Plaintext, PlaintextType, ProgramID, Register, RegisterType, Value},
};

/// Returns an error if the given plaintext type contains a `String` literal leaf,
/// since string ternary selection is not supported (strings have a variable byte-length
/// and cannot be selected by a fixed byte-wise multiplexer).
fn ensure_no_string_leaves<N: Network>(
    stack: &impl StackTrait<N>,
    plaintext_type: &PlaintextType<N>,
    validated: &mut HashSet<(ProgramID<N>, Identifier<N>)>,
) -> Result<()> {
    match plaintext_type {
        PlaintextType::Literal(LiteralType::String) => {
            bail!("Instruction 'ternary' does not support the 'string' type")
        }
        PlaintextType::Literal(_) => Ok(()),
        PlaintextType::Array(array_type) => ensure_no_string_leaves(stack, array_type.next_element_type(), validated),
        PlaintextType::Struct(identifier) => {
            // Validate each resolved struct once, even if multiple members refer to it.
            let key = (*stack.program_id(), *identifier);
            if validated.contains(&key) {
                return Ok(());
            }
            let struct_type = stack.program().get_struct(identifier)?;
            for (_, member_type) in struct_type.members() {
                ensure_no_string_leaves(stack, member_type, validated)?;
            }
            validated.insert(key);
            Ok(())
        }
        PlaintextType::ExternalStruct(locator) => {
            let external_stack = stack.get_external_stack(locator.program_id())?;
            ensure_no_string_leaves(&*external_stack, &PlaintextType::Struct(*locator.resource()), validated)
        }
    }
}

/// Selects `first`, if `condition` is true, otherwise selects `second`, storing the result in `destination`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ternary<N: Network> {
    /// The operands: `[condition, first, second]`.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
}

impl<N: Network> Ternary<N> {
    /// Initializes a new `ternary` instruction.
    pub fn new(operands: Vec<Operand<N>>, destination: Register<N>) -> Result<Self> {
        ensure!(operands.len() == 3, "Instruction '{}' must have three operands", Self::opcode());
        Ok(Self { operands, destination })
    }

    /// Returns the opcode.
    pub const fn opcode() -> Opcode {
        Opcode::Literal("ternary")
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        debug_assert!(self.operands.len() == 3, "Instruction '{}' must have three operands", Self::opcode());
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

impl<N: Network> Ternary<N> {
    /// Evaluates the instruction.
    pub fn evaluate(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersTrait<N>) -> Result<()> {
        // Ensure the number of operands is correct.
        if self.operands.len() != 3 {
            bail!("Instruction '{}' expects 3 operands, found {} operands", Self::opcode(), self.operands.len())
        }

        // Load the condition operand as a boolean literal.
        let condition = match registers.load_literal(stack, &self.operands[0])? {
            Literal::Boolean(boolean) => boolean,
            other => bail!(
                "Instruction '{}' expects the first operand to be a 'boolean', found '{}'",
                Self::opcode(),
                other.to_type()
            ),
        };
        // Load the two branch operands as plaintexts.
        let first = registers.load_plaintext(stack, &self.operands[1])?;
        let second = registers.load_plaintext(stack, &self.operands[2])?;

        // Select between the two branches.
        let output = <Plaintext<N> as console::prelude::Ternary>::ternary(&condition, &first, &second);

        // Store the output.
        registers.store(stack, &self.destination, Value::Plaintext(output))
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        // Ensure the number of operands is correct.
        if self.operands.len() != 3 {
            bail!("Instruction '{}' expects 3 operands, found {} operands", Self::opcode(), self.operands.len())
        }

        // Load the condition operand as a boolean literal.
        let condition = match registers.load_literal_circuit(stack, &self.operands[0])? {
            circuit::Literal::Boolean(boolean) => boolean,
            other => bail!(
                "Instruction '{}' expects the first operand to be a 'boolean', found '{}'",
                Self::opcode(),
                other.to_type()
            ),
        };
        // Load the two branch operands as plaintexts.
        let first = registers.load_plaintext_circuit(stack, &self.operands[1])?;
        let second = registers.load_plaintext_circuit(stack, &self.operands[2])?;

        // Select between the two branches.
        let output = <circuit::Plaintext<A> as circuit::traits::Ternary>::ternary(&condition, &first, &second);

        // Store the output.
        registers.store_circuit(stack, &self.destination, circuit::Value::Plaintext(output))
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        self.evaluate(stack, registers)
    }

    /// Returns the output type from the given program and input types.
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        if input_types.len() != 3 {
            bail!("Instruction '{}' expects 3 inputs, found {} inputs", Self::opcode(), input_types.len())
        }
        // Ensure the number of operands is correct.
        if self.operands.len() != 3 {
            bail!("Instruction '{}' expects 3 operands, found {} operands", Self::opcode(), self.operands.len())
        }

        // Ensure the first input is a boolean literal.
        match &input_types[0] {
            RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Boolean)) => {}
            other => bail!(
                "Instruction '{}' expects the first input to be of type 'boolean', found '{other}'",
                Self::opcode()
            ),
        }

        // Ensure the second and third inputs are plaintexts.
        let plaintext_type = match (&input_types[1], &input_types[2]) {
            (RegisterType::Plaintext(plaintext_type), RegisterType::Plaintext(_)) => plaintext_type.clone(),
            _ => bail!(
                "Instruction '{}' expects plaintext inputs for the branches, found '{}' and '{}'",
                Self::opcode(),
                input_types[1],
                input_types[2]
            ),
        };

        // Ensure the second and third input types are equivalent.
        if !register_types_equivalent(stack, &input_types[1], stack, &input_types[2])? {
            bail!(
                "Instruction '{}' expects the branches to have equivalent types. Found '{}' and '{}'",
                Self::opcode(),
                input_types[1],
                input_types[2]
            )
        }

        // Reject plaintext types that contain a `string` leaf: string ternary is not supported
        // because strings have a variable byte-length and cannot be selected by a byte-wise MUX.
        ensure_no_string_leaves(stack, &plaintext_type, &mut HashSet::new())?;

        // The two branches are structurally equivalent, so either one describes the output; pick the first.
        Ok(vec![RegisterType::Plaintext(plaintext_type)])
    }
}

impl<N: Network> Parser for Ternary<N> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the first operand (condition) from the string.
        let (string, condition) = Operand::parse(string)?;
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the second operand from the string.
        let (string, first) = Operand::parse(string)?;
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the third operand from the string.
        let (string, second) = Operand::parse(string)?;
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "into" from the string.
        let (string, _) = tag("into")(string)?;
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;

        Ok((string, Self { operands: vec![condition, first, second], destination }))
    }
}

impl<N: Network> FromStr for Ternary<N> {
    type Err = Error;

    /// Parses a string into an operation.
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for Ternary<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Ternary<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if self.operands.len() != 3 {
            return Err(fmt::Error);
        }
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {}", self.destination)
    }
}

impl<N: Network> FromBytes for Ternary<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let mut operands = Vec::with_capacity(3);
        for _ in 0..3 {
            operands.push(Operand::read_le(&mut reader)?);
        }
        let destination = Register::read_le(&mut reader)?;
        Ok(Self { operands, destination })
    }
}

impl<N: Network> ToBytes for Ternary<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // The invariant is maintained by `new`, `read_le`, and `parse`.
        debug_assert_eq!(self.operands.len(), 3, "Instruction 'ternary' must have three operands");
        if self.operands.len() != 3 {
            return Err(error(format!("The number of operands must be 3, found {}", self.operands.len())));
        }
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        self.destination.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (remainder, ternary) = Ternary::<CurrentNetwork>::parse("ternary r0 r1 r2 into r3").unwrap();
        assert!(remainder.is_empty(), "Parser did not consume all of the string: '{remainder}'");
        assert_eq!(ternary.operands.len(), 3);
        assert_eq!(ternary.operands[0], Operand::Register(Register::Locator(0)));
        assert_eq!(ternary.operands[1], Operand::Register(Register::Locator(1)));
        assert_eq!(ternary.operands[2], Operand::Register(Register::Locator(2)));
        assert_eq!(ternary.destination, Register::Locator(3));
    }

    #[test]
    fn test_display_roundtrip() {
        let input = "ternary r0 r1 r2 into r3";
        let ternary = Ternary::<CurrentNetwork>::from_str(input).unwrap();
        assert_eq!(input, ternary.to_string());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let ternary = Ternary::<CurrentNetwork>::from_str("ternary r0 r1 r2 into r3").unwrap();
        let bytes = ternary.to_bytes_le().unwrap();
        let decoded = Ternary::<CurrentNetwork>::from_bytes_le(&bytes).unwrap();
        assert_eq!(ternary, decoded);
    }
}
