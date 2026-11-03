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
};
use console::{
    network::prelude::*,
    program::{Literal, LiteralType, Plaintext, PlaintextType, Register, RegisterType, Scalar, Value},
};

/// BHP256 is a collision-resistant function that processes inputs in 256-bit chunks.
pub type CommitBHP256<N> = CommitInstruction<N, { CommitVariant::CommitBHP256 as u8 }>;
/// BHP512 is a collision-resistant function that processes inputs in 512-bit chunks.
pub type CommitBHP512<N> = CommitInstruction<N, { CommitVariant::CommitBHP512 as u8 }>;
/// BHP768 is a collision-resistant function that processes inputs in 768-bit chunks.
pub type CommitBHP768<N> = CommitInstruction<N, { CommitVariant::CommitBHP768 as u8 }>;
/// BHP1024 is a collision-resistant function that processes inputs in 1024-bit chunks.
pub type CommitBHP1024<N> = CommitInstruction<N, { CommitVariant::CommitBHP1024 as u8 }>;

/// Pedersen64 is a collision-resistant function that processes inputs in 64-bit chunks.
pub type CommitPED64<N> = CommitInstruction<N, { CommitVariant::CommitPED64 as u8 }>;
/// Pedersen128 is a collision-resistant function that processes inputs in 128-bit chunks.
pub type CommitPED128<N> = CommitInstruction<N, { CommitVariant::CommitPED128 as u8 }>;

/// BHP256 commit over raw bits (no type-tagged serialization).
pub type CommitBHP256Raw<N> = CommitInstruction<N, { CommitVariant::CommitBHP256Raw as u8 }>;
/// BHP512 commit over raw bits.
pub type CommitBHP512Raw<N> = CommitInstruction<N, { CommitVariant::CommitBHP512Raw as u8 }>;
/// BHP768 commit over raw bits.
pub type CommitBHP768Raw<N> = CommitInstruction<N, { CommitVariant::CommitBHP768Raw as u8 }>;
/// BHP1024 commit over raw bits.
pub type CommitBHP1024Raw<N> = CommitInstruction<N, { CommitVariant::CommitBHP1024Raw as u8 }>;
/// Pedersen64 commit over raw bits.
pub type CommitPED64Raw<N> = CommitInstruction<N, { CommitVariant::CommitPED64Raw as u8 }>;
/// Pedersen128 commit over raw bits.
pub type CommitPED128Raw<N> = CommitInstruction<N, { CommitVariant::CommitPED128Raw as u8 }>;

/// Which commit function to use.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CommitVariant {
    CommitBHP256,
    CommitBHP512,
    CommitBHP768,
    CommitBHP1024,
    CommitPED64,
    CommitPED128,
    // The variants that commit over raw inputs.
    CommitBHP256Raw,
    CommitBHP512Raw,
    CommitBHP768Raw,
    CommitBHP1024Raw,
    CommitPED64Raw,
    CommitPED128Raw,
}

impl CommitVariant {
    // Returns the opcode associated with the variant.
    pub const fn opcode(variant: u8) -> &'static str {
        match variant {
            0 => "commit.bhp256",
            1 => "commit.bhp512",
            2 => "commit.bhp768",
            3 => "commit.bhp1024",
            4 => "commit.ped64",
            5 => "commit.ped128",
            // The variants that commit over raw inputs.
            6 => "commit.bhp256.raw",
            7 => "commit.bhp512.raw",
            8 => "commit.bhp768.raw",
            9 => "commit.bhp1024.raw",
            10 => "commit.ped64.raw",
            11 => "commit.ped128.raw",
            12.. => panic!("Invalid 'commit' instruction opcode"),
        }
    }

    // Returns `true` if the variant commits over raw bits.
    pub const fn is_raw(variant: u8) -> bool {
        matches!(variant, 6..=11)
    }
}

/// Returns 'true' if the destination type is valid.
fn is_valid_destination_type(destination_type: LiteralType) -> bool {
    matches!(destination_type, LiteralType::Address | LiteralType::Field | LiteralType::Group)
}

/// Commits the operand into the declared type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CommitInstruction<N: Network, const VARIANT: u8> {
    /// The operand as `input`.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
    /// The destination register type.
    destination_type: LiteralType,
}

impl<N: Network, const VARIANT: u8> CommitInstruction<N, VARIANT> {
    /// Initializes a new `commit` instruction.
    #[inline]
    pub fn new(operands: Vec<Operand<N>>, destination: Register<N>, destination_type: LiteralType) -> Result<Self> {
        // Sanity check that the operands is exactly two inputs.
        ensure!(operands.len() == 2, "Commit instructions must have two operands");
        // Sanity check the destination type.
        ensure!(is_valid_destination_type(destination_type), "Invalid destination type for 'commit' instruction");
        // Return the instruction.
        Ok(Self { operands, destination, destination_type })
    }

    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Commit(CommitVariant::opcode(VARIANT))
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that the operands is exactly two inputs.
        debug_assert!(self.operands.len() == 2, "Commit operations must have two operands");
        // Return the operands.
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }

    /// Returns the destination register type.
    #[inline]
    pub const fn destination_type(&self) -> LiteralType {
        self.destination_type
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

// This code is nearly identical in `execute` and `evaluate`; we
// extract it here in a macro.
//
// The `$q` parameter allows us to wrap a value in `Result::Ok`, since
// the `Aleo` functions don't return a `Result` but the `Network` ones do.
macro_rules! do_commit {
    ($N: ident, $variant: expr, $destination_type: expr, $input: expr, $randomizer: expr, $ty: ty, $q: expr) => {{
        let func = match $variant {
            0 | 6 => $N::commit_to_group_bhp256,
            1 | 7 => $N::commit_to_group_bhp512,
            2 | 8 => $N::commit_to_group_bhp768,
            3 | 9 => $N::commit_to_group_bhp1024,
            4 | 10 => $N::commit_to_group_ped64,
            5 | 11 => $N::commit_to_group_ped128,
            12.. => bail!("Invalid 'commit' variant: {}", $variant),
        };

        let bits = match CommitVariant::is_raw($variant) {
            true => $input.to_bits_raw_le(),
            false => $input.to_bits_le(),
        };

        let literal_output: $ty = $q(func(&bits, $randomizer))?.into();
        literal_output.cast_lossy($destination_type)?
    }};
}

/// Evaluate a commit operation.
///
/// This allows running the commit without the machinery of stacks and registers.
/// This is necessary for the Leo interpeter.
pub fn evaluate_commit<N: Network>(
    variant: CommitVariant,
    input: &Value<N>,
    randomizer: &Scalar<N>,
    destination_type: LiteralType,
) -> Result<Literal<N>> {
    evaluate_commit_internal(variant as u8, input, randomizer, destination_type)
}

fn evaluate_commit_internal<N: Network>(
    variant: u8,
    input: &Value<N>,
    randomizer: &Scalar<N>,
    destination_type: LiteralType,
) -> Result<Literal<N>> {
    Ok(do_commit!(N, variant, destination_type, input, randomizer, Literal<N>, |x| x))
}

impl<N: Network, const VARIANT: u8> CommitInstruction<N, VARIANT> {
    /// Evaluates the instruction.
    pub fn evaluate(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersTrait<N>) -> Result<()> {
        // Ensure the number of operands is correct.
        if self.operands.len() != 2 {
            bail!("Instruction '{}' expects 2 operands, found {} operands", Self::opcode(), self.operands.len())
        }
        // Ensure the destination type is valid.
        ensure!(is_valid_destination_type(self.destination_type), "Invalid destination type in 'commit' instruction");

        // Retrieve the input and randomizer.
        let input = registers.load(stack, &self.operands[0])?;
        let randomizer = registers.load(stack, &self.operands[1])?;
        // Retrieve the randomizer.
        let randomizer = match randomizer {
            Value::Plaintext(Plaintext::Literal(Literal::Scalar(randomizer), ..)) => randomizer,
            _ => bail!("Invalid randomizer type for the commit evaluation, expected a scalar"),
        };

        let output = evaluate_commit_internal(VARIANT, &input, &randomizer, self.destination_type)?;

        // Store the output.
        registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(output)))
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        use circuit::traits::{ToBits, ToBitsRaw};

        // Ensure the number of operands is correct.
        if self.operands.len() != 2 {
            bail!("Instruction '{}' expects 2 operands, found {} operands", Self::opcode(), self.operands.len())
        }
        // Ensure the destination type is valid.
        ensure!(is_valid_destination_type(self.destination_type), "Invalid destination type in 'commit' instruction");

        // Retrieve the input and randomizer.
        let input = registers.load_circuit(stack, &self.operands[0])?;
        let randomizer = registers.load_circuit(stack, &self.operands[1])?;
        // Retrieve the randomizer.
        let randomizer = match randomizer {
            circuit::Value::Plaintext(circuit::Plaintext::Literal(circuit::Literal::Scalar(randomizer), ..)) => {
                randomizer
            }
            _ => bail!("Invalid randomizer type for the commit execution, expected a scalar"),
        };

        let output =
            do_commit!(A, VARIANT, self.destination_type, &input, &randomizer, circuit::Literal<A>, Result::<_>::Ok);

        // Convert the output to a stack value.
        let output = circuit::Value::Plaintext(circuit::Plaintext::Literal(output, Default::default()));
        // Store the output.
        registers.store_circuit(stack, &self.destination, output)
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
        _stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        if input_types.len() != 2 {
            bail!("Instruction '{}' expects 2 inputs, found {} inputs", Self::opcode(), input_types.len())
        }
        // Ensure the number of operands is correct.
        if self.operands.len() != 2 {
            bail!("Instruction '{}' expects 2 operands, found {} operands", Self::opcode(), self.operands.len())
        }
        // Ensure the destination type is valid.
        ensure!(is_valid_destination_type(self.destination_type), "Invalid destination type in 'commit' instruction");

        // TODO (howardwu): If the operation is Pedersen, check that it is within the number of bits.

        match VARIANT {
            0..=11 => Ok(vec![RegisterType::Plaintext(PlaintextType::Literal(self.destination_type))]),
            12.. => bail!("Invalid 'commit' variant: {VARIANT}"),
        }
    }
}

impl<N: Network, const VARIANT: u8> Parser for CommitInstruction<N, VARIANT> {
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
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "into" from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "as" from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register type from the string.
        let (string, destination_type) = LiteralType::parse(string)?;
        // Ensure the destination type is allowed.
        match destination_type {
            LiteralType::Address | LiteralType::Field | LiteralType::Group => {
                Ok((string, Self { operands: vec![first, second], destination, destination_type }))
            }
            _ => map_res(fail, |_: ParserResult<Self>| {
                Err(error(format!("Failed to parse 'commit': '{destination_type}' is invalid")))
            })(string),
        }
    }
}

impl<N: Network, const VARIANT: u8> FromStr for CommitInstruction<N, VARIANT> {
    type Err = Error;

    /// Parses a string into an operation.
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

impl<N: Network, const VARIANT: u8> Debug for CommitInstruction<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for CommitInstruction<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is 2.
        if self.operands.len() != 2 {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {} as {}", self.destination, self.destination_type)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for CommitInstruction<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(2);
        // Read the operands.
        for _ in 0..2 {
            operands.push(Operand::read_le(&mut reader)?);
        }
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;
        // Read the destination register type.
        let destination_type = LiteralType::read_le(&mut reader)?;

        // Return the operation.
        Self::new(operands, destination, destination_type).map_err(error)
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for CommitInstruction<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is 2.
        if self.operands.len() != 2 {
            return Err(error(format!("The number of operands must be 2, found {}", self.operands.len())));
        }
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the destination register.
        self.destination.write_le(&mut writer)?;
        // Write the destination register type.
        self.destination_type.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    /// **Attention**: When changing this, also update in `tests/instruction/commit.rs`.
    fn valid_destination_types() -> &'static [LiteralType] {
        &[LiteralType::Address, LiteralType::Field, LiteralType::Group]
    }

    #[test]
    fn test_parse() {
        for destination_type in valid_destination_types() {
            let instruction = format!("commit.bhp512 r0 r1 into r2 as {destination_type}");
            let (string, commit) = CommitBHP512::<CurrentNetwork>::parse(&instruction).unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            assert_eq!(commit.operands.len(), 2, "The number of operands is incorrect");
            assert_eq!(commit.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
            assert_eq!(commit.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
            assert_eq!(commit.destination, Register::Locator(2), "The destination register is incorrect");
            assert_eq!(commit.destination_type, *destination_type, "The destination type is incorrect");
        }
    }

    #[test]
    fn test_parse_raw() {
        for destination_type in valid_destination_types() {
            let instruction = format!("commit.bhp256.raw r0 r1 into r2 as {destination_type}");
            let (string, commit) = CommitBHP256Raw::<CurrentNetwork>::parse(&instruction).unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            assert_eq!(commit.operands.len(), 2, "The number of operands is incorrect");
            assert_eq!(commit.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
            assert_eq!(commit.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
            assert_eq!(commit.destination, Register::Locator(2), "The destination register is incorrect");
            assert_eq!(commit.destination_type, *destination_type, "The destination type is incorrect");
        }
    }

    #[test]
    fn test_raw_differs_from_standard() {
        use console::{
            program::{Literal, Plaintext, Value},
            types::{Field, Scalar},
        };

        type N = CurrentNetwork;

        // Use a non-trivial field literal (not zero) so the bits actually differ between
        // to_bits_le (type-tagged) and to_bits_raw_le (untagged).
        let input_field = Field::<N>::one();
        let randomizer = Scalar::<N>::one();
        let value = Value::Plaintext(Plaintext::from(Literal::Field(input_field)));

        let standard = evaluate_commit(CommitVariant::CommitBHP256, &value, &randomizer, LiteralType::Field).unwrap();
        let raw = evaluate_commit(CommitVariant::CommitBHP256Raw, &value, &randomizer, LiteralType::Field).unwrap();

        assert_ne!(
            standard, raw,
            "commit.bhp256 and commit.bhp256.raw must produce different outputs for the same input"
        );

        // Check that committing on the field element is equivalent to the raw commit via the instruction.
        let expected_commitment = N::commit_bhp256(&input_field.to_bits_le(), &randomizer).unwrap();
        assert_eq!(Literal::Field(expected_commitment), raw);
    }
}
