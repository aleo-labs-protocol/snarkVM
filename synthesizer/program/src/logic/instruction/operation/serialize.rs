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
    program::{ArrayType, Identifier, LiteralType, Locator, Plaintext, PlaintextType, Register, RegisterType, Value},
};

/// Serializes the bits of the input.
pub type SerializeBits<N> = SerializeInstruction<N, { SerializeVariant::ToBits as u8 }>;
/// Serializes the raw bits of the input.
pub type SerializeBitsRaw<N> = SerializeInstruction<N, { SerializeVariant::ToBitsRaw as u8 }>;

/// The serialize variant.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SerializeVariant {
    ToBits,
    ToBitsRaw,
}

impl SerializeVariant {
    // Returns the opcode associated with the variant.
    pub const fn opcode(variant: u8) -> &'static str {
        match variant {
            0 => "serialize.bits",
            1 => "serialize.bits.raw",
            _ => panic!("Invalid 'serialize' instruction opcode"),
        }
    }
}

/// Checks that the number of operands is correct.
fn check_number_of_operands(variant: u8, num_operands: usize) -> Result<()> {
    if num_operands != 1 {
        bail!("Instruction '{}' expects 1 operand, found {num_operands} operands", SerializeVariant::opcode(variant))
    }
    Ok(())
}

/// Checks that the operand type is valid.
fn check_operand_type_is_valid(variant: u8, operand_type: &PlaintextType<impl Network>) -> Result<()> {
    // A helper function to check a literal type.
    fn check_literal_type(literal_type: &LiteralType) -> Result<()> {
        match literal_type {
            LiteralType::Address
            | LiteralType::Boolean
            | LiteralType::Field
            | LiteralType::Group
            | LiteralType::I8
            | LiteralType::I16
            | LiteralType::I32
            | LiteralType::I64
            | LiteralType::I128
            | LiteralType::U8
            | LiteralType::U16
            | LiteralType::U32
            | LiteralType::U64
            | LiteralType::U128
            | LiteralType::Scalar
            | LiteralType::Identifier => Ok(()),
            _ => bail!("Invalid literal type '{literal_type}' for 'serialize' instruction"),
        }
    }

    match operand_type {
        PlaintextType::Literal(literal_type) => check_literal_type(literal_type),
        PlaintextType::Array(array_type) => match array_type.base_element_type() {
            PlaintextType::Literal(literal_type) => check_literal_type(literal_type),
            _ => bail!("Invalid element type '{array_type}' for 'serialize' instruction"),
        },
        _ => bail!("Instruction '{}' cannot take type '{operand_type}' as input", SerializeVariant::opcode(variant)),
    }
}

/// Check that the destination type is valid.
fn check_destination_type_is_valid(variant: u8, destination_type: &ArrayType<impl Network>) -> Result<()> {
    match (variant, destination_type) {
        (0 | 1, array_type) if array_type.is_bit_array() => Ok(()),
        _ => {
            bail!("Instruction '{}' cannot output type '{destination_type}'", SerializeVariant::opcode(variant))
        }
    }
}

/// Serialize the operand into the declared type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SerializeInstruction<N: Network, const VARIANT: u8> {
    /// The operand as `input`.
    operands: Vec<Operand<N>>,
    /// The operand type.
    operand_type: PlaintextType<N>,
    /// The destination register.
    destination: Register<N>,
    /// The destination register type.
    destination_type: ArrayType<N>,
}

impl<N: Network, const VARIANT: u8> SerializeInstruction<N, VARIANT> {
    /// Initializes a new `serialize` instruction.
    pub fn new(
        operands: Vec<Operand<N>>,
        operand_type: PlaintextType<N>,
        destination: Register<N>,
        destination_type: ArrayType<N>,
    ) -> Result<Self> {
        // Sanity check the number of operands.
        check_number_of_operands(VARIANT, operands.len())?;
        // Ensure that the operand type is valid.
        check_operand_type_is_valid(VARIANT, &operand_type)?;
        // Sanity check the destination type.
        check_destination_type_is_valid(VARIANT, &destination_type)?;
        // Return the instruction.
        Ok(Self { operands, operand_type, destination, destination_type })
    }

    /// Returns the opcode.
    pub const fn opcode() -> Opcode {
        Opcode::Serialize(SerializeVariant::opcode(VARIANT))
    }

    /// Returns the operands in the operation.
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that the operands is the correct length.
        if cfg!(debug_assertions) {
            check_number_of_operands(VARIANT, self.operands.len()).unwrap();
            check_operand_type_is_valid(VARIANT, &self.operand_type).unwrap();
            check_destination_type_is_valid(VARIANT, &self.destination_type).unwrap();
        }
        // Return the operand.
        &self.operands
    }

    /// Returns the operand type.
    pub const fn operand_type(&self) -> &PlaintextType<N> {
        &self.operand_type
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }

    /// Returns the destination register type.
    #[inline]
    pub const fn destination_type(&self) -> &ArrayType<N> {
        &self.destination_type
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        self.operand_type.contains_external_struct()
    }
}

/// Evaluate a `serialize` operation.
///
/// This allows running `serialize` without the machinery of stacks and registers.
/// This is necessary for the Leo interpreter.
pub fn evaluate_serialize<N: Network>(
    variant: SerializeVariant,
    input: &Value<N>,
    destination_type: &ArrayType<N>,
) -> Result<Value<N>> {
    evaluate_serialize_internal(variant as u8, input, destination_type)
}

fn evaluate_serialize_internal<N: Network>(
    variant: u8,
    input: &Value<N>,
    destination_type: &ArrayType<N>,
) -> Result<Value<N>> {
    match (variant, destination_type) {
        (0, array_type) if array_type.is_bit_array() => {
            // Get the desired length of the array.
            let length = **array_type.length();
            // Serialize the input to bits.
            let bits = input.to_bits_le();
            // Return the bits as a plaintext array.
            Ok(Value::Plaintext(Plaintext::from_bit_array(bits, length)?))
        }
        (1, array_type) if array_type.is_bit_array() => {
            // Get the desired length of the array.
            let length = **array_type.length();
            // Serialize the input to raw bits.
            let bits = input.to_bits_raw_le();
            // Return the bits as a plaintext array.
            Ok(Value::Plaintext(Plaintext::from_bit_array(bits, length)?))
        }
        _ => bail!(
            "Invalid destination type '{}' for instruction '{}'",
            destination_type,
            SerializeVariant::opcode(variant)
        ),
    }
}

impl<N: Network, const VARIANT: u8> SerializeInstruction<N, VARIANT> {
    /// Evaluates the instruction.
    pub fn evaluate(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersTrait<N>) -> Result<()> {
        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, self.operands.len())?;
        // Ensure that the operand type is valid.
        check_operand_type_is_valid(VARIANT, &self.operand_type)?;
        // Ensure the destination type is valid.
        check_destination_type_is_valid(VARIANT, &self.destination_type)?;

        // Load the operand.
        let input = registers.load(stack, &self.operands[0])?;

        let output = evaluate_serialize_internal(VARIANT, &input, &self.destination_type)?;

        // Store the output.
        registers.store(stack, &self.destination, output)
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        use crate::circuit::traits::{ToBits, ToBitsRaw};

        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, self.operands.len())?;
        // Ensure that the operand type is valid.
        check_operand_type_is_valid(VARIANT, &self.operand_type)?;
        // Ensure the destination type is valid.
        check_destination_type_is_valid(VARIANT, &self.destination_type)?;

        // Load the operand.
        let input = registers.load_circuit(stack, &self.operands[0])?;

        let output = match (VARIANT, &self.destination_type) {
            (0, array_type) if array_type.is_bit_array() => {
                // Get the desired length of the array.
                let length = **array_type.length();
                // Serialize the input to bits.
                let bits = input.to_bits_le();
                // Return the bits as a plaintext array.
                circuit::Value::Plaintext(circuit::Plaintext::from_bit_array(bits, length)?)
            }
            (1, array_type) if array_type.is_bit_array() => {
                // Get the desired length of the array.
                let length = **array_type.length();
                // Serialize the input to raw bits.
                let bits = input.to_bits_raw_le();
                // Return the bits as a plaintext array.
                circuit::Value::Plaintext(circuit::Plaintext::from_bit_array(bits, length)?)
            }
            _ => bail!("Invalid destination type '{}' for instruction '{}'", &self.destination_type, Self::opcode(),),
        };

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
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, self.operands.len())?;
        // Ensure the operand type is valid.
        check_operand_type_is_valid(VARIANT, &self.operand_type)?;
        // Ensure the destination type is valid.
        check_destination_type_is_valid(VARIANT, &self.destination_type)?;

        // Check that the input type matches the operand type.
        ensure!(input_types.len() == 1, "Expected exactly one input type");
        match &input_types[0] {
            RegisterType::Plaintext(plaintext_type) => {
                ensure!(
                    plaintext_type == &self.operand_type,
                    "Input type {} does not match operand type {}",
                    input_types[0],
                    self.operand_type
                )
            }
            type_ => bail!("Input type {type_} does not match operand type {}", self.operand_type),
        }

        // A helper to get a struct declaration.
        let get_struct = |identifier: &Identifier<N>| stack.program().get_struct(identifier).cloned();

        // A helper to get an external struct declaration.
        let get_external_struct = |locator: &Locator<N>| {
            stack.get_external_stack(locator.program_id())?.program().get_struct(locator.resource()).cloned()
        };

        // Get the size in bits of the operand.
        let size_in_bits = match VARIANT {
            0 => self.operand_type.size_in_bits(&get_struct, &get_external_struct)?,
            1 => self.operand_type.size_in_bits_raw(&get_struct, &get_external_struct)?,
            variant => bail!("Invalid `serialize` variant '{variant}'"),
        };

        // Check that the number of bits of the operand matches the destination.
        ensure!(
            size_in_bits == **self.destination_type.length() as usize,
            "The number of bits of the operand '{size_in_bits}' does not match the destination '{}'",
            **self.destination_type.length()
        );

        Ok(vec![RegisterType::Plaintext(PlaintextType::Array(self.destination_type.clone()))])
    }
}

impl<N: Network, const VARIANT: u8> Parser for SerializeInstruction<N, VARIANT> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parse the operands from the string.
        fn parse_operands<N: Network>(string: &str, num_operands: usize) -> ParserResult<'_, Vec<Operand<N>>> {
            let mut operands = Vec::with_capacity(num_operands);
            let mut string = string;

            for _ in 0..num_operands {
                // Parse the whitespace from the string.
                let (next_string, _) = Sanitizer::parse_whitespaces(string)?;
                // Parse the operand from the string.
                let (next_string, operand) = Operand::parse(next_string)?;
                // Update the string.
                string = next_string;
                // Push the operand.
                operands.push(operand);
            }

            Ok((string, operands))
        }

        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the operands from the string.
        let (string, operands) = parse_operands(string, 1)?;

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "(" from the string.
        let (string, _) = tag("(")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the operand type from the string.
        let (string, operand_type) = PlaintextType::parse(string)?;
        // Parse the ")" from the string.
        let (string, _) = tag(")")(string)?;

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
        // Parse the "(" from the string.
        let (string, _) = tag("(")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register type from the string.
        let (string, destination_type) = ArrayType::parse(string)?;
        // Parse the ")" from the string.
        let (string, _) = tag(")")(string)?;

        // Construct the instruction, checking for errors.
        match Self::new(operands, operand_type, destination, destination_type) {
            Ok(instruction) => Ok((string, instruction)),
            Err(e) => map_res(fail, |_: ParserResult<Self>| {
                Err(error(format!("Failed to parse '{}' instruction: {e}", Self::opcode())))
            })(string),
        }
    }
}

impl<N: Network, const VARIANT: u8> FromStr for SerializeInstruction<N, VARIANT> {
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

impl<N: Network, const VARIANT: u8> Debug for SerializeInstruction<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for SerializeInstruction<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, " ({}) into {} ({})", self.operand_type, self.destination, self.destination_type)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for SerializeInstruction<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the operand.
        let operand = Operand::read_le(&mut reader)?;
        // Read the operand type.
        let operand_type = PlaintextType::read_le(&mut reader)?;
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;
        // Read the destination register type.
        let destination_type = ArrayType::read_le(&mut reader)?;
        // Return the operation.
        match Self::new(vec![operand], operand_type, destination, destination_type) {
            Ok(instruction) => Ok(instruction),
            Err(e) => Err(error(format!("Failed to read '{}' instruction: {e}", Self::opcode()))),
        }
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for SerializeInstruction<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the operand type.
        self.operand_type.write_le(&mut writer)?;
        // Write the destination register.
        self.destination.write_le(&mut writer)?;
        // Write the destination register type.
        self.destination_type.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{network::MainnetV0, types::U32};

    type CurrentNetwork = MainnetV0;

    /// **Attention**: When changing this, also update in `tests/instruction/serialize.rs`.
    fn valid_source_types<N: Network>() -> &'static [PlaintextType<N>] {
        &[
            PlaintextType::Literal(LiteralType::Address),
            PlaintextType::Literal(LiteralType::Field),
            PlaintextType::Literal(LiteralType::Group),
            PlaintextType::Literal(LiteralType::I8),
            PlaintextType::Literal(LiteralType::I16),
            PlaintextType::Literal(LiteralType::I32),
            PlaintextType::Literal(LiteralType::I128),
            PlaintextType::Literal(LiteralType::I64),
            PlaintextType::Literal(LiteralType::U8),
            PlaintextType::Literal(LiteralType::U16),
            PlaintextType::Literal(LiteralType::U32),
            PlaintextType::Literal(LiteralType::U64),
            PlaintextType::Literal(LiteralType::U128),
            PlaintextType::Literal(LiteralType::Scalar),
            PlaintextType::Literal(LiteralType::Identifier),
        ]
    }

    /// Randomly sample a destination type.
    fn sample_destination_type<N: Network, const VARIANT: u8>(rng: &mut TestRng) -> ArrayType<N> {
        // Generate a random array length between 1 and N::LATEST_MAX_ARRAY_ELEMENTS().
        let array_length = 1 + (u32::rand(rng) % u32::try_from(N::LATEST_MAX_ARRAY_ELEMENTS()).unwrap());
        match VARIANT {
            0 | 1 => {
                ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(array_length)]).unwrap()
            }
            _ => panic!("Invalid variant"),
        }
    }

    fn run_parser_test<const VARIANT: u8>(rng: &mut TestRng) {
        for source_type in valid_source_types() {
            {
                let opcode = SerializeVariant::opcode(VARIANT);
                let destination_type = sample_destination_type::<CurrentNetwork, VARIANT>(rng);
                let instruction = format!("{opcode} r0 ({source_type}) into r1 ({destination_type})");
                println!("Parsing instruction: '{instruction}'");

                let (string, serialize) = SerializeInstruction::<CurrentNetwork, VARIANT>::parse(&instruction).unwrap();
                assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
                assert_eq!(serialize.operands.len(), 1, "The number of operands is incorrect");
                assert_eq!(
                    serialize.operands[0],
                    Operand::Register(Register::Locator(0)),
                    "The first operand is incorrect"
                );
                assert_eq!(&serialize.operand_type, source_type, "The operand type is incorrect");
                assert_eq!(serialize.destination, Register::Locator(1), "The destination register is incorrect");
                assert_eq!(&serialize.destination_type, &destination_type, "The destination type is incorrect");
            }
        }
    }

    #[test]
    fn test_parse() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Run the parser test for each variant.
        run_parser_test::<{ SerializeVariant::ToBits as u8 }>(rng);
        run_parser_test::<{ SerializeVariant::ToBitsRaw as u8 }>(rng);

        SerializeBitsRaw::<CurrentNetwork>::from_str("serialize.bits.raw r0 (boolean) into r1 ([boolean; 1u32])")
            .unwrap();
    }
}
