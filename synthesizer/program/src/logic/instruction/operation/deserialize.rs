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
    program::{
        ArrayType,
        Identifier,
        Literal,
        LiteralType,
        Locator,
        Plaintext,
        PlaintextType,
        Register,
        RegisterType,
        StructType,
        U8,
        U16,
        U32,
        Value,
    },
};

use indexmap::IndexMap;

/// Deserializes the bits into a value.
pub type DeserializeBits<N> = DeserializeInstruction<N, { DeserializeVariant::FromBits as u8 }>;
/// Deserializes the raw bits into a value.
pub type DeserializeBitsRaw<N> = DeserializeInstruction<N, { DeserializeVariant::FromBitsRaw as u8 }>;

/// The deserialization variant.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DeserializeVariant {
    FromBits,
    FromBitsRaw,
}

impl DeserializeVariant {
    // Returns the opcode associated with the variant.
    pub const fn opcode(variant: u8) -> &'static str {
        match variant {
            0 => "deserialize.bits",
            1 => "deserialize.bits.raw",
            _ => panic!("Invalid 'deserialize' instruction opcode"),
        }
    }

    // Returns the variant, given a `u8`.
    pub const fn from_u8(variant: u8) -> Self {
        match variant {
            0 => Self::FromBits,
            1 => Self::FromBitsRaw,
            _ => panic!("Invalid 'deserialize' instruction variant"),
        }
    }
}

/// Checks that the number of operands is correct.
fn check_number_of_operands(variant: u8, num_operands: usize) -> Result<()> {
    if num_operands != 1 {
        bail!("Instruction '{}' expects 1 operand, found {num_operands} operands", DeserializeVariant::opcode(variant))
    }
    Ok(())
}

/// Checks that the operand type is valid.
fn check_operand_type_is_valid(variant: u8, array_type: &ArrayType<impl Network>) -> Result<()> {
    match variant {
        0 | 1 if array_type.is_bit_array() => Ok(()),
        _ => {
            bail!("Instruction '{}' cannot output type '{array_type}'", DeserializeVariant::opcode(variant))
        }
    }
}

/// Check that the destination type is valid.
fn check_destination_type_is_valid(variant: u8, destination_type: &PlaintextType<impl Network>) -> Result<()> {
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
            _ => bail!("Invalid literal type '{literal_type}' for 'deserialize' instruction"),
        }
    }

    match destination_type {
        PlaintextType::Literal(literal_type) => check_literal_type(literal_type),
        PlaintextType::Array(array_type) => match array_type.base_element_type() {
            PlaintextType::Literal(literal_type) => check_literal_type(literal_type),
            _ => bail!("Invalid element type '{array_type}' for 'deserialize' instruction"),
        },
        _ => bail!(
            "Instruction '{}' cannot take type '{destination_type}' as input",
            DeserializeVariant::opcode(variant)
        ),
    }
}

/// Deserializes the operand into the declared type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeserializeInstruction<N: Network, const VARIANT: u8> {
    /// The operand as `input`.
    operands: Vec<Operand<N>>,
    /// The operand type.
    operand_type: ArrayType<N>,
    /// The destination register.
    destination: Register<N>,
    /// The destination register type.
    destination_type: PlaintextType<N>,
}

impl<N: Network, const VARIANT: u8> DeserializeInstruction<N, VARIANT> {
    /// Initializes a new `deserialize` instruction.
    pub fn new(
        operands: Vec<Operand<N>>,
        operand_type: ArrayType<N>,
        destination: Register<N>,
        destination_type: PlaintextType<N>,
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
        Opcode::Deserialize(DeserializeVariant::opcode(VARIANT))
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
    pub const fn operand_type(&self) -> &ArrayType<N> {
        &self.operand_type
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }

    /// Returns the destination register type.
    #[inline]
    pub const fn destination_type(&self) -> &PlaintextType<N> {
        &self.destination_type
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        self.destination_type.contains_external_struct()
    }
}

/// Evaluate a `deserialize` operation.
///
/// This allows running `deserialize` without the machinery of stacks and registers.
/// This is necessary for the Leo interpreter.
pub fn evaluate_deserialize<N: Network, F0, F1>(
    variant: DeserializeVariant,
    bits: &[bool],
    destination_type: &PlaintextType<N>,
    get_struct: &F0,
    get_external_struct: &F1,
) -> Result<Plaintext<N>>
where
    F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
    F1: Fn(&Locator<N>) -> Result<StructType<N>>,
{
    evaluate_deserialize_internal(variant as u8, bits, destination_type, get_struct, get_external_struct, 0)
}

fn evaluate_deserialize_internal<N: Network, F0, F1>(
    variant: u8,
    bits: &[bool],
    destination_type: &PlaintextType<N>,
    get_struct: &F0,
    get_external_struct: &F1,
    depth: usize,
) -> Result<Plaintext<N>>
where
    F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
    F1: Fn(&Locator<N>) -> Result<StructType<N>>,
{
    // Ensure that the depth is within the maximum limit.
    if depth > N::MAX_DATA_DEPTH {
        bail!("Plaintext depth exceeds maximum limit: {}", N::MAX_DATA_DEPTH)
    }

    // A helper to get the number of bits needed.
    let get_size_in_bits = |plaintext_type: &PlaintextType<N>| -> Result<usize> {
        match DeserializeVariant::from_u8(variant) {
            DeserializeVariant::FromBits => plaintext_type.size_in_bits(get_struct, &get_external_struct),
            DeserializeVariant::FromBitsRaw => plaintext_type.size_in_bits_raw(get_struct, &get_external_struct),
        }
    };

    // Get the number of bits needed.
    let size_in_bits = get_size_in_bits(destination_type)?;

    // Check that the number of bits is correct.
    let bits = bits.to_vec();
    ensure!(
        bits.len() == size_in_bits,
        "The number of bits of the operand '{}' does not match the destination '{size_in_bits}'",
        bits.len()
    );

    // The starting index used to create subsequent subslices of the `bits` slice.
    let mut index = 0;

    // Helper function to get the next n bits as a slice.
    let mut next_bits = |n: usize| -> Result<&[bool]> {
        // Safely procure a subslice with the length `n` starting at `index`.
        let subslice = bits.get(index..index + n);
        // Check if the range is within bounds.
        if let Some(next_bits) = subslice {
            // Move the starting index.
            index += n;
            // Return the subslice.
            Ok(next_bits)
        } else {
            bail!("Insufficient bits");
        }
    };

    // Closure to deserialize a struct from a resolved `StructType<N>`.
    let mut deserialize_struct = |struct_: &StructType<N>| -> Result<Plaintext<N>> {
        // If the variant is `FromBits`, check the variant and metadata.
        if variant == (DeserializeVariant::FromBits as u8) {
            let plaintext_variant = next_bits(2)?;
            let plaintext_variant = [plaintext_variant[0], plaintext_variant[1]];
            ensure!(
                plaintext_variant == PlaintextType::<N>::STRUCT_PREFIX_BITS,
                "Invalid plaintext variant for struct type"
            );

            let num_members = u8::from_bits_le(next_bits(8)?)?;
            ensure!(struct_.members().len() == num_members as usize, "Struct exceeds maximum of entries.");
        }

        // Get the members.
        let mut members = IndexMap::with_capacity(struct_.members().len());

        for (member_identifier, member_type) in struct_.members().iter() {
            let expected_member_size = get_size_in_bits(member_type)?;

            if variant == (DeserializeVariant::FromBits as u8) {
                let identifier_size = u8::from_bits_le(next_bits(8)?)?;
                ensure!(
                    member_identifier.size_in_bits() == identifier_size,
                    "Mismatched identifier size. Expected '{}', found '{}'",
                    member_identifier.size_in_bits(),
                    identifier_size
                );

                let identifier_bits = next_bits(identifier_size as usize)?;
                let identifier = Identifier::<N>::from_bits_le(identifier_bits)?;
                ensure!(
                    *member_identifier == identifier,
                    "Mismatched identifier. Expected '{member_identifier}', found '{identifier}'",
                );

                let member_size = u16::from_bits_le(next_bits(16)?)?;
                ensure!(
                    member_size as usize == expected_member_size,
                    "Mismatched member size. Expected '{expected_member_size}', found '{member_size}'",
                );
            }

            let value = evaluate_deserialize_internal(
                variant,
                next_bits(expected_member_size)?,
                member_type,
                get_struct,
                get_external_struct,
                depth + 1,
            )?;

            if members.insert(*member_identifier, value).is_some() {
                bail!("Duplicate identifier in struct.");
            }
        }

        Ok(Plaintext::Struct(members, Default::default()))
    };

    match destination_type {
        PlaintextType::Literal(literal_type) => {
            // Get the expected size of the literal.
            let expected_size = literal_type.size_in_bits::<N>();

            // If the variant is `FromBits`, check the variant and metadata.
            if variant == (DeserializeVariant::FromBits as u8) {
                let plaintext_variant = next_bits(2)?;
                let plaintext_variant = [plaintext_variant[0], plaintext_variant[1]];
                ensure!(
                    plaintext_variant == PlaintextType::<N>::LITERAL_PREFIX_BITS,
                    "Invalid plaintext variant for literal type '{literal_type}'"
                );

                let literal_variant = u8::from_bits_le(next_bits(8)?)?;
                ensure!(
                    literal_variant == literal_type.type_id(),
                    "Mismatched literal type. Expected '{literal_type}', found '{literal_variant}'"
                );

                let literal_size = u16::from_bits_le(next_bits(16)?)?;
                ensure!(
                    literal_size == expected_size,
                    "Mismatched literal size. Expected '{expected_size}', found '{literal_size}'",
                );
            };
            // Deserialize the literal.
            let literal = Literal::from_bits_le(literal_type.type_id(), next_bits(expected_size as usize)?)?;
            Ok(Plaintext::Literal(literal, Default::default()))
        }
        PlaintextType::Struct(identifier) => {
            // Get the struct.
            let struct_ = get_struct(identifier)?;
            deserialize_struct(&struct_)
        }
        PlaintextType::ExternalStruct(locator) => {
            // Get the external struct.
            let struct_ = get_external_struct(locator)?;
            deserialize_struct(&struct_)
        }
        PlaintextType::Array(array_type) => {
            // If the variant is `FromBits`, check the variant and metadata.
            if variant == (DeserializeVariant::FromBits as u8) {
                let plaintext_variant = next_bits(2)?;
                let plaintext_variant = [plaintext_variant[0], plaintext_variant[1]];
                ensure!(
                    plaintext_variant == PlaintextType::<N>::ARRAY_PREFIX_BITS,
                    "Invalid plaintext variant for array type"
                );

                let num_elements = u32::from_bits_le(next_bits(32)?)?;
                ensure!(
                    **array_type.length() == num_elements,
                    "Mismatched array length. Expected '{}', found '{}'",
                    **array_type.length(),
                    num_elements
                );
            }

            let expected_element_type = array_type.next_element_type();
            let expected_element_size = get_size_in_bits(expected_element_type)?;

            let mut elements = Vec::with_capacity(**array_type.length() as usize);

            for _ in 0..**array_type.length() {
                if variant == (DeserializeVariant::FromBits as u8) {
                    let element_size = u16::from_bits_le(next_bits(16)?)?;
                    ensure!(
                        element_size as usize == expected_element_size,
                        "Mismatched element size. Expected '{expected_element_size}', found '{element_size}'",
                    );
                }
                let element = evaluate_deserialize_internal(
                    variant,
                    next_bits(expected_element_size)?,
                    expected_element_type,
                    get_struct,
                    get_external_struct,
                    depth + 1,
                )?;
                elements.push(element);
            }

            // Cache the plaintext bits, and return the array.
            Ok(Plaintext::Array(elements, Default::default()))
        }
    }
}

fn execute_deserialize_internal<A: circuit::Aleo<Network = N>, N: Network, F0, F1>(
    variant: u8,
    bits: &[circuit::Boolean<A>],
    destination_type: &PlaintextType<N>,
    get_struct: &F0,
    get_external_struct: &F1,
    depth: usize,
) -> Result<circuit::Plaintext<A>>
where
    F0: Fn(&Identifier<N>) -> Result<StructType<N>>,
    F1: Fn(&Locator<N>) -> Result<StructType<N>>,
{
    use snarkvm_circuit::{Inject, traits::FromBits};

    // Ensure that the depth is within the maximum limit.
    if depth > A::Network::MAX_DATA_DEPTH {
        bail!("Plaintext depth exceeds maximum limit: {}", N::MAX_DATA_DEPTH)
    }

    // A helper to get the number of bits needed.
    let get_size_in_bits = |plaintext_type: &PlaintextType<N>| -> Result<usize> {
        match DeserializeVariant::from_u8(variant) {
            DeserializeVariant::FromBits => plaintext_type.size_in_bits(get_struct, get_external_struct),
            DeserializeVariant::FromBitsRaw => plaintext_type.size_in_bits_raw(get_struct, get_external_struct),
        }
    };

    // Get the number of bits needed.
    let size_in_bits = get_size_in_bits(destination_type)?;

    // Check that the number of bits is correct.
    let bits = bits.to_vec();
    ensure!(
        bits.len() == size_in_bits,
        "The number of bits of the operand '{}' does not match the destination '{size_in_bits}'",
        bits.len()
    );

    // The starting index used to create subsequent subslices of the `bits` slice.
    let mut index = 0;

    // Helper function to get the next n bits as a slice.
    let mut next_bits = |n: usize| -> Result<&[circuit::Boolean<A>]> {
        // Safely procure a subslice with the length `n` starting at `index`.
        let subslice = bits.get(index..index + n);
        // Check if the range is within bounds.
        if let Some(next_bits) = subslice {
            // Move the starting index.
            index += n;
            // Return the subslice.
            Ok(next_bits)
        } else {
            bail!("Insufficient bits");
        }
    };

    // Closure to deserialize a struct from a resolved `StructType<N>`.
    let mut deserialize_struct = |struct_: &StructType<N>| -> Result<circuit::Plaintext<A>> {
        // Get the expected number of members.
        let expected_num_members =
            u8::try_from(struct_.members().len()).map_err(|_| anyhow!("Struct exceeds maximum of entries."))?;

        // If the variant is `FromBits`, check the variant and metadata.
        if variant == (DeserializeVariant::FromBits as u8) {
            let plaintext_variant = next_bits(2)?;
            let expected_bits = PlaintextType::<A::Network>::STRUCT_PREFIX_BITS.map(circuit::Boolean::<A>::constant);
            A::assert_eq(&expected_bits[0], &plaintext_variant[0])?;
            A::assert_eq(&expected_bits[1], &plaintext_variant[1])?;

            let num_members = circuit::U8::<A>::from_bits_le(next_bits(8)?);
            A::assert_eq(num_members, circuit::U8::<A>::constant(U8::new(expected_num_members)))?;
        }

        // Get the members.
        let mut members = IndexMap::with_capacity(struct_.members().len());

        for (member_identifier, member_type) in struct_.members().iter() {
            // Get the expected member size.
            let expected_member_size = u16::try_from(get_size_in_bits(member_type)?)
                .map_err(|_| anyhow!("Member size exceeds maximum of 65535 bits."))?;

            // If the variant is `FromBits`, check the member metadata.
            if variant == (DeserializeVariant::FromBits as u8) {
                let expected_identifier_size = member_identifier.size_in_bits();
                let identifier_size = circuit::U8::<A>::from_bits_le(next_bits(8)?);
                A::assert_eq(&identifier_size, circuit::U8::<A>::constant(U8::new(expected_identifier_size)))?;

                let identifier_bits = next_bits(expected_identifier_size as usize)?;
                let identifier = circuit::Identifier::<A>::from_bits_le(identifier_bits);
                A::assert_eq(circuit::Identifier::<A>::constant(*member_identifier), &identifier)?;

                let member_size = circuit::U16::<A>::from_bits_le(next_bits(16)?);
                A::assert_eq(&member_size, circuit::U16::<A>::constant(U16::new(expected_member_size)))?;
            }

            let value = execute_deserialize_internal(
                variant,
                next_bits(expected_member_size as usize)?,
                member_type,
                get_struct,
                get_external_struct,
                depth + 1,
            )?;

            if members.insert(circuit::Identifier::constant(*member_identifier), value).is_some() {
                bail!("Duplicate identifier in struct.");
            }
        }

        // Cache the plaintext bits, and return the struct.
        Ok(circuit::Plaintext::Struct(members, Default::default()))
    };

    match destination_type {
        PlaintextType::Literal(literal_type) => {
            // Get the expected size of the literal.
            let expected_size = literal_type.size_in_bits::<A::Network>();

            // If the variant is `FromBits`, check the variant and metadata.
            if variant == (DeserializeVariant::FromBits as u8) {
                let plaintext_variant = next_bits(2)?;
                let expected_bits =
                    PlaintextType::<A::Network>::LITERAL_PREFIX_BITS.map(circuit::Boolean::<A>::constant);
                A::assert_eq(&expected_bits[0], &plaintext_variant[0])?;
                A::assert_eq(&expected_bits[1], &plaintext_variant[1])?;

                let literal_variant = circuit::U8::<A>::from_bits_le(next_bits(8)?);
                A::assert_eq(&literal_variant, circuit::U8::<A>::constant(U8::new(literal_type.type_id())))?;

                let literal_size = circuit::U16::<A>::from_bits_le(next_bits(16)?);
                A::assert_eq(&literal_size, circuit::U16::<A>::constant(U16::new(expected_size)))?;
            };
            // Deserialize the literal.
            let literal = circuit::Literal::<A>::from_bits_le(
                &circuit::U8::<A>::constant(U8::new(literal_type.type_id())),
                next_bits(expected_size as usize)?,
            );
            Ok(circuit::Plaintext::from(literal))
        }
        PlaintextType::Struct(identifier) => {
            // Get the struct.
            let struct_ = get_struct(identifier)?;
            deserialize_struct(&struct_)
        }
        PlaintextType::ExternalStruct(_identifier) => {
            // Get the external struct.
            let struct_ = get_external_struct(_identifier)?;
            deserialize_struct(&struct_)
        }
        PlaintextType::Array(array_type) => {
            // Get the expected length of the array.
            let expected_length = **array_type.length();

            // If the variant is `FromBits`, check the variant and metadata.
            if variant == (DeserializeVariant::FromBits as u8) {
                let plaintext_variant = next_bits(2)?;
                let expected_bits = PlaintextType::<A::Network>::ARRAY_PREFIX_BITS.map(circuit::Boolean::<A>::constant);
                A::assert_eq(&expected_bits[0], &plaintext_variant[0])?;
                A::assert_eq(&expected_bits[1], &plaintext_variant[1])?;

                let num_elements = circuit::U32::<A>::from_bits_le(next_bits(32)?);
                A::assert_eq(&num_elements, circuit::U32::<A>::constant(U32::new(expected_length)))?;
            }

            let expected_element_type = array_type.next_element_type();
            let expected_element_size = u16::try_from(get_size_in_bits(expected_element_type)?)
                .map_err(|_| anyhow!("Element size exceeds maximum of 65535 bits."))?;

            let mut elements = Vec::with_capacity(expected_length as usize);

            for _ in 0..**array_type.length() {
                if variant == (DeserializeVariant::FromBits as u8) {
                    let element_size = circuit::U16::<A>::from_bits_le(next_bits(16)?);
                    A::assert_eq(&element_size, circuit::U16::<A>::constant(U16::new(expected_element_size)))?;
                }

                let element = execute_deserialize_internal(
                    variant,
                    next_bits(expected_element_size as usize)?,
                    expected_element_type,
                    get_struct,
                    get_external_struct,
                    depth + 1,
                )?;
                elements.push(element);
            }

            // Cache the plaintext bits, and return the array.
            Ok(circuit::Plaintext::Array(elements, Default::default()))
        }
    }
}

impl<N: Network, const VARIANT: u8> DeserializeInstruction<N, VARIANT> {
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

        // Get the bits of the operand.
        let bits = match input {
            Value::Plaintext(plaintext) => {
                // Get the plaintext as a bit array.
                plaintext.as_bit_array()?
            }
            _ => bail!("Expected input to be a plaintext bit array"),
        };

        // A helper to get a struct declaration.
        let get_struct = |identifier: &Identifier<N>| stack.program().get_struct(identifier).cloned();

        // A helper to get an external struct declaration.
        let get_external_struct = |locator: &Locator<N>| {
            stack.get_external_stack(locator.program_id())?.program().get_struct(locator.resource()).cloned()
        };

        // Get the size in bits of the operand.
        let size_in_bits = match VARIANT {
            0 => self.destination_type.size_in_bits(&get_struct, &get_external_struct)?,
            1 => self.destination_type.size_in_bits_raw(&get_struct, &get_external_struct)?,
            variant => bail!("Invalid `deserialize` variant '{variant}'"),
        };

        // Check that the number of bits matches the desired length.
        ensure!(
            bits.len() == size_in_bits as usize,
            "The number of bits of the operand '{}' does not match the destination '{size_in_bits}'",
            bits.len()
        );

        // Deserialize into the desired output.
        let output = evaluate_deserialize_internal(
            VARIANT,
            &bits,
            &self.destination_type,
            &get_struct,
            &get_external_struct,
            0,
        )?;

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
        check_number_of_operands(VARIANT, self.operands.len())?;
        // Ensure that the operand type is valid.
        check_operand_type_is_valid(VARIANT, &self.operand_type)?;
        // Ensure the destination type is valid.
        check_destination_type_is_valid(VARIANT, &self.destination_type)?;

        // Load the operand.
        let input = registers.load_circuit(stack, &self.operands[0])?;

        // Get the input as a bit array.
        let bits = match input {
            circuit::Value::Plaintext(plaintext) => plaintext.as_bit_array()?,
            _ => bail!("Expected input to be a plaintext"),
        };

        // A helper to get a struct declaration.
        let get_struct = |identifier: &Identifier<N>| stack.program().get_struct(identifier).cloned();

        // A helper to get an external struct declaration.
        let get_external_struct = |locator: &Locator<N>| {
            stack.get_external_stack(locator.program_id())?.program().get_struct(locator.resource()).cloned()
        };

        // Get the size in bits of the operand.
        let size_in_bits = match VARIANT {
            0 => self.destination_type.size_in_bits(&get_struct, &get_external_struct)?,
            1 => self.destination_type.size_in_bits_raw(&get_struct, &get_external_struct)?,
            variant => bail!("Invalid `deserialize` variant '{variant}'"),
        };

        // Check that the number of bits matches the desired length.
        ensure!(
            bits.len() == size_in_bits as usize,
            "The number of bits of the operand '{}' does not match the destination '{size_in_bits}'",
            bits.len()
        );

        // Deserialize the bits into the desired literal type.
        let output =
            execute_deserialize_internal(VARIANT, &bits, &self.destination_type, &get_struct, &get_external_struct, 0)?;

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
        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, self.operands.len())?;
        // Ensure the operand type is valid.
        check_operand_type_is_valid(VARIANT, &self.operand_type)?;
        // Ensure the destination type is valid.
        check_destination_type_is_valid(VARIANT, &self.destination_type)?;

        // Check that the input type matches the operand type.
        ensure!(input_types.len() == 1, "Expected exactly one input type");
        match &input_types[0] {
            RegisterType::Plaintext(PlaintextType::Array(array_type)) if array_type == &self.operand_type => {}
            _ => bail!("Input type {:?} does not match operand type {:?}", input_types[0], self.operand_type),
        }

        // A helper to get a struct declaration.
        let get_struct = |identifier: &Identifier<N>| stack.program().get_struct(identifier).cloned();

        // A helper to get an external struct declaration.
        let get_external_struct = |locator: &Locator<N>| {
            stack.get_external_stack(locator.program_id())?.program().get_struct(locator.resource()).cloned()
        };

        // Get the size in bits of the operand.
        let size_in_bits = match VARIANT {
            0 => self.destination_type.size_in_bits(&get_struct, &get_external_struct)?,
            1 => self.destination_type.size_in_bits_raw(&get_struct, &get_external_struct)?,
            variant => bail!("Invalid `deserialize` variant '{variant}'"),
        };

        // Check that the number of bits of the operand matches the destination.
        ensure!(
            **self.operand_type.length() as usize == size_in_bits,
            "The number of bits of the operand '{}' does not match the destination '{size_in_bits}'",
            **self.operand_type.length()
        );

        Ok(vec![RegisterType::Plaintext(self.destination_type.clone())])
    }
}

impl<N: Network, const VARIANT: u8> Parser for DeserializeInstruction<N, VARIANT> {
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
        let (string, operand_type) = ArrayType::parse(string)?;
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
        let (string, destination_type) = PlaintextType::parse(string)?;
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

impl<N: Network, const VARIANT: u8> FromStr for DeserializeInstruction<N, VARIANT> {
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

impl<N: Network, const VARIANT: u8> Debug for DeserializeInstruction<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for DeserializeInstruction<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, " ({}) into {} ({})", self.operand_type, self.destination, self.destination_type)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for DeserializeInstruction<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the operand.
        let operand = Operand::read_le(&mut reader)?;
        // Read the operand type.
        let operand_type = ArrayType::read_le(&mut reader)?;
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;
        // Read the destination register type.
        let destination_type = PlaintextType::read_le(&mut reader)?;
        // Return the operation.
        match Self::new(vec![operand], operand_type, destination, destination_type) {
            Ok(instruction) => Ok(instruction),
            Err(e) => Err(error(format!("Failed to read '{}' instruction: {e}", Self::opcode()))),
        }
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for DeserializeInstruction<N, VARIANT> {
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

    /// **Attention**: When changing this, also update in `tests/instruction/deserialize.rs`.
    fn valid_destination_types<N: Network>() -> &'static [PlaintextType<N>] {
        &[
            PlaintextType::Literal(LiteralType::Address),
            PlaintextType::Literal(LiteralType::Field),
            PlaintextType::Literal(LiteralType::Group),
            PlaintextType::Literal(LiteralType::I8),
            PlaintextType::Literal(LiteralType::I16),
            PlaintextType::Literal(LiteralType::I32),
            PlaintextType::Literal(LiteralType::I64),
            PlaintextType::Literal(LiteralType::I128),
            PlaintextType::Literal(LiteralType::U8),
            PlaintextType::Literal(LiteralType::U16),
            PlaintextType::Literal(LiteralType::U32),
            PlaintextType::Literal(LiteralType::U64),
            PlaintextType::Literal(LiteralType::U128),
            PlaintextType::Literal(LiteralType::Scalar),
            PlaintextType::Literal(LiteralType::Identifier),
        ]
    }

    /// Randomly sample a source type.
    fn sample_source_type<N: Network, const VARIANT: u8>(rng: &mut TestRng) -> ArrayType<N> {
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
        for destination_type in valid_destination_types::<CurrentNetwork>() {
            {
                let opcode = DeserializeVariant::opcode(VARIANT);
                let source_type = sample_source_type::<CurrentNetwork, VARIANT>(rng);
                let instruction = format!("{opcode} r0 ({source_type}) into r1 ({destination_type})",);
                println!("Parsing instruction: '{instruction}'");

                let (string, deserialize) =
                    DeserializeInstruction::<CurrentNetwork, VARIANT>::parse(&instruction).unwrap();
                assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
                assert_eq!(deserialize.operands.len(), 1, "The number of operands is incorrect");
                assert_eq!(
                    deserialize.operands[0],
                    Operand::Register(Register::Locator(0)),
                    "The first operand is incorrect"
                );
                assert_eq!(&deserialize.operand_type, &source_type, "The operand type is incorrect");
                assert_eq!(deserialize.destination, Register::Locator(1), "The destination register is incorrect");
                assert_eq!(&deserialize.destination_type, destination_type, "The destination type is incorrect");
            }
        }
    }

    #[test]
    fn test_parse() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Run the parser test for each variant.
        run_parser_test::<{ DeserializeVariant::FromBits as u8 }>(rng);
        run_parser_test::<{ DeserializeVariant::FromBitsRaw as u8 }>(rng);
    }
}
