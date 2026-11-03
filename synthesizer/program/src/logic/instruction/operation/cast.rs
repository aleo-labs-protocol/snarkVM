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
    RegistersSigner,
    RegistersTrait,
    StackTrait,
    types_equivalent,
};
use console::{
    network::prelude::*,
    program::{
        ArrayType,
        DynamicRecord,
        Entry,
        EntryType,
        Identifier,
        Literal,
        LiteralType,
        Locator,
        Owner,
        Plaintext,
        PlaintextType,
        Record,
        Register,
        RegisterType,
        StructType,
        Value,
        ValueType,
    },
    types::Field,
};

use indexmap::IndexMap;

/// The type of the cast operation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum CastType<N: Network> {
    GroupXCoordinate,
    GroupYCoordinate,
    Plaintext(PlaintextType<N>),
    Record(Identifier<N>),
    ExternalRecord(Locator<N>),
    DynamicRecord,
}

impl<N: Network> CastType<N> {
    /// Returns `true` if the cast type is an array and the size exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        matches!(self,
            Self::Plaintext(plaintext_type) if plaintext_type.exceeds_max_array_size(max_array_size))
    }

    /// Returns `true` if the cast type contains an identifier type.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        match self {
            Self::Plaintext(plaintext_type) => plaintext_type.contains_identifier_type(),
            _ => Ok(false),
        }
    }
}

impl<N: Network> Parser for CastType<N> {
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the cast type from the string.
        alt((
            map(tag("group.x"), |_| Self::GroupXCoordinate),
            map(tag("group.y"), |_| Self::GroupYCoordinate),
            // We match this variant outside its usual position to ensure "dynamic.record" is not
            // parsed as a static record with identifier "record"
            map(tag("dynamic.record"), |_| Self::DynamicRecord),
            map(pair(Locator::parse, tag(".record")), |(locator, _)| Self::ExternalRecord(locator)),
            map(pair(Identifier::parse, tag(".record")), |(identifier, _)| Self::Record(identifier)),
            map(PlaintextType::parse, Self::Plaintext),
        ))(string)
    }
}

impl<N: Network> Display for CastType<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::GroupXCoordinate => write!(f, "group.x"),
            Self::GroupYCoordinate => write!(f, "group.y"),
            Self::Plaintext(plaintext_type) => write!(f, "{plaintext_type}"),
            Self::Record(identifier) => write!(f, "{identifier}.record"),
            Self::ExternalRecord(locator) => write!(f, "{locator}.record"),
            Self::DynamicRecord => write!(f, "dynamic.record"),
        }
    }
}

impl<N: Network> Debug for CastType<N> {
    /// Prints the cast type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> FromStr for CastType<N> {
    type Err = Error;

    /// Returns a cast type from a string literal.
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

impl<N: Network> ToBytes for CastType<N> {
    /// Writes the cast type to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::GroupXCoordinate => 0u8.write_le(&mut writer),
            Self::GroupYCoordinate => 1u8.write_le(&mut writer),
            Self::Plaintext(plaintext_type) => {
                2u8.write_le(&mut writer)?;
                plaintext_type.write_le(&mut writer)
            }
            Self::Record(identifier) => {
                3u8.write_le(&mut writer)?;
                identifier.write_le(&mut writer)
            }
            Self::ExternalRecord(locator) => {
                4u8.write_le(&mut writer)?;
                locator.write_le(&mut writer)
            }
            Self::DynamicRecord => 5u8.write_le(&mut writer),
        }
    }
}

impl<N: Network> FromBytes for CastType<N> {
    /// Reads the cast type from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let variant = u8::read_le(&mut reader)?;
        match variant {
            0 => Ok(Self::GroupXCoordinate),
            1 => Ok(Self::GroupYCoordinate),
            2 => Ok(Self::Plaintext(PlaintextType::read_le(&mut reader)?)),
            3 => Ok(Self::Record(Identifier::read_le(&mut reader)?)),
            4 => Ok(Self::ExternalRecord(Locator::read_le(&mut reader)?)),
            5 => Ok(Self::DynamicRecord),
            6.. => Err(error(format!("Failed to deserialize cast type variant {variant}"))),
        }
    }
}

/// The `cast` instruction.
pub type Cast<N> = CastOperation<N, { CastVariant::Cast as u8 }>;
/// The `cast.lossy` instruction.
pub type CastLossy<N> = CastOperation<N, { CastVariant::CastLossy as u8 }>;

/// The variant of the cast operation.
enum CastVariant {
    Cast,
    CastLossy,
}

/// Casts the operands into the declared type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CastOperation<N: Network, const VARIANT: u8> {
    /// The operands.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
    /// The cast type.
    cast_type: CastType<N>,
}

impl<N: Network, const VARIANT: u8> CastOperation<N, VARIANT> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Cast(match VARIANT {
            0 => "cast",
            1 => "cast.lossy",
            2.. => panic!("Invalid cast variant"),
        })
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }

    #[inline]
    pub const fn cast_type(&self) -> &CastType<N> {
        &self.cast_type
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        matches!(&self.cast_type, CastType::Plaintext(plaintext_type) if plaintext_type.contains_external_struct())
    }

    /// Validates the operands and destination for a DynamicRecord cast.
    /// Returns an error if the cast type is DynamicRecord and the operands/destination are invalid.
    fn validate_dynamic_record_cast(
        cast_type: &CastType<N>,
        operands: &[Operand<N>],
        destination: &Register<N>,
    ) -> Result<()> {
        if *cast_type == CastType::DynamicRecord {
            // Casting to a dynamic record requires exactly one operand of the form r<i>.
            if operands.len() != 1 || !matches!(operands[0], Operand::Register(Register::Locator(_))) {
                bail!("Casting to a dynamic record requires a single operand of the form r<i>");
            }
            // Casting to a dynamic record requires a destination of the form r<i>.
            if !matches!(destination, Register::Locator(_)) {
                bail!("Casting to a dynamic record requires a destination of the form r<i>");
            }
        }
        Ok(())
    }
}

impl<N: Network, const VARIANT: u8> CastOperation<N, VARIANT> {
    /// Evaluates the instruction.
    pub fn evaluate(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersSigner<N>) -> Result<()> {
        // If the variant is `cast.lossy`, then check that the `cast_type` is a `PlaintextType::Literal`.
        if VARIANT == CastVariant::CastLossy as u8 {
            ensure!(
                matches!(self.cast_type, CastType::Plaintext(PlaintextType::Literal(..))),
                "`cast.lossy` is only supported for casting to a literal type"
            )
        }

        // Load the operands values.
        let inputs: Vec<_> = self.operands.iter().map(|operand| registers.load(stack, operand)).try_collect()?;

        match &self.cast_type {
            CastType::GroupXCoordinate => {
                ensure!(inputs.len() == 1, "Casting to a group x-coordinate requires exactly 1 operand");
                let field = match &inputs[0] {
                    Value::Plaintext(Plaintext::Literal(Literal::Group(group), ..)) => group.to_x_coordinate(),
                    _ => bail!("Casting to a group x-coordinate requires a group element"),
                };
                registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(Literal::Field(field))))
            }
            CastType::GroupYCoordinate => {
                ensure!(inputs.len() == 1, "Casting to a group y-coordinate requires exactly 1 operand");
                let field = match &inputs[0] {
                    Value::Plaintext(Plaintext::Literal(Literal::Group(group), ..)) => group.to_y_coordinate(),
                    _ => bail!("Casting to a group y-coordinate requires a group element"),
                };
                registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(Literal::Field(field))))
            }
            CastType::Plaintext(PlaintextType::Literal(literal_type)) => {
                ensure!(inputs.len() == 1, "Casting to a literal requires exactly 1 operand");
                let value = match &inputs[0] {
                    Value::Plaintext(Plaintext::Literal(literal, ..)) => match VARIANT {
                        0 => literal.cast(*literal_type)?,
                        1 => literal.cast_lossy(*literal_type)?,
                        2.. => unreachable!("Invalid cast variant"),
                    },
                    _ => bail!("Casting to a literal requires a literal"),
                };
                registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(value)))
            }
            CastType::Plaintext(PlaintextType::Struct(struct_name)) => {
                let plaintext = self.evaluate_cast_to_struct(stack, *struct_name, inputs)?;
                registers.store(stack, &self.destination, plaintext.into())
            }
            CastType::Plaintext(PlaintextType::ExternalStruct(locator)) => {
                let external_stack = stack.get_external_stack(locator.program_id())?;
                let plaintext = self.evaluate_cast_to_struct(&*external_stack, *locator.resource(), inputs)?;
                registers.store(stack, &self.destination, plaintext.into())
            }
            CastType::Plaintext(PlaintextType::Array(array_type)) => {
                self.cast_to_array(stack, registers, array_type, inputs)
            }
            CastType::Record(record_name) => {
                // Ensure the operands length is at least the minimum.
                if inputs.len() < N::MIN_RECORD_ENTRIES {
                    bail!("Casting to a record requires at least {} operand", N::MIN_RECORD_ENTRIES)
                }

                // Retrieve the struct and ensure it is defined in the program.
                let record_type = stack.program().get_record(record_name)?;

                // Ensure that the number of operands is equal to the number of record entries, including the `owner`.
                if inputs.len() != record_type.entries().len() + 1 {
                    bail!(
                        "Casting to the record {} requires {} operands, but {} were provided",
                        record_type.name(),
                        record_type.entries().len() + 1,
                        inputs.len()
                    )
                }

                // Initialize the record owner.
                let owner: Owner<N, Plaintext<N>> = match &inputs[0] {
                    // Ensure the entry is an address.
                    Value::Plaintext(Plaintext::Literal(Literal::Address(owner), ..)) => {
                        match record_type.owner().is_public() {
                            true => Owner::Public(*owner),
                            false => Owner::Private(Plaintext::Literal(Literal::Address(*owner), Default::default())),
                        }
                    }
                    _ => bail!("Invalid record 'owner'"),
                };

                // Initialize the record entries.
                let mut entries = IndexMap::new();
                for (entry, (entry_name, entry_type)) in
                    inputs.iter().skip(N::MIN_RECORD_ENTRIES).zip_eq(record_type.entries())
                {
                    // Compute the plaintext type.
                    let plaintext_type = entry_type.plaintext_type();
                    // Retrieve the plaintext value from the entry.
                    let plaintext = match entry {
                        Value::Plaintext(plaintext) => {
                            // Ensure the entry matches the register type.
                            stack.matches_plaintext(plaintext, plaintext_type)?;
                            // Output the plaintext.
                            plaintext.clone()
                        }
                        // Ensure the record entry is not a record.
                        Value::Record(..) => bail!("Casting a record into a record entry is illegal"),
                        // Ensure the record entry is not a future.
                        Value::Future(..) => bail!("Casting a future into a record entry is illegal"),
                        // Ensure the record entry is not a dynamic record.
                        Value::DynamicRecord(..) => {
                            bail!("Casting a dynamic record into a record entry is illegal")
                        }
                        // Ensure the record entry is not a dynamic future.
                        Value::DynamicFuture(..) => bail!("Casting a dynamic future into a record entry is illegal"),
                    };
                    // Append the entry to the record entries.
                    match entry_type {
                        EntryType::Constant(..) => entries.insert(*entry_name, Entry::Constant(plaintext)),
                        EntryType::Public(..) => entries.insert(*entry_name, Entry::Public(plaintext)),
                        EntryType::Private(..) => entries.insert(*entry_name, Entry::Private(plaintext)),
                    };
                }

                // Prepare the index as a field element.
                let index = Field::from_u64(self.destination.locator());
                // Compute the randomizer as `HashToScalar(tvk || index)`.
                let randomizer = N::hash_to_scalar_psd2(&[registers.tvk()?, index])?;
                // Compute the nonce from the randomizer.
                let nonce = N::g_scalar_multiply(&randomizer);

                // Construct the version.
                // Attention: The record version is currently on Version 1. If the record version is updated, change this value.
                let version = console::program::U8::one();

                // Construct the record.
                let record = Record::<N, Plaintext<N>>::from_plaintext(owner, entries, nonce, version)?;
                // Store the record.
                registers.store(stack, &self.destination, Value::Record(record))
            }
            CastType::ExternalRecord(_locator) => {
                bail!("Illegal operation: Cannot cast to an external record.")
            }
            CastType::DynamicRecord => {
                // Check that there is exactly one input.
                ensure!(inputs.len() == 1, "Casting to a dynamic record requires exactly 1 operand");
                // Retrieve and convert the record into a dynamic record.
                let dynamic_record = match &inputs[0] {
                    Value::Record(record) => DynamicRecord::from_record(record)?,
                    _ => bail!("Casting to a dynamic record requires the operand value to be a record"),
                };
                registers.store(stack, &self.destination, Value::DynamicRecord(dynamic_record))
            }
        }
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        // If the variant is `cast.lossy`, then check that the `cast_type` is a `PlaintextType::Literal`.
        if VARIANT == CastVariant::CastLossy as u8 {
            ensure!(
                matches!(self.cast_type, CastType::Plaintext(PlaintextType::Literal(..))),
                "`cast.lossy` is only supported for casting to a literal type"
            )
        }

        use circuit::{Eject, Inject};

        // Load the operands values.
        let inputs: Vec<_> =
            self.operands.iter().map(|operand| registers.load_circuit(stack, operand)).try_collect()?;

        match &self.cast_type {
            CastType::GroupXCoordinate => {
                ensure!(inputs.len() == 1, "Casting to a group x-coordinate requires exactly 1 operand");
                let field = match &inputs[0] {
                    circuit::Value::Plaintext(circuit::Plaintext::Literal(circuit::Literal::Group(group), ..)) => {
                        group.to_x_coordinate()
                    }
                    _ => bail!("Casting to a group x-coordinate requires a group element"),
                };
                registers.store_circuit(
                    stack,
                    &self.destination,
                    circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Field(field))),
                )
            }
            CastType::GroupYCoordinate => {
                ensure!(inputs.len() == 1, "Casting to a group y-coordinate requires exactly 1 operand");
                let field = match &inputs[0] {
                    circuit::Value::Plaintext(circuit::Plaintext::Literal(circuit::Literal::Group(group), ..)) => {
                        group.to_y_coordinate()
                    }
                    _ => bail!("Casting to a group y-coordinate requires a group element"),
                };
                registers.store_circuit(
                    stack,
                    &self.destination,
                    circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Field(field))),
                )
            }
            CastType::Plaintext(PlaintextType::Literal(literal_type)) => {
                ensure!(inputs.len() == 1, "Casting to a literal requires exactly 1 operand");
                let value = match &inputs[0] {
                    circuit::Value::Plaintext(circuit::Plaintext::Literal(literal, ..)) => match VARIANT {
                        0 => literal.cast(*literal_type)?,
                        1 => literal.cast_lossy(*literal_type)?,
                        2.. => unreachable!("Invalid cast variant"),
                    },
                    _ => bail!("Casting to a literal requires a literal"),
                };
                registers.store_circuit(
                    stack,
                    &self.destination,
                    circuit::Value::Plaintext(circuit::Plaintext::from(value)),
                )
            }
            CastType::Plaintext(PlaintextType::Struct(struct_name)) => {
                let plaintext = self.execute_cast_to_struct(stack, *struct_name, inputs)?;
                // Store the struct.
                registers.store_circuit(stack, &self.destination, plaintext.into())
            }
            CastType::Plaintext(PlaintextType::ExternalStruct(locator)) => {
                let external_stack = stack.get_external_stack(locator.program_id())?;
                let plaintext = self.execute_cast_to_struct(&*external_stack, *locator.resource(), inputs)?;
                // Store the struct.
                registers.store_circuit(stack, &self.destination, plaintext.into())
            }
            CastType::Plaintext(PlaintextType::Array(array_type)) => {
                // Ensure the operands length is at least the minimum.
                if inputs.len() < N::MIN_ARRAY_ELEMENTS {
                    bail!("Casting to an array requires at least {} operand(s)", N::MIN_ARRAY_ELEMENTS)
                }
                // Ensure the number of elements does not exceed the maximum.
                if inputs.len() > N::LATEST_MAX_ARRAY_ELEMENTS() {
                    bail!("Casting to array '{array_type}' cannot exceed {} elements", N::LATEST_MAX_ARRAY_ELEMENTS())
                }

                // Ensure that the number of operands is equal to the number of array entries.
                if inputs.len() != **array_type.length() as usize {
                    bail!(
                        "Casting to the array {} requires {} operands, but {} were provided",
                        array_type,
                        array_type.length(),
                        inputs.len()
                    )
                }

                // Initialize the elements.
                let mut elements = Vec::with_capacity(inputs.len());
                for element in inputs.iter() {
                    // Retrieve the plaintext value from the element.
                    let plaintext = match element {
                        circuit::Value::Plaintext(plaintext) => {
                            // Ensure the plaintext matches the element type.
                            stack.matches_plaintext(&plaintext.eject_value(), array_type.next_element_type())?;
                            // Output the plaintext.
                            plaintext.clone()
                        }
                        // Ensure the element is not a record.
                        circuit::Value::Record(..) => bail!("Casting a record into an array element is illegal"),
                        // Ensure the element is not a future.
                        circuit::Value::Future(..) => bail!("Casting a future into an array element is illegal"),
                        // Ensure the element is not a dynamic record.
                        circuit::Value::DynamicRecord(..) => {
                            bail!("Casting a dynamic record into an array element is illegal")
                        }
                        // Ensure the element is not a dynamic future.
                        circuit::Value::DynamicFuture(..) => {
                            bail!("Casting a dynamic future into an array element is illegal")
                        }
                    };
                    // Store the element.
                    elements.push(plaintext);
                }

                // Construct the array.
                let array = circuit::Plaintext::Array(elements, Default::default());
                // Store the array.
                registers.store_circuit(stack, &self.destination, circuit::Value::Plaintext(array))
            }
            CastType::Record(record_name) => {
                // Ensure the operands length is at least the minimum.
                if inputs.len() < N::MIN_RECORD_ENTRIES {
                    bail!("Casting to a record requires at least {} operand(s)", N::MIN_RECORD_ENTRIES)
                }
                // Ensure the number of entries does not exceed the maximum.
                if inputs.len() > N::MAX_RECORD_ENTRIES {
                    bail!("Casting to record '{record_name}' cannot exceed {} members", N::MAX_RECORD_ENTRIES)
                }

                // Retrieve the struct and ensure it is defined in the program.
                let record_type = stack.program().get_record(record_name)?;

                // Ensure that the number of operands is equal to the number of record entries, including the `owner`.
                if inputs.len() != record_type.entries().len() + 1 {
                    bail!(
                        "Casting to the record {} requires {} operands, but {} were provided",
                        record_type.name(),
                        record_type.entries().len() + 1,
                        inputs.len()
                    )
                }

                // Initialize the record owner.
                let owner: circuit::Owner<A, circuit::Plaintext<A>> = match &inputs[0] {
                    // Ensure the entry is an address.
                    circuit::Value::Plaintext(circuit::Plaintext::Literal(circuit::Literal::Address(owner), ..)) => {
                        match record_type.owner().is_public() {
                            true => circuit::Owner::Public(owner.clone()),
                            false => circuit::Owner::Private(circuit::Plaintext::Literal(
                                circuit::Literal::Address(owner.clone()),
                                Default::default(),
                            )),
                        }
                    }
                    _ => bail!("Invalid record 'owner'"),
                };

                // Initialize the record entries.
                let mut entries = IndexMap::new();
                for (entry, (entry_name, entry_type)) in
                    inputs.iter().skip(N::MIN_RECORD_ENTRIES).zip_eq(record_type.entries())
                {
                    // Compute the register type.
                    let register_type = RegisterType::from(ValueType::from(entry_type.clone()));
                    // Retrieve the plaintext value from the entry.
                    let plaintext = match entry {
                        circuit::Value::Plaintext(plaintext) => {
                            // Ensure the entry matches the register type.
                            stack.matches_register_type(
                                &circuit::Value::Plaintext(plaintext.clone()).eject_value(),
                                &register_type,
                            )?;
                            // Output the plaintext.
                            plaintext.clone()
                        }
                        // Ensure the record entry is not a record.
                        circuit::Value::Record(..) => bail!("Casting a record into a record entry is illegal"),
                        // Ensure the record entry is not a future.
                        circuit::Value::Future(..) => bail!("Casting a future into a record entry is illegal"),
                        // Ensure the record entry is not a dynamic record.
                        circuit::Value::DynamicRecord(..) => {
                            bail!("Casting a dynamic record into a record entry is illegal")
                        }
                        // Ensure the record entry is not a dynamic future.
                        circuit::Value::DynamicFuture(..) => {
                            bail!("Casting a dynamic future into a record entry is illegal")
                        }
                    };
                    // Construct the entry name constant circuit.
                    let entry_name = circuit::Identifier::constant(*entry_name);
                    // Append the entry to the record entries.
                    match entry_type {
                        EntryType::Constant(..) => entries.insert(entry_name, circuit::Entry::Constant(plaintext)),
                        EntryType::Public(..) => entries.insert(entry_name, circuit::Entry::Public(plaintext)),
                        EntryType::Private(..) => entries.insert(entry_name, circuit::Entry::Private(plaintext)),
                    };
                }

                // Prepare the index as a constant field element.
                let index = circuit::Field::constant(Field::from_u64(self.destination.locator()));
                // Compute the randomizer as `HashToScalar(tvk || index)`.
                let randomizer = A::hash_to_scalar_psd2(&[registers.tvk_circuit()?, index]);
                // Compute the nonce from the randomizer.
                let nonce = A::g_scalar_multiply(&randomizer);

                // Inject the version (as `Mode::Private`).
                // Attention: The record version is currently on Version 1. If the record version is updated, change this value.
                // Note: The record version is injected as `Mode::Private` as the version is enforced by consensus
                // when verifying a transaction to use the correct record version. See `Output::verify` in `Transition`
                // for the verification logic enforced by consensus.
                let version = circuit::U8::new(circuit::Mode::Private, console::program::U8::one());

                // Construct the record.
                let record =
                    circuit::Record::<A, circuit::Plaintext<A>>::from_plaintext(owner, entries, nonce, version)?;
                // Store the record.
                registers.store_circuit(stack, &self.destination, circuit::Value::Record(record))
            }
            CastType::ExternalRecord(_locator) => {
                bail!("Illegal operation: Cannot cast to an external record.")
            }
            CastType::DynamicRecord => {
                // Check that there is exactly one input.
                ensure!(inputs.len() == 1, "Casting to a dynamic record requires exactly 1 operand");
                // Retrieve and convert the record into a dynamic record.
                let dynamic_record = match &inputs[0] {
                    circuit::Value::Record(record) => circuit::DynamicRecord::from_record(record)?,
                    _ => bail!("Casting to a dynamic record requires the operand value to be a record"),
                };
                // Store the dynamic record.
                registers.store_circuit(stack, &self.destination, circuit::Value::DynamicRecord(dynamic_record))
            }
        }
    }

    /// Finalizes the instruction.
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        // If the variant is `cast.lossy`, then check that the `cast_type` is a `PlaintextType::Literal`.
        if VARIANT == CastVariant::CastLossy as u8 {
            ensure!(
                matches!(self.cast_type, CastType::Plaintext(PlaintextType::Literal(..))),
                "`cast.lossy` is only supported for casting to a literal type"
            )
        }

        // Load the operands values.
        let inputs: Vec<_> = self.operands.iter().map(|operand| registers.load(stack, operand)).try_collect()?;

        match &self.cast_type {
            CastType::GroupXCoordinate => {
                ensure!(inputs.len() == 1, "Casting to a group x-coordinate requires exactly 1 operand");
                let field = match &inputs[0] {
                    Value::Plaintext(Plaintext::Literal(Literal::Group(group), ..)) => group.to_x_coordinate(),
                    _ => bail!("Casting to a group x-coordinate requires a group element"),
                };
                registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(Literal::Field(field))))
            }
            CastType::GroupYCoordinate => {
                ensure!(inputs.len() == 1, "Casting to a group y-coordinate requires exactly 1 operand");
                let field = match &inputs[0] {
                    Value::Plaintext(Plaintext::Literal(Literal::Group(group), ..)) => group.to_y_coordinate(),
                    _ => bail!("Casting to a group y-coordinate requires a group element"),
                };
                registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(Literal::Field(field))))
            }
            CastType::Plaintext(PlaintextType::Literal(literal_type)) => {
                ensure!(inputs.len() == 1, "Casting to a literal requires exactly 1 operand");
                let value = match &inputs[0] {
                    Value::Plaintext(Plaintext::Literal(literal, ..)) => match VARIANT {
                        0 => literal.cast(*literal_type)?,
                        1 => literal.cast_lossy(*literal_type)?,
                        2.. => unreachable!("Invalid cast variant"),
                    },
                    _ => bail!("Casting to a literal requires a literal"),
                };
                registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(value)))
            }
            CastType::Plaintext(PlaintextType::Struct(struct_name)) => {
                let plaintext = self.evaluate_cast_to_struct(stack, *struct_name, inputs)?;
                registers.store(stack, &self.destination, plaintext.into())
            }
            CastType::Plaintext(PlaintextType::ExternalStruct(locator)) => {
                let external_stack = stack.get_external_stack(locator.program_id())?;
                let plaintext = self.evaluate_cast_to_struct(&*external_stack, *locator.resource(), inputs)?;
                registers.store(stack, &self.destination, plaintext.into())
            }
            CastType::Plaintext(PlaintextType::Array(array_type)) => {
                self.cast_to_array(stack, registers, array_type, inputs)
            }
            CastType::Record(_record_name) => {
                bail!("Illegal operation: Cannot cast to a record in a finalize scope.")
            }
            CastType::ExternalRecord(_locator) => {
                bail!("Illegal operation: Cannot cast to an external record in a finalize scope.")
            }
            CastType::DynamicRecord => {
                bail!("Illegal operation: Cannot cast to a dynamic record in a finalize scope.")
            }
        }
    }

    /// Returns the output type from the given program and input types.
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // If the variant is `cast.lossy`, then check that the `cast_type` is a `PlaintextType::Literal`.
        if VARIANT == CastVariant::CastLossy as u8 {
            ensure!(
                matches!(self.cast_type, CastType::Plaintext(PlaintextType::Literal(..))),
                "`cast.lossy` is only supported for casting to a literal type"
            )
        }

        // Ensure the number of operands is correct.
        ensure!(
            input_types.len() == self.operands.len(),
            "Instruction '{}' expects {} operands, found {} operands",
            Self::opcode(),
            input_types.len(),
            self.operands.len(),
        );

        fn struct_checks<N: Network>(
            struct_stack: &impl StackTrait<N>,
            stack: &impl StackTrait<N>,
            struct_type: &StructType<N>,
            input_types: &[RegisterType<N>],
        ) -> Result<()> {
            let struct_name = struct_type.name();

            // Ensure the input types length is at least the minimum.
            if input_types.len() < N::MIN_STRUCT_ENTRIES {
                bail!("Casting to a struct requires at least {} operand(s)", N::MIN_STRUCT_ENTRIES)
            }
            // Ensure the number of members does not exceed the maximum.
            if input_types.len() > N::MAX_STRUCT_ENTRIES {
                bail!("Casting to struct '{struct_type}' cannot exceed {} members", N::MAX_STRUCT_ENTRIES)
            }

            // Ensure that the number of input types is equal to the number of struct members.
            ensure!(
                input_types.len() == struct_type.members().len(),
                "Casting to the struct {} requires {} operands, but {} were provided",
                struct_name,
                struct_type.members().len(),
                input_types.len()
            );
            // Ensure the input types match the struct.
            for ((_, member_type), input_type) in struct_type.members().iter().zip_eq(input_types) {
                match input_type {
                    // Ensure the plaintext type matches the member type.
                    RegisterType::Plaintext(plaintext_type) => {
                        ensure!(
                            types_equivalent(struct_stack, member_type, stack, plaintext_type,)?,
                            "Struct '{struct_name}' member type mismatch: expected '{member_type}', found '{plaintext_type}'"
                        )
                    }
                    // Ensure the input type cannot be a record (this is unsupported behavior).
                    RegisterType::Record(record_name) => bail!(
                        "Struct '{struct_name}' member type mismatch: expected '{member_type}', found record '{record_name}'"
                    ),
                    // Ensure the input type cannot be an external record (this is unsupported behavior).
                    RegisterType::ExternalRecord(locator) => bail!(
                        "Struct '{struct_name}' member type mismatch: expected '{member_type}', found external record '{locator}'"
                    ),
                    // Ensure the input type cannot be a future (this is unsupported behavior).
                    RegisterType::Future(..) => {
                        bail!("Struct '{struct_name}' member type mismatch: expected '{member_type}', found future")
                    }
                    // Ensure the input type cannot be a dynamic record (this is unsupported behavior).
                    RegisterType::DynamicRecord => {
                        bail!(
                            "Struct '{struct_name}' member type mismatch: expected '{member_type}', found dynamic record"
                        )
                    }
                    // Ensure the input type cannot be a dynamic future (this is unsupported behavior).
                    RegisterType::DynamicFuture => {
                        bail!(
                            "Struct '{struct_name}' member type mismatch: expected '{member_type}', found dynamic future"
                        )
                    }
                }
            }

            Ok(())
        }

        // Ensure the output type is defined in the program.
        match &self.cast_type {
            CastType::GroupXCoordinate | CastType::GroupYCoordinate => {
                ensure!(input_types.len() == 1, "Casting to a group coordinate requires exactly 1 operand");
                ensure!(
                    matches!(input_types[0], RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Group))),
                    "Type mismatch: expected 'group', found '{}'",
                    input_types[0]
                );
            }
            CastType::Plaintext(PlaintextType::Literal(..)) => {
                ensure!(input_types.len() == 1, "Casting to a literal requires exactly 1 operand");
            }
            CastType::Plaintext(PlaintextType::ExternalStruct(locator)) => {
                let external_stack = stack.get_external_stack(locator.program_id())?;
                let struct_type = external_stack.program().get_struct(locator.resource())?;
                struct_checks(&*external_stack, stack, struct_type, input_types)?;
            }
            CastType::Plaintext(PlaintextType::Struct(struct_name)) => {
                // Retrieve the struct and ensure it is defined in the program.
                let struct_type = stack.program().get_struct(struct_name)?;
                struct_checks(stack, stack, struct_type, input_types)?;
            }
            CastType::Plaintext(PlaintextType::Array(array_type)) => {
                // Ensure the input types length is at least the minimum.
                if input_types.len() < N::MIN_ARRAY_ELEMENTS {
                    bail!("Casting to an array requires at least {} operand(s)", N::MIN_ARRAY_ELEMENTS)
                }
                // Ensure the number of elements does not exceed the maximum.
                if input_types.len() > N::LATEST_MAX_ARRAY_ELEMENTS() {
                    bail!("Casting to array '{array_type}' cannot exceed {} elements", N::LATEST_MAX_ARRAY_ELEMENTS())
                }

                // Ensure that the number of input types is equal to the number of array entries.
                if input_types.len() != **array_type.length() as usize {
                    bail!(
                        "Casting to the array {} requires {} operands, but {} were provided",
                        array_type,
                        array_type.length(),
                        input_types.len()
                    )
                }

                // Ensure the input types match the element type.
                for input_type in input_types {
                    match input_type {
                        // Ensure the plaintext type matches the member type.
                        RegisterType::Plaintext(plaintext_type) => {
                            ensure!(
                                types_equivalent(stack, plaintext_type, stack, array_type.next_element_type())?,
                                "Array element type mismatch: expected '{}', found '{plaintext_type}'",
                                array_type.next_element_type()
                            )
                        }
                        // Ensure the input type cannot be a record (this is unsupported behavior).
                        RegisterType::Record(record_name) => bail!(
                            "Array element type mismatch: expected '{}', found record '{record_name}'",
                            array_type.next_element_type()
                        ),
                        // Ensure the input type cannot be an external record (this is unsupported behavior).
                        RegisterType::ExternalRecord(locator) => bail!(
                            "Array element type mismatch: expected '{}', found external record '{locator}'",
                            array_type.next_element_type()
                        ),
                        // Ensure the input type cannot be a future (this is unsupported behavior).
                        RegisterType::Future(..) => bail!(
                            "Array element type mismatch: expected '{}', found future",
                            array_type.next_element_type()
                        ),
                        // Ensure the input type cannot be a dynamic record (this is unsupported behavior).
                        RegisterType::DynamicRecord => bail!(
                            "Array element type mismatch: expected '{}', found dynamic record",
                            array_type.next_element_type()
                        ),
                        // Ensure the input type cannot be a dynamic future (this is unsupported behavior).
                        RegisterType::DynamicFuture => bail!(
                            "Array element type mismatch: expected '{}', found dynamic future",
                            array_type.next_element_type()
                        ),
                    }
                }
            }
            CastType::Record(record_name) => {
                // Retrieve the record type and ensure is defined in the program.
                let record = stack.program().get_record(record_name)?;

                // Ensure the input types length is at least the minimum.
                if input_types.len() < N::MIN_RECORD_ENTRIES {
                    bail!("Casting to a record requires at least {} operand(s)", N::MIN_RECORD_ENTRIES)
                }
                // Ensure the number of entries does not exceed the maximum.
                if input_types.len() > N::MAX_RECORD_ENTRIES {
                    bail!("Casting to record '{record_name}' cannot exceed {} members", N::MAX_RECORD_ENTRIES)
                }

                // Ensure that the number of input types is equal to the number of record entries, including the `owner`.
                ensure!(
                    input_types.len() == record.entries().len() + 1,
                    "Casting to the record {} requires {} operands, but {} were provided",
                    record.name(),
                    record.entries().len() + 1,
                    input_types.len()
                );
                // Ensure the first input type is an address.
                ensure!(
                    input_types[0] == RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Address)),
                    "Casting to a record requires the first operand to be an address"
                );

                // Ensure the input types match the record.
                for (input_type, (_, entry_type)) in
                    input_types.iter().skip(N::MIN_RECORD_ENTRIES).zip_eq(record.entries())
                {
                    match input_type {
                        // Ensure the plaintext type matches the entry type.
                        RegisterType::Plaintext(plaintext_type) => match entry_type {
                            EntryType::Constant(entry_type)
                            | EntryType::Public(entry_type)
                            | EntryType::Private(entry_type) => {
                                ensure!(
                                    entry_type == plaintext_type,
                                    "Record '{record_name}' entry type mismatch: expected '{entry_type}', found '{plaintext_type}'"
                                )
                            }
                        },
                        // Ensure the input type cannot be a record (this is unsupported behavior).
                        RegisterType::Record(record_name) => bail!(
                            "Record '{record_name}' entry type mismatch: expected '{entry_type}', found record '{record_name}'"
                        ),
                        // Ensure the input type cannot be an external record (this is unsupported behavior).
                        RegisterType::ExternalRecord(locator) => bail!(
                            "Record '{record_name}' entry type mismatch: expected '{entry_type}', found external record '{locator}'"
                        ),
                        // Ensure the input type cannot be a future (this is unsupported behavior).
                        RegisterType::Future(..) => {
                            bail!("Record '{record_name}' entry type mismatch: expected '{entry_type}', found future")
                        }
                        // Ensure the input type cannot be a dynamic record (this is unsupported behavior).
                        RegisterType::DynamicRecord => {
                            bail!(
                                "Record '{record_name}' entry type mismatch: expected '{entry_type}', found dynamic record"
                            )
                        }
                        // Ensure the input type cannot be a dynamic future (this is unsupported behavior).
                        RegisterType::DynamicFuture => {
                            bail!(
                                "Record '{record_name}' entry type mismatch: expected '{entry_type}', found dynamic future"
                            )
                        }
                    }
                }
            }
            CastType::ExternalRecord(_locator) => {
                bail!("Illegal operation: Cannot cast to an external record.")
            }
            CastType::DynamicRecord => {
                ensure!(input_types.len() == 1, "Casting to a dynamic record requires exactly 1 operand");
                ensure!(
                    matches!(input_types[0], RegisterType::Record(..) | RegisterType::ExternalRecord(..)),
                    "Casting to a dynamic record requires a static record (whether external or not) as the operand"
                );
            }
        }

        Ok(vec![match &self.cast_type {
            CastType::GroupXCoordinate => RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Field)),
            CastType::GroupYCoordinate => RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Field)),
            CastType::Plaintext(plaintext_type) => RegisterType::Plaintext(plaintext_type.clone()),
            CastType::Record(identifier) => RegisterType::Record(*identifier),
            CastType::ExternalRecord(locator) => RegisterType::ExternalRecord(*locator),
            CastType::DynamicRecord => RegisterType::DynamicRecord,
        }])
    }
}

macro_rules! cast_to_struct_common {
    ($N: ident, $struct_name: expr, $inputs: expr, $stack: expr, $plaintext: path, $record: path, $future: path,
     $eject_value: expr, $process_member: expr
    ) => {{
        // Ensure the operands length is at least the minimum.
        if $inputs.len() < $N::MIN_STRUCT_ENTRIES {
            bail!("Casting to a struct requires at least {} operand(s)", N::MIN_STRUCT_ENTRIES)
        }
        // Ensure the number of members does not exceed the maximum.
        if $inputs.len() > $N::MAX_STRUCT_ENTRIES {
            bail!("Casting to a struct cannot exceed {} members", N::MAX_STRUCT_ENTRIES)
        }

        // Retrieve the struct and ensure it is defined in the program.
        let struct_ = $stack.program().get_struct($struct_name)?;

        // Ensure that the number of operands is equal to the number of struct members.
        if $inputs.len() != struct_.members().len() {
            bail!(
                "Casting to the struct {} requires {} operands, but {} were provided",
                struct_.name(),
                struct_.members().len(),
                $inputs.len()
            )
        }

        // Initialize the struct members.
        let mut members = IndexMap::new();
        for (member, (member_name, member_type)) in $inputs.iter().zip_eq(struct_.members()) {
            // Retrieve the plaintext value from the entry.
            let plaintext = match member {
                $plaintext(plaintext) => {
                    // Ensure the member matches the register type.
                    $stack.matches_plaintext(&$eject_value(plaintext), member_type)?;
                    // Output the plaintext.
                    plaintext.clone()
                }
                // Ensure the struct member is not a record.
                $record(..) => {
                    bail!("Casting a record into a struct member is illegal")
                }
                // Ensure the struct member is not a future.
                $future(..) => {
                    bail!("Casting a future into a struct member is illegal")
                }
                // Catch-all for other value types (DynamicRecord, DynamicFuture)
                _ => {
                    bail!("Casting this value type into a struct member is illegal")
                }
            };
            // Append the member to the struct members.
            members.insert($process_member(member_name), plaintext);
        }

        members
    }};
}

impl<N: Network, const VARIANT: u8> CastOperation<N, VARIANT> {
    fn evaluate_cast_to_struct(
        &self,
        stack: &impl StackTrait<N>,
        struct_name: Identifier<N>,
        inputs: Vec<Value<N>>,
    ) -> Result<Plaintext<N>> {
        let members = cast_to_struct_common!(
            N,
            &struct_name,
            inputs,
            stack,
            Value::Plaintext,
            Value::Record,
            Value::Future,
            |x: &Plaintext<_>| x.clone(),
            |x: &Identifier<_>| *x
        );
        // Construct the struct.
        Ok(Plaintext::Struct(members, Default::default()))
    }

    fn execute_cast_to_struct<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        struct_name: Identifier<N>,
        inputs: Vec<circuit::Value<A>>,
    ) -> Result<circuit::Plaintext<A>> {
        use circuit::Eject;
        let members = cast_to_struct_common!(
            N,
            &struct_name,
            inputs,
            stack,
            circuit::Value::Plaintext,
            circuit::Value::Record,
            circuit::Value::Future,
            |x: &circuit::Plaintext<_>| x.eject_value(),
            |x: &Identifier<N>| circuit::Identifier::constant(*x)
        );
        // Construct the struct.
        Ok(circuit::Plaintext::Struct(members, Default::default()))
    }

    /// A helper method to handle casting to an array.
    fn cast_to_array(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersTrait<N>,
        array_type: &ArrayType<N>,
        inputs: Vec<Value<N>>,
    ) -> Result<()> {
        // Ensure that there is at least one operand.
        if inputs.len() < N::MIN_ARRAY_ELEMENTS {
            bail!("Casting to an array requires at least {} operand", N::MIN_ARRAY_ELEMENTS)
        }

        // Ensure that the number of operands is equal to the number of array entries.
        if inputs.len() != **array_type.length() as usize {
            bail!(
                "Casting to the array {} requires {} operands, but {} were provided",
                array_type,
                array_type.length(),
                inputs.len()
            )
        }

        // Initialize the elements.
        let mut elements = Vec::with_capacity(inputs.len());
        for element in inputs.iter() {
            // Retrieve the plaintext value from the element.
            let plaintext = match element {
                Value::Plaintext(plaintext) => {
                    // Ensure the plaintext matches the element type.
                    stack.matches_plaintext(plaintext, array_type.next_element_type())?;
                    // Output the plaintext.
                    plaintext.clone()
                }
                // Ensure the element is not a record.
                Value::Record(..) => bail!("Casting a record into an array element is illegal"),
                // Ensure the element is not a future.
                Value::Future(..) => bail!("Casting a future into an array element is illegal"),
                // Ensure the element is not a dynamic record.
                Value::DynamicRecord(..) => bail!("Casting a dynamic record into an array element is illegal"),
                // Ensure the element is not a dynamic future.
                Value::DynamicFuture(..) => bail!("Casting a dynamic future into an array element is illegal"),
            };
            // Store the element.
            elements.push(plaintext);
        }

        // Construct the array.
        let array = Plaintext::Array(elements, Default::default());
        // Store the array.
        registers.store(stack, &self.destination, Value::Plaintext(array))
    }
}

impl<N: Network, const VARIANT: u8> Parser for CastOperation<N, VARIANT> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses an operand from the string.
        fn parse_operand<N: Network>(string: &str) -> ParserResult<'_, Operand<N>> {
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the operand from the string.
            Operand::parse(string)
        }

        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the operands from the string.
        let (string, operands) = many1(parse_operand)(string)?;
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
        // Parse the cast type from the string.
        let (string, cast_type) = CastType::parse(string)?;
        // Check that the number of operands does not exceed the maximum number of data entries.
        let max_operands = match cast_type {
            CastType::GroupXCoordinate
            | CastType::GroupYCoordinate
            | CastType::Plaintext(PlaintextType::Literal(_)) => 1,
            CastType::Plaintext(PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_)) => N::MAX_STRUCT_ENTRIES,
            CastType::Plaintext(PlaintextType::Array(_)) => N::LATEST_MAX_ARRAY_ELEMENTS(),
            CastType::Record(_) | CastType::ExternalRecord(_) => N::MAX_RECORD_ENTRIES,
            CastType::DynamicRecord => 1,
        };

        // Validate DynamicRecord cast constraints.
        if let Err(e) = Self::validate_dynamic_record_cast(&cast_type, &operands, &destination) {
            return map_res(fail, move |_: ParserResult<Self>| Err(error(e.to_string())))(string);
        }

        match !operands.is_empty() && (operands.len() <= max_operands) {
            true => Ok((string, Self { operands, destination, cast_type })),
            false => {
                map_res(fail, |_: ParserResult<Self>| Err(error("Failed to parse 'cast' opcode: too many operands")))(
                    string,
                )
            }
        }
    }
}

impl<N: Network, const VARIANT: u8> FromStr for CastOperation<N, VARIANT> {
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

impl<N: Network, const VARIANT: u8> Debug for CastOperation<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for CastOperation<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is within the bounds.
        let max_operands = match self.cast_type {
            CastType::GroupYCoordinate
            | CastType::GroupXCoordinate
            | CastType::Plaintext(PlaintextType::Literal(_)) => 1,
            CastType::Plaintext(PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_)) => N::MAX_STRUCT_ENTRIES,
            CastType::Plaintext(PlaintextType::Array(_)) => N::LATEST_MAX_ARRAY_ELEMENTS(),
            CastType::Record(_) | CastType::ExternalRecord(_) => N::MAX_RECORD_ENTRIES,
            CastType::DynamicRecord => 1,
        };
        if self.operands.is_empty() || self.operands.len() > max_operands {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {} as {}", self.destination, self.cast_type)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for CastOperation<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the number of operands.
        let mut num_operands = u8::read_le(&mut reader)? as usize;
        // If the number of operands is `u8::MAX`, read the actual number of operands as a `u16`.
        if num_operands == u8::MAX as usize {
            num_operands = u16::read_le(&mut reader)? as usize
        }

        // Ensure that the number of operands does not exceed the upper bound.
        // Note: Although a similar check is performed later, this check is performed to ensure that an exceedingly large number of operands is not allocated.
        // Note: This check is purely a sanity check, as it is not type-aware.
        if num_operands.is_zero() || num_operands > N::LATEST_MAX_ARRAY_ELEMENTS() {
            return Err(error(format!(
                "The number of operands must be nonzero and <= {}",
                N::LATEST_MAX_ARRAY_ELEMENTS()
            )));
        }

        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(num_operands);
        // Read the operands.
        for _ in 0..num_operands {
            operands.push(Operand::read_le(&mut reader)?);
        }

        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;

        // Read the cast type.
        let cast_type = CastType::read_le(&mut reader)?;

        // Ensure the number of operands is within the bounds for the cast type.
        let max_operands = match cast_type {
            CastType::GroupYCoordinate
            | CastType::GroupXCoordinate
            | CastType::Plaintext(PlaintextType::Literal(_)) => 1,
            CastType::Plaintext(PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_)) => N::MAX_STRUCT_ENTRIES,
            CastType::Plaintext(PlaintextType::Array(_)) => N::LATEST_MAX_ARRAY_ELEMENTS(),
            CastType::Record(_) | CastType::ExternalRecord(_) => N::MAX_RECORD_ENTRIES,
            CastType::DynamicRecord => 1,
        };
        if num_operands.is_zero() || num_operands > max_operands {
            return Err(error(format!("The number of operands must be nonzero and <= {max_operands}")));
        }

        // Validate DynamicRecord cast constraints.
        Self::validate_dynamic_record_cast(&cast_type, &operands, &destination).map_err(|e| error(e.to_string()))?;

        // Return the operation.
        Ok(Self { operands, destination, cast_type })
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for CastOperation<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is within the bounds.
        let max_operands = match self.cast_type {
            CastType::GroupYCoordinate
            | CastType::GroupXCoordinate
            | CastType::Plaintext(PlaintextType::Literal(_)) => 1,
            CastType::Plaintext(PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_)) => N::MAX_STRUCT_ENTRIES,
            CastType::Plaintext(PlaintextType::Array(_)) => N::LATEST_MAX_ARRAY_ELEMENTS(),
            CastType::Record(_) | CastType::ExternalRecord(_) => N::MAX_RECORD_ENTRIES,
            CastType::DynamicRecord => 1,
        };
        if self.operands.is_empty() || self.operands.len() > max_operands {
            return Err(error(format!("The number of operands must be nonzero and <= {max_operands}")));
        }

        // Write the number of operands.
        if self.operands.len() >= u8::MAX as usize {
            // Write the `u8::MAX` value.
            u8::MAX.write_le(&mut writer)?;
            // Write the actual number of operands as a `u16`.
            u16::try_from(self.operands.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        } else {
            u8::try_from(self.operands.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        }
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the destination register.
        self.destination.write_le(&mut writer)?;
        // Write the cast type.
        self.cast_type.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        network::MainnetV0,
        program::{Access, Identifier},
    };

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, cast) =
            Cast::<CurrentNetwork>::parse("cast r0.owner r0.token_amount into r1 as token.record").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(cast.operands.len(), 2, "The number of operands is incorrect");
        assert_eq!(
            cast.operands[0],
            Operand::Register(Register::Access(0, vec![Access::from(Identifier::from_str("owner").unwrap())])),
            "The first operand is incorrect"
        );
        assert_eq!(
            cast.operands[1],
            Operand::Register(Register::Access(0, vec![Access::from(Identifier::from_str("token_amount").unwrap())])),
            "The second operand is incorrect"
        );
        assert_eq!(cast.destination, Register::Locator(1), "The destination register is incorrect");
        assert_eq!(
            cast.cast_type,
            CastType::Record(Identifier::from_str("token").unwrap()),
            "The value type is incorrect"
        );
    }

    #[test]
    fn test_parse_cast_into_plaintext_max_operands() {
        let mut string = "cast ".to_string();
        let mut operands = Vec::with_capacity(CurrentNetwork::MAX_STRUCT_ENTRIES);
        for i in 0..CurrentNetwork::MAX_STRUCT_ENTRIES {
            string.push_str(&format!("r{i} "));
            operands.push(Operand::Register(Register::Locator(i as u64)));
        }
        string.push_str(&format!("into r{} as foo", CurrentNetwork::MAX_STRUCT_ENTRIES));
        let (string, cast) = Cast::<CurrentNetwork>::parse(&string).unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(cast.operands.len(), CurrentNetwork::MAX_STRUCT_ENTRIES, "The number of operands is incorrect");
        assert_eq!(cast.operands, operands, "The operands are incorrect");
        assert_eq!(
            cast.destination,
            Register::Locator(CurrentNetwork::MAX_STRUCT_ENTRIES as u64),
            "The destination register is incorrect"
        );
        assert_eq!(
            cast.cast_type,
            CastType::Plaintext(PlaintextType::Struct(Identifier::from_str("foo").unwrap())),
            "The value type is incorrect"
        );
    }

    #[test]
    fn test_parse_cast_into_record_max_operands() {
        let mut string = "cast ".to_string();
        let mut operands = Vec::with_capacity(CurrentNetwork::MAX_RECORD_ENTRIES);
        for i in 0..CurrentNetwork::MAX_RECORD_ENTRIES {
            string.push_str(&format!("r{i} "));
            operands.push(Operand::Register(Register::Locator(i as u64)));
        }
        string.push_str(&format!("into r{} as token.record", CurrentNetwork::MAX_RECORD_ENTRIES));
        let (string, cast) = Cast::<CurrentNetwork>::parse(&string).unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(cast.operands.len(), CurrentNetwork::MAX_RECORD_ENTRIES, "The number of operands is incorrect");
        assert_eq!(cast.operands, operands, "The operands are incorrect");
        assert_eq!(
            cast.destination,
            Register::Locator((CurrentNetwork::MAX_RECORD_ENTRIES) as u64),
            "The destination register is incorrect"
        );
        assert_eq!(
            cast.cast_type,
            CastType::Record(Identifier::from_str("token").unwrap()),
            "The value type is incorrect"
        );
    }

    #[test]
    fn test_parse_cast_into_record_too_many_operands() {
        let mut string = "cast ".to_string();
        for i in 0..=CurrentNetwork::MAX_RECORD_ENTRIES {
            string.push_str(&format!("r{i} "));
        }
        string.push_str(&format!("into r{} as token.record", CurrentNetwork::MAX_RECORD_ENTRIES + 1));
        assert!(Cast::<CurrentNetwork>::parse(&string).is_err(), "Parser did not error");
    }

    #[test]
    fn test_parse_cast_into_plaintext_too_many_operands() {
        let mut string = "cast ".to_string();
        for i in 0..=CurrentNetwork::MAX_STRUCT_ENTRIES {
            string.push_str(&format!("r{i} "));
        }
        string.push_str(&format!("into r{} as foo", CurrentNetwork::MAX_STRUCT_ENTRIES + 1));
        assert!(Cast::<CurrentNetwork>::parse(&string).is_err(), "Parser did not error");
    }

    #[test]
    fn test_parse_cast_into_dynamic_record() {
        let correct_cases = ["cast r0 into r1 as dynamic.record", "cast r1 into r5 as dynamic.record"];

        let incorrect_cases = [
            // Too few operands
            "cast into r1 as dynamic.record",
            // Too many operands (two)
            "cast r0 r1 into r2 as dynamic.record",
            // Too many operands
            "cast r0 r1 r2 into r3 as dynamic.record",
            // Too few destinations (with tag)
            "cast r0 into as dynamic.record",
            // Too few destinations (without tag)
            "cast r0 as dynamic.record",
            // Incorrect operand structure
            "cast r0.owner into r1 as dynamic.record",
            // Incorrect destination structure
            "cast r0 into r1.owner as dynamic.record",
        ];

        for case in correct_cases {
            assert!(Cast::<CurrentNetwork>::parse(case).is_ok(), "Parser failed for: {case}");
        }

        for case in incorrect_cases {
            assert!(Cast::<CurrentNetwork>::parse(case).is_err(), "Parser did not fail for: {case}");
        }
    }

    #[test]
    fn test_cast_type_contains_identifier_type() {
        // Identifier literal type should be detected.
        let cast_type = CastType::<CurrentNetwork>::Plaintext(PlaintextType::Literal(LiteralType::Identifier));
        assert!(cast_type.contains_identifier_type().unwrap());

        // Non-identifier literal types should not be detected.
        let cast_type = CastType::<CurrentNetwork>::Plaintext(PlaintextType::Literal(LiteralType::Field));
        assert!(!cast_type.contains_identifier_type().unwrap());
        let cast_type = CastType::<CurrentNetwork>::Plaintext(PlaintextType::Literal(LiteralType::U64));
        assert!(!cast_type.contains_identifier_type().unwrap());

        // Non-plaintext cast types should not be detected.
        let cast_type = CastType::<CurrentNetwork>::GroupXCoordinate;
        assert!(!cast_type.contains_identifier_type().unwrap());
        let cast_type = CastType::<CurrentNetwork>::GroupYCoordinate;
        assert!(!cast_type.contains_identifier_type().unwrap());
        let cast_type = CastType::<CurrentNetwork>::Record(Identifier::from_str("token").unwrap());
        assert!(!cast_type.contains_identifier_type().unwrap());
    }

    #[test]
    fn test_cast_instruction_contains_identifier_type() {
        // A cast to identifier type should be detected.
        let (_, cast) = Cast::<CurrentNetwork>::parse("cast r0 into r1 as identifier").unwrap();
        assert!(cast.cast_type().contains_identifier_type().unwrap());

        // A cast to field type should not be detected.
        let (_, cast) = Cast::<CurrentNetwork>::parse("cast r0 into r1 as field").unwrap();
        assert!(!cast.cast_type().contains_identifier_type().unwrap());

        // A cast.lossy to identifier type should be detected.
        let (_, cast) = CastLossy::<CurrentNetwork>::parse("cast.lossy r0 into r1 as identifier").unwrap();
        assert!(cast.cast_type().contains_identifier_type().unwrap());
    }
}
