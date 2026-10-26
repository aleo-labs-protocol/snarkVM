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
use circuit::{Eject, Inject, Mode, traits::ToField};
use console::{
    collections::merkle_tree::MerklePath,
    network::prelude::*,
    program::{
        Access,
        Address,
        DynamicRecord,
        Entry,
        Field,
        Identifier,
        Plaintext,
        PlaintextType,
        RECORD_DATA_TREE_DEPTH,
        Register,
        RegisterType,
        ToField as ConsoleToField,
        ToFields as ConsoleToFields,
        U64,
        Value,
    },
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use indexmap::IndexMap;

type CircuitLH<A> = circuit::Poseidon8<A>;
type CircuitPH<A> = circuit::Poseidon2<A>;

/// The expected visibility of a record entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Visibility {
    /// The entry is constant.
    Constant = 0,
    /// The entry is public.
    Public = 1,
    /// The entry is private.
    Private = 2,
}

impl Visibility {
    /// Returns the name of the visibility.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Constant => "constant",
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    /// Returns `true` if the visibility matches the given entry variant.
    pub fn matches_entry<N: Network>(&self, entry: &Entry<N, Plaintext<N>>) -> bool {
        matches!(
            (self, entry),
            (Self::Constant, Entry::Constant(_))
                | (Self::Public, Entry::Public(_))
                | (Self::Private, Entry::Private(_))
        )
    }
}

/// Retrieves the value of an entry in a dynamic record.
/// Internally, this instruction verifies a Merkle membership proof that the
/// requested entry is a leaf of the record's committed Merkle root.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GetRecordDynamic<N: Network> {
    /// The register containing the dynamic record being read.
    // It is always of the form `Operand::Register(Register::Locator(u64))`.
    operands: [Operand<N>; 1],
    /// The destination register to store the value of the entry.
    // The variant is always Register::Locator
    destination: Register<N>,
    /// The Identifier of the entry being read.
    entry_identifier: Identifier<N>,
    /// The type of the entry being read.
    plaintext_type: PlaintextType<N>,
    /// The visibility of the entry.
    /// When `Some`, visibility bits are injected as constants in the circuit.
    /// When `None`, visibility bits are injected as private witnesses in the circuit.
    visibility: Option<Visibility>,
}

impl<N: Network> GetRecordDynamic<N> {
    /// Initializes a new `get.record.dynamic` instruction.
    #[inline]
    pub fn new(
        operand: Operand<N>,
        destination: Register<N>,
        plaintext_type: PlaintextType<N>,
        visibility: Option<Visibility>,
    ) -> Result<Self> {
        ensure!(
            matches!(destination, Register::Locator(_)),
            "Expected destination of the form r<i>, found {destination}"
        );

        let (prepared_operands, entry_identifier) =
            if let Operand::Register(Register::Access(index, accesses)) = operand {
                if let [Access::Member(identifier)] = accesses.as_slice() {
                    ([Operand::Register(Register::Locator(index))], *identifier)
                } else {
                    bail!("Expected a single entry identifier, found {accesses:?}")
                }
            } else {
                bail!("Expected input to be of the form r<i>.<name>, found {operand:?}")
            };

        Ok(Self { operands: prepared_operands, destination, entry_identifier, plaintext_type, visibility })
    }

    /// Returns the visibility, if any.
    #[inline]
    pub const fn visibility(&self) -> Option<&Visibility> {
        self.visibility.as_ref()
    }

    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::GetRecordDynamic("get.record.dynamic")
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

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        self.plaintext_type.contains_external_struct()
    }
}

impl<N: Network> GetRecordDynamic<N> {
    /// Evaluates the instruction.
    pub fn evaluate(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersTrait<N>) -> Result<()> {
        // Retrieve the dynamic record.
        let dynamic_record = {
            let value = registers.load(stack, &self.operands[0])?;
            if let Value::DynamicRecord(dynamic_record) = value {
                dynamic_record
            } else {
                bail!("Expected dynamic record, found {value}")
            }
        };
        // Retrieve the entry from the record data.
        let entry = if let Some(data) = dynamic_record.data() {
            if let Some(entry) = data.get(&self.entry_identifier) {
                entry
            } else {
                bail!("Entry {} not found in dynamic record", self.entry_identifier)
            }
        } else {
            bail!("Dynamic record data has not been populated")
        };

        // Check visibility, if it was specified.
        if let Some(expected) = &self.visibility {
            ensure!(
                expected.matches_entry(entry),
                "Visibility mismatch in `get.record.dynamic` for entry '{}': expected {}, found {}",
                self.entry_identifier,
                expected.name(),
                match entry {
                    Entry::Constant(_) => "constant",
                    Entry::Public(_) => "public",
                    Entry::Private(_) => "private",
                },
            );
        }

        // Get the plaintext value from the entry.
        let plaintext = match entry {
            Entry::Constant(plaintext) => plaintext,
            Entry::Public(plaintext) => plaintext,
            Entry::Private(plaintext) => plaintext,
        };

        ensure!(
            stack.matches_plaintext(plaintext, &self.plaintext_type).is_ok(),
            "Type mismatch in dynamic record entry {:?}: expected {:?}, found {:?}",
            self.entry_identifier,
            self.plaintext_type,
            entry
        );

        // Store the output.
        registers.store(stack, &self.destination, Value::Plaintext(plaintext.clone()))
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        // Retrieve the dynamic record
        let circuit_dynamic_record = {
            let value = registers.load_circuit(stack, &self.operands[0])?;
            if let circuit::Value::DynamicRecord(dynamic_record) = value {
                dynamic_record
            } else {
                bail!("Expected dynamic record, found {:?}", value.eject_value())
            }
        };

        // Compute the Merkle path for the entry.
        // If the data is not present (for instance, during key synthesis), populate with arbitrary data first.
        let (console_entry, console_path) = Self::compute_or_sample_path(
            circuit_dynamic_record.data(),
            &self.entry_identifier,
            stack,
            &self.plaintext_type,
            &circuit_dynamic_record.root().eject_value(),
            self.visibility.as_ref(),
        )?;

        // This verification is only a sanity check and not performed in-circuit.
        {
            // Check visibility, if it was specified.
            if let Some(expected) = &self.visibility {
                ensure!(
                    expected.matches_entry(&console_entry),
                    "Visibility mismatch in `get.record.dynamic` for entry '{}': expected {}, found {}",
                    self.entry_identifier,
                    expected.name(),
                    match &console_entry {
                        Entry::Constant(_) => "constant",
                        Entry::Public(_) => "public",
                        Entry::Private(_) => "private",
                    },
                );
            }

            let plaintext = match &console_entry {
                Entry::Constant(plaintext) => plaintext,
                Entry::Public(plaintext) => plaintext,
                Entry::Private(plaintext) => plaintext,
            };
            ensure!(
                stack.matches_plaintext(plaintext, &self.plaintext_type).is_ok(),
                "Type mismatch in dynamic record entry {:?}: expected {:?}, found {:?}",
                self.entry_identifier,
                self.plaintext_type,
                console_entry
            );
        }

        // Loading the root of the merkleized-data tree
        let circuit_root = circuit_dynamic_record.root();

        // Constructing the in-circuit leaf. An entry is described by:
        // - its identifier, which is injected into the circuit as a constant `Field` element.
        // - its visibility which is injected as two bits.
        //   When the visibility is specified, these bits are constants. Otherwise they are private witnesses.
        // - its plaintext value.
        let mode = match self.visibility {
            Some(_) => Mode::Constant,
            None => Mode::Private,
        };
        let circuit_identifier = circuit::Identifier::constant(self.entry_identifier);
        let circuit_entry = circuit::Entry::new(Mode::Private, console_entry);
        let mut circuit_leaf = vec![circuit_identifier.to_field()];
        circuit_leaf.extend(circuit_entry.to_fields_with_visibility_as_mode(mode));

        // Initialize the in-circuit hashers.
        let (console_leaf_hasher, console_path_hasher) = DynamicRecord::initialize_hashers();
        let circuit_leaf_hasher = CircuitLH::<A>::constant(console_leaf_hasher.clone());
        let circuit_path_hasher = CircuitPH::<A>::constant(console_path_hasher.clone());

        // Constructing the in-circuit path (i.e. Merkle proof) in private mode.
        let circuit_path = circuit::merkle_tree::MerklePath::new(Mode::Private, console_path);

        // Verifying the path inside the circuit.
        A::assert(circuit_path.verify(&circuit_leaf_hasher, &circuit_path_hasher, circuit_root, &circuit_leaf))?;

        let circuit_entry_plaintext = match circuit_entry {
            circuit::Entry::Constant(plaintext) => plaintext,
            circuit::Entry::Public(plaintext) => plaintext,
            circuit::Entry::Private(plaintext) => plaintext,
        };

        registers.store_circuit(stack, &self.destination, circuit::Value::Plaintext(circuit_entry_plaintext))?;

        Ok(())
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(
        &self,
        _stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        _registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        bail!("Forbidden operation: Finalize cannot invoke 'get.record.dynamic'.")
    }

    /// Returns the output type from the given program and input types.
    pub fn output_types(
        &self,
        _stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        ensure!(input_types.len() == 1, "Expected 1 input type, found {}", input_types.len());
        ensure!(
            matches!(input_types[0], RegisterType::DynamicRecord),
            "Expected dynamic record, found {}",
            input_types[0]
        );

        Ok(vec![RegisterType::Plaintext(self.plaintext_type.clone())])
    }
}

impl<N: Network> GetRecordDynamic<N> {
    // Internal auxiliary function which computes the console Merkle path to the given entry.
    // If the record data is not present, it is populated with arbitrary values.
    // This can happen:
    //  - during synthesis, where it is normal
    //  - during execution, where it is an error
    //
    // In the case where the data is present, the root of the resulting tree is checked against the provided one.
    // An error is also returned if the data is present but does not contain the requested entry.
    #[allow(clippy::type_complexity)]
    fn compute_or_sample_path(
        opt_data: Option<&IndexMap<Identifier<N>, Entry<N, Plaintext<N>>>>,
        entry_identifier: &Identifier<N>,
        stack: &impl StackTrait<N>,
        plaintext_type: &PlaintextType<N>,
        root: &Field<N>,
        visibility: Option<&Visibility>,
    ) -> Result<(Entry<N, Plaintext<N>>, MerklePath<N, RECORD_DATA_TREE_DEPTH>)> {
        match opt_data {
            Some(data) => {
                // Retrieve the entry.
                let (index, _, entry) = data.get_full(entry_identifier).ok_or_else(|| {
                    anyhow!("The dynamic record's data is present but does not contain entry {entry_identifier}",)
                })?;

                // Construct the leaf of the merkleized data tree.
                let mut leaf = vec![entry_identifier.to_field()?];
                leaf.extend(entry.to_fields()?);
                let tree = DynamicRecord::merkleize_data(data)?;

                // Compute the path.
                let path = tree.prove(index, &leaf)?;

                // Check that the leaf index in the path matches the entry index in the data.
                ensure!(
                    *path.leaf_index() == index as u64,
                    "Entry {} has index {} in the dynamic record's data, but its leaf index in the dynamic record's Merkle tree is {}",
                    entry_identifier,
                    index,
                    *path.leaf_index()
                );
                // Check that the root in the path matches the provided root.
                ensure!(
                    tree.root() == root,
                    "The root in the dynamic record does not match the one computed from its data"
                );

                Ok((entry.clone(), path.clone()))
            }
            None => {
                // Sample an arbitrary value for the entry, consistent with the specified type.
                // Note: This MUST be deterministic across all validators verifying the same deployment.
                // The not-present branch is reached during `CheckDeployment` synthesis (a sampled dynamic
                // record carries no data), and the sampled value is stored to a register that a program
                // can feed into a `call.dynamic` target. Drawing it from the ambient `rand::rng()` would
                // let the same deployment verify on some validators and fail on others. We therefore seed
                // a deterministic RNG from the (deterministic) record root and entry identifier; the
                // concrete value is a dummy witness used only for synthesis, so only its determinism matters.
                let value = {
                    let root_bytes = root.to_bytes_le()?;
                    let entry_bytes = entry_identifier.to_field()?.to_bytes_le()?;
                    let root_seed = u64::from_bytes_le(&root_bytes[..8])?;
                    let entry_seed = u64::from_bytes_le(&entry_bytes[..8])?;
                    let mut rng = ChaChaRng::seed_from_u64(root_seed ^ entry_seed);
                    let address = Address::<N>::rand(&mut rng);
                    stack.sample_value(&address, &RegisterType::Plaintext(plaintext_type.clone()), &mut rng)?
                };

                let entry = match value {
                    // When visibility is specified, the visibility bits are injected as constants in the circuit.
                    // The entry variant must match so that the circuit structure is correct during synthesis/key generation.
                    // When unspecified, visibility is a private witness so the variant here can be arbitrary. In this case it is `Public`.
                    Value::Plaintext(plaintext) => match visibility {
                        Some(Visibility::Constant) => Entry::Constant(plaintext),
                        Some(Visibility::Private) => Entry::Private(plaintext),
                        Some(Visibility::Public) | None => Entry::Public(plaintext),
                    },
                    _ => {
                        bail!("Expected plaintext value while sampling an entry for a dynamic record, found {value:?}")
                    }
                };

                let path =
                    MerklePath::try_from((U64::new(0), vec![Field::<N>::zero(); RECORD_DATA_TREE_DEPTH as usize]))?;

                Ok((entry, path))
            }
        }
    }
}

impl<N: Network> Parser for GetRecordDynamic<N> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the source operand from the string.
        let (string, source_operand) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the 'into' from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the 'as' from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the plaintext type from the string.
        let (string, plaintext_type) = PlaintextType::parse(string)?;
        // Optionally parse a visibility suffix (e.g. `.private`, `.public`, `.constant`).
        let (string, visibility) = opt(alt((
            map(tag(".constant"), |_| Visibility::Constant),
            map(tag(".public"), |_| Visibility::Public),
            map(tag(".private"), |_| Visibility::Private),
        )))(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        match Self::new(source_operand, destination, plaintext_type, visibility) {
            Ok(instruction) => Ok((string, instruction)),
            Err(e) => map_res(fail, |_: ParserResult<Self>| {
                Err(error(format!("Failed to parse '{}' instruction: {e}", Self::opcode())))
            })(string),
        }
    }
}

impl<N: Network> FromStr for GetRecordDynamic<N> {
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

impl<N: Network> Debug for GetRecordDynamic<N> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for GetRecordDynamic<N> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Print the operation.
        write!(
            f,
            "{} {}.{} into {} as {}",
            Self::opcode(),
            self.operands[0],
            self.entry_identifier,
            self.destination,
            self.plaintext_type
        )?;
        // Append visibility suffix if specified.
        match &self.visibility {
            Some(Visibility::Constant) => write!(f, ".constant"),
            Some(Visibility::Public) => write!(f, ".public"),
            Some(Visibility::Private) => write!(f, ".private"),
            None => Ok(()),
        }
    }
}

impl<N: Network> FromBytes for GetRecordDynamic<N> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let operand = Operand::read_le(&mut reader)?;
        let destination = Register::read_le(&mut reader)?;
        let entry_identifier = Identifier::read_le(&mut reader)?;
        let plaintext_type = PlaintextType::read_le(&mut reader)?;

        // Read the optional expected visibility.
        let has_visibility = bool::read_le(&mut reader)?;
        let visibility = if has_visibility {
            let vis = u8::read_le(&mut reader)?;
            Some(match vis {
                0 => Visibility::Constant,
                1 => Visibility::Public,
                2 => Visibility::Private,
                _ => return Err(error(format!("Expected visibility must be 0, 1, or 2, found {vis}"))),
            })
        } else {
            None
        };

        if !matches!(operand, Operand::Register(Register::Locator(_))) {
            return Err(error(format!("Expected (prepared) operand of the form r<i>, found {operand}")));
        }

        if !matches!(destination, Register::Locator(_)) {
            return Err(error(format!("Expected destination of the form r<i>, found {destination}")));
        }

        // Return the operation.
        Ok(Self { operands: [operand], destination, entry_identifier, plaintext_type, visibility })
    }
}

impl<N: Network> ToBytes for GetRecordDynamic<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the source operand.
        self.operands[0].write_le(&mut writer)?;
        // Write the destination register.
        self.destination.write_le(&mut writer)?;
        // Write the entry identifier.
        self.entry_identifier.write_le(&mut writer)?;
        // Write the entry type.
        self.plaintext_type.write_le(&mut writer)?;
        // Write the optional expected visibility.
        self.visibility.is_some().write_le(&mut writer)?;
        if let Some(visibility) = &self.visibility {
            (*visibility as u8).write_le(&mut writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use console::{network::MainnetV0, program::ArrayType};
    type CurrentNetwork = MainnetV0;

    fn test_serialization(instruction: GetRecordDynamic<CurrentNetwork>) {
        let bytes = instruction.to_bytes_le().unwrap();
        let bytes_result = GetRecordDynamic::from_bytes_le(&bytes[..]);
        assert!(bytes_result.is_ok());
        assert_eq!(instruction, bytes_result.unwrap());

        let str = instruction.to_string();
        let str_result = GetRecordDynamic::from_str(&str);
        assert!(str_result.is_ok());
        assert_eq!(instruction, str_result.unwrap());
    }

    #[test]
    fn test_parse_and_serialization() {
        // ************ Literal types ************
        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.outdated into r1 as bool").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("outdated").unwrap());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("bool").unwrap());
        assert!(instruction.visibility().is_none());
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.middleman into r1 as address").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("middleman").unwrap());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("address").unwrap());

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.sk into r1 as field").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("sk").unwrap());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("field").unwrap());
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.pk into r1 as group").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("pk").unwrap());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("group").unwrap());
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.crs_byte into r1 as u8").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("crs_byte").unwrap());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u8").unwrap());
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.size into r1 as u16").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("size").unwrap());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u16").unwrap());
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.register into r1 as u32").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("register").unwrap());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u32").unwrap());
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.usize into r1 as u64").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("usize").unwrap());
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u64").unwrap());
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.long into r1 as u128").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(0)));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("long").unwrap());
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u128").unwrap());
        test_serialization(instruction);

        // ************ Other correct cases ************
        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r3.banana into r3 as fruit_struct").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(3)));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("banana").unwrap());
        assert_eq!(instruction.destination, Register::Locator(3));
        assert_eq!(instruction.plaintext_type, PlaintextType::Struct(Identifier::from_str("fruit_struct").unwrap()));
        test_serialization(instruction);

        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r1.apples into r1 as [fruit_struct; 20u32]")
                .unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(1)));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("apples").unwrap());
        assert_eq!(instruction.destination, Register::Locator(1));
        assert_eq!(
            instruction.plaintext_type,
            PlaintextType::Array(ArrayType::from_str("[fruit_struct; 20u32]").unwrap())
        );
        test_serialization(instruction);

        let (remainder, instruction) = GetRecordDynamic::<CurrentNetwork>::parse(
            "get.record.dynamic r45.dragonfruit_matrix into r49 as [[fruit_struct; 20u32]; 10u32]",
        )
        .unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.operands().len(), 1);
        assert_eq!(instruction.operands()[0], Operand::Register(Register::Locator(45)));
        assert_eq!(instruction.entry_identifier, Identifier::from_str("dragonfruit_matrix").unwrap());
        assert_eq!(instruction.destination, Register::Locator(49));
        assert_eq!(
            instruction.plaintext_type,
            PlaintextType::Array(ArrayType::from_str("[[fruit_struct; 20u32]; 10u32]").unwrap())
        );
        test_serialization(instruction);

        // ************ Incorrect cases ************
        let incorrect_cases = [
            // Incorrect source: no identifier
            "get.record.dynamic r1 into r0 as field",
            // Incorrect: several source operands
            "get.record.dynamic r1.apples r2.banana into r0 as field",
            // Incorrect: several target operands
            "get.record.dynamic r1.apples into r0 r1 as field",
            // Incorrect: no "into"
            "get.record.dynamic r1.apples as field",
            // Incorrect: no "as"
            "get.record.dynamic r1.apples into r0 field",
            // Incorrect: no entry type
            "get.record.dynamic r1.apples into r0 as",
            // Incorrect: wrong access type access
            "get.record.dynamic r1[2u32] into r0 as fruit_struct",
            // Incorrect: finer access than the allowed entry name
            "get.record.dynamic r1.grape_vine[70u32] into r0 as fruit_struct",
        ];

        for case in incorrect_cases {
            assert!(GetRecordDynamic::<CurrentNetwork>::parse(case).is_err());
        }
    }

    #[test]
    fn test_parse_with_visibility() {
        // Parse with `.private` visibility.
        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.amount into r1 as u64.private").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u64").unwrap());
        assert_eq!(instruction.visibility(), Some(&Visibility::Private));
        test_serialization(instruction);

        // Parse with `.public` visibility.
        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.amount into r1 as u64.public").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u64").unwrap());
        assert_eq!(instruction.visibility(), Some(&Visibility::Public));
        test_serialization(instruction);

        // Parse with `.constant` visibility.
        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.amount into r1 as u64.constant").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u64").unwrap());
        assert_eq!(instruction.visibility(), Some(&Visibility::Constant));
        test_serialization(instruction);

        // Parse struct type with visibility.
        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.banana into r1 as fruit_struct.private")
                .unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.plaintext_type, PlaintextType::Struct(Identifier::from_str("fruit_struct").unwrap()));
        assert_eq!(instruction.visibility(), Some(&Visibility::Private));
        test_serialization(instruction);

        // Parse without visibility (existing behavior).
        let (remainder, instruction) =
            GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.amount into r1 as u64").unwrap();
        assert!(remainder.is_empty());
        assert_eq!(instruction.plaintext_type, PlaintextType::from_str("u64").unwrap());
        assert!(instruction.visibility().is_none());
        test_serialization(instruction);

        // Invalid visibility suffix should not parse as visibility (falls back to bare type).
        let result = GetRecordDynamic::<CurrentNetwork>::parse("get.record.dynamic r0.amount into r1 as u64.secret");
        // `PlaintextType::parse` parses `u64`, then `opt(alt(...))` does not match `.secret`,
        // so the instruction parses successfully but `.secret` remains.
        assert!(result.is_ok());
        let (remainder, instruction) = result.unwrap();
        assert_eq!(remainder, ".secret");
        assert!(instruction.visibility().is_none());
    }
}
