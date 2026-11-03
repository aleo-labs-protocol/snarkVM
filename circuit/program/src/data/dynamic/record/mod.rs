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

mod equal;
mod find;
mod to_bits;
mod to_fields;

use crate::{Access, Aleo, Entry, Equal, Identifier, Literal, Plaintext, Record, ToBits, ToFields, Value};

use console::RECORD_DATA_TREE_DEPTH;
use snarkvm_circuit_algorithms::{Poseidon2, Poseidon8};
use snarkvm_circuit_collections::merkle_tree::MerkleTree;
use snarkvm_circuit_types::{Address, Boolean, Field, Group, U8, environment::prelude::*};

type CircuitLH<A> = Poseidon8<A>;
type CircuitPH<A> = Poseidon2<A>;

/// The record data tree.
pub type RecordDataTree<A> = MerkleTree<A, CircuitLH<A>, CircuitPH<A>, RECORD_DATA_TREE_DEPTH>;

/// A dynamic record is a fixed-size representation of a record. Like static
/// `Record`s, a dynamic record contains an owner, nonce, and a version.
/// However, instead of storing the full data, it only stores the Merkle root of
/// the data. This ensures that all dynamic records have a constant size,
/// regardless of the amount of data they contain.
///
/// Suppose we have the following record with two data entries:
///
/// ```text
/// record foo:
///     owner as address.private;
///     microcredits as u64.private;
///     memo as [u8; 32u32].public;
/// ```
///
/// The leaves of its Merkle tree are computed as follows:
///
/// ```text
/// L_0 := HashPSD8(ToField(name_0) || ToFields(entry_0))
/// L_1 := HashPSD8(ToField(name_1) || ToFields(entry_1))
/// ```
///
/// where `name_i` is the field encoding of the entry identifier (e.g. `"microcredits"` → `Field`),
/// and `ToFields` encodes the entry's mode and plaintext variant.
///
/// The tree has depth `RECORD_DATA_TREE_DEPTH = 5` and is constructed with
/// path hasher `HashPSD2` and the padding scheme outlined in
/// [`snarkVM`'s `MerkleTree`](snarkvm_circuit_collections::merkle_tree::MerkleTree).
#[derive(Clone)]
pub struct DynamicRecord<A: Aleo> {
    /// The owner of the record.
    owner: Address<A>,
    /// The Merkle root of the record data.
    root: Field<A>,
    /// The nonce of the record.
    nonce: Group<A>,
    /// The version of the record.
    version: U8<A>,
    /// The optional console record data.
    /// Note: This is NOT part of the circuit representation.
    data: Option<console::RecordData<A::Network>>,
}

impl<A: Aleo> Inject for DynamicRecord<A> {
    type Primitive = console::DynamicRecord<A::Network>;

    /// Initializes a plaintext record from a primitive.
    fn new(_: Mode, record: Self::Primitive) -> Self {
        Self {
            owner: Inject::new(Mode::Private, *record.owner()),
            root: Inject::new(Mode::Private, *record.root()),
            nonce: Inject::new(Mode::Private, *record.nonce()),
            version: Inject::new(Mode::Private, *record.version()),
            data: record.data().clone(),
        }
    }
}

impl<A: Aleo> DynamicRecord<A> {
    /// Returns the owner of the record.
    pub const fn owner(&self) -> &Address<A> {
        &self.owner
    }

    /// Returns the Merkle root of the record data.
    pub const fn root(&self) -> &Field<A> {
        &self.root
    }

    /// Returns the nonce of the record.
    pub const fn nonce(&self) -> &Group<A> {
        &self.nonce
    }

    /// Returns the version of the record.
    pub const fn version(&self) -> &U8<A> {
        &self.version
    }

    /// Returns the console record data.
    pub const fn data(&self) -> Option<&console::RecordData<A::Network>> {
        self.data.as_ref()
    }
}

impl<A: Aleo> Eject for DynamicRecord<A> {
    type Primitive = console::DynamicRecord<A::Network>;

    /// Ejects the mode of the dynamic record.
    fn eject_mode(&self) -> Mode {
        let owner = self.owner.eject_mode();
        let root = self.root.eject_mode();
        let nonce = self.nonce.eject_mode();
        let version = self.version.eject_mode();

        Mode::combine(owner, [root, nonce, version])
    }

    /// Ejects the dynamic record.
    fn eject_value(&self) -> Self::Primitive {
        Self::Primitive::new_unchecked(
            self.owner.eject_value(),
            self.root.eject_value(),
            self.nonce.eject_value(),
            self.version.eject_value(),
            self.data.clone(),
        )
    }
}

impl<A: Aleo> DynamicRecord<A> {
    /// Creates a dynamic record from a static one.
    pub fn from_record(record: &Record<A, Plaintext<A>>) -> Result<Self> {
        // This mimics the console::DynamicRecord::from_record function.

        // Note that, in most lines below, cloning (e.g. of record.owner())
        // does not introduce a new variable into the witness but rather creates
        // a new reference to the preexisting witness variable.

        // Get the owner.
        let owner = (**record.owner()).clone();
        // Get the record's data (not part of the circuit representation)
        let data = record.data();
        // Get the nonce.
        let nonce = record.nonce().clone();
        // Get the version.
        let version = record.version().clone();

        let tree = Self::merkleize_data(data)?;
        let root = tree.root().clone();

        let console_data =
            data.iter().map(|(identifier, entry)| (identifier, entry).eject_value()).collect::<IndexMap<_, _>>();

        Ok(Self { owner, root, nonce, version, data: Some(console_data) })
    }

    /// Serializes the given (ordered) entries to field elements, prepends an identifier tag
    /// per entry, and computes the Merkle tree over the resulting leaves. More details on
    /// the structure of the tree can be found in [`DynamicRecord`].
    pub fn merkleize_data(data: &IndexMap<Identifier<A>, Entry<A, Plaintext<A>>>) -> Result<RecordDataTree<A>> {
        // Initialize the circuit hashers.
        let (console_leaf_hasher, console_path_hasher) = console::DynamicRecord::initialize_hashers();
        let circuit_leaf_hasher = CircuitLH::<A>::constant(console_leaf_hasher.clone());
        let circuit_path_hasher = CircuitPH::<A>::constant(console_path_hasher.clone());

        // Serialize the in-circuit entries to leaf field elements.
        let leaves = data
            .iter()
            .map(|(identifier, entry)| {
                let fields = entry.to_fields();
                let mut leaf = Vec::with_capacity(1 + fields.len());
                leaf.push(identifier.to_field());
                leaf.extend(fields);
                leaf
            })
            .collect::<Vec<Vec<Field<A>>>>();

        // Construct the merkle tree
        RecordDataTree::<A>::new(circuit_leaf_hasher, circuit_path_hasher, &leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use snarkvm_circuit_types::environment::{Inject, assert_scope};
    use snarkvm_utilities::{TestRng, Uniform};

    use core::str::FromStr;

    type CurrentNetwork = <Circuit as Environment>::Network;
    type ConsoleRecord = console::Record<CurrentNetwork, console::Plaintext<CurrentNetwork>>;

    /// Verifies circuit/console equivalence for a record parsed from a string.
    /// This helper enables easier testing of various record structures.
    fn check_circuit_console_equivalence(
        record_str: &str,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        // Parse the record from the string.
        let console_record = ConsoleRecord::from_str(record_str).unwrap();

        // Convert to console DynamicRecord.
        let console_dynamic = console::DynamicRecord::from_record(&console_record).unwrap();

        // Inject the console record into the circuit.
        let circuit_record = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, console_record);

        Circuit::scope("check_circuit_console_equivalence", || {
            // Convert to circuit DynamicRecord.
            let circuit_dynamic = DynamicRecord::<Circuit>::from_record(&circuit_record).unwrap();

            // Verify the circuit root matches the console root.
            let circuit_root = circuit_dynamic.root().eject_value();
            let console_root = *console_dynamic.root();
            assert_eq!(
                circuit_root, console_root,
                "Circuit and console DynamicRecord should produce the same Merkle root"
            );

            // Verify other fields match.
            assert_eq!(circuit_dynamic.owner().eject_value(), *console_dynamic.owner());
            assert_eq!(circuit_dynamic.nonce().eject_value(), *console_dynamic.nonce());
            assert_eq!(circuit_dynamic.version().eject_value(), *console_dynamic.version());

            // Verify circuit constraint counts.
            assert_scope!(num_constants, num_public, num_private, num_constraints);
        });

        Circuit::reset();
    }

    /// Creates a console record with the given data for testing.
    fn create_console_record(
        rng: &mut TestRng,
        data: console::RecordData<CurrentNetwork>,
        owner_is_private: bool,
    ) -> ConsoleRecord {
        let owner = match owner_is_private {
            true => console::Owner::Private(console::Plaintext::from(console::Literal::Address(
                console::Address::rand(rng),
            ))),
            false => console::Owner::Public(console::Address::rand(rng)),
        };
        ConsoleRecord::from_plaintext(owner, data, console::Group::rand(rng), console::U8::new(0)).unwrap()
    }

    #[test]
    fn test_circuit_console_equivalence_empty_record() {
        // Empty record with public owner.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1075, 0, 0, 0);
    }

    #[test]
    fn test_circuit_console_equivalence_single_private_field() {
        // Record with a single private u64 field.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          amount: 100u64.private,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1100, 0, 3175, 3175);
    }

    #[test]
    fn test_circuit_console_equivalence_single_public_field() {
        // Record with a single public u64 field.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          amount: 100u64.public,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1100, 0, 3175, 3175);
    }

    #[test]
    fn test_circuit_console_equivalence_single_constant_field() {
        // Record with a single constant u64 field.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          amount: 100u64.constant,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1100, 0, 3175, 3175);
    }

    #[test]
    fn test_circuit_console_equivalence_mixed_entry_types() {
        let rng = &mut TestRng::default();

        // Create test data with mixed entry types (private, public, constant).
        let mut data = IndexMap::new();
        data.insert(
            console::Identifier::from_str("a").unwrap(),
            console::Entry::Private(console::Plaintext::from(console::Literal::U64(console::U64::rand(rng)))),
        );
        data.insert(
            console::Identifier::from_str("b").unwrap(),
            console::Entry::Public(console::Plaintext::from(console::Literal::U64(console::U64::rand(rng)))),
        );
        data.insert(
            console::Identifier::from_str("c").unwrap(),
            console::Entry::Constant(console::Plaintext::from(console::Literal::U64(console::U64::rand(rng)))),
        );

        // Create the record and convert to string for consistent testing.
        let console_record = create_console_record(rng, data, true);
        let record_str = console_record.to_string();

        check_circuit_console_equivalence(&record_str, 1151, 0, 4665, 4665);
    }

    #[test]
    fn test_circuit_console_equivalence_nested_struct() {
        let rng = &mut TestRng::default();

        // Create a nested struct entry.
        let mut inner_map = IndexMap::new();
        inner_map.insert(
            console::Identifier::from_str("x").unwrap(),
            console::Plaintext::from(console::Literal::U64(console::U64::rand(rng))),
        );
        inner_map.insert(
            console::Identifier::from_str("y").unwrap(),
            console::Plaintext::from(console::Literal::U64(console::U64::rand(rng))),
        );
        let inner = console::Plaintext::Struct(inner_map, Default::default());

        let mut data = IndexMap::new();
        data.insert(console::Identifier::from_str("point").unwrap(), console::Entry::Private(inner));

        // Create the record and convert to string for consistent testing.
        let console_record = create_console_record(rng, data, false);
        let record_str = console_record.to_string();

        check_circuit_console_equivalence(&record_str, 1180, 0, 3180, 3180);
    }

    #[test]
    fn test_circuit_console_equivalence_private_owner() {
        // Record with private owner.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1075, 0, 0, 0);
    }

    #[test]
    fn test_circuit_console_equivalence_multiple_fields() {
        // Record with multiple fields of the same visibility.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          x: 1u64.private,
          y: 2u64.private,
          z: 3u64.private,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1151, 0, 4665, 4665);
    }

    #[test]
    fn test_circuit_console_equivalence_boolean_field() {
        // Record with a boolean field.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          flag: true.private,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1100, 0, 3175, 3175);
    }

    #[test]
    fn test_circuit_console_equivalence_address_field() {
        // Record with an address field.
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          recipient: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        check_circuit_console_equivalence(record_str, 1100, 0, 3685, 3687);
    }

    #[test]
    fn test_find_owner() {
        let record_str = r#"{
          owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
          _nonce: 0group.public,
          _version: 0u8.public
        }"#;
        let console_record = ConsoleRecord::from_str(record_str).unwrap();
        let circuit_record = Record::<Circuit, Plaintext<Circuit>>::new(Mode::Private, console_record);
        let circuit_dynamic = DynamicRecord::<Circuit>::from_record(&circuit_record).unwrap();

        // Finding "owner" must succeed.
        let path = [Access::Member(Identifier::from_str("owner").unwrap())];
        assert!(circuit_dynamic.find(&path).is_ok());

        // Any path other than "owner" must fail.
        let path_bad = [Access::Member(Identifier::from_str("data").unwrap())];
        assert!(circuit_dynamic.find(&path_bad).is_err());
    }
}
