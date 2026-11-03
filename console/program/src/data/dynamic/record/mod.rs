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
mod equal;
mod find;
mod parse;
mod to_bits;
mod to_fields;

use crate::{
    Access,
    Address,
    Boolean,
    Entry,
    Field,
    Group,
    Identifier,
    Literal,
    Network,
    Owner,
    Plaintext,
    Record,
    Result,
    ToField,
    ToFields,
    U8,
    Value,
};

use snarkvm_console_algorithms::{Poseidon2, Poseidon8};
use snarkvm_console_collections::merkle_tree::MerkleTree;
use snarkvm_console_network::*;

use indexmap::IndexMap;

/// The depth of the record data tree.
pub const RECORD_DATA_TREE_DEPTH: u8 = 5;

/// The record data tree.
pub type RecordDataTree<E> = MerkleTree<E, Poseidon8<E>, Poseidon2<E>, RECORD_DATA_TREE_DEPTH>;
/// The console data.
pub type RecordData<N> = IndexMap<Identifier<N>, Entry<N, Plaintext<N>>>;

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
/// and `ToFields` packs the entry's mode tag bits (2 bits), plaintext bits, and a terminus `1`
/// bit into field elements. The terminus bit ensures collision-resistance across entries of
/// different lengths.
///
/// The tree has depth `RECORD_DATA_TREE_DEPTH = 5` and is constructed with
/// path hasher `HashPSD2` and the padding scheme outlined in
/// [`snarkVM`'s `MerkleTree`](snarkvm_console_collections::merkle_tree::MerkleTree).
#[derive(Clone)]
pub struct DynamicRecord<N: Network> {
    /// The owner of the record.
    owner: Address<N>,
    /// The Merkle root of the record data.
    root: Field<N>,
    /// The nonce of the record.
    nonce: Group<N>,
    /// The version of the record.
    version: U8<N>,
    /// The optional record data.
    data: Option<RecordData<N>>,
}

impl<N: Network> DynamicRecord<N> {
    /// Initializes a dynamic record without checking that the root, tree, and data are consistent.
    pub const fn new_unchecked(
        owner: Address<N>,
        root: Field<N>,
        nonce: Group<N>,
        version: U8<N>,
        data: Option<RecordData<N>>,
    ) -> Self {
        Self { owner, root, nonce, version, data }
    }
}

impl<N: Network> DynamicRecord<N> {
    /// Returns the owner of the record.
    pub const fn owner(&self) -> &Address<N> {
        &self.owner
    }

    /// Returns the Merkle root of the record data.
    pub const fn root(&self) -> &Field<N> {
        &self.root
    }

    /// Returns the nonce of the record.
    pub const fn nonce(&self) -> &Group<N> {
        &self.nonce
    }

    /// Returns the version of the record.
    pub const fn version(&self) -> &U8<N> {
        &self.version
    }

    /// Returns the optional record data.
    pub const fn data(&self) -> &Option<RecordData<N>> {
        &self.data
    }

    /// Returns `true` if the dynamic record is a hiding variant.
    pub fn is_hiding(&self) -> bool {
        !self.version.is_zero()
    }
}

impl<N: Network> DynamicRecord<N> {
    /// Creates a dynamic record from a static record.
    pub fn from_record(record: &Record<N, Plaintext<N>>) -> Result<Self> {
        // Get the owner.
        let owner = *record.owner().clone();
        // Get the record data.
        let data = record.data().clone();
        // Get the nonce.
        let nonce = *record.nonce();
        // Get the version.
        let version = *record.version();

        // Construct the merkle tree.
        let tree = Self::merkleize_data(&data)?;

        // Get the root.
        let root = *tree.root();

        Ok(Self::new_unchecked(owner, root, nonce, version, Some(data)))
    }

    /// Creates a static record from this dynamic record.
    pub fn to_record(&self, owner_is_private: bool) -> Result<Record<N, Plaintext<N>>> {
        // Ensure that the data is present.
        let Some(data) = &self.data else {
            bail!("Cannot convert a dynamic record to static record without the underlying data");
        };
        // Create the owner.
        let owner = match owner_is_private {
            false => Owner::<N, Plaintext<N>>::Public(self.owner),
            true => Owner::<N, Plaintext<N>>::Private(Plaintext::from(Literal::Address(self.owner))),
        };
        // Return the record.
        Record::<N, Plaintext<N>>::from_plaintext(owner, data.clone(), self.nonce, self.version)
    }

    /// Computes the Merkle tree containing the given (ordered) entries as
    /// leaves. More details on the structure of the tree can be found in
    /// [`DynamicRecord`].
    pub fn merkleize_data(data: &IndexMap<Identifier<N>, Entry<N, Plaintext<N>>>) -> Result<RecordDataTree<N>> {
        // Construct the leaves.
        let leaves = data
            .iter()
            .map(|(name, entry)| {
                // Compute the entry fields.
                let fields = entry.to_fields()?;
                // Initialize the leaf with sufficient capacity.
                let mut leaf = Vec::with_capacity(1 + fields.len());
                // Add the entry name.
                leaf.push(name.to_field()?);
                // Add the entry data.
                leaf.extend(fields);

                Ok(leaf)
            })
            .collect::<Result<Vec<_>>>()?;

        // Initialize the hashers.
        let (leaf_hasher, path_hasher) = Self::initialize_hashers();

        // Construct the merkle tree.
        RecordDataTree::new(leaf_hasher, path_hasher, &leaves)
    }

    /// Returns the leaf and path hashers used to merkleize record entries.
    pub fn initialize_hashers() -> (&'static Poseidon8<N>, &'static Poseidon2<N>) {
        (N::dynamic_record_leaf_hasher(), N::dynamic_record_path_hasher())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    use crate::{Entry, Literal, Owner, Record};
    use snarkvm_console_types::{Address, Group, U8, U64};
    use snarkvm_utilities::{TestRng, Uniform};

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_data_depth() {
        assert_eq!(CurrentNetwork::MAX_DATA_ENTRIES.ilog2(), RECORD_DATA_TREE_DEPTH as u32);
    }

    fn create_test_record(
        rng: &mut TestRng,
        data: RecordData<CurrentNetwork>,
        owner_is_private: bool,
    ) -> Record<CurrentNetwork, Plaintext<CurrentNetwork>> {
        let owner = match owner_is_private {
            true => Owner::Private(Plaintext::from(Literal::Address(Address::rand(rng)))),
            false => Owner::Public(Address::rand(rng)),
        };
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(owner, data, Group::rand(rng), U8::new(0))
            .unwrap()
    }

    fn assert_round_trip(record: &Record<CurrentNetwork, Plaintext<CurrentNetwork>>, owner_is_private: bool) {
        let dynamic = DynamicRecord::from_record(record).unwrap();
        let recovered = dynamic.to_record(owner_is_private).unwrap();
        assert_eq!(record.nonce(), recovered.nonce());
        assert_eq!(record.data(), recovered.data());
    }

    #[test]
    fn test_round_trip_various_records() {
        let rng = &mut TestRng::default();

        // Empty record.
        let record = create_test_record(rng, indexmap::IndexMap::new(), false);
        assert_round_trip(&record, false);

        // Private entries.
        let data = indexmap::indexmap! {
            Identifier::from_str("a").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("b").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let record = create_test_record(rng, data, true);
        assert_round_trip(&record, true);

        // Public entries.
        let data = indexmap::indexmap! {
            Identifier::from_str("x").unwrap() => Entry::Public(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let record = create_test_record(rng, data, false);
        assert_round_trip(&record, false);

        // Mixed visibility.
        let data = indexmap::indexmap! {
            Identifier::from_str("pub").unwrap() => Entry::Public(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("priv").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("const").unwrap() => Entry::Constant(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let record = create_test_record(rng, data, true);
        assert_round_trip(&record, true);

        // Struct entry.
        let inner = Plaintext::Struct(
            indexmap::indexmap! {
                Identifier::from_str("x").unwrap() => Plaintext::from(Literal::U64(U64::rand(rng))),
                Identifier::from_str("y").unwrap() => Plaintext::from(Literal::U64(U64::rand(rng))),
            },
            Default::default(),
        );
        let data = indexmap::indexmap! {
            Identifier::from_str("point").unwrap() => Entry::Private(inner),
        };
        let record = create_test_record(rng, data, false);
        assert_round_trip(&record, false);
    }

    #[test]
    fn test_root_determinism() {
        let rng = &mut TestRng::default();

        let data1 = indexmap::indexmap! {
            Identifier::from_str("a").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::new(100)))),
        };
        let data2 = indexmap::indexmap! {
            Identifier::from_str("a").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::new(100)))),
        };
        let data3 = indexmap::indexmap! {
            Identifier::from_str("a").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::new(200)))),
        };

        let r1 = DynamicRecord::from_record(&create_test_record(rng, data1, false)).unwrap();
        let r2 = DynamicRecord::from_record(&create_test_record(rng, data2, false)).unwrap();
        let r3 = DynamicRecord::from_record(&create_test_record(rng, data3, false)).unwrap();

        assert_eq!(r1.root(), r2.root(), "Same data should produce same root");
        assert_ne!(r1.root(), r3.root(), "Different data should produce different roots");
    }

    #[test]
    fn test_membership_proofs() {
        let rng = &mut TestRng::default();

        let data = indexmap::indexmap! {
            Identifier::from_str("a").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("b").unwrap() => Entry::Public(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("c").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };

        // Build tree and get leaves.
        let tree = DynamicRecord::<CurrentNetwork>::merkleize_data(&data).unwrap();
        let leaves: Vec<_> = data
            .iter()
            .map(|(name, entry)| {
                let mut leaf = vec![name.to_field().unwrap()];
                leaf.extend(entry.to_fields().unwrap());
                leaf
            })
            .collect();

        // Valid proofs.
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.prove(i, leaf).unwrap();
            assert!(tree.verify(&path, tree.root(), leaf));
        }

        // Invalid proofs.
        let path = tree.prove(0, &leaves[0]).unwrap();
        assert!(!tree.verify(&path, tree.root(), &leaves[1])); // Wrong leaf.
        assert!(!tree.verify(&path, &Field::from_u64(12345), &leaves[0])); // Wrong root.
    }

    #[test]
    fn test_find_owner() {
        let rng = &mut TestRng::default();
        let owner_addr = Address::rand(rng);
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            Owner::Public(owner_addr),
            indexmap::IndexMap::new(),
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let dynamic = DynamicRecord::from_record(&record).unwrap();

        // Finding "owner" must return the owner address.
        let path = [Access::Member(Identifier::from_str("owner").unwrap())];
        let value = dynamic.find(&path).unwrap();
        assert_eq!(value, Value::Plaintext(Plaintext::from(Literal::Address(owner_addr))));
    }

    #[test]
    fn test_find_rejects_non_owner_paths() {
        let rng = &mut TestRng::default();
        let record = create_test_record(rng, indexmap::IndexMap::new(), false);
        let dynamic = DynamicRecord::from_record(&record).unwrap();

        // Any path other than "owner" must be rejected.
        let path = [Access::Member(Identifier::from_str("data").unwrap())];
        assert!(dynamic.find(&path).is_err());

        // An empty path must be rejected.
        let empty: &[Access<CurrentNetwork>] = &[];
        assert!(dynamic.find(empty).is_err());

        // A path of length > 1 must be rejected.
        let long_path = [
            Access::Member(Identifier::from_str("owner").unwrap()),
            Access::Member(Identifier::from_str("nested").unwrap()),
        ];
        assert!(dynamic.find(&long_path).is_err());
    }
}
