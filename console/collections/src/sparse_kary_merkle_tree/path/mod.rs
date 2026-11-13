// Copyright (c) 2019-2025 Provable Inc.
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

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SparseKaryMerklePath<E: Environment, PH: PathHash, const DEPTH: u8, const ARITY: u8> {
    /// The key hash for the path (determines the path through the tree).
    key_hash: Field<E>,
    /// The `siblings` contains a list of sibling hashes from the leaf to the root.
    siblings: Vec<Vec<PH::Hash>>,
    /// Phantom data for the environment.
    _phantom: std::marker::PhantomData<E>,
}

impl<E: Environment, PH: PathHash, const DEPTH: u8, const ARITY: u8> SparseKaryMerklePath<E, PH, DEPTH, ARITY> {
    /// Returns a new instance of a sparse Merkle path.
    pub fn try_from((key_hash, siblings): (Field<E>, Vec<Vec<PH::Hash>>)) -> Result<Self> {
        // Ensure the Merkle tree depth is greater than 0.
        ensure!(DEPTH > 0, "Merkle tree depth must be greater than 0");
        // Ensure the Merkle tree arity is greater than 1.
        ensure!(ARITY > 1, "Merkle tree arity must be greater than 1");
        // Ensure the Merkle path is the correct length.
        ensure!(siblings.len() == DEPTH as usize, "Found an incorrect Merkle path length");
        for sibling in &siblings {
            // Note: The ARITY is guaranteed to be greater than 1 (by the above check).
            ensure!(sibling.len() == (ARITY - 1) as usize, "Found an incorrect Merkle path arity");
        }
        // Return the Merkle path.
        Ok(Self { key_hash, siblings, _phantom: std::marker::PhantomData })
    }
}

impl<E: Environment, PH: PathHash, const DEPTH: u8, const ARITY: u8> SparseKaryMerklePath<E, PH, DEPTH, ARITY> {
    /// Returns the key hash for the path.
    pub fn key_hash(&self) -> &Field<E> {
        &self.key_hash
    }

    /// Returns the siblings for the path.
    pub fn siblings(&self) -> &[Vec<PH::Hash>] {
        &self.siblings
    }

    /// Returns `true` if the Merkle path is valid for the given root, key, and leaf.
    pub fn verify<KH: KeyHash<Hash = Field<E>>, LH: LeafHash<Hash = PH::Hash>>(
        &self,
        key_hasher: &KH,
        leaf_hasher: &LH,
        path_hasher: &PH,
        root: &PH::Hash,
        key: &KH::Key,
        leaf: &LH::Leaf,
    ) -> bool {
        // Hash the key.
        let key_hash = match key_hasher.hash_key(key) {
            Ok(hash) => hash,
            Err(error) => {
                eprintln!("Failed to hash the key during verification: {error}");
                return false;
            }
        };

        // Ensure the key hash matches the one in the path.
        if self.key_hash != key_hash {
            eprintln!("Key hash mismatch during verification");
            return false;
        }

        // Ensure the path length matches the expected depth.
        if self.siblings.len() != DEPTH as usize {
            eprintln!("Found an incorrect Merkle path length");
            return false;
        }

        // Initialize a tracker for the current hash, by computing the leaf hash to start.
        let mut current_hash = match leaf_hasher.hash_leaf(leaf) {
            Ok(candidate_leaf_hash) => candidate_leaf_hash,
            Err(error) => {
                eprintln!("Failed to hash the Merkle leaf during verification: {error}");
                return false;
            }
        };

        // Convert the key hash to bits to determine the path.
        // Use consecutive bits to get maximum entropy from the hash.
        let key_bits = key_hash.to_bits_le();

        // Compute the number of bits needed per level.
        let bits_per_level = ARITY.next_power_of_two().trailing_zeros() as usize;

        // Compute the path indices from the key hash using consecutive bits.
        let mut path_indices = Vec::with_capacity(DEPTH as usize);
        for depth in 0..DEPTH as usize {
            let start_bit = depth * bits_per_level;
            let end_bit = std::cmp::min(start_bit + bits_per_level, key_bits.len());

            let mut index = 0usize;
            for (i, bit) in key_bits[start_bit..end_bit].iter().enumerate() {
                if *bit {
                    index |= 1 << i;
                }
            }

            // Ensure the index is within the arity.
            path_indices.push(index % ARITY as usize);
        }

        // Check levels between leaf level and root.
        // Iterate from leaf to root (reverse order).
        for (indicator_index, sibling_hashes) in path_indices.into_iter().rev().zip_eq(self.siblings.iter().rev()) {
            // Construct the ordering of sibling hashes for this level.
            let mut sibling_hashes = sibling_hashes.clone();

            // Insert the current hash into the list of sibling hashes at the correct position.
            sibling_hashes.insert(indicator_index, current_hash);

            // Update the current hash for the next level.
            match path_hasher.hash_children(&sibling_hashes) {
                Ok(hash) => current_hash = hash,
                Err(error) => {
                    eprintln!("Failed to hash the Merkle path during verification: {error}");
                    return false;
                }
            }
        }

        // Ensure the final hash matches the given root.
        current_hash == *root
    }
}

impl<E: Environment, PH: PathHash, const DEPTH: u8, const ARITY: u8> FromBytes
    for SparseKaryMerklePath<E, PH, DEPTH, ARITY>
{
    /// Reads in a Merkle path from a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the key hash.
        let key_hash = Field::<E>::read_le(&mut reader)?;
        // Read the Merkle path siblings.
        let siblings = (0..DEPTH)
            .map(|_| (0..ARITY - 1).map(|_| FromBytes::read_le(&mut reader)).collect::<IoResult<Vec<_>>>())
            .collect::<IoResult<Vec<_>>>()?;
        // Return the Merkle path.
        Self::try_from((key_hash, siblings)).map_err(into_io_error)
    }
}

impl<E: Environment, PH: PathHash, const DEPTH: u8, const ARITY: u8> ToBytes
    for SparseKaryMerklePath<E, PH, DEPTH, ARITY>
{
    /// Writes the Merkle path to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the key hash.
        self.key_hash.write_le(&mut writer)?;
        // Write the Merkle path siblings.
        self.siblings
            .iter()
            .try_for_each(|siblings| siblings.iter().try_for_each(|sibling| sibling.write_le(&mut writer)))
    }
}

impl<E: Environment, PH: PathHash, const DEPTH: u8, const ARITY: u8> Serialize
    for SparseKaryMerklePath<E, PH, DEPTH, ARITY>
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ToBytesSerializer::serialize_with_size_encoding(self, serializer)
    }
}

impl<'de, E: Environment, PH: PathHash, const DEPTH: u8, const ARITY: u8> Deserialize<'de>
    for SparseKaryMerklePath<E, PH, DEPTH, ARITY>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "Sparse K-ary Merkle path")
    }
}
