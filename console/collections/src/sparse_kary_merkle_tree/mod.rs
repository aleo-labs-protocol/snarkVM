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

mod helpers;
pub use helpers::*;

mod path;
pub use path::*;

#[cfg(test)]
mod tests;

use snarkvm_console_types::prelude::*;

use std::collections::BTreeMap;

#[derive(Clone)]
pub struct SparseKaryMerkleTree<
    KH: KeyHash<Hash = Field<E>>,
    LH: LeafHash<Hash = PH::Hash>,
    PH: PathHash,
    E: Environment,
    const DEPTH: u8,
    const ARITY: u8,
> {
    /// The key hasher for the Merkle tree.
    key_hasher: KH,
    /// The leaf hasher for the Merkle tree.
    leaf_hasher: LH,
    /// The path hasher for the Merkle tree.
    path_hasher: PH,
    /// The computed root of the sparse Merkle tree.
    root: PH::Hash,
    /// The internal nodes, stored as a map from path to hash.
    nodes: BTreeMap<Vec<u8>, PH::Hash>,
    /// The leaves, stored as a map from key hash to leaf hash.
    leaves: BTreeMap<Field<E>, PH::Hash>,
    /// The canonical empty hash.
    empty_hash: PH::Hash,
    /// The number of leaves in the tree.
    number_of_leaves: usize,
    /// Phantom data for the environment.
    _phantom: std::marker::PhantomData<E>,
}

impl<
    KH: KeyHash<Hash = Field<E>>,
    LH: LeafHash<Hash = PH::Hash>,
    PH: PathHash,
    E: Environment,
    const DEPTH: u8,
    const ARITY: u8,
> SparseKaryMerkleTree<KH, LH, PH, E, DEPTH, ARITY>
{
    /// Initializes a new empty sparse Merkle tree.
    #[inline]
    pub fn new(key_hasher: &KH, leaf_hasher: &LH, path_hasher: &PH) -> Result<Self> {
        // Ensure the Merkle tree depth is greater than 0.
        ensure!(DEPTH > 0, "Merkle tree depth must be greater than 0");
        // Ensure the Merkle tree arity is greater than 1.
        ensure!(ARITY > 1, "Merkle tree arity must be greater than 1");

        // Compute the empty hash.
        let empty_hash = path_hasher.hash_empty::<ARITY>()?;

        // Compute the root for an empty tree.
        let mut root = empty_hash;
        for _ in 0..DEPTH {
            root = path_hasher.hash_children(&vec![root; ARITY as usize])?;
        }

        Ok(Self {
            key_hasher: key_hasher.clone(),
            leaf_hasher: leaf_hasher.clone(),
            path_hasher: path_hasher.clone(),
            root,
            nodes: BTreeMap::new(),
            leaves: BTreeMap::new(),
            empty_hash,
            number_of_leaves: 0,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Inserts or updates a key-value pair in the sparse Merkle tree.
    /// The key hash determines the path through the tree, using consecutive bits for full entropy.
    pub fn update(&mut self, key: &KH::Key, leaf: &LH::Leaf) -> Result<()> {
        // Hash the key - this provides collision resistance through the hash function.
        // We use consecutive bits from the hash to get maximum entropy.
        let key_hash = self.key_hasher.hash_key(key)?;

        // Hash the leaf.
        let leaf_hash = self.leaf_hasher.hash_leaf(leaf)?;

        // Store the leaf hash indexed by key hash, checking if this is a new leaf.
        let is_new = self.leaves.insert(key_hash, leaf_hash).is_none();

        // Update the leaf count.
        if is_new {
            self.number_of_leaves += 1;
        }

        // Recompute the root by traversing from the leaf to the root.
        self.recompute_root(&key_hash)?;

        Ok(())
    }

    /// Returns the Merkle path for the given key.
    pub fn prove(&self, key: &KH::Key, leaf: &LH::Leaf) -> Result<SparseKaryMerklePath<E, PH, DEPTH, ARITY>> {
        // Hash the key for both storage lookup and path determination.
        let key_hash = self.key_hasher.hash_key(key)?;

        // Hash the leaf.
        let leaf_hash = self.leaf_hasher.hash_leaf(leaf)?;

        // Ensure the leaf exists in the tree.
        let stored_leaf_hash = self.leaves.get(&key_hash).ok_or_else(|| anyhow!("Leaf not found in tree"))?;
        ensure!(*stored_leaf_hash == leaf_hash, "Leaf hash mismatch");

        // Get the path indices from the key hash.
        let path_indices = self.compute_path_indices(&key_hash)?;

        // Collect sibling hashes along the path.
        let mut siblings = Vec::with_capacity(DEPTH as usize);

        for depth in (0..DEPTH).rev() {
            let index = path_indices[depth as usize];

            // Collect all siblings at this level.
            let mut level_siblings = Vec::with_capacity(ARITY as usize - 1);
            for i in 0..ARITY {
                if i as usize != index {
                    let sibling_path = Self::compute_node_path(&path_indices[..depth as usize], i)?;
                    let sibling_hash = *self.nodes.get(&sibling_path).unwrap_or(&self.empty_hash);
                    level_siblings.push(sibling_hash);
                }
            }

            siblings.push(level_siblings);
        }

        // Reverse to go from leaf to root.
        siblings.reverse();

        // Create the Merkle path using the key hash for identification.
        SparseKaryMerklePath::try_from((key_hash, siblings))
    }

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    pub fn verify(
        &self,
        path: &SparseKaryMerklePath<E, PH, DEPTH, ARITY>,
        root: &PH::Hash,
        key: &KH::Key,
        leaf: &LH::Leaf,
    ) -> bool {
        path.verify(&self.key_hasher, &self.leaf_hasher, &self.path_hasher, root, key, leaf)
    }

    /// Returns the Merkle root of the tree.
    pub const fn root(&self) -> &PH::Hash {
        &self.root
    }

    /// Returns the empty hash.
    pub const fn empty_hash(&self) -> &PH::Hash {
        &self.empty_hash
    }

    /// Returns the number of leaves in the Merkle tree.
    pub const fn number_of_leaves(&self) -> usize {
        self.number_of_leaves
    }

    /// Returns the leaf hash for a given key, if it exists.
    pub fn get(&self, key: &KH::Key) -> Result<Option<PH::Hash>> {
        let key_hash = self.key_hasher.hash_key(key)?;
        Ok(self.leaves.get(&key_hash).copied())
    }

    /// Computes the path indices for a given key (public helper for debugging).
    pub fn compute_path_for_key(&self, key: &KH::Key) -> Result<Vec<usize>> {
        let key_hash = self.key_hasher.hash_key(key)?;
        self.compute_path_indices(&key_hash)
    }

    /// Recomputes the root after updating a leaf at the given key hash.
    fn recompute_root(&mut self, key_hash: &Field<E>) -> Result<()> {
        // Get the path indices from the key hash using consecutive bits.
        let path_indices = self.compute_path_indices(key_hash)?;

        // Start with the leaf hash.
        let mut current_hash = *self.leaves.get(key_hash).ok_or_else(|| anyhow!("Leaf not found"))?;

        // Store the leaf at its path position in the nodes map as well.
        // This allows other paths to find this leaf when they need it as a sibling.
        let leaf_path = path_indices.iter().map(|&i| u8::try_from(i)).collect::<Result<Vec<_>, _>>()?;
        self.nodes.insert(leaf_path, current_hash);

        // Traverse from the leaf to the root, updating all nodes along the path.
        for depth in (0..DEPTH).rev() {
            let index = path_indices[depth as usize];

            // Compute the sibling hashes at this level.
            let mut children = Vec::with_capacity(ARITY as usize);
            for i in 0..ARITY {
                if i as usize == index {
                    children.push(current_hash);
                } else {
                    // Try to get the sibling from the nodes map, otherwise use empty hash.
                    let sibling_path = Self::compute_node_path(&path_indices[..depth as usize], i)?;
                    children.push(*self.nodes.get(&sibling_path).unwrap_or(&self.empty_hash));
                }
            }

            // Hash the children to get the parent hash.
            let parent_hash = self.path_hasher.hash_children(&children)?;

            // Store the PARENT hash at its path (the path from root to this parent node).
            // The parent is at depth `depth`, represented by path_indices[..depth].
            if depth > 0 {
                let parent_path =
                    path_indices[..depth as usize].iter().map(|&i| u8::try_from(i)).collect::<Result<Vec<_>, _>>()?;
                self.nodes.insert(parent_path, parent_hash);
            }

            current_hash = parent_hash;
        }

        // Update the root.
        self.root = current_hash;

        Ok(())
    }

    /// Computes the path indices through the tree for a given key hash.
    /// Uses consecutive bits to maximize entropy. With sufficient depth, this provides
    /// strong collision resistance (e.g., DEPTH=32, ARITY=2 uses 32 bits → 2^32 positions).
    fn compute_path_indices(&self, key_hash: &Field<E>) -> Result<Vec<usize>> {
        let mut indices = Vec::with_capacity(DEPTH as usize);

        // Convert the key hash to bits.
        let key_bits = key_hash.to_bits_le();

        // Compute the number of bits needed per level.
        let bits_per_level = ARITY.next_power_of_two().trailing_zeros() as usize;

        // Use CONSECUTIVE bits from the key hash to get maximum entropy.
        // For example: DEPTH=32, ARITY=2 → uses bits [0..32] → 2^32 unique positions.
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
            indices.push(index % ARITY as usize);
        }

        Ok(indices)
    }

    /// Computes a unique path identifier for a node in the tree.
    fn compute_node_path(path_prefix: &[usize], index: u8) -> Result<Vec<u8>> {
        let mut path = Vec::with_capacity(path_prefix.len() + 1);
        for &p in path_prefix {
            path.push(u8::try_from(p)?);
        }
        path.push(index);
        Ok(path)
    }
}
