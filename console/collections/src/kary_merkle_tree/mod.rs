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

mod helpers;
pub use helpers::*;

mod path;
pub use path::*;

#[cfg(test)]
mod tests;

use snarkvm_console_types::prelude::*;

use std::ops::Range;

#[derive(Clone)]
pub struct KaryMerkleTree<LH: LeafHash<Hash = PH::Hash>, PH: PathHash, const DEPTH: u8, const ARITY: u8> {
    /// The leaf hasher for the Merkle tree.
    leaf_hasher: LH,
    /// The path hasher for the Merkle tree.
    path_hasher: PH,
    /// The computed root of the full Merkle tree.
    root: PH::Hash,
    /// The internal hashes, from root to hashed leaves, of the full Merkle tree.
    tree: Vec<PH::Hash>,
    /// The canonical empty hash.
    empty_hash: PH::Hash,
    /// The number of hashed leaves in the tree.
    number_of_leaves: usize,
}

/// Returns the next power of `n` that's greater than or equal to `base`.
/// Returns `None` for edge cases or in case of overflow.
fn checked_next_power_of_n(base: usize, n: usize) -> Option<usize> {
    if n <= 1 {
        return None;
    }

    let mut value = 1;
    while value < base {
        value = value.checked_mul(n)?;
    }
    Some(value)
}

impl<LH: LeafHash<Hash = PH::Hash>, PH: PathHash, const DEPTH: u8, const ARITY: u8>
    KaryMerkleTree<LH, PH, DEPTH, ARITY>
{
    /// Initializes a new Merkle tree with the given leaves.
    #[inline]
    pub fn new(leaf_hasher: &LH, path_hasher: &PH, leaves: &[LH::Leaf]) -> Result<Self> {
        let timer = timing_span!("MerkleTree::new").entered();

        // Ensure the Merkle tree depth is greater than 0.
        ensure!(DEPTH > 0, "Merkle tree depth must be greater than 0");
        // Ensure the Merkle tree depth is less than or equal to 64.
        ensure!(DEPTH <= 64u8, "Merkle tree depth must be less than or equal to 64");
        // Ensure the Merkle tree arity is greater than 1.
        ensure!(ARITY > 1, "Merkle tree arity must be greater than 1");
        // Ensure the Merkle tree does not overflow a u128.
        ensure!((ARITY as u128).checked_pow(DEPTH as u32).is_some(), "Merkle tree size overflowed");

        // Compute the maximum number of leaves.
        let Some(max_leaves) = checked_next_power_of_n(leaves.len(), ARITY as usize) else {
            bail!("Integer overflow when computing the maximum number of leaves in the Merkle tree");
        };

        // Compute the number of nodes.
        let num_nodes = (max_leaves - 1) / (ARITY as usize - 1);
        // Compute the tree size as the maximum number of leaves plus the number of nodes.
        let tree_size = max_leaves + num_nodes;
        // Compute the number of levels in the Merkle tree (i.e. log_arity(tree_size)).
        let tree_depth = tree_depth::<DEPTH, ARITY>(tree_size)?;
        // Compute the number of padded levels.
        let padding_depth = DEPTH - tree_depth;

        // Compute the empty hash.
        let empty_hash = path_hasher.hash_empty::<ARITY>()?;

        // Calculate the size of the tree which excludes leafless nodes.
        // The minimum tree size is either a single root node or the calculated number of nodes plus
        // the supplied leaves, and empty hashes that pad up to the tree's arity (making every node full).
        let arity = ARITY as usize;
        let all_nodes_are_full = leaves.len() % arity == 0;
        let minimum_tree_size = std::cmp::max(
            1,
            num_nodes + leaves.len() + if all_nodes_are_full { 0 } else { arity - leaves.len() % arity },
        );

        // Initialize the Merkle tree.
        let mut tree = vec![empty_hash; minimum_tree_size];

        // Compute and store each leaf hash.
        tree[num_nodes..num_nodes + leaves.len()].clone_from_slice(&leaf_hasher.hash_leaves(leaves)?);
        timing_event!("Hashed {} leaves", leaves.len());

        // Compute and store the hashes for each level, iterating from the penultimate level to the root level.
        let mut start_index = num_nodes;
        // Compute the start index of the current level.
        while let Some(start) = parent::<ARITY>(start_index) {
            // Compute the end index of the current level.
            let end = child_indexes::<ARITY>(start).next().ok_or_else(|| anyhow!("Missing left-most child"))?;

            // Construct the children for each node in the current level.
            let child_nodes = (start..end)
                .take_while(|&i| child_indexes::<ARITY>(i).next().and_then(|idx| tree.get(idx)).is_some())
                .map(|i| &tree[child_indexes::<ARITY>(i)])
                .collect::<Vec<_>>();

            // Compute and store the hashes for each node in the current level.
            let num_full_nodes = child_nodes.len();
            let hashes = path_hasher.hash_all_children(&child_nodes)?;
            tree[start..][..num_full_nodes].clone_from_slice(&hashes);
            // Use the precomputed empty node hash for every empty node, if there are any.
            if start + num_full_nodes < end {
                let empty_node_hash = path_hasher.hash_children(&vec![empty_hash; arity])?;
                for node in tree.iter_mut().take(end).skip(start + num_full_nodes) {
                    *node = empty_node_hash;
                }
            }
            // Update the start index for the next level.
            start_index = start;
        }
        timing_event!("Hashed {} levels", tree_depth);

        // Compute the root hash, by iterating from the root level up to `DEPTH`.
        let mut root_hash = tree[0];
        for _ in 0..padding_depth {
            // Update the root hash, by hashing the current root hash with the empty hashes.

            let mut input = Vec::with_capacity(ARITY as usize);
            input.push(root_hash);
            // Resize the vector to ARITY length, filling with empty_hash if necessary.
            input.resize(ARITY as usize, empty_hash);

            root_hash = path_hasher.hash_children(&input)?;
        }
        timing_event!("Hashed {} padding levels", padding_depth);

        drop(timer);

        Ok(Self {
            leaf_hasher: leaf_hasher.clone(),
            path_hasher: path_hasher.clone(),
            root: root_hash,
            tree,
            empty_hash,
            number_of_leaves: leaves.len(),
        })
    }

    #[inline]
    /// Returns the Merkle path for the given leaf index and leaf.
    pub fn prove(&self, leaf_index: usize, leaf: &LH::Leaf) -> Result<KaryMerklePath<PH, DEPTH, ARITY>> {
        // Ensure the leaf index is valid.
        ensure!(leaf_index < self.number_of_leaves, "The given Merkle leaf index is out of bounds");

        // Compute the leaf hash.
        let leaf_hash = self.leaf_hasher.hash_leaf(leaf)?;

        // Compute the start index (on the left) for the leaf hashes level in the Merkle tree.
        let start = match checked_next_power_of_n(self.number_of_leaves, ARITY as usize) {
            Some(num_leaves) => (num_leaves - 1) / (ARITY as usize - 1),
            None => bail!("Integer overflow when computing the Merkle tree start index"),
        };

        // Compute the absolute index of the leaf in the Merkle tree.
        let mut index = start + leaf_index;
        // Ensure the leaf index is valid.
        ensure!(index < self.tree.len(), "The given Merkle leaf index is out of bounds");
        // Ensure the leaf hash matches the one in the tree.
        ensure!(self.tree[index] == leaf_hash, "The given Merkle leaf does not match the one in the Merkle tree");

        // Initialize a vector for the Merkle path.
        let mut path = Vec::with_capacity(DEPTH as usize);

        // Iterate from the leaf hash to the root level, storing the sibling hashes along the path.
        for _ in 0..DEPTH {
            // Compute the index of the sibling hash, if it exists.
            if let Some(siblings) = siblings::<ARITY>(index) {
                // Append the sibling hashes to the path.
                let sibling_hashes = siblings.map(|index| self.tree[index]).collect::<Vec<_>>();

                path.push(sibling_hashes);
                // Compute the index of the parent hash, if it exists.
                match parent::<ARITY>(index) {
                    // Update the index to the parent index.
                    Some(parent) => index = parent,
                    // If the parent does not exist, the path is complete.
                    None => break,
                }
            }
        }

        // If the Merkle path length is not equal to `DEPTH`, pad the path with the empty hash.
        if path.len() != DEPTH as usize {
            let empty_hashes = (0..ARITY.saturating_sub(1)).map(|_| self.empty_hash).collect::<Vec<_>>();
            path.resize(DEPTH as usize, empty_hashes);
        }

        // Return the Merkle path.
        KaryMerklePath::try_from((leaf_index as u64, path))
    }

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    pub fn verify(&self, path: &KaryMerklePath<PH, DEPTH, ARITY>, root: &PH::Hash, leaf: &LH::Leaf) -> bool {
        path.verify(&self.leaf_hasher, &self.path_hasher, root, leaf)
    }

    /// Returns the Merkle root of the tree.
    pub const fn root(&self) -> &PH::Hash {
        &self.root
    }

    /// Returns the Merkle tree (excluding the hashes of the leaves).
    pub fn tree(&self) -> &[PH::Hash] {
        &self.tree
    }

    /// Returns the empty hash.
    pub const fn empty_hash(&self) -> &PH::Hash {
        &self.empty_hash
    }

    /// Returns the number of leaves in the Merkle tree.
    pub const fn number_of_leaves(&self) -> usize {
        self.number_of_leaves
    }
}

/// Returns the depth of the tree, given the size of the tree.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn tree_depth<const DEPTH: u8, const ARITY: u8>(tree_size: usize) -> Result<u8> {
    let tree_size = u64::try_from(tree_size)?;

    ensure!(tree_size < 4503599627370496_u64, "Tree size must be less than 2^52");

    // Calculate the tree depth based on the tree size and arity.
    // log_arity(tree_size) =  ln(tree_size) / ln(arity).
    let tree_depth_float = (tree_size as f64).ln() / (ARITY as f64).ln();
    let tree_depth = u8::try_from(tree_depth_float.floor() as u64)?;

    // Ensure the tree depth is within the depth bound.
    match tree_depth <= DEPTH {
        // Return the tree depth.
        true => Ok(tree_depth),
        false => bail!("Merkle tree cannot exceed depth {DEPTH}: attempted to reach depth {tree_depth}"),
    }
}

/// Returns the indexes of the children, given an index.
fn child_indexes<const ARITY: u8>(index: usize) -> Range<usize> {
    let start = index * ARITY as usize + 1;
    start..start + ARITY as usize
}

/// Returns the index of the siblings, given an index.
#[inline]
fn siblings<const ARITY: u8>(index: usize) -> Option<impl Iterator<Item = usize>> {
    if is_root(index) {
        None
    } else {
        // Find the left-most sibling.
        let left_most_sibling = ((index - 1) / ARITY as usize) * ARITY as usize + 1;

        // Add all the siblings except for the given index.
        Some((left_most_sibling..left_most_sibling + ARITY as usize).filter(move |&i| index != i))
    }
}

/// Returns true iff the index represents the root.
#[inline]
const fn is_root(index: usize) -> bool {
    index == 0
}

/// Returns the index of the parent, given the index of a child.
#[inline]
const fn parent<const ARITY: u8>(index: usize) -> Option<usize> {
    if index > 0 { Some((index - 1) / ARITY as usize) } else { None }
}
