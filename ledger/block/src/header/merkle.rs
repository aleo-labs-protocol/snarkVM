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

use super::*;

impl<N: Network> Header<N> {
    /// Returns the block header root.
    pub fn to_root(&self) -> Result<Field<N>> {
        Ok(*self.to_tree()?.root())
    }

    /// Returns the Merkle path for the Merkle tree of the block header.
    pub fn to_path(&self, leaf: &HeaderLeaf<N>) -> Result<HeaderPath<N>> {
        // Compute the Merkle path.
        self.to_tree()?.prove(leaf.index() as usize, &leaf.to_bits_le())
    }

    /// Returns the Merkle leaf for the given ID in the header.
    pub fn to_leaf(&self, id: &Field<N>) -> Result<HeaderLeaf<N>> {
        // If the ID is the previous state root, return the 0th leaf.
        if id == &*self.previous_state_root {
            Ok(HeaderLeaf::<N>::new(0, *self.previous_state_root))
        }
        // If the ID is the transactions root, return the 1st leaf.
        else if id == &self.transactions_root {
            Ok(HeaderLeaf::<N>::new(1, self.transactions_root))
        }
        // If the ID is the finalize root, return the 2nd leaf.
        else if id == &self.finalize_root {
            Ok(HeaderLeaf::<N>::new(2, self.finalize_root))
        }
        // If the ID is the ratifications root, return the 3rd leaf.
        else if id == &self.ratifications_root {
            Ok(HeaderLeaf::<N>::new(3, self.ratifications_root))
        }
        // If the ID is the solutions root, return the 4th leaf.
        else if id == &self.solutions_root {
            Ok(HeaderLeaf::<N>::new(4, self.solutions_root))
        }
        // If the ID is the subdag root, return the 5th leaf
        else if id == &self.subdag_root {
            Ok(HeaderLeaf::<N>::new(5, self.subdag_root))
        }
        // If the ID is the metadata hash, then return the 7th leaf.
        else if id == &self.metadata.to_hash()? {
            Ok(HeaderLeaf::<N>::new(7, *id))
        }
        // Otherwise, bail.
        else {
            bail!("Non-existent block header leaf ID: {id}")
        }
    }

    /// Returns an instance of the Merkle tree for the block header.
    pub fn to_tree(&self) -> Result<HeaderTree<N>> {
        // Determine the number of leaves.
        let num_leaves = usize::pow(2, HEADER_DEPTH as u32);

        // Construct the Merkle leaves.
        let mut leaves: Vec<Vec<bool>> = Vec::with_capacity(num_leaves);
        leaves.push(HeaderLeaf::<N>::new(0, *self.previous_state_root).to_bits_le());
        leaves.push(HeaderLeaf::<N>::new(1, self.transactions_root).to_bits_le());
        leaves.push(HeaderLeaf::<N>::new(2, self.finalize_root).to_bits_le());
        leaves.push(HeaderLeaf::<N>::new(3, self.ratifications_root).to_bits_le());
        leaves.push(HeaderLeaf::<N>::new(4, self.solutions_root).to_bits_le());
        leaves.push(HeaderLeaf::<N>::new(5, self.subdag_root).to_bits_le());
        leaves.push(HeaderLeaf::<N>::new(6, Field::zero()).to_bits_le());
        leaves.push(HeaderLeaf::<N>::new(7, self.metadata.to_hash()?).to_bits_le());

        // Ensure the correct number of leaves are allocated.
        ensure!(num_leaves == leaves.len(), "Incorrect number of leaves in the Merkle tree for the block header");

        // Compute the Merkle tree.
        N::merkle_tree_bhp::<HEADER_DEPTH>(&leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1_000;

    fn check_path<N: Network>(header_path: HeaderPath<N>, root: Field<N>, leaf: &HeaderLeaf<N>) -> Result<()> {
        // Ensure that the path is valid for the corresponding root and leaf.
        assert!(N::verify_merkle_path_bhp(&header_path, &root, &leaf.to_bits_le()));

        // Check serialization.
        let expected_bytes = header_path.to_bytes_le()?;
        assert_eq!(header_path, HeaderPath::<N>::read_le(&expected_bytes[..])?);
        assert!(HeaderPath::<N>::read_le(&expected_bytes[1..]).is_err());
        Ok(())
    }

    #[test]
    fn test_merkle() -> Result<()> {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let coinbase_target = u64::rand(rng);
            let proof_target = rng.random_range(0..coinbase_target);

            let header = Header::<CurrentNetwork>::from(
                Into::<<CurrentNetwork as Network>::StateRoot>::into(Field::rand(rng)),
                Field::rand(rng),
                Field::rand(rng),
                Field::rand(rng),
                Field::rand(rng),
                Field::rand(rng),
                Metadata::new(
                    CurrentNetwork::ID,
                    u64::rand(rng),
                    u32::rand(rng),
                    u128::rand(rng),
                    u128::rand(rng),
                    coinbase_target,
                    proof_target,
                    u64::rand(rng),
                    rng.random_range(0..i64::MAX),
                    rng.random_range(0..i64::MAX),
                )
                .with_context(|| "Failed to generate block metadata")?,
            )
            .with_context(|| "Failed to create block header")?;

            // Compute the header root.
            let root = header.to_root()?;

            // Check the 0th leaf.
            let leaf = header.to_leaf(&*header.previous_state_root())?;
            assert_eq!(leaf.index(), 0);
            check_path(header.to_path(&leaf)?, root, &leaf)?;

            // Check the 1st leaf.
            let leaf = header.to_leaf(&header.transactions_root())?;
            assert_eq!(leaf.index(), 1);
            check_path(header.to_path(&leaf)?, root, &leaf)?;

            // Check the 2nd leaf.
            let leaf = header.to_leaf(&header.finalize_root())?;
            assert_eq!(leaf.index(), 2);
            check_path(header.to_path(&leaf)?, root, &leaf)?;

            // Check the 3rd leaf.
            let leaf = header.to_leaf(&header.ratifications_root())?;
            assert_eq!(leaf.index(), 3);
            check_path(header.to_path(&leaf)?, root, &leaf)?;

            // Check the 4th leaf.
            let leaf = header.to_leaf(&header.solutions_root())?;
            assert_eq!(leaf.index(), 4);
            check_path(header.to_path(&leaf)?, root, &leaf)?;

            // Check the 5th leaf.
            let leaf = header.to_leaf(&header.subdag_root())?;
            assert_eq!(leaf.index(), 5);
            check_path(header.to_path(&leaf)?, root, &leaf)?;

            // Check the 7th leaf.
            let leaf = header.to_leaf(&CurrentNetwork::hash_bhp1024(&header.metadata().to_bits_le())?)?;
            assert_eq!(leaf.index(), 7);
            check_path(header.to_path(&leaf)?, root, &leaf)?;
        }

        Ok(())
    }
}
