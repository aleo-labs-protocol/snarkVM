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
    /// Initializes the genesis block header.
    pub fn genesis(
        ratifications: &Ratifications<N>,
        transactions: &Transactions<N>,
        ratified_finalize_operations: Vec<FinalizeOperation<N>>,
    ) -> Result<Self> {
        #[cfg(not(any(debug_assertions, feature = "test")))]
        ensure!(ratifications.len() == 1, "The genesis block must contain exactly 1 ratification");
        #[cfg(not(any(debug_assertions, feature = "test")))]
        ensure!(!ratified_finalize_operations.is_empty(), "The genesis block must contain ratify-finalize operations");

        // Prepare a genesis block header.
        let previous_state_root = Into::<N::StateRoot>::into(Field::zero());
        let transactions_root = transactions.to_transactions_root()?;
        let finalize_root = transactions.to_finalize_root(ratified_finalize_operations)?;
        let ratifications_root = ratifications.to_ratifications_root()?;
        let solutions_root = Field::zero();
        let subdag_root = Field::zero();
        let metadata = Metadata::genesis()?;

        // Return the genesis block header.
        Self::from(
            previous_state_root,
            transactions_root,
            finalize_root,
            ratifications_root,
            solutions_root,
            subdag_root,
            metadata,
        )
    }

    /// Returns `true` if the block header is a genesis block header.
    ///
    /// Return an error if the header is malformed.
    pub fn is_genesis(&self) -> Result<bool> {
        if !self.metadata.is_genesis()? {
            return Ok(false);
        }

        // Ensure the header is valid otherwise
        ensure!(*self.previous_state_root == Field::zero(), "Invalid previous state root");
        ensure!(self.transactions_root != Field::zero(), "Invalid transactions root");
        ensure!(self.finalize_root != Field::zero(), "Invalid finalize root");
        ensure!(self.ratifications_root != Field::zero(), "Invalid ratifications root");
        ensure!(self.solutions_root == Field::zero(), "Invalid solutions root");
        ensure!(self.subdag_root == Field::zero(), "Invalid subdag root");

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    /// Returns the expected block header size by summing its subcomponent sizes.
    /// Update this method if the contents of a block header have changed.
    fn get_expected_size<N: Network>() -> usize {
        // Previous state root, transactions root, finalize root, ratifications root, and solutions root size.
        (Field::<N>::size_in_bytes() * 6)
            // Metadata size.
            + 1 + 8 + 4 + 16 + 16 + 8 + 8 + 8 + 8 + 8
            // Add an additional 3 bytes for versioning.
            + 1 + 2
    }

    #[test]
    fn test_genesis_header_size() {
        let rng = &mut TestRng::default();

        // Prepare the expected size.
        let expected_size = get_expected_size::<CurrentNetwork>();
        // Prepare the genesis block header.
        let genesis_header = crate::header::test_helpers::sample_block_header(rng);
        // Ensure the size of the genesis block header is correct.
        assert_eq!(expected_size, genesis_header.to_bytes_le().unwrap().len());
    }

    #[test]
    fn test_genesis_header() {
        let rng = &mut TestRng::default();

        // Prepare the genesis block header.
        let header = crate::header::test_helpers::sample_block_header(rng);
        // Ensure the block header is a genesis block header.
        assert!(header.is_genesis().unwrap());

        // Ensure the genesis block contains the following.
        assert_eq!(*header.previous_state_root(), Field::zero());
        assert_eq!(header.solutions_root(), Field::zero());
        assert_eq!(header.subdag_root(), Field::zero());
        assert_eq!(header.network(), CurrentNetwork::ID);
        assert_eq!(header.round(), 0);
        assert_eq!(header.height(), 0);
        assert_eq!(header.cumulative_weight(), 0);
        assert_eq!(header.coinbase_target(), CurrentNetwork::GENESIS_COINBASE_TARGET);
        assert_eq!(header.proof_target(), CurrentNetwork::GENESIS_PROOF_TARGET);
        assert_eq!(header.last_coinbase_target(), CurrentNetwork::GENESIS_COINBASE_TARGET);
        assert_eq!(header.last_coinbase_timestamp(), CurrentNetwork::GENESIS_TIMESTAMP);
        assert_eq!(header.timestamp(), CurrentNetwork::GENESIS_TIMESTAMP);

        // Ensure the genesis block does *not* contain the following.
        assert_ne!(header.transactions_root(), Field::zero());
        assert_ne!(header.finalize_root(), Field::zero());
        assert_ne!(header.ratifications_root(), Field::zero());
    }
}
