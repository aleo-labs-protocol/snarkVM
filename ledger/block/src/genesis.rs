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

impl<N: Network> Block<N> {
    /// Specifies the number of genesis transactions.
    pub const NUM_GENESIS_TRANSACTIONS: usize = 4;

    /// Returns `true` if the block is a genesis block.
    pub fn is_genesis(&self) -> Result<bool> {
        if !self.header.is_genesis()? {
            return Ok(false);
        }

        ensure!(self.previous_hash == N::BlockHash::default(), "Invalid previous hash");
        ensure!(self.authority.is_beacon(), "Invalid block authority");
        ensure!(self.solutions.is_empty(), "Invalid solutins");
        ensure!(self.transactions.num_rejected() == 0, "Invalid number of rejected transactions");
        ensure!(self.aborted_transaction_ids.is_empty(), "Genesis block must not contain aborted transactions");

        // Perform additional checks in production
        #[cfg(not(any(test, feature = "test")))]
        {
            ensure!(self.ratifications.len() == 1, "Invalid number of ratifications");
            ensure!(
                self.transactions.num_accepted() == Self::NUM_GENESIS_TRANSACTIONS,
                "Invalid number of accepted transactions"
            );
            ensure!(
                self.transactions.num_finalize() == 2 * Self::NUM_GENESIS_TRANSACTIONS,
                "Invalid number of finalized transactions"
            );
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_genesis() {
        // Load the genesis block.
        let genesis_block = Block::<CurrentNetwork>::read_le(CurrentNetwork::genesis_bytes()).unwrap();
        assert!(genesis_block.is_genesis().unwrap());
    }
}
