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

use crate::block::{Block, Network};

use snarkvm_utilities::ensure_equals;

use std::collections::VecDeque;

use anyhow::{Result, ensure};

/// Helper struct for caching the most recent blocks.
pub(super) struct BlockCache<N: Network> {
    /// Contains the most recent blocks ordered by height.
    /// We do not use a BTreeMap here as the cache is small and updates to a vector are more efficient
    ///
    /// Invariant: all entries in this vector (except the first) a height equal to h+1 (where h` is the previous block entry)
    blocks: VecDeque<Block<N>>,
}

impl<N: Network> BlockCache<N> {
    /// The maximum size of the cache in blocks.
    pub(super) const BLOCK_CACHE_SIZE: u32 = 10;

    /// Initialize the cache with the given blocks.
    pub fn new(blocks: Vec<Block<N>>) -> Result<Self> {
        ensure!(blocks.len() <= Self::BLOCK_CACHE_SIZE as usize, "Too many blocks to fit in the cache");

        if let Some(block) = blocks.first() {
            ensure!(block.height() != 0, "Cannot cache the genesis block");
        }
        for idx in 1..blocks.len() {
            ensure!(blocks[idx - 1].height() + 1 == blocks[idx].height(), "Not a continuous chain of blocks");
        }

        Ok(Self { blocks: VecDeque::from(blocks) })
    }

    /// Insert a new block into the cache.
    /// Must be the successor of the last block inserted into the cache.
    #[inline]
    pub fn insert(&mut self, block: Block<N>) -> Result<()> {
        ensure!(block.height() != 0, "Cannot cache the genesis block");

        if let Some(prev) = self.blocks.back() {
            ensure_equals!(
                prev.height() + 1,
                block.height(),
                "Block is not the successor of the last block inserted into the cache"
            );
        }

        self.blocks.push_back(block.clone());
        if self.blocks.len() > (Self::BLOCK_CACHE_SIZE as usize) {
            self.blocks.pop_front();
        }

        Ok(())
    }

    /// Return the block at the given height if it is in the cache.i
    #[inline]
    pub fn get_block(&self, block_height: u32) -> Option<&Block<N>> {
        let first_block = self.blocks.front()?;

        // Determine to location of the cached block (if any).
        // This returns `None` if `block_height` is lower than the height of the first cached block.
        let offset = block_height.checked_sub(first_block.height())?;

        self.blocks.get(offset as usize)
    }

    /// Return the block with the given hash if it is in the cache.
    #[inline]
    pub fn get_block_by_hash(&self, block_hash: &N::BlockHash) -> Option<&Block<N>> {
        // Perform a linear search through the cache.
        // This is cheap, as the cache is very small.
        self.blocks.iter().find(|block| &block.hash() == block_hash)
    }

    /// Remove the last `n` blocks from the cache.
    #[inline]
    pub fn remove_last_n(&mut self, n: u32) -> Result<()> {
        for _ in 0..n {
            self.blocks.pop_back();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_helpers::CurrentNetwork;

    use snarkvm_console::{
        account::{Field, PrivateKey},
        prelude::{Rng, TestRng},
    };
    use snarkvm_ledger_authority::Authority;
    use snarkvm_ledger_block::{Header, Metadata, Ratifications, Transactions};

    type BlockCache = super::BlockCache<CurrentNetwork>;

    #[test]
    fn eviction() {
        // The number of blocks to insert during the test
        // (must be more than the cache size)
        const NUM_BLOCKS: u32 = 15;
        const { assert!(NUM_BLOCKS > BlockCache::BLOCK_CACHE_SIZE) };

        let rng = &mut TestRng::default();
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // Construct a chain of blocks.
        let mut previous_hash = None;
        let blocks: Vec<_> = (0..NUM_BLOCKS)
            .map(|h| {
                let transactions = Transactions::from(&[]);
                let ratifications = Ratifications::try_from(vec![]).unwrap();
                let header = if h == 0 {
                    Header::genesis(&ratifications, &transactions, vec![]).unwrap()
                } else {
                    // Use mock metadata to save compute time.
                    let metadata = Metadata::new(
                        CurrentNetwork::ID,
                        (h * 2) as u64,
                        h,
                        0,
                        (h * 1000) as u128,
                        CurrentNetwork::GENESIS_COINBASE_TARGET,
                        CurrentNetwork::GENESIS_PROOF_TARGET + 1,
                        CurrentNetwork::GENESIS_COINBASE_TARGET,
                        CurrentNetwork::GENESIS_TIMESTAMP + ((h - 1) * 100) as i64,
                        CurrentNetwork::GENESIS_TIMESTAMP + (h * 100) as i64,
                    )
                    .unwrap();

                    let previous_state_root: <CurrentNetwork as Network>::StateRoot = rng.random();
                    Header::<CurrentNetwork>::from(
                        previous_state_root,
                        Field::from_u32(1),
                        Field::from_u32(1),
                        Field::from_u32(1),
                        Field::from_u32(1),
                        Field::from_u32(1),
                        metadata,
                    )
                    .unwrap()
                };
                let block_hash = rng.random();
                let authority = Authority::<CurrentNetwork>::new_beacon(&private_key, block_hash, rng).unwrap();

                let block = Block::from_unchecked(
                    block_hash.into(),
                    previous_hash.unwrap_or_default(),
                    header,
                    authority,
                    ratifications,
                    None.into(),
                    vec![],
                    transactions,
                    vec![],
                )
                .unwrap();

                previous_hash = Some(block.hash());
                block
            })
            .collect();

        let mut cache = BlockCache::new(vec![]).unwrap();
        let mut blocks = blocks.into_iter().skip(1);

        // First, fill up the cache.
        while cache.blocks.len() < (BlockCache::BLOCK_CACHE_SIZE as usize) {
            cache.insert(blocks.next().unwrap()).unwrap();
        }

        // Then, continue insertions and check that old blocks are evicted.
        for block in blocks {
            let hash = block.hash();
            let height = block.height();

            cache.insert(block).unwrap();

            // Ensure eviction work.
            assert_eq!(cache.blocks.len(), BlockCache::BLOCK_CACHE_SIZE as usize);

            // Ensure the correct block is returned.
            let ret1 = cache.get_block(height).unwrap();
            let ret2 = cache.get_block_by_hash(&hash).unwrap();

            assert_eq!(ret1.hash(), hash);
            assert_eq!(ret2.hash(), hash);
            assert_eq!(ret1.height(), height);
            assert_eq!(ret2.height(), height);

            assert_eq!(cache.blocks[0].height(), height - BlockCache::BLOCK_CACHE_SIZE + 1);
        }

        // Fetch something that isn't the last block.
        let block = cache.get_block(10).unwrap();
        assert_eq!(block.height(), 10);

        // Fetch the last thing that must be in the cache.
        assert!(cache.get_block(NUM_BLOCKS - BlockCache::BLOCK_CACHE_SIZE).is_some());
        // Fetch something that must not be in the cache.
        assert!(cache.get_block(NUM_BLOCKS - BlockCache::BLOCK_CACHE_SIZE - 1).is_none());
    }
}
