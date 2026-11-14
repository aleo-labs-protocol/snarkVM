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
    BlockStore,
    ConsensusStorage,
    FinalizeStore,
    helpers::memory::{BlockMemory, FinalizeMemory, TransactionMemory, TransitionMemory},
};
use console::prelude::*;
use snarkvm_utilities::StorageMode;

/// An in-memory consensus storage.
#[derive(Clone)]
pub struct ConsensusMemory<N: Network> {
    /// The finalize store.
    finalize_store: FinalizeStore<N, FinalizeMemory<N>>,
    /// The block store.
    block_store: BlockStore<N, BlockMemory<N>>,
}

#[rustfmt::skip]
impl<N: Network> ConsensusStorage<N> for ConsensusMemory<N> {
    type FinalizeStorage = FinalizeMemory<N>;
    type BlockStorage = BlockMemory<N>;
    type TransactionStorage = TransactionMemory<N>;
    type TransitionStorage = TransitionMemory<N>;

    /// Initializes the consensus storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        // Initialize the finalize store.
        let finalize_store = FinalizeStore::<N, FinalizeMemory<N>>::open(storage.clone())?;
        // Initialize the block store.
        let block_store = BlockStore::<N, BlockMemory<N>>::open(storage)?;
        // Return the consensus storage.
        Ok(Self {
            finalize_store,
            block_store,
        })
    }

    /// Returns the finalize store.
    fn finalize_store(&self) -> &FinalizeStore<N, Self::FinalizeStorage> {
        &self.finalize_store
    }

    /// Returns the block store.
    fn block_store(&self) -> &BlockStore<N, Self::BlockStorage> {
        &self.block_store
    }
}
