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
    BlockStorage,
    BlockStore,
    FinalizeStorage,
    FinalizeStore,
    TransactionStorage,
    TransactionStore,
    TransitionStorage,
    TransitionStore,
};
use console::network::prelude::*;

use aleo_std_storage::StorageMode;
use anyhow::Result;
use core::marker::PhantomData;

/// A trait for consensus storage.
pub trait ConsensusStorage<N: Network>: 'static + Clone + Send + Sync {
    /// The finalize storage.
    type FinalizeStorage: FinalizeStorage<N>;
    /// The block storage.
    type BlockStorage: BlockStorage<N, TransactionStorage = Self::TransactionStorage, TransitionStorage = Self::TransitionStorage>;
    /// The transaction storage.
    type TransactionStorage: TransactionStorage<N, TransitionStorage = Self::TransitionStorage>;
    /// The transition storage.
    type TransitionStorage: TransitionStorage<N>;

    /// Initializes the consensus storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self>;

    /// Returns the finalize storage.
    fn finalize_store(&self) -> &FinalizeStore<N, Self::FinalizeStorage>;
    /// Returns the block storage.
    fn block_store(&self) -> &BlockStore<N, Self::BlockStorage>;
    /// Returns the transaction store.
    fn transaction_store(&self) -> &TransactionStore<N, Self::TransactionStorage> {
        self.block_store().transaction_store()
    }
    /// Returns the transition store.
    fn transition_store(&self) -> &TransitionStore<N, Self::TransitionStorage> {
        self.block_store().transition_store()
    }
    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        debug_assert!(self.block_store().storage_mode() == self.transaction_store().storage_mode());
        debug_assert!(self.transaction_store().storage_mode() == self.transition_store().storage_mode());
        self.transition_store().storage_mode()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.finalize_store().start_atomic();
        self.block_store().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.finalize_store().is_atomic_in_progress() || self.block_store().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.finalize_store().atomic_checkpoint();
        self.block_store().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.finalize_store().clear_latest_checkpoint();
        self.block_store().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.finalize_store().atomic_rewind();
        self.block_store().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.finalize_store().abort_atomic();
        self.block_store().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.finalize_store().finish_atomic()?;
        self.block_store().finish_atomic()
    }
}

/// The consensus store.
#[derive(Clone)]
pub struct ConsensusStore<N: Network, C: ConsensusStorage<N>> {
    /// The consensus storage.
    storage: C,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, C: ConsensusStorage<N>> ConsensusStore<N, C> {
    /// Initializes the consensus store.
    pub fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        // Initialize the consensus storage.
        let storage = C::open(storage.into())?;
        // Return the consensus store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes a consensus store from storage.
    pub fn from(storage: C) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Returns the finalize store.
    pub fn finalize_store(&self) -> &FinalizeStore<N, C::FinalizeStorage> {
        self.storage.finalize_store()
    }

    /// Returns the block store.
    pub fn block_store(&self) -> &BlockStore<N, C::BlockStorage> {
        self.storage.block_store()
    }

    /// Catches up with the primary instance; only applicable to storage opened in secondary mode.
    /// See [`BlockStore::catch_up_with_primary`] for details.
    #[cfg(feature = "rocks")]
    pub fn catch_up_with_primary(&self) -> Result<()> {
        self.block_store().catch_up_with_primary()
    }

    /// Returns the transaction store.
    pub fn transaction_store(&self) -> &TransactionStore<N, C::TransactionStorage> {
        self.storage.transaction_store()
    }

    /// Returns the transition store.
    pub fn transition_store(&self) -> &TransitionStore<N, C::TransitionStorage> {
        self.storage.transition_store()
    }

    /// Starts an atomic batch write operation.
    pub fn start_atomic(&self) {
        self.storage.start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    pub fn is_atomic_in_progress(&self) -> bool {
        self.storage.is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    pub fn atomic_checkpoint(&self) {
        self.storage.atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    pub fn clear_latest_checkpoint(&self) {
        self.storage.clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    pub fn atomic_rewind(&self) {
        self.storage.atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    pub fn abort_atomic(&self) {
        self.storage.abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    pub fn finish_atomic(&self) -> Result<()> {
        self.storage.finish_atomic()
    }

    /// Returns the storage mode.
    pub fn storage_mode(&self) -> &StorageMode {
        self.storage.storage_mode()
    }
}
