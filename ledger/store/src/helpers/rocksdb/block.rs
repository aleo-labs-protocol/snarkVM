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
    ConfirmedTxType,
    TransactionStore,
    TransitionStore,
    block::{BLOCK_TREE_CACHE_PREFIX, block_tree_cache_path},
    helpers::{
        rocksdb::{
            BlockMap,
            MapID,
            TransactionDB,
            TransitionDB,
            internal::{self, DataMap, Database},
        },
        traits::MapRead,
    },
};
use console::{prelude::*, program::BlockTree, types::Field};
use snarkvm_ledger_authority::Authority;
use snarkvm_ledger_block::{Header, Ratifications, Rejected, Solutions};
use snarkvm_ledger_puzzle::SolutionID;
use snarkvm_synthesizer_program::FinalizeOperation;

use aleo_std_storage::StorageMode;
use std::fs;
use tracing::debug;

/// A RocksDB block storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct BlockDB<N: Network> {
    /// The mapping of `block height` to `state root`.
    state_root_map: DataMap<u32, N::StateRoot>,
    /// The mapping of `state root` to `block height`.
    reverse_state_root_map: DataMap<N::StateRoot, u32>,
    /// The mapping of `block height` to `block hash`.
    id_map: DataMap<u32, N::BlockHash>,
    /// The mapping of `block hash` to `block height`.
    reverse_id_map: DataMap<N::BlockHash, u32>,
    /// The header map.
    header_map: DataMap<N::BlockHash, Header<N>>,
    /// The authority map.
    authority_map: DataMap<N::BlockHash, Authority<N>>,
    /// The certificate map.
    certificate_map: DataMap<Field<N>, (u32, u64)>,
    /// The ratifications map.
    ratifications_map: DataMap<N::BlockHash, Ratifications<N>>,
    /// The solutions map.
    solutions_map: DataMap<N::BlockHash, Solutions<N>>,
    /// The solution IDs map.
    solution_ids_map: DataMap<SolutionID<N>, u32>,
    /// The aborted solution IDs map.
    aborted_solution_ids_map: DataMap<N::BlockHash, Vec<SolutionID<N>>>,
    /// The aborted solution heights map.
    aborted_solution_heights_map: DataMap<SolutionID<N>, u32>,
    /// The transactions map.
    transactions_map: DataMap<N::BlockHash, Vec<N::TransactionID>>,
    /// The aborted transaction IDs map.
    aborted_transaction_ids_map: DataMap<N::BlockHash, Vec<N::TransactionID>>,
    /// The rejected or aborted transaction ID map.
    rejected_or_aborted_transaction_id_map: DataMap<N::TransactionID, N::BlockHash>,
    /// The confirmed transactions map.
    confirmed_transactions_map:
        DataMap<N::TransactionID, (N::BlockHash, ConfirmedTxType<N>, Vec<FinalizeOperation<N>>)>,
    /// The rejected deployment or execution map.
    rejected_deployment_or_execution_map: DataMap<Field<N>, Rejected<N>>,
    /// The transaction store.
    transaction_store: TransactionStore<N, TransactionDB<N>>,
}

#[rustfmt::skip]
impl<N: Network> BlockStorage<N> for BlockDB<N> {
    type StateRootMap = DataMap<u32, N::StateRoot>;
    type ReverseStateRootMap = DataMap<N::StateRoot, u32>;
    type IDMap = DataMap<u32, N::BlockHash>;
    type ReverseIDMap = DataMap<N::BlockHash, u32>;
    type HeaderMap = DataMap<N::BlockHash, Header<N>>;
    type AuthorityMap = DataMap<N::BlockHash, Authority<N>>;
    type CertificateMap = DataMap<Field<N>, (u32, u64)>;
    type RatificationsMap = DataMap<N::BlockHash, Ratifications<N>>;
    type SolutionsMap = DataMap<N::BlockHash, Solutions<N>>;
    type SolutionIDsMap = DataMap<SolutionID<N>, u32>;
    type AbortedSolutionIDsMap = DataMap<N::BlockHash, Vec<SolutionID<N>>>;
    type AbortedSolutionHeightsMap = DataMap<SolutionID<N>, u32>;
    type TransactionsMap = DataMap<N::BlockHash, Vec<N::TransactionID>>;
    type AbortedTransactionIDsMap = DataMap<N::BlockHash, Vec<N::TransactionID>>;
    type RejectedOrAbortedTransactionIDMap = DataMap<N::TransactionID, N::BlockHash>;
    type ConfirmedTransactionsMap = DataMap<N::TransactionID, (N::BlockHash, ConfirmedTxType<N>, Vec<FinalizeOperation<N>>)>;
    type RejectedDeploymentOrExecutionMap = DataMap<Field<N>, Rejected<N>>;
    type TransactionStorage = TransactionDB<N>;
    type TransitionStorage = TransitionDB<N>;

    /// Initializes the block storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        // Initialize the transition store.
        let transition_store = TransitionStore::<N, TransitionDB<N>>::open(storage.clone())?;
        // Initialize the transaction store.
        let transaction_store = TransactionStore::<N, TransactionDB<N>>::open(transition_store)?;
        // Return the block storage.
        Ok(Self {
            state_root_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::StateRoot))?,
            reverse_state_root_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::ReverseStateRoot))?,
            id_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::ID))?,
            reverse_id_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::ReverseID))?,
            header_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::Header))?,
            authority_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::Authority))?,
            certificate_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::Certificate))?,
            ratifications_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::Ratifications))?,
            solutions_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::Solutions))?,
            solution_ids_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::PuzzleCommitments))?,
            aborted_solution_ids_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::AbortedSolutionIDs))?,
            aborted_solution_heights_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::AbortedSolutionHeights))?,
            transactions_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::Transactions))?,
            aborted_transaction_ids_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::AbortedTransactionIDs))?,
            rejected_or_aborted_transaction_id_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::RejectedOrAbortedTransactionID))?,
            confirmed_transactions_map: internal::RocksDB::open_map(N::ID, storage.clone(), MapID::Block(BlockMap::ConfirmedTransactions))?,
            rejected_deployment_or_execution_map: internal::RocksDB::open_map(N::ID, storage, MapID::Block(BlockMap::RejectedDeploymentOrExecution))?,
            transaction_store,
        })
    }

    /// Returns the state root map.
    fn state_root_map(&self) -> &Self::StateRootMap {
        &self.state_root_map
    }

    /// Returns the reverse state root map.
    fn reverse_state_root_map(&self) -> &Self::ReverseStateRootMap {
        &self.reverse_state_root_map
    }

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap {
        &self.id_map
    }

    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap {
        &self.reverse_id_map
    }

    /// Returns the header map.
    fn header_map(&self) -> &Self::HeaderMap {
        &self.header_map
    }

    /// Returns the authority map.
    fn authority_map(&self) -> &Self::AuthorityMap {
        &self.authority_map
    }

    /// Returns the certificate map.
    fn certificate_map(&self) -> &Self::CertificateMap {
        &self.certificate_map
    }

    /// Returns the ratifications map.
    fn ratifications_map(&self) -> &Self::RatificationsMap {
        &self.ratifications_map
    }

    /// Returns the solutions map.
    fn solutions_map(&self) -> &Self::SolutionsMap {
        &self.solutions_map
    }

    /// Returns the solution IDs map.
    fn solution_ids_map(&self) -> &Self::SolutionIDsMap {
        &self.solution_ids_map
    }

    /// Returns the aborted solution IDs map.
    fn aborted_solution_ids_map(&self) -> &Self::AbortedSolutionIDsMap {
        &self.aborted_solution_ids_map
    }

    /// Returns the aborted solution heights map.
    fn aborted_solution_heights_map(&self) -> &Self::AbortedSolutionHeightsMap {
        &self.aborted_solution_heights_map
    }

    /// Returns the transactions map.
    fn transactions_map(&self) -> &Self::TransactionsMap {
        &self.transactions_map
    }

    /// Returns the aborted transaction IDs map.
    fn aborted_transaction_ids_map(&self) -> &Self::AbortedTransactionIDsMap {
        &self.aborted_transaction_ids_map
    }

    /// Returns the rejected transaction ID or aborted transaction ID map.
    fn rejected_or_aborted_transaction_id_map(&self) -> &Self::RejectedOrAbortedTransactionIDMap {
        &self.rejected_or_aborted_transaction_id_map
    }

    /// Returns the confirmed transactions map.
    fn confirmed_transactions_map(&self) -> &Self::ConfirmedTransactionsMap {
        &self.confirmed_transactions_map
    }

    /// Returns the rejected deployment or execution map.
    fn rejected_deployment_or_execution_map(&self) -> &Self::RejectedDeploymentOrExecutionMap {
        &self.rejected_deployment_or_execution_map
    }

    /// Returns the transaction store.
    fn transaction_store(&self) -> &TransactionStore<N, Self::TransactionStorage> {
        &self.transaction_store
    }

    /// Stores a database backup at the given location.
    #[cfg(feature = "rocks")]
    fn backup_database<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), String> {
        // Any map can be used to retrieve the common RocksDB instance.
        self.id_map().backup_database(path)
    }

    /// Catches up with the primary instance; only applicable to secondary instances.
    fn catch_up_with_primary(&self) -> Result<()> {
        // Any map can be used to retrieve the common RocksDB instance.
        self.id_map().catch_up_with_primary()
    }

    /// Creates the block tree based on the contents of the storage.
    fn create_block_tree(&self) -> Result<BlockTree<N>> {
        fn construct_from_scratch<N: Network>(storage: &BlockDB<N>) -> Result<BlockTree<N>> {
            // Prepare an iterator over the block heights and prepare the leaves of the block tree.
            let hashes = storage
                .id_map()
                .iter_confirmed()
                .sorted_unstable_by(|(h1, _), (h2, _)| h1.cmp(h2))
                .map(|(_, hash)| hash.to_bits_le())
                .collect::<Vec<Vec<bool>>>();

            // Construct the block tree.
            N::merkle_tree_bhp(&hashes)
        }

        let Some(path) = block_tree_cache_path::<N, _>(self) else {
            debug!("Creating the block tree from scratch");
            return construct_from_scratch(self);
        };

        if let Ok(cached) = fs::read(&path) {
            let ret = match cached.strip_prefix(BLOCK_TREE_CACHE_PREFIX) {
                Some(serialized_state) => {
                    debug!("Loading the cached block tree from {}", path.display());

                    // Deserialize the contents of the block tree, and recreate it from them.
                    bincode::deserialize(serialized_state)
                        .map_err(anyhow::Error::from)
                        .and_then(N::merkle_tree_bhp_from_state)
                        .or_else(|e| {
                            tracing::error!("Failed to load the cached block tree ({e}), constructing from scratch");
                            construct_from_scratch(self)
                        })
                }
                // The cache was written by a version using a different format; discard it.
                None => {
                    debug!("Discarding the outdated block tree cache at {}", path.display());
                    construct_from_scratch(self)
                }
            };

            // Ensure that an old cached tree is not reused.
            let _ = fs::remove_file(path);

            ret
        } else {
            debug!("Creating the block tree from scratch");
            construct_from_scratch(self)
        }
    }
}

#[cfg(all(feature = "rocks", feature = "metrics"))]
impl<N: Network> BlockDB<N> {
    /// Reads RocksDB internal properties and publishes them to the metrics registry.
    /// Any map can be used since they all share the same underlying RocksDB instance.
    pub fn export_rocksdb_metrics(&self) {
        self.id_map.export_rocksdb_metrics();
    }
}
