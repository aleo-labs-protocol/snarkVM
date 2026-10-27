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

pub mod confirmed_tx_type;
pub use confirmed_tx_type::*;

mod cache;
use cache::BlockCache;

use crate::{
    TransactionStorage,
    TransactionStore,
    TransitionStorage,
    TransitionStore,
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::{
    network::prelude::*,
    program::{BlockTree, HeaderLeaf, ProgramID, StatePath},
    types::Field,
};
use snarkvm_ledger_authority::Authority;
use snarkvm_ledger_block::{
    Block,
    ConfirmedTransaction,
    Header,
    Ratifications,
    Rejected,
    Solutions,
    Transaction,
    Transactions,
};
use snarkvm_ledger_narwhal_batch_certificate::BatchCertificate;
use snarkvm_ledger_puzzle::{Solution, SolutionID};
use snarkvm_synthesizer_program::{FinalizeOperation, Program};

use aleo_std_storage::StorageMode;
#[cfg(feature = "rocks")]
use aleo_std_storage::aleo_ledger_dir;
#[cfg(any(feature = "rocks", feature = "prune-authority-data"))]
use aleo_std_storage::aleo_secondary_ledger_dir;
use anyhow::{Context, Result};
#[cfg(feature = "locktick")]
use locktick::{LockGuard, parking_lot::RwLock};
#[cfg(not(feature = "locktick"))]
use parking_lot::RwLock;
use std::{borrow::Cow, sync::Arc};
#[cfg(feature = "rocks")]
use std::{fs, io::BufWriter};
#[cfg(feature = "prune-authority-data")]
use tracing::{debug, info, warn};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// Separates the confirmed transaction into a tuple.
#[allow(clippy::type_complexity)]
fn to_confirmed_tuple<N: Network>(
    confirmed: ConfirmedTransaction<N>,
) -> Result<(ConfirmedTxType<N>, Transaction<N>, Vec<FinalizeOperation<N>>)> {
    match confirmed {
        ConfirmedTransaction::AcceptedDeploy(index, tx, finalize_operations) => {
            // Return the confirmed tuple.
            Ok((ConfirmedTxType::AcceptedDeploy(index), tx, finalize_operations))
        }
        ConfirmedTransaction::AcceptedExecute(index, tx, finalize_operations) => {
            // Return the confirmed tuple.
            Ok((ConfirmedTxType::AcceptedExecute(index), tx, finalize_operations))
        }
        ConfirmedTransaction::RejectedDeploy(index, tx, rejected, finalize_operations) => {
            // Return the confirmed tuple.
            Ok((ConfirmedTxType::RejectedDeploy(index, rejected), tx, finalize_operations))
        }
        ConfirmedTransaction::RejectedExecute(index, tx, rejected, finalize_operations) => {
            // Return the confirmed tuple.
            Ok((ConfirmedTxType::RejectedExecute(index, rejected), tx, finalize_operations))
        }
    }
}

fn to_confirmed_transaction<N: Network>(
    confirmed_type: ConfirmedTxType<N>,
    transaction: Transaction<N>,
    finalize_operations: Vec<FinalizeOperation<N>>,
) -> Result<ConfirmedTransaction<N>> {
    match confirmed_type {
        ConfirmedTxType::AcceptedDeploy(index) => {
            // Return the confirmed transaction.
            ConfirmedTransaction::accepted_deploy(index, transaction, finalize_operations)
        }
        ConfirmedTxType::AcceptedExecute(index) => {
            // Return the confirmed transaction.
            ConfirmedTransaction::accepted_execute(index, transaction, finalize_operations)
        }
        ConfirmedTxType::RejectedDeploy(index, rejected) => {
            // Return the confirmed transaction.
            ConfirmedTransaction::rejected_deploy(index, transaction, rejected, finalize_operations)
        }
        ConfirmedTxType::RejectedExecute(index, rejected) => {
            // Return the confirmed transaction.
            ConfirmedTransaction::rejected_execute(index, transaction, rejected, finalize_operations)
        }
    }
}

/// The prefix of the block tree cache file, used to recognize its format.
///
/// Bump the trailing digits whenever the cached payload changes, so that a cache
/// file written by an older version is discarded instead of failing to decode.
#[cfg(feature = "rocks")]
pub(crate) const BLOCK_TREE_CACHE_PREFIX: &[u8; 12] = b"aleo.tree.01";

/// Returns the path to the block tree cache file, or `None` if the block tree is not to be cached.
pub(crate) fn block_tree_cache_path<N: Network, B: BlockStorage<N>>(storage: &B) -> Option<std::path::PathBuf> {
    #[cfg(feature = "rocks")]
    {
        // A secondary instance must not touch the primary's cache, and it can't keep one of its own
        // either, as it catches up with the primary on startup, which would make its cache stale.
        if aleo_secondary_ledger_dir(N::ID, storage.storage_mode()).is_some() {
            return None;
        }

        let mut path = aleo_ledger_dir(N::ID, storage.storage_mode());
        path.push("block_tree");
        Some(path)
    }
    #[cfg(not(feature = "rocks"))]
    {
        let _ = storage;
        None
    }
}

fn missing_block_in_tree_error(height: u32, block_tree_cache_path: Option<&std::path::Path>) -> String {
    match block_tree_cache_path {
        Some(path) => format!(
            "Block {height} exists in tree but not in storage;\
            perhaps you used a wrong block tree cache file at '{}'?",
            path.display()
        ),
        None => format!(
            "Block {height} exists in tree but not in storage;\
            perhaps you used a wrong block tree cache file?"
        ),
    }
}

/// The number of recent blocks whose authority data is retained with the `prune-authority-data` feature.
///
/// At the ideal block time of 2.5 seconds, the network produces `60 * 60 * 24 / 2.5 = 34,560` blocks
/// per day, so retaining 500,000 blocks keeps roughly two weeks of authority data before pruning.
///
/// Defined in every build because snarkOS uses it to decide which peers can still serve a block range.
#[cfg(not(test))]
pub const AUTHORITY_RETENTION_BLOCKS: u32 = 500_000;
/// A reduced retention window for unit tests, so pruning can be exercised without building 500,000 blocks.
#[cfg(test)]
pub const AUTHORITY_RETENTION_BLOCKS: u32 = 100;

/// The keys of the block metadata map. Each key's value is raw bytes whose encoding is owned by
/// that key's getter and setter on [`BlockStorage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum BlockMetadataKey {
    /// The authority-pruning watermark. See [`BlockStorage::authority_pruned_below`].
    AuthorityPruned = 0,
}

/// Returns the lowest block height whose authority data is retained when the chain is at
/// `latest_height`. Without `prune-authority-data`, every height is retained.
pub fn oldest_retained_authority_height(latest_height: u32) -> u32 {
    if cfg!(feature = "prune-authority-data") {
        latest_height.saturating_sub(AUTHORITY_RETENTION_BLOCKS - 1)
    } else {
        0
    }
}

/// The number of heights pruned in one startup batch, one authority deletion each.
#[cfg(all(feature = "prune-authority-data", not(test)))]
const AUTHORITY_PRUNING_CHUNK_HEIGHTS: u32 = 10_000;
/// A small chunk for unit tests, so several chunks fit in a short chain.
#[cfg(all(feature = "prune-authority-data", test))]
const AUTHORITY_PRUNING_CHUNK_HEIGHTS: u32 = 16;

/// The number of certificate index deletions in a startup pass at which the certificate map is
/// compacted afterwards. RocksDB's own scheduling leaves most of a large deletion as tombstones that
/// every later startup pass reads past.
#[cfg(all(feature = "prune-authority-data", not(test)))]
const AUTHORITY_PRUNING_COMPACTION_THRESHOLD: usize = 1_000_000;
/// A small threshold for unit tests.
#[cfg(all(feature = "prune-authority-data", test))]
const AUTHORITY_PRUNING_COMPACTION_THRESHOLD: usize = 5;

/// The number of certificate index deletions in one startup batch.
#[cfg(all(feature = "prune-authority-data", not(test)))]
const CERTIFICATE_PRUNING_BATCH_SIZE: usize = 10_000;
/// A small batch for unit tests, so the pass flushes while its iterator is open.
#[cfg(all(feature = "prune-authority-data", test))]
const CERTIFICATE_PRUNING_BATCH_SIZE: usize = 3;

/// Insert-time pruning logs progress at debug level once per this many blocks.
#[cfg(feature = "prune-authority-data")]
const AUTHORITY_PRUNING_LOG_INTERVAL: u32 = 10_000;

/// Returns the IDs of the certificates committed by an authority.
fn certificate_ids<N: Network>(authority: &Authority<N>) -> Vec<Field<N>> {
    match authority {
        Authority::Beacon(_) => Vec::new(),
        Authority::Quorum(subdag) => subdag.certificate_ids().collect(),
    }
}

/// Removes the authority of every block in `heights`, without reading it, and records that every
/// height below `heights.end` is pruned. Call it inside an atomic batch scope; genesis is never
/// pruned. The blocks' certificate indexes stay until the next startup and read as absent meanwhile.
///
/// Decoding an authority checks every curve point and costs tens of milliseconds, so pruning never
/// does it. Callers that pause atomic writes must keep one block per paused span (see
/// `VM::add_next_block`), since the watermark is visible to the next scope only once committed.
#[cfg(feature = "prune-authority-data")]
fn prune_authority_heights<N: Network, B: BlockStorage<N>>(storage: &B, heights: core::ops::Range<u32>) -> Result<()> {
    for height in heights.start.max(1)..heights.end {
        let Some(block_hash) = storage.id_map().get_speculative(&height)? else {
            warn!("Not pruning the authority of block {height}: it has no hash recorded");
            continue;
        };
        storage.authority_map().remove(&block_hash)?;
    }
    storage.set_authority_pruned_below(heights.end)
}

/// Prunes, when opening storage, the authorities between the watermark and the retained window,
/// then the certificate indexes of every pruned block.
#[cfg(feature = "prune-authority-data")]
fn prune_expired_authorities<N: Network, B: BlockStorage<N>>(storage: &B, latest_height: u32) -> Result<()> {
    let start = storage.authority_pruned_below()?.unwrap_or(1);
    prune_authority_range(storage, start, oldest_retained_authority_height(latest_height))?;
    if let Some(below) = storage.authority_pruned_below()? {
        prune_certificate_indexes(storage, below)?;
    }
    Ok(())
}

/// Prunes the authorities of `start..floor` in chunks, one batch each, logging progress. Each chunk
/// advances the watermark, so an interrupted run resumes where it stopped.
#[cfg(feature = "prune-authority-data")]
fn prune_authority_range<N: Network, B: BlockStorage<N>>(storage: &B, start: u32, floor: u32) -> Result<()> {
    if start >= floor {
        return Ok(());
    }
    let total = floor - start;
    info!("Pruning the authority data of {total} blocks below block {floor}");

    let timer = std::time::Instant::now();
    let report_every = (total / 100).max(AUTHORITY_PRUNING_CHUNK_HEIGHTS);
    let mut next_report = report_every;
    for chunk_start in (start..floor).step_by(AUTHORITY_PRUNING_CHUNK_HEIGHTS as usize) {
        let chunk_end = chunk_start.saturating_add(AUTHORITY_PRUNING_CHUNK_HEIGHTS).min(floor);
        atomic_batch_scope!(storage, { prune_authority_heights(storage, chunk_start..chunk_end) })?;

        let done = chunk_end - start;
        if done >= next_report && done < total {
            let rate = f64::from(done) / timer.elapsed().as_secs_f64().max(f64::EPSILON);
            let percent = 100.0 * f64::from(done) / f64::from(total);
            let remaining = f64::from(total - done) / rate;
            info!("Pruned {done} of {total} blocks ({percent:.0}%), {rate:.0} blocks/s, about {remaining:.0} s left");
            next_report = done + report_every;
        }
    }
    info!("Pruned the authority data below block {floor} in {:.1} s", timer.elapsed().as_secs_f64());
    Ok(())
}

/// Removes the certificate indexes of blocks below `below`, in one pass over the small index rows.
/// It runs on every startup, since inserts leave these rows behind.
/// Returns whether it attempted to compact the certificate map afterwards.
#[cfg(feature = "prune-authority-data")]
fn prune_certificate_indexes<N: Network, B: BlockStorage<N>>(storage: &B, below: u32) -> Result<bool> {
    let flush = |batch: &[Field<N>]| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        atomic_batch_scope!(storage, {
            for certificate_id in batch {
                storage.certificate_map().remove(certificate_id)?;
            }
            Ok(())
        })
    };

    let timer = std::time::Instant::now();
    let mut removed = 0;
    let mut batch = Vec::with_capacity(CERTIFICATE_PRUNING_BATCH_SIZE);
    // Keep one forward iterator to avoid rescanning RocksDB tombstones. Each batch removes only keys
    // already yielded.
    for (certificate_id, index) in storage.certificate_map().iter_confirmed() {
        if (1..below).contains(&index.0) {
            batch.push(certificate_id.into_owned());
            removed += 1;
            if batch.len() == CERTIFICATE_PRUNING_BATCH_SIZE {
                flush(&batch)?;
                batch.clear();
            }
        }
    }
    flush(&batch)?;

    if removed > 0 {
        info!("Removed {removed} certificate indexes of pruned blocks in {:.1} s", timer.elapsed().as_secs_f64());
    } else {
        debug!("No certificate indexes of pruned blocks to remove ({:.1} s)", timer.elapsed().as_secs_f64());
    }

    // Compact after a large deletion, so later startups do not read past its tombstones. A failure
    // costs only time on the next startup.
    if removed < AUTHORITY_PRUNING_COMPACTION_THRESHOLD {
        return Ok(false);
    }
    let timer = std::time::Instant::now();
    match storage.compact_certificate_map() {
        Ok(()) => info!("Compacted the certificate map in {:.1} s", timer.elapsed().as_secs_f64()),
        Err(error) => warn!("Failed to compact the certificate map: {error}"),
    }
    Ok(true)
}

/// A trait for block storage.
pub trait BlockStorage<N: Network>: 'static + Clone + Send + Sync {
    /// The mapping of `block height` to `state root`.
    type StateRootMap: for<'a> Map<'a, u32, N::StateRoot>;
    /// The mapping of `state root` to `block height`.
    type ReverseStateRootMap: for<'a> Map<'a, N::StateRoot, u32>;
    /// The mapping of `block height` to `block hash`.
    type IDMap: for<'a> Map<'a, u32, N::BlockHash>;
    /// The mapping of `block hash` to `block height`.
    type ReverseIDMap: for<'a> Map<'a, N::BlockHash, u32>;
    /// The mapping of `block hash` to `block header`.
    type HeaderMap: for<'a> Map<'a, N::BlockHash, Header<N>>;
    /// The mapping of `block hash` to `block authority`.
    type AuthorityMap: for<'a> Map<'a, N::BlockHash, Authority<N>>;
    /// The mapping of `certificate ID` to (`block height`, `round height`).
    type CertificateMap: for<'a> Map<'a, Field<N>, (u32, u64)>;
    /// The mapping of `block hash` to `block ratifications`.
    type RatificationsMap: for<'a> Map<'a, N::BlockHash, Ratifications<N>>;
    /// The mapping of `block hash` to `block solutions`.
    type SolutionsMap: for<'a> Map<'a, N::BlockHash, Solutions<N>>;
    /// The mapping of `solution ID` to `block height`.
    type SolutionIDsMap: for<'a> Map<'a, SolutionID<N>, u32>;
    /// The mapping of `block hash` to `[aborted solution ID]`.
    type AbortedSolutionIDsMap: for<'a> Map<'a, N::BlockHash, Vec<SolutionID<N>>>;
    /// The mapping of aborted `solution ID` to `block height`.
    type AbortedSolutionHeightsMap: for<'a> Map<'a, SolutionID<N>, u32>;
    /// The mapping of `block hash` to `[transaction ID]`.
    type TransactionsMap: for<'a> Map<'a, N::BlockHash, Vec<N::TransactionID>>;
    /// The mapping of `block hash` to `[aborted transaction ID]`.
    type AbortedTransactionIDsMap: for<'a> Map<'a, N::BlockHash, Vec<N::TransactionID>>;
    /// The mapping of rejected or aborted `transaction ID` to `block hash`.
    type RejectedOrAbortedTransactionIDMap: for<'a> Map<'a, N::TransactionID, N::BlockHash>;
    /// The mapping of `transaction ID` to `(block hash, confirmed tx type, finalize operations)`.
    type ConfirmedTransactionsMap: for<'a> Map<'a, N::TransactionID, (N::BlockHash, ConfirmedTxType<N>, Vec<FinalizeOperation<N>>)>;
    /// The rejected deployment or execution map.
    type RejectedDeploymentOrExecutionMap: for<'a> Map<'a, Field<N>, Rejected<N>>;
    /// The block metadata map: block-store state that shares the block store's atomic batches.
    type BlockMetadataMap: for<'a> Map<'a, BlockMetadataKey, Vec<u8>>;
    /// The transaction storage.
    type TransactionStorage: TransactionStorage<N, TransitionStorage = Self::TransitionStorage>;
    /// The transition storage.
    type TransitionStorage: TransitionStorage<N>;

    /// Initializes the block storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self>;

    /// Returns the state root map.
    fn state_root_map(&self) -> &Self::StateRootMap;
    /// Returns the reverse state root map.
    fn reverse_state_root_map(&self) -> &Self::ReverseStateRootMap;
    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap;
    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap;
    /// Returns the header map.
    fn header_map(&self) -> &Self::HeaderMap;
    /// Returns the authority map.
    fn authority_map(&self) -> &Self::AuthorityMap;
    /// Returns the certificate map.
    fn certificate_map(&self) -> &Self::CertificateMap;
    /// Returns the ratifications map.
    fn ratifications_map(&self) -> &Self::RatificationsMap;
    /// Returns the solutions map.
    fn solutions_map(&self) -> &Self::SolutionsMap;
    /// Returns the solution IDs map.
    fn solution_ids_map(&self) -> &Self::SolutionIDsMap;
    /// Returns the aborted solution IDs map.
    fn aborted_solution_ids_map(&self) -> &Self::AbortedSolutionIDsMap;
    /// Returns the aborted solution heights map.
    fn aborted_solution_heights_map(&self) -> &Self::AbortedSolutionHeightsMap;
    /// Returns the accepted transactions map.
    fn transactions_map(&self) -> &Self::TransactionsMap;
    /// Returns the aborted transaction IDs map.
    fn aborted_transaction_ids_map(&self) -> &Self::AbortedTransactionIDsMap;
    /// Returns the rejected or aborted transaction ID map.
    fn rejected_or_aborted_transaction_id_map(&self) -> &Self::RejectedOrAbortedTransactionIDMap;
    /// Returns the confirmed transactions map.
    fn confirmed_transactions_map(&self) -> &Self::ConfirmedTransactionsMap;
    /// Returns the rejected deployment or execution map.
    fn rejected_deployment_or_execution_map(&self) -> &Self::RejectedDeploymentOrExecutionMap;
    /// Returns the block metadata map.
    fn block_metadata_map(&self) -> &Self::BlockMetadataMap;

    /// Compacts the certificate map's storage, so its deleted rows stop costing reads. Storage
    /// without deferred compaction does nothing.
    fn compact_certificate_map(&self) -> Result<()> {
        Ok(())
    }

    /// Returns `true` if authority data has been pruned from this storage, which a build without
    /// `prune-authority-data` refuses to open.
    fn is_authority_pruned(&self) -> Result<bool> {
        Ok(self.authority_pruned_below()?.is_some())
    }

    /// Returns the authority-pruning watermark `W`: the authority data of every height in `1..W` has
    /// been pruned. `None` if nothing has been pruned. The speculative read also sees a watermark
    /// queued earlier in the current batch.
    fn authority_pruned_below(&self) -> Result<Option<u32>> {
        // The value is `W` as a little-endian `u32`. An empty value predates the watermark and
        // records only that pruning has started.
        match self.block_metadata_map().get_speculative(&BlockMetadataKey::AuthorityPruned)? {
            None => Ok(None),
            Some(bytes) if bytes.is_empty() => Ok(Some(1)),
            Some(bytes) => {
                let Ok(bytes) = <[u8; 4]>::try_from(bytes.as_slice()) else {
                    bail!("Malformed authority-pruning watermark");
                };
                Ok(Some(u32::from_le_bytes(bytes)))
            }
        }
    }

    /// Records that the authority data of every height in `1..below` has been pruned. Call it in
    /// the batch that deletes the data. The watermark never moves backwards.
    fn set_authority_pruned_below(&self, below: u32) -> Result<()> {
        debug_assert!(self.is_atomic_in_progress(), "The watermark must share the batch of the deletes");
        if self.authority_pruned_below()?.is_some_and(|current| current >= below) {
            return Ok(());
        }
        self.block_metadata_map().insert(BlockMetadataKey::AuthorityPruned, below.to_le_bytes().to_vec())
    }
    /// Returns the transaction store.
    fn transaction_store(&self) -> &TransactionStore<N, Self::TransactionStorage>;

    /// Returns the transition store.
    fn transition_store(&self) -> &TransitionStore<N, Self::TransitionStorage> {
        self.transaction_store().transition_store()
    }
    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        debug_assert!(self.transaction_store().storage_mode() == self.transition_store().storage_mode());
        self.transition_store().storage_mode()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.state_root_map().start_atomic();
        self.reverse_state_root_map().start_atomic();
        self.id_map().start_atomic();
        self.reverse_id_map().start_atomic();
        self.header_map().start_atomic();
        self.authority_map().start_atomic();
        self.certificate_map().start_atomic();
        self.ratifications_map().start_atomic();
        self.solutions_map().start_atomic();
        self.solution_ids_map().start_atomic();
        self.aborted_solution_ids_map().start_atomic();
        self.aborted_solution_heights_map().start_atomic();
        self.transactions_map().start_atomic();
        self.aborted_transaction_ids_map().start_atomic();
        self.rejected_or_aborted_transaction_id_map().start_atomic();
        self.confirmed_transactions_map().start_atomic();
        self.rejected_deployment_or_execution_map().start_atomic();
        self.block_metadata_map().start_atomic();
        self.transaction_store().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.state_root_map().is_atomic_in_progress()
            || self.reverse_state_root_map().is_atomic_in_progress()
            || self.id_map().is_atomic_in_progress()
            || self.reverse_id_map().is_atomic_in_progress()
            || self.header_map().is_atomic_in_progress()
            || self.authority_map().is_atomic_in_progress()
            || self.certificate_map().is_atomic_in_progress()
            || self.ratifications_map().is_atomic_in_progress()
            || self.solutions_map().is_atomic_in_progress()
            || self.solution_ids_map().is_atomic_in_progress()
            || self.aborted_solution_ids_map().is_atomic_in_progress()
            || self.aborted_solution_heights_map().is_atomic_in_progress()
            || self.transactions_map().is_atomic_in_progress()
            || self.aborted_transaction_ids_map().is_atomic_in_progress()
            || self.rejected_or_aborted_transaction_id_map().is_atomic_in_progress()
            || self.confirmed_transactions_map().is_atomic_in_progress()
            || self.rejected_deployment_or_execution_map().is_atomic_in_progress()
            || self.block_metadata_map().is_atomic_in_progress()
            || self.transaction_store().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.state_root_map().atomic_checkpoint();
        self.reverse_state_root_map().atomic_checkpoint();
        self.id_map().atomic_checkpoint();
        self.reverse_id_map().atomic_checkpoint();
        self.header_map().atomic_checkpoint();
        self.authority_map().atomic_checkpoint();
        self.certificate_map().atomic_checkpoint();
        self.ratifications_map().atomic_checkpoint();
        self.solutions_map().atomic_checkpoint();
        self.solution_ids_map().atomic_checkpoint();
        self.aborted_solution_ids_map().atomic_checkpoint();
        self.aborted_solution_heights_map().atomic_checkpoint();
        self.transactions_map().atomic_checkpoint();
        self.aborted_transaction_ids_map().atomic_checkpoint();
        self.rejected_or_aborted_transaction_id_map().atomic_checkpoint();
        self.confirmed_transactions_map().atomic_checkpoint();
        self.rejected_deployment_or_execution_map().atomic_checkpoint();
        self.block_metadata_map().atomic_checkpoint();
        self.transaction_store().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.state_root_map().clear_latest_checkpoint();
        self.reverse_state_root_map().clear_latest_checkpoint();
        self.id_map().clear_latest_checkpoint();
        self.reverse_id_map().clear_latest_checkpoint();
        self.header_map().clear_latest_checkpoint();
        self.authority_map().clear_latest_checkpoint();
        self.certificate_map().clear_latest_checkpoint();
        self.ratifications_map().clear_latest_checkpoint();
        self.solutions_map().clear_latest_checkpoint();
        self.solution_ids_map().clear_latest_checkpoint();
        self.aborted_solution_ids_map().clear_latest_checkpoint();
        self.aborted_solution_heights_map().clear_latest_checkpoint();
        self.transactions_map().clear_latest_checkpoint();
        self.aborted_transaction_ids_map().clear_latest_checkpoint();
        self.rejected_or_aborted_transaction_id_map().clear_latest_checkpoint();
        self.confirmed_transactions_map().clear_latest_checkpoint();
        self.rejected_deployment_or_execution_map().clear_latest_checkpoint();
        self.block_metadata_map().clear_latest_checkpoint();
        self.transaction_store().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.state_root_map().atomic_rewind();
        self.reverse_state_root_map().atomic_rewind();
        self.id_map().atomic_rewind();
        self.reverse_id_map().atomic_rewind();
        self.header_map().atomic_rewind();
        self.authority_map().atomic_rewind();
        self.certificate_map().atomic_rewind();
        self.ratifications_map().atomic_rewind();
        self.solutions_map().atomic_rewind();
        self.solution_ids_map().atomic_rewind();
        self.aborted_solution_ids_map().atomic_rewind();
        self.aborted_solution_heights_map().atomic_rewind();
        self.transactions_map().atomic_rewind();
        self.aborted_transaction_ids_map().atomic_rewind();
        self.rejected_or_aborted_transaction_id_map().atomic_rewind();
        self.confirmed_transactions_map().atomic_rewind();
        self.rejected_deployment_or_execution_map().atomic_rewind();
        self.block_metadata_map().atomic_rewind();
        self.transaction_store().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.state_root_map().abort_atomic();
        self.reverse_state_root_map().abort_atomic();
        self.id_map().abort_atomic();
        self.reverse_id_map().abort_atomic();
        self.header_map().abort_atomic();
        self.authority_map().abort_atomic();
        self.certificate_map().abort_atomic();
        self.ratifications_map().abort_atomic();
        self.solutions_map().abort_atomic();
        self.solution_ids_map().abort_atomic();
        self.aborted_solution_ids_map().abort_atomic();
        self.aborted_solution_heights_map().abort_atomic();
        self.transactions_map().abort_atomic();
        self.aborted_transaction_ids_map().abort_atomic();
        self.rejected_or_aborted_transaction_id_map().abort_atomic();
        self.confirmed_transactions_map().abort_atomic();
        self.rejected_deployment_or_execution_map().abort_atomic();
        self.block_metadata_map().abort_atomic();
        self.transaction_store().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.state_root_map().finish_atomic()?;
        self.reverse_state_root_map().finish_atomic()?;
        self.id_map().finish_atomic()?;
        self.reverse_id_map().finish_atomic()?;
        self.header_map().finish_atomic()?;
        self.authority_map().finish_atomic()?;
        self.certificate_map().finish_atomic()?;
        self.ratifications_map().finish_atomic()?;
        self.solutions_map().finish_atomic()?;
        self.solution_ids_map().finish_atomic()?;
        self.aborted_solution_ids_map().finish_atomic()?;
        self.aborted_solution_heights_map().finish_atomic()?;
        self.transactions_map().finish_atomic()?;
        self.aborted_transaction_ids_map().finish_atomic()?;
        self.rejected_or_aborted_transaction_id_map().finish_atomic()?;
        self.confirmed_transactions_map().finish_atomic()?;
        self.rejected_deployment_or_execution_map().finish_atomic()?;
        self.block_metadata_map().finish_atomic()?;
        self.transaction_store().finish_atomic()
    }

    /// Pauses atomic writes.
    fn pause_atomic_writes(&self) -> Result<()> {
        // Since this applies to the entire storage, any map can be used; this
        // one is just the first one in the list.
        self.state_root_map().pause_atomic_writes()
    }

    /// Unpauses atomic writes.
    fn unpause_atomic_writes<const DISCARD_BATCH: bool>(&self) -> Result<()> {
        // Since this applies to the entire storage, any map can be used; this
        // one is just the first one in the list.
        self.state_root_map().unpause_atomic_writes::<DISCARD_BATCH>()
    }

    /// Stores the given `(state root, block)` pair into storage.
    fn insert(&self, state_root: N::StateRoot, block: &Block<N>) -> Result<()> {
        // Prepare the confirmed transactions.
        let confirmed = block
            .transactions()
            .iter()
            .cloned()
            .map(|confirmed| to_confirmed_tuple(confirmed))
            .collect::<Result<Vec<_>, _>>()?;

        // Retrieve the certificate IDs to store.
        let certificates_to_store = match block.authority() {
            Authority::Beacon(_) => Vec::new(),
            Authority::Quorum(subdag) => {
                subdag.iter().flat_map(|(round, certificates)| certificates.iter().map(|c| (c.id(), *round))).collect()
            }
        };

        // Prepare the rejected transaction IDs and their corresponding unconfirmed transaction IDs.
        let rejected_transaction_ids: Vec<_> = block
            .transactions()
            .iter()
            .filter(|tx| tx.is_rejected())
            .map(|tx| tx.to_unconfirmed_transaction_id())
            .collect::<Result<Vec<_>>>()?;

        atomic_batch_scope!(self, {
            // Prune the authority that expires with this block. If pruning is behind (a startup
            // catch-up stopped part-way), leave the gap to the next startup so inserts stay bounded.
            #[cfg(feature = "prune-authority-data")]
            if let Some(expired_height) = block.height().checked_sub(AUTHORITY_RETENTION_BLOCKS)
                && self.authority_pruned_below()?.unwrap_or(1) == expired_height
            {
                prune_authority_heights(self, expired_height..expired_height + 1)?;
                if expired_height.is_multiple_of(AUTHORITY_PRUNING_LOG_INTERVAL) {
                    debug!("Pruned authority data up to block {expired_height}");
                }
            }

            // Store the (block height, state root) pair.
            self.state_root_map().insert(block.height(), state_root)?;
            // Store the (state root, block height) pair.
            self.reverse_state_root_map().insert(state_root, block.height())?;

            // Store the block hash.
            self.id_map().insert(block.height(), block.hash())?;
            // Store the block height.
            self.reverse_id_map().insert(block.hash(), block.height())?;
            // Store the block header.
            self.header_map().insert(block.hash(), *block.header())?;

            // Store the block authority.
            self.authority_map().insert(block.hash(), block.authority().clone())?;

            // Store the block certificates.
            for (certificate_id, round) in certificates_to_store {
                self.certificate_map().insert(certificate_id, (block.height(), round))?;
            }

            // Store the block ratifications.
            self.ratifications_map().insert(block.hash(), block.ratifications().clone())?;

            // Store the block solutions.
            self.solutions_map().insert(block.hash(), block.solutions().clone())?;

            // Store the block solution IDs.
            for solution_id in block.solutions().solution_ids() {
                self.solution_ids_map().insert(*solution_id, block.height())?;
            }

            // Store the aborted solution IDs.
            self.aborted_solution_ids_map().insert(block.hash(), block.aborted_solution_ids().clone())?;

            // Store the block aborted solution heights.
            for solution_id in block.aborted_solution_ids() {
                self.aborted_solution_heights_map().insert(*solution_id, block.height())?;
            }

            // Store the transaction IDs.
            self.transactions_map().insert(block.hash(), block.transaction_ids().copied().collect())?;

            // Store the aborted transaction IDs.
            self.aborted_transaction_ids_map().insert(block.hash(), block.aborted_transaction_ids().clone())?;
            for aborted_transaction_id in block.aborted_transaction_ids() {
                self.rejected_or_aborted_transaction_id_map().insert(*aborted_transaction_id, block.hash())?;
            }

            // Store the rejected transactions IDs.
            for rejected_transaction_id in rejected_transaction_ids {
                self.rejected_or_aborted_transaction_id_map().insert(rejected_transaction_id, block.hash())?;
            }

            // Store the confirmed transactions.
            for (confirmed_type, transaction, finalize_operations) in confirmed {
                // Store the block hash and confirmed transaction data.
                self.confirmed_transactions_map()
                    .insert(transaction.id(), (block.hash(), confirmed_type.clone(), finalize_operations))?;
                // Store the rejected deployment or execution.
                if let ConfirmedTxType::RejectedDeploy(_, rejected) | ConfirmedTxType::RejectedExecute(_, rejected) =
                    confirmed_type
                {
                    self.rejected_deployment_or_execution_map().insert(rejected.to_id()?, rejected)?;
                }
                // Store the transaction.
                self.transaction_store().insert(&transaction)?;
            }

            Ok(())
        })
    }

    /// Removes the block for the given `block hash`.
    fn remove(&self, block_hash: &N::BlockHash) -> Result<()> {
        // Retrieve the block height.
        let Some(block_height) = self.get_block_height(block_hash)? else {
            bail!("Failed to remove block: missing block height for block hash '{block_hash}'")
        };
        // Retrieve the state root.
        let Some(state_root) = self.state_root_map().get_confirmed(&block_height)?.map(|x| *x) else {
            bail!("Failed to remove block: missing state root for block height '{block_height}'");
        };
        // Retrieve the transaction IDs.
        let Some(transaction_ids) = self.transactions_map().get_confirmed(block_hash)? else {
            bail!("Failed to remove block: missing transactions for block '{block_height}' ('{block_hash}')");
        };
        // Retrieve the solutions.
        let Some(solutions) = self.solutions_map().get_confirmed(block_hash)?.map(|x| x.into_owned()) else {
            bail!("Failed to remove block: missing solutions for block '{block_height}' ('{block_hash}')");
        };

        // Retrieve the aborted solution IDs.
        let aborted_solution_ids = self.get_block_aborted_solution_ids(block_hash)?.unwrap_or_default();

        // Retrieve the aborted transaction IDs.
        let aborted_transaction_ids = self.get_block_aborted_transaction_ids(block_hash)?.unwrap_or_default();

        // Retrieve the rejected transaction IDs, and the deployment or execution ID.
        let rejected_transaction_ids_and_deployment_or_execution_id = match self.get_block_transactions(block_hash)? {
            Some(transactions) => transactions
                .iter()
                .filter(|tx| tx.is_rejected())
                .map(|tx| Ok((tx.to_unconfirmed_transaction_id()?, tx.to_rejected_id()?)))
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        };

        // Determine the certificate IDs to remove.
        let certificate_ids_to_remove = match self.authority_map().get_confirmed(block_hash)? {
            Some(authority) => certificate_ids(&authority),
            None => bail!("Failed to remove block: missing authority for block '{block_height}' ('{block_hash}')"),
        };

        atomic_batch_scope!(self, {
            // Remove the (block height, state root) pair.
            self.state_root_map().remove(&block_height)?;
            // Remove the (state root, block height) pair.
            self.reverse_state_root_map().remove(&state_root)?;

            // Remove the block hash.
            self.id_map().remove(&block_height)?;
            // Remove the block height.
            self.reverse_id_map().remove(block_hash)?;
            // Remove the block header.
            self.header_map().remove(block_hash)?;

            // Remove the block authority.
            self.authority_map().remove(block_hash)?;

            // Remove the block certificates.
            for certificate_id in certificate_ids_to_remove.iter() {
                self.certificate_map().remove(certificate_id)?;
            }

            // Remove the block ratifications.
            self.ratifications_map().remove(block_hash)?;

            // Remove the block solutions.
            self.solutions_map().remove(block_hash)?;

            // Remove the block solution IDs.
            for solution_id in solutions.solution_ids() {
                self.solution_ids_map().remove(solution_id)?;
            }

            // Remove the aborted solution IDs.
            self.aborted_solution_ids_map().remove(block_hash)?;

            // Remove the aborted solution heights.
            for solution_id in aborted_solution_ids {
                self.aborted_solution_heights_map().remove(&solution_id)?;
            }

            // Remove the transaction IDs.
            self.transactions_map().remove(block_hash)?;

            // Remove the aborted transaction IDs.
            self.aborted_transaction_ids_map().remove(block_hash)?;
            for aborted_transaction_id in aborted_transaction_ids {
                self.rejected_or_aborted_transaction_id_map().remove(&aborted_transaction_id)?;
            }

            // Remove the rejected state.
            for (rejected_transaction_id, rejected_id) in rejected_transaction_ids_and_deployment_or_execution_id {
                // Remove the rejected transaction ID.
                self.rejected_or_aborted_transaction_id_map().remove(&rejected_transaction_id)?;
                // Remove the rejected deployment or execution.
                if let Some(rejected_id) = rejected_id {
                    self.rejected_deployment_or_execution_map().remove(&rejected_id)?;
                }
            }

            // Remove the block transactions.
            for transaction_id in transaction_ids.iter() {
                // Remove the reverse transaction ID.
                self.confirmed_transactions_map().remove(transaction_id)?;
                // Remove the transaction.
                self.transaction_store().remove(transaction_id)?;
            }

            Ok(())
        })
    }

    /// Returns `true` if the given transaction ID exists.
    fn contains_transaction_id(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        Ok(self.transaction_store().contains_transaction_id(transaction_id)?
            || self.contains_rejected_or_aborted_transaction_id(transaction_id)?)
    }

    /// Returns `true` if the given rejected transaction ID or aborted transaction ID exists.
    fn contains_rejected_or_aborted_transaction_id(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        self.rejected_or_aborted_transaction_id_map().contains_key_confirmed(transaction_id)
    }

    /// Returns `true` if the given rejected deployment or execution ID.
    fn contains_rejected_deployment_or_execution_id(&self, rejected_id: &Field<N>) -> Result<bool> {
        self.rejected_deployment_or_execution_map().contains_key_confirmed(rejected_id)
    }

    /// Returns the block height that contains the given `state root`.
    fn find_block_height_from_state_root(&self, state_root: N::StateRoot) -> Result<Option<u32>> {
        Ok(self.reverse_state_root_map().get_confirmed(&state_root)?.map(|x| *x))
    }

    /// Returns the block hash that contains the given `transaction ID`.
    fn find_block_hash(&self, transaction_id: &N::TransactionID) -> Result<Option<N::BlockHash>> {
        match self.confirmed_transactions_map().get_confirmed(transaction_id)? {
            Some(Cow::Borrowed((block_hash, _, _))) => Ok(Some(*block_hash)),
            Some(Cow::Owned((block_hash, _, _))) => Ok(Some(block_hash)),
            None => match self.rejected_or_aborted_transaction_id_map().get_confirmed(transaction_id)? {
                Some(Cow::Borrowed(block_hash)) => Ok(Some(*block_hash)),
                Some(Cow::Owned(block_hash)) => Ok(Some(block_hash)),
                None => Ok(None),
            },
        }
    }

    /// Returns the block height that contains the given `solution ID`.
    fn find_block_height_from_solution_id(&self, solution_id: &SolutionID<N>) -> Result<Option<u32>> {
        Ok(match self.solution_ids_map().get_confirmed(solution_id)? {
            some @ Some(..) => some,
            None => self.aborted_solution_heights_map().get_confirmed(solution_id)?,
        }
        .map(|x| *x))
    }

    /// Returns the state root that contains the given `block height`.
    fn get_state_root(&self, block_height: u32) -> Result<Option<N::StateRoot>> {
        Ok(self.state_root_map().get_confirmed(&block_height)?.map(|x| *x))
    }

    /// Returns a state path for the given `commitment`.
    fn get_state_path_for_commitment(&self, commitment: &Field<N>, block_tree: &BlockTree<N>) -> Result<StatePath<N>> {
        // Ensure the commitment exists.
        if !self.transition_store().contains_commitment(commitment)? {
            bail!("Commitment '{commitment}' does not exist");
        }

        // Find the transition that contains the commitment.
        let transition_id = self.transition_store().find_transition_id(commitment)?;
        // Find the transaction that contains the transition.
        let Some(transaction_id) = self.transaction_store().find_transaction_id_from_transition_id(&transition_id)?
        else {
            bail!("The transaction ID for commitment '{commitment}' is missing in storage");
        };
        // Find the block that contains the transaction.
        let Some(block_hash) = self.find_block_hash(&transaction_id)? else {
            bail!("The block hash for commitment '{commitment}' is missing in storage");
        };

        // Retrieve the transition.
        let Some(transition) = self.transition_store().get_transition(&transition_id)? else {
            bail!("The transition '{transition_id}' for commitment '{commitment}' is missing in storage");
        };
        // Retrieve the block height.
        let Some(block_height) = self.get_block_height(&block_hash)? else {
            bail!("The block height for commitment '{commitment}' is missing in storage");
        };
        // Retrieve the previous block hash.
        let Some(previous_hash) = self.get_previous_block_hash(block_height)? else {
            bail!("The previous block hash for commitment '{commitment}' is missing in storage");
        };
        // Retrieve the block header.
        let Some(block_header) = self.get_block_header(&block_hash)? else {
            bail!("The block header for commitment '{commitment}' is missing in storage");
        };
        // Ensure the block height matches.
        if block_header.height() != block_height {
            bail!("Mismatching block height for block {block_height} ('{block_hash}')")
        }
        // Retrieve the block transactions.
        let Some(transactions) = self.get_block_transactions(&block_hash)? else {
            bail!("The block transactions for commitment '{commitment}' are missing in storage");
        };

        // Construct the global state root and block path.
        let global_state_root = *block_tree.root();
        let block_path = block_tree.prove(block_height as usize, &block_hash.to_bits_le())?;

        // Ensure the global state root exists in storage.
        // A block tree that contains only genesis uses the `Field::one()` stored at height 0.
        // Any other block tree must have its root stored.
        #[cfg(feature = "dev_genesis_state_root")]
        let root_in_storage = if block_tree.number_of_leaves() == 1 {
            self.get_state_root(0)?.as_ref() == Some(&Field::<N>::one().into())
        } else {
            self.reverse_state_root_map().contains_key_confirmed(&global_state_root.into())?
        };
        #[cfg(not(feature = "dev_genesis_state_root"))]
        let root_in_storage = self.reverse_state_root_map().contains_key_confirmed(&global_state_root.into())?;
        if !root_in_storage {
            bail!("The global state root '{global_state_root}' for commitment '{commitment}' is missing in storage");
        }

        // Construct the transition root, transition path and transaction leaf.
        let transition_root = transition.to_root()?;
        let transition_leaf = transition.to_leaf(commitment, false)?;
        let transition_path = transition.to_path(&transition_leaf)?;

        // Construct the transactions path.
        let Ok(transactions_path) = transactions.to_path(transaction_id) else {
            bail!("The transaction '{transaction_id}' for commitment '{commitment}' is not in the block");
        };

        // Construct the transaction path and transaction leaf.
        let Some(transaction) = transactions.get(&transaction_id) else {
            bail!("The transaction '{transaction_id}' for commitment '{commitment}' is not in the block");
        };
        let transaction_leaf = transaction.to_leaf(transition.id())?;
        let transaction_path = transaction.to_path(&transaction_leaf)?;

        // Construct the block header path.
        let header_root = block_header.to_root()?;
        let header_leaf = HeaderLeaf::<N>::new(1, block_header.transactions_root());
        let header_path = block_header.to_path(&header_leaf)?;

        Ok(StatePath::from(
            global_state_root.into(),
            block_path,
            block_hash,
            previous_hash,
            header_root,
            header_path,
            header_leaf,
            transactions_path,
            transaction.id(),
            transaction_path,
            transaction_leaf,
            transition_root,
            *transition.tcm(),
            transition_path,
            transition_leaf,
        ))
    }

    /// Returns a list of state paths for the given list of `commitment`s.
    fn get_state_paths_for_commitments(
        &self,
        commitments: &[Field<N>],
        block_tree: &BlockTree<N>,
    ) -> Result<Vec<StatePath<N>>> {
        // Restrict the number of commitments requested to the maximum number of inputs in a transition.
        if commitments.len() > N::MAX_INPUTS {
            bail!("Too many commitments provided: expected at most {}, got {}", N::MAX_INPUTS, commitments.len());
        }
        commitments.iter().map(|commitment| self.get_state_path_for_commitment(commitment, block_tree)).collect()
    }

    /// Returns the previous block hash of the given `block height`.
    fn get_previous_block_hash(&self, height: u32) -> Result<Option<N::BlockHash>> {
        if height.is_zero() {
            Ok(Some(N::BlockHash::default()))
        } else {
            Ok(self.id_map().get_confirmed(&(height - 1))?.map(|x| *x))
        }
    }

    /// Returns the block hash for the given `block height`.
    fn get_block_hash(&self, height: u32) -> Result<Option<N::BlockHash>> {
        Ok(self.id_map().get_confirmed(&height)?.map(|x| *x))
    }

    /// Returns the block height for the given `block hash`.
    fn get_block_height(&self, block_hash: &N::BlockHash) -> Result<Option<u32>> {
        Ok(self.reverse_id_map().get_confirmed(block_hash)?.map(|x| *x))
    }

    /// Returns the block header for the given `block hash`.
    fn get_block_header(&self, block_hash: &N::BlockHash) -> Result<Option<Header<N>>> {
        Ok(self.header_map().get_confirmed(block_hash)?.map(|x| x.into_owned()))
    }

    /// Returns the block authority for the given `block hash`.
    fn get_block_authority(&self, block_hash: &N::BlockHash) -> Result<Option<Authority<N>>> {
        Ok(self.authority_map().get_confirmed(block_hash)?.map(|x| x.into_owned()))
    }

    /// Returns the (block height, round) of a certificate, or `None` if it is unknown. The index of a
    /// block whose authority has been pruned can remain until the next startup removes it; it reads
    /// as absent.
    fn get_certificate_index(&self, certificate_id: &Field<N>) -> Result<Option<(u32, u64)>> {
        let Some(index) = self.certificate_map().get_confirmed(certificate_id)?.map(|x| *x) else {
            return Ok(None);
        };
        #[cfg(feature = "prune-authority-data")]
        if self.authority_pruned_below()?.is_some_and(|below| (1..below).contains(&index.0)) {
            return Ok(None);
        }
        Ok(Some(index))
    }

    /// Returns true if there is a block that contains the specified certificate.
    fn contains_block_for_certificate(&self, certificate_id: &Field<N>) -> Result<bool> {
        Ok(self.get_certificate_index(certificate_id)?.is_some())
    }

    /// Returns the batch certificate for the given `certificate ID`.
    fn get_batch_certificate(&self, certificate_id: &Field<N>) -> Result<Option<BatchCertificate<N>>> {
        // Retrieve the height and round for the given certificate ID.
        let Some((block_height, round)) = self.get_certificate_index(certificate_id)? else {
            return Ok(None);
        };
        // Retrieve the block hash.
        let Some(block_hash) = self.get_block_hash(block_height)? else {
            bail!("The block hash for block '{block_height}' is missing in block storage")
        };
        // Retrieve the authority for the given block hash.
        let Some(authority) = self.authority_map().get_confirmed(&block_hash)? else {
            // Pruning may have removed the authority after the index was read.
            #[cfg(feature = "prune-authority-data")]
            if self.authority_pruned_below()?.is_some_and(|below| (1..below).contains(&block_height)) {
                return Ok(None);
            }
            bail!("The authority for '{block_hash}' is missing in block storage")
        };
        // Retrieve the certificate for the given certificate ID.
        match &authority {
            Cow::Owned(Authority::Quorum(subdag)) | Cow::Borrowed(Authority::Quorum(subdag)) => {
                match subdag.get(&round) {
                    Some(certificates) => {
                        // Retrieve the certificate for the given certificate ID.
                        match certificates.iter().find(|certificate| &certificate.id() == certificate_id) {
                            Some(certificate) => Ok(Some(certificate.clone())),
                            None => bail!("The certificate '{certificate_id}' is missing in block storage"),
                        }
                    }
                    None => bail!("The certificates for round '{round}' is missing in block storage"),
                }
            }
            _ => bail!(
                "Cannot fetch batch certificate '{certificate_id}' - The authority for block '{block_height}' is not a subdag"
            ),
        }
    }

    /// Returns the block ratifications for the given `block hash`.
    fn get_block_ratifications(&self, block_hash: &N::BlockHash) -> Result<Option<Ratifications<N>>> {
        Ok(self.ratifications_map().get_confirmed(block_hash)?.map(|x| x.into_owned()))
    }

    /// Returns the block solutions for the given `block hash`.
    fn get_block_solutions(&self, block_hash: &N::BlockHash) -> Result<Solutions<N>> {
        let Some(solutions) = self.solutions_map().get_confirmed(block_hash)? else {
            bail!("Missing solutions for block ('{block_hash}')");
        };
        Ok(solutions.into_owned())
    }

    /// Returns the prover solution for the given solution ID, or `None` if no reference to this solution
    /// exists in the ledger.
    fn get_solution(&self, solution_id: &SolutionID<N>) -> Result<Option<Solution<N>>> {
        // Retrieve the block height for the solution ID.
        let Some(block_height) = self.find_block_height_from_solution_id(solution_id)? else {
            // In this case, the solution is not yet known to the ledger.
            return Ok(None);
        };

        // Errors below are more severe, as it measn there is a reference to solution, but
        // the solution itself is missing.

        // Get the block hash for the given height.
        let Some(block_hash) = self.get_block_hash(block_height)? else {
            bail!("The block hash for block '{block_height}' is missing in block storage")
        };

        // Get the solutions for the block.
        let Some(solutions) = self.solutions_map().get_confirmed(&block_hash)? else {
            bail!("The solutions for block '{block_height}' are missing in block storage")
        };

        // Retrieve the prover solution.
        if let Some(solutions) = solutions.deref().deref()
            && let Some(solution) = solutions.get(solution_id).cloned()
        {
            Ok(Some(solution))
        } else {
            bail!("The prover solution for solution ID '{solution_id}' is missing in block storage");
        }
    }

    /// Returns the block aborted solution IDs for the given `block hash`.
    fn get_block_aborted_solution_ids(&self, block_hash: &N::BlockHash) -> Result<Option<Vec<SolutionID<N>>>> {
        Ok(self.aborted_solution_ids_map().get_confirmed(block_hash)?.map(|x| x.into_owned()))
    }

    /// Returns the block transactions for the given `block hash`.
    fn get_block_transactions(&self, block_hash: &N::BlockHash) -> Result<Option<Transactions<N>>> {
        // Retrieve the transaction IDs.
        let Some(transaction_ids) = self.transactions_map().get_confirmed(block_hash)? else {
            return Ok(None);
        };
        // Retrieve the transactions.
        transaction_ids
            .iter()
            .map(|transaction_id| self.get_confirmed_transaction(transaction_id))
            .collect::<Result<Option<Transactions<_>>>>()
    }

    /// Returns the block aborted transaction IDs for the given `block hash`.
    fn get_block_aborted_transaction_ids(&self, block_hash: &N::BlockHash) -> Result<Option<Vec<N::TransactionID>>> {
        Ok(self.aborted_transaction_ids_map().get_confirmed(block_hash)?.map(|x| x.into_owned()))
    }

    /// Returns the transaction for the given `TransactionID`, or `None` if no transaction of this ID exists.
    fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        // Check if the transaction was rejected or aborted.
        // Note: We can only retrieve accepted or rejected transactions. We cannot retrieve aborted transactions.
        let Some(block_hash) = self.rejected_or_aborted_transaction_id_map().get_confirmed(transaction_id)? else {
            return self.transaction_store().get_transaction(transaction_id);
        };
        let Some(transactions) = self.get_block_transactions(&block_hash)? else {
            bail!("Missing transactions for block '{block_hash}' in block storage")
        };

        let Some(confirmed) = transactions.find_confirmed_transaction_for_unconfirmed_transaction_id(transaction_id)
        else {
            if let Some(aborted_ids) = self.get_block_aborted_transaction_ids(&block_hash)?
                && aborted_ids.contains(transaction_id)
            {
                bail!("Transaction '{transaction_id}' was aborted in block '{block_hash}'");
            } else {
                return Ok(None);
            }
        };
        Ok(Some(confirmed.transaction().clone()))
    }

    /// Returns the confirmed transaction for the given `transaction ID`, or `None` if no confirmed transaction of this ID exists.
    fn get_confirmed_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<ConfirmedTransaction<N>>> {
        // Retrieve the transaction.
        let Some(transaction) = self.get_transaction(transaction_id)? else {
            return Ok(None);
        };

        // Retrieve the confirmed attributes.
        let Some((_, confirmed_type, finalize_operations)) =
            self.confirmed_transactions_map().get_confirmed(&transaction.id())?.map(|x| x.into_owned())
        else {
            return Ok(None);
        };

        // Construct the confirmed transaction.
        to_confirmed_transaction(confirmed_type, transaction, finalize_operations).map(Some)
    }

    /// Retrieve an unconfirmed transaction using its ID.
    ///
    /// For unconfirmed and accepted transactions, this will return original transaction issued by the client.
    /// This function also returns the original execution/deployment for a rejected transaction,
    /// even when the given `TransactionID` is of a fee transaction.
    ///
    /// # Returns
    /// - `Ok(txn)` if the transaction exists and is not confirmed
    /// - `Ok(None)` if no such unconfirmed transaction exist
    /// - `Err(_)` if any other error occured (most likely a storage corruption)
    fn get_unconfirmed_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        // Check if the transaction was rejected or aborted.
        // Note: We can only retrieve accepted or rejected transactions. We cannot retrieve aborted transactions.
        match self.rejected_or_aborted_transaction_id_map().get_confirmed(transaction_id)? {
            Some(block_hash) => match self.get_block_transactions(&block_hash)? {
                Some(transactions) => {
                    match transactions.find_confirmed_transaction_for_unconfirmed_transaction_id(transaction_id) {
                        Some(confirmed) => Ok(Some(confirmed.to_unconfirmed_transaction()?)),
                        None => Ok(None),
                    }
                }
                // This is an error, because there must always be a transactions entry for a known block hash.
                None => bail!(
                    "Transaction '{transaction_id}' is associated with a block '{block_hash}', but no transactions entry exists for it"
                ),
            },
            None => {
                let Some(txn) = self.transaction_store().get_transaction(transaction_id)? else {
                    return Ok(None);
                };

                // If the transaction is a fee transaction, return the original execution/deployment instead.
                if let Transaction::Fee(_, fee) = txn {
                    // Look up the original transaction in its block.
                    let Some(block_hash) = self.find_block_hash(transaction_id)? else {
                        // This is an error, because a fee transaction must always have an original transaction associated with it.
                        bail!("Transaction {transaction_id} is a fee transaction with no associated block");
                    };

                    match self.get_block_transactions(&block_hash)? {
                        Some(transactions) => transactions.find_unconfirmed_transaction_for_transition_id(fee.id()),
                        None => bail!(
                            "Transaction {transaction_id} is associated with block '{block_hash}' but no transacitons entry exists for it"
                        ),
                    }
                } else {
                    Ok(Some(txn))
                }
            }
        }
    }

    /// Returns the block for the given `block hash`.
    fn get_block(&self, block_hash: &N::BlockHash) -> Result<Option<Block<N>>> {
        // Retrieve the block height.
        let Some(height) = self.get_block_height(block_hash)? else { return Ok(None) };

        // Retrieve the block header.
        let Some(header) = self.get_block_header(block_hash)? else {
            bail!("Missing block header for block {height} ('{block_hash}')");
        };
        // Ensure the block height matches.
        if header.height() != height {
            bail!("Mismatching block height for block {height} ('{block_hash}')")
        }

        // Retrieve the previous block hash.
        let Some(previous_hash) = self.get_previous_block_hash(height)? else {
            bail!("Missing previous block hash for block {height} ('{block_hash}')");
        };
        // Retrieve the block authority.
        let Some(authority) = self.get_block_authority(block_hash)? else {
            bail!("Missing authority for block {height} ('{block_hash}')");
        };
        // Retrieve the block ratifications.
        let Some(ratifications) = self.get_block_ratifications(block_hash)? else {
            bail!("Missing ratifications for block {height} ('{block_hash}')");
        };
        // Retrieve the block solutions.
        let Ok(solutions) = self.get_block_solutions(block_hash) else {
            bail!("Missing solutions for block {height} ('{block_hash}')");
        };
        // Retrieve the block aborted solution IDs.
        let Some(aborted_solution_ids) = self.get_block_aborted_solution_ids(block_hash)? else {
            bail!("Missing aborted solutions IDs for block {height} ('{block_hash}')");
        };
        // Retrieve the block transactions.
        let Some(transactions) = self.get_block_transactions(block_hash)? else {
            bail!("Missing transactions for block {height} ('{block_hash}')");
        };
        // Retrieve the block aborted transaction IDs.
        let Some(aborted_transaction_ids) = self.get_block_aborted_transaction_ids(block_hash)? else {
            bail!("Missing aborted transaction IDs for block {height} ('{block_hash}')");
        };

        // Return the block.
        Ok(Some(Block::from_unchecked(
            *block_hash,
            previous_hash,
            header,
            authority,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
        )?))
    }

    #[cfg(feature = "rocks")]
    fn backup_database<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), String>;

    /// Catches up with the primary instance; only applicable to secondary instances.
    #[cfg(feature = "rocks")]
    fn catch_up_with_primary(&self) -> Result<()>;

    fn create_block_tree(&self) -> Result<BlockTree<N>>;
}

/// The `BlockStore` is the user facing API that either uses `BlockMemory` or `BlockDB` as its storae backend.
#[derive(Clone)]
pub struct BlockStore<N: Network, B: BlockStorage<N>> {
    /// The block storage.
    storage: B,
    /// The block tree.
    tree: Arc<RwLock<BlockTree<N>>>,
    /// Cache of the most recent blocks.
    block_cache: Arc<Option<RwLock<BlockCache<N>>>>,
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Initializes the block storage and its cache.
    pub fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = B::open(storage)?;

        // Pruned authority data cannot be restored, so a non-pruning build must not take over the store.
        #[cfg(not(feature = "prune-authority-data"))]
        if storage.is_authority_pruned()? {
            bail!(
                "This ledger has had authority data pruned, which only a build with the `prune-authority-data` feature \
                 can open"
            );
        }

        let tree = storage.create_block_tree()?;
        let block_tree_cache_path = block_tree_cache_path::<N, _>(&storage);

        let mut initial_cache = Vec::new();
        let cache_end_height = u32::try_from(tree.number_of_leaves())?;
        let cache_start_height = cache_end_height.saturating_sub(BlockCache::<N>::BLOCK_CACHE_SIZE);

        for height in cache_start_height..cache_end_height {
            // Ignore genesis block.
            if height == 0 {
                continue;
            }

            // Get the hash for the next block to add to the cache.
            let hash = storage
                .id_map()
                .get_confirmed(&height)?
                .with_context(|| missing_block_in_tree_error(height, block_tree_cache_path.as_deref()))?;

            initial_cache.push(
                storage.get_block(&hash)?.with_context(|| format!("Block {hash} exists in tree but not in storage"))?,
            );
        }

        let block_cache = RwLock::new(BlockCache::new(initial_cache)?);

        // A secondary instance is read-only: the primary prunes, and the secondary sees the result
        // when it catches up.
        #[cfg(feature = "prune-authority-data")]
        if aleo_secondary_ledger_dir(N::ID, storage.storage_mode()).is_none()
            // Block heights start at zero, so the latest height is one less than the number of leaves.
            && let Some(latest_height) = cache_end_height.checked_sub(1)
            && let Err(error) = prune_expired_authorities(&storage, latest_height)
        {
            // The remaining expired data is pruned on the next startup, so this must not block this one.
            warn!("Failed to prune expired authority data: {error}. Run 'snarkos clean' and resync if this persists.");
        }

        Ok(Self { storage, tree: Arc::new(RwLock::new(tree)), block_cache: Arc::new(Some(block_cache)) })
    }

    /// Stores the given block into storage.
    pub fn insert(&self, block: &Block<N>) -> Result<()> {
        // Acquire the write lock on the block tree.
        let mut tree = self.tree.write();
        // Prepare an updated Merkle tree containing the new block hash.
        let updated_tree = tree.prepare_append(&[block.hash().to_bits_le()])?;
        // Ensure the next block height is correct.
        if block.height() != u32::try_from(updated_tree.number_of_leaves())? - 1 {
            bail!("Attempted to insert a block at the incorrect height into storage")
        }
        // A fixed genesis state root facilitates deterministic creation of transactions for easier testing.
        //
        // At height 0 the stored state root is `Field::one()`. `contains_state_root` accepts that
        // value and rejects the block tree root. `current_state_root` and `Query::VM` return the fixed
        // root while the tree contains only genesis, so a transaction built from `current_state_root`
        // verifies at height 0.
        // `get_state_path_for_commitment` still embeds the block tree root. That root is not stored at
        // height 0, so spending a genesis record fails with `global state root does not exist (yet)`
        // until block 1 stores the tree root.
        // Never enable this feature on a real network. Start the ledger from genesis with the feature
        // already on. Turning it on or off against an existing store fails the state-root check in
        // `Ledger::load`.
        #[cfg(feature = "dev_genesis_state_root")]
        let state_root = if block.height() == 0 { Field::<N>::one().into() } else { (*updated_tree.root()).into() };
        #[cfg(not(feature = "dev_genesis_state_root"))]
        let state_root = (*updated_tree.root()).into();
        // Insert the (state root, block height) pair.
        self.storage.insert(state_root, block)?;
        // Update the block tree, preserving the previous Merkle tree allocation for performance.
        updated_tree.preserve_tree_allocation(&mut tree);
        *tree = updated_tree;
        // Add the block to the block cache (unless it is a genesis block).
        if block.height() != 0
            && let Some(block_cache) = &*self.block_cache
        {
            block_cache.write().insert(block.clone())?;
        }
        // Return success.
        Ok(())
    }

    /// Returns the size of the block cache (or `None` if the block cache is not enabled).
    pub fn cache_size(&self) -> Option<u32> {
        if self.block_cache.is_none() { None } else { Some(BlockCache::<N>::BLOCK_CACHE_SIZE) }
    }

    /// Reverts the Merkle tree to its shape before the insertion of the last 'n' blocks.
    pub fn remove_last_n_from_tree_only(&self, n: u32) -> Result<()> {
        // Ensure 'n' is non-zero.
        ensure!(n > 0, "Cannot remove zero blocks");
        // Acquire the write lock on the block tree.
        let mut tree = self.tree.write();
        // Prepare an updated Merkle tree removing the last 'n' block hashes.
        let updated_tree = tree.prepare_remove_last_n(usize::try_from(n)?)?;
        // Update the block tree.
        *tree = updated_tree;
        // Return success.
        Ok(())
    }

    /// Removes the last (most recent) `n` blocks from storage.
    pub fn remove_last_n(&self, n: u32) -> Result<()> {
        // Ensure 'n' is non-zero.
        ensure!(n > 0, "Cannot remove zero blocks");

        // Acquire the write lock on the block tree.
        let mut tree = self.tree.write();

        // Determine the block heights to remove.
        let heights = match self.max_height() {
            Some(end_height) => {
                // Determine the start block height to remove.
                let start_height = end_height
                    .checked_sub(n - 1)
                    .ok_or_else(|| anyhow!("Failed to remove last '{n}' blocks: block height underflow"))?;
                // Ensure the block height matches the number of leaves in the Merkle tree.
                ensure!(end_height == u32::try_from(tree.number_of_leaves())? - 1, "Block height mismatch");
                // Output the block heights.
                start_height..=end_height
            }
            None => bail!("Failed to remove last '{n}' blocks: no blocks in storage"),
        };
        // Fetch the block hashes to remove.
        let hashes = cfg_into_iter!(heights)
            .map(|height| match self.storage.get_block_hash(height)? {
                Some(hash) => Ok(hash),
                None => bail!("Failed to remove last '{n}' blocks: missing block hash for block {height}"),
            })
            .collect::<Result<Vec<_>>>()?;

        // Prepare an updated Merkle tree removing the last 'n' block hashes.
        let updated_tree = tree.prepare_remove_last_n(usize::try_from(n)?)?;

        atomic_batch_scope!(self, {
            // Remove the blocks, in descending order.
            for block_hash in hashes.iter().rev() {
                self.storage.remove(block_hash)?;
            }
            Ok(())
        })?;

        // Update the block tree.
        *tree = updated_tree;
        // Also remove the last n blocks from the cache.
        if let Some(block_cache) = &*self.block_cache {
            block_cache.write().remove_last_n(n)?;
        }
        // Return success.
        Ok(())
    }

    /// Returns the transaction store.
    pub fn transaction_store(&self) -> &TransactionStore<N, B::TransactionStorage> {
        self.storage.transaction_store()
    }

    /// Returns the transition store.
    pub fn transition_store(&self) -> &TransitionStore<N, B::TransitionStorage> {
        self.storage.transaction_store().transition_store()
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

    /// Pauses atomic writes.
    pub fn pause_atomic_writes(&self) -> Result<()> {
        self.storage.pause_atomic_writes()
    }

    /// Unpauses atomic writes.
    pub fn unpause_atomic_writes<const DISCARD_BATCH: bool>(&self) -> Result<()> {
        self.storage.unpause_atomic_writes::<DISCARD_BATCH>()
    }

    /// Stores a database backup at the given location.
    #[cfg(feature = "rocks")]
    pub fn backup_database<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), String> {
        self.storage.backup_database(path)
    }

    /// Catches up with the primary instance, making all the blocks it has inserted so far
    /// readable from storage; only applicable to storage opened in secondary mode.
    ///
    /// # Note
    /// This only refreshes the contents of the database, and not any in-memory state (e.g. the
    /// block tree), so the latest block height should be obtained via [`Self::max_height`].
    #[cfg(feature = "rocks")]
    pub fn catch_up_with_primary(&self) -> Result<()> {
        self.storage.catch_up_with_primary()
    }

    /// Serializes and persists the current block tree.
    #[cfg(feature = "rocks")]
    pub fn cache_block_tree(&self) -> Result<()> {
        // Prepare the path for the target file.
        let Some(path) = block_tree_cache_path::<N, _>(&self.storage) else {
            // The block tree is not cached for this storage.
            return Ok(());
        };

        // Take an owned snapshot of the tree, so that the read lock is released before the write
        // begins. Serializing a borrowed state would instead hold the lock for the entire write,
        // which can take seconds - and `Self::insert` needs the write lock for every block, so that
        // is a stall in block processing. The cost is one extra copy of the tree's nodes, held only
        // until the write concludes.
        let state = self.tree.read().to_state().into_owned();

        // Create the target file. Truncating the previous cache in place is fine: it is consumed
        // and deleted on startup (see `BlockStorage::create_block_tree`), so a cache from an older
        // height is never reused, and an interrupted write leaves a file that fails to load and
        // falls back to constructing the tree from scratch - exactly what no file at all does.
        let file = fs::File::create(&path)?;
        // The block tree can become quite large, so use a BufWriter in order to
        // not have to keep the entire serialized tree in memory, and to reduce
        // the number of syscalls involved with disk writes. 1MiB should provide
        // a good balance between the CPU cache and maximum disk throughput.
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        writer.write_all(BLOCK_TREE_CACHE_PREFIX)?;
        // Note: only the contents of the tree are cached, not its hashers; the latter are
        // deterministic, and recreating them is far cheaper than deserializing them.
        bincode::serialize_into(&mut writer, &state)?;
        writer.flush()?;
        // TODO(ljedrz): the serialization itself can still take ~2.5s, so we may want to perform
        // chunking and parallel serialization. Now that it no longer holds the block tree lock,
        // this is purely a matter of the background write finishing sooner. This may be useful for
        // other applications, so it should be implemented as a common utility.

        tracing::debug!("Cached the current block tree to {}", path.display());

        Ok(())
    }

    /// Returns the root of the block tree.
    pub fn get_block_tree_root(&self) -> Field<N> {
        *self.tree.read().root()
    }
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Returns the block height that contains the given `state root`.
    pub fn find_block_height_from_state_root(&self, state_root: N::StateRoot) -> Result<Option<u32>> {
        self.storage.find_block_height_from_state_root(state_root)
    }

    /// Returns the block hash that contains the given `transaction ID`.
    pub fn find_block_hash(&self, transaction_id: &N::TransactionID) -> Result<Option<N::BlockHash>> {
        self.storage.find_block_hash(transaction_id)
    }

    /// Returns the block height that contains the given `solution ID`.
    pub fn find_block_height_from_solution_id(&self, solution_id: &SolutionID<N>) -> Result<Option<u32>> {
        self.storage.find_block_height_from_solution_id(solution_id)
    }
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Returns the read-locked `BlockCache`.
    ///
    /// This may return `None` due to lock contention, even if the cache is enabled.
    #[inline]
    #[cfg(feature = "locktick")]
    fn get_block_cache(&self) -> Option<LockGuard<parking_lot::RwLockReadGuard<'_, BlockCache<N>>>> {
        // This uses `try_read` to avoid deadlocks or prologned blocking of a thread in rayon: https://github.com/rayon-rs/rayon/issues/1205
        if let Some(cache) = &*self.block_cache { cache.try_read() } else { None }
    }

    #[inline]
    #[cfg(not(feature = "locktick"))]
    fn get_block_cache(&self) -> Option<parking_lot::RwLockReadGuard<'_, BlockCache<N>>> {
        // This uses `try_read` to avoid deadlocks or prologned blocking of a thread in rayon: https://github.com/rayon-rs/rayon/issues/1205
        if let Some(cache) = &*self.block_cache { cache.try_read() } else { None }
    }

    /// Returns the current state root.
    pub fn current_state_root(&self) -> N::StateRoot {
        let tree = self.tree.read();
        // Height 0 stores `Field::one()` as its state root.
        #[cfg(feature = "dev_genesis_state_root")]
        if tree.number_of_leaves() == 1 {
            return Field::<N>::one().into();
        }
        (*tree.root()).into()
    }

    /// Returns the current block height.
    pub fn current_block_height(&self) -> u32 {
        u32::try_from(self.tree.read().number_of_leaves()).unwrap().saturating_sub(1)
    }

    /// Returns the state root that contains the given `block height`.
    pub fn get_state_root(&self, block_height: u32) -> Result<Option<N::StateRoot>> {
        self.storage.get_state_root(block_height)
    }

    /// Returns a state path for the given `commitment`.
    pub fn get_state_path_for_commitment(&self, commitment: &Field<N>) -> Result<StatePath<N>> {
        self.storage.get_state_path_for_commitment(commitment, &self.tree.read())
    }

    /// Returns a list of state paths for the given list of `commitment`s.
    pub fn get_state_paths_for_commitments(&self, commitments: &[Field<N>]) -> Result<Vec<StatePath<N>>> {
        self.storage.get_state_paths_for_commitments(commitments, &self.tree.read())
    }

    /// Returns the previous block hash of the given `block height`.
    pub fn get_previous_block_hash(&self, height: u32) -> Result<Option<N::BlockHash>> {
        if let Some(cache) = self.get_block_cache()
            && let Some(block) = cache.get_block(height)
        {
            return Ok(Some(block.previous_hash()));
        }

        self.storage.get_previous_block_hash(height)
    }

    /// Returns the block hash for the given `block height`.
    pub fn get_block_hash(&self, height: u32) -> Result<Option<N::BlockHash>> {
        if let Some(cache) = self.get_block_cache()
            && let Some(block) = cache.get_block(height)
        {
            return Ok(Some(block.hash()));
        }

        self.storage.get_block_hash(height)
    }

    /// Returns the block height for the given `block hash`.
    pub fn get_block_height(&self, block_hash: &N::BlockHash) -> Result<Option<u32>> {
        self.storage.get_block_height(block_hash)
    }

    /// Returns the block header for the given `block hash`.
    pub fn get_block_header(&self, block_hash: &N::BlockHash) -> Result<Option<Header<N>>> {
        if let Some(cache) = self.get_block_cache()
            && let Some(block) = cache.get_block_by_hash(block_hash)
        {
            Ok(Some(*block.header()))
        } else {
            self.storage.get_block_header(block_hash)
        }
    }

    /// Returns the block authority for the given `block hash`.
    pub fn get_block_authority(&self, block_hash: &N::BlockHash) -> Result<Option<Authority<N>>> {
        if let Some(cache) = self.get_block_cache()
            && let Some(block) = cache.get_block_by_hash(block_hash)
        {
            Ok(Some(block.authority().clone()))
        } else {
            self.storage.get_block_authority(block_hash)
        }
    }

    /// Returns the block ratifications for the given `block hash`.
    pub fn get_block_ratifications(&self, block_hash: &N::BlockHash) -> Result<Option<Ratifications<N>>> {
        if let Some(block_cache) = self.get_block_cache()
            && let Some(block) = block_cache.get_block_by_hash(block_hash)
        {
            Ok(Some(block.ratifications().clone()))
        } else {
            self.storage.get_block_ratifications(block_hash)
        }
    }

    /// Returns the block solutions for the given `block hash`.
    pub fn get_block_solutions(&self, block_hash: &N::BlockHash) -> Result<Solutions<N>> {
        if let Some(block_cache) = self.get_block_cache()
            && let Some(block) = block_cache.get_block_by_hash(block_hash)
        {
            Ok(block.solutions().clone())
        } else {
            self.storage.get_block_solutions(block_hash)
        }
    }

    /// Returns the prover solution for the given solution ID.
    pub fn get_solution(&self, solution_id: &SolutionID<N>) -> Result<Option<Solution<N>>> {
        self.storage.get_solution(solution_id)
    }

    /// Returns the block transactions for the given `block hash`.
    pub fn get_block_transactions(&self, block_hash: &N::BlockHash) -> Result<Option<Transactions<N>>> {
        self.storage.get_block_transactions(block_hash)
    }

    /// Returns the block aborted transaction IDs for the given `block hash`.
    pub fn get_block_aborted_transaction_ids(
        &self,
        block_hash: &N::BlockHash,
    ) -> Result<Option<Vec<N::TransactionID>>> {
        self.storage.get_block_aborted_transaction_ids(block_hash)
    }

    /// Retrieve a transaction using its ID.
    ///
    /// For a rejected transaction, this returns the fee transaction, not the original/unconfirmed one.
    ///
    /// # Returns
    /// - `Ok(txn)` if the transaction exists
    /// - `Ok(None)` if no such transaction exist
    /// - `Err(_)` if any other error occured
    ///
    pub fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        self.storage.get_transaction(transaction_id)
    }

    /// Retreive a confirmed transation using its ID.
    ///
    /// # Returns
    /// - `Ok(txn)` if the transaction exists
    /// - `Ok(None)` if no such confirmed transaction exist
    /// - `Err(_)` if no such transaction exist or any other error occured
    pub fn get_confirmed_transaction(
        &self,
        transaction_id: &N::TransactionID,
    ) -> Result<Option<ConfirmedTransaction<N>>> {
        self.storage.get_confirmed_transaction(transaction_id)
    }

    /// Retrieve an unconfirmed transaction using its ID.
    ///
    /// For a rejected transaction, this returns the origin transaction issued by the user, not the fee transaction.
    ///
    /// # Returns
    /// - `Ok(txn)` if the transaction exists and is not confirmed
    /// - `Ok(None)` if no such unconfirmed transaction exist
    /// - `Err(_)` if any other error occured
    ///
    pub fn get_unconfirmed_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        self.storage.get_unconfirmed_transaction(transaction_id)
    }

    /// Returns the block for the given `block hash`.
    pub fn get_block(&self, block_hash: &N::BlockHash) -> Result<Option<Block<N>>> {
        if let Some(cache) = self.block_cache.as_ref()
            && let Some(block) = cache.read().get_block_by_hash(block_hash)
        {
            return Ok(Some(block.clone()));
        }
        match self.storage.get_block(block_hash) {
            // Below the watermark a missing authority is expected; report it as pruned only if it is
            // the sole gap, and surface any other missing component as the error it is.
            #[cfg(feature = "prune-authority-data")]
            Err(error) => match self.storage.get_block_height(block_hash)? {
                Some(height)
                    if self.storage.authority_pruned_below()?.is_some_and(|below| (1..below).contains(&height))
                        && self.storage.get_block_authority(block_hash)?.is_none() =>
                {
                    self.check_block_data_without_authority(block_hash)?;
                    bail!("Block {height} ('{block_hash}') cannot be reconstructed: its authority has been pruned")
                }
                _ => Err(error),
            },
            result => result,
        }
    }

    /// Checks that every component of a block except its authority is present and consistent, and
    /// returns the block height. Use it for blocks whose authority may have been pruned.
    pub fn check_block_data_without_authority(&self, block_hash: &N::BlockHash) -> Result<u32> {
        let Some(height) = self.storage.get_block_height(block_hash)? else {
            bail!("Missing block height for block '{block_hash}'");
        };
        let Some(header) = self.storage.get_block_header(block_hash)? else {
            bail!("Missing block header for block {height} ('{block_hash}')");
        };
        ensure!(header.height() == height, "Mismatching block height for block {height} ('{block_hash}')");
        ensure!(
            self.storage.get_previous_block_hash(height)?.is_some(),
            "Missing previous block hash for block {height} ('{block_hash}')"
        );
        ensure!(
            self.storage.get_block_ratifications(block_hash)?.is_some(),
            "Missing ratifications for block {height} ('{block_hash}')"
        );
        self.storage
            .get_block_solutions(block_hash)
            .with_context(|| format!("Missing solutions for block {height} ('{block_hash}')"))?;
        ensure!(
            self.storage.get_block_aborted_solution_ids(block_hash)?.is_some(),
            "Missing aborted solution IDs for block {height} ('{block_hash}')"
        );
        ensure!(
            self.storage.get_block_transactions(block_hash)?.is_some(),
            "Missing transactions for block {height} ('{block_hash}')"
        );
        ensure!(
            self.storage.get_block_aborted_transaction_ids(block_hash)?.is_some(),
            "Missing aborted transaction IDs for block {height} ('{block_hash}')"
        );
        Ok(height)
    }

    /// Returns the latest edition for the given `program ID`.
    pub fn get_latest_edition_for_program(&self, program_id: &ProgramID<N>) -> Result<Option<u16>> {
        self.storage.transaction_store().get_latest_edition_for_program(program_id)
    }

    /// Returns the latest program for the given `program ID`.
    pub fn get_latest_program(&self, program_id: &ProgramID<N>) -> Result<Option<Program<N>>> {
        self.storage.transaction_store().get_latest_program(program_id)
    }

    /// Returns the program for the given `program ID` and `edition`.
    pub fn get_program_for_edition(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<Program<N>>> {
        self.storage.transaction_store().get_program_for_edition(program_id, edition)
    }

    /// Returns true if there is a block for the given certificate.
    pub fn contains_block_for_certificate(&self, certificate_id: &Field<N>) -> Result<bool> {
        self.storage.contains_block_for_certificate(certificate_id)
    }

    /// Returns the batch certificate for the given `certificate ID`.
    pub fn get_batch_certificate(&self, certificate_id: &Field<N>) -> Result<Option<BatchCertificate<N>>> {
        self.storage.get_batch_certificate(certificate_id)
    }
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Returns `true` if the given state root exists.
    pub fn contains_state_root(&self, state_root: &N::StateRoot) -> Result<bool> {
        self.storage.reverse_state_root_map().contains_key_confirmed(state_root)
    }

    /// Returns `true` if the given block height exists.
    pub fn contains_block_height(&self, height: u32) -> Result<bool> {
        self.storage.id_map().contains_key_confirmed(&height)
    }

    /// Returns `true` if the given block hash exists.
    pub fn contains_block_hash(&self, block_hash: &N::BlockHash) -> Result<bool> {
        self.storage.reverse_id_map().contains_key_confirmed(block_hash)
    }

    /// Returns `true` if the given transaction ID exists.
    pub fn contains_transaction_id(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        self.storage.contains_transaction_id(transaction_id)
    }

    /// Returns `true` if the given rejected transaction ID or aborted transaction ID exists.
    pub fn contains_rejected_or_aborted_transaction_id(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        self.storage.contains_rejected_or_aborted_transaction_id(transaction_id)
    }

    /// Returns `true` if the given rejected deployment or execution ID.
    pub fn contains_rejected_deployment_or_execution_id(&self, rejected_id: &Field<N>) -> Result<bool> {
        self.storage.contains_rejected_deployment_or_execution_id(rejected_id)
    }

    /// Returns `true` if the given certificate ID exists.
    pub fn contains_certificate(&self, certificate_id: &Field<N>) -> Result<bool> {
        self.contains_block_for_certificate(certificate_id)
    }

    /// Returns `true` if the given solution ID exists.
    pub fn contains_solution_id(&self, solution_id: &SolutionID<N>) -> Result<bool> {
        Ok(self.storage.solution_ids_map().contains_key_confirmed(solution_id)?
            || self.contains_aborted_solution_id(solution_id)?)
    }

    /// Returns `true` if the given aborted solution ID exists.
    fn contains_aborted_solution_id(&self, solution_id: &SolutionID<N>) -> Result<bool> {
        self.storage.aborted_solution_heights_map().contains_key_confirmed(solution_id)
    }
}

impl<N: Network, B: BlockStorage<N>> BlockStore<N, B> {
    /// Returns an iterator over the state roots, for all blocks in `self`.
    pub fn state_roots(&self) -> impl '_ + Iterator<Item = Cow<'_, N::StateRoot>> {
        self.storage.reverse_state_root_map().keys_confirmed()
    }

    /// Returns an iterator over the block heights, for all blocks in `self`.
    pub fn heights(&self) -> impl '_ + Iterator<Item = Cow<'_, u32>> {
        self.storage.id_map().keys_confirmed()
    }

    /// Returns the height of the latest block in the storage.
    pub fn max_height(&self) -> Option<u32> {
        self.storage.id_map().len_confirmed().checked_sub(1)?.try_into().ok()
    }

    /// Returns an iterator over the block hashes, for all blocks in `self`.
    pub fn hashes(&self) -> impl '_ + Iterator<Item = Cow<'_, N::BlockHash>> {
        self.storage.reverse_id_map().keys_confirmed()
    }

    /// Returns an iterator over the solution IDs, for all blocks in `self`.
    pub fn solution_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, SolutionID<N>>> {
        self.storage.solution_ids_map().keys_confirmed()
    }
}

#[cfg(all(feature = "rocks", feature = "metrics"))]
impl<N: Network> BlockStore<N, crate::helpers::rocksdb::BlockDB<N>> {
    /// Reads RocksDB internal properties and publishes them to the metrics registry.
    /// This is a cheap, synchronous call — properties come from in-memory counters with no I/O.
    pub fn export_rocksdb_metrics(&self) {
        self.storage.export_rocksdb_metrics();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "rocks")]
    use crate::helpers::rocksdb::BlockDB;
    use crate::{helpers::memory::BlockMemory, test_helpers::sample_block_chain};
    use std::path::Path;

    type CurrentNetwork = console::network::MainnetV0;

    /// Returns a chain whose block 1 carries a quorum authority, and one of that authority's certificate IDs.
    #[cfg(any(feature = "prune-authority-data", feature = "rocks"))]
    fn sample_block_chain_with_quorum(
        num_blocks: u32,
        rng: &mut TestRng,
    ) -> (Vec<Block<CurrentNetwork>>, Field<CurrentNetwork>) {
        let mut blocks = sample_block_chain(num_blocks, rng);
        let authority = snarkvm_ledger_authority::test_helpers::sample_quorum_authority(rng);
        let certificate_id = certificate_ids(&authority)[0];
        let block = blocks[1].clone();
        blocks[1] = Block::from_unchecked(
            block.hash(),
            block.previous_hash(),
            *block.header(),
            authority,
            block.ratifications().clone(),
            block.solutions().clone(),
            block.aborted_solution_ids().clone(),
            block.transactions().clone(),
            block.aborted_transaction_ids().clone(),
        )
        .unwrap();
        (blocks, certificate_id)
    }

    /// Returns a block hash derived from a height, for tests that fill the maps directly.
    #[cfg(feature = "prune-authority-data")]
    fn hash_at(height: u32) -> <CurrentNetwork as Network>::BlockHash {
        Field::<CurrentNetwork>::from_u32(height).into()
    }

    #[test]
    fn test_current_block_height_empty() {
        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        // Current_block_height shouldn't panic.
        assert_eq!(block_store.current_block_height(), 0);

        // Verify the equivalence of the alternative method.
        assert_eq!(block_store.max_height().unwrap_or_default(), 0);
    }

    #[test]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Sample the block.
        let block = snarkvm_ledger_test_helpers::sample_genesis_block(rng);
        let block_hash = block.hash();

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        // Ensure the block does not exist.
        let candidate = block_store.get_block(&block_hash).unwrap();
        assert_eq!(None, candidate);

        // Insert the block.
        block_store.insert(&block).unwrap();

        // Retrieve the block.
        let candidate = block_store.get_block(&block_hash).unwrap();
        assert_eq!(Some(block), candidate);

        // Remove the block.
        block_store.remove_last_n(1).unwrap();

        // Ensure the block does not exist.
        let candidate = block_store.get_block(&block_hash).unwrap();
        assert_eq!(None, candidate);
    }

    /// Ensures pruning stores drop authority data outside the retention window while preserving permanent block data.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_authority_retention_with_pruning() {
        const NUM_BLOCKS: u32 = 103;

        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(NUM_BLOCKS, rng);
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        for block in blocks.iter().take(101) {
            block_store.insert(block).unwrap();
        }

        let genesis_hash = blocks[0].hash();
        let expired_hash = blocks[1].hash();
        let boundary_hash = blocks[2].hash();

        // At height 100, height 1 is still inside the retained window.
        assert!(block_store.get_block_authority(&expired_hash).unwrap().is_some());

        // At height 101, height 1 expires while height 2 remains retained.
        block_store.insert(&blocks[101]).unwrap();
        assert_eq!(block_store.storage.authority_pruned_below().unwrap(), Some(2));

        assert!(block_store.get_block_authority(&genesis_hash).unwrap().is_some());
        assert!(block_store.get_block_authority(&expired_hash).unwrap().is_none());
        assert!(block_store.get_block_authority(&boundary_hash).unwrap().is_some());
        let error = block_store.get_block(&expired_hash).unwrap_err().to_string();
        assert!(error.contains("has been pruned"), "{error}");

        // A missing authority at or above the watermark is corruption, not pruning.
        block_store.storage.authority_map().remove(&boundary_hash).unwrap();
        let error = block_store.get_block(&boundary_hash).unwrap_err().to_string();
        assert!(!error.contains("pruned") && error.contains("Missing authority"), "{error}");

        // A missing component other than the authority is reported as itself, not as pruning.
        block_store.storage.ratifications_map().remove(&expired_hash).unwrap();
        let error = block_store.get_block(&expired_hash).unwrap_err().to_string();
        assert!(error.contains("Missing ratifications"), "{error}");

        // Permanent block data remains available.
        assert_eq!(block_store.get_block_hash(1).unwrap(), Some(expired_hash));
        assert_eq!(block_store.get_block_header(&expired_hash).unwrap(), Some(*blocks[1].header()));
        assert_eq!(block_store.get_block_transactions(&expired_hash).unwrap(), Some(blocks[1].transactions().clone()));
    }

    /// Ensures non-pruning stores retain authority data and continue reconstructing old blocks.
    #[cfg(not(feature = "prune-authority-data"))]
    #[test]
    fn test_authority_retention_without_pruning() {
        const NUM_BLOCKS: u32 = 103;

        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(NUM_BLOCKS, rng);
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        for block in blocks.iter().take(102) {
            block_store.insert(block).unwrap();
        }

        let expired_hash = blocks[1].hash();

        // At height 101, height 1 is still inside the retained window.
        assert!(block_store.get_block_authority(&expired_hash).unwrap().is_some());

        // Non-pruning builds retain height 1 after height 102 is inserted.
        block_store.insert(&blocks[102]).unwrap();

        assert!(block_store.get_block_authority(&expired_hash).unwrap().is_some());
        assert_eq!(block_store.get_block(&expired_hash).unwrap(), Some(blocks[1].clone()));
    }

    /// Ensures insert-time pruning leaves the expired block's certificate rows, that they read as
    /// absent, and that startup pruning removes them.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_certificate_pruning() {
        let rng = &mut TestRng::default();
        let (blocks, certificate_id) = sample_block_chain_with_quorum(103, rng);

        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        for block in blocks.iter().take(101) {
            block_store.insert(block).unwrap();
        }

        assert!(block_store.contains_certificate(&certificate_id).unwrap());
        assert!(block_store.get_batch_certificate(&certificate_id).unwrap().is_some());

        block_store.insert(&blocks[101]).unwrap();

        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_none());
        assert!(block_store.storage.certificate_map().contains_key_confirmed(&certificate_id).unwrap());
        assert!(!block_store.contains_certificate(&certificate_id).unwrap());
        assert!(!block_store.contains_block_for_certificate(&certificate_id).unwrap());
        assert!(block_store.get_batch_certificate(&certificate_id).unwrap().is_none());

        prune_expired_authorities(&block_store.storage, 101).unwrap();
        assert!(!block_store.storage.certificate_map().contains_key_confirmed(&certificate_id).unwrap());
    }

    /// Ensures a failed block insertion atomically rolls back authority and certificate pruning.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_insertion_failure_rolls_back_authority_pruning() {
        let rng = &mut TestRng::default();
        let (blocks, certificate_id) = sample_block_chain_with_quorum(103, rng);

        let storage = BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap();
        for block in blocks.iter().take(101) {
            let state_root = <CurrentNetwork as Network>::StateRoot::from(Field::from_u32(block.height()));
            storage.insert(state_root, block).unwrap();
        }

        let expired_hash = blocks[1].hash();
        let candidate = &blocks[101];
        let candidate_hash = candidate.hash();
        let candidate_state_root = <CurrentNetwork as Network>::StateRoot::from(Field::from_u32(candidate.height()));
        let result: Result<()> = atomic_batch_scope!(storage, {
            storage.insert(candidate_state_root, candidate)?;
            bail!("Injected failure after block insertion")
        });

        assert!(result.is_err());
        assert!(!storage.is_authority_pruned().unwrap());
        assert!(storage.authority_map().contains_key_confirmed(&expired_hash).unwrap());
        assert!(storage.certificate_map().contains_key_confirmed(&certificate_id).unwrap());
        assert!(!storage.id_map().contains_key_confirmed(&candidate.height()).unwrap());
        assert!(!storage.reverse_id_map().contains_key_confirmed(&candidate_hash).unwrap());
        assert!(!storage.authority_map().contains_key_confirmed(&candidate_hash).unwrap());
        assert!(!storage.reverse_state_root_map().contains_key_confirmed(&candidate_state_root).unwrap());
        storage.insert(candidate_state_root, candidate).unwrap();
        assert!(storage.is_authority_pruned().unwrap());
        assert!(!storage.authority_map().contains_key_confirmed(&expired_hash).unwrap());
        // The certificate row stays until the next startup, and reads as absent.
        assert!(storage.certificate_map().contains_key_confirmed(&certificate_id).unwrap());
        assert!(!storage.contains_block_for_certificate(&certificate_id).unwrap());
        assert!(storage.id_map().contains_key_confirmed(&candidate.height()).unwrap());
    }

    /// Ensures a rolled-back insertion also rolls back the pruning marker in RocksDB.
    #[cfg(all(feature = "rocks", feature = "prune-authority-data"))]
    #[test]
    fn test_insertion_failure_rolls_back_pruning_marker() {
        let rng = &mut TestRng::default();
        let (blocks, _) = sample_block_chain_with_quorum(103, rng);
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let storage = BlockDB::<CurrentNetwork>::open(StorageMode::new_test(Some(temp_dir))).unwrap();
        let state_root = |block: &Block<CurrentNetwork>| {
            <CurrentNetwork as Network>::StateRoot::from(Field::from_u32(block.height()))
        };
        for block in blocks.iter().take(101) {
            storage.insert(state_root(block), block).unwrap();
        }

        let candidate = &blocks[101];
        let result: Result<()> = atomic_batch_scope!(storage, {
            storage.insert(state_root(candidate), candidate)?;
            bail!("Injected failure after block insertion")
        });
        assert!(result.is_err());
        assert!(!storage.is_authority_pruned().unwrap());

        storage.insert(state_root(candidate), candidate).unwrap();
        assert!(storage.is_authority_pruned().unwrap());
    }

    /// Ensures a discarded paused batch, as the VM discards a failed block, also discards the pruning marker.
    #[cfg(all(feature = "rocks", feature = "prune-authority-data"))]
    #[test]
    fn test_discarded_paused_batch_discards_pruning_marker() {
        let rng = &mut TestRng::default();
        let (blocks, _) = sample_block_chain_with_quorum(103, rng);
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let block_store =
            BlockStore::<CurrentNetwork, BlockDB<_>>::open(StorageMode::new_test(Some(temp_dir))).unwrap();
        for block in blocks.iter().take(101) {
            block_store.insert(block).unwrap();
        }

        // The VM pauses atomic writes around insertion and finalization, and discards both on failure.
        block_store.pause_atomic_writes().unwrap();
        block_store.insert(&blocks[101]).unwrap();
        block_store.abort_atomic();
        block_store.unpause_atomic_writes::<true>().unwrap();
        assert!(!block_store.storage.is_authority_pruned().unwrap());
        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_some());
    }

    /// Ensures height pruning removes an authority without touching its certificate indexes, and
    /// skips heights without a hash.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_prune_authority_heights_leaves_certificate_indexes() {
        let rng = &mut TestRng::default();
        let authority = snarkvm_ledger_authority::test_helpers::sample_quorum_authority(rng);
        let certificate_id = certificate_ids(&authority)[0];
        let storage = BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap();
        let block_hash: <CurrentNetwork as Network>::BlockHash = Field::<CurrentNetwork>::rand(rng).into();
        let block_height = 1;

        storage.id_map().insert(block_height, block_hash).unwrap();
        storage.authority_map().insert(block_hash, authority).unwrap();
        storage.certificate_map().insert(certificate_id, (block_height, 2)).unwrap();

        atomic_batch_scope!(storage, { prune_authority_heights(&storage, block_height..block_height + 1) }).unwrap();
        assert!(!storage.authority_map().contains_key_confirmed(&block_hash).unwrap());
        assert!(storage.certificate_map().contains_key_confirmed(&certificate_id).unwrap());
        assert_eq!(storage.authority_pruned_below().unwrap(), Some(block_height + 1));

        // Heights without a hash are skipped.
        atomic_batch_scope!(storage, { prune_authority_heights(&storage, 1..4) }).unwrap();
        assert_eq!(storage.authority_pruned_below().unwrap(), Some(4));
    }

    /// Removes the authority-pruning watermark, which the typed setter cannot move backwards.
    #[cfg(feature = "prune-authority-data")]
    fn clear_authority_pruned<B: BlockStorage<CurrentNetwork>>(storage: &B) {
        storage.block_metadata_map().remove(&BlockMetadataKey::AuthorityPruned).unwrap();
    }

    /// Fills the maps of `num_heights` blocks with beacon authorities, indexed by height.
    #[cfg(feature = "prune-authority-data")]
    fn fill_authorities<B: BlockStorage<CurrentNetwork>>(storage: &B, num_heights: u32) {
        let rng = &mut TestRng::default();
        let authority = sample_block_chain(1, rng)[0].authority().clone();
        atomic_batch_scope!(storage, {
            for height in 0..num_heights {
                storage.id_map().insert(height, hash_at(height))?;
                storage.authority_map().insert(hash_at(height), authority.clone())?;
            }
            Ok(())
        })
        .unwrap();
    }

    #[cfg(feature = "prune-authority-data")]
    fn check_startup_pruning_closes_multi_chunk_gap<B: BlockStorage<CurrentNetwork>>(storage: B) {
        let latest_height = 3 * AUTHORITY_PRUNING_CHUNK_HEIGHTS + AUTHORITY_RETENTION_BLOCKS + 1;
        fill_authorities(&storage, latest_height + 1);
        // One expired block carries a quorum authority with indexed certificates.
        let quorum_height = 3 * AUTHORITY_PRUNING_CHUNK_HEIGHTS;
        let quorum = snarkvm_ledger_authority::test_helpers::sample_quorum_authority(&mut TestRng::default());
        let quorum_certificates = certificate_ids(&quorum);
        storage.authority_map().insert(hash_at(quorum_height), quorum).unwrap();
        for certificate_id in &quorum_certificates {
            storage.certificate_map().insert(*certificate_id, (quorum_height, 1)).unwrap();
        }

        // More expired indexes than one certificate batch holds, so the pass flushes mid-iteration.
        let expired_indexes: Vec<Field<CurrentNetwork>> = (0..3 * u32::try_from(CERTIFICATE_PRUNING_BATCH_SIZE)
            .unwrap())
            .map(|i| Field::from_u32(1_000_000 + i))
            .collect();
        for (i, certificate_id) in (1..).zip(&expired_indexes) {
            storage.certificate_map().insert(*certificate_id, (i, 1)).unwrap();
        }
        // Indexes of a retained block and of genesis are kept.
        let retained_index = Field::from_u32(u32::MAX);
        storage.certificate_map().insert(retained_index, (latest_height, 1)).unwrap();
        let genesis_index = Field::from_u32(u32::MAX - 1);
        storage.certificate_map().insert(genesis_index, (0, 1)).unwrap();

        assert!(!storage.is_authority_pruned().unwrap());
        prune_expired_authorities(&storage, latest_height).unwrap();
        for certificate_id in quorum_certificates.iter().chain(&expired_indexes) {
            assert!(!storage.certificate_map().contains_key_confirmed(certificate_id).unwrap());
        }
        assert!(storage.certificate_map().contains_key_confirmed(&retained_index).unwrap());
        assert!(storage.certificate_map().contains_key_confirmed(&genesis_index).unwrap());

        let floor = oldest_retained_authority_height(latest_height);
        assert_eq!(storage.authority_pruned_below().unwrap(), Some(floor));
        assert!(storage.authority_map().contains_key_confirmed(&hash_at(0)).unwrap());
        assert!(!storage.authority_map().contains_key_confirmed(&hash_at(floor - 1)).unwrap());
        assert!(storage.authority_map().contains_key_confirmed(&hash_at(floor)).unwrap());
        assert_eq!(storage.authority_map().len_confirmed(), AUTHORITY_RETENTION_BLOCKS as usize + 1);

        // A second run finds an empty range.
        prune_expired_authorities(&storage, latest_height).unwrap();
        assert_eq!(storage.authority_pruned_below().unwrap(), Some(floor));
        assert_eq!(storage.authority_map().len_confirmed(), AUTHORITY_RETENTION_BLOCKS as usize + 1);
    }

    /// Checks that an interrupted startup resumes from the watermark instead of rescanning.
    #[cfg(feature = "prune-authority-data")]
    fn check_startup_pruning_resumes_from_watermark<B: BlockStorage<CurrentNetwork>>(storage: B) {
        let latest_height = AUTHORITY_PRUNING_CHUNK_HEIGHTS + AUTHORITY_RETENTION_BLOCKS + 1;
        fill_authorities(&storage, latest_height + 1);

        // A previous run committed the chunks below `resume` and stopped.
        let resume = 10;
        atomic_batch_scope!(storage, { storage.set_authority_pruned_below(resume) }).unwrap();
        prune_expired_authorities(&storage, latest_height).unwrap();

        let floor = oldest_retained_authority_height(latest_height);
        assert_eq!(storage.authority_pruned_below().unwrap(), Some(floor));
        // Heights below the watermark are not revisited.
        assert!(storage.authority_map().contains_key_confirmed(&hash_at(resume - 1)).unwrap());
        assert!(!storage.authority_map().contains_key_confirmed(&hash_at(resume)).unwrap());
        assert!(!storage.authority_map().contains_key_confirmed(&hash_at(floor - 1)).unwrap());
    }

    /// Ensures a certificate row of a pruned block reads as absent, while a missing authority at or
    /// above the watermark is still reported as corruption.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_certificate_reader_errors_only_above_watermark() {
        let storage = BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap();
        atomic_batch_scope!(storage, { storage.set_authority_pruned_below(3) }).unwrap();
        for (height, certificate_id) in [(2, Field::from_u32(2)), (3, Field::from_u32(3))] {
            storage.id_map().insert(height, hash_at(height)).unwrap();
            storage.certificate_map().insert(certificate_id, (height, 1)).unwrap();
        }

        // Height 2 is below the watermark: its authority was pruned.
        assert!(storage.get_batch_certificate(&Field::from_u32(2)).unwrap().is_none());
        assert!(!storage.contains_block_for_certificate(&Field::from_u32(2)).unwrap());
        // Height 3 is retained, so its missing authority is corruption.
        let error = storage.get_batch_certificate(&Field::from_u32(3)).unwrap_err().to_string();
        assert!(error.contains("authority"), "{error}");
    }

    /// Checks that the certificate pass decides to compact after deleting at least the threshold, and
    /// not below.
    #[cfg(feature = "prune-authority-data")]
    fn check_certificate_pass_compacts_at_least_threshold<B: BlockStorage<CurrentNetwork>>(storage: B) {
        let insert_rows = |offset: u32, count: usize| {
            for i in 0..u32::try_from(count).unwrap() {
                storage.certificate_map().insert(Field::from_u32(offset + i), (1, 1)).unwrap();
            }
        };
        atomic_batch_scope!(storage, { storage.set_authority_pruned_below(2) }).unwrap();

        insert_rows(0, AUTHORITY_PRUNING_COMPACTION_THRESHOLD - 1);
        assert!(!prune_certificate_indexes(&storage, 2).unwrap());

        insert_rows(1_000, AUTHORITY_PRUNING_COMPACTION_THRESHOLD);
        assert!(prune_certificate_indexes(&storage, 2).unwrap());
        assert_eq!(storage.certificate_map().len_confirmed(), 0);
    }

    /// Ensures the certificate pass decides to compact only at the threshold with in-memory storage,
    /// where compaction itself is a no-op.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_certificate_pass_compacts_at_least_threshold() {
        check_certificate_pass_compacts_at_least_threshold(
            BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap(),
        );
    }

    /// Ensures the certificate pass compacts only at the threshold with RocksDB storage.
    #[cfg(all(feature = "prune-authority-data", feature = "rocks"))]
    #[test]
    fn test_certificate_pass_compacts_at_least_threshold_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        check_certificate_pass_compacts_at_least_threshold(
            BlockDB::<CurrentNetwork>::open(StorageMode::new_test(Some(temp_dir))).unwrap(),
        );
    }

    /// Ensures an interrupted startup resumes from the watermark with in-memory storage.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_startup_pruning_resumes_from_watermark() {
        check_startup_pruning_resumes_from_watermark(
            BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap(),
        );
    }

    /// Ensures an interrupted startup resumes from the watermark with RocksDB storage.
    #[cfg(all(feature = "prune-authority-data", feature = "rocks"))]
    #[test]
    fn test_startup_pruning_resumes_from_watermark_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        check_startup_pruning_resumes_from_watermark(
            BlockDB::<CurrentNetwork>::open(StorageMode::new_test(Some(temp_dir))).unwrap(),
        );
    }

    /// Ensures a failed chunk rolls back its deletions and leaves the watermark unchanged.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_failed_pruning_chunk_rolls_back() {
        let storage = BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap();
        fill_authorities(&storage, 10);

        let result: Result<()> = atomic_batch_scope!(storage, {
            prune_authority_heights(&storage, 1..4)?;
            bail!("Injected failure after pruning")
        });
        assert!(result.is_err());
        assert_eq!(storage.authority_pruned_below().unwrap(), None);
        assert!(storage.authority_map().contains_key_confirmed(&hash_at(1)).unwrap());
    }

    /// Ensures an insert prunes only when the watermark is caught up, and leaves a gap to startup.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_insert_pruning_skips_when_behind() {
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(104, rng);
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        for block in blocks.iter().take(103) {
            block_store.insert(block).unwrap();
        }
        assert_eq!(block_store.storage.authority_pruned_below().unwrap(), Some(3));

        // Emulate a startup catch-up that stopped part-way: the watermark lags the expiring height.
        let storage = &block_store.storage;
        clear_authority_pruned(storage);
        atomic_batch_scope!(storage, { storage.set_authority_pruned_below(2) }).unwrap();
        block_store.insert(&blocks[103]).unwrap();
        assert!(block_store.get_block_authority(&blocks[3].hash()).unwrap().is_some());
        assert_eq!(block_store.storage.authority_pruned_below().unwrap(), Some(2));
    }

    /// Ensures an empty marker, written before the watermark existed, reads as a watermark of 1.
    #[test]
    fn test_legacy_empty_marker_decodes_as_one() {
        let storage = BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap();
        storage.block_metadata_map().insert(BlockMetadataKey::AuthorityPruned, Vec::new()).unwrap();
        assert_eq!(storage.authority_pruned_below().unwrap(), Some(1));
        assert!(storage.is_authority_pruned().unwrap());
    }

    /// Ensures startup pruning walks heights through `id_map` and leaves authorities it does not index.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_startup_pruning_keeps_unindexed_authorities() {
        let storage = BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap();
        let latest_height = AUTHORITY_RETENTION_BLOCKS + 10;
        fill_authorities(&storage, latest_height + 1);
        // An authority whose hash no height points to.
        let orphan_hash = hash_at(latest_height + 1);
        let authority = storage.authority_map().get_confirmed(&hash_at(1)).unwrap().unwrap().into_owned();
        storage.authority_map().insert(orphan_hash, authority).unwrap();

        prune_expired_authorities(&storage, latest_height).unwrap();

        assert!(!storage.authority_map().contains_key_confirmed(&hash_at(1)).unwrap());
        assert!(storage.authority_map().contains_key_confirmed(&orphan_hash).unwrap());
    }

    /// Ensures the pruning marker is written the first time an insertion prunes an authority, and not before.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_pruning_marker_written_on_first_prune() {
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(102, rng);
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        // Heights 0 to 100 retain every authority.
        for block in blocks.iter().take(101) {
            block_store.insert(block).unwrap();
        }
        assert!(!block_store.storage.is_authority_pruned().unwrap());

        // Height 101 prunes height 1.
        block_store.insert(&blocks[101]).unwrap();
        assert!(block_store.storage.is_authority_pruned().unwrap());
    }

    /// Ensures startup pruning with nothing to prune leaves the marker unset.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_pruning_marker_not_written_without_pruning() {
        let rng = &mut TestRng::default();
        let blocks = sample_block_chain(50, rng);
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        for block in &blocks {
            block_store.insert(block).unwrap();
        }
        prune_expired_authorities(&block_store.storage, 49).unwrap();
        assert!(!block_store.storage.is_authority_pruned().unwrap());
    }

    /// Ensures a build without `prune-authority-data` refuses a store that carries the pruning marker.
    #[cfg(all(feature = "rocks", not(feature = "prune-authority-data")))]
    #[test]
    fn test_open_refuses_pruned_storage() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let storage_mode = StorageMode::new_test(Some(temp_dir));
        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode.clone()).unwrap();
        let storage = &block_store.storage;
        atomic_batch_scope!(storage, { storage.set_authority_pruned_below(2) }).unwrap();
        drop(block_store);

        let error = match BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode) {
            Ok(_) => panic!("A build without `prune-authority-data` opened a pruned store"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("prune-authority-data"), "{error}");
    }

    /// Ensures startup pruning closes a multi-chunk gap and is idempotent with in-memory storage.
    #[cfg(feature = "prune-authority-data")]
    #[test]
    fn test_startup_pruning_closes_multi_chunk_gap() {
        let storage = BlockMemory::<CurrentNetwork>::open(StorageMode::new_test(None)).unwrap();
        check_startup_pruning_closes_multi_chunk_gap(storage);
    }

    /// Ensures startup pruning closes a multi-chunk gap and is idempotent with RocksDB storage.
    #[cfg(all(feature = "prune-authority-data", feature = "rocks"))]
    #[test]
    fn test_startup_pruning_closes_multi_chunk_gap_rocksdb() {
        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let storage = BlockDB::<CurrentNetwork>::open(StorageMode::new_test(Some(temp_dir))).unwrap();
        check_startup_pruning_closes_multi_chunk_gap(storage);
    }

    /// Ensures opening a pruning RocksDB store removes stale authority and certificate data.
    #[cfg(all(feature = "rocks", feature = "prune-authority-data"))]
    #[test]
    fn test_authority_pruning_on_startup_enabled() {
        let rng = &mut TestRng::default();
        let (blocks, certificate_id) = sample_block_chain_with_quorum(103, rng);

        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let storage_mode = StorageMode::new_test(Some(temp_dir));
        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode.clone()).unwrap();
        for block in &blocks {
            block_store.insert(block).unwrap();
        }

        // Insert-time pruning removed block 1's authority. Its certificate row lingers until the next
        // startup, and reads as absent, not as an error.
        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_none());
        assert!(block_store.storage.certificate_map().contains_key_confirmed(&certificate_id).unwrap());
        assert!(!block_store.contains_certificate(&certificate_id).unwrap());
        assert!(!block_store.contains_block_for_certificate(&certificate_id).unwrap());
        assert!(block_store.get_batch_certificate(&certificate_id).unwrap().is_none());

        // Restore stale authority data and clear the watermark to emulate a database created before pruning.
        block_store.storage.authority_map().insert(blocks[1].hash(), blocks[1].authority().clone()).unwrap();
        block_store.storage.certificate_map().insert(certificate_id, (1, 2)).unwrap();
        clear_authority_pruned(&block_store.storage);
        drop(block_store);

        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode.clone()).unwrap();
        assert!(block_store.storage.is_authority_pruned().unwrap());
        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_none());
        assert!(!block_store.contains_certificate(&certificate_id).unwrap());
        assert!(!block_store.storage.certificate_map().contains_key_confirmed(&certificate_id).unwrap());
        drop(block_store);

        // Reopening after cleanup is idempotent.
        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode).unwrap();
        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_none());
        assert!(!block_store.contains_certificate(&certificate_id).unwrap());
    }

    /// Ensures opening a non-pruning RocksDB store preserves authority and certificate data.
    #[cfg(all(feature = "rocks", not(feature = "prune-authority-data")))]
    #[test]
    fn test_authority_pruning_on_startup_disabled() {
        let rng = &mut TestRng::default();
        let (blocks, certificate_id) = sample_block_chain_with_quorum(103, rng);

        let temp_dir = Arc::new(tempfile::tempdir().unwrap());
        let storage_mode = StorageMode::new_test(Some(temp_dir));
        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode.clone()).unwrap();
        for block in &blocks {
            block_store.insert(block).unwrap();
        }

        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_some());
        assert!(block_store.contains_certificate(&certificate_id).unwrap());
        drop(block_store);

        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode.clone()).unwrap();
        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_some());
        assert!(block_store.contains_certificate(&certificate_id).unwrap());
        drop(block_store);

        // Reopening without pruning remains idempotent.
        let block_store = BlockStore::<CurrentNetwork, BlockDB<_>>::open(storage_mode).unwrap();
        assert!(block_store.get_block_authority(&blocks[1].hash()).unwrap().is_some());
        assert!(block_store.contains_certificate(&certificate_id).unwrap());
    }

    /// Ensures state paths remain available after the corresponding block authority is removed.
    #[test]
    fn test_state_path_does_not_require_authority() {
        let rng = &mut TestRng::default();
        let block = snarkvm_ledger_test_helpers::sample_genesis_block(rng);
        let block_hash = block.hash();
        let commitment = *block.transactions().commitments().next().unwrap();
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        block_store.insert(&block).unwrap();
        let expected = block_store.get_state_path_for_commitment(&commitment).unwrap();

        block_store.storage.authority_map().remove(&block_hash).unwrap();
        assert!(block_store.get_block(&block_hash).is_err());
        assert_eq!(block_store.get_state_path_for_commitment(&commitment).unwrap(), expected);
    }

    #[test]
    fn test_find_block_hash() {
        let rng = &mut TestRng::default();

        // Sample the block.
        let block = snarkvm_ledger_test_helpers::sample_genesis_block(rng);
        let block_hash = block.hash();
        assert!(block.transactions().num_accepted() > 0, "This test must be run with at least one transaction.");

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        // Ensure the block does not exist.
        let candidate = block_store.get_block(&block_hash).unwrap();
        assert_eq!(None, candidate);

        for transaction_id in block.transaction_ids() {
            // Ensure the block hash is not found.
            let candidate = block_store.find_block_hash(transaction_id).unwrap();
            assert_eq!(None, candidate);
        }

        // Insert the block.
        block_store.insert(&block).unwrap();

        for transaction_id in block.transaction_ids() {
            // Find the block hash.
            let candidate = block_store.find_block_hash(transaction_id).unwrap();
            assert_eq!(Some(block_hash), candidate);
        }

        // Remove the block.
        block_store.remove_last_n(1).unwrap();

        for transaction_id in block.transaction_ids() {
            // Ensure the block hash is not found.
            let candidate = block_store.find_block_hash(transaction_id).unwrap();
            assert_eq!(None, candidate);
        }
    }

    #[test]
    fn test_get_transaction() {
        let rng = &mut TestRng::default();

        // Sample the block.
        let block = snarkvm_ledger_test_helpers::sample_genesis_block(rng);
        assert!(block.transactions().num_accepted() > 0, "This test must be run with at least one transaction.");

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Insert the block.
        block_store.insert(&block).unwrap();

        for confirmed in block.transactions().clone().into_iter() {
            // Retrieve the transaction.
            assert_eq!(block_store.get_transaction(&confirmed.id()).unwrap().unwrap(), confirmed.into_transaction());
        }
    }

    #[test]
    fn test_get_confirmed_transaction() {
        let rng = &mut TestRng::default();

        // Sample the block.
        let block = snarkvm_ledger_test_helpers::sample_genesis_block(rng);
        assert!(block.transactions().num_accepted() > 0, "This test must be run with at least one transaction.");

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Insert the block.
        block_store.insert(&block).unwrap();

        for confirmed in block.transactions().clone().into_iter() {
            // Retrieve the transaction.
            assert_eq!(block_store.get_confirmed_transaction(&confirmed.id()).unwrap().unwrap(), confirmed);
        }
    }

    #[test]
    fn test_get_unconfirmed_transaction() {
        let rng = &mut TestRng::default();

        // Sample the block.
        let block = snarkvm_ledger_test_helpers::sample_genesis_block(rng);
        assert!(block.transactions().num_accepted() > 0, "This test must be run with at least one transaction.");

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Insert the block.
        block_store.insert(&block).unwrap();

        for confirmed in block.transactions().clone().into_iter() {
            // Retrieve the transaction.
            assert_eq!(
                block_store.get_unconfirmed_transaction(&confirmed.id()).unwrap().unwrap(),
                confirmed.to_unconfirmed_transaction().unwrap()
            );
        }
    }

    /// Test that we can look up a rejected transaction using the fee transaction ID.
    #[test]
    fn test_rejected_transaction() {
        let rng = &mut TestRng::default();

        let private_key = snarkvm_ledger_test_helpers::sample_genesis_private_key(rng);

        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        let fee = snarkvm_ledger_test_helpers::sample_fee_public_transaction(rng);
        let rejected = snarkvm_ledger_test_helpers::sample_rejected_execution(false, rng);
        let transactions =
            Transactions::from_iter([
                ConfirmedTransaction::rejected_execute(0, fee.clone(), rejected.clone(), vec![]).unwrap()
            ]);
        let ratifications = Ratifications::try_from(vec![]).unwrap();

        let header = Header::genesis(&ratifications, &transactions, vec![]).unwrap();
        let previous_hash = <CurrentNetwork as Network>::BlockHash::default();

        let fee_id = fee.id();
        let unconfirmed_id = rejected.to_unconfirmed_id(&fee.fee_transition()).unwrap().into();

        // Construct the block.
        let block = Block::new_beacon(
            &private_key,
            previous_hash,
            header,
            ratifications,
            None.into(),
            vec![],
            transactions,
            vec![unconfirmed_id],
            rng,
        )
        .unwrap();

        block_store.insert(&block).unwrap();

        let txn1 = block_store.get_unconfirmed_transaction(&unconfirmed_id).unwrap().unwrap();
        let txn2 = block_store.get_unconfirmed_transaction(&fee_id).unwrap().unwrap();

        // Ensure the execute transaction is returned in both cases.
        assert!(matches!(txn2, Transaction::Execute(..)));
        assert_eq!(txn1, txn2);

        let txn3 = block_store.get_transaction(&unconfirmed_id).unwrap().unwrap();
        let txn4 = block_store.get_transaction(&fee_id).unwrap().unwrap();

        // For get_transaction the Fee must be returned in both cases.
        assert!(matches!(txn3, Transaction::Fee(..)));
        assert_ne!(txn1, txn3);
        assert_eq!(txn3, txn4);
    }

    /// The stored genesis state root is the fixed value when `dev_genesis_state_root` is enabled.
    #[cfg(feature = "dev_genesis_state_root")]
    #[test]
    fn test_dev_genesis_state_root() {
        let rng = &mut TestRng::default();

        let private_key = snarkvm_ledger_test_helpers::sample_genesis_private_key(rng);
        let transactions = Transactions::from_iter(Vec::<ConfirmedTransaction<CurrentNetwork>>::new());
        let ratifications = Ratifications::try_from(vec![]).unwrap();
        let header = Header::genesis(&ratifications, &transactions, vec![]).unwrap();
        let previous_hash = <CurrentNetwork as Network>::BlockHash::default();

        // Construct the genesis block.
        let block = Block::new_beacon(
            &private_key,
            previous_hash,
            header,
            ratifications,
            None.into(),
            vec![],
            transactions,
            vec![],
            rng,
        )
        .unwrap();

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Insert the block.
        block_store.insert(&block).unwrap();

        // The stored genesis state root is the fixed value.
        let state_root = block_store.get_state_root(0).unwrap().unwrap().to_string();
        assert_eq!(state_root, "sr1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqquwxeur");
    }

    /// A genesis commitment checks the passed block tree's root.
    ///
    /// Height 0 stores `Field::one()`. That substitution applies only while the passed
    /// block tree contains genesis alone. A taller tree must have its own root stored.
    #[cfg(feature = "dev_genesis_state_root")]
    #[test]
    fn test_genesis_commitment_checks_passed_block_tree_root() {
        let rng = &mut TestRng::default();

        let block = snarkvm_ledger_test_helpers::sample_genesis_block(rng);
        let commitment = block.transactions().commitments().next().unwrap();

        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        block_store.insert(&block).unwrap();

        let storage = &block_store.storage;
        let genesis_tree = storage.create_block_tree().unwrap();

        // The store's genesis tree is accepted. Height 0 stores `Field::one()`.
        storage.get_state_path_for_commitment(commitment, &genesis_tree).unwrap();

        // A tree that is not the stored genesis tree is rejected, even for a genesis commitment.
        let mut extra_leaf = block.hash().to_bits_le();
        extra_leaf[0] = !extra_leaf[0];
        let foreign_tree = genesis_tree.prepare_append(&[extra_leaf]).unwrap();
        let error = storage.get_state_path_for_commitment(commitment, &foreign_tree).unwrap_err();
        assert!(error.to_string().contains("is missing in storage"), "{error:?}");
    }

    #[test]
    fn test_missing_block_in_tree_error_includes_block_tree_path() {
        let error = missing_block_in_tree_error(42, Some(Path::new("/tmp/snarkvm/ledger/block_tree")));

        assert!(error.contains("Block 42 exists in tree but not in storage"));
        assert!(error.contains("wrong block tree cache file"));
        assert!(error.contains("/tmp/snarkvm/ledger/block_tree"));
    }
}
