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

use snarkvm_ledger_committee::{MAX_DELEGATORS, MIN_DELEGATOR_STAKE, MIN_VALIDATOR_SELF_STAKE};
use snarkvm_ledger_puzzle::SolutionID;

use snarkvm_synthesizer_error::{
    FinalizeError,
    IndexedFinalizeError,
    IntoIndexedFinalize,
    VmCheckBlockContentError,
    indexed_finalize_bail,
};
use snarkvm_utilities::{cfg_sort_by_cached_key, defer, dev_eprintln};

/// Uniqueness tracking accumulated while assembling a candidate block's transactions.
struct CandidateTransactionDetails<N: Network> {
    /// The IDs of the transitions in this block.
    transition_ids: IndexSet<N::TransitionID>,
    /// The IDs of the transition inputs in this block.
    input_ids: IndexSet<Field<N>>,
    /// The IDs of the transition outputs in this block.
    output_ids: IndexSet<Field<N>>,
    /// The serial numbers spent by record inputs in this block.
    serial_numbers: IndexSet<Field<N>>,
    /// The tags from record inputs in this block.
    tags: IndexSet<Field<N>>,
    /// The record output commitments in this block.
    commitments: IndexSet<Field<N>>,
    /// The record output nonces in this block.
    nonces: IndexSet<Group<N>>,
    /// The transition public keys (`tpk`) in this block.
    tpks: IndexSet<Group<N>>,
    /// The transition commitments (`tcm`) in this block.
    tcms: IndexSet<Field<N>>,
    /// The public fee payers of the deployments in this block.
    deployment_payers: IndexSet<Address<N>>,
    /// The IDs of the programs deployed or upgraded in this block.
    deployments: IndexSet<ProgramID<N>>,
    /// The combined density (variables and constraints) of the deployments in this block.
    block_combined_density: u64,
}

impl<N: Network> Default for CandidateTransactionDetails<N> {
    fn default() -> Self {
        Self {
            transition_ids: IndexSet::new(),
            input_ids: IndexSet::new(),
            output_ids: IndexSet::new(),
            serial_numbers: IndexSet::new(),
            tags: IndexSet::new(),
            commitments: IndexSet::new(),
            nonces: IndexSet::new(),
            tpks: IndexSet::new(),
            tcms: IndexSet::new(),
            deployment_payers: IndexSet::new(),
            deployments: IndexSet::new(),
            block_combined_density: 0,
        }
    }
}

impl<N: Network> CandidateTransactionDetails<N> {
    /// Records a transaction: extends uniqueness sets and updates counters.
    fn record_transaction(&mut self, transaction: &Transaction<N>) {
        self.transition_ids.extend(transaction.transition_ids());
        self.input_ids.extend(transaction.input_ids());
        self.output_ids.extend(transaction.output_ids());
        self.serial_numbers.extend(transaction.serial_numbers().copied());
        self.tags.extend(transaction.tags().copied());
        self.commitments.extend(transaction.commitments().copied());
        self.nonces.extend(transaction.nonces().copied());
        self.tpks.extend(transaction.transition_public_keys());
        self.tcms.extend(transaction.transition_commitments().copied());
        if let Transaction::Deploy(_, _, _, deployment, fee) = transaction {
            fee.payer().map(|payer| self.deployment_payers.insert(payer));
            self.deployments.insert(*deployment.program_id());
            self.block_combined_density = self.block_combined_density.saturating_add(deployment.combined_density());
        }
    }
}

type AbortReason = String;
type ComputeSpend = u64;
/// An intermediary speculation artifact indicating whether a transaction should
/// be aborted or finalized with a certain compute_spend.
enum ShouldAbortResult {
    Abort(AbortReason),
    Finalize(ComputeSpend),
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Speculates on the given list of transactions in the VM.
    /// This function aborts all transactions that are not are well-formed or unique.
    ///
    ///
    /// Returns the confirmed transactions, aborted transaction IDs,
    /// and finalize operations from pre-ratify and post-ratify.
    ///
    /// # Note
    /// This method is used to create a new block (including the genesis block).
    ///   - If `coinbase_reward = None`, then the `ratifications` will not be modified.
    ///   - If `coinbase_reward = Some(coinbase_reward)`, then the method will append a
    ///     `Ratify::BlockReward(block_reward)` and `Ratify::PuzzleReward(puzzle_reward)`
    ///     to the front of the `ratifications` list.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn speculate<'a, R: Rng + CryptoRng>(
        &self,
        state: FinalizeGlobalState,
        time_since_last_block: i64, // TODO (raychu86): Consider moving this value into `FinalizeGlobalState`.
        coinbase_reward: Option<u64>,
        candidate_ratifications: Vec<Ratify<N>>,
        candidate_solutions: &Solutions<N>,
        candidate_transactions: impl ExactSizeIterator<Item = &'a Transaction<N>>,
        rng: &mut R,
    ) -> Result<(Ratifications<N>, Transactions<N>, Vec<N::TransactionID>, Vec<FinalizeOperation<N>>)> {
        let timer = timer!("VM::speculate");

        // Collect the candidate transactions into a vector.
        let candidate_transactions: Vec<_> = candidate_transactions.collect::<Vec<_>>();
        let candidate_transaction_ids: Vec<_> = candidate_transactions.iter().map(|tx| tx.id()).collect();

        // Determine if the vm is currently processing the genesis block.
        let is_genesis =
            self.block_store().find_block_height_from_state_root(self.block_store().current_state_root())?.is_none();
        // If the transactions are not part of the genesis block, ensure each transaction is well-formed and unique. Abort any transactions that are not.
        let (verified_transactions, verification_aborted_transactions) = match is_genesis {
            // If the current state root does not exist in the block store, then the genesis block has not been introduced yet.
            true => (candidate_transactions, vec![]),
            // Verify transactions for all non-genesis cases.
            false => self.prepare_for_speculate(&candidate_transactions, state, rng)?,
        };

        // Performs a **dry-run** over the list of ratifications, solutions, and transactions.
        let (ratifications, confirmed_transactions, speculation_aborted_transactions, ratified_finalize_operations) =
            self.atomic_speculate(
                state,
                time_since_last_block,
                coinbase_reward,
                candidate_ratifications,
                candidate_solutions.clone(),
                verified_transactions.into_iter().cloned().collect(),
            )?;

        // Get the aborted transaction ids.
        let verification_aborted_transaction_ids = verification_aborted_transactions.iter().map(|(tx, e)| (tx.id(), e));
        let speculation_aborted_transaction_ids = speculation_aborted_transactions.iter().map(|(tx, e)| (tx.id(), e));
        let unordered_aborted_transaction_ids: IndexMap<N::TransactionID, &String> =
            verification_aborted_transaction_ids.chain(speculation_aborted_transaction_ids).collect();

        // Filter and order the aborted transaction ids according to candidate_transactions
        let aborted_transaction_ids: Vec<_> = candidate_transaction_ids
            .into_iter()
            .filter_map(|tx_id| {
                unordered_aborted_transaction_ids.get(&tx_id).map(|error| {
                    warn!("Speculation safely aborted a transaction - {error} ({tx_id})");
                    dev_eprintln!("Speculation safely aborted a transaction - {error} ({tx_id})");
                    tx_id
                })
            })
            .collect();

        finish!(timer, "Finished dry-run of the transactions");

        // Return the ratifications, confirmed transactions, aborted transaction IDs, and ratified finalize operations.
        Ok((
            ratifications,
            confirmed_transactions.into_iter().collect(),
            aborted_transaction_ids,
            ratified_finalize_operations,
        ))
    }

    /// Checks the speculation on the given transactions in the VM.
    /// This function also ensure that the given transactions are well-formed and unique.
    ///
    /// Returns the finalize operations from pre-ratify and post-ratify.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    #[inline]
    pub fn check_speculate<R: Rng + CryptoRng>(
        &self,
        state: FinalizeGlobalState,
        time_since_last_block: i64,
        ratifications: &Ratifications<N>,
        solutions: &Solutions<N>,
        transactions: &Transactions<N>,
        rng: &mut R,
    ) -> Result<Vec<FinalizeOperation<N>>> {
        let timer = timer!("VM::check_speculate");

        // Retrieve the transactions and their rejected IDs.
        let transactions_and_rejected_ids = cfg_iter!(transactions)
            .map(|transaction| transaction.to_rejected_id().map(|rejected_id| (transaction.deref(), rejected_id)))
            .collect::<Result<Vec<_>>>()?;
        // Ensure each transaction is well-formed and unique.
        // NOTE: We perform the transaction checks here prior to `atomic_speculate` because we must
        // ensure that the `Fee` transactions are valid. We can't unify the transaction checks in `atomic_speculate`
        // because we run speculation on the unconfirmed variant of the transactions.
        self.check_transactions(&transactions_and_rejected_ids, rng)?;

        // Reconstruct the candidate ratifications to verify the speculation.
        let candidate_ratifications = ratifications.iter().cloned().collect::<Vec<_>>();
        // Reconstruct the unconfirmed transactions to verify the speculation.
        let candidate_transactions =
            transactions.iter().map(|confirmed| confirmed.to_unconfirmed_transaction()).collect::<Result<Vec<_>>>()?;

        // Performs a **dry-run** over the list of ratifications, solutions, and transactions.
        let (speculate_ratifications, confirmed_transactions, aborted_transactions, ratified_finalize_operations) =
            self.atomic_speculate(
                state,
                time_since_last_block,
                None,
                candidate_ratifications,
                solutions.clone(),
                candidate_transactions,
            )?;

        // Ensure the ratifications after speculation match.
        if ratifications != &speculate_ratifications {
            bail!("The ratifications after speculation do not match the ratifications in the block");
        }
        // Ensure the transactions after speculation match.
        let confirmed_transactions = confirmed_transactions.into_iter().collect();
        if transactions != &confirmed_transactions {
            let confirmed_transaction_ids =
                confirmed_transactions.transaction_ids().map(|id| id.to_string()).collect::<Vec<_>>();
            bail!(
                "The transactions after speculation do not match the transactions in the block. IDs: {confirmed_transaction_ids:?} - Transactions:{transactions:?} - confirmed_transactions:{confirmed_transactions:?}"
            );
        }
        // Ensure there are no aborted transaction IDs from this speculation.
        // Note: There should be no aborted transactions, because we are checking a block,
        // where any aborted transactions should be in the aborted transaction ID list, not in transactions.
        ensure!(aborted_transactions.is_empty(), "Aborted transactions found in the block (from speculation)");

        finish!(timer, "Finished dry-run of the transactions");

        // Return the ratified finalize operations.
        Ok(ratified_finalize_operations)
    }

    /// Committee lookback for `block.round()` semantics matching `Ledger::get_committee_lookback_for_round`.
    #[cfg(any(test, feature = "test"))]
    fn committee_lookback_for_round(&self, round: u64) -> Result<Option<Committee<N>>> {
        let previous_round = match round.is_multiple_of(2) {
            true => round.saturating_sub(1),
            false => round.saturating_sub(2),
        };
        let committee_lookback_round = previous_round.saturating_sub(Committee::<N>::COMMITTEE_LOOKBACK_RANGE);
        self.finalize_store().committee_store().get_committee_for_round(committee_lookback_round)
    }

    /// Epoch hash at `block_height`, matching `Ledger::get_epoch_hash`.
    #[cfg(any(test, feature = "test"))]
    fn epoch_hash_for_height(&self, block_height: u32) -> Result<N::BlockHash> {
        let epoch_number = block_height.saturating_div(N::NUM_BLOCKS_PER_EPOCH);
        let epoch_starting_height = epoch_number.saturating_mul(N::NUM_BLOCKS_PER_EPOCH);
        if epoch_starting_height == 0 {
            return Ok(N::BlockHash::default());
        }
        match self.block_store().get_previous_block_hash(epoch_starting_height)? {
            Some(hash) => Ok(hash),
            None => bail!("Missing previous block hash for epoch boundary height {epoch_starting_height}"),
        }
    }

    /// Runs `check_speculate` and [`Block::verify`] for a candidate next block. Caller supplies
    /// committee lookbacks and related ledger-derived inputs (see `Ledger::check_block_content_inner`).
    ///
    /// # Panics
    /// This function panics if called from an async context.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn check_block_content_inner<R: Rng + CryptoRng>(
        &self,
        block: &Block<N>,
        latest_block: &Block<N>,
        latest_block_timestamp: i64,
        latest_state_root: N::StateRoot,
        previous_committee_lookback: &Committee<N>,
        committee_lookback: &Committee<N>,
        puzzle: &Puzzle<N>,
        latest_epoch_hash: N::BlockHash,
        current_timestamp: i64,
        rng: &mut R,
    ) -> Result<(Vec<SolutionID<N>>, Vec<N::TransactionID>), VmCheckBlockContentError> {
        let block_timestamp = (block.height() >= N::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default())
            .then_some(block.timestamp());
        // Determine the block's spend and synthesis limits.
        let (block_spend_limit, block_synthesis_limit) = if let Authority::Quorum(subdag) = block.authority() {
            (subdag.spend_limit(block.height()), subdag.synthesis_limit(block.height()))
        } else {
            Authority::<N>::beacon_limits(block.height())
        };
        let state = FinalizeGlobalState::new::<N>(
            block.round(),
            block.height(),
            block_timestamp,
            block.cumulative_weight(),
            block.cumulative_proof_target(),
            block.previous_hash(),
            block_spend_limit,
            block_synthesis_limit,
        )
        .map_err(VmCheckBlockContentError::Verification)?;

        let time_since_last_block = block.timestamp().saturating_sub(latest_block_timestamp);
        let ratified_finalize_operations = self
            .check_speculate(
                state,
                time_since_last_block,
                block.ratifications(),
                block.solutions(),
                block.transactions(),
                rng,
            )
            .map_err(VmCheckBlockContentError::Speculation)?;

        block
            .verify(
                latest_block,
                latest_state_root,
                previous_committee_lookback,
                committee_lookback,
                puzzle,
                latest_epoch_hash,
                current_timestamp,
                ratified_finalize_operations,
            )
            .map_err(VmCheckBlockContentError::Verification)
    }

    /// Like [`Self::check_block_content_inner`], loading the block tip and committee lookbacks from this VM.
    ///
    /// Note: this duplicates the lookups that `Ledger` performs before calling
    /// [`Self::check_block_content_inner`], so that a test holding only a [`VM`] can run the same
    /// check. Production callers go through `Ledger::check_next_block`; if this is ever needed
    /// outside of tests, the two copies should be unified rather than both being maintained.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    #[cfg(any(test, feature = "test"))]
    #[inline]
    pub fn check_block_content_from_tip<R: Rng + CryptoRng>(
        &self,
        block: &Block<N>,
        rng: &mut R,
    ) -> Result<(Vec<SolutionID<N>>, Vec<N::TransactionID>), VmCheckBlockContentError> {
        let max_height = self
            .block_store()
            .max_height()
            .ok_or_else(|| VmCheckBlockContentError::Verification(anyhow!("empty block store")))?;
        let latest_hash = self
            .block_store()
            .get_block_hash(max_height)
            .map_err(VmCheckBlockContentError::Verification)?
            .ok_or_else(|| VmCheckBlockContentError::Verification(anyhow!("missing tip block hash")))?;
        let latest_block = self
            .block_store()
            .get_block(&latest_hash)
            .map_err(VmCheckBlockContentError::Verification)?
            .ok_or_else(|| VmCheckBlockContentError::Verification(anyhow!("missing tip block")))?;
        let latest_block_timestamp = latest_block.timestamp();
        let latest_state_root = self.block_store().current_state_root();

        let committee_lookback = self
            .committee_lookback_for_round(block.round())
            .map_err(VmCheckBlockContentError::Verification)?
            .ok_or_else(|| {
                VmCheckBlockContentError::Verification(anyhow!(
                    "missing committee lookback for block round {}",
                    block.round()
                ))
            })?;
        let previous_committee_lookback = self
            .committee_lookback_for_round(block.round().saturating_sub(1))
            .map_err(VmCheckBlockContentError::Verification)?
            .ok_or_else(|| {
                VmCheckBlockContentError::Verification(anyhow!(
                    "missing previous committee lookback for block round {}",
                    block.round()
                ))
            })?;

        let latest_epoch_hash =
            self.epoch_hash_for_height(latest_block.height()).map_err(VmCheckBlockContentError::Verification)?;

        let current_timestamp = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| VmCheckBlockContentError::Verification(anyhow!(e)))?
                .as_secs(),
        )
        .map_err(|e| VmCheckBlockContentError::Verification(anyhow!(e)))?;

        self.check_block_content_inner(
            block,
            &latest_block,
            latest_block_timestamp,
            latest_state_root,
            &previous_committee_lookback,
            &committee_lookback,
            self.puzzle(),
            latest_epoch_hash,
            current_timestamp,
            rng,
        )
    }

    /// Finalizes the given transactions into the VM.
    ///
    /// Returns the finalize operations from pre-ratify and post-ratify.
    #[inline]
    pub fn finalize(
        &self,
        state: FinalizeGlobalState,
        ratifications: &Ratifications<N>,
        solutions: &Solutions<N>,
        transactions: &Transactions<N>,
    ) -> Result<Vec<FinalizeOperation<N>>> {
        let timer = timer!("VM::finalize");

        // Performs a **real-run** of finalize over the list of ratifications, solutions, and transactions.
        let ratified_finalize_operations = self.atomic_finalize(state, ratifications, solutions, transactions)?;

        finish!(timer, "Finished real-run of finalize");
        Ok(ratified_finalize_operations)
    }
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// The maximum number of confirmed transactions allowed in a block.
    #[cfg(not(any(test, feature = "test")))]
    pub const MAXIMUM_CONFIRMED_TRANSACTIONS: usize = Transactions::<N>::MAX_TRANSACTIONS;
    /// The maximum number of confirmed transactions allowed in a block.
    /// This is deliberately set to a low value (8) for testing purposes only.
    #[cfg(any(test, feature = "test"))]
    pub const MAXIMUM_CONFIRMED_TRANSACTIONS: usize = 8;

    /// Performs atomic speculation over a list of transactions.
    ///
    /// Returns the ratifications, confirmed transactions, aborted transactions,
    /// and finalize operations from pre-ratify and post-ratify.
    ///
    /// # Note
    /// This method is used by `VM::speculate` and `VM::check_speculate`.
    ///   - If `coinbase_reward = None`, then the `ratifications` will not be modified.
    ///   - If `coinbase_reward = Some(coinbase_reward)`, then the method will append a
    ///     `Ratify::BlockReward(block_reward)` and `Ratify::PuzzleReward(puzzle_reward)`
    ///     to the front of the `ratifications` list.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    fn atomic_speculate(
        &self,
        state: FinalizeGlobalState,
        time_since_last_block: i64,
        coinbase_reward: Option<u64>,
        ratifications: Vec<Ratify<N>>,
        solutions: Solutions<N>,
        transactions: Vec<Transaction<N>>,
    ) -> Result<(
        Ratifications<N>,
        Vec<ConfirmedTransaction<N>>,
        Vec<(Transaction<N>, String)>,
        Vec<FinalizeOperation<N>>,
    )> {
        let sequential_op = SequentialOperation::AtomicSpeculate(
            state,
            time_since_last_block,
            coinbase_reward,
            ratifications,
            solutions,
            transactions,
        );
        let Some(SequentialOperationResult::AtomicSpeculate(ret)) = self.run_sequential_operation(sequential_op) else {
            bail!("Already shutting down");
        };

        ret
    }

    /// Internal function called when invoking [`Self::atomic_speculate`].
    ///
    /// # Note
    /// This function must only be called from the sequential operation thread.
    ///
    /// # Panics
    /// This function panics if not called from the sequential operation thread.
    pub(crate) fn atomic_speculate_inner(
        &self,
        state: FinalizeGlobalState,
        time_since_last_block: i64,
        coinbase_reward: Option<u64>,
        ratifications: Vec<Ratify<N>>,
        solutions: Solutions<N>,
        transactions: Vec<Transaction<N>>,
    ) -> Result<(
        Ratifications<N>,
        Vec<ConfirmedTransaction<N>>,
        Vec<(Transaction<N>, String)>,
        Vec<FinalizeOperation<N>>,
    )> {
        self.ensure_sequential_processing();

        let timer = timer!("VM::atomic_speculate");

        // Retrieve the number of solutions.
        let num_solutions = solutions.len();
        // Retrieve the number of transactions.
        let num_transactions = transactions.len();
        // Determine the maximum number of aborted solutions allowed in a block.
        let max_aborted_solutions = Solutions::<N>::max_aborted_solutions();
        // Determine the maximum number of aborted transactions allowed in a block.
        let max_aborted_transactions = Transactions::<N>::max_aborted_transactions();

        // Clear out any pending rejection reasons in case of errors in the previous iteration.
        {
            let mut rejected_reasons = self.pending_rejected_reasons.write();
            if !rejected_reasons.is_empty() {
                // This may be emitted once during shutdown.
                warn!("There are pending rejection reasons, clearing them up: {:?}", &*rejected_reasons);
            }
            rejected_reasons.clear();
        }

        // Perform the finalize operation on the preset finalize mode.
        atomic_finalize!(self.finalize_store(), FinalizeMode::DryRun, {
            // Ensure the number of solutions does not exceed the maximum.
            if num_solutions > max_aborted_solutions {
                // Note: This will abort the entire atomic batch.
                return Err(format!("Too many solutions in the block - {num_solutions}",));
            }

            // Ensure the number of transactions does not exceed the maximum.
            if num_transactions > max_aborted_transactions {
                // Note: This will abort the entire atomic batch.
                return Err(format!(
                    "Too many transactions in the block - {num_transactions} (max: {max_aborted_transactions})",
                ));
            }

            // Initialize an iterator for ratifications before finalize.
            let pre_ratifications = ratifications.iter().filter(|r| match r {
                Ratify::Genesis(_, _, _) => true,
                Ratify::BlockReward(..) | Ratify::PuzzleReward(..) => false,
            });
            // Initialize an iterator for ratifications after finalize.
            let post_ratifications = ratifications.iter().filter(|r| match r {
                Ratify::Genesis(_, _, _) => false,
                Ratify::BlockReward(..) | Ratify::PuzzleReward(..) => true,
            });

            // Initialize a list of finalize operations.
            let mut ratified_finalize_operations = Vec::new();

            // Retrieve the finalize store.
            let store = self.finalize_store();

            /* Perform the ratifications before finalize. */

            match Self::atomic_pre_ratify(store, state, pre_ratifications) {
                // Store the finalize operations from the post-ratify.
                Ok(operations) => ratified_finalize_operations.extend(operations),
                // Note: This will abort the entire atomic batch.
                Err(e) => return Err(format!("Failed to pre-ratify - {e}")),
            }

            /* Perform the atomic finalize over the transactions. */

            // Acquire a guard on the contents of the process.
            // Note: Due to the highly-sensitive nature of processing all `finalize` calls,
            // we choose to acquire it for the entire duration of this atomic batch.
            let process = self.process.lock();

            // Revert any unstaged stacks, when the function returns.
            // Note. This function does not call `commit_stacks` so the staged stacks will always be reverted
            //  regardless of whether the function succeeds or fails.
            defer! {
                process.revert_stacks();
            }

            // Initialize a list of the confirmed transactions.
            let mut confirmed = Vec::with_capacity(num_transactions);
            // Initialize a list of the aborted transactions.
            let mut aborted = Vec::new();
            // Initialize a counter for the confirmed transaction index.
            let mut counter = 0u32;
            // Accumulate per-block uniqueness checks.
            let mut candidate_transaction_details = CandidateTransactionDetails::<N>::default();
            // Accumulate per-block spend.
            let mut block_spend = 0u64;
            // Determine the transaction spend limit. These unwraps are safe, see tests in consensus_heights.rs
            let consensus_version = N::CONSENSUS_VERSION(state.block_height()).unwrap();
            let transaction_spend_limit =
                consensus_config_value_by_version!(N, TRANSACTION_SPEND_LIMIT, consensus_version).unwrap();
            // Determine the block spend limit.
            let block_spend_limit = state.block_spend_limit();

            // Finalize the transactions.
            'outer: for transaction in transactions {
                // Ensure the number of confirmed transactions does not exceed the maximum.
                // Upon reaching the maximum number of confirmed transactions, all remaining transactions are aborted.
                if confirmed.len() >= Self::MAXIMUM_CONFIRMED_TRANSACTIONS {
                    // Store the aborted transaction.
                    aborted.push((transaction.clone(), "Exceeds block transaction limit".to_string()));
                    // Continue to the next transaction.
                    continue 'outer;
                }

                // Determine whether to skip this transaction.
                match self.should_abort_transaction(
                    &transaction,
                    &candidate_transaction_details,
                    transaction_spend_limit,
                    None,
                    consensus_version,
                ) {
                    ShouldAbortResult::Abort(abort_reason) => {
                        // Store the aborted transaction.
                        aborted.push((transaction.clone(), abort_reason));
                        // Continue to the next transaction.
                        continue 'outer;
                    }
                    ShouldAbortResult::Finalize(compute_spend) => {
                        // If the consensus version is >= V16, ensure that the
                        // transaction is not exceeding block spend limits.
                        //
                        // TODO(vicsn) a more robust setup would rely on the
                        // batch_spend_limit directly, checking on a
                        // per-certificate basis whether or not transactions
                        // exceed it.
                        if consensus_version >= ConsensusVersion::V16 {
                            if let Some(block_spend_limit) = block_spend_limit
                                && block_spend.saturating_add(compute_spend) > block_spend_limit
                            {
                                aborted.push((
                                    transaction.clone(),
                                    format!("Exceeds the block spend limit with compute_spend: '{compute_spend}'"),
                                ));
                                // Continue to the next transaction.
                                continue 'outer;
                            }
                            // Track the compute_spend used so far.
                            block_spend = block_spend.saturating_add(compute_spend);
                        }
                    }
                }

                // Process the transaction in an isolated atomic batch.
                // - If the transaction succeeds, the finalize operations are stored.
                // - If the transaction fails, the atomic batch is aborted and no finalize operations are stored.
                let outcome = match &transaction {
                    // The finalize operation here involves appending the 'stack',
                    // and adding the program to the finalize tree.
                    Transaction::Deploy(_, _, program_owner, deployment, fee) => {
                        // Define the closure for processing a rejected deployment.
                        let process_rejected_deployment =
                            |fee: &Fee<N>,
                             deployment: Deployment<N>,
                             rejected_reason: RejectedReason<N>|
                             -> Result<Result<ConfirmedTransaction<N>, String>> {
                                process
                                    .finalize_fee(state, store, fee)
                                    .map_err(anyhow::Error::from)
                                    .and_then(|finalize| {
                                        Transaction::from_fee(fee.clone()).map(|fee_tx| (fee_tx, finalize))
                                    })
                                    .map(|(fee_tx, finalize)| {
                                        let rejected = Rejected::new_deployment(*program_owner, deployment);
                                        ConfirmedTransaction::rejected_deploy(counter, fee_tx, rejected, finalize)
                                            .and_then(|confirmed_tx| {
                                                // Store the rejection reason.
                                                self.pending_rejected_reasons
                                                    .write()
                                                    .insert(confirmed_tx.id(), rejected_reason.clone());
                                                store
                                                    .insert_rejected_reason(*confirmed_tx.id(), rejected_reason)
                                                    .map_err(|e| anyhow!("Failed to store rejection reason: {e}"))?;
                                                Ok(confirmed_tx)
                                            })
                                            .map_err(|e| e.to_string())
                                    })
                            };

                        // Check if the program has already been deployed in this block.
                        match candidate_transaction_details.deployments.contains(deployment.program_id()) {
                            // If the program has already been deployed, construct the rejected deploy transaction.
                            true => {
                                let rejected_reason = RejectedReason::DuplicateProgramID(*deployment.program_id());
                                match process_rejected_deployment(fee, *deployment.clone(), rejected_reason) {
                                    Ok(result) => result,
                                    Err(error) => {
                                        // Note: On failure, skip this transaction, and continue speculation.
                                        dev_eprintln!("Failed to finalize the fee in a rejected deploy - {error}");
                                        // Store the aborted transaction.
                                        aborted.push((transaction.clone(), error.to_string()));
                                        // Continue to the next transaction.
                                        continue 'outer;
                                    }
                                }
                            }
                            // If the program has not yet been deployed, attempt to deploy it.
                            false => match process.finalize_deployment(state, store, deployment, fee) {
                                // Construct the accepted deploy transaction.
                                Ok((stack, finalize)) => {
                                    // Add the stack to the process with the option to be reverted.
                                    process.stage_stack(stack);
                                    ConfirmedTransaction::accepted_deploy(counter, transaction.clone(), finalize)
                                        .map_err(|e| e.to_string())
                                }
                                // Construct the rejected deploy transaction.
                                Err(error) => {
                                    dev_eprintln!("Failed to finalize deploy tx {} - {error}", transaction.id());
                                    trace!("Failed to finalize deploy tx {} - {error}", transaction.id());
                                    let rejected_reason = RejectedReason::from_indexed_finalize_error(error);
                                    match process_rejected_deployment(fee, *deployment.clone(), rejected_reason) {
                                        Ok(result) => result,
                                        Err(error) => {
                                            // Note: On failure, skip this transaction, and continue speculation.
                                            dev_eprintln!("Failed to finalize the fee in a rejected deploy - {error}");
                                            // Store the aborted transaction.
                                            aborted.push((transaction.clone(), error.to_string()));
                                            // Continue to the next transaction.
                                            continue 'outer;
                                        }
                                    }
                                }
                            },
                        }
                    }
                    // The finalize operation here involves calling 'update_key_value',
                    // and update the respective leaves of the finalize tree.
                    Transaction::Execute(_, _, execution, fee) => {
                        // Determine if the transaction is safe for execution, and proceed to execute it.
                        match self
                            .prepare_for_execution(state, store, execution)
                            .and_then(|_| process.finalize_execution(state, store, execution, fee.as_ref()))
                        {
                            // Construct the accepted execute transaction.
                            Ok(finalize) => {
                                ConfirmedTransaction::accepted_execute(counter, transaction.clone(), finalize)
                                    .map_err(|e| e.to_string())
                            }
                            // Construct the rejected execute transaction.
                            Err(error) => {
                                dev_eprintln!("Failed to finalize execute tx {} - {error}", transaction.id());
                                trace!("Failed to finalize execute tx {} - {error}", transaction.id());
                                let rejected_reason = RejectedReason::from_indexed_finalize_error(error);
                                match fee {
                                    // Finalize the fee, to ensure it is valid.
                                    Some(fee) => {
                                        match process
                                            .finalize_fee(state, store, fee)
                                            .map_err(anyhow::Error::from)
                                            .and_then(|finalize| {
                                                Transaction::from_fee(fee.clone()).map(|fee_tx| (fee_tx, finalize))
                                            }) {
                                            Ok((fee_tx, finalize)) => {
                                                // Construct the rejected execution.
                                                let rejected = Rejected::new_execution(*execution.clone());
                                                // Construct the rejected execute transaction.
                                                ConfirmedTransaction::rejected_execute(
                                                    counter, fee_tx, rejected, finalize,
                                                )
                                                .and_then(|confirmed_tx| {
                                                    // Store the rejection reason.
                                                    self.pending_rejected_reasons
                                                        .write()
                                                        .insert(confirmed_tx.id(), rejected_reason.clone());
                                                    store
                                                        .insert_rejected_reason(*confirmed_tx.id(), rejected_reason)
                                                        .map_err(|e| anyhow!("Failed to store rejection reason: {e}"))?;
                                                    Ok(confirmed_tx)
                                                })
                                                .map_err(|e| e.to_string())
                                            }
                                            Err(error) => {
                                                // Note: On failure, skip this transaction, and continue speculation.
                                                dev_eprintln!(
                                                    "Failed to finalize the fee in a rejected execute - {error}"
                                                );
                                                // Store the aborted transaction.
                                                aborted.push((transaction.clone(), error.to_string()));
                                                // Continue to the next transaction.
                                                continue 'outer;
                                            }
                                        }
                                    }

                                    // This is a foundational bug - the caller is violating protocol rules.
                                    // It is possible that a `credits.aleo/split` transaction has no fee. However, it
                                    // is a simple transition without finalize operations and should not fail here.
                                    // If a `credits.aleo/upgrade` transaction has no fee and fails, we simply abort it.
                                    // Note: This will abort the entire atomic batch.
                                    None => {
                                        // Abort the upgrade transaction.
                                        if transaction.contains_upgrade() && execution.len() == 1 {
                                            aborted.push((
                                                transaction.clone(),
                                                "Failed to finalize a `credits.aleo/upgrade` call with no fee"
                                                    .to_string(),
                                            ));
                                            // Continue to the next transaction.
                                            continue 'outer;
                                        }
                                        Err("Rejected execute transaction has no fee".to_string())
                                    }
                                }
                            }
                        }
                    }
                    // There are no finalize operations here.
                    // Note: This will abort the entire atomic batch.
                    Transaction::Fee(..) => Err("Cannot speculate on a fee transaction".to_string()),
                };
                lap!(timer, "Speculated on transaction '{}'", transaction.id());

                match outcome {
                    // If the transaction succeeded, store it and continue to the next transaction.
                    Ok(confirmed_transaction) => {
                        // Track the accepted transaction details.
                        candidate_transaction_details.record_transaction(confirmed_transaction.transaction());
                        // Store the confirmed transaction.
                        confirmed.push(confirmed_transaction);
                        // Increment the transaction index counter.
                        counter = counter.saturating_add(1);
                    }
                    // If the transaction failed, abort the entire batch.
                    Err(error) => {
                        error!("Critical bug in speculate: {error}\n\n{transaction}");
                        dev_eprintln!("Critical bug in speculate: {error}\n\n{transaction}");
                        // Note: This will abort the entire atomic batch.
                        return Err(format!("Failed to speculate on transaction - {error}"));
                    }
                }
            }

            // Ensure all transactions were processed.
            if confirmed.len() + aborted.len() != num_transactions {
                // Note: This will abort the entire atomic batch.
                return Err("Not all transactions were processed in 'VM::atomic_speculate'".to_string());
            }

            /* Perform the ratifications after finalize. */

            // Prepare the reward ratifications, if any.
            let reward_ratifications = match coinbase_reward {
                // If the coinbase reward is `None`, then there are no reward ratifications.
                None => vec![],
                // If the coinbase reward is `Some(coinbase_reward)`, then we must compute the reward ratifications.
                Some(coinbase_reward) => {
                    // Calculate the transaction fees.
                    let Ok(transaction_fees) =
                        confirmed.iter().map(|tx| Ok(*tx.priority_fee_amount()?)).sum::<Result<u64>>()
                    else {
                        // Note: This will abort the entire atomic batch.
                        return Err("Failed to calculate the transaction fees during speculation".to_string());
                    };

                    // Compute the block reward.
                    let block_reward = snarkvm_ledger_block::block_reward::<N>(
                        state.block_height(),
                        N::STARTING_SUPPLY,
                        N::BLOCK_TIME,
                        time_since_last_block,
                        coinbase_reward,
                        transaction_fees,
                    )
                    .map_err(|e| format!("Failed to compute the block reward - {e}"))?;
                    // Compute the puzzle reward.
                    let puzzle_reward = snarkvm_ledger_block::puzzle_reward(coinbase_reward);

                    // Output the reward ratifications.
                    vec![Ratify::BlockReward(block_reward), Ratify::PuzzleReward(puzzle_reward)]
                }
            };

            // Update the post-ratifications iterator.
            let post_ratifications = reward_ratifications.iter().chain(post_ratifications);

            // Process the post-ratifications.
            match Self::atomic_post_ratify(&self.puzzle, store, state, post_ratifications, &solutions, false) {
                // Store the finalize operations from the post-ratify.
                Ok(operations) => ratified_finalize_operations.extend(operations),
                // Note: This will abort the entire atomic batch.
                Err(e) => return Err(format!("Failed to post-ratify - {e}")),
            }

            /* Construct the ratifications after speculation. */

            let Ok(ratifications) =
                Ratifications::try_from_iter(reward_ratifications.into_iter().chain(ratifications.into_iter()))
            else {
                // Note: This will abort the entire atomic batch.
                return Err("Failed to construct the ratifications after speculation".to_string());
            };

            finish!(timer);

            // On return, 'atomic_finalize!' will abort the batch, and return the ratifications,
            // confirmed & aborted transactions, and finalize operations from pre-ratify and post-ratify.
            Ok((ratifications, confirmed, aborted, ratified_finalize_operations))
        })
    }

    /// Performs atomic finalization over a list of transactions.
    ///
    /// Returns the finalize operations from pre-ratify and post-ratify.
    #[inline]
    fn atomic_finalize(
        &self,
        state: FinalizeGlobalState,
        ratifications: &Ratifications<N>,
        solutions: &Solutions<N>,
        transactions: &Transactions<N>,
    ) -> Result<Vec<FinalizeOperation<N>>> {
        // The tests may run this method ad-hoc, outside of the context of add_next_block.
        #[cfg(not(test))]
        self.ensure_sequential_processing();

        let timer = timer!("VM::atomic_finalize");

        self.store.finalize_store().block_height().store(state.block_height(), std::sync::atomic::Ordering::SeqCst);

        // Perform the finalize operation on the preset finalize mode.
        let finalize_result = atomic_finalize!(self.finalize_store(), FinalizeMode::RealRun, {
            // Initialize an iterator for ratifications before finalize.
            let pre_ratifications = ratifications.iter().filter(|r| match r {
                Ratify::Genesis(_, _, _) => true,
                Ratify::BlockReward(..) | Ratify::PuzzleReward(..) => false,
            });
            // Initialize an iterator for ratifications after finalize.
            let post_ratifications = ratifications.iter().filter(|r| match r {
                Ratify::Genesis(_, _, _) => false,
                Ratify::BlockReward(..) | Ratify::PuzzleReward(..) => true,
            });

            // Initialize a list of finalize operations.
            let mut ratified_finalize_operations = Vec::new();

            // Retrieve the finalize store.
            let store = self.finalize_store();

            /* Perform the ratifications before finalize. */

            match Self::atomic_pre_ratify(store, state, pre_ratifications) {
                // Store the finalize operations from the post-ratify.
                Ok(operations) => ratified_finalize_operations.extend(operations),
                // Note: This will abort the entire atomic batch.
                Err(e) => return Err(format!("Failed to pre-ratify - {e}")),
            }

            /* Perform the atomic finalize over the transactions. */

            // Acquire a guard on the contents of the process.
            // Note: Due to the highly-sensitive nature of processing all `finalize` calls,
            // we choose to acquire it for the entire duration of this atomic batch.
            let process = self.process.lock();

            // Revert any unstaged stacks, when the function returns.
            // Note. `commit_stacks` is called at the bottom of this function after successful finalization.
            //  The staged stacks are only reverted if the function returns an error.
            defer! {
                process.revert_stacks();
            }

            // Finalize the transactions.
            for (index, transaction) in transactions.iter().enumerate() {
                // Convert the transaction index to a u32.
                // Note: On failure, this will abort the entire atomic batch.
                let index = u32::try_from(index).map_err(|_| "Failed to convert transaction index".to_string())?;
                // Ensure the index matches the expected index.
                if index != transaction.index() {
                    // Note: This will abort the entire atomic batch.
                    return Err(format!("Mismatch in {} transaction index", transaction.variant()));
                }
                // Process the transaction in an isolated atomic batch.
                // - If the transaction succeeds, the finalize operations are stored.
                // - If the transaction fails, the atomic batch is aborted and no finalize operations are stored.
                let outcome: Result<(), String> = match transaction {
                    ConfirmedTransaction::AcceptedDeploy(_, transaction, finalize) => {
                        // Extract the deployment and fee from the transaction.
                        let (deployment, fee) = match transaction {
                            Transaction::Deploy(_, _, _, deployment, fee) => (deployment, fee),
                            // Note: This will abort the entire atomic batch.
                            _ => return Err("Expected deploy transaction".to_string()),
                        };
                        // The finalize operation here involves appending the 'stack', and adding the program to the finalize tree.
                        match process.finalize_deployment(state, store, deployment, fee) {
                            // Ensure the finalize operations match the expected.
                            Ok((stack, finalize_operations)) => match finalize == &finalize_operations {
                                // Add the stack to the process with the option to be reverted.
                                true => process.stage_stack(stack),
                                // Note: This will abort the entire atomic batch.
                                false => {
                                    return Err(format!(
                                        "Mismatch in finalize operations for an accepted deploy - (found: {finalize_operations:?}, expected: {finalize:?})"
                                    ));
                                }
                            },
                            // Note: This will abort the entire atomic batch.
                            Err(error) => {
                                return Err(format!("Failed to finalize an accepted deploy transaction - {error}"));
                            }
                        };
                        Ok(())
                    }
                    ConfirmedTransaction::AcceptedExecute(_, transaction, finalize) => {
                        // Extract the execution and fee from the transaction.
                        let (execution, fee) = match transaction {
                            Transaction::Execute(_, _, execution, fee) => (execution, fee),
                            // Note: This will abort the entire atomic batch.
                            _ => return Err("Expected execute transaction".to_string()),
                        };
                        // The finalize operation here involves calling 'update_key_value',
                        // and update the respective leaves of the finalize tree.
                        match process.finalize_execution(state, store, execution, fee.as_ref()) {
                            // Ensure the finalize operations match the expected.
                            Ok(finalize_operations) => {
                                if finalize != &finalize_operations {
                                    // Note: This will abort the entire atomic batch.
                                    return Err(format!(
                                        "Mismatch in finalize operations for an accepted execute - (found: {finalize_operations:?}, expected: {finalize:?})"
                                    ));
                                }
                            }
                            // Note: This will abort the entire atomic batch.
                            Err(error) => {
                                return Err(format!("Failed to finalize an accepted execute transaction - {error}"));
                            }
                        }
                        Ok(())
                    }
                    ConfirmedTransaction::RejectedDeploy(_, Transaction::Fee(fee_tx_id, fee), rejected, finalize) => {
                        // Extract the rejected deployment.
                        let Some(deployment) = rejected.deployment() else {
                            // Note: This will abort the entire atomic batch.
                            return Err("Expected rejected deployment".to_string());
                        };
                        // Compute the expected deployment ID.
                        let Ok(expected_deployment_id) = deployment.to_deployment_id() else {
                            // Note: This will abort the entire atomic batch.
                            return Err("Failed to compute the deployment ID for a rejected deployment".to_string());
                        };
                        // Retrieve the candidate deployment ID.
                        let Ok(candidate_deployment_id) = fee.deployment_or_execution_id() else {
                            // Note: This will abort the entire atomic batch.
                            return Err("Failed to retrieve the deployment ID from the fee".to_string());
                        };
                        // Ensure this fee corresponds to the deployment.
                        if candidate_deployment_id != expected_deployment_id {
                            // Note: This will abort the entire atomic batch.
                            return Err("Mismatch in fee for a rejected deploy transaction".to_string());
                        }
                        // Lastly, finalize the fee.
                        match process.finalize_fee(state, store, fee) {
                            // Ensure the finalize operations match the expected.
                            Ok(finalize_operations) => {
                                if finalize != &finalize_operations {
                                    // Note: This will abort the entire atomic batch.
                                    return Err(format!(
                                        "Mismatch in finalize operations for a rejected deploy - (found: {finalize_operations:?}, expected: {finalize:?})"
                                    ));
                                }

                                if let Some(rejected_reason) = self.pending_rejected_reasons.write().remove(fee_tx_id) {
                                    store.insert_rejected_reason(**fee_tx_id, rejected_reason.clone()).map_err(
                                        |_| "Couldn't store the reason behind a rejected deployment".to_string(),
                                    )?;
                                }
                            }
                            // Note: This will abort the entire atomic batch.
                            Err(_e) => {
                                return Err("Failed to finalize the fee in a rejected deploy transaction".to_string());
                            }
                        }
                        Ok(())
                    }
                    ConfirmedTransaction::RejectedExecute(_, Transaction::Fee(fee_tx_id, fee), rejected, finalize) => {
                        // Extract the rejected execution.
                        let Some(execution) = rejected.execution() else {
                            // Note: This will abort the entire atomic batch.
                            return Err("Expected rejected execution".to_string());
                        };
                        // Compute the expected execution ID.
                        let Ok(expected_execution_id) = execution.to_execution_id() else {
                            // Note: This will abort the entire atomic batch.
                            return Err("Failed to compute the execution ID for a rejected execution".to_string());
                        };
                        // Retrieve the candidate execution ID.
                        let Ok(candidate_execution_id) = fee.deployment_or_execution_id() else {
                            // Note: This will abort the entire atomic batch.
                            return Err("Failed to retrieve the execution ID from the fee".to_string());
                        };
                        // Ensure this fee corresponds to the execution.
                        if candidate_execution_id != expected_execution_id {
                            // Note: This will abort the entire atomic batch.
                            return Err("Mismatch in fee for a rejected execute transaction".to_string());
                        }
                        // Lastly, finalize the fee.
                        match process.finalize_fee(state, store, fee) {
                            // Ensure the finalize operations match the expected.
                            Ok(finalize_operations) => {
                                if finalize != &finalize_operations {
                                    // Note: This will abort the entire atomic batch.
                                    return Err(format!(
                                        "Mismatch in finalize operations for a rejected execute - (found: {finalize_operations:?}, expected: {finalize:?})"
                                    ));
                                }

                                if let Some(rejected_reason) = self.pending_rejected_reasons.write().remove(fee_tx_id) {
                                    store.insert_rejected_reason(**fee_tx_id, rejected_reason.clone()).map_err(
                                        |_| "Couldn't store the reason behind a rejected execute".to_string(),
                                    )?;
                                }
                            }
                            // Note: This will abort the entire atomic batch.
                            Err(_e) => {
                                return Err("Failed to finalize the fee in a rejected execute transaction".to_string());
                            }
                        }
                        Ok(())
                    }
                    // Note: This will abort the entire atomic batch.
                    _ => return Err("Invalid confirmed transaction type".to_string()),
                };
                lap!(timer, "Finalizing transaction {}", transaction.id());

                match outcome {
                    // If the transaction succeeded to finalize, continue to the next transaction.
                    Ok(()) => (),
                    // If the transaction failed to finalize, abort and continue to the next transaction.
                    Err(error) => {
                        error!("Critical bug in finalize: {error}\n\n{transaction}");
                        dev_eprintln!("Critical bug in finalize: {error}\n\n{transaction}");
                        // Note: This will abort the entire atomic batch.
                        return Err(format!("Failed to finalize on transaction - {error}"));
                    }
                }
            }

            /* Perform the ratifications after finalize. */

            match Self::atomic_post_ratify(
                &self.puzzle,
                store,
                state,
                post_ratifications,
                solutions,
                store.record_history_json(),
            ) {
                // Store the finalize operations from the post-ratify.
                Ok(operations) => ratified_finalize_operations.extend(operations),
                // Note: This will abort the entire atomic batch.
                Err(e) => return Err(format!("Failed to post-ratify - {e}")),
            }

            /* Start the commit process. */

            // Commit all the stacks to the process.
            process.commit_stacks();

            finish!(timer); // <- Note: This timer does **not** include the time to write batch to DB.

            Ok(ratified_finalize_operations)
        });

        finalize_result
    }

    /// Returns ShouldAbortResult.
    ///
    /// The transaction will be aborted if any of the following conditions are met:
    /// - The transaction is producing a duplicate transition
    /// - The transaction is double-spending an input
    /// - The transaction is producing a duplicate output
    /// - The transaction is producing a duplicate transition public key
    /// - The transaction is producing a duplicate serial number
    /// - The transaction is producing a duplicate tag
    /// - The transaction is producing a duplicate commitment
    /// - The transaction is producing a duplicate nonce
    /// - The transaction is producing a duplicate transition commitment
    /// - The transaction is another deployment in the block from the same public fee payer.
    /// - The transaction contains a transition that has been deployed or upgraded in this block.
    /// - The transaction surpasses the spend limits.
    ///
    /// - Note: If a transaction is a deployment for a program following its deployment or redeployment in this block,
    ///   it is not aborted. Instead, it will be rejected and its fee will be consumed.
    fn should_abort_transaction(
        &self,
        transaction: &Transaction<N>,
        candidate_transaction_details: &CandidateTransactionDetails<N>,
        transaction_spend_limit: u64,
        block_synthesis_limit: Option<u64>,
        consensus_version: ConsensusVersion,
    ) -> ShouldAbortResult {
        // Ensure that the transaction is not a fee transaction.
        if let Transaction::Fee(..) = transaction {
            return ShouldAbortResult::Abort("Fee transactions are not allowed in speculate".to_string());
        }

        // Ensure that:
        //  - the transaction is not producing a duplicate transition.
        //  - the programs in the component transitions haven't been deployed or upgraded in this block.
        let mut transition_ids_in_transaction = IndexSet::new();
        for transition in transaction.transitions() {
            // Get the transition ID.
            let transition_id = transition.id();
            // If the transition ID is duplicated within this transaction, abort the transaction.
            if !transition_ids_in_transaction.insert(*transition_id) {
                return ShouldAbortResult::Abort(format!("Duplicate transition {transition_id} in transaction"));
            }
            // If the transition ID is already produced in this block or previous blocks, abort the transaction.
            if candidate_transaction_details.transition_ids.contains(transition_id)
                || self.transition_store().contains_transition_id(transition_id).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate transition {transition_id}"));
            }
            // If the transition's program is being deployed or redeployed in this block, abort the transaction.
            if candidate_transaction_details.deployments.contains(transition.program_id()) {
                return ShouldAbortResult::Abort(format!(
                    "Program {} is being deployed or redeployed in this block",
                    transition.program_id()
                ));
            }
        }

        // Ensure that the transaction is not double-spending an input.
        let mut input_ids_in_transaction = IndexSet::new();
        for input_id in transaction.input_ids() {
            // If the input ID is duplicated within this transaction, abort the transaction.
            if !input_ids_in_transaction.insert(*input_id) {
                return ShouldAbortResult::Abort(format!("Double-spending input {input_id} in transaction"));
            }
            // If the input ID is already spent in this block or previous blocks, abort the transaction.
            if candidate_transaction_details.input_ids.contains(input_id)
                || self.transition_store().contains_input_id(input_id).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Double-spending input {input_id}"));
            }
        }

        // Ensure that the transaction is not producing a duplicate output.
        let mut output_ids_in_transaction = IndexSet::new();
        for output_id in transaction.output_ids() {
            // If the output ID is duplicated within this transaction, abort the transaction.
            if !output_ids_in_transaction.insert(*output_id) {
                return ShouldAbortResult::Abort(format!("Duplicate output {output_id} in transaction"));
            }
            // If the output ID is already produced in this block or previous blocks, abort the transaction.
            if candidate_transaction_details.output_ids.contains(output_id)
                || self.transition_store().contains_output_id(output_id).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate output {output_id}"));
            }
        }

        // Ensure that the record spends are unique within the transaction, the block, and the chain.
        let mut serial_numbers_in_transaction = IndexSet::new();
        for serial_number in transaction.serial_numbers() {
            if !serial_numbers_in_transaction.insert(*serial_number) {
                return ShouldAbortResult::Abort(format!("Duplicate serial number {serial_number} in transaction"));
            }
            if candidate_transaction_details.serial_numbers.contains(serial_number)
                || self.transition_store().contains_serial_number(serial_number).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate serial number {serial_number}"));
            }
        }

        let mut tags_in_transaction = IndexSet::new();
        for tag in transaction.tags() {
            if !tags_in_transaction.insert(*tag) {
                return ShouldAbortResult::Abort(format!("Duplicate tag {tag} in transaction"));
            }
            if candidate_transaction_details.tags.contains(tag)
                || self.transition_store().contains_tag(tag).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate tag {tag}"));
            }
        }

        let mut commitments_in_transaction = IndexSet::new();
        for commitment in transaction.commitments() {
            if !commitments_in_transaction.insert(*commitment) {
                return ShouldAbortResult::Abort(format!("Duplicate commitment {commitment} in transaction"));
            }
            if candidate_transaction_details.commitments.contains(commitment)
                || self.transition_store().contains_commitment(commitment).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate commitment {commitment}"));
            }
        }

        let mut nonces_in_transaction = IndexSet::new();
        for nonce in transaction.nonces() {
            if !nonces_in_transaction.insert(*nonce) {
                return ShouldAbortResult::Abort(format!("Duplicate nonce {nonce} in transaction"));
            }
            if candidate_transaction_details.nonces.contains(nonce)
                || self.transition_store().contains_nonce(nonce).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate nonce {nonce}"));
            }
        }

        // Ensure the transition public keys and transition commitments are unique.
        // Note that the tpk and tcm are not in a 1:1 correspondence, so both must be checked.
        let mut tpks_in_transaction = IndexSet::new();
        for tpk in transaction.transition_public_keys() {
            // If the transition public key is duplicated within this transaction, abort the transaction.
            if !tpks_in_transaction.insert(*tpk) {
                return ShouldAbortResult::Abort(format!("Duplicate transition public key {tpk} in transaction"));
            }
            // If the transition public key is already produced in this block or previous blocks, abort the transaction.
            if candidate_transaction_details.tpks.contains(tpk)
                || self.transition_store().contains_tpk(tpk).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate transition public key {tpk}"));
            }
        }

        let mut tcms_in_transaction = IndexSet::new();
        for tcm in transaction.transition_commitments() {
            if !tcms_in_transaction.insert(*tcm) {
                return ShouldAbortResult::Abort(format!("Duplicate transition commitment {tcm} in transaction"));
            }
            if candidate_transaction_details.tcms.contains(tcm)
                || self.transition_store().contains_tcm(tcm).unwrap_or(true)
            {
                return ShouldAbortResult::Abort(format!("Duplicate transition commitment {tcm}"));
            }
        }

        // If the transaction is a deployment, ensure that it is not another deployment in the block from the same public fee payer.
        if let Transaction::Deploy(_, _, _, _, fee) = transaction {
            // If any public deployment payer has already deployed in this block, abort the transaction.
            if let Some(payer) = fee.payer()
                && candidate_transaction_details.deployment_payers.contains(&payer)
            {
                return ShouldAbortResult::Abort(format!(
                    "Another deployment in the block from the same public fee payer {payer}"
                ));
            }
        }

        // Before V16, we return without tracking any compute spend and checking deployment limits.
        if consensus_version < ConsensusVersion::V16 {
            ShouldAbortResult::Finalize(0)
        // If the consensus version is >= V16, ensure that the transaction is not exceeding spend or deployment limits.
        } else {
            let compute_spend =
                match transaction_compute_spend_in_microcredits(self.process(), transaction, consensus_version) {
                    Ok(compute_spend) => compute_spend,
                    Err(e) => return ShouldAbortResult::Abort(format!("Failed to compute transaction spend: {e}")),
                };

            if compute_spend > transaction_spend_limit {
                return ShouldAbortResult::Abort(format!(
                    "Exceeds the transaction spend limit with compute_spend: '{compute_spend}'"
                ));
            }
            // If we are keeping track of block-wide circuit density and this transaction contains a
            // deployment, make sure its density does not make the running total exceed the limit.
            // This applies for V18 and the first V19 block, where `block_synthesis_limit` is `Some`.
            if consensus_version >= ConsensusVersion::V18
                && let Transaction::Deploy(_, _, _, deployment, _) = transaction
                && let Some(synthesis_limit) = block_synthesis_limit
                && candidate_transaction_details.block_combined_density.saturating_add(deployment.combined_density())
                    > synthesis_limit
            {
                return ShouldAbortResult::Abort(format!(
                    "Deployment density '{}' added to current accumulated block-wide density '{}' exceeds the limit '{}'",
                    deployment.combined_density(),
                    candidate_transaction_details.block_combined_density,
                    synthesis_limit
                ));
            }

            ShouldAbortResult::Finalize(compute_spend)
        }
    }

    /// Performs precondition checks on the transactions prior to speculation.
    ///
    /// This method is used to check the following conditions:
    /// - If a transaction is a fee transaction or if it is invalid,
    ///   then the transaction will be aborted.
    pub(crate) fn prepare_for_speculate<'a, R: CryptoRng + Rng>(
        &self,
        transactions: &[&'a Transaction<N>],
        state: FinalizeGlobalState,
        rng: &mut R,
    ) -> Result<(Vec<&'a Transaction<N>>, Vec<(&'a Transaction<N>, String)>)> {
        // Construct the list of transactions that need to verified.
        let mut transactions_to_verify = Vec::with_capacity(transactions.len());
        // Construct the list of valid and invalid transactions.
        let mut valid_transactions = Vec::with_capacity(transactions.len());
        let mut aborted_transactions = Vec::with_capacity(transactions.len());

        // Accumulate per-block uniqueness checks.
        let mut candidate_transaction_details = CandidateTransactionDetails::<N>::default();
        // Determine the transaction spend limit. These unwraps are safe, see tests in consensus_heights.rs
        let consensus_version = N::CONSENSUS_VERSION(state.block_height()).unwrap();
        let transaction_spend_limit =
            consensus_config_value_by_version!(N, TRANSACTION_SPEND_LIMIT, consensus_version).unwrap();

        // Abort duplicate, overspending, invalid, or disallowed transactions before verification.
        for transaction in transactions.iter() {
            match self.should_abort_transaction(
                transaction,
                &candidate_transaction_details,
                transaction_spend_limit,
                state.block_synthesis_limit(),
                consensus_version,
            ) {
                ShouldAbortResult::Abort(abort_reason) => {
                    // Store the aborted transaction.
                    aborted_transactions.push((*transaction, abort_reason));
                }
                ShouldAbortResult::Finalize(_compute_spend) => {
                    // Track the accepted transaction details.
                    candidate_transaction_details.record_transaction(transaction);
                    // Mark the transaction ready to verify.
                    transactions_to_verify.push(transaction);
                }
            }
        }

        // Separate the transactions into deploys and executions.
        let (deployments, executions): (Vec<&Transaction<N>>, Vec<&Transaction<N>>) =
            transactions_to_verify.into_iter().partition(|tx| tx.is_deploy());
        // Chunk the deploys and executions into groups for parallel verification.
        let deployments_for_verification = deployments.chunks(Self::MAX_PARALLEL_DEPLOY_VERIFICATIONS);
        let executions_for_verification = executions.chunks(Self::MAX_PARALLEL_EXECUTE_VERIFICATIONS);

        // Verify the transactions in batches and separate the valid and invalid transactions.
        for transactions in deployments_for_verification.chain(executions_for_verification) {
            let rngs = (0..transactions.len()).map(|_| StdRng::from_seed(rng.random())).collect::<Vec<_>>();
            // Verify the transactions and collect the error message if there is one.
            let (valid, invalid): (Vec<_>, Vec<_>) =
                cfg_into_iter!(transactions).zip(rngs).partition_map(|(transaction, mut rng)| {
                    // Verify the transaction.
                    match self.check_transaction(transaction, None, &mut rng) {
                        // If the transaction is valid, add it to the list of valid transactions.
                        Ok(_) => Either::Left(*transaction),
                        // If the transaction is invalid, add it to the list of aborted transactions.
                        Err(e) => Either::Right((*transaction, e.to_string())),
                    }
                });

            // Collect the valid and aborted transactions.
            valid_transactions.extend(valid);
            aborted_transactions.extend(invalid);
        }

        // Sort the valid and aborted transactions based on their position in the original list.
        let position: IndexSet<_> = transactions.iter().map(|tx| tx.id()).collect();
        cfg_sort_by_cached_key!(valid_transactions, |tx| position.get_index_of(&tx.id()));
        cfg_sort_by_cached_key!(aborted_transactions, |tx| position.get_index_of(&tx.0.id()));

        // Return the valid and invalid transactions.
        Ok((valid_transactions, aborted_transactions))
    }

    /// Performs precondition checks on the transaction prior to execution.
    ///
    /// This method is used to check the following conditions:
    /// - If the transaction contains a `credits.aleo/bond_validator` transition,
    ///   then the outcome should not exceed the maximum committee size.
    #[inline]
    fn prepare_for_execution(
        &self,
        state: FinalizeGlobalState,
        store: &FinalizeStore<N, C::FinalizeStorage>,
        execution: &Execution<N>,
    ) -> Result<(), IndexedFinalizeError<N, Command<N>>> {
        // Construct the program ID.
        let program_id = ProgramID::from_str("credits.aleo")?;
        // Construct the committee mapping name.
        let committee_mapping = Identifier::from_str("committee")?;
        // Construct the bond_validator resource name.
        let bond_validator = Identifier::from_str("bond_validator")?;

        // Check if the execution has any `bond_validator` transitions, and collect
        // the unique validator addresses if so.
        // Note: This does not dedup for existing and new validator addresses.
        let bond_validator_addresses: HashSet<_> = execution
            .transitions()
            .filter_map(|transition| match transition.is_bond_validator() {
                // Get the first argument of the transition output if it is a `Future` with a `Plaintext` argument.
                true => match transition.outputs().first() {
                    Some(Output::Future(_, Some(future))) => future.arguments().first().and_then(|arg| match arg {
                        Argument::Plaintext(Plaintext::Literal(Literal::Address(address), _)) => Some(*address),
                        _ => None,
                    }),
                    _ => None,
                },
                false => None,
            })
            .collect();

        // Check if we need to reject the execution if the number of new validators exceeds the maximum committee size.
        match bond_validator_addresses.is_empty() {
            false => {
                // Retrieve the committee members from storage.
                let committee_members = store
                    .get_mapping_speculative(program_id, committee_mapping)?
                    .into_iter()
                    .map(|(key, _)| match key {
                        // Extract the address from the key.
                        Plaintext::Literal(Literal::Address(address), _) => Ok(address),
                        _ => Err(anyhow!("Invalid committee key (missing address) - {key}")),
                    })
                    .collect::<Result<HashSet<_>>>()
                    .into_indexed(
                        Some((program_id, self.process().get_latest_edition_for_program(&program_id))),
                        Some(committee_mapping),
                        None::<(usize, Command<N>)>,
                    )?;
                // Retrieve the latest edition for error context.
                let program_edition = self.process().get_latest_edition_for_program(&program_id);
                // Get the number of new validators being bonded to.
                let num_new_validators =
                    bond_validator_addresses.into_iter().filter(|address| !committee_members.contains(address)).count();
                // Compute the next committee size.
                let next_committee_size = committee_members.len().saturating_add(num_new_validators);
                // Determine the maximum committee size to use.
                let max_committee_size = consensus_config_value!(N, MAX_CERTIFICATES, state.block_height())
                    .ok_or(anyhow!("Failed to retrieve the maximum committee size"))?;
                // Check that the number of new validators being bonded does not exceed the maximum number of validators.
                match next_committee_size > max_committee_size as usize {
                    true => indexed_finalize_bail!(
                        Some((program_id, program_edition)),
                        Some(bond_validator),
                        "Call to '{program_id}/bond_validator' exceeds the committee size"
                    ),
                    false => Ok(()),
                }
            }
            true => Ok(()),
        }
    }

    /// Performs the pre-ratifications before finalizing transactions.
    #[inline]
    fn atomic_pre_ratify<'a>(
        store: &FinalizeStore<N, C::FinalizeStorage>,
        state: FinalizeGlobalState,
        pre_ratifications: impl Iterator<Item = &'a Ratify<N>>,
    ) -> Result<Vec<FinalizeOperation<N>>> {
        // Construct the program ID.
        let program_id = ProgramID::from_str("credits.aleo")?;
        // Construct the committee mapping name.
        let committee_mapping = Identifier::from_str("committee")?;
        // Construct the delegated mapping name.
        let delegated_mapping: Identifier<N> = Identifier::from_str("delegated")?;
        // Construct the bonded mapping name.
        let bonded_mapping = Identifier::from_str("bonded")?;
        // Construct the account mapping name.
        let account_mapping = Identifier::from_str("account")?;
        // Construct the metadata mapping name.
        let metadata_mapping = Identifier::from_str("metadata")?;
        // Construct the withdraw mapping name.
        let withdraw_mapping = Identifier::from_str("withdraw")?;

        // Initialize a list of finalize operations.
        let mut finalize_operations = Vec::new();

        // Initialize a flag for the genesis ratification.
        let mut is_genesis_ratified = false;

        // Iterate over the ratifications.
        for ratify in pre_ratifications {
            match ratify {
                Ratify::Genesis(committee, public_balances, bonded_balances) => {
                    // Ensure this is the genesis block.
                    ensure!(state.block_height() == 0, "Ratify::Genesis(..) expected a genesis block");
                    // Ensure the genesis committee round is 0.
                    ensure!(
                        committee.starting_round() == 0,
                        "Ratify::Genesis(..) expected a genesis committee round of 0"
                    );
                    // Ensure that the number of members in the committee does not exceed the maximum.
                    let max_committee_size = consensus_config_value!(N, MAX_CERTIFICATES, state.block_height())
                        .ok_or(anyhow!("Ratify::Genesis(..) failed to retrieve the maximum committee size"))?;
                    ensure!(
                        committee.members().len() <= max_committee_size as usize,
                        "Ratify::Genesis(..) exceeds the maximum number of committee members"
                    );
                    // Ensure that the number of delegators does not exceed the maximum.
                    ensure!(
                        bonded_balances.len().saturating_sub(committee.members().len()) <= MAX_DELEGATORS as usize,
                        "Ratify::Genesis(..) exceeds the maximum number of delegators"
                    );
                    // Ensure genesis has not been ratified yet.
                    ensure!(!is_genesis_ratified, "Ratify::Genesis(..) has already been ratified");

                    // TODO (howardwu): Consider whether to initialize the mappings here.
                    //  Currently, this is breaking for test cases that use VM but do not insert the genesis block.
                    // // Initialize the store for 'credits.aleo'.
                    // let credits = Program::<N>::credits()?;
                    // for mapping in credits.mappings().values() {
                    //     // Ensure that all mappings are initialized.
                    //     if !store.contains_mapping_confirmed(credits.id(), mapping.name())? {
                    //         // Initialize the mappings for 'credits.aleo'.
                    //         finalize_operations.push(store.initialize_mapping(*credits.id(), *mapping.name())?);
                    //     }
                    // }

                    // Calculate the stake per validator using `bonded_balances`.
                    //
                    // Note: There is no need to check the `delegated` mapping in the genesis block,
                    // because the design of `bonded_balances` by definition does not support
                    // delegating to a non-bonded validator. Thus, the assumption is that the
                    // `delegated` mapping will be correct by construction.
                    let mut stake_per_validator = IndexMap::with_capacity(committee.members().len());
                    for (address, (validator_address, _, amount)) in bonded_balances.iter() {
                        // Check that the amount meets the minimum requirement, depending on whether the address is a validator.
                        if *address == *validator_address {
                            ensure!(
                                *amount >= MIN_VALIDATOR_SELF_STAKE,
                                "Ratify::Genesis(..) the validator {address} must stake at least {MIN_VALIDATOR_SELF_STAKE}",
                            );
                        } else {
                            ensure!(
                                *amount >= MIN_DELEGATOR_STAKE,
                                "Ratify::Genesis(..) the delegator {address} must stake at least {MIN_DELEGATOR_STAKE}",
                            );
                            // If the corresponding validator is not a committee member yet, then continue.
                            if !committee.is_committee_member(*validator_address) {
                                continue;
                            }
                            // If the address is a delegator, check that the corresponding validator is open.
                            ensure!(
                                committee.is_committee_member_open(*validator_address),
                                "Ratify::Genesis(..) the delegator {address} is delegating to a closed validator {validator_address}",
                            );
                        }
                        // Accumulate the staked amount per validator.
                        let total = stake_per_validator.entry(validator_address).or_insert(0u64);
                        *total = total.saturating_add(*amount);
                    }
                    // Ensure the stake per validator matches the committee.
                    ensure!(
                        stake_per_validator.len() == committee.members().len(),
                        "Ratify::Genesis(..) the number of validators in the committee does not match the number of validators in the bonded balances",
                    );

                    // Check that `committee` is consistent with `stake_per_validator`.
                    for (validator_address, amount) in &stake_per_validator {
                        // Retrieve the expected validator stake from the committee.
                        let Some((expected_amount, _, _)) = committee.members().get(*validator_address) else {
                            bail!(
                                "Ratify::Genesis(..) found a validator in the bonded balances that is not in the committee"
                            )
                        };
                        // Ensure the staked amount matches the committee.
                        ensure!(
                            *expected_amount == *amount,
                            "Ratify::Genesis(..) inconsistent staked amount for validator {validator_address}",
                        );
                    }
                    // Ensure that the total stake matches the sum of the staked amounts.
                    ensure!(
                        committee.total_stake() == stake_per_validator.values().sum::<u64>(),
                        "Ratify::Genesis(..) incorrect total total stake for the committee"
                    );

                    // Split the bonded balances into stakers and withdrawal addresses.
                    let (next_stakers, withdrawal_addresses) = bonded_balances.iter().fold(
                        (
                            IndexMap::with_capacity(bonded_balances.len()),
                            IndexMap::with_capacity(bonded_balances.len()),
                        ),
                        |(mut stakers, mut withdrawal_addresses), (staker, (validator, withdrawal_address, amount))| {
                            stakers.insert(*staker, (*validator, *amount));
                            withdrawal_addresses.insert(*staker, *withdrawal_address);
                            (stakers, withdrawal_addresses)
                        },
                    );

                    let next_delegated = to_next_delegated(&next_stakers);

                    // Construct the next committee map and next bonded map.
                    let (next_committee_map, next_bonded_map, next_delegated_map) =
                        to_next_committee_bonded_delegated_map(committee, &next_stakers, &next_delegated);

                    // Construct the next withdraw map.
                    let next_withdraw_map = to_next_withdraw_map(&withdrawal_addresses);

                    // Insert the next committee into storage.
                    store.committee_store().insert(state.block_height(), *(committee.clone()))?;
                    // Store the finalize operations for updating the committee and bonded mapping.
                    finalize_operations.extend(&[
                        // Replace the committee mapping in storage.
                        store.replace_mapping(program_id, committee_mapping, next_committee_map)?,
                        // Replace the delegated mapping in storage.
                        store.replace_mapping(program_id, delegated_mapping, next_delegated_map)?,
                        // Replace the bonded mapping in storage.
                        store.replace_mapping(program_id, bonded_mapping, next_bonded_map)?,
                        // Replace the withdraw mapping in storage.
                        store.replace_mapping(program_id, withdraw_mapping, next_withdraw_map)?,
                    ]);

                    // Update the number of validators.
                    finalize_operations.extend(&[
                        // Update the number of validators in the metadata mapping.
                        store.update_key_value(
                            program_id,
                            metadata_mapping,
                            Plaintext::from_str("aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc")?,
                            Value::from_str(&format!("{}u32", committee.num_members()))?,
                        )?,
                    ]);

                    // Update the number of delegators.
                    finalize_operations.extend(&[
                        // Update the number of delegators in the metadata mapping.
                        store.update_key_value(
                            program_id,
                            metadata_mapping,
                            Plaintext::from_str("aleo1qgqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqanmpl0")?,
                            Value::from_str(&format!(
                                "{}u32",
                                bonded_balances.len().saturating_sub(committee.num_members())
                            ))?,
                        )?,
                    ]);

                    // Map the public balances into the appropriate format.
                    let public_balances = public_balances
                        .iter()
                        .map(|(address, amount)| {
                            (Plaintext::from(Literal::Address(*address)), Value::from(Literal::U64(U64::new(*amount))))
                        })
                        .collect::<Vec<_>>();

                    // Update the public balances.
                    finalize_operations.extend(&[
                        // Update the public balances in storage.
                        store.replace_mapping(program_id, account_mapping, public_balances)?,
                    ]);

                    // Set the genesis ratification flag.
                    is_genesis_ratified = true;
                }
                Ratify::BlockReward(..) | Ratify::PuzzleReward(..) => continue,
            }
        }

        // Return the finalize operations.
        Ok(finalize_operations)
    }

    /// Performs the post-ratifications after finalizing transactions.
    #[inline]
    fn atomic_post_ratify<'a>(
        puzzle: &Puzzle<N>,
        store: &FinalizeStore<N, C::FinalizeStorage>,
        state: FinalizeGlobalState,
        post_ratifications: impl Iterator<Item = &'a Ratify<N>>,
        solutions: &Solutions<N>,
        write_history_json: bool,
    ) -> Result<Vec<FinalizeOperation<N>>> {
        // Construct the program ID.
        let program_id = ProgramID::from_str("credits.aleo")?;
        // Construct the committee mapping name.
        let committee_mapping = Identifier::from_str("committee")?;
        // Construct the delegated mapping name.
        let delegated_mapping = Identifier::from_str("delegated")?;
        // Construct the bonded mapping name.
        let bonded_mapping = Identifier::from_str("bonded")?;
        // Construct the account mapping name.
        let account_mapping = Identifier::from_str("account")?;

        // Initialize a list of finalize operations.
        let mut finalize_operations = Vec::new();

        // Initialize a flag for the block reward ratification.
        let mut is_block_reward_ratified = false;
        // Initialize a flag for the puzzle reward ratification.
        let mut is_puzzle_reward_ratified = false;

        // Iterate over the ratifications.
        for ratify in post_ratifications {
            match ratify {
                Ratify::Genesis(..) => continue,
                Ratify::BlockReward(block_reward) => {
                    // Ensure the block reward has not been ratified yet.
                    ensure!(!is_block_reward_ratified, "Ratify::BlockReward(..) has already been ratified");

                    // Retrieve the committee mapping from storage.
                    let current_committee_map = store.get_mapping_speculative(program_id, committee_mapping)?;
                    // Retrieve the delegator mapping from storage.
                    let current_delegator_map = store.get_mapping_speculative(program_id, delegated_mapping)?;
                    // Convert the committee mapping into a committee.
                    let current_committee = committee_and_delegated_maps_into_committee(
                        state.block_round(),
                        current_committee_map,
                        current_delegator_map,
                    )?;
                    // Retrieve the bonded mapping from storage.
                    let current_bonded_map = store.get_mapping_speculative(program_id, bonded_mapping)?;
                    // Convert the bonded map into stakers.
                    let current_stakers = bonded_map_into_stakers(current_bonded_map)?;

                    // Ensure the committee matches the bonded mapping.
                    ensure_stakers_matches(&current_committee, &current_stakers)?;

                    // Compute the updated stakers, using the committee and block reward.
                    let next_stakers = staking_rewards(&current_stakers, &current_committee, *block_reward);

                    // Compute the updated delegated amounts, using the next_stakers updated amounts.
                    let next_delegated = to_next_delegated(&next_stakers);

                    // Compute the updated committee, using the delegatees.
                    let next_committee = to_next_committee(&current_committee, state.block_round(), &next_delegated)?;

                    // Construct the next committee map, the next bonded map, and the next delegated map.
                    let (next_committee_map, next_bonded_map, next_delegated_map) =
                        to_next_committee_bonded_delegated_map(&next_committee, &next_stakers, &next_delegated);

                    // Insert the next committee into storage.
                    store.committee_store().insert(state.block_height(), next_committee)?;

                    // Canonical finalize writes the credits.aleo snapshots for this block.
                    // A failed write is reported and the block continues. A later finalize of this
                    // height overwrites any files left by an attempt that did not become canonical.
                    if write_history_json {
                        let height = state.block_height();
                        let written = (|| -> Result<()> {
                            let history = History::new(N::ID, store.storage_mode());
                            history.store_mapping(height, MappingName::Delegated, &next_delegated_map)?;
                            history.store_mapping(height, MappingName::Bonded, &next_bonded_map)?;
                            let metadata_mapping = Identifier::from_str("metadata")?;
                            let metadata_map = store.get_mapping_speculative(program_id, metadata_mapping)?;
                            history.store_mapping(height, MappingName::Metadata, &metadata_map)?;
                            let unbonding_mapping = Identifier::from_str("unbonding")?;
                            let unbonding_map = store.get_mapping_speculative(program_id, unbonding_mapping)?;
                            history.store_mapping(height, MappingName::Unbonding, &unbonding_map)?;
                            let withdraw_mapping = Identifier::from_str("withdraw")?;
                            let withdraw_map = store.get_mapping_speculative(program_id, withdraw_mapping)?;
                            history.store_mapping(height, MappingName::Withdraw, &withdraw_map)?;
                            let rewards = staking_rewards_historical_mapping(&current_stakers, &next_stakers);
                            history.store_mapping(height, MappingName::StakingRewards, &rewards)?;
                            Ok(())
                        })();
                        if let Err(error) = written {
                            warn!("Failed to write JSON history for block {height}: {error}");
                        }
                    }

                    // Store the finalize operations for updating the committee and bonded mapping.
                    finalize_operations.extend(&[
                        // Replace the committee mapping in storage.
                        store.replace_mapping(program_id, committee_mapping, next_committee_map)?,
                        // Replace the delegated mapping in storage.
                        store.replace_mapping(program_id, delegated_mapping, next_delegated_map)?,
                        // Replace the bonded mapping in storage.
                        store.replace_mapping(program_id, bonded_mapping, next_bonded_map)?,
                    ]);

                    // Set the block reward ratification flag.
                    is_block_reward_ratified = true;
                }
                Ratify::PuzzleReward(puzzle_reward) => {
                    // Ensure the puzzle reward has not been ratified yet.
                    ensure!(!is_puzzle_reward_ratified, "Ratify::PuzzleReward(..) has already been ratified");

                    // If the puzzle reward is zero, skip.
                    if *puzzle_reward == 0 {
                        continue;
                    }
                    // Retrieve the solutions.
                    let Some(solutions) = solutions.deref() else {
                        continue;
                    };
                    // Compute the proof targets, with the corresponding addresses.
                    let proof_targets = solutions
                        .values()
                        .map(|s| Ok((s.address(), puzzle.get_proof_target(s)?)))
                        .collect::<Result<Vec<_>>>()?;
                    // Calculate the proving rewards.
                    let proving_rewards = proving_rewards(proof_targets, *puzzle_reward);
                    // Iterate over the proving rewards.
                    for (address, amount) in proving_rewards {
                        // Construct the key.
                        let key = Plaintext::from(Literal::Address(address));
                        // Retrieve the current public balance.
                        let value = store.get_value_speculative(program_id, account_mapping, &key)?;
                        // Compute the next public balance.
                        let next_value = Value::from(Literal::U64(U64::new(match value {
                            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(value), _))) => {
                                (*value).saturating_add(amount)
                            }
                            None => amount,
                            v => bail!("Critical bug in post-ratify puzzle reward- Invalid amount ({v:?})"),
                        })));
                        // Update the public balance in finalize storage.
                        let operation = store.update_key_value(program_id, account_mapping, key, next_value)?;
                        finalize_operations.push(operation);
                    }

                    // Set the puzzle reward ratification flag.
                    is_puzzle_reward_ratified = true;
                }
            }
        }

        // Return the finalize operations.
        Ok(finalize_operations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{
        test_helpers,
        test_helpers::{sample_finalize_state, sample_vm},
    };
    use console::{
        account::{Address, PrivateKey, ViewKey},
        program::{Ciphertext, Entry, Record},
        types::Field,
    };
    use snarkvm_ledger_block::{Block, Header, Metadata, Transaction, Transition};
    use snarkvm_ledger_committee::{MAX_DELEGATORS, MIN_VALIDATOR_STAKE};
    use snarkvm_synthesizer_program::Program;

    use rand::distr::SampleString;

    type CurrentNetwork = test_helpers::CurrentNetwork;
    #[cfg(not(feature = "rocks"))]
    type LedgerType = snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>;
    #[cfg(feature = "rocks")]
    type LedgerType = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>;

    /// Sample a new program and deploy it to the VM. Returns the program name.
    fn new_program_deployment<R: Rng + CryptoRng>(
        vm: &VM<CurrentNetwork, LedgerType>,
        private_key: &PrivateKey<CurrentNetwork>,
        previous_block: &Block<CurrentNetwork>,
        unspent_records: &mut Vec<Record<CurrentNetwork, Ciphertext<CurrentNetwork>>>,
        rng: &mut R,
    ) -> Result<(String, Block<CurrentNetwork>)> {
        let program_name = format!("a{}.aleo", Alphanumeric.sample_string(rng, 8).to_lowercase());

        let program = Program::<CurrentNetwork>::from_str(&format!(
            "
program {program_name};

mapping account:
    // The token owner.
    key as address.public;
    // The token amount.
    value as u64.public;

function mint_public:
    input r0 as address.public;
    input r1 as u64.public;
    async mint_public r0 r1 into r2;
    output r2 as {program_name}/mint_public.future;

finalize mint_public:
    input r0 as address.public;
    input r1 as u64.public;

    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];

function transfer_public:
    input r0 as address.public;
    input r1 as u64.public;
    async transfer_public self.caller r0 r1 into r2;
    output r2 as {program_name}/transfer_public.future;

finalize transfer_public:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.public;

    get.or_use account[r0] 0u64 into r3;
    get.or_use account[r1] 0u64 into r4;

    sub r3 r2 into r5;
    add r4 r2 into r6;

    set r5 into account[r0];
    set r6 into account[r1];"
        ))?;

        // Prepare the additional fee.
        let view_key = ViewKey::<CurrentNetwork>::try_from(private_key)?;
        let credits = Some(unspent_records.pop().unwrap().decrypt(&view_key)?);

        // Deploy.
        let transaction = vm.deploy(private_key, &program, credits, 10, None, rng)?;

        // Construct the new block.
        let next_block = sample_next_block(vm, private_key, &[transaction], previous_block, unspent_records, rng)?;

        Ok((program_name, next_block))
    }

    /// Construct a new block based on the given transactions.
    fn sample_next_block<R: Rng + CryptoRng>(
        vm: &VM<CurrentNetwork, LedgerType>,
        private_key: &PrivateKey<CurrentNetwork>,
        transactions: &[Transaction<CurrentNetwork>],
        previous_block: &Block<CurrentNetwork>,
        unspent_records: &mut Vec<Record<CurrentNetwork, Ciphertext<CurrentNetwork>>>,
        rng: &mut R,
    ) -> Result<Block<CurrentNetwork>> {
        // Create the finalize state for the next block height.
        let next_block_height = previous_block.height() + 1;
        let time_since_last_block = MainnetV0::BLOCK_TIME as i64;
        let next_block_timestamp = previous_block.timestamp().saturating_add(time_since_last_block);
        let next_timestamp = (next_block_height
            >= MainnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default())
        .then_some(next_block_timestamp);
        let finalize_state = FinalizeGlobalState::from(
            next_block_height as u64,
            next_block_height,
            next_timestamp,
            [0u8; 32],
            None,
            None,
        );

        // Speculate on the candidate ratifications, solutions, and transactions.
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) = vm.speculate(
            finalize_state,
            time_since_last_block,
            Some(0u64),
            vec![],
            &None.into(),
            transactions.iter(),
            rng,
        )?;

        // Construct the metadata associated with the block.
        let metadata = Metadata::new(
            CurrentNetwork::ID,
            previous_block.round() + 1,
            previous_block.height() + 1,
            0,
            0,
            CurrentNetwork::GENESIS_COINBASE_TARGET,
            CurrentNetwork::GENESIS_PROOF_TARGET,
            previous_block.last_coinbase_target(),
            previous_block.last_coinbase_timestamp(),
            next_block_timestamp,
        )?;

        // Construct the new block header.
        let header = Header::from(
            vm.block_store().current_state_root(),
            transactions.to_transactions_root().unwrap(),
            transactions.to_finalize_root(ratified_finalize_operations).unwrap(),
            ratifications.to_ratifications_root().unwrap(),
            Field::zero(),
            Field::zero(),
            metadata,
        )?;

        let block = Block::new_beacon(
            private_key,
            previous_block.hash(),
            header,
            ratifications,
            None.into(),
            vec![],
            transactions,
            aborted_transaction_ids,
            rng,
        )?;

        // Track the new records.
        let new_records = block
            .transitions()
            .cloned()
            .flat_map(Transition::into_records)
            .map(|(_, record)| record)
            .collect::<Vec<_>>();
        unspent_records.extend(new_records);

        Ok(block)
    }

    /// Generate split transactions for the unspent records.
    fn generate_splits<R: Rng + CryptoRng>(
        vm: &VM<CurrentNetwork, LedgerType>,
        private_key: &PrivateKey<CurrentNetwork>,
        previous_block: &Block<CurrentNetwork>,
        unspent_records: &mut Vec<Record<CurrentNetwork, Ciphertext<CurrentNetwork>>>,
        rng: &mut R,
    ) -> Result<Block<CurrentNetwork>> {
        // Prepare the additional fee.
        let view_key = ViewKey::<CurrentNetwork>::try_from(private_key)?;

        // Generate split transactions.
        let mut transactions = Vec::new();
        while !unspent_records.is_empty() {
            let record = unspent_records.pop().unwrap().decrypt(&view_key)?;

            // Fetch the record balance and divide it in half.
            let split_balance = match record.find(&[Identifier::from_str("microcredits")?]) {
                Ok(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => *amount / 2,
                _ => bail!("fee record does not contain a microcredits entry"),
            };

            // Prepare the inputs.
            let inputs = [
                Value::<CurrentNetwork>::Record(record),
                Value::<CurrentNetwork>::from_str(&format!("{split_balance}u64")).unwrap(),
            ]
            .into_iter();

            // Execute.
            let transaction = vm.execute(private_key, ("credits.aleo", "split"), inputs, None, 0, None, rng).unwrap();

            transactions.push(transaction);
        }

        // Construct the new block.
        sample_next_block(vm, private_key, &transactions, previous_block, unspent_records, rng)
    }

    /// Create an execution transaction.
    fn create_execution(
        vm: &VM<CurrentNetwork, LedgerType>,
        caller_private_key: PrivateKey<CurrentNetwork>,
        program_id: &str,
        function_name: &str,
        inputs: Vec<Value<CurrentNetwork>>,
        unspent_records: &mut Vec<Record<CurrentNetwork, Ciphertext<CurrentNetwork>>>,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        assert!(vm.contains_program(&ProgramID::from_str(program_id).unwrap()));

        // Prepare the additional fee.
        let view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
        let unspent_record = unspent_records.pop().unwrap();
        let credits = Some(unspent_record.decrypt(&view_key).unwrap());

        // Execute.
        let transaction = vm
            .execute(&caller_private_key, (program_id, function_name), inputs.into_iter(), credits, 1, None, rng)
            .unwrap();
        // Verify.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Return the transaction.
        transaction
    }

    /// Sample a public mint transaction.
    fn sample_mint_public(
        vm: &VM<CurrentNetwork, LedgerType>,
        caller_private_key: PrivateKey<CurrentNetwork>,
        program_id: &str,
        recipient: Address<CurrentNetwork>,
        amount: u64,
        unspent_records: &mut Vec<Record<CurrentNetwork, Ciphertext<CurrentNetwork>>>,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let inputs = vec![
            Value::<CurrentNetwork>::from_str(&recipient.to_string()).unwrap(),
            Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap(),
        ];

        create_execution(vm, caller_private_key, program_id, "mint_public", inputs, unspent_records, rng)
    }

    /// Sample a public transfer transaction.
    fn sample_transfer_public(
        vm: &VM<CurrentNetwork, LedgerType>,
        caller_private_key: PrivateKey<CurrentNetwork>,
        program_id: &str,
        recipient: Address<CurrentNetwork>,
        amount: u64,
        unspent_records: &mut Vec<Record<CurrentNetwork, Ciphertext<CurrentNetwork>>>,
        rng: &mut TestRng,
    ) -> Transaction<CurrentNetwork> {
        let inputs = vec![
            Value::<CurrentNetwork>::from_str(&recipient.to_string()).unwrap(),
            Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap(),
        ];

        create_execution(vm, caller_private_key, program_id, "transfer_public", inputs, unspent_records, rng)
    }

    /// A helper method to construct the rejected transaction format for `atomic_finalize`.
    fn reject(
        index: u32,
        transaction: &Transaction<CurrentNetwork>,
        finalize: &[FinalizeOperation<CurrentNetwork>],
    ) -> ConfirmedTransaction<CurrentNetwork> {
        match transaction {
            Transaction::Execute(_, _, execution, fee) => ConfirmedTransaction::RejectedExecute(
                index,
                Transaction::from_fee(fee.clone().unwrap()).unwrap(),
                Rejected::new_execution(*execution.clone()),
                finalize.to_vec(),
            ),
            _ => panic!("only reject execution transactions"),
        }
    }

    /// Samples the validators.
    fn sample_validators<N: Network>(
        num_validators: usize,
        rng: &mut TestRng,
    ) -> IndexMap<PrivateKey<N>, (u64, bool, u8)> {
        (0..num_validators)
            .map(|_| {
                let private_key = PrivateKey::new(rng).unwrap();
                let amount = MIN_VALIDATOR_STAKE;
                let is_open = true;
                let commission: u8 = 0;
                (private_key, (amount, is_open, commission))
            })
            .collect::<IndexMap<_, _>>()
    }

    /// Returns a `committee_map` and the `allocated_amount` given the validators and delegators.
    fn sample_committee_map_and_allocated_amount<N: Network>(
        validators: &IndexMap<PrivateKey<N>, (u64, bool, u8)>,
        delegators: &IndexMap<PrivateKey<N>, (Address<N>, u64)>,
    ) -> (IndexMap<Address<N>, (u64, bool, u8)>, u64) {
        // Reset the tracked amount.
        let mut allocated_amount = 0;

        // Construct the **correct** committee.
        let mut committee_map = IndexMap::new();
        for (private_key, (amount, is_open, commission)) in validators {
            let address = Address::try_from(private_key).unwrap();
            committee_map.insert(address, (*amount, *is_open, *commission));
            allocated_amount += amount;
        }
        for (delegator, (validator, amount)) in delegators {
            if let indexmap::map::Entry::Occupied(mut entry) = committee_map.entry(*validator) {
                let (current_amount, is_open, commission) = entry.get();
                // Ensure the validator is open.
                assert!(*is_open, "delegator {delegator} is delegating {amount} microcredits to a closed validator");
                // Update the committee map.
                entry.insert((current_amount + amount, *is_open, *commission));
            } else {
                unreachable!("delegator {delegator} is delegating to a closed validator")
            }
            // Accumulate the allocated amount.
            allocated_amount += amount;
        }

        (committee_map, allocated_amount)
    }

    /// Returns the `bonded_balances` given the validators and delegators.
    /// Note that the withdrawal address is the same as the staker address.
    fn sample_bonded_balances<N: Network>(
        validators: &IndexMap<PrivateKey<N>, (u64, bool, u8)>,
        delegators: &IndexMap<PrivateKey<N>, (Address<N>, u64)>,
    ) -> IndexMap<Address<N>, (Address<N>, Address<N>, u64)> {
        let mut bonded_balances = IndexMap::with_capacity(validators.len() + delegators.len());
        for (private_key, (amount, _, _)) in validators {
            let address = Address::try_from(private_key).unwrap();
            bonded_balances.insert(address, (address, address, *amount));
        }
        for (private_key, (validator, amount)) in delegators {
            let address = Address::try_from(private_key).unwrap();
            bonded_balances.insert(address, (*validator, address, *amount));
        }
        bonded_balances
    }

    /// Returns the `public_balances` given the addresses and total amount.
    /// Note that the balances are evenly distributed among the addresses.
    fn sample_public_balances<N: Network>(addresses: &[Address<N>], total_amount: u64) -> IndexMap<Address<N>, u64> {
        // Check that the addresses are not empty.
        assert!(!addresses.is_empty(), "must provide at least one address");
        // Distribute the total amount evenly among the addresses.
        let amount_per_address = total_amount / addresses.len() as u64;
        let mut public_balances: IndexMap<_, _> =
            addresses.iter().map(|address| (*address, amount_per_address)).collect();
        // Distribute the remainder to the first address.
        let remaining = total_amount % addresses.len() as u64;
        if remaining > 0 {
            *public_balances.get_mut(&addresses[0]).unwrap() += remaining;
        }
        // Return the public balances.
        public_balances
    }

    #[test]
    fn test_finalize_duplicate_deployment() {
        let rng = &mut TestRng::default();

        let vm = crate::vm::test_helpers::sample_vm();

        // Fetch a deployment transaction.
        let deployment_transaction = crate::vm::test_helpers::sample_deployment_transaction(rng);
        let deployment_transaction_id = deployment_transaction.id();

        // Construct the program name.
        let program_id = ProgramID::from_str("testing.aleo").unwrap();

        // Prepare the confirmed transactions.
        let (ratifications, confirmed_transactions, aborted_transaction_ids, _) = vm
            .speculate(
                sample_finalize_state(1),
                CurrentNetwork::BLOCK_TIME as i64,
                None,
                vec![],
                &None.into(),
                [deployment_transaction.clone()].iter(),
                rng,
            )
            .unwrap();
        assert_eq!(confirmed_transactions.len(), 1);
        assert!(aborted_transaction_ids.is_empty());

        // Ensure the VM does not contain this program.
        assert!(!vm.contains_program(&program_id));

        // Finalize the transaction.
        assert!(vm.finalize(sample_finalize_state(1), &ratifications, &None.into(), &confirmed_transactions).is_ok());

        // Ensure the VM contains this program.
        assert!(vm.contains_program(&program_id));

        // Ensure the VM can't redeploy the same transaction.
        assert!(vm.finalize(sample_finalize_state(1), &ratifications, &None.into(), &confirmed_transactions).is_err());

        // Ensure the VM contains this program.
        assert!(vm.contains_program(&program_id));

        // Ensure the dry run of the redeployment will cause a reject transaction to be created.
        let (_, candidate_transactions, aborted_transaction_ids, _) = vm
            .atomic_speculate(
                sample_finalize_state(1),
                CurrentNetwork::BLOCK_TIME as i64,
                None,
                vec![],
                None.into(),
                vec![deployment_transaction],
            )
            .unwrap();
        assert_eq!(candidate_transactions.len(), 1);
        assert!(matches!(candidate_transactions[0], ConfirmedTransaction::RejectedDeploy(..)));
        assert!(aborted_transaction_ids.is_empty());

        // Check that the unconfirmed transaction ID of the rejected deployment is correct.
        assert_eq!(candidate_transactions[0].to_unconfirmed_transaction_id().unwrap(), deployment_transaction_id);
    }

    #[test]
    fn test_bond_validator_above_maximum_fails() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Initialize the validators with the maximum number of validators.
        let validators = sample_validators::<CurrentNetwork>(
            consensus_config_value!(CurrentNetwork, MAX_CERTIFICATES, 0).unwrap() as usize,
            rng,
        );

        // Initialize a new address.
        let new_validator_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let new_validator_address = Address::try_from(&new_validator_private_key).unwrap();

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) =
            sample_committee_map_and_allocated_amount(&validators, &IndexMap::new());

        // Collect all of the addresses in a single place
        let validator_addresses =
            validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>();

        // Construct the public balances, allocating the remaining supply.
        let new_validator_balance = MIN_VALIDATOR_STAKE + 100_000_000;
        let mut public_balances = sample_public_balances(
            &validator_addresses,
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount - new_validator_balance,
        );
        // Set the public balance of the new validator to the minimum validator stake.
        public_balances.insert(new_validator_address, new_validator_balance);

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &IndexMap::new());

        // Construct the genesis block, which should pass.
        let block = vm
            .genesis_quorum(
                validators.keys().next().unwrap(),
                Committee::new_genesis(committee_map).unwrap(),
                public_balances,
                bonded_balances,
                rng,
            )
            .unwrap();

        // Add the block.
        vm.add_next_block(&block).unwrap();

        // Attempt to bond a new validator above the maximum number of validators.
        let inputs = vec![
            Value::<CurrentNetwork>::from_str(&validator_addresses.first().unwrap().to_string()).unwrap(), // Withdrawal address
            Value::<CurrentNetwork>::from_str(&format!("{MIN_VALIDATOR_STAKE}u64")).unwrap(),              // Amount
            Value::<CurrentNetwork>::from_str("42u8").unwrap(),                                            // Commission
        ];

        // Execute.
        let bond_validator_transaction = vm
            .execute(
                &new_validator_private_key,
                ("credits.aleo", "bond_validator"),
                inputs.into_iter(),
                None,
                1,
                None,
                rng,
            )
            .unwrap();

        // Verify.
        vm.check_transaction(&bond_validator_transaction, None, rng).unwrap();

        // Speculate on the transactions.
        let transactions = vec![bond_validator_transaction.clone()];
        let (_, confirmed_transactions, _, _) = vm
            .atomic_speculate(
                sample_finalize_state(1),
                CurrentNetwork::BLOCK_TIME as i64,
                None,
                vec![],
                None.into(),
                transactions,
            )
            .unwrap();

        // Assert that the transaction is rejected.
        assert_eq!(confirmed_transactions.len(), 1);
        assert_eq!(
            confirmed_transactions[0],
            reject(0, &bond_validator_transaction, confirmed_transactions[0].finalize_operations())
        );
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_genesis_num_validators_does_not_exceed_maximum_before_v3() {
        // This test will fail if the consensus v3 height is 0
        assert_ne!(0, CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V3).unwrap());

        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // TODO: Fix this test by adding additional constraints to `Committee::new_genesis`
        // Initialize more validators than the maximum committee size. `Committee::new_genesis`
        // bounds the committee by `LATEST_MAX_CERTIFICATES`, not by the limit at height 0.
        let validators =
            sample_validators::<CurrentNetwork>(Committee::<CurrentNetwork>::max_committee_size() as usize + 1, rng);

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, _allocated_amount) =
            sample_committee_map_and_allocated_amount(&validators, &IndexMap::new());

        assert!(Committee::new_genesis(committee_map).is_err());
    }

    #[cfg(not(feature = "test"))]
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_migration_v3_maximum_validator_increase() {
        // This test will fail if the consensus v3 height is 0
        assert_ne!(0, CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V3).unwrap());

        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Initialize the validators with the maximum number of validators before consensus v3.
        let validators = sample_validators::<CurrentNetwork>(
            consensus_config_value!(CurrentNetwork, MAX_CERTIFICATES, 0).unwrap() as usize,
            rng,
        );

        // Initialize a new address.
        let new_validator_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let new_validator_address = Address::try_from(&new_validator_private_key).unwrap();

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) =
            sample_committee_map_and_allocated_amount(&validators, &IndexMap::new());

        // Collect all of the addresses in a single place
        let validator_addresses =
            validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>();

        // Construct the public balances, allocating the remaining supply.
        let new_validator_balance = MIN_VALIDATOR_STAKE + 100_000_000;
        let mut public_balances = sample_public_balances(
            &validator_addresses,
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount - new_validator_balance,
        );
        // Set the public balance of the new validator to the minimum validator stake.
        public_balances.insert(new_validator_address, new_validator_balance);

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &IndexMap::new());

        // Construct the genesis block, which should pass.
        let block = vm
            .genesis_quorum(
                validators.keys().next().unwrap(),
                Committee::new_genesis(committee_map).unwrap(),
                public_balances,
                bonded_balances,
                rng,
            )
            .unwrap();

        // Add the block.
        vm.add_next_block(&block).unwrap();

        // Attempt to bond a new validator above the maximum number of validators.
        let inputs = vec![
            Value::<CurrentNetwork>::from_str(&validator_addresses.first().unwrap().to_string()).unwrap(), // Withdrawal address
            Value::<CurrentNetwork>::from_str(&format!("{MIN_VALIDATOR_STAKE}u64")).unwrap(),              // Amount
            Value::<CurrentNetwork>::from_str("42u8").unwrap(),                                            // Commission
        ];

        // Execute.
        let bond_validator_transaction = vm
            .execute(
                &new_validator_private_key,
                ("credits.aleo", "bond_validator"),
                inputs.clone().into_iter(),
                None,
                1,
                None,
                rng,
            )
            .unwrap();

        // Verify.
        vm.check_transaction(&bond_validator_transaction, None, rng).unwrap();

        // Speculate on the transactions.
        let transactions = vec![bond_validator_transaction.clone()];
        let (_, confirmed_transactions, _, _) = vm
            .atomic_speculate(
                sample_finalize_state(1),
                CurrentNetwork::BLOCK_TIME as i64,
                None,
                vec![],
                None.into(),
                transactions,
            )
            .unwrap();

        // Assert that the transaction is rejected.
        assert_eq!(confirmed_transactions.len(), 1);
        assert_eq!(
            confirmed_transactions[0],
            reject(0, &bond_validator_transaction, confirmed_transactions[0].finalize_operations())
        );

        // Speculate on the transactions.
        let transactions = vec![bond_validator_transaction.clone()];
        let (_, confirmed_transactions, aborted_transaction_ids, _) = vm
            .atomic_speculate(
                sample_finalize_state(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V3).unwrap()),
                CurrentNetwork::BLOCK_TIME as i64,
                None,
                vec![],
                None.into(),
                transactions,
            )
            .unwrap();

        // Assert that the transaction is accepted.
        assert_eq!(confirmed_transactions.len(), 1);
        assert!(confirmed_transactions[0].is_accepted());
        assert!(aborted_transaction_ids.is_empty());

        assert_eq!(confirmed_transactions[0].transaction(), &bond_validator_transaction);
    }

    #[test]
    #[ignore]
    fn test_atomic_finalize_many() {
        let rng = &mut TestRng::default();

        // Sample a private key and address for the caller.
        let caller_private_key = test_helpers::sample_genesis_private_key(rng);
        let caller_address = Address::try_from(&caller_private_key).unwrap();

        // Sample a private key and address for the recipient.
        let recipient_private_key = PrivateKey::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize the vm.
        let vm = test_helpers::sample_vm_with_genesis_block(rng);

        // Deploy a new program.
        let genesis =
            vm.block_store().get_block(&vm.block_store().get_block_hash(0).unwrap().unwrap()).unwrap().unwrap();

        // Get the unspent records.
        let mut unspent_records = genesis
            .transitions()
            .cloned()
            .flat_map(Transition::into_records)
            .map(|(_, record)| record)
            .collect::<Vec<_>>();

        // Construct the deployment block.
        let (program_id, deployment_block) =
            new_program_deployment(&vm, &caller_private_key, &genesis, &mut unspent_records, rng).unwrap();

        // Add the deployment block to the VM.
        vm.add_next_block(&deployment_block).unwrap();

        // Generate more records to use for the next block.
        let splits_block =
            generate_splits(&vm, &caller_private_key, &deployment_block, &mut unspent_records, rng).unwrap();

        // Add the splits block to the VM.
        vm.add_next_block(&splits_block).unwrap();

        // Construct the initial mint.
        let initial_mint =
            sample_mint_public(&vm, caller_private_key, &program_id, caller_address, 20, &mut unspent_records, rng);
        let initial_mint_block =
            sample_next_block(&vm, &caller_private_key, &[initial_mint], &splits_block, &mut unspent_records, rng)
                .unwrap();

        // Add the block to the vm.
        vm.add_next_block(&initial_mint_block).unwrap();

        // Construct a mint and a transfer.
        let mint_10 =
            sample_mint_public(&vm, caller_private_key, &program_id, caller_address, 10, &mut unspent_records, rng);
        let mint_20 =
            sample_mint_public(&vm, caller_private_key, &program_id, caller_address, 20, &mut unspent_records, rng);
        let transfer_10 = sample_transfer_public(
            &vm,
            caller_private_key,
            &program_id,
            recipient_address,
            10,
            &mut unspent_records,
            rng,
        );
        let transfer_20 = sample_transfer_public(
            &vm,
            caller_private_key,
            &program_id,
            recipient_address,
            20,
            &mut unspent_records,
            rng,
        );
        let transfer_30 = sample_transfer_public(
            &vm,
            caller_private_key,
            &program_id,
            recipient_address,
            30,
            &mut unspent_records,
            rng,
        );

        // TODO (raychu86): Confirm that the finalize_operations here are correct.

        // Starting Balance = 20
        // Mint_10 -> Balance = 20 + 10  = 30
        // Transfer_10 -> Balance = 30 - 10 = 20
        // Transfer_20 -> Balance = 20 - 20 = 0
        {
            let transactions = vec![mint_10.clone(), transfer_10.clone(), transfer_20.clone()];
            let (_, confirmed_transactions, aborted_transaction_ids, _) = vm
                .atomic_speculate(
                    sample_finalize_state(1),
                    CurrentNetwork::BLOCK_TIME as i64,
                    None,
                    vec![],
                    None.into(),
                    transactions,
                )
                .unwrap();

            // Assert that all the transactions are accepted.
            assert_eq!(confirmed_transactions.len(), 3);
            confirmed_transactions.iter().for_each(|confirmed_tx| assert!(confirmed_tx.is_accepted()));
            assert!(aborted_transaction_ids.is_empty());

            assert_eq!(confirmed_transactions[0].transaction(), &mint_10);
            assert_eq!(confirmed_transactions[1].transaction(), &transfer_10);
            assert_eq!(confirmed_transactions[2].transaction(), &transfer_20);
        }

        // Starting Balance = 20
        // Transfer_20 -> Balance = 20 - 20 = 0
        // Mint_10 -> Balance = 0 + 10 = 10
        // Mint_20 -> Balance = 10 + 20 = 30
        // Transfer_30 -> Balance = 30 - 30 = 0
        {
            let transactions = vec![transfer_20.clone(), mint_10.clone(), mint_20.clone(), transfer_30.clone()];
            let (_, confirmed_transactions, aborted_transaction_ids, _) = vm
                .atomic_speculate(
                    sample_finalize_state(1),
                    CurrentNetwork::BLOCK_TIME as i64,
                    None,
                    vec![],
                    None.into(),
                    transactions,
                )
                .unwrap();

            // Assert that all the transactions are accepted.
            assert_eq!(confirmed_transactions.len(), 4);
            confirmed_transactions.iter().for_each(|confirmed_tx| assert!(confirmed_tx.is_accepted()));
            assert!(aborted_transaction_ids.is_empty());

            // Ensure that the transactions are in the correct order.
            assert_eq!(confirmed_transactions[0].transaction(), &transfer_20);
            assert_eq!(confirmed_transactions[1].transaction(), &mint_10);
            assert_eq!(confirmed_transactions[2].transaction(), &mint_20);
            assert_eq!(confirmed_transactions[3].transaction(), &transfer_30);
        }

        // Starting Balance = 20
        // Transfer_20 -> Balance = 20 - 20 = 0
        // Transfer_10 -> Balance = 0 - 10 = -10 (should be rejected)
        {
            let transactions = vec![transfer_20.clone(), transfer_10.clone()];
            let (_, confirmed_transactions, aborted_transaction_ids, _) = vm
                .atomic_speculate(
                    sample_finalize_state(1),
                    CurrentNetwork::BLOCK_TIME as i64,
                    None,
                    vec![],
                    None.into(),
                    transactions,
                )
                .unwrap();

            // Assert that the accepted and rejected transactions are correct.
            assert_eq!(confirmed_transactions.len(), 2);
            assert!(aborted_transaction_ids.is_empty());

            assert!(confirmed_transactions[0].is_accepted());
            assert!(confirmed_transactions[1].is_rejected());

            assert_eq!(confirmed_transactions[0].transaction(), &transfer_20);
            assert_eq!(
                confirmed_transactions[1],
                reject(1, &transfer_10, confirmed_transactions[1].finalize_operations())
            );
        }

        // Starting Balance = 20
        // Mint_20 -> Balance = 20 + 20
        // Transfer_30 -> Balance = 40 - 30 = 10
        // Transfer_20 -> Balance = 10 - 20 = -10 (should be rejected)
        // Transfer_10 -> Balance = 10 - 10 = 0
        {
            let transactions = vec![mint_20.clone(), transfer_30.clone(), transfer_20.clone(), transfer_10.clone()];
            let (_, confirmed_transactions, aborted_transaction_ids, _) = vm
                .atomic_speculate(
                    sample_finalize_state(1),
                    CurrentNetwork::BLOCK_TIME as i64,
                    None,
                    vec![],
                    None.into(),
                    transactions,
                )
                .unwrap();

            // Assert that the accepted and rejected transactions are correct.
            assert_eq!(confirmed_transactions.len(), 4);
            assert!(aborted_transaction_ids.is_empty());

            assert!(confirmed_transactions[0].is_accepted());
            assert!(confirmed_transactions[1].is_accepted());
            assert!(confirmed_transactions[2].is_rejected());
            assert!(confirmed_transactions[3].is_accepted());

            assert_eq!(confirmed_transactions[0].transaction(), &mint_20);
            assert_eq!(confirmed_transactions[1].transaction(), &transfer_30);
            assert_eq!(
                confirmed_transactions[2],
                reject(2, &transfer_20, confirmed_transactions[2].finalize_operations())
            );
            assert_eq!(confirmed_transactions[3].transaction(), &transfer_10);
        }
    }

    #[test]
    #[ignore]
    fn test_finalize_catch_halt() {
        let rng = &mut TestRng::default();

        // Sample a private key, view key, and address for the caller.
        let caller_private_key = test_helpers::sample_genesis_private_key(rng);
        let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

        for finalize_logic in &[
            "finalize ped_hash:
    input r0 as u128.public;
    hash.ped64 r0 into r1 as field;
    set r1 into hashes[r0];",
            "finalize ped_hash:
    input r0 as u128.public;
    div r0 0u128 into r1;",
        ] {
            // Initialize the vm.
            let vm = test_helpers::sample_vm_with_genesis_block(rng);

            // Deploy a new program.
            let genesis =
                vm.block_store().get_block(&vm.block_store().get_block_hash(0).unwrap().unwrap()).unwrap().unwrap();

            // Get the unspent records.
            let mut unspent_records = genesis
                .transitions()
                .cloned()
                .flat_map(Transition::into_records)
                .map(|(_, record)| record)
                .collect::<Vec<_>>();

            // Create a program that will always cause a E::halt in the finalize execution.
            let program_id = "testing.aleo";
            let program = Program::<CurrentNetwork>::from_str(&format!(
                "
program {program_id};

mapping hashes:
    key as u128.public;
    value as field.public;

function ped_hash:
    input r0 as u128.public;
    // hash.ped64 r0 into r1 as field; // <--- This will cause a E::halt.
    async ped_hash r0 into r1;
    output r1 as {program_id}/ped_hash.future;

{finalize_logic}"
            ))
            .unwrap();

            let credits = Some(unspent_records.pop().unwrap().decrypt(&caller_view_key).unwrap());

            // Deploy the program.
            let deployment_transaction = vm.deploy(&caller_private_key, &program, credits, 10, None, rng).unwrap();

            // Construct the deployment block.
            let deployment_block = sample_next_block(
                &vm,
                &caller_private_key,
                &[deployment_transaction],
                &genesis,
                &mut unspent_records,
                rng,
            )
            .unwrap();

            // Add the deployment block to the VM.
            vm.add_next_block(&deployment_block).unwrap();

            // Construct a transaction that will cause a E::halt in the finalize execution.
            let inputs = vec![Value::<CurrentNetwork>::from_str("1u128").unwrap()];
            let transaction =
                create_execution(&vm, caller_private_key, program_id, "ped_hash", inputs, &mut unspent_records, rng);

            // Speculatively execute the transaction. Ensure that this call does not panic and returns a rejected transaction.
            let (_, confirmed_transactions, aborted_transaction_ids, _) = vm
                .speculate(
                    sample_finalize_state(1),
                    CurrentNetwork::BLOCK_TIME as i64,
                    None,
                    vec![],
                    &None.into(),
                    [transaction.clone()].iter(),
                    rng,
                )
                .unwrap();
            assert!(aborted_transaction_ids.is_empty());

            // Ensure that the transaction is rejected.
            assert_eq!(confirmed_transactions.len(), 1);
            assert!(transaction.is_execute());
            if let Transaction::Execute(_, _, execution, fee) = transaction {
                let fee_transaction = Transaction::from_fee(fee.unwrap()).unwrap();
                let expected_confirmed_transaction = ConfirmedTransaction::RejectedExecute(
                    0,
                    fee_transaction,
                    Rejected::new_execution(*execution),
                    vec![],
                );

                let confirmed_transaction = confirmed_transactions.iter().next().unwrap();
                assert_eq!(confirmed_transaction, &expected_confirmed_transaction);
            }
        }
    }

    #[test]
    #[ignore]
    fn test_rejected_transaction_should_not_update_storage() {
        let rng = &mut TestRng::default();

        // Sample a private key.
        let private_key = test_helpers::sample_genesis_private_key(rng);
        let address = Address::try_from(&private_key).unwrap();

        // Initialize the vm.
        let vm = test_helpers::sample_vm_with_genesis_block(rng);

        // Deploy a new program.
        let genesis =
            vm.block_store().get_block(&vm.block_store().get_block_hash(0).unwrap().unwrap()).unwrap().unwrap();

        // Get the unspent records.
        let mut unspent_records = genesis
            .transitions()
            .cloned()
            .flat_map(Transition::into_records)
            .map(|(_, record)| record)
            .collect::<Vec<_>>();

        // Generate more records to use for the next block.
        let splits_block = generate_splits(&vm, &private_key, &genesis, &mut unspent_records, rng).unwrap();

        // Add the splits block to the VM.
        vm.add_next_block(&splits_block).unwrap();

        // Construct the deployment block.
        let deployment_block = {
            let program = Program::<CurrentNetwork>::from_str(
                "
program testing.aleo;

mapping entries:
    key as address.public;
    value as u8.public;

function compute:
    input r0 as u8.public;
    async compute self.caller r0 into r1;
    output r1 as testing.aleo/compute.future;

finalize compute:
    input r0 as address.public;
    input r1 as u8.public;
    get.or_use entries[r0] r1 into r2;
    add r1 r2 into r3;
    set r3 into entries[r0];
    get entries[r0] into r4;
    add r4 r1 into r5;
    set r5 into entries[r0];
",
            )
            .unwrap();

            // Prepare the additional fee.
            let view_key = ViewKey::<CurrentNetwork>::try_from(private_key).unwrap();
            let credits = Some(unspent_records.pop().unwrap().decrypt(&view_key).unwrap());

            // Deploy.
            let transaction = vm.deploy(&private_key, &program, credits, 10, None, rng).unwrap();

            // Construct the new block.
            sample_next_block(&vm, &private_key, &[transaction], &splits_block, &mut unspent_records, rng).unwrap()
        };

        // Add the deployment block to the VM.
        vm.add_next_block(&deployment_block).unwrap();

        // Generate more records to use for the next block.
        let splits_block = generate_splits(&vm, &private_key, &deployment_block, &mut unspent_records, rng).unwrap();

        // Add the splits block to the VM.
        vm.add_next_block(&splits_block).unwrap();

        // Create an execution transaction, that will be rejected.
        let r0 = Value::<CurrentNetwork>::from_str("100u8").unwrap();
        let first = create_execution(&vm, private_key, "testing.aleo", "compute", vec![r0], &mut unspent_records, rng);

        // Construct the next block.
        let next_block =
            sample_next_block(&vm, &private_key, &[first], &splits_block, &mut unspent_records, rng).unwrap();

        // Check that the transaction was rejected.
        assert!(next_block.transactions().iter().next().unwrap().is_rejected());

        // Add the next block to the VM.
        vm.add_next_block(&next_block).unwrap();

        // Check that the storage was not updated.
        let program_id = ProgramID::from_str("testing.aleo").unwrap();
        let mapping_name = Identifier::from_str("entries").unwrap();
        assert!(
            !vm.finalize_store()
                .contains_key_confirmed(program_id, mapping_name, &Plaintext::from(Literal::Address(address)))
                .unwrap()
        );

        // Create an execution transaction, that will be rejected.
        let r0 = Value::<CurrentNetwork>::from_str("100u8").unwrap();
        let first = create_execution(&vm, private_key, "testing.aleo", "compute", vec![r0], &mut unspent_records, rng);

        // Create an execution transaction, that will be accepted.
        let r0 = Value::<CurrentNetwork>::from_str("1u8").unwrap();
        let second = create_execution(&vm, private_key, "testing.aleo", "compute", vec![r0], &mut unspent_records, rng);

        // Construct the next block.
        let next_block =
            sample_next_block(&vm, &private_key, &[first, second], &next_block, &mut unspent_records, rng).unwrap();

        // Check that the first transaction was rejected.
        assert!(next_block.transactions().iter().next().unwrap().is_rejected());

        // Add the next block to the VM.
        vm.add_next_block(&next_block).unwrap();

        // Check that the storage was updated correctly.
        let value = vm
            .finalize_store()
            .get_value_speculative(program_id, mapping_name, &Plaintext::from(Literal::Address(address)))
            .unwrap()
            .unwrap();
        let expected = Value::<CurrentNetwork>::from_str("3u8").unwrap();
        assert_eq!(value, expected);
    }

    #[test]
    fn test_excess_transactions_should_be_aborted() {
        let rng = &mut TestRng::default();

        // Sample a private key.
        let caller_private_key = test_helpers::sample_genesis_private_key(rng);
        let caller_address = Address::try_from(&caller_private_key).unwrap();

        // Initialize the vm.
        let vm = test_helpers::sample_vm_with_genesis_block(rng);

        // Deploy a new program.
        let genesis =
            vm.block_store().get_block(&vm.block_store().get_block_hash(0).unwrap().unwrap()).unwrap().unwrap();

        // Get the unspent records.
        let mut unspent_records = genesis
            .transitions()
            .cloned()
            .flat_map(Transition::into_records)
            .map(|(_, record)| record)
            .collect::<Vec<_>>();

        // Construct the deployment block.
        let (program_id, deployment_block) =
            new_program_deployment(&vm, &caller_private_key, &genesis, &mut unspent_records, rng).unwrap();

        // Add the deployment block to the VM.
        vm.add_next_block(&deployment_block).unwrap();

        let mut transactions = Vec::new();
        let mut excess_transaction_ids = Vec::new();

        for _ in 0..VM::<CurrentNetwork, LedgerType>::MAXIMUM_CONFIRMED_TRANSACTIONS + 1 {
            let inputs = vec![
                Value::<CurrentNetwork>::from_str(&caller_address.to_string()).unwrap(),
                Value::<CurrentNetwork>::from_str("10u64").unwrap(),
            ];

            let transaction = vm
                .execute(&caller_private_key, (&program_id, "mint_public"), inputs.into_iter(), None, 1, None, rng)
                .unwrap();
            // Verify.
            vm.check_transaction(&transaction, None, rng).unwrap();

            // Abort the transaction if the block is full.
            if transactions.len() >= VM::<CurrentNetwork, LedgerType>::MAXIMUM_CONFIRMED_TRANSACTIONS {
                excess_transaction_ids.push(transaction.id());
            }

            transactions.push(transaction);
        }

        // Construct the next block.
        let next_block =
            sample_next_block(&vm, &caller_private_key, &transactions, &deployment_block, &mut unspent_records, rng)
                .unwrap();

        // Ensure that the excess transactions were aborted.
        assert_eq!(next_block.aborted_transaction_ids(), &excess_transaction_ids);
        assert_eq!(next_block.transactions().len(), VM::<CurrentNetwork, LedgerType>::MAXIMUM_CONFIRMED_TRANSACTIONS);
    }

    #[test]
    fn test_ratify_genesis_greater_than_max_committee_size() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Construct the validators, greater than the maximum committee size.
        let validators =
            sample_validators::<CurrentNetwork>(Committee::<CurrentNetwork>::max_committee_size() as usize + 1, rng);

        // Construct the committee.
        let mut committee_map = IndexMap::new();
        for (private_key, (amount, _, _)) in &validators {
            let address = Address::try_from(private_key).unwrap();
            committee_map.insert(address, (*amount, true, 0));
        }

        // Attempt to construct a `Committee` with more than the maximum committee size.
        let result = Committee::new_genesis(committee_map);
        assert!(result.is_err());

        // Reset the validators.
        // Note: We use a smaller committee size to ensure that there is enough supply to allocate to the validators and genesis block transactions.
        let validators = sample_validators::<CurrentNetwork>(
            consensus_config_value!(CurrentNetwork, MAX_CERTIFICATES, 0).unwrap() as usize,
            rng,
        );

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) =
            sample_committee_map_and_allocated_amount(&validators, &IndexMap::new());

        // Construct the public balances, allocating the remaining supply.
        let public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &IndexMap::new());

        // Construct the genesis block, which should pass.
        let block = vm
            .genesis_quorum(
                validators.keys().next().unwrap(),
                Committee::new_genesis(committee_map).unwrap(),
                public_balances,
                bonded_balances,
                rng,
            )
            .unwrap();

        // Add the block.
        vm.add_next_block(&block).unwrap();
    }

    // Note that the maximum delegator size is large enough that the ratification ID cannot be computed.
    #[test]
    fn test_ratify_genesis_greater_than_max_delegator_size() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Construct the validators.
        // Note: We use a smaller committee size to ensure that there is enough supply to allocate to the validators and genesis block transactions.
        let validators = sample_validators::<CurrentNetwork>(
            consensus_config_value!(CurrentNetwork, MAX_CERTIFICATES, 0).unwrap() as usize / 4,
            rng,
        );

        // Construct the delegators, greater than the maximum delegator size.
        let delegators = (0..MAX_DELEGATORS + 1)
            .map(|_| {
                let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
                let validator = Address::try_from(validators.keys().next().unwrap()).unwrap();
                let amount = MIN_DELEGATOR_STAKE;
                (private_key, (validator, amount))
            })
            .collect::<IndexMap<_, _>>();

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) = sample_committee_map_and_allocated_amount(&validators, &delegators);

        // Construct the public balances, allocating the remaining supply to the validators and zero to the delegators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances.extend(sample_public_balances(
            &delegators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            0,
        ));

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &delegators);

        // Construct the genesis block, which should fail.
        let result = vm.genesis_quorum(
            validators.keys().next().unwrap(),
            Committee::new_genesis(committee_map).unwrap(),
            public_balances,
            bonded_balances,
            rng,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_ratify_genesis_is_correct() {
        const NUM_VALIDATORS: usize = 5;
        const NUM_DELEGATORS: usize = 8;

        // Sample an RNG.
        let rng = &mut TestRng::default();

        println!("Initializing VMs.");

        // Initialize the VM.
        let vm = sample_vm();

        println!("Constructing validator and delegator sets.");

        // Sample the validators.
        let validators = sample_validators(NUM_VALIDATORS, rng);

        // Sample the delegators, cycling through the validators.
        let delegators: IndexMap<_, _> = (0..NUM_DELEGATORS)
            .map(|i| {
                let private_key = PrivateKey::new(rng).unwrap();
                let validator = Address::try_from(validators.keys().nth(i % NUM_VALIDATORS).unwrap()).unwrap();
                let amount = MIN_DELEGATOR_STAKE;
                (private_key, (validator, amount))
            })
            .collect();

        // Sample a genesis block without any delegators.
        // Specifically, the genesis block will contain a `Ratification` with:
        //   - the committee state, containing only the validator amounts.
        //   - the public balances for the delegators, with 10_000_000u64 microcredits each (plus 843_880u64 microcredits for fees).
        //   - the public balances for the validators dividing up the remaining starting supply.
        //   - the bonded balances, only containing the validators.

        println!("Initializing the VM.");

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) = sample_committee_map_and_allocated_amount(&validators, &delegators);
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances, allocating the remaining supply to the validators and zero to the delegators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances.extend(sample_public_balances(
            &delegators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            0,
        ));

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &delegators);

        println!("Generating the genesis block.");

        let genesis = vm
            .genesis_quorum(
                validators.keys().next().unwrap(),
                committee.clone(),
                public_balances.clone(),
                bonded_balances.clone(),
                rng,
            )
            .unwrap();

        println!("Adding the genesis block to the VM.");

        // Add the genesis block to the VM.
        vm.add_next_block(&genesis).unwrap();

        // Check that the state of the `credits.aleo` program is correct.
        let program_id = ProgramID::from_str("credits.aleo").unwrap();
        let committee_mapping_name = Identifier::from_str("committee").unwrap();
        let account_mapping_name = Identifier::from_str("account").unwrap();
        let bonded_mapping_name = Identifier::from_str("bonded").unwrap();
        let metadata_mapping_name = Identifier::from_str("metadata").unwrap();
        let unbonding_mapping_name = Identifier::from_str("unbonding").unwrap();
        let withdraw_mapping_name = Identifier::from_str("withdraw").unwrap();

        // Get and check the committee mapping.
        let actual_committee = vm.finalize_store().get_mapping_confirmed(program_id, committee_mapping_name).unwrap();
        let expected_committee = committee
            .members()
            .iter()
            .map(|(address, (_, is_open, commission))| {
                (
                    Plaintext::from_str(&address.to_string()).unwrap(),
                    Value::from_str(&format!("{{ is_open: {is_open}, commission: {commission}u8 }}")).unwrap(),
                )
            })
            .collect_vec();
        // Note that `actual_committee` and `expected_committee` are vectors and not necessarily in the same order.
        // By checking that the lengths of the vector are equal and that all entries in `actual_committee` are in `expected_committee`,
        // we can ensure that the two vectors contain the same data.
        assert_eq!(actual_committee.len(), expected_committee.len());
        for entry in actual_committee.iter() {
            assert!(expected_committee.contains(entry));
        }

        // Get and check the account mapping.
        let actual_account = vm.finalize_store().get_mapping_confirmed(program_id, account_mapping_name).unwrap();
        let expected_account = public_balances
            .iter()
            .map(|(address, amount)| {
                (Plaintext::from_str(&address.to_string()).unwrap(), Value::from_str(&format!("{amount}u64")).unwrap())
            })
            .collect_vec();
        // Note that `actual_account` and `expected_account` are vectors and not necessarily in the same order.
        // By checking that the lengths of the vector are equal and that all entries in `actual_account` are in `expected_account`,
        // we can ensure that the two vectors contain the same data.
        assert_eq!(actual_account.len(), expected_account.len());
        // Check that all entries except for the first validator are the same.
        for entry in actual_account.iter() {
            let first_validator = Address::try_from(validators.keys().next().unwrap()).unwrap();
            // Note that the first validator is used to execute additional transactions in `VM::genesis_quorum`.
            // Therefore, the balance of the first validator will be different from the expected balance.
            if entry.0 == Plaintext::from_str(&first_validator.to_string()).unwrap() {
                assert_eq!(entry.1, Value::from_str("144991999894112u64").unwrap());
            } else {
                assert!(expected_account.contains(entry));
            }
        }

        // Get and check the bonded mapping.
        let actual_bonded = vm.finalize_store().get_mapping_confirmed(program_id, bonded_mapping_name).unwrap();
        let expected_bonded = bonded_balances
            .iter()
            .map(|(address, (validator, _, amount))| {
                (
                    Plaintext::from_str(&address.to_string()).unwrap(),
                    Value::from_str(&format!("{{ validator: {validator}, microcredits: {amount}u64 }}")).unwrap(),
                )
            })
            .collect_vec();
        // Note that `actual_bonded` and `expected_bonded` are vectors and not necessarily in the same order.
        // By checking that the lengths of the vector are equal and that all entries in `actual_bonded` are in `expected_bonded`,
        // we can ensure that the two vectors contain the same data.
        assert_eq!(actual_bonded.len(), expected_bonded.len());
        for entry in actual_bonded.iter() {
            assert!(expected_bonded.contains(entry));
        }

        // Get and check the withdraw mapping.
        let actual_withdraw = vm.finalize_store().get_mapping_confirmed(program_id, withdraw_mapping_name).unwrap();
        let expected_withdraw = bonded_balances
            .iter()
            .map(|(address, (_, withdrawal_address, _))| {
                (
                    Plaintext::from_str(&address.to_string()).unwrap(),
                    Value::from_str(&withdrawal_address.to_string()).unwrap(),
                )
            })
            .collect_vec();
        // Note that `actual_withdraw` and `expected_withdraw` are vectors and not necessarily in the same order.
        // By checking that the lengths of the vector are equal and that all entries in `actual_withdraw` are in `expected_withdraw`,
        // we can ensure that the two vectors contain the same data.
        assert_eq!(actual_withdraw.len(), expected_withdraw.len());
        for entry in actual_withdraw.iter() {
            assert!(expected_withdraw.contains(entry));
        }

        // Get and check the entry in metadata mapping corresponding to the number of validators.
        let num_validators = vm
            .finalize_store()
            .get_value_confirmed(
                program_id,
                metadata_mapping_name,
                &Plaintext::from_str("aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc").unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(num_validators, Value::from_str(&format!("{NUM_VALIDATORS}u32")).unwrap());

        // Get and check the entry in metadata mapping corresponding to the number of delegators.
        let num_delegators = vm
            .finalize_store()
            .get_value_confirmed(
                program_id,
                metadata_mapping_name,
                &Plaintext::from_str("aleo1qgqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqanmpl0").unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(num_delegators, Value::from_str(&format!("{NUM_DELEGATORS}u32")).unwrap());

        // Get and check the unbonding mapping.
        let actual_unbonding = vm.finalize_store().get_mapping_confirmed(program_id, unbonding_mapping_name).unwrap();
        assert!(actual_unbonding.is_empty());
    }

    #[test]
    fn test_ratify_genesis_is_consistent() {
        const NUM_VALIDATORS: usize = 5;
        const NUM_DELEGATORS: usize = 8;

        // Sample an RNG.
        let rng = &mut TestRng::default();

        println!("Initializing VMs.");

        // Initialize two VMs.
        let vm_1 = sample_vm();
        let vm_2 = sample_vm();

        println!("Constructing validator and delegator sets.");

        // Sample the validators.
        let validators = sample_validators(NUM_VALIDATORS, rng);

        // Sample the delegators, cycling through the validators.
        let delegators: IndexMap<_, _> = (0..NUM_DELEGATORS)
            .map(|i| {
                let private_key = PrivateKey::new(rng).unwrap();
                let validator = Address::try_from(validators.keys().nth(i % NUM_VALIDATORS).unwrap()).unwrap();
                let amount = MIN_DELEGATOR_STAKE;
                (private_key, (validator, amount))
            })
            .collect();

        // For the first VM, sample a genesis block without any delegators.
        // Specifically, the genesis block will contain a `Ratification` with:
        //   - the committee state, containing only the validator amounts.
        //   - the public balances for the delegators, with 10_000_000u64 microcredits each (plus 843_880u64 microcredits for fees).
        //   - the public balances for the validators dividing up the remaining starting supply.
        //   - the bonded balances, only containing the validators.

        println!("Initializing the first VM.");

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, mut allocated_amount) =
            sample_committee_map_and_allocated_amount(&validators, &IndexMap::new());
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances.
        let mut public_balances = IndexMap::new();
        for (private_key, (_validator, _amount)) in &delegators {
            let address = Address::try_from(private_key).unwrap();
            let amount = MIN_DELEGATOR_STAKE * 2;
            public_balances.insert(address, amount);
            allocated_amount += amount;
        }
        public_balances.extend(sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        ));

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &IndexMap::new());

        println!("[VM1] Generating the genesis block.");

        let genesis_1 = vm_1
            .genesis_quorum(validators.keys().next().unwrap(), committee, public_balances, bonded_balances, rng)
            .unwrap();

        println!("[VM1] Adding the genesis block to the VM.");

        // Add the genesis block to the VM.
        vm_1.add_next_block(&genesis_1).unwrap();

        println!("[VM1] Generating bond transactions for each of the delegators.");

        // Generate bond transactions for each of the delegators.
        let mut transactions = Vec::new();
        for (private_key, (validator, amount)) in &delegators {
            let transaction = vm_1
                .execute(
                    private_key,
                    ("credits.aleo", "bond_public"),
                    vec![
                        Value::<CurrentNetwork>::from_str(&validator.to_string()).unwrap(),
                        Value::<CurrentNetwork>::from_str(&Address::try_from(private_key).unwrap().to_string())
                            .unwrap(),
                        Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap(),
                    ]
                    .into_iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();
            transactions.push(transaction);
        }

        println!("[VM1] Generating the next block.");
        let next_block =
            sample_next_block(&vm_1, validators.keys().next().unwrap(), &transactions, &genesis_1, &mut vec![], rng)
                .unwrap();

        println!("[VM1] Adding the next block to the VM.");
        vm_1.add_next_block(&next_block).unwrap();

        // For the second VM, sample a genesis block with the same validators and delegators.
        // Specifically, the genesis block will contain a `Ratification` with:
        //   - the committee state, containing the total staked amount per validator.
        //   - the public balances for the delegators, with 0 microcredits each.
        //   - the public balances for the validators dividing up the remaining starting supply.
        //   - the bonded balances, containing the validators and delegators.

        println!("Initializing the second VM.");

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) = sample_committee_map_and_allocated_amount(&validators, &delegators);
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances, allocating the remaining supply to the validators and zero to the delegators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances.extend(sample_public_balances(
            &delegators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            0,
        ));

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &delegators);

        println!("[VM2] Generating the genesis block.");

        // Construct the genesis block.
        let genesis_2 = vm_2
            .genesis_quorum(validators.keys().next().unwrap(), committee, public_balances, bonded_balances, rng)
            .unwrap();

        println!("[VM2] Adding the genesis block to the VM.");

        // Add the genesis block to the VM.
        vm_2.add_next_block(&genesis_2).unwrap();

        println!("[VM2] Generating the next block.");
        let next_block =
            sample_next_block(&vm_2, validators.keys().next().unwrap(), &[], &genesis_2, &mut vec![], rng).unwrap();
        println!("[VM2] Adding the next block to the VM to simulate block rewards.");
        vm_2.add_next_block(&next_block).unwrap();

        println!("Checking that all mappings in `credits.aleo` are equal across the two VMs.");

        // Check that all mappings in `credits.aleo` are equal across the two VMs.
        let program_id = ProgramID::from_str("credits.aleo").unwrap();
        let committee_mapping_name = Identifier::from_str("committee").unwrap();
        let bonded_mapping_name = Identifier::from_str("bonded").unwrap();
        let unbonding_mapping_name = Identifier::from_str("unbonding").unwrap();
        let account_mapping_name = Identifier::from_str("account").unwrap();
        let metadata_mapping_name = Identifier::from_str("metadata").unwrap();
        let withdraw_mapping_name = Identifier::from_str("withdraw").unwrap();

        let committee_1 = vm_1.finalize_store().get_mapping_confirmed(program_id, committee_mapping_name).unwrap();
        let committee_2 = vm_2.finalize_store().get_mapping_confirmed(program_id, committee_mapping_name).unwrap();
        assert_eq!(committee_1, committee_2);

        let bonded_1 = vm_1.finalize_store().get_mapping_confirmed(program_id, bonded_mapping_name).unwrap();
        let bonded_2 = vm_2.finalize_store().get_mapping_confirmed(program_id, bonded_mapping_name).unwrap();
        assert_eq!(bonded_1, bonded_2);

        let unbonding_1 = vm_1.finalize_store().get_mapping_confirmed(program_id, unbonding_mapping_name).unwrap();
        let unbonding_2 = vm_2.finalize_store().get_mapping_confirmed(program_id, unbonding_mapping_name).unwrap();
        assert_eq!(unbonding_1, unbonding_2);

        // Check that the account mapping across both VMs have the same keys.
        let account_1 = vm_1
            .finalize_store()
            .get_mapping_confirmed(program_id, account_mapping_name)
            .unwrap()
            .into_iter()
            .map(|(k, _)| k.to_string())
            .collect::<std::collections::HashSet<_>>();
        let account_2 = vm_2
            .finalize_store()
            .get_mapping_confirmed(program_id, account_mapping_name)
            .unwrap()
            .into_iter()
            .map(|(k, _)| k.to_string())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(account_1, account_2);

        // Check that the metadata mapping across both VMs are equal.
        let metadata_1 = vm_1.finalize_store().get_mapping_confirmed(program_id, metadata_mapping_name).unwrap();
        let metadata_2 = vm_2.finalize_store().get_mapping_confirmed(program_id, metadata_mapping_name).unwrap();
        assert_eq!(metadata_1, metadata_2);

        // Check that the withdraw mapping across both VMs are equal.
        let withdraw_1 = vm_1.finalize_store().get_mapping_confirmed(program_id, withdraw_mapping_name).unwrap();
        let withdraw_2 = vm_2.finalize_store().get_mapping_confirmed(program_id, withdraw_mapping_name).unwrap();
        assert_eq!(withdraw_1, withdraw_2);
    }

    #[test]
    fn test_ratify_genesis_with_insufficient_validator_balance() {
        // Sample an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Attempt to construct a genesis quorum, with a validator with an insufficient amount.
        let mut validators = (0..3)
            .map(|_| {
                let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
                let address = Address::try_from(&private_key).unwrap();
                let amount = MIN_VALIDATOR_STAKE;
                let is_open = true;
                let commission = 0u8;
                (address, (amount, is_open, commission))
            })
            .collect::<IndexMap<_, _>>();
        validators
            .insert(Address::try_from(PrivateKey::new(rng).unwrap()).unwrap(), (MIN_VALIDATOR_STAKE - 1, true, 0));

        // Construct the committee.
        let result = Committee::new_genesis(validators);
        assert!(result.is_err());

        // Track the allocated amount.
        let mut allocated_amount = 0;

        // Reset the validators.
        let validators = sample_validators(4, rng);

        // Construct the committee.
        let committee = Committee::new_genesis(
            validators
                .iter()
                .map(|(private_key, (amount, _, _))| {
                    let address = Address::try_from(private_key).unwrap();
                    allocated_amount += *amount;
                    (address, (*amount, true, 0u8))
                })
                .collect(),
        )
        .unwrap();

        // Construct the public balances, allocating the remaining supply to rest of the validators.
        let public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &IndexMap::new());

        // Construct the genesis block, which should pass.
        let block = vm
            .genesis_quorum(validators.keys().next().unwrap(), committee, public_balances, bonded_balances, rng)
            .unwrap();

        // Add the block.
        vm.add_next_block(&block).unwrap();
    }

    #[test]
    fn test_ratify_genesis_with_insufficient_delegator_balance() {
        // Sample an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Track the allocated amount.
        let mut allocated_amount = 0;

        // Sample the validators.
        let validators = sample_validators(4, rng);

        // Attempt to construct a genesis quorum, with a delegator with an insufficient amount.
        let mut delegators = IndexMap::new();
        delegators.insert(
            PrivateKey::new(rng).unwrap(),
            (Address::try_from(validators.keys().next().unwrap()).unwrap(), MIN_DELEGATOR_STAKE - 1),
        );

        // Construct the committee.
        let mut committee_map = IndexMap::new();
        for (private_key, (amount, _, _)) in &validators {
            let address = Address::try_from(private_key).unwrap();
            let amount = if address == Address::try_from(validators.keys().next().unwrap()).unwrap() {
                *amount + MIN_DELEGATOR_STAKE - 1
            } else {
                *amount
            };
            committee_map.insert(address, (amount, true, 0u8));
            allocated_amount += amount;
        }
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances, allocating the remaining supply to rest of the validators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances
            .extend(sample_public_balances(&[Address::try_from(delegators.keys().next().unwrap()).unwrap()], 0));

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &delegators);

        // Construct the genesis block, which should fail.
        let result =
            vm.genesis_quorum(validators.keys().next().unwrap(), committee, public_balances, bonded_balances, rng);
        assert!(result.is_err());

        // Reset the delegators.
        let mut delegators = IndexMap::new();
        delegators.insert(
            PrivateKey::new(rng).unwrap(),
            (Address::try_from(validators.keys().next().unwrap()).unwrap(), MIN_DELEGATOR_STAKE),
        );

        // Track the allocated amount.
        let mut allocated_amount = 0;

        // Construct the committee.
        let mut committee_map = IndexMap::new();
        for (private_key, (amount, _, _)) in &validators {
            let address = Address::try_from(private_key).unwrap();
            let amount = if address == Address::try_from(validators.keys().next().unwrap()).unwrap() {
                *amount + MIN_DELEGATOR_STAKE
            } else {
                *amount
            };
            committee_map.insert(address, (amount, true, 0u8));
            allocated_amount += amount;
        }
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances, allocating the remaining supply to rest of the validators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances
            .extend(sample_public_balances(&[Address::try_from(delegators.keys().next().unwrap()).unwrap()], 0));

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &delegators);

        // Construct the genesis block, which should pass.
        let block = vm
            .genesis_quorum(validators.keys().next().unwrap(), committee, public_balances, bonded_balances, rng)
            .unwrap();

        // Add the block.
        vm.add_next_block(&block).unwrap();
    }

    #[test]
    fn test_ratify_genesis_with_incorrect_committee_amounts() {
        // Sample an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Initialize the validators.
        let validators = sample_validators(4, rng);

        // Initialize the delegators.
        let delegators = (0..4)
            .map(|_| {
                let private_key = PrivateKey::new(rng).unwrap();
                let validator = Address::try_from(validators.keys().next().unwrap()).unwrap();
                let amount = MIN_DELEGATOR_STAKE;
                (private_key, (validator, amount))
            })
            .collect::<IndexMap<_, _>>();

        // Construct the **incorrect** committee.
        // Track the allocated amount.
        // Note: this committee is missing the additional stake from the delegators.
        let (committee_map, allocated_amount) =
            sample_committee_map_and_allocated_amount(&validators, &IndexMap::new());
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances, allocating the remaining supply to rest of the validators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances.extend(sample_public_balances(
            &delegators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            0,
        ));

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &delegators);

        // Construct the genesis block, which should fail.
        let result = vm.genesis_quorum(
            validators.keys().next().unwrap(),
            committee,
            public_balances,
            bonded_balances.clone(),
            rng,
        );
        assert!(result.is_err());

        // Construct the **correct** committee.
        // Reset the tracked amount.
        let (committee_map, allocated_amount) = sample_committee_map_and_allocated_amount(&validators, &delegators);
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances, allocating the remaining supply to rest of the validators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances.extend(sample_public_balances(
            &delegators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            0,
        ));

        // Construct the genesis block, which should pass.
        let block = vm
            .genesis_quorum(validators.keys().next().unwrap(), committee, public_balances, bonded_balances, rng)
            .unwrap();

        // Add the block.
        vm.add_next_block(&block).unwrap();
    }

    #[test]
    fn test_ratify_genesis_with_closed_validator() {
        // Sample an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Initialize the validators, with one closed.
        let validators = (0..4)
            .map(|i| {
                let private_key = PrivateKey::new(rng).unwrap();
                let amount = MIN_VALIDATOR_STAKE;
                let is_open = i != 0;
                let commission = 0;
                (private_key, (amount, is_open, commission))
            })
            .collect::<IndexMap<_, _>>();

        // Initialize a potential delegator.
        let delegator_key = PrivateKey::new(rng).unwrap();
        let delegator_address = Address::try_from(delegator_key).unwrap();

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) =
            sample_committee_map_and_allocated_amount(&validators, &IndexMap::new());

        // Construct the public balances, allocating half to the first validator and the remaining to the delegator.
        let public_balances = sample_public_balances(
            &[Address::try_from(validators.keys().next().unwrap()).unwrap(), delegator_address],
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );

        // Construct the bonded balances.
        let bonded_balances = sample_bonded_balances(&validators, &IndexMap::new());

        // Construct the genesis block, which should pass.
        let block = vm
            .genesis_quorum(
                validators.keys().next().unwrap(),
                Committee::new_genesis(committee_map).unwrap(),
                public_balances,
                bonded_balances,
                rng,
            )
            .unwrap();

        // Add the block.
        vm.add_next_block(&block).unwrap();

        // Attempt to bond the potential delegator to the closed validator.
        let transaction = vm
            .execute(
                &delegator_key,
                ("credits.aleo", "bond_public"),
                vec![
                    Value::<CurrentNetwork>::from_str(
                        &Address::try_from(validators.keys().next().unwrap()).unwrap().to_string(),
                    )
                    .unwrap(),
                    Value::<CurrentNetwork>::from_str(&Address::try_from(delegator_key).unwrap().to_string()).unwrap(),
                    Value::<CurrentNetwork>::from_str(&format!("{MIN_DELEGATOR_STAKE}u64")).unwrap(),
                ]
                .into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Generate the next block.
        let next_block =
            sample_next_block(&vm, validators.keys().next().unwrap(), &[transaction], &block, &mut vec![], rng)
                .unwrap();

        // Add the next block.
        vm.add_next_block(&next_block).unwrap();

        // Check that the delegator is not in the `bonded` mapping.
        let bonded_mapping = vm
            .finalize_store()
            .get_mapping_confirmed(
                ProgramID::from_str("credits.aleo").unwrap(),
                Identifier::from_str("bonded").unwrap(),
            )
            .unwrap();
        assert_eq!(bonded_mapping.len(), validators.len());

        // Attempt to bond the potential delegator to the open validator.
        let transaction = vm
            .execute(
                &delegator_key,
                ("credits.aleo", "bond_public"),
                vec![
                    Value::<CurrentNetwork>::from_str(
                        &Address::try_from(validators.keys().nth(1).unwrap()).unwrap().to_string(),
                    )
                    .unwrap(),
                    Value::<CurrentNetwork>::from_str(&Address::try_from(delegator_key).unwrap().to_string()).unwrap(),
                    Value::<CurrentNetwork>::from_str(&format!("{MIN_DELEGATOR_STAKE}u64")).unwrap(),
                ]
                .into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Generate the next block.
        let next_block =
            sample_next_block(&vm, validators.keys().next().unwrap(), &[transaction], &next_block, &mut vec![], rng)
                .unwrap();

        // Add the next block.
        vm.add_next_block(&next_block).unwrap();

        // Check that the delegator is in the `bonded` mapping.
        let bonded_mapping = vm
            .finalize_store()
            .get_mapping_confirmed(
                ProgramID::from_str("credits.aleo").unwrap(),
                Identifier::from_str("bonded").unwrap(),
            )
            .unwrap();
        assert_eq!(bonded_mapping.len(), validators.len() + 1);
    }

    #[test]
    fn test_ratify_genesis_withdrawal_address() {
        const NUM_VALIDATORS: usize = 5;
        const NUM_DELEGATORS: usize = 8;

        // Sample an RNG.
        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Sample the validators.
        let validators = sample_validators(NUM_VALIDATORS, rng);

        // Sample the delegators, cycling through the validators.
        let delegators: IndexMap<_, _> = (0..NUM_DELEGATORS)
            .map(|i| {
                let private_key = PrivateKey::new(rng).unwrap();
                let validator = Address::try_from(validators.keys().nth(i % NUM_VALIDATORS).unwrap()).unwrap();
                let amount = MIN_DELEGATOR_STAKE;
                (private_key, (validator, amount))
            })
            .collect();

        // Construct the committee.
        // Track the allocated amount.
        let (committee_map, allocated_amount) = sample_committee_map_and_allocated_amount(&validators, &delegators);
        let committee = Committee::new_genesis(committee_map).unwrap();

        // Construct the public balances, allocating the remaining supply to the validators and zero to the delegators.
        let mut public_balances = sample_public_balances(
            &validators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount,
        );
        public_balances.extend(sample_public_balances(
            &delegators.keys().map(|private_key| Address::try_from(private_key).unwrap()).collect::<Vec<_>>(),
            0,
        ));

        // Construct the bonded balances.
        let mut bonded_balances = sample_bonded_balances(&validators, &delegators);

        // Randomly sample and update the withdrawal addresses in the bonded balances.
        for (_, (_, withdrawal_address, _)) in bonded_balances.iter_mut() {
            *withdrawal_address = Address::rand(rng);
        }

        // Construct the genesis block.
        let genesis = vm
            .genesis_quorum(
                validators.keys().next().unwrap(),
                committee.clone(),
                public_balances.clone(),
                bonded_balances.clone(),
                rng,
            )
            .unwrap();

        // Add the genesis block to the VM.
        vm.add_next_block(&genesis).unwrap();

        // Check that the state of the `credits.aleo` program is correct.
        let program_id = ProgramID::from_str("credits.aleo").unwrap();
        let withdraw_mapping_name = Identifier::from_str("withdraw").unwrap();

        // Get and check the withdraw mapping.
        let actual_withdraw = vm.finalize_store().get_mapping_confirmed(program_id, withdraw_mapping_name).unwrap();
        let expected_withdraw = bonded_balances
            .iter()
            .map(|(address, (_, withdrawal_address, _))| {
                (
                    Plaintext::from_str(&address.to_string()).unwrap(),
                    Value::from_str(&withdrawal_address.to_string()).unwrap(),
                )
            })
            .collect_vec();
        // Note that `actual_withdraw` and `expected_withdraw` are vectors and not necessarily in the same order.
        // By checking that the lengths of the vector are equal and that all entries in `actual_withdraw` are in `expected_withdraw`,
        // we can ensure that the two vectors contain the same data.
        assert_eq!(actual_withdraw.len(), expected_withdraw.len());
        for entry in actual_withdraw.iter() {
            assert!(expected_withdraw.contains(entry));
        }
    }

    #[test]
    #[ignore]
    fn test_rejection_reason_storage() {
        let rng = &mut TestRng::default();

        // Sample a private key.
        let private_key = test_helpers::sample_genesis_private_key(rng);

        // Initialize the vm.
        let vm = test_helpers::sample_vm_with_genesis_block(rng);

        // Deploy a new program.
        let genesis =
            vm.block_store().get_block(&vm.block_store().get_block_hash(0).unwrap().unwrap()).unwrap().unwrap();

        // Get the unspent records.
        let mut unspent_records = genesis
            .transitions()
            .cloned()
            .flat_map(Transition::into_records)
            .map(|(_, record)| record)
            .collect::<Vec<_>>();

        // Construct the deployment block.
        let deployment_block = {
            let program = Program::<CurrentNetwork>::from_str(
                "
program testing.aleo;

mapping entries:
    key as address.public;
    value as u8.public;

function compute:
    input r0 as u8.public;
    async compute self.caller r0 into r1;
    output r1 as testing.aleo/compute.future;

finalize compute:
    input r0 as address.public;
    input r1 as u8.public;
    get.or_use entries[r0] r1 into r2;
    add r1 r2 into r3;
    set r3 into entries[r0];
    get entries[r0] into r4;
    add r4 r1 into r5;
    set r5 into entries[r0];
",
            )
            .unwrap();

            // Prepare the additional fee.
            let view_key = ViewKey::<CurrentNetwork>::try_from(private_key).unwrap();
            let credits = Some(unspent_records.pop().unwrap().decrypt(&view_key).unwrap());

            // Deploy.
            let transaction = vm.deploy(&private_key, &program, credits, 10, None, rng).unwrap();

            // Construct the new block.
            sample_next_block(&vm, &private_key, &[transaction], &genesis, &mut unspent_records, rng).unwrap()
        };

        // Add the deployment block to the VM.
        vm.add_next_block(&deployment_block).unwrap();

        // Create an execution transaction, that will be rejected.
        let r0 = Value::<CurrentNetwork>::from_str("100u8").unwrap();
        let rejected_tx =
            create_execution(&vm, private_key, "testing.aleo", "compute", vec![r0], &mut unspent_records, rng);

        // Construct the next block with the rejected transaction.
        let next_block =
            sample_next_block(&vm, &private_key, &[rejected_tx], &deployment_block, &mut unspent_records, rng).unwrap();

        // Check that the transaction was rejected.
        assert_eq!(next_block.transactions().len(), 1);
        let rejected_transaction = next_block.transactions().iter().next().unwrap();
        assert!(rejected_transaction.is_rejected());

        // Add the next block to the VM.
        vm.add_next_block(&next_block).unwrap();

        // Check that the rejection reason was stored.
        let tx_id = *rejected_transaction.id();
        let rejection_reason = vm.finalize_store().get_rejected_reason(&tx_id).unwrap();
        assert!(rejection_reason.is_some(), "Rejection reason should be stored");
    }
}
