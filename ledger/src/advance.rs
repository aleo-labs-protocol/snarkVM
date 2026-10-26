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

use anyhow::Context;

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Returns a candidate for the next block in the ledger, using a committed subdag and its transmissions.
    /// This candidate can then be passed to [`Ledger::advance_to_next_block`] to be added to the ledger.
    ///
    /// The function will prevent concurrent update to the ledger, and may block if an update is currently in progress.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    pub fn prepare_advance_to_next_quorum_block<R: Rng + CryptoRng>(
        &self,
        subdag: Subdag<N>,
        transmissions: IndexMap<TransmissionID<N>, Transmission<N>>,
        rng: &mut R,
    ) -> Result<Block<N>, CheckBlockError<N>> {
        // Retrieve the latest block as the previous block (for the next block).
        // Hold this lock while preparing the template, so that the latest block does not change mid-speculation.
        let previous_block = self.current_block.read();

        // Decouple the transmissions into ratifications, solutions, and transactions.
        let (ratifications, solutions, transactions) = decouple_transmissions(transmissions.into_iter())?;
        // Currently, we do not support ratifications from the memory pool.
        if !ratifications.is_empty() {
            return Err(anyhow!("Ratifications are currently unsupported from the memory pool").into());
        }
        // Construct the block template.
        let (header, ratifications, solutions, aborted_solution_ids, transactions, aborted_transaction_ids) =
            self.construct_block_template(&previous_block, Some(&subdag), ratifications, solutions, transactions, rng)?;

        // Construct the new quorum block.
        Block::new_quorum(
            previous_block.hash(),
            header,
            subdag,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
        )
        .map_err(|e| CheckBlockError::Other(e))
    }

    /// Returns a candidate for the next block in the ledger.
    /// This candidate can then be passed to [`Ledger::advance_to_next_block`] to be added to the ledger.
    ///
    /// Note, that beacon blocks are only used for testing purposes.
    /// Production code will most likely used `[Ledger::prepare_advance_to_next_quorum_block`] instead.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    pub fn prepare_advance_to_next_beacon_block<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        candidate_ratifications: Vec<Ratify<N>>,
        candidate_solutions: Vec<Solution<N>>,
        candidate_transactions: Vec<Transaction<N>>,
        rng: &mut R,
    ) -> Result<Block<N>, CheckBlockError<N>> {
        // Currently, we do not support ratifications from the memory pool.
        if !candidate_ratifications.is_empty() {
            return Err(anyhow!("Ratifications are currently unsupported from the memory pool").into());
        }

        // Retrieve the latest block as the previous block (for the next block).
        // Hold this lock while preparing the template, so that the latest block does not change mid-speculation.
        let previous_block = self.current_block.read();

        // Construct the block template.
        let (header, ratifications, solutions, aborted_solution_ids, transactions, aborted_transaction_ids) = self
            .construct_block_template(
                &previous_block,
                None,
                candidate_ratifications,
                candidate_solutions,
                candidate_transactions,
                rng,
            )?;

        // Construct the new beacon block.
        Block::new_beacon(
            private_key,
            previous_block.hash(),
            header,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
            rng,
        )
        .map_err(|e| CheckBlockError::Other(e))
    }

    /// Adds the given block as the next block in the ledger.
    ///
    /// This function expects a valid block, that either was created by a trusted source, or successfully passed
    /// the blocks checks (e.g. [`Ledger::check_next_block`]).
    ///
    /// # Concurrency
    /// It is guaranteed that at most one call this function is executing at any time and that no reads to the Ledger
    /// (e.g, by [`Self::prepare_next_beacon_block`] or [`Self::check_next_block`]) execute while the ledger is advancing.
    /// However, it is still possible that a *previously* valid block is rejected by a call to this function,
    /// if the ledger advanced between calling `prepare_next_*_block` and passing it to this function.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    pub fn advance_to_next_block(&self, block: &Block<N>) -> Result<()> {
        // Acquire a write lock to current_block to prevent current updates or reads to the block or state root.
        let mut current_block = self.current_block.write();

        // Check again for any possible race conditions.
        if current_block.is_genesis()? {
            // current block is initialized as the genesis block, but the ledger will
            // also advance to it on startup.
            ensure!(
                current_block.height() == block.height() || current_block.height() + 1 == block.height(),
                "The given block is not the direct successor of the latest block"
            );
        } else {
            ensure!(block.height() != 0, "Non-genesis blocks cannot have height 0");
            ensure!(
                current_block.height() + 1 == block.height(),
                "The given block is not the direct successor of the latest block"
            );
        }
        // Update the VM.
        self.vm.add_next_block(block).with_context(|| "Failed to add block to VM")?;
        // Update the current block.
        *current_block = block.clone();
        // Drop the write lock on the current block.
        drop(current_block);

        // Update the cached committee from storage.
        if let Ok(current_committee) = self.vm.finalize_store().committee_store().current_committee() {
            *self.current_committee.write() = Some(current_committee);
        }

        // If the block is the start of a new epoch, or the epoch hash has not been set,
        // update the current epoch hash and clear the epoch prover cache.
        if block.height().is_multiple_of(N::NUM_BLOCKS_PER_EPOCH) || self.current_epoch_hash.read().is_none() {
            // Update and log the current epoch hash.
            match self.get_epoch_hash(block.height()).ok() {
                Some(epoch_hash) => {
                    trace!("Updating the current epoch hash at block {} to '{epoch_hash}'", block.height());
                    *self.current_epoch_hash.write() = Some(epoch_hash);
                }
                None => {
                    error!("Failed to update the current epoch hash at block {}", block.height());
                }
            }
            // Clear the epoch provers cache. This is done because once the ledger enters a new epoch,
            // all solutions from the previous epoch are no longer relevant.
            // Note: solutions that land on exactly the epoch boundary are still considered part of the previous epoch,
            // because they were created prior to the advancement to the new epoch (using the previous epoch's puzzle).
            self.epoch_provers_cache.write().clear();
        } else {
            // If the block is not part of a new epoch, add the new provers to the epoch prover cache.
            if let Some(solutions) = block.solutions().as_deref() {
                let mut epoch_provers_cache = self.epoch_provers_cache.write();
                for (_, s) in solutions.iter() {
                    let _ = *epoch_provers_cache.entry(s.address()).and_modify(|e| *e += 1).or_insert(1);
                }
            }
        }

        Ok(())
    }
}

/// Splits candidate solutions into a collection of accepted ones and aborted ones.
pub fn split_candidate_solutions<T, F>(
    mut candidate_solutions: Vec<T>,
    max_solutions: usize,
    mut verification_fn: F,
) -> (Vec<T>, Vec<T>)
where
    T: Sized + Copy,
    F: FnMut(&mut T) -> bool,
{
    // Separate the candidate solutions into valid and aborted solutions.
    let mut valid_candidate_solutions = Vec::with_capacity(max_solutions);
    let mut aborted_candidate_solutions = Vec::new();
    // Reverse the candidate solutions in order to be able to chunk them more efficiently.
    candidate_solutions.reverse();
    // Verify the candidate solutions in chunks. This is done so that we can potentially
    // perform these operations in parallel while keeping the end result deterministic.
    let chunk_size = 16;
    while !candidate_solutions.is_empty() {
        // Check if the collection of valid solutions is full.
        if valid_candidate_solutions.len() >= max_solutions {
            // If that's the case, mark the rest of the candidates as aborted.
            aborted_candidate_solutions.extend(candidate_solutions.into_iter().rev());
            break;
        }

        // Split off a chunk of the candidate solutions.
        let mut candidates_chunk = if candidate_solutions.len() > chunk_size {
            candidate_solutions.split_off(candidate_solutions.len() - chunk_size)
        } else {
            std::mem::take(&mut candidate_solutions)
        };

        // Verify the solutions in the chunk.
        let verification_results = candidates_chunk.iter_mut().rev().map(|solution| {
            let verified = verification_fn(solution);
            (solution, verified)
        });

        // Process the results of the verification.
        for (solution, is_valid) in verification_results.into_iter() {
            if is_valid && valid_candidate_solutions.len() < max_solutions {
                valid_candidate_solutions.push(*solution);
            } else {
                aborted_candidate_solutions.push(*solution);
            }
        }
    }

    // The `aborted_candidate_solutions` can contain both verified and unverified solutions.
    // When `check_solution_mut` is used as `verification_fn`, these aborted solutions
    // may include both mutated and un-mutated variants. This occurs because the verification
    // check is skipped once the `max_solutions` limit is reached.
    //
    // This approach is SAFE because currently, only the `solutionID` of aborted solutions is stored.
    // However, if full aborted solutions need to be stored in the future, this logic will need to be revisited.
    (valid_candidate_solutions, aborted_candidate_solutions)
}

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Constructs a block template for the next block in the ledger.
    ///
    /// # Concurrency
    /// This function assumes that `previous_block` is identical to [`Self::current_block`]. To ensure this,
    /// you should hold a read (or write) lock to the latter while calling this function.
    /// Otherwise, it would be possible that the state root is inconsistent with the previous block, and for the
    /// returned block template to be invalid.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    #[allow(clippy::type_complexity)]
    fn construct_block_template<R: Rng + CryptoRng>(
        &self,
        previous_block: &Block<N>,
        subdag: Option<&Subdag<N>>,
        candidate_ratifications: Vec<Ratify<N>>,
        candidate_solutions: Vec<Solution<N>>,
        candidate_transactions: Vec<Transaction<N>>,
        rng: &mut R,
    ) -> Result<
        (Header<N>, Ratifications<N>, Solutions<N>, Vec<SolutionID<N>>, Transactions<N>, Vec<N::TransactionID>),
        CheckBlockError<N>,
    > {
        // Construct the solutions.
        let (solutions, aborted_solutions, solutions_root, combined_proof_target) = match candidate_solutions.is_empty()
        {
            true => (None, vec![], Field::<N>::zero(), 0u128),
            false => {
                // Retrieve the latest epoch hash directly from the previous block.
                // (so we avoid read-locking current_block again)
                let latest_epoch_hash = match self.current_epoch_hash.read().as_ref() {
                    Some(epoch_hash) => *epoch_hash,
                    None => self.get_epoch_hash(previous_block.height())?,
                };
                // Retrieve the latest proof target.
                let latest_proof_target = previous_block.proof_target();
                // Separate the candidate solutions into valid and aborted solutions.
                let mut accepted_solutions: IndexMap<Address<N>, u64> = IndexMap::new();
                let (valid_candidate_solutions, aborted_candidate_solutions) =
                    split_candidate_solutions(candidate_solutions, N::MAX_SOLUTIONS, |solution| {
                        let prover_address = solution.address();
                        let num_accepted_solutions = accepted_solutions.get(&prover_address).copied().unwrap_or(0);
                        // Check if the prover has reached their solution limit.
                        if self.is_solution_limit_reached_at_timestamp(
                            &prover_address,
                            num_accepted_solutions,
                            previous_block.timestamp(),
                        ) {
                            return false;
                        }
                        // Check if the solution is valid and update the number of accepted solutions.
                        match self.puzzle().check_solution_mut(solution, latest_epoch_hash, latest_proof_target) {
                            // Increment the number of accepted solutions for the prover.
                            Ok(()) => {
                                *accepted_solutions.entry(prover_address).or_insert(0) += 1;
                                true
                            }
                            // The solution is invalid, so we do not increment the number of accepted solutions.
                            Err(_) => false,
                        }
                    });

                // Check if there are any valid solutions.
                match valid_candidate_solutions.is_empty() {
                    true => (None, aborted_candidate_solutions, Field::<N>::zero(), 0u128),
                    false => {
                        // Construct the solutions.
                        let solutions = PuzzleSolutions::new(valid_candidate_solutions)?;
                        // Compute the solutions root.
                        let solutions_root = solutions.to_accumulator_point()?;
                        // Compute the combined proof target.
                        let combined_proof_target = self.puzzle().get_combined_proof_target(&solutions)?;
                        // Output the solutions, solutions root, and combined proof target.
                        (Some(solutions), aborted_candidate_solutions, solutions_root, combined_proof_target)
                    }
                }
            }
        };
        // Prepare the solutions.
        let solutions = Solutions::from(solutions);

        // Construct the aborted solution IDs.
        let aborted_solution_ids = aborted_solutions.iter().map(Solution::id).collect::<Vec<_>>();

        // Retrieve the latest state root.
        let latest_state_root = self.latest_state_root();
        // Retrieve the latest cumulative proof target.
        let latest_cumulative_proof_target = previous_block.cumulative_proof_target();
        // Retrieve the latest coinbase target.
        let latest_coinbase_target = previous_block.coinbase_target();
        // Retrieve the latest cumulative weight.
        let latest_cumulative_weight = previous_block.cumulative_weight();
        // Retrieve the last coinbase target.
        let last_coinbase_target = previous_block.last_coinbase_target();
        // Retrieve the last coinbase timestamp.
        let last_coinbase_timestamp = previous_block.last_coinbase_timestamp();

        // Compute the next round number.
        let next_round = match subdag {
            Some(subdag) => {
                if previous_block.round() >= subdag.anchor_round() {
                    return Err(CheckBlockError::InvalidRound {
                        new: subdag.anchor_round(),
                        previous: previous_block.round(),
                    });
                }

                subdag.anchor_round()
            }
            None => previous_block.round().saturating_add(1),
        };
        // Compute the next height.
        let next_height = previous_block.height().saturating_add(1);
        // Determine the timestamp for the next block.
        let next_timestamp = match subdag {
            Some(subdag) => {
                // Retrieve the previous committee lookback.
                let previous_committee_lookback = {
                    // Calculate the penultimate round, which is the round before the anchor round.
                    let penultimate_round = subdag.anchor_round().saturating_sub(1);
                    // Output the committee lookback for the penultimate round.
                    self.get_committee_lookback_for_round(penultimate_round)?
                        .ok_or(anyhow!("Failed to fetch committee lookback for round {penultimate_round}"))?
                };
                // Return the timestamp for the given committee lookback.
                subdag.timestamp(&previous_committee_lookback)
            }
            None => OffsetDateTime::now_utc().unix_timestamp(),
        };

        // Calculate the next coinbase targets and timestamps.
        let (
            next_coinbase_target,
            next_proof_target,
            next_cumulative_proof_target,
            next_cumulative_weight,
            next_last_coinbase_target,
            next_last_coinbase_timestamp,
        ) = to_next_targets::<N>(
            N::CONSENSUS_VERSION(next_height)?,
            latest_cumulative_proof_target,
            combined_proof_target,
            latest_coinbase_target,
            latest_cumulative_weight,
            last_coinbase_target,
            last_coinbase_timestamp,
            next_timestamp,
        )?;

        // Calculate the coinbase reward.
        let coinbase_reward = coinbase_reward::<N>(
            next_height,
            next_timestamp,
            N::GENESIS_TIMESTAMP,
            N::STARTING_SUPPLY,
            N::REWARD_ANCHOR_TIME,
            N::ANCHOR_HEIGHT,
            N::BLOCK_TIME,
            combined_proof_target,
            u64::try_from(latest_cumulative_proof_target)
                .map_err(|e| anyhow!("Failed to convert cumulative proof target to u64 - {e}"))?,
            latest_coinbase_target,
        )?;

        // Determine if the block timestamp should be included.
        let next_block_timestamp =
            (next_height >= N::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default()).then_some(next_timestamp);
        let (block_spend_limit, block_synthesis_limit) = if let Some(subdag) = subdag {
            (subdag.spend_limit(next_height), subdag.synthesis_limit(next_height))
        } else {
            (Subdag::<N>::min_spend_limit(next_height), Subdag::<N>::min_synthesis_limit(next_height))
        };
        // Construct the finalize state.
        let state = FinalizeGlobalState::new::<N>(
            next_round,
            next_height,
            next_block_timestamp,
            next_cumulative_weight,
            next_cumulative_proof_target,
            previous_block.hash(),
            block_spend_limit,
            block_synthesis_limit,
        )?;
        // Speculate over the ratifications, solutions, and transactions.
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) = self.vm.speculate(
            state,
            next_timestamp.saturating_sub(previous_block.timestamp()),
            Some(coinbase_reward),
            candidate_ratifications,
            &solutions,
            candidate_transactions.iter(),
            rng,
        )?;

        // Compute the ratifications root.
        let ratifications_root = ratifications.to_ratifications_root()?;

        // Construct the subdag root.
        let subdag_root = match subdag {
            Some(subdag) => subdag.to_subdag_root()?,
            None => Field::zero(),
        };

        // Construct the metadata.
        let metadata = Metadata::new(
            N::ID,
            next_round,
            next_height,
            next_cumulative_weight,
            next_cumulative_proof_target,
            next_coinbase_target,
            next_proof_target,
            next_last_coinbase_target,
            next_last_coinbase_timestamp,
            next_timestamp,
        )?;

        // Construct the header.
        let header = Header::from(
            latest_state_root,
            transactions.to_transactions_root()?,
            transactions.to_finalize_root(ratified_finalize_operations)?,
            ratifications_root,
            solutions_root,
            subdag_root,
            metadata,
        )?;

        // Return the block template.
        Ok((header, ratifications, solutions, aborted_solution_ids, transactions, aborted_transaction_ids))
    }
}
