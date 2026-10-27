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

#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

use super::*;
use snarkvm_ledger_puzzle::Puzzle;
use snarkvm_synthesizer_program::FinalizeOperation;

use std::collections::HashSet;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

impl<N: Network> Block<N> {
    /// Ensures the block is well-formed and consistent with the previous block.
    ///
    /// # Returns
    /// - On success, the sets of transaction and solution IDs that existed in this subDAG but were already included in the previous block.
    /// - On failure, the error that caused verification to fail, e.g., invalid block hash, invalid block authority, or invalid transmissions.
    pub fn verify(
        &self,
        previous_block: &Block<N>,
        current_state_root: N::StateRoot,
        previous_committee_lookback: &Committee<N>,
        current_committee_lookback: &Committee<N>,
        current_puzzle: &Puzzle<N>,
        current_epoch_hash: N::BlockHash,
        current_timestamp: i64,
        ratified_finalize_operations: Vec<FinalizeOperation<N>>,
    ) -> Result<(Vec<SolutionID<N>>, Vec<N::TransactionID>)> {
        // Ensure the block hash is correct.
        self.verify_hash(previous_block.height(), previous_block.hash())?;

        // Ensure the block authority is correct.
        let (
            expected_round,
            expected_height,
            expected_timestamp,
            expected_existing_solution_ids,
            expected_existing_transaction_ids,
        ) = self.verify_authority(
            previous_block.round(),
            previous_block.height(),
            previous_committee_lookback,
            current_committee_lookback,
        )?;

        // Ensure the block solutions are correct.
        let (
            expected_cumulative_weight,
            expected_cumulative_proof_target,
            expected_coinbase_target,
            expected_proof_target,
            expected_last_coinbase_target,
            expected_last_coinbase_timestamp,
            expected_block_reward,
            expected_puzzle_reward,
        ) = self.verify_solutions(previous_block, current_puzzle, current_epoch_hash)?;

        // Ensure the block ratifications are correct.
        self.verify_ratifications(expected_block_reward, expected_puzzle_reward)?;

        // Ensure the block transactions are correct.
        self.verify_transactions()?;

        // Set the expected previous state root.
        let expected_previous_state_root = current_state_root;
        // Compute the expected transactions root.
        let expected_transactions_root = self.compute_transactions_root()?;
        // Compute the expected finalize root.
        let expected_finalize_root = self.compute_finalize_root(ratified_finalize_operations)?;
        // Compute the expected ratifications root.
        let expected_ratifications_root = self.compute_ratifications_root()?;
        // Compute the expected solutions root.
        let expected_solutions_root = self.compute_solutions_root()?;
        // Compute the expected subdag root.
        let expected_subdag_root = self.compute_subdag_root()?;

        // Ensure the block header is correct.
        self.header.verify(
            expected_previous_state_root,
            expected_transactions_root,
            expected_finalize_root,
            expected_ratifications_root,
            expected_solutions_root,
            expected_subdag_root,
            expected_round,
            expected_height,
            expected_cumulative_weight,
            expected_cumulative_proof_target,
            expected_coinbase_target,
            expected_proof_target,
            expected_last_coinbase_target,
            expected_last_coinbase_timestamp,
            expected_timestamp,
            current_timestamp,
        )?;

        // Return the expected existing solution IDs and transaction IDs.
        Ok((expected_existing_solution_ids, expected_existing_transaction_ids))
    }
}

impl<N: Network> Block<N> {
    /// Ensures the block hash is correct.
    fn verify_hash(&self, previous_height: u32, previous_hash: N::BlockHash) -> Result<(), Error> {
        // Determine the expected height.
        let expected_height = previous_height.saturating_add(1);

        // Ensure the previous block hash matches.
        ensure!(
            self.previous_hash == previous_hash,
            "Previous block hash is incorrect in block {expected_height} (found '{}', expected '{}')",
            self.previous_hash,
            previous_hash
        );

        // Compute the Merkle root of the block header.
        let Ok(header_root) = self.header.to_root() else {
            bail!("Failed to compute the Merkle root of the block header");
        };
        // Compute the block hash.
        let candidate_hash = match N::hash_bhp1024(&to_bits_le![previous_hash, header_root]) {
            Ok(candidate_hash) => candidate_hash,
            Err(error) => bail!("Failed to compute the block hash for block {expected_height} - {error}"),
        };
        // Ensure the block hash matches.
        ensure!(
            *self.block_hash == candidate_hash,
            "Block hash is incorrect in block {expected_height} (found '{}', expected '{}')",
            self.block_hash,
            Into::<N::BlockHash>::into(candidate_hash)
        );
        // Return success.
        Ok(())
    }

    /// Ensures the block authority is correct.
    fn verify_authority(
        &self,
        previous_round: u64,
        previous_height: u32,
        previous_committee_lookback: &Committee<N>,
        current_committee_lookback: &Committee<N>,
    ) -> Result<(u64, u32, i64, Vec<SolutionID<N>>, Vec<N::TransactionID>)> {
        // Note: Do not remove this. This ensures that all blocks after genesis are quorum blocks.
        #[cfg(not(any(test, feature = "test")))]
        ensure!(self.authority.is_quorum(), "The next block must be a quorum block");

        // Determine the expected height.
        let expected_height = previous_height.saturating_add(1);

        // Determine the expected round.
        let expected_round = match &self.authority {
            // Beacon blocks increment the previous block round by 1.
            Authority::Beacon(..) => previous_round.saturating_add(1),
            // Quorum blocks use the subdag anchor round.
            Authority::Quorum(subdag) => {
                // Ensure the certificates follow the canonical order for this consensus version.
                subdag.check_certificate_order(expected_height)?;
                // Ensure the subdag anchor round is after the previous block round.
                ensure!(
                    subdag.anchor_round() > previous_round,
                    "Subdag anchor round is not after previous block round in block {} (found '{}', expected after '{}')",
                    expected_height,
                    subdag.anchor_round(),
                    previous_round
                );
                // Ensure that the rounds in the subdag are sequential.
                if previous_round != 0 {
                    for round in previous_round..=subdag.anchor_round() {
                        ensure!(
                            subdag.contains_key(&round),
                            "Subdag is missing round {round} in block {expected_height}",
                        );
                    }
                }
                // Output the subdag anchor round.
                subdag.anchor_round()
            }
        };
        // Ensure the block round minus the committee lookback range is at least the starting round of the committee lookback.
        ensure!(
            expected_round.saturating_sub(Committee::<N>::COMMITTEE_LOOKBACK_RANGE)
                >= current_committee_lookback.starting_round(),
            "Block {expected_height} has an invalid round (found '{}', expected at least '{}')",
            expected_round.saturating_sub(Committee::<N>::COMMITTEE_LOOKBACK_RANGE),
            current_committee_lookback.starting_round()
        );

        // Ensure the block authority is correct.
        // Determine the solution IDs and transaction IDs that are expected to be in previous blocks.
        let (expected_existing_solution_ids, expected_existing_transaction_ids) = match &self.authority {
            Authority::Beacon(signature) => {
                // Retrieve the signer.
                let signer = signature.to_address();
                // Ensure the block is signed by a committee member.
                ensure!(
                    current_committee_lookback.members().contains_key(&signer),
                    "Beacon block {expected_height} has a signer not in the committee (found '{signer}')",
                );
                // Ensure the signature is valid.
                ensure!(
                    signature.verify(&signer, &[*self.block_hash]),
                    "Signature is invalid in block {expected_height}"
                );

                (vec![], vec![])
            }
            Authority::Quorum(subdag) => {
                // Compute the expected leader.
                let expected_leader = current_committee_lookback.get_leader(expected_round)?;
                // Ensure the block is authored by the expected leader.
                ensure!(
                    subdag.leader_address() == expected_leader,
                    "Quorum block {expected_height} is authored by an unexpected leader (found: {}, expected: {expected_leader})",
                    subdag.leader_address()
                );
                // Ensure the transmission IDs from the subdag correspond to the block.
                // This is redundant if the block has been created via `Block::from()`;
                // however, we need to obtain the solution and transaction IDs here,
                // so may want to remove the redundant check in `Block::from()` and leave it here.
                Self::check_subdag_transmissions(
                    subdag,
                    &self.solutions,
                    &self.aborted_solution_ids,
                    &self.transactions,
                    &self.aborted_transaction_ids,
                )?
            }
        };

        // Determine the expected timestamp.
        let expected_timestamp = match &self.authority {
            // Beacon blocks do not have a timestamp check.
            Authority::Beacon(..) => self.timestamp(),
            // Quorum blocks use the weighted median timestamp from the subdag.
            Authority::Quorum(subdag) => subdag.timestamp(previous_committee_lookback),
        };

        // Check that the committee IDs are correct.
        if let Authority::Quorum(subdag) = &self.authority {
            // Check that the committee ID of the leader certificate is correct.
            ensure!(
                subdag.leader_certificate().committee_id() == current_committee_lookback.id(),
                "Leader certificate has an incorrect committee ID"
            );

            // Check that all certificates on each round have the same committee ID.
            cfg_iter!(subdag).try_for_each(|(round, certificates)| {
                // Check that every certificate for a given round shares the same committee ID.
                let expected_committee_id = certificates
                    .first()
                    .map(|certificate| certificate.committee_id())
                    .ok_or(anyhow!("No certificates found for subdag round {round}"))?;
                ensure!(
                    certificates.iter().skip(1).all(|certificate| certificate.committee_id() == expected_committee_id),
                    "Certificates on round {round} do not all have the same committee ID",
                );
                Ok(())
            })?;
        }

        // Return success.
        Ok((
            expected_round,
            expected_height,
            expected_timestamp,
            expected_existing_solution_ids,
            expected_existing_transaction_ids,
        ))
    }

    /// Ensures the block ratifications are correct.
    fn verify_ratifications(&self, expected_block_reward: u64, expected_puzzle_reward: u64) -> Result<()> {
        let height = self.height();

        // Ensure there are sufficient ratifications.
        ensure!(self.ratifications.len() >= 2, "Block {height} must contain at least 2 ratifications");

        // Initialize a ratifications iterator.
        let mut ratifications_iter = self.ratifications.iter();

        // Retrieve the block reward from the first block ratification.
        let block_reward = match ratifications_iter.next() {
            Some(Ratify::BlockReward(block_reward)) => *block_reward,
            _ => bail!("Block {height} is invalid - the first ratification must be a block reward"),
        };
        // Retrieve the puzzle reward from the second block ratification.
        let puzzle_reward = match ratifications_iter.next() {
            Some(Ratify::PuzzleReward(puzzle_reward)) => *puzzle_reward,
            _ => bail!("Block {height} is invalid - the second ratification must be a puzzle reward"),
        };

        // Ensure the block reward is correct.
        ensure!(
            block_reward == expected_block_reward,
            "Block {height} has an invalid block reward (found '{block_reward}', expected '{expected_block_reward}')",
        );
        // Ensure the puzzle reward is correct.
        ensure!(
            puzzle_reward == expected_puzzle_reward,
            "Block {height} has an invalid puzzle reward (found '{puzzle_reward}', expected '{expected_puzzle_reward}')",
        );
        Ok(())
    }

    /// Ensures the block solutions are correct.
    fn verify_solutions(
        &self,
        previous_block: &Block<N>,
        current_puzzle: &Puzzle<N>,
        current_epoch_hash: N::BlockHash,
    ) -> Result<(u128, u128, u64, u64, u64, i64, u64, u64)> {
        let height = self.height();
        let timestamp = self.timestamp();

        // Ensure the number of solutions is within the allowed range.
        // This check is redundant if the block has been created via `Block::from()`.
        ensure!(
            self.solutions.len() <= N::MAX_SOLUTIONS,
            "Block {height} contains too many prover solutions (found '{}', expected '{}')",
            self.solutions.len(),
            N::MAX_SOLUTIONS
        );

        // Ensure the number of aborted solution IDs is within the allowed range.
        // This check is redundant if the block has been created via `Block::from()`.
        ensure!(
            self.aborted_solution_ids.len() <= Solutions::<N>::max_aborted_solutions(),
            "Block {height} contains too many aborted solution IDs (found '{}')",
            self.aborted_solution_ids.len(),
        );

        // Ensure there are no duplicate solution IDs.
        if has_duplicates(
            self.solutions
                .as_ref()
                .map(PuzzleSolutions::solution_ids)
                .into_iter()
                .flatten()
                .chain(self.aborted_solution_ids()),
        ) {
            bail!("Found a duplicate solution in block {height}");
        }

        // Compute the combined proof target.
        let combined_proof_target = match self.solutions.deref() {
            Some(solutions) => current_puzzle.get_combined_proof_target(solutions)?,
            None => 0u128,
        };

        // Verify the solutions.
        if let Some(coinbase) = self.solutions.deref() {
            // Ensure the puzzle proof is valid.
            if let Err(e) = current_puzzle.check_solutions(coinbase, current_epoch_hash, previous_block.proof_target())
            {
                bail!("Block {height} contains an invalid puzzle proof - {e}");
            }

            // Ensure that the block cumulative proof target is less than the previous block's coinbase target.
            // Note: This is a sanity check, as the cumulative proof target resets to 0 if the
            // coinbase target was reached in this block.
            if self.cumulative_proof_target() >= previous_block.coinbase_target() as u128 {
                bail!("The cumulative proof target in block {height} must be less than the previous coinbase target")
            }
        };

        // Calculate the next coinbase targets and timestamps.
        let (
            expected_coinbase_target,
            expected_proof_target,
            expected_cumulative_proof_target,
            expected_cumulative_weight,
            expected_last_coinbase_target,
            expected_last_coinbase_timestamp,
        ) = to_next_targets::<N>(
            N::CONSENSUS_VERSION(height)?,
            previous_block.cumulative_proof_target(),
            combined_proof_target,
            previous_block.coinbase_target(),
            previous_block.cumulative_weight(),
            previous_block.last_coinbase_target(),
            previous_block.last_coinbase_timestamp(),
            timestamp,
        )?;

        // Calculate the expected coinbase reward.
        let expected_coinbase_reward = coinbase_reward::<N>(
            height,
            timestamp,
            N::GENESIS_TIMESTAMP,
            N::STARTING_SUPPLY,
            N::REWARD_ANCHOR_TIME,
            N::ANCHOR_HEIGHT,
            N::BLOCK_TIME,
            combined_proof_target,
            u64::try_from(previous_block.cumulative_proof_target())?,
            previous_block.coinbase_target(),
        )?;

        // Calculate the expected transaction fees.
        let expected_transaction_fees =
            self.transactions.iter().map(|tx| Ok(*tx.priority_fee_amount()?)).sum::<Result<u64>>()?;

        // Calculate the time since last block.
        let time_since_last_block = timestamp.saturating_sub(previous_block.timestamp());
        // Compute the expected block reward.
        let expected_block_reward = block_reward::<N>(
            height,
            N::STARTING_SUPPLY,
            N::BLOCK_TIME,
            time_since_last_block,
            expected_coinbase_reward,
            expected_transaction_fees,
        )?;
        // Compute the expected puzzle reward.
        let expected_puzzle_reward = puzzle_reward(expected_coinbase_reward);

        Ok((
            expected_cumulative_weight,
            expected_cumulative_proof_target,
            expected_coinbase_target,
            expected_proof_target,
            expected_last_coinbase_target,
            expected_last_coinbase_timestamp,
            expected_block_reward,
            expected_puzzle_reward,
        ))
    }

    /// Ensures the block transactions are correct.
    fn verify_transactions(&self) -> Result<()> {
        let height = self.height();

        // Ensure the number of transactions is within the allowed range.
        // This check is redundant if the block has been created via `Block::from()`.
        if self.transactions.len() > Transactions::<N>::MAX_TRANSACTIONS {
            bail!(
                "Cannot validate a block with more than {} confirmed transactions",
                Transactions::<N>::MAX_TRANSACTIONS
            );
        }

        // Ensure the number of aborted transaction IDs is within the allowed range.
        // This check is redundant if the block has been created via `Block::from()`.
        if self.aborted_transaction_ids.len() > Transactions::<N>::max_aborted_transactions() {
            bail!(
                "Cannot validate a block with more than {} aborted transaction IDs",
                Transactions::<N>::max_aborted_transactions()
            );
        }

        // Ensure there are no duplicate transaction IDs.
        if has_duplicates(self.transaction_ids().chain(self.aborted_transaction_ids.iter())) {
            bail!("Found a duplicate transaction in block {height}");
        }

        // Ensure there are no duplicate transition IDs.
        if has_duplicates(self.transition_ids()) {
            bail!("Found a duplicate transition in block {height}");
        }

        // Ensure there are no duplicate program IDs.
        if has_duplicates(
            self.transactions().iter().filter_map(|tx| tx.transaction().deployment().map(|d| d.program_id())),
        ) {
            bail!("Found a duplicate program ID in block {height}");
        }

        /* Input */

        // Ensure there are no duplicate input IDs.
        if has_duplicates(self.input_ids()) {
            bail!("Found a duplicate input ID in block {height}");
        }
        // Ensure there are no duplicate serial numbers.
        if has_duplicates(self.serial_numbers()) {
            bail!("Found a duplicate serial number in block {height}");
        }
        // Ensure there are no duplicate tags.
        if has_duplicates(self.tags()) {
            bail!("Found a duplicate tag in block {height}");
        }

        /* Output */

        // Ensure there are no duplicate output IDs.
        if has_duplicates(self.output_ids()) {
            bail!("Found a duplicate output ID in block {height}");
        }
        // Ensure there are no duplicate commitments.
        if has_duplicates(self.commitments()) {
            bail!("Found a duplicate commitment in block {height}");
        }
        // Ensure there are no duplicate nonces.
        if has_duplicates(self.nonces()) {
            bail!("Found a duplicate nonce in block {height}");
        }

        /* Metadata */

        // Ensure there are no duplicate transition public keys.
        if has_duplicates(self.transition_public_keys()) {
            bail!("Found a duplicate transition public key in block {height}");
        }
        // Ensure there are no duplicate transition commitments.
        if has_duplicates(self.transition_commitments()) {
            bail!("Found a duplicate transition commitment in block {height}");
        }
        Ok(())
    }
}
impl<N: Network> Block<N> {
    /// Computes the transactions root for the block.
    fn compute_transactions_root(&self) -> Result<Field<N>> {
        match self.transactions.to_transactions_root() {
            Ok(transactions_root) => Ok(transactions_root),
            Err(error) => bail!("Failed to compute the transactions root for block {} - {error}", self.height()),
        }
    }

    /// Computes the finalize root for the block.
    fn compute_finalize_root(&self, ratified_finalize_operations: Vec<FinalizeOperation<N>>) -> Result<Field<N>> {
        match self.transactions.to_finalize_root(ratified_finalize_operations) {
            Ok(finalize_root) => Ok(finalize_root),
            Err(error) => bail!("Failed to compute the finalize root for block {} - {error}", self.height()),
        }
    }

    /// Computes the ratifications root for the block.
    fn compute_ratifications_root(&self) -> Result<Field<N>> {
        match self.ratifications.to_ratifications_root() {
            Ok(ratifications_root) => Ok(ratifications_root),
            Err(error) => bail!("Failed to compute the ratifications root for block {} - {error}", self.height()),
        }
    }

    /// Computes the solutions root for the block.
    fn compute_solutions_root(&self) -> Result<Field<N>> {
        self.solutions.to_solutions_root()
    }

    /// Computes the subdag root for the block.
    fn compute_subdag_root(&self) -> Result<Field<N>> {
        match self.authority {
            Authority::Quorum(ref subdag) => subdag.to_subdag_root(),
            Authority::Beacon(_) => Ok(Field::zero()),
        }
    }

    /// Checks that the transmission IDs in the given subdag matches the solutions and transactions in the block.
    /// Returns the IDs of the transactions and solutions that should already exist in the ledger.
    pub(super) fn check_subdag_transmissions(
        subdag: &Subdag<N>,
        solutions: &Option<PuzzleSolutions<N>>,
        aborted_solution_ids: &[SolutionID<N>],
        transactions: &Transactions<N>,
        aborted_transaction_ids: &[N::TransactionID],
    ) -> Result<(Vec<SolutionID<N>>, Vec<N::TransactionID>)> {
        // Prepare an iterator over the solution IDs.
        let mut solutions = solutions.as_ref().map(|s| s.deref()).into_iter().flatten().peekable();
        // Prepare an iterator over the unconfirmed transactions.
        let unconfirmed_transactions = cfg_iter!(transactions)
            .map(|confirmed| confirmed.to_unconfirmed_transaction())
            .collect::<Result<Vec<_>>>()?;
        let mut unconfirmed_transactions = unconfirmed_transactions.iter().peekable();

        // Initialize a set of already seen transaction and solution IDs.
        let mut seen_transaction_ids = HashSet::new();
        let mut seen_solution_ids = HashSet::new();

        // Initialize a set of aborted or already-existing solution IDs.
        let mut aborted_or_existing_solution_ids = HashSet::new();
        // Initialize a set of aborted or already-existing transaction IDs.
        let mut aborted_or_existing_transaction_ids = HashSet::new();

        // Iterate over the transmission IDs.
        for transmission_id in subdag.transmission_ids() {
            // If the transaction or solution ID has already been seen, then continue.
            // Note: This is done instead of checking `TransmissionID` directly, because we need to
            // ensure that each transaction or solution ID is unique. The `TransmissionID` is guaranteed
            // to be unique, however the transaction/solution ID may not be due to malleability concerns.
            match transmission_id {
                TransmissionID::Ratification => {}
                TransmissionID::Solution(solution_id, _) => {
                    if !seen_solution_ids.insert(solution_id) {
                        continue;
                    }
                }
                TransmissionID::Transaction(transaction_id, _) => {
                    if !seen_transaction_ids.insert(transaction_id) {
                        continue;
                    }
                }
            }

            // Process the transmission ID.
            match transmission_id {
                TransmissionID::Ratification => {}
                TransmissionID::Solution(solution_id, _checksum) => {
                    match solutions.peek() {
                        // Check the next solution matches the expected solution ID.
                        // We don't check against the checksum, because check_solution_mut might mutate the solution.
                        Some((_, solution)) if solution.id() == *solution_id => {
                            // Increment the solution iterator.
                            solutions.next();
                        }
                        // Otherwise, add the solution ID to the aborted or existing list.
                        _ => {
                            if !aborted_or_existing_solution_ids.insert(*solution_id) {
                                bail!("Block contains a duplicate aborted solution ID (found '{solution_id}')");
                            }
                        }
                    }
                }
                TransmissionID::Transaction(transaction_id, checksum) => {
                    match unconfirmed_transactions.peek() {
                        // Check the next transaction matches the expected transaction.
                        Some(transaction)
                            if transaction.id() == *transaction_id
                                && Data::<Transaction<N>>::Buffer(transaction.to_bytes_le()?.into())
                                    .to_checksum::<N>()?
                                    == *checksum =>
                        {
                            // Increment the unconfirmed transaction iterator.
                            unconfirmed_transactions.next();
                        }
                        // Otherwise, add the transaction ID to the aborted or existing list.
                        _ => {
                            if !aborted_or_existing_transaction_ids.insert(*transaction_id) {
                                bail!("Block contains a duplicate aborted transaction ID (found '{transaction_id}')");
                            }
                        }
                    }
                }
            }
        }

        // Ensure there are no more solutions in the block.
        ensure!(solutions.next().is_none(), "There exist more solutions than expected.");
        // Ensure there are no more transactions in the block.
        ensure!(unconfirmed_transactions.next().is_none(), "There exist more transactions than expected.");

        // Ensure the aborted solution IDs match.
        for aborted_solution_id in aborted_solution_ids {
            // If the aborted transaction ID is not found, throw an error.
            if !aborted_or_existing_solution_ids.contains(aborted_solution_id) {
                bail!(
                    "Block contains an aborted solution ID that is not found in the subdag (found '{aborted_solution_id}')"
                );
            }
        }
        // Ensure the aborted transaction IDs match.
        for aborted_transaction_id in aborted_transaction_ids {
            // If the aborted transaction ID is not found, throw an error.
            if !aborted_or_existing_transaction_ids.contains(aborted_transaction_id) {
                bail!(
                    "Block contains an aborted transaction ID that is not found in the subdag (found '{aborted_transaction_id}')"
                );
            }
        }

        // Retrieve the solution IDs that should already exist in the ledger.
        let existing_solution_ids: Vec<_> = aborted_or_existing_solution_ids
            .difference(&aborted_solution_ids.iter().copied().collect())
            .copied()
            .collect();
        // Retrieve the transaction IDs that should already exist in the ledger.
        let existing_transaction_ids: Vec<_> = aborted_or_existing_transaction_ids
            .difference(&aborted_transaction_ids.iter().copied().collect())
            .copied()
            .collect();

        Ok((existing_solution_ids, existing_transaction_ids))
    }
}
