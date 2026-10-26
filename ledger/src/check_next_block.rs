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

use crate::{narwhal::BatchHeader, puzzle::SolutionID};

use anyhow::{Context, bail};

use snarkvm_synthesizer_error::VmCheckBlockContentError;

/// Wrapper for a block that has a valid subDAG, but where the block header,
/// solutions, and transmissions have not been verified yet.
///
/// This type is created by `Ledger::check_block_subdag` and consumed by `Ledger::check_block_content`.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingBlock<N: Network>(Block<N>);

impl<N: Network> Deref for PendingBlock<N> {
    type Target = Block<N>;

    fn deref(&self) -> &Block<N> {
        &self.0
    }
}

impl<N: Network> Debug for PendingBlock<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PendingBlock {{ height: {}, hash: {} }}", self.height(), self.hash())
    }
}

/// Error returned by [`Self::check_block_subdag`] and [`Self::check_block_subdag_inner`].
///
/// This allows parsing for begning errors, such as the block already existing in the ledger.
#[derive(thiserror::Error, Debug)]
pub enum CheckBlockError<N: Network> {
    #[error("Block with hash {hash} already exists in the ledger")]
    BlockAlreadyExists { hash: N::BlockHash },
    #[error("Block has invalid height. Expected {expected}, but got {actual}")]
    InvalidHeight { expected: u32, actual: u32 },
    #[error("Block has invalid round. Was {new}, but must be greater than previous round ({previous})")]
    InvalidRound { new: u64, previous: u64 },
    #[error("Block has invalid hash")]
    InvalidHash,
    /// An error related to the given prefix of pending blocks.
    #[error("The prefix as an error at index {index} - {error:?}")]
    InvalidPrefix { index: usize, error: Box<CheckBlockError<N>> },
    #[error("The block contains solution '{solution_id}', but it already exists in the ledger")]
    SolutionAlreadyExists { solution_id: SolutionID<N> },
    #[error("Failed to speculate over unconfirmed transactions - {inner}")]
    SpeculationFailed { inner: anyhow::Error },
    #[error("Failed to verify block - {inner}")]
    VerificationFailed { inner: anyhow::Error },
    #[error("Prover '{prover_address}' has reached their solution limit for the current epoch")]
    SolutionLimitReached { prover_address: Address<N> },
    #[error("The previous block should contain solution '{solution_id}', but it does not exist in the ledger")]
    PreviousSolutionNotFound { solution_id: SolutionID<N> },
    #[error("The previous block should contain solution '{transaction_id}', but it does not exist in the ledger")]
    PreviousTransactionNotFound { transaction_id: N::TransactionID },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl<N: Network> CheckBlockError<N> {
    pub fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::Other(err) => err,
            _ => anyhow::anyhow!("{self:?}"),
        }
    }
}

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Checks that the subDAG in a given block is valid, but does not fully verify the block.
    ///
    /// # Arguments
    /// * `block` - The block to check.
    /// * `prefix` - A sequence of blocks between the block to check and the current height of the ledger.
    ///
    /// # Returns
    /// * On success, a [`PendingBlock`] representing the block that was checked. Once the prefix of this block has been fully added to the ledger,
    ///   the [`PendingBlock`] can then be passed to [`Self::check_block_content`] to fully verify it.
    /// * On failure, a [`CheckBlockError`] describing the reason the block was rejected.
    ///
    /// # Notes
    /// * This does *not* check that the header of the block is correct or execute/verify any of the transmissions contained within it.
    /// * In most cases, you want to use [`Self::check_next_block`] instead to perform a full verification.
    /// * This will reject any blocks with a height <= the current height and any blocks with a height >= the current height + GC.
    ///   For the former, a valid block already exists and,for the latter, the comittee is still unknown.
    /// * This function executes atomically, in that there is guaranteed to be no concurrent updates to the ledger during its execution.
    ///   However there are no ordering guarantees *between* multiple invocations of this function, [`Self::check_block_content`] and [`Self::advance_to_next_block`].
    pub fn check_block_subdag(
        &self,
        block: Block<N>,
        prefix: &[PendingBlock<N>],
    ) -> Result<PendingBlock<N>, CheckBlockError<N>> {
        self.check_block_subdag_inner(&block, prefix)?;
        Ok(PendingBlock(block))
    }

    fn check_block_subdag_inner(&self, block: &Block<N>, prefix: &[PendingBlock<N>]) -> Result<(), CheckBlockError<N>> {
        // Grab a lock to the latest_block in the ledger, to prevent concurrent writes to the ledger,
        // and to ensure that this check is atomic.
        //
        // Note: The latest block in the ledger is not necessarily the direct predecessor of `block`.
        // If `prefix` is non-empty the direct predecessor is the last entry in the prefix.
        let latest_block = self.current_block.read();

        // First check that the heights and hashes of the pending block sequence and of the new block are correct.
        // The hash checks should be redundant, but we perform them out of extra caution.
        let mut expected_height = latest_block.height() + 1;
        for (index, prefix_block) in prefix.iter().enumerate() {
            if prefix_block.height() != expected_height {
                return Err(CheckBlockError::InvalidPrefix {
                    index,
                    error: Box::new(CheckBlockError::InvalidHeight {
                        expected: expected_height,
                        actual: prefix_block.height(),
                    }),
                });
            }

            if self.contains_block_hash(&prefix_block.hash())? {
                return Err(CheckBlockError::InvalidPrefix {
                    index,
                    error: Box::new(CheckBlockError::BlockAlreadyExists { hash: prefix_block.hash() }),
                });
            }

            expected_height += 1;
        }

        if self.contains_block_hash(&block.hash())? {
            return Err(CheckBlockError::BlockAlreadyExists { hash: block.hash() });
        }

        if block.height() != expected_height {
            return Err(CheckBlockError::InvalidHeight { expected: expected_height, actual: block.height() });
        }

        // Ensure the certificates in the block subdag have met quorum requirements.
        self.check_block_subdag_quorum(block)?;

        // Check subDAG atomicity against the latest block in the prefix.
        // Only if the prefix is empty, check against the latest block in the ledger.
        let predecessor = prefix.last().map_or(&*latest_block, |b| &**b);
        self.check_block_subdag_atomicity(block, predecessor)?;

        // Ensure that all leaves of the subdag point to valid batches in other subdags/blocks.
        self.check_block_subdag_leaves(block, prefix)?;

        Ok(())
    }

    /// Checks the given block is a valid next block with regard to the current state/height of the Ledger.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    pub fn check_next_block<R: CryptoRng + Rng>(&self, block: &Block<N>, rng: &mut R) -> Result<()> {
        self.check_block_subdag_inner(block, &[]).map_err(|err| err.into_anyhow())?;
        self.check_block_content_inner(block, rng).map_err(|err| err.into_anyhow())?;

        Ok(())
    }

    /// Takes a pending block and performs the remaining checks to full verify it.
    ///
    /// # Arguments
    /// This takes a [`PendingBlock`] as input, which is the output of a successful call to [`Self::check_block_subdag`].
    /// The latter already verified the block's DAG and certificate signatures.
    ///
    /// # Return Value
    /// This returns a [`Block`] on success representing the fully verified block.
    ///
    /// # Notes
    /// - This check can only succeed for pending blocks that are a direct successor of the latest block in the ledger.
    /// - Execution of this function is atomic, and there is guaranteed to be no concurrent update to the ledger during its execution.
    /// - Even though this function may return `Ok(block)`, advancing the ledger to this block may still fail, if there was an update to the ledger
    ///   *between* calling `check_block_content` and `advance_to_next_block`.
    ///   If your implementation requires atomicity across these two steps, you need to implement your own locking mechanism.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    pub fn check_block_content<R: CryptoRng + Rng>(
        &self,
        block: PendingBlock<N>,
        rng: &mut R,
    ) -> Result<Block<N>, CheckBlockError<N>> {
        self.check_block_content_inner(&block.0, rng)?;
        Ok(block.0)
    }

    /// # Panics
    /// This function panics if called from an async context.
    fn check_block_content_inner<R: CryptoRng + Rng>(
        &self,
        block: &Block<N>,
        rng: &mut R,
    ) -> Result<(), CheckBlockError<N>> {
        let latest_block = self.current_block.read();
        let latest_block_timestamp = latest_block.timestamp();

        // Ensure, again, that the ledger has not advanced yet. This prevents cryptic errors form appearing during the block check.
        if block.height() != latest_block.height() + 1 {
            return Err(CheckBlockError::InvalidHeight { expected: latest_block.height() + 1, actual: block.height() });
        }

        // Also ensure the round is valid, otherwise speculation on transactions will fail with a cryptic error.
        if block.round() <= latest_block.round() {
            return Err(CheckBlockError::InvalidRound { new: block.round(), previous: latest_block.round() });
        }

        // Ensure the solutions do not already exist.
        for solution_id in block.solutions().solution_ids() {
            if self.contains_solution_id(solution_id)? {
                return Err(CheckBlockError::SolutionAlreadyExists { solution_id: *solution_id });
            }
        }

        // Retrieve the committee lookback.
        let committee_lookback = self
            .get_committee_lookback_for_round(block.round())?
            .ok_or(anyhow!("Failed to fetch committee lookback for round {}", block.round()))?;

        // Retrieve the previous committee lookback.
        let previous_committee_lookback = {
            // Calculate the penultimate round, which is the round before the anchor round.
            let penultimate_round = block.round().saturating_sub(1);
            // Output the committee lookback for the penultimate round.
            self.get_committee_lookback_for_round(penultimate_round)?
                .ok_or(anyhow!("Failed to fetch committee lookback for round {penultimate_round}"))?
        };

        // Get the latest epoch hash.
        let latest_epoch_hash = match self.current_epoch_hash.read().as_ref() {
            Some(epoch_hash) => *epoch_hash,
            None => self.get_epoch_hash(latest_block.height())?,
        };

        let (expected_existing_solution_ids, expected_existing_transaction_ids) =
            match self.vm.check_block_content_inner(
                block,
                &latest_block,
                latest_block_timestamp,
                self.latest_state_root(),
                &previous_committee_lookback,
                &committee_lookback,
                self.puzzle(),
                latest_epoch_hash,
                OffsetDateTime::now_utc().unix_timestamp(),
                rng,
            ) {
                Ok(ids) => ids,
                Err(VmCheckBlockContentError::Speculation(inner)) => {
                    return Err(CheckBlockError::SpeculationFailed { inner });
                }
                Err(VmCheckBlockContentError::Verification(inner)) => {
                    return Err(CheckBlockError::VerificationFailed { inner });
                }
            };

        // Ensure that the provers are within their stake bounds.
        if let Some(solutions) = block.solutions().deref() {
            let mut accepted_solutions: IndexMap<Address<N>, u64> = IndexMap::new();
            for solution in solutions.values() {
                let prover_address = solution.address();
                let num_accepted_solutions = *accepted_solutions.get(&prover_address).unwrap_or(&0);
                // Check if the prover has reached their solution limit.
                if self.is_solution_limit_reached_at_timestamp(
                    &prover_address,
                    num_accepted_solutions,
                    latest_block_timestamp,
                ) {
                    return Err(CheckBlockError::SolutionLimitReached { prover_address });
                }
                // Track the already accepted solutions.
                *accepted_solutions.entry(prover_address).or_insert(0) += 1;
            }
        }

        // Ensure that each existing solution ID from the block exists in the ledger.
        for existing_solution_id in expected_existing_solution_ids {
            if !self.contains_solution_id(&existing_solution_id)? {
                return Err(CheckBlockError::PreviousSolutionNotFound { solution_id: existing_solution_id });
            }
        }

        // Ensure that each existing transaction ID from the block exists in the ledger.
        for existing_transaction_id in expected_existing_transaction_ids {
            if !self.contains_transaction_id(&existing_transaction_id)? {
                return Err(CheckBlockError::PreviousTransactionNotFound { transaction_id: existing_transaction_id });
            }
        }

        Ok(())
    }

    /// Check that leaves in the subdag point to batches in other blocks that are valid.
    ///
    //
    /// # Arguments
    /// * `block` - The block to check.
    /// * `prefix` - A sequence of [`PendingBlock`]s between the block to check and the current height of the ledger.
    ///
    /// # Notes
    /// This only checks that leaves point to valid batch in the previous round, and *not* hat the batches are signed correctly
    /// or that the edges are valid, as those checks already happened when the node received the batch.
    fn check_block_subdag_leaves(&self, block: &Block<N>, prefix: &[PendingBlock<N>]) -> Result<()> {
        // Check if the block has a subdag.
        let Authority::Quorum(subdag) = block.authority() else {
            return Ok(());
        };

        let previous_certs: HashSet<_> = prefix
            .iter()
            .filter_map(|block| match block.authority() {
                Authority::Quorum(subdag) => Some(subdag.certificate_ids()),
                Authority::Beacon(_) => None,
            })
            .flatten()
            .collect();

        // Store the IDs of all certificates in this subDAG.
        // This allows determining which edges point to other subDAGs/blocks.
        let subdag_certs: HashSet<_> = subdag.certificate_ids().collect();

        // Generate a set of all external certificates this subDAG references.
        // If multiple certificates reference the same external certificate, the id and round number will be
        // identical and the set will contain only one entry for the external certificate.
        let leaf_edges: HashSet<_> = subdag
            .certificates()
            .flat_map(|cert| cert.previous_certificate_ids().iter().map(|prev_id| (cert.round() - 1, prev_id)))
            .filter(|(_, prev_id)| !subdag_certs.contains(prev_id))
            .collect();

        cfg_iter!(leaf_edges).try_for_each(|(prev_round, prev_id)| {
            if prev_round + (BatchHeader::<N>::MAX_GC_ROUNDS as u64) - 1 <= block.round() {
                // If the previous round is at the end of GC, we cannot (and do not need to) verify the next batch.
                // For this leaf we are at the maximum length of the DAG, so any following batches are not allowed
                // to be part of the block and, thus, a malicious actor cannot remove them.
                return Ok::<(), Error>(());
            }

            // Ensure that the certificate is associated with a previous block.
            if !previous_certs.contains(prev_id) && !self.vm.block_store().contains_block_for_certificate(prev_id)? {
                bail!(
                    "Batch(es) in the block point(s) to a certificate {prev_id} in round {prev_round} that is not associated with a previous block"
                )
            }

            Ok(())
        })
    }

    /// Check that the certificates in the block subdag have met quorum requirements.
    ///
    /// Called by [`Self::check_block_subdag`]
    fn check_block_subdag_quorum(&self, block: &Block<N>) -> Result<()> {
        // Check if the block has a subdag.
        let subdag = match block.authority() {
            Authority::Quorum(subdag) => subdag,
            _ => return Ok(()),
        };

        // Check that all certificates on each round have met quorum requirements.
        cfg_iter!(subdag).try_for_each(|(round, certificates)| {
            // Retrieve the committee lookback for the round.
            let committee_lookback = self
                .get_committee_lookback_for_round(*round)
                .with_context(|| format!("Failed to get committee lookback for round {round}"))?
                .ok_or_else(|| anyhow!("No committee lookback for round {round}"))?;

            // Check that each certificate for this round has met quorum requirements.
            // Note that we do not need to check the quorum requirement for the previous certificates
            // because that is done during construction in `BatchCertificate::new`.
            cfg_iter!(certificates).try_for_each(|certificate| {
                // Collect the certificate signers. Note that `signers` is cached on the
                // certificate, so this does not re-derive an address per signature.
                let mut signers: HashSet<_> = certificate.signers().iter().copied().collect();
                // Append the certificate author.
                signers.insert(certificate.author());

                // Ensure that the signers of the certificate reach the quorum threshold.
                ensure!(
                    committee_lookback.is_quorum_threshold_reached(&signers),
                    "Certificate '{}' for round {round} does not meet quorum requirements",
                    certificate.id()
                );

                Ok::<_, Error>(())
            })?;

            Ok::<_, Error>(())
        })?;

        Ok(())
    }

    /// Checks that the block subdag can not be split into multiple valid subdags.
    ///
    /// Called by [`Self::check_block_subdag`]
    fn check_block_subdag_atomicity(&self, block: &Block<N>, latest_block: &Block<N>) -> Result<()> {
        let latest_round = latest_block.round();

        // Returns `true` if there is a path from the previous certificate to the current certificate.
        fn is_linked<N: Network>(
            subdag: &Subdag<N>,
            previous_certificate: &BatchCertificate<N>,
            current_certificate: &BatchCertificate<N>,
        ) -> Result<bool> {
            // Initialize the list containing the traversal.
            let mut traversal = vec![current_certificate];
            // Iterate over the rounds from the current certificate to the previous certificate.
            for round in (previous_certificate.round()..current_certificate.round()).rev() {
                // Retrieve all of the certificates for this past round.
                let certificates = subdag.get(&round).ok_or(anyhow!("No certificates found for round {round}"))?;
                // Filter the certificates to only include those that are in the traversal.
                traversal = certificates
                    .into_iter()
                    .filter(|p| traversal.iter().any(|c| c.previous_certificate_ids().contains(&p.id())))
                    .collect();
            }
            Ok(traversal.contains(&previous_certificate))
        }

        // Check if the block has a subdag.
        let subdag = match block.authority() {
            Authority::Quorum(subdag) => subdag,
            _ => return Ok(()),
        };

        // Iterate over the rounds to find possible leader certificates.
        for round in (latest_round.saturating_add(2)..=subdag.anchor_round().saturating_sub(2)).rev().step_by(2) {
            // Retrieve the previous committee lookback.
            let previous_committee_lookback = self
                .get_committee_lookback_for_round(round)?
                .ok_or_else(|| anyhow!("No committee lookback found for round {round}"))?;

            // Compute the leader for the commit round.
            let computed_leader = previous_committee_lookback
                .get_leader(round)
                .with_context(|| format!("Failed to compute leader for round {round}"))?;

            // Retrieve the previous leader certificates.
            let previous_certificate = match subdag.get(&round).and_then(|certificates| {
                certificates.iter().find(|certificate| certificate.author() == computed_leader)
            }) {
                Some(cert) => cert,
                None => continue,
            };

            // Determine if there is a path between the previous certificate and the subdag's leader certificate.
            if is_linked(subdag, previous_certificate, subdag.leader_certificate())? {
                bail!(
                    "The previous certificate should not be linked to the current certificate in block {}",
                    block.height()
                );
            }
        }

        Ok(())
    }
}
