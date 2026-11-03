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

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
// #![warn(clippy::cast_possible_truncation)]
#![cfg_attr(test, allow(clippy::single_element_loop))]

extern crate snarkvm_console as console;

pub mod header;
pub use header::*;

mod helpers;
pub use helpers::*;

pub mod ratifications;
pub use ratifications::*;

pub mod ratify;
pub use ratify::*;

pub mod solutions;
pub use solutions::*;

pub mod transaction;
pub use transaction::*;

pub mod transactions;
pub use transactions::*;

pub mod transition;
pub use transition::*;

mod bytes;
mod genesis;
mod serialize;
mod string;
mod verify;

use console::{
    account::PrivateKey,
    network::prelude::*,
    program::{Ciphertext, Record},
    types::{Field, Group, U64},
};
use snarkvm_ledger_authority::Authority;
use snarkvm_ledger_committee::Committee;
use snarkvm_ledger_narwhal_data::Data;
use snarkvm_ledger_narwhal_subdag::Subdag;
use snarkvm_ledger_narwhal_transmission_id::TransmissionID;
use snarkvm_ledger_puzzle::{PuzzleSolutions, Solution, SolutionID};

#[derive(Clone, PartialEq, Eq)]
pub struct Block<N: Network> {
    /// The hash of this block.
    block_hash: N::BlockHash,
    /// The hash of the previous block.
    previous_hash: N::BlockHash,
    /// The header of this block.
    header: Header<N>,
    /// The authority for this block.
    authority: Authority<N>,
    /// The ratifications in this block.
    ratifications: Ratifications<N>,
    /// The solutions in the block.
    solutions: Solutions<N>,
    /// The aborted solution IDs in this block.
    aborted_solution_ids: Vec<SolutionID<N>>,
    /// The transactions in this block.
    transactions: Transactions<N>,
    /// The aborted transaction IDs in this block.
    aborted_transaction_ids: Vec<N::TransactionID>,
}

impl<N: Network> Block<N> {
    /// Initializes a new beacon block from the given previous block hash, block header,
    /// ratifications, solutions, transactions, and aborted transaction IDs.
    pub fn new_beacon<R: Rng + CryptoRng>(
        private_key: &PrivateKey<N>,
        previous_hash: N::BlockHash,
        header: Header<N>,
        ratifications: Ratifications<N>,
        solutions: Solutions<N>,
        aborted_solution_ids: Vec<SolutionID<N>>,
        transactions: Transactions<N>,
        aborted_transaction_ids: Vec<N::TransactionID>,
        rng: &mut R,
    ) -> Result<Self> {
        // Compute the block hash.
        let block_hash = N::hash_bhp1024(&to_bits_le![previous_hash, header.to_root()?])?;
        // Construct the beacon authority.
        let authority = Authority::new_beacon(private_key, block_hash, rng)?;
        // Construct the block.
        Self::from(
            previous_hash,
            header,
            authority,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
        )
    }

    /// Initializes a new quorum block from the given previous block hash, block header,
    /// subdag, ratifications, solutions, transactions, and aborted transaction IDs.
    pub fn new_quorum(
        previous_hash: N::BlockHash,
        header: Header<N>,
        subdag: Subdag<N>,
        ratifications: Ratifications<N>,
        solutions: Solutions<N>,
        aborted_solution_ids: Vec<SolutionID<N>>,
        transactions: Transactions<N>,
        aborted_transaction_ids: Vec<N::TransactionID>,
    ) -> Result<Self> {
        // Construct the beacon authority.
        let authority = Authority::new_quorum(subdag);
        // Construct the block.
        Self::from(
            previous_hash,
            header,
            authority,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
        )
    }

    /// Initializes a new block from the given previous block hash, block header, authority,
    /// ratifications, solutions, aborted solution IDs, transactions, and aborted transaction IDs.
    fn from(
        previous_hash: N::BlockHash,
        header: Header<N>,
        authority: Authority<N>,
        ratifications: Ratifications<N>,
        solutions: Solutions<N>,
        aborted_solution_ids: Vec<SolutionID<N>>,
        transactions: Transactions<N>,
        aborted_transaction_ids: Vec<N::TransactionID>,
    ) -> Result<Self> {
        // Ensure the number of aborted solutions IDs is within the allowed range.
        if aborted_solution_ids.len() > Solutions::<N>::max_aborted_solutions() {
            bail!(
                "Cannot initialize a block with {} aborted solutions IDs which exceed the maximum {}",
                aborted_solution_ids.len(),
                Solutions::<N>::max_aborted_solutions()
            );
        }

        // Ensure the number of transactions is within the allowed range.
        if transactions.len() > Transactions::<N>::MAX_TRANSACTIONS {
            bail!(
                "Cannot initialize a block with {} confirmed transactions which exceed the maximum {}",
                transactions.len(),
                Transactions::<N>::MAX_TRANSACTIONS
            );
        }

        // Here we do not check that the number of solutions is within the allowed range,
        // because that was already done when constructing [`Solutions`] values,
        // specifically in [`PuzzleSolutions::new()`].

        // Ensure the number of aborted transaction IDs is within the allowed range.
        if aborted_transaction_ids.len() > Transactions::<N>::max_aborted_transactions() {
            bail!(
                "Cannot initialize a block with {} aborted transaction IDs which exceed the maximum {}",
                aborted_transaction_ids.len(),
                Transactions::<N>::max_aborted_transactions()
            );
        }

        // Compute the block hash.
        let block_hash = N::hash_bhp1024(&to_bits_le![previous_hash, header.to_root()?])?;

        // Verify the authority.
        match &authority {
            Authority::Beacon(signature) => {
                // Derive the signer address.
                let address = signature.to_address();
                // Ensure the signature is valid.
                ensure!(signature.verify(&address, &[block_hash]), "Invalid signature for block {}", header.height());
            }
            Authority::Quorum(subdag) => {
                // Ensure the certificates follow the canonical order for this consensus version.
                subdag.check_certificate_order(header.height())?;
                // Ensure the transmission IDs from the subdag correspond to the block.
                Self::check_subdag_transmissions(
                    subdag,
                    &solutions,
                    &aborted_solution_ids,
                    &transactions,
                    &aborted_transaction_ids,
                )?;
            }
        }

        // Ensure that coinbase accumulator matches the solutions.
        if header.solutions_root() != solutions.to_solutions_root()? {
            bail!("The solutions root in the block does not correspond to the solutions");
        }

        // Ensure that the subdag root matches the authority.
        let subdag_root = match &authority {
            Authority::Beacon(_) => Field::<N>::zero(),
            Authority::Quorum(subdag) => subdag.to_subdag_root()?,
        };
        if header.subdag_root() != subdag_root {
            bail!("The subdag root in the block does not correspond to the authority");
        }

        // Return the block.
        Self::from_unchecked(
            block_hash.into(),
            previous_hash,
            header,
            authority,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
        )
    }

    /// Initializes a new block from the given block hash, previous block hash, block header,
    /// authority, ratifications, solutions, transactions, and aborted transaction IDs.
    ///
    /// This function does *not* perform any checks on the given data, and should only be called
    /// if the inputs are trusted.
    pub fn from_unchecked(
        block_hash: N::BlockHash,
        previous_hash: N::BlockHash,
        header: Header<N>,
        authority: Authority<N>,
        ratifications: Ratifications<N>,
        solutions: Solutions<N>,
        aborted_solution_ids: Vec<SolutionID<N>>,
        transactions: Transactions<N>,
        aborted_transaction_ids: Vec<N::TransactionID>,
    ) -> Result<Self> {
        // Return the block.
        Ok(Self {
            block_hash,
            previous_hash,
            header,
            authority,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
        })
    }
}

impl<N: Network> Block<N> {
    /// Returns the block hash.
    pub const fn hash(&self) -> N::BlockHash {
        self.block_hash
    }

    /// Returns the previous block hash.
    pub const fn previous_hash(&self) -> N::BlockHash {
        self.previous_hash
    }

    /// Returns the authority.
    pub const fn authority(&self) -> &Authority<N> {
        &self.authority
    }

    /// Returns the ratifications in this block.
    pub const fn ratifications(&self) -> &Ratifications<N> {
        &self.ratifications
    }

    /// Returns the solutions in the block.
    pub const fn solutions(&self) -> &Solutions<N> {
        &self.solutions
    }

    /// Returns the aborted solution IDs in this block.
    pub const fn aborted_solution_ids(&self) -> &Vec<SolutionID<N>> {
        &self.aborted_solution_ids
    }

    /// Returns the transactions in this block.
    pub const fn transactions(&self) -> &Transactions<N> {
        &self.transactions
    }

    /// Returns the aborted transaction IDs in this block.
    pub const fn aborted_transaction_ids(&self) -> &Vec<N::TransactionID> {
        &self.aborted_transaction_ids
    }
}

impl<N: Network> Block<N> {
    /// Returns the block header.
    pub const fn header(&self) -> &Header<N> {
        &self.header
    }

    /// Returns the previous state root from the block header.
    pub const fn previous_state_root(&self) -> N::StateRoot {
        self.header.previous_state_root()
    }

    /// Returns the transactions root in the block header.
    pub const fn transactions_root(&self) -> Field<N> {
        self.header.transactions_root()
    }

    /// Returns the finalize root in the block header.
    pub const fn finalize_root(&self) -> Field<N> {
        self.header.finalize_root()
    }

    /// Returns the ratifications root in the block header.
    pub const fn ratifications_root(&self) -> Field<N> {
        self.header.ratifications_root()
    }

    /// Returns the solutions root in the block header.
    pub const fn solutions_root(&self) -> Field<N> {
        self.header.solutions_root()
    }

    /// Returns the metadata in the block header.
    pub const fn metadata(&self) -> &Metadata<N> {
        self.header.metadata()
    }

    /// Returns the network ID of this block.
    pub const fn network(&self) -> u16 {
        self.header.network()
    }

    /// Returns the height of this block.
    pub const fn height(&self) -> u32 {
        self.header.height()
    }

    /// Returns the round number of this block.
    pub const fn round(&self) -> u64 {
        self.header.round()
    }

    /// Returns the epoch number of this block.
    pub const fn epoch_number(&self) -> u32 {
        self.height() / N::NUM_BLOCKS_PER_EPOCH
    }

    /// Returns the cumulative weight for this block.
    pub const fn cumulative_weight(&self) -> u128 {
        self.header.cumulative_weight()
    }

    /// Returns the cumulative proof target for this block.
    pub const fn cumulative_proof_target(&self) -> u128 {
        self.header.cumulative_proof_target()
    }

    /// Returns the coinbase target for this block.
    pub const fn coinbase_target(&self) -> u64 {
        self.header.coinbase_target()
    }

    /// Returns the proof target for this block.
    pub const fn proof_target(&self) -> u64 {
        self.header.proof_target()
    }

    /// Returns the coinbase target of the last coinbase.
    pub const fn last_coinbase_target(&self) -> u64 {
        self.header.last_coinbase_target()
    }

    /// Returns the block timestamp of the last coinbase.
    pub const fn last_coinbase_timestamp(&self) -> i64 {
        self.header.last_coinbase_timestamp()
    }

    /// Returns the Unix timestamp (UTC) for this block.
    pub const fn timestamp(&self) -> i64 {
        self.header.timestamp()
    }
}

impl<N: Network> Block<N> {
    /// Returns `true` if the block contains the given transition ID.
    pub fn contains_transition(&self, transition_id: &N::TransitionID) -> bool {
        self.transactions.contains_transition(transition_id)
    }

    /// Returns `true` if the block contains the given serial number.
    pub fn contains_serial_number(&self, serial_number: &Field<N>) -> bool {
        self.transactions.contains_serial_number(serial_number)
    }

    /// Returns `true` if the block contains the given commitment.
    pub fn contains_commitment(&self, commitment: &Field<N>) -> bool {
        self.transactions.contains_commitment(commitment)
    }
}

impl<N: Network> Block<N> {
    /// Returns the solution with the given solution ID, if it exists.
    pub fn get_solution(&self, solution_id: &SolutionID<N>) -> Option<&Solution<N>> {
        self.solutions.as_ref().and_then(|solution| solution.get_solution(solution_id))
    }

    /// Returns the transaction with the given transaction ID, if it exists.
    pub fn get_transaction(&self, transaction_id: &N::TransactionID) -> Option<&Transaction<N>> {
        self.transactions.get(transaction_id).map(|t| t.deref())
    }

    /// Returns the confirmed transaction with the given transaction ID, if it exists.
    pub fn get_confirmed_transaction(&self, transaction_id: &N::TransactionID) -> Option<&ConfirmedTransaction<N>> {
        self.transactions.get(transaction_id)
    }
}

impl<N: Network> Block<N> {
    /// Returns the transaction with the given transition ID, if it exists.
    pub fn find_transaction_for_transition_id(&self, transition_id: &N::TransitionID) -> Option<&Transaction<N>> {
        self.transactions.find_transaction_for_transition_id(transition_id)
    }

    /// Returns the transaction with the given serial number, if it exists.
    pub fn find_transaction_for_serial_number(&self, serial_number: &Field<N>) -> Option<&Transaction<N>> {
        self.transactions.find_transaction_for_serial_number(serial_number)
    }

    /// Returns the transaction with the given commitment, if it exists.
    pub fn find_transaction_for_commitment(&self, commitment: &Field<N>) -> Option<&Transaction<N>> {
        self.transactions.find_transaction_for_commitment(commitment)
    }

    /// Returns the transition with the corresponding transition ID, if it exists.
    pub fn find_transition(&self, transition_id: &N::TransitionID) -> Option<&Transition<N>> {
        self.transactions.find_transition(transition_id)
    }

    /// Returns the transition for the given serial number, if it exists.
    pub fn find_transition_for_serial_number(&self, serial_number: &Field<N>) -> Option<&Transition<N>> {
        self.transactions.find_transition_for_serial_number(serial_number)
    }

    /// Returns the transition for the given commitment, if it exists.
    pub fn find_transition_for_commitment(&self, commitment: &Field<N>) -> Option<&Transition<N>> {
        self.transactions.find_transition_for_commitment(commitment)
    }

    /// Returns the record with the corresponding commitment, if it exists.
    pub fn find_record(&self, commitment: &Field<N>) -> Option<&Record<N, Ciphertext<N>>> {
        self.transactions.find_record(commitment)
    }
}

impl<N: Network> Block<N> {
    /// Returns an iterator over the solution IDs in this block.
    pub fn solution_ids(&self) -> Option<impl '_ + Iterator<Item = &SolutionID<N>>> {
        self.solutions.as_ref().map(|solution| solution.solution_ids())
    }

    /// Returns an iterator over the transaction IDs, for all transactions in `self`.
    pub fn transaction_ids(&self) -> impl '_ + Iterator<Item = &N::TransactionID> {
        self.transactions.transaction_ids()
    }

    /// Returns an iterator over all transactions in `self` that are accepted deploy transactions.
    pub fn deployments(&self) -> impl '_ + Iterator<Item = &ConfirmedTransaction<N>> {
        self.transactions.deployments()
    }

    /// Returns an iterator over all transactions in `self` that are accepted execute transactions.
    pub fn executions(&self) -> impl '_ + Iterator<Item = &ConfirmedTransaction<N>> {
        self.transactions.executions()
    }

    /// Returns an iterator over all transitions.
    pub fn transitions(&self) -> impl '_ + Iterator<Item = &Transition<N>> {
        self.transactions.transitions()
    }

    /// Returns an iterator over the transition IDs, for all transitions.
    pub fn transition_ids(&self) -> impl '_ + Iterator<Item = &N::TransitionID> {
        self.transactions.transition_ids()
    }

    /// Returns an iterator over the transition public keys, for all transactions.
    pub fn transition_public_keys(&self) -> impl '_ + Iterator<Item = &Group<N>> {
        self.transactions.transition_public_keys()
    }

    /// Returns an iterator over the transition commitments, for all transactions.
    pub fn transition_commitments(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.transactions.transition_commitments()
    }

    /// Returns an iterator over the tags, for all transition inputs that are records.
    pub fn tags(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.transactions.tags()
    }

    /// Returns an iterator over the input IDs, for all transition inputs that are records.
    pub fn input_ids(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.transactions.input_ids()
    }

    /// Returns an iterator over the serial numbers, for all transition inputs that are records.
    pub fn serial_numbers(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.transactions.serial_numbers()
    }

    /// Returns an iterator over the output IDs, for all transition inputs that are records.
    pub fn output_ids(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.transactions.output_ids()
    }

    /// Returns an iterator over the commitments, for all transition outputs that are records.
    pub fn commitments(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.transactions.commitments()
    }

    /// Returns an iterator over the records, for all transition outputs that are records.
    pub fn records(&self) -> impl '_ + Iterator<Item = (&Field<N>, &Record<N, Ciphertext<N>>)> {
        self.transactions.records()
    }

    /// Returns an iterator over the nonces, for all transition outputs that are records.
    pub fn nonces(&self) -> impl '_ + Iterator<Item = &Group<N>> {
        self.transactions.nonces()
    }

    /// Returns an iterator over the transaction fee amounts, for all transactions.
    pub fn transaction_fee_amounts(&self) -> impl '_ + Iterator<Item = Result<U64<N>>> {
        self.transactions.transaction_fee_amounts()
    }
}

impl<N: Network> Block<N> {
    /// Returns a consuming iterator over the transaction IDs, for all transactions in `self`.
    pub fn into_transaction_ids(self) -> impl Iterator<Item = N::TransactionID> {
        self.transactions.into_transaction_ids()
    }

    /// Returns a consuming iterator over all transactions in `self` that are accepted deploy transactions.
    pub fn into_deployments(self) -> impl Iterator<Item = ConfirmedTransaction<N>> {
        self.transactions.into_deployments()
    }

    /// Returns a consuming iterator over all transactions in `self` that are accepted execute transactions.
    pub fn into_executions(self) -> impl Iterator<Item = ConfirmedTransaction<N>> {
        self.transactions.into_executions()
    }

    /// Returns a consuming iterator over all transitions.
    pub fn into_transitions(self) -> impl Iterator<Item = Transition<N>> {
        self.transactions.into_transitions()
    }

    /// Returns a consuming iterator over the transition IDs, for all transitions.
    pub fn into_transition_ids(self) -> impl Iterator<Item = N::TransitionID> {
        self.transactions.into_transition_ids()
    }

    /// Returns a consuming iterator over the transition public keys, for all transactions.
    pub fn into_transition_public_keys(self) -> impl Iterator<Item = Group<N>> {
        self.transactions.into_transition_public_keys()
    }

    /// Returns a consuming iterator over the tags, for all transition inputs that are records.
    pub fn into_tags(self) -> impl Iterator<Item = Field<N>> {
        self.transactions.into_tags()
    }

    /// Returns a consuming iterator over the serial numbers, for all transition inputs that are records.
    pub fn into_serial_numbers(self) -> impl Iterator<Item = Field<N>> {
        self.transactions.into_serial_numbers()
    }

    /// Returns a consuming iterator over the commitments, for all transition outputs that are records.
    pub fn into_commitments(self) -> impl Iterator<Item = Field<N>> {
        self.transactions.into_commitments()
    }

    /// Returns a consuming iterator over the records, for all transition outputs that are records.
    pub fn into_records(self) -> impl Iterator<Item = (Field<N>, Record<N, Ciphertext<N>>)> {
        self.transactions.into_records()
    }

    /// Returns a consuming iterator over the nonces, for all transition outputs that are records.
    pub fn into_nonces(self) -> impl Iterator<Item = Group<N>> {
        self.transactions.into_nonces()
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;

    use snarkvm_algorithms::snark::varuna::VarunaVersion;
    use snarkvm_console::account::{Address, PrivateKey};
    use snarkvm_ledger_query::Query;
    use snarkvm_ledger_store::{BlockStore, helpers::memory::BlockMemory};
    use snarkvm_synthesizer_process::Process;
    use snarkvm_utilities::PrettyUnwrap;

    use aleo_std::StorageMode;
    use std::sync::OnceLock;

    type CurrentNetwork = console::network::MainnetV0;
    type CurrentAleo = snarkvm_circuit::network::AleoV0;

    /// Samples a random genesis block.
    pub(crate) fn sample_genesis_block(rng: &mut TestRng) -> Block<CurrentNetwork> {
        // Sample the genesis block and components.
        let (block, _, _) = sample_genesis_block_and_components(rng);
        // Return the block.
        block
    }

    /// Samples a random genesis block and the transaction from the genesis block.
    pub(crate) fn sample_genesis_block_and_transaction(
        rng: &mut TestRng,
    ) -> (Block<CurrentNetwork>, Transaction<CurrentNetwork>) {
        // Sample the genesis block and components.
        let (block, transaction, _) = sample_genesis_block_and_components(rng);
        // Return the block and transaction.
        (block, transaction)
    }

    /// Samples a random genesis block, the transaction from the genesis block, and the genesis private key.
    pub(crate) fn sample_genesis_block_and_components(
        rng: &mut TestRng,
    ) -> (Block<CurrentNetwork>, Transaction<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
        static INSTANCE: OnceLock<(Block<CurrentNetwork>, Transaction<CurrentNetwork>, PrivateKey<CurrentNetwork>)> =
            OnceLock::new();
        INSTANCE.get_or_init(|| sample_genesis_block_and_components_raw(rng)).clone()
    }

    /// Samples a random genesis block, the transaction from the genesis block, and the genesis private key.
    fn sample_genesis_block_and_components_raw(
        rng: &mut TestRng,
    ) -> (Block<CurrentNetwork>, Transaction<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
        // Sample the genesis private key.
        let private_key = PrivateKey::new(rng).unwrap();
        let address = Address::<CurrentNetwork>::try_from(private_key).unwrap();

        // Prepare the locator.
        let locator = ("credits.aleo", "transfer_public_to_private");
        // Prepare the amount for each call to the function.
        let amount = 100_000_000u64;
        // Prepare the function inputs.
        let inputs = [address.to_string(), format!("{amount}_u64")];

        // Initialize the process.
        let process = Process::load().unwrap();
        // Authorize the function.
        let authorization =
            process.authorize::<CurrentAleo, _>(&private_key, locator.0, locator.1, inputs.iter(), rng).unwrap();
        // Execute the function.
        let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        // Prepare the assignments.
        trace.prepare(&Query::from(block_store)).unwrap();
        // Compute the proof and construct the execution.
        let execution = trace.prove_execution::<CurrentAleo, _>(locator.0, VarunaVersion::V1, rng).unwrap();
        // Convert the execution.
        // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
        let execution = Execution::from_str(&execution.to_string()).unwrap();

        // Construct the transaction.
        let transaction = Transaction::from_execution(execution, None).unwrap();
        // Prepare the confirmed transaction.
        let confirmed = ConfirmedTransaction::accepted_execute(0, transaction.clone(), vec![]).unwrap();
        // Prepare the transactions.
        let transactions = Transactions::from_iter([confirmed]);

        // Construct the ratifications.
        let ratifications = Ratifications::try_from(vec![]).unwrap();

        // Prepare the block header.
        let header = Header::genesis(&ratifications, &transactions, vec![]).unwrap();
        // Prepare the previous block hash.
        let previous_hash = <CurrentNetwork as Network>::BlockHash::default();

        // Construct the block.
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
        assert!(block.header().is_genesis().pretty_unwrap(), "Failed to initialize a genesis block");
        // Return the block, transaction, and private key.
        (block, transaction, private_key)
    }

    pub(crate) fn sample_metadata() -> Metadata<CurrentNetwork> {
        let network = CurrentNetwork::ID;
        let round = u64::MAX;
        let height = u32::MAX;
        let cumulative_weight = u128::MAX - 1;
        let cumulative_proof_target = u128::MAX - 1;
        let coinbase_target = u64::MAX;
        let proof_target = u64::MAX - 1;
        let last_coinbase_target = u64::MAX;
        let timestamp = i64::MAX - 1;
        let last_coinbase_timestamp = timestamp - 1;

        Metadata::new(
            network,
            round,
            height,
            cumulative_weight,
            cumulative_proof_target,
            coinbase_target,
            proof_target,
            last_coinbase_target,
            last_coinbase_timestamp,
            timestamp,
        )
        .pretty_unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use console::network::MainnetV0;
    use indexmap::IndexMap;
    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_find_transaction_for_transition_id() {
        let rng = &mut TestRng::default();

        let (block, transaction) = crate::test_helpers::sample_genesis_block_and_transaction(rng);
        let transactions = block.transactions();

        // Retrieve the transitions.
        let transitions = transaction.transitions().collect::<Vec<_>>();
        assert!(!transitions.is_empty());

        // Ensure the transaction is found.
        for transition in transitions {
            assert_eq!(block.find_transaction_for_transition_id(transition.id()), Some(&transaction));
            assert_eq!(transactions.find_transaction_for_transition_id(transition.id()), Some(&transaction));
        }

        // Ensure the transaction is not found.
        for _ in 0..10 {
            let transition_id = &rng.random();
            assert_eq!(block.find_transaction_for_transition_id(transition_id), None);
            assert_eq!(transactions.find_transaction_for_transition_id(transition_id), None);
        }
    }

    #[test]
    fn test_find_transaction_for_commitment() {
        let rng = &mut TestRng::default();

        let (block, transaction) = crate::test_helpers::sample_genesis_block_and_transaction(rng);
        let transactions = block.transactions();

        // Retrieve the commitments.
        let commitments = transaction.commitments().collect::<Vec<_>>();
        assert!(!commitments.is_empty());

        // Ensure the commitments are found.
        for commitment in commitments {
            assert_eq!(block.find_transaction_for_commitment(commitment), Some(&transaction));
            assert_eq!(transactions.find_transaction_for_commitment(commitment), Some(&transaction));
        }

        // Ensure the commitments are not found.
        for _ in 0..10 {
            let commitment = &rng.random();
            assert_eq!(block.find_transaction_for_commitment(commitment), None);
            assert_eq!(transactions.find_transaction_for_commitment(commitment), None);
        }
    }

    #[test]
    fn test_find_transition() {
        let rng = &mut TestRng::default();

        let (block, transaction) = crate::test_helpers::sample_genesis_block_and_transaction(rng);
        let transactions = block.transactions();

        // Retrieve the transitions.
        let transitions = transaction.transitions().collect::<Vec<_>>();
        assert!(!transitions.is_empty());

        // Ensure the transitions are found.
        for transition in transitions {
            assert_eq!(block.find_transition(transition.id()), Some(transition));
            assert_eq!(transactions.find_transition(transition.id()), Some(transition));
            assert_eq!(transaction.find_transition(transition.id()), Some(transition));
        }

        // Ensure the transitions are not found.
        for _ in 0..10 {
            let transition_id = &rng.random();
            assert_eq!(block.find_transition(transition_id), None);
            assert_eq!(transactions.find_transition(transition_id), None);
            assert_eq!(transaction.find_transition(transition_id), None);
        }
    }

    #[test]
    fn test_find_transition_for_commitment() {
        let rng = &mut TestRng::default();

        let (block, transaction) = crate::test_helpers::sample_genesis_block_and_transaction(rng);
        let transactions = block.transactions();

        // Retrieve the transitions.
        let transitions = transaction.transitions().collect::<Vec<_>>();
        assert!(!transitions.is_empty());

        for transition in transitions {
            // Retrieve the commitments.
            let commitments = transition.commitments().collect::<Vec<_>>();
            assert!(!commitments.is_empty());

            // Ensure the commitments are found.
            for commitment in commitments {
                assert_eq!(block.find_transition_for_commitment(commitment), Some(transition));
                assert_eq!(transactions.find_transition_for_commitment(commitment), Some(transition));
                assert_eq!(transaction.find_transition_for_commitment(commitment), Some(transition));
            }
        }

        // Ensure the commitments are not found.
        for _ in 0..10 {
            let commitment = &rng.random();
            assert_eq!(block.find_transition_for_commitment(commitment), None);
            assert_eq!(transactions.find_transition_for_commitment(commitment), None);
            assert_eq!(transaction.find_transition_for_commitment(commitment), None);
        }
    }

    #[test]
    fn test_find_record() {
        let rng = &mut TestRng::default();

        let (block, transaction) = crate::test_helpers::sample_genesis_block_and_transaction(rng);
        let transactions = block.transactions();

        // Retrieve the records.
        let records = transaction.records().collect::<IndexMap<_, _>>();
        assert!(!records.is_empty());

        // Ensure the records are found.
        for (commitment, record) in records {
            assert_eq!(block.find_record(commitment), Some(record));
            assert_eq!(transactions.find_record(commitment), Some(record));
            assert_eq!(transaction.find_record(commitment), Some(record));
        }

        // Ensure the records are not found.
        for _ in 0..10 {
            let commitment = &rng.random();
            assert_eq!(block.find_record(commitment), None);
            assert_eq!(transactions.find_record(commitment), None);
            assert_eq!(transaction.find_record(commitment), None);
        }
    }

    #[test]
    fn test_serde_metadata() {
        let metadata = crate::test_helpers::sample_metadata();
        let json_metadata = serde_json::to_string(&metadata).unwrap();
        let deserialized_metadata: Metadata<CurrentNetwork> = serde_json::from_str(&json_metadata).unwrap();
        assert_eq!(metadata, deserialized_metadata);
    }
}
