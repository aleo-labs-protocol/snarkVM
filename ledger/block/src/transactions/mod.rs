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

pub mod confirmed;
pub use confirmed::*;

pub mod rejected;
pub use rejected::*;

pub mod rejected_reason;
pub use rejected_reason::*;

mod bytes;
mod merkle;
mod serialize;
mod string;

use crate::{Transaction, Transition};
use console::{
    network::prelude::*,
    program::{
        Ciphertext,
        FINALIZE_ID_DEPTH,
        FINALIZE_OPERATIONS_DEPTH,
        Identifier,
        ProgramID,
        ProgramOwner,
        Record,
        TRANSACTIONS_DEPTH,
        TransactionsPath,
        TransactionsTree,
    },
    types::{Field, Group, U64},
};
use snarkvm_ledger_committee::Committee;
use snarkvm_ledger_narwhal_batch_header::BatchHeader;
use snarkvm_synthesizer_error::IndexedFinalizeError;
use snarkvm_synthesizer_program::{Command, FinalizeOperation};

use indexmap::IndexMap;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// The set of transactions included in a block.
#[derive(Clone, PartialEq, Eq)]
pub struct Transactions<N: Network> {
    /// The transactions included in a block.
    transactions: IndexMap<N::TransactionID, ConfirmedTransaction<N>>,
}

impl<N: Network> Transactions<N> {
    /// Initializes from a given transactions list.
    pub fn from(transactions: &[ConfirmedTransaction<N>]) -> Self {
        Self::from_iter(transactions.iter())
    }
}

impl<N: Network> FromIterator<ConfirmedTransaction<N>> for Transactions<N> {
    /// Initializes from an iterator of transactions.
    fn from_iter<T: IntoIterator<Item = ConfirmedTransaction<N>>>(iter: T) -> Self {
        Self { transactions: iter.into_iter().map(|transaction| (transaction.id(), transaction)).collect() }
    }
}

impl<'a, N: Network> FromIterator<&'a ConfirmedTransaction<N>> for Transactions<N> {
    /// Initializes from an iterator of transactions.
    fn from_iter<T: IntoIterator<Item = &'a ConfirmedTransaction<N>>>(iter: T) -> Self {
        Self::from_iter(iter.into_iter().cloned())
    }
}

impl<N: Network> Transactions<N> {
    /// Returns the transaction for the given transaction ID.
    pub fn get(&self, transaction_id: &N::TransactionID) -> Option<&ConfirmedTransaction<N>> {
        self.transactions.get(transaction_id)
    }

    /// Returns 'true' if there are no accepted or rejected transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Returns the number of confirmed transactions.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Returns the number of accepted transactions.
    pub fn num_accepted(&self) -> usize {
        cfg_values!(self.transactions).filter(|tx| tx.is_accepted()).count()
    }

    /// Returns the number of rejected transactions.
    pub fn num_rejected(&self) -> usize {
        cfg_values!(self.transactions).filter(|tx| tx.is_rejected()).count()
    }

    /// Returns the number of finalize operations.
    pub fn num_finalize(&self) -> usize {
        cfg_values!(self.transactions).map(|tx| tx.num_finalize()).sum()
    }

    /// Returns the index of the transaction with the given ID, if it exists.
    pub fn index_of(&self, transaction_id: &N::TransactionID) -> Option<usize> {
        self.transactions.get_index_of(transaction_id)
    }
}

impl<N: Network> Transactions<N> {
    /// Returns `true` if the transactions contains the given transition ID.
    pub fn contains_transition(&self, transition_id: &N::TransitionID) -> bool {
        cfg_values!(self.transactions).any(|tx| tx.contains_transition(transition_id))
    }

    /// Returns `true` if the transactions contains the given serial number.
    pub fn contains_serial_number(&self, serial_number: &Field<N>) -> bool {
        cfg_values!(self.transactions).any(|tx| tx.contains_serial_number(serial_number))
    }

    /// Returns `true` if the transactions contains the given commitment.
    pub fn contains_commitment(&self, commitment: &Field<N>) -> bool {
        cfg_values!(self.transactions).any(|tx| tx.contains_commitment(commitment))
    }
}

impl<N: Network> Transactions<N> {
    /// Returns the confirmed transaction for the given unconfirmed transaction ID, if it exists.
    pub fn find_confirmed_transaction_for_unconfirmed_transaction_id(
        &self,
        unconfirmed_transaction_id: &N::TransactionID,
    ) -> Option<&ConfirmedTransaction<N>> {
        cfg_find!(self.transactions, |txn| txn.contains_unconfirmed_transaction_id(unconfirmed_transaction_id))
    }

    /// Returns the transaction with the given transition ID, if it exists.
    ///
    /// If the given transition ID is a fee transition for a rejected transaction,
    /// this will return the fee transaction.
    pub fn find_transaction_for_transition_id(&self, transition_id: &N::TransitionID) -> Option<&Transaction<N>> {
        cfg_find!(self.transactions, |txn| txn.contains_transition(transition_id)).map(|tx| tx.transaction())
    }

    /// Returns the unconfirmed transaction with the given transition ID, if it exists.
    ///
    /// If the given transition ID is a fee transition for a rejected transaction,
    /// this will return the original/unconfirmed transaction, not the fee transaction.
    pub fn find_unconfirmed_transaction_for_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<Transaction<N>>> {
        let result = cfg_find!(self.transactions, |tx| tx.contains_transition(transition_id));

        match result {
            Some(txn) => Ok(Some(txn.to_unconfirmed_transaction()?)),
            None => Ok(None),
        }
    }

    /// Returns the transaction with the given serial number, if it exists.
    pub fn find_transaction_for_serial_number(&self, serial_number: &Field<N>) -> Option<&Transaction<N>> {
        cfg_find!(self.transactions, |txn| txn.contains_serial_number(serial_number)).map(|tx| tx.transaction())
    }

    /// Returns the transaction with the given commitment, if it exists.
    pub fn find_transaction_for_commitment(&self, commitment: &Field<N>) -> Option<&Transaction<N>> {
        cfg_find!(self.transactions, |txn| txn.contains_commitment(commitment)).map(|tx| tx.transaction())
    }

    /// Returns the transition with the corresponding transition ID, if it exists.
    pub fn find_transition(&self, transition_id: &N::TransitionID) -> Option<&Transition<N>> {
        cfg_find_map!(self.transactions, |txn| txn.find_transition(transition_id))
    }

    /// Returns the transition for the given serial number, if it exists.
    pub fn find_transition_for_serial_number(&self, serial_number: &Field<N>) -> Option<&Transition<N>> {
        cfg_find_map!(self.transactions, |txn| txn.find_transition_for_serial_number(serial_number))
    }

    /// Returns the transition for the given commitment, if it exists.
    pub fn find_transition_for_commitment(&self, commitment: &Field<N>) -> Option<&Transition<N>> {
        cfg_find_map!(self.transactions, |txn| txn.find_transition_for_commitment(commitment))
    }

    /// Returns the record with the corresponding commitment, if it exists.
    pub fn find_record(&self, commitment: &Field<N>) -> Option<&Record<N, Ciphertext<N>>> {
        cfg_find_map!(self.transactions, |txn| txn.find_record(commitment))
    }
}

impl<N: Network> Transactions<N> {
    /// The maximum number of transactions allowed in a block.
    pub const MAX_TRANSACTIONS: usize = usize::pow(2, TRANSACTIONS_DEPTH as u32).saturating_sub(1);

    /// The maximum number of aborted transactions allowed in a block.
    pub fn max_aborted_transactions() -> usize {
        BatchHeader::<N>::MAX_TRANSMISSIONS_PER_BATCH
            * BatchHeader::<N>::MAX_GC_ROUNDS
            * Committee::<N>::max_committee_size() as usize
    }

    /// Returns an iterator over all transactions, for all transactions in `self`.
    pub fn iter(&self) -> impl '_ + ExactSizeIterator<Item = &ConfirmedTransaction<N>> {
        self.transactions.values()
    }

    /// Returns a parallel iterator over all transactions, for all transactions in `self`.
    #[cfg(not(feature = "serial"))]
    pub fn par_iter(&self) -> impl '_ + IndexedParallelIterator<Item = &ConfirmedTransaction<N>> {
        self.transactions.par_values()
    }

    /// Returns an iterator over the transaction IDs, for all transactions in `self`.
    pub fn transaction_ids(&self) -> impl '_ + ExactSizeIterator<Item = &N::TransactionID> {
        self.transactions.keys()
    }

    /// Returns an iterator over all transactions in `self` that are accepted deploy transactions.
    pub fn deployments(&self) -> impl '_ + Iterator<Item = &ConfirmedTransaction<N>> {
        self.iter().filter(|tx| tx.is_accepted() && tx.is_deploy())
    }

    /// Returns an iterator over all transactions in `self` that are accepted execute transactions.
    pub fn executions(&self) -> impl '_ + Iterator<Item = &ConfirmedTransaction<N>> {
        self.iter().filter(|tx| tx.is_accepted() && tx.is_execute())
    }

    /// Returns an iterator over all transitions.
    pub fn transitions(&self) -> impl '_ + Iterator<Item = &Transition<N>> {
        self.iter().flat_map(|tx| tx.transitions())
    }

    /// Returns an iterator over the transition IDs, for all transitions.
    pub fn transition_ids(&self) -> impl '_ + Iterator<Item = &N::TransitionID> {
        self.iter().flat_map(|tx| tx.transition_ids())
    }

    /// Returns an iterator over the transition public keys, for all transactions.
    pub fn transition_public_keys(&self) -> impl '_ + Iterator<Item = &Group<N>> {
        self.iter().flat_map(|tx| tx.transition_public_keys())
    }

    /// Returns an iterator over the transition commitments, for all transactions.
    pub fn transition_commitments(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.iter().flat_map(|tx| tx.transition_commitments())
    }

    /// Returns an iterator over the tags, for all transition inputs that are records.
    pub fn tags(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.iter().flat_map(|tx| tx.tags())
    }

    /// Returns an iterator over the input IDs, for all transition inputs that are records.
    pub fn input_ids(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.iter().flat_map(|tx| tx.input_ids())
    }

    /// Returns an iterator over the serial numbers, for all transition inputs that are records.
    pub fn serial_numbers(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.iter().flat_map(|tx| tx.serial_numbers())
    }

    /// Returns an iterator over the output IDs, for all transition inputs that are records.
    pub fn output_ids(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.iter().flat_map(|tx| tx.output_ids())
    }

    /// Returns an iterator over the commitments, for all transition outputs that are records.
    pub fn commitments(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.iter().flat_map(|tx| tx.commitments())
    }

    /// Returns an iterator over the records, for all transition outputs that are records.
    pub fn records(&self) -> impl '_ + Iterator<Item = (&Field<N>, &Record<N, Ciphertext<N>>)> {
        self.iter().flat_map(|tx| tx.records())
    }

    /// Returns an iterator over the nonces, for all transition outputs that are records.
    pub fn nonces(&self) -> impl '_ + Iterator<Item = &Group<N>> {
        self.iter().flat_map(|tx| tx.nonces())
    }

    /// Returns an iterator over the transaction fee amounts, for all transactions.
    pub fn transaction_fee_amounts(&self) -> impl '_ + Iterator<Item = Result<U64<N>>> {
        self.iter().map(|tx| tx.fee_amount())
    }

    /// Returns an iterator over the finalize operations, for all transactions.
    pub fn finalize_operations(&self) -> impl '_ + Iterator<Item = &FinalizeOperation<N>> {
        self.iter().flat_map(|tx| tx.finalize_operations())
    }
}

impl<N: Network> IntoIterator for Transactions<N> {
    type IntoIter = indexmap::map::IntoValues<N::TransactionID, Self::Item>;
    type Item = ConfirmedTransaction<N>;

    /// Returns a consuming iterator over all transactions, for all transactions in `self`.
    fn into_iter(self) -> Self::IntoIter {
        self.transactions.into_values()
    }
}

impl<N: Network> Transactions<N> {
    /// Returns a consuming iterator over the transaction IDs, for all transactions in `self`.
    pub fn into_transaction_ids(self) -> impl ExactSizeIterator<Item = N::TransactionID> {
        self.transactions.into_keys()
    }

    /// Returns a consuming iterator over all transactions in `self` that are accepted deploy transactions.
    pub fn into_deployments(self) -> impl Iterator<Item = ConfirmedTransaction<N>> {
        self.into_iter().filter(|tx| tx.is_accepted() && tx.is_deploy())
    }

    /// Returns a consuming iterator over all transactions in `self` that are accepted execute transactions.
    pub fn into_executions(self) -> impl Iterator<Item = ConfirmedTransaction<N>> {
        self.into_iter().filter(|tx| tx.is_accepted() && tx.is_execute())
    }

    /// Returns a consuming iterator over all transitions.
    pub fn into_transitions(self) -> impl Iterator<Item = Transition<N>> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_transitions())
    }

    /// Returns a consuming iterator over the transition IDs, for all transitions.
    pub fn into_transition_ids(self) -> impl Iterator<Item = N::TransitionID> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_transition_ids())
    }

    /// Returns a consuming iterator over the transition public keys, for all transactions.
    pub fn into_transition_public_keys(self) -> impl Iterator<Item = Group<N>> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_transition_public_keys())
    }

    /// Returns a consuming iterator over the tags, for all transition inputs that are records.
    pub fn into_tags(self) -> impl Iterator<Item = Field<N>> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_tags())
    }

    /// Returns a consuming iterator over the serial numbers, for all transition inputs that are records.
    pub fn into_serial_numbers(self) -> impl Iterator<Item = Field<N>> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_serial_numbers())
    }

    /// Returns a consuming iterator over the commitments, for all transition outputs that are records.
    pub fn into_commitments(self) -> impl Iterator<Item = Field<N>> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_commitments())
    }

    /// Returns a consuming iterator over the records, for all transition outputs that are records.
    pub fn into_records(self) -> impl Iterator<Item = (Field<N>, Record<N, Ciphertext<N>>)> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_records())
    }

    /// Returns a consuming iterator over the nonces, for all transition outputs that are records.
    pub fn into_nonces(self) -> impl Iterator<Item = Group<N>> {
        self.into_iter().flat_map(|tx| tx.into_transaction().into_nonces())
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    /// Samples a block transactions.
    pub(crate) fn sample_block_transactions(rng: &mut TestRng) -> Transactions<CurrentNetwork> {
        crate::test_helpers::sample_genesis_block(rng).transactions().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_ledger_narwhal_batch_header::BatchHeader;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_max_transmissions() {
        // Determine the maximum number of transmissions in a block.
        let max_transmissions_per_block = BatchHeader::<CurrentNetwork>::MAX_TRANSMISSIONS_PER_BATCH
            * BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS
            * CurrentNetwork::LATEST_MAX_CERTIFICATES() as usize;

        // Note: The maximum number of *transmissions* in a block cannot exceed the maximum number of *transactions* in a block.
        // If you intended to change the number of 'MAX_TRANSACTIONS', note that this will break the inclusion proof,
        // and you will need to migrate all users to a new circuit for the inclusion proof.
        assert!(
            max_transmissions_per_block <= Transactions::<CurrentNetwork>::MAX_TRANSACTIONS,
            "The maximum number of transmissions in a block is too large"
        );
    }
}
