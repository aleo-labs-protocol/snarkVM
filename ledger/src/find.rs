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

use snarkvm_utilities::flatten_error;

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Returns the block height that contains the given `state root`.
    pub fn find_block_height_from_state_root(&self, state_root: N::StateRoot) -> Result<Option<u32>> {
        self.vm.block_store().find_block_height_from_state_root(state_root)
    }

    /// Returns the block hash that contains the given `transaction ID`.
    pub fn find_block_hash(&self, transaction_id: &N::TransactionID) -> Result<Option<N::BlockHash>> {
        self.vm.block_store().find_block_hash(transaction_id)
    }

    /// Returns the block height that contains the given `solution ID`.
    pub fn find_block_height_from_solution_id(&self, solution_id: &SolutionID<N>) -> Result<Option<u32>> {
        self.vm.block_store().find_block_height_from_solution_id(solution_id)
    }

    /// Returns the latest transaction ID that contains the given `program ID`.
    /// If amendments exist for the latest edition, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID for the latest edition.
    pub fn find_latest_transaction_id_from_program_id(
        &self,
        program_id: &ProgramID<N>,
    ) -> Result<Option<N::TransactionID>> {
        self.vm.transaction_store().find_latest_transaction_id_from_program_id(program_id)
    }

    /// Returns the original deployment transaction ID for the given `program ID` and `edition`.
    /// This returns the initial deployment, not any subsequent amendments.
    pub fn find_original_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.vm.transaction_store().find_original_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the latest transaction ID for the given `program ID` and `edition`.
    /// If amendments exist, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID.
    pub fn find_latest_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.vm.transaction_store().find_latest_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the transaction ID for the given `program ID`, `edition`, and `amendment_index`.
    /// Returns `None` if no such amendment exists.
    pub fn find_transaction_id_from_program_id_edition_and_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<N::TransactionID>> {
        self.vm.transaction_store().find_transaction_id_from_program_id_edition_and_amendment(
            program_id,
            edition,
            amendment_index,
        )
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    pub fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.vm.transaction_store().find_transaction_id_from_transition_id(transition_id)
    }

    /// Returns the transition ID that contains the given `input ID` or `output ID`.
    pub fn find_transition_id(&self, id: &Field<N>) -> Result<N::TransitionID> {
        self.vm.transition_store().find_transition_id(id)
    }

    /// Returns the record ciphertexts that belong to the given view key.
    #[allow(clippy::type_complexity)]
    pub fn find_record_ciphertexts<'a>(
        &'a self,
        view_key: &'a ViewKey<N>,
        filter: RecordsFilter<N>,
    ) -> Result<impl 'a + Iterator<Item = (Field<N>, Cow<'a, Record<N, Ciphertext<N>>>)>> {
        // Derive the x-coordinate of the address corresponding to the given view key.
        let address_x_coordinate = view_key.to_address().to_x_coordinate();
        // Derive the `sk_tag` from the graph key.
        let sk_tag = match GraphKey::try_from(view_key) {
            Ok(graph_key) => graph_key.sk_tag(),
            Err(e) => bail!("Failed to derive the graph key from the view key: {e}"),
        };

        Ok(self.records().flat_map(move |cow| {
            // Retrieve the commitment and record.
            let (commitment, record) = match cow {
                (Cow::Borrowed(commitment), record) => (*commitment, record),
                (Cow::Owned(commitment), record) => (commitment, record),
            };

            // Check ownership before determining whether to decrypt the record.
            if !record.is_owner_with_address_x_coordinate(view_key, &address_x_coordinate) {
                return None;
            }

            // Determine whether to decrypt this record (or not), based on the filter.
            let commitment = match filter {
                RecordsFilter::All => Ok(Some(commitment)),
                RecordsFilter::Spent => Record::<N, Plaintext<N>>::tag(sk_tag, commitment).and_then(|tag| {
                    // Determine if the record is spent.
                    self.contains_tag(&tag).map(|is_spent| match is_spent {
                        true => Some(commitment),
                        false => None,
                    })
                }),
                RecordsFilter::Unspent => Record::<N, Plaintext<N>>::tag(sk_tag, commitment).and_then(|tag| {
                    // Determine if the record is spent.
                    self.contains_tag(&tag).map(|is_spent| match is_spent {
                        true => None,
                        false => Some(commitment),
                    })
                }),
                RecordsFilter::SlowSpent(private_key) => {
                    Record::<N, Plaintext<N>>::serial_number(private_key, commitment).and_then(|serial_number| {
                        // Determine if the record is spent.
                        self.contains_serial_number(&serial_number).map(|is_spent| match is_spent {
                            true => Some(commitment),
                            false => None,
                        })
                    })
                }
                RecordsFilter::SlowUnspent(private_key) => {
                    Record::<N, Plaintext<N>>::serial_number(private_key, commitment).and_then(|serial_number| {
                        // Determine if the record is spent.
                        self.contains_serial_number(&serial_number).map(|is_spent| match is_spent {
                            true => None,
                            false => Some(commitment),
                        })
                    })
                }
            };

            match commitment {
                Ok(Some(commitment)) => Some((commitment, record)),
                Ok(None) => None,
                Err(err) => {
                    warn!("{}", &flatten_error(err.context("Failed to process 'find_record_ciphertexts({filter:?})'")));
                    None
                }
            }
        }))
    }

    /// Returns the records that belong to the given view key.
    #[allow(clippy::type_complexity)]
    pub fn find_records<'a>(
        &'a self,
        view_key: &'a ViewKey<N>,
        filter: RecordsFilter<N>,
    ) -> Result<impl 'a + Iterator<Item = (Field<N>, Record<N, Plaintext<N>>)>> {
        self.find_record_ciphertexts(view_key, filter).map(|iter| {
            iter.flat_map(|(commitment, record)| match record.decrypt(view_key) {
                Ok(record) => Some((commitment, record)),
                Err(err) => {
                    warn!("{}", &flatten_error(err.context("Failed to decrypt record")));
                    None
                }
            })
        })
    }
}
