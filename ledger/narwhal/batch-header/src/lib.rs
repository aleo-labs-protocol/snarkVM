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
#![warn(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_arguments)]

extern crate snarkvm_console as console;

mod bytes;
mod serialize;
mod string;
mod to_id;

use console::{
    account::{Address, PrivateKey, Signature},
    prelude::*,
    types::Field,
};
use snarkvm_ledger_narwhal_transmission_id::TransmissionID;

use indexmap::IndexSet;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq)]
pub struct BatchHeader<N: Network> {
    /// The batch ID, defined as the hash of the author, round number, timestamp, transmission IDs,
    /// committee ID, and previous batch certificate IDs.
    batch_id: Field<N>,
    /// The author of the batch.
    author: Address<N>,
    /// The round number.
    round: u64,
    /// The timestamp.
    timestamp: i64,
    /// The committee ID.
    committee_id: Field<N>,
    /// The set of `transmission IDs`.
    transmission_ids: IndexSet<TransmissionID<N>>,
    /// The batch certificate IDs of the previous round.
    previous_certificate_ids: IndexSet<Field<N>>,
    /// The signature of the batch ID from the creator.
    signature: Signature<N>,
}

impl<N: Network> BatchHeader<N> {
    /// The maximum number of rounds to store before garbage collecting.
    pub const MAX_GC_ROUNDS: usize = 100;
    /// The maximum number of transmissions in a batch.
    /// Note: This limit is set to 50 as part of safety measures to prevent DoS attacks.
    /// This limit can be increased in the future as performance improves. Alternatively,
    /// the rate of block production can be sped up to compensate for the limit set here.
    pub const MAX_TRANSMISSIONS_PER_BATCH: usize = 50;
}

impl<N: Network> BatchHeader<N> {
    /// The maximum number of microcredits that can be spent on compute by the transactions in a batch.
    pub fn batch_spend_limit(height: u32) -> u64 {
        // TODO(vicsn) a more robust setup would bound the batch spend limit further.
        // For example to: 5_f64 * credits_per_second_of_runtime / max_certificates.
        if height >= N::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap() {
            consensus_config_value!(N, TRANSACTION_SPEND_LIMIT, height).unwrap()
        } else {
            // NOTE: div by 20 was temporary until we could dial in what the limit should be.
            consensus_config_value!(N, TRANSACTION_SPEND_LIMIT, height).unwrap()
                * Self::MAX_TRANSMISSIONS_PER_BATCH as u64
                / 20
        }
    }
}

impl<N: Network> BatchHeader<N> {
    /// Initializes a new batch header.
    pub fn new<R: Rng + CryptoRng>(
        private_key: &PrivateKey<N>,
        round: u64,
        timestamp: i64,
        committee_id: Field<N>,
        transmission_ids: IndexSet<TransmissionID<N>>,
        previous_certificate_ids: IndexSet<Field<N>>,
        rng: &mut R,
    ) -> Result<Self> {
        match round {
            0 | 1 => {
                // If the round is zero or one, then there should be no previous certificate IDs.
                ensure!(previous_certificate_ids.is_empty(), "Invalid round number, must not have certificates");
            }
            // If the round is not zero and not one, then there should be at least one previous certificate ID.
            _ => ensure!(!previous_certificate_ids.is_empty(), "Invalid round number, must have certificates"),
        }

        // Ensure that the number of transmissions is within bounds.
        ensure!(
            transmission_ids.len() <= Self::MAX_TRANSMISSIONS_PER_BATCH,
            "Invalid number of transmission IDs ({})",
            transmission_ids.len()
        );
        // Ensure that the number of previous certificate IDs is within bounds.
        ensure!(
            previous_certificate_ids.len() <= N::LATEST_MAX_CERTIFICATES() as usize,
            "Invalid number of previous certificate IDs ({})",
            previous_certificate_ids.len()
        );

        // Retrieve the address.
        let author = Address::try_from(private_key)?;
        // Compute the batch ID.
        let batch_id = Self::compute_batch_id(
            author,
            round,
            timestamp,
            committee_id,
            &transmission_ids,
            &previous_certificate_ids,
        )?;
        // Sign the preimage.
        let signature = private_key.sign(&[batch_id], rng)?;
        // Return the batch header.
        Ok(Self {
            batch_id,
            author,
            round,
            timestamp,
            committee_id,
            transmission_ids,
            previous_certificate_ids,
            signature,
        })
    }

    /// Initializes a new batch header.
    pub fn from(
        author: Address<N>,
        round: u64,
        timestamp: i64,
        committee_id: Field<N>,
        transmission_ids: IndexSet<TransmissionID<N>>,
        previous_certificate_ids: IndexSet<Field<N>>,
        signature: Signature<N>,
    ) -> Result<Self> {
        match round {
            0 | 1 => {
                // If the round is zero or one, then there should be no previous certificate IDs.
                ensure!(previous_certificate_ids.is_empty(), "Invalid round number, must not have certificates");
            }
            // If the round is not zero and not one, then there should be at least one previous certificate ID.
            _ => ensure!(!previous_certificate_ids.is_empty(), "Invalid round number, must have certificates"),
        }

        // Ensure that the number of transmissions is within bounds.
        ensure!(
            transmission_ids.len() <= Self::MAX_TRANSMISSIONS_PER_BATCH,
            "Invalid number of transmission IDs ({})",
            transmission_ids.len()
        );
        // Ensure that the number of previous certificate IDs is within bounds.
        ensure!(
            previous_certificate_ids.len() <= N::LATEST_MAX_CERTIFICATES() as usize,
            "Invalid number of previous certificate IDs ({})",
            previous_certificate_ids.len()
        );

        // Compute the batch ID.
        let batch_id = Self::compute_batch_id(
            author,
            round,
            timestamp,
            committee_id,
            &transmission_ids,
            &previous_certificate_ids,
        )?;
        // Verify the signature.
        if !signature.verify(&author, &[batch_id]) {
            bail!("Invalid signature for the batch header");
        }
        // Return the batch header.
        Ok(Self::from_unchecked(
            author,
            batch_id,
            round,
            timestamp,
            committee_id,
            transmission_ids,
            previous_certificate_ids,
            signature,
        ))
    }

    /// Initializes a new batch header from the given data,
    /// *without* checking it for correctness/consistency.
    pub fn from_unchecked(
        author: Address<N>,
        batch_id: Field<N>,
        round: u64,
        timestamp: i64,
        committee_id: Field<N>,
        transmission_ids: IndexSet<TransmissionID<N>>,
        previous_certificate_ids: IndexSet<Field<N>>,
        signature: Signature<N>,
    ) -> Self {
        // Return the batch header.
        Self { author, batch_id, round, timestamp, committee_id, transmission_ids, previous_certificate_ids, signature }
    }
}

impl<N: Network> BatchHeader<N> {
    /// Returns the batch ID.
    pub const fn batch_id(&self) -> Field<N> {
        self.batch_id
    }

    /// Returns the author.
    pub const fn author(&self) -> Address<N> {
        self.author
    }

    /// Returns the round number.
    pub const fn round(&self) -> u64 {
        self.round
    }

    /// Returns the timestamp.
    pub const fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Returns the committee ID.
    pub const fn committee_id(&self) -> Field<N> {
        self.committee_id
    }

    /// Returns the transmission IDs.
    pub const fn transmission_ids(&self) -> &IndexSet<TransmissionID<N>> {
        &self.transmission_ids
    }

    /// Returns the batch certificate IDs for the previous round.
    pub const fn previous_certificate_ids(&self) -> &IndexSet<Field<N>> {
        &self.previous_certificate_ids
    }

    /// Returns the signature.
    pub const fn signature(&self) -> &Signature<N> {
        &self.signature
    }
}

impl<N: Network> BatchHeader<N> {
    /// Returns `true` if the batch header is empty.
    pub fn is_empty(&self) -> bool {
        self.transmission_ids.is_empty()
    }

    /// Returns the number of transmissions in the batch header.
    pub fn len(&self) -> usize {
        self.transmission_ids.len()
    }

    /// Returns `true` if the batch contains the specified `transmission ID`.
    pub fn contains(&self, transmission_id: impl Into<TransmissionID<N>>) -> bool {
        self.transmission_ids.contains(&transmission_id.into())
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{
        account::PrivateKey,
        network::MainnetV0,
        prelude::{TestRng, Uniform},
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    type CurrentNetwork = MainnetV0;

    /// Returns a sample batch header, sampled at random.
    pub fn sample_batch_header(rng: &mut TestRng) -> BatchHeader<CurrentNetwork> {
        sample_batch_header_for_round(rng.random(), rng)
    }

    /// Returns a sample batch header with a given round; the rest is sampled at random.
    pub fn sample_batch_header_for_round(round: u64, rng: &mut TestRng) -> BatchHeader<CurrentNetwork> {
        // Sample certificate IDs.
        let certificate_ids = (0..10).map(|_| Field::<CurrentNetwork>::rand(rng)).collect::<IndexSet<_>>();
        // Return the batch header.
        sample_batch_header_for_round_with_previous_certificate_ids(round, certificate_ids, rng)
    }

    /// Returns a sample batch header with a given round and set of previous certificate IDs; the rest is sampled at random.
    pub fn sample_batch_header_for_round_with_previous_certificate_ids(
        round: u64,
        previous_certificate_ids: IndexSet<Field<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> BatchHeader<CurrentNetwork> {
        // Sample a private key.
        let private_key = PrivateKey::new(rng).unwrap();
        // Generate a new certificated with the key as its author.
        sample_batch_header_for_round_and_key_with_previous_certificate_ids(
            round,
            &private_key,
            previous_certificate_ids,
            rng,
        )
    }

    /// Returns a sample batch header with a given round, author key, and set of previous certificate IDs; the rest is sampled at random.
    pub fn sample_batch_header_for_round_and_key_with_previous_certificate_ids(
        round: u64,
        private_key: &PrivateKey<CurrentNetwork>,
        previous_certificate_ids: IndexSet<Field<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> BatchHeader<CurrentNetwork> {
        // Sample the committee ID.
        let committee_id = Field::<CurrentNetwork>::rand(rng);
        // Sample transmission IDs.
        let transmission_ids = snarkvm_ledger_narwhal_transmission_id::test_helpers::sample_transmission_ids(rng)
            .into_iter()
            .collect::<IndexSet<_>>();
        // The timestamp needs to be current to pass integration tests.
        let timestamp =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("System time before UNIX epoch").as_secs() as i64;
        // Return the batch header.
        BatchHeader::new(private_key, round, timestamp, committee_id, transmission_ids, previous_certificate_ids, rng)
            .unwrap()
    }

    /// Returns a list of sample batch headers, sampled at random.
    pub fn sample_batch_headers(rng: &mut TestRng) -> Vec<BatchHeader<CurrentNetwork>> {
        // Initialize a sample vector.
        let mut sample = Vec::with_capacity(10);
        // Append sample batches.
        for _ in 0..10 {
            // Append the batch header.
            sample.push(sample_batch_header(rng));
        }
        // Return the sample vector.
        sample
    }
}
