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

extern crate snarkvm_console as console;

mod bytes;
mod serialize;
mod string;

use console::{account::Address, prelude::*, program::SUBDAG_CERTIFICATES_DEPTH, types::Field};
use snarkvm_ledger_committee::Committee;
use snarkvm_ledger_narwhal_batch_certificate::BatchCertificate;
use snarkvm_ledger_narwhal_batch_header::BatchHeader;
use snarkvm_ledger_narwhal_transmission_id::TransmissionID;

use indexmap::IndexSet;
use std::collections::BTreeMap;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// Returns `true` if the rounds are sequential.
fn is_sequential<T>(map: &BTreeMap<u64, T>) -> bool {
    let mut previous_round = None;
    for &round in map.keys() {
        match previous_round {
            Some(previous) if previous + 1 != round => return false,
            _ => previous_round = Some(round),
        }
    }
    true
}

/// Orders the given subDAG using the same left-to-right DFS traversal as the Narwhal block producer.
fn order_subdag_with_dfs<N: Network>(
    subdag: &BTreeMap<u64, IndexSet<BatchCertificate<N>>>,
) -> BTreeMap<u64, IndexSet<BatchCertificate<N>>> {
    use std::collections::HashSet;

    // Initialize a map for the certificates to commit.
    let mut commit = BTreeMap::<u64, IndexSet<_>>::new();
    // Initialize a set for the already ordered certificates.
    let mut already_ordered = HashSet::new();
    // Initialize a buffer for the certificates to order, starting with the leader certificate.
    let mut buffer =
        subdag.iter().next_back().map_or_else(Vec::new, |(_, leader)| leader.iter().cloned().collect::<Vec<_>>());
    // Iterate over the certificates to order.
    while let Some(certificate) = buffer.pop() {
        // Insert the certificate into the map.
        commit.entry(certificate.round()).or_default().insert(certificate.clone());
        // Iterate over the previous certificate IDs.
        // Note: Using '.rev()' preserves left-to-right order because the buffer is a LIFO stack.
        for previous_certificate_id in certificate.previous_certificate_ids().iter().rev() {
            // If the previous certificate is already ordered, continue.
            if already_ordered.contains(previous_certificate_id) {
                continue;
            }
            let Some(previous_certificate) = subdag
                .get(&certificate.round().saturating_sub(1))
                .and_then(|map| map.iter().find(|certificate| certificate.id() == *previous_certificate_id))
            else {
                // It is either ordered or below the GC round.
                continue;
            };
            // Insert the previous certificate into the set of already ordered certificates.
            already_ordered.insert(previous_certificate.id());
            // Insert the previous certificate into the buffer.
            buffer.push(previous_certificate.clone());
        }
    }
    commit
}

/// Checks that the given subDAG is not partitioned by traversing it starting from the leader.
///
/// Returns `true` if the DFS traversal using the given subdag structure matches the commit.
/// Note, this does not guarantee that the subDAG contains all batches it should, because this function has no knowledge of other blocks/subDAGs.
fn sanity_check_subdag_with_dfs<N: Network>(subdag: &BTreeMap<u64, IndexSet<BatchCertificate<N>>>) -> bool {
    // Return `true` if the subdag matches the commit.
    &order_subdag_with_dfs(subdag) == subdag
}

/// Returns `true` if the certificates match the canonical left-to-right DFS order.
fn is_subdag_ordered_with_dfs<N: Network>(subdag: &BTreeMap<u64, IndexSet<BatchCertificate<N>>>) -> bool {
    // Reconstruct the canonical certificate order.
    let ordered_subdag = order_subdag_with_dfs(subdag);
    // Compare each round and each certificate in insertion order.
    ordered_subdag.len() == subdag.len()
        && ordered_subdag.iter().zip_eq(subdag).all(
            |((expected_round, expected_certificates), (round, certificates))| {
                expected_round == round && expected_certificates.iter().eq(certificates)
            },
        )
}

/// Returns the weighted median timestamp of the given timestamps and stakes.
fn weighted_median(timestamps_and_stake: Vec<(i64, u64)>) -> i64 {
    let mut timestamps_and_stake = timestamps_and_stake;

    // Sort the timestamps.
    #[cfg(not(feature = "serial"))]
    timestamps_and_stake.par_sort_unstable_by_key(|(timestamp, _)| *timestamp);
    #[cfg(feature = "serial")]
    timestamps_and_stake.sort_unstable_by_key(|(timestamp, _)| *timestamp);

    // Calculate the total stake of the authors.
    let total_stake = timestamps_and_stake.iter().map(|(_, stake)| *stake).sum::<u64>();

    // Initialize the current timestamp and accumulated stake.
    let mut current_timestamp: i64 = 0;
    let mut accumulated_stake: u64 = 0;

    // Find the weighted median timestamp.
    for (timestamp, stake) in timestamps_and_stake.iter() {
        accumulated_stake = accumulated_stake.saturating_add(*stake);
        current_timestamp = *timestamp;
        if accumulated_stake.saturating_mul(2) >= total_stake {
            break;
        }
    }

    // Return the weighted median timestamp
    current_timestamp
}

#[derive(Clone)]
pub struct Subdag<N: Network> {
    /// The subdag of round certificates.
    subdag: BTreeMap<u64, IndexSet<BatchCertificate<N>>>,
}

impl<N: Network> PartialEq for Subdag<N> {
    fn eq(&self, other: &Self) -> bool {
        self.subdag == other.subdag
    }
}

impl<N: Network> Eq for Subdag<N> {}

impl<N: Network> Subdag<N> {
    /// Initializes a new subdag.
    pub fn from(subdag: BTreeMap<u64, IndexSet<BatchCertificate<N>>>) -> Result<Self> {
        // Ensure the subdag is not empty.
        ensure!(!subdag.is_empty(), "Subdag cannot be empty");
        // Ensure the subdag does not exceed the maximum number of rounds.
        ensure!(
            subdag.len() <= usize::try_from(Self::MAX_ROUNDS)?,
            "Subdag cannot exceed the maximum number of rounds"
        );
        // Ensure the anchor round is even.
        ensure!(subdag.iter().next_back().map_or(0, |(r, _)| *r).is_multiple_of(2), "Anchor round must be even");
        // Ensure there is only one leader certificate.
        ensure!(subdag.iter().next_back().map_or(0, |(_, c)| c.len()) == 1, "Subdag cannot have multiple leaders");
        // Ensure the rounds are sequential.
        ensure!(is_sequential(&subdag), "Subdag rounds must be sequential");
        // Ensure the subdag structure matches the commit.
        ensure!(sanity_check_subdag_with_dfs(&subdag), "Subdag structure does not match commit");
        // Ensure the leader certificate is an even round.
        Ok(Self { subdag })
    }

    /// Initializes a new subdag.
    pub fn from_unchecked(subdag: BTreeMap<u64, IndexSet<BatchCertificate<N>>>) -> Self {
        Self { subdag }
    }
}

impl<N: Network> Subdag<N> {
    /// The maximum number of rounds in a subdag (bounded up to GC depth).
    pub const MAX_ROUNDS: u64 = BatchHeader::<N>::MAX_GC_ROUNDS as u64;
}

impl<N: Network> Subdag<N> {
    /// Returns the anchor round.
    pub fn anchor_round(&self) -> u64 {
        self.subdag.iter().next_back().map_or(0, |(round, _)| *round)
    }

    /// Returns the certificate IDs of the subdag (from earliest round to latest round).
    pub fn certificate_ids(&self) -> impl Iterator<Item = Field<N>> + '_ {
        self.values().flatten().map(BatchCertificate::id)
    }

    /// Checks that the certificates are canonically ordered for the consensus rules at `block_height`.
    ///
    /// Before consensus V18, this preserves the historical order-insensitive behavior.
    /// Starting in V18, each round must match the left-to-right DFS order produced from the leader certificate.
    pub fn check_certificate_order(&self, block_height: u32) -> Result<()> {
        if block_height >= N::CONSENSUS_HEIGHT(ConsensusVersion::V18)? {
            ensure!(
                is_subdag_ordered_with_dfs(&self.subdag),
                "Subdag certificates are not canonically ordered in block {block_height}"
            );
        }
        Ok(())
    }

    /// Returns certificates in this subdag (from earliest round to latest round).
    pub fn certificates(&self) -> impl Iterator<Item = &BatchCertificate<N>> {
        self.values().flatten()
    }

    /// Returns the block spend limit for this subdag at `block_height`.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn spend_limit(&self, block_height: u32) -> Option<u64> {
        if block_height >= N::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap() {
            // Compute the number of certificates in the subdag.
            let subdag_certificates_count = self.values().map(|certificates| certificates.len() as u64).sum::<u64>();
            // Compute the batch spend limit.
            let batch_spend_limit = BatchHeader::<N>::batch_spend_limit(block_height);
            // For each certificate in the subdag, we can spend up to the batch spend limit.
            Some(subdag_certificates_count.saturating_mul(batch_spend_limit))
        } else {
            None
        }
    }

    /// Returns the synthesis limit for this subdag at `block_height`.
    // Note: This limit refers to the total number of non-zero entries across all circuits in all deployments in the subdag.
    // It is enforced for every V18 block and for the first V19 block. `check_transaction` reads the
    // consensus version from the previous block, so the first V19 block would otherwise skip both
    // the V18 block-wide limit and the V19 per-transaction limits. From the second V19 block,
    // per-transaction variable and constraint limits apply instead.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn synthesis_limit(&self, block_height: u32) -> Option<u64> {
        if block_height >= N::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap()
            && block_height <= N::CONSENSUS_HEIGHT(ConsensusVersion::V19).unwrap()
        {
            // One full round of consensus has a synthesis budget of 5 seconds.
            let synthesis_per_second_runtime = 5_f64 * N::SYNTHESIS_PER_SECOND_OF_RUNTIME as f64;
            // A certificate therefore has a synthesis budget of 5 seconds / MAX_CERTIFICATES.
            let synthesis_per_certificate = synthesis_per_second_runtime
                / consensus_config_value!(N, MAX_CERTIFICATES, block_height).unwrap() as f64;
            // Compute the number of certificates in the subdag.
            let subdag_certificates_count =
                self.values().map(|certificates| certificates.len() as u64).sum::<u64>() as f64;
            // The synthesis limit is the number of certificates times the synthesis budget per certificate.
            Some((synthesis_per_certificate * subdag_certificates_count) as u64)
        } else {
            None
        }
    }

    /// Returns a lower-bound certificate count for a subdag with `max_certificates` per round.
    ///
    /// For `N = max_certificates` written as `N = 3f + 1`, this is the integer `2 * (f + 1)`.
    /// In general (including `N = 3f + 1 + k` with `0 <= k < 3`), this is two rounds of the
    /// availability threshold: `2 * ((N + 2) / 3)`.
    #[inline]
    pub fn min_certificates(max_certificates: u16) -> u64 {
        let n = max_certificates as u64;
        // `(N + 2) / 3 = f + 1` when `N = 3f + 1 + k` with `0 <= k < 3`.
        n.saturating_add(2).saturating_div(3).saturating_mul(2)
    }

    /// Returns the block spend limit for a subdag with `min_certificates` at `block_height`.
    ///
    /// Used for beacon blocks, which have no subdag but must still enforce block-wide limits.
    #[inline]
    pub fn min_spend_limit(block_height: u32) -> Option<u64> {
        // unwrap: `CONSENSUS_HEIGHT` is defined for every `ConsensusVersion`.
        if block_height >= N::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap() {
            // unwrap: `MAX_CERTIFICATES` is defined for every consensus height.
            let max_certs = consensus_config_value!(N, MAX_CERTIFICATES, block_height).unwrap();
            Some(Self::min_certificates(max_certs).saturating_mul(BatchHeader::<N>::batch_spend_limit(block_height)))
        } else {
            None
        }
    }

    /// Returns the synthesis limit for a subdag with `min_certificates` at `block_height`.
    ///
    /// Used for beacon blocks, which have no subdag but must still enforce block-wide limits.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn min_synthesis_limit(block_height: u32) -> Option<u64> {
        // unwrap: `CONSENSUS_HEIGHT` is defined for every `ConsensusVersion`.
        if block_height >= N::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap()
            && block_height <= N::CONSENSUS_HEIGHT(ConsensusVersion::V19).unwrap()
        {
            let synthesis_per_second_runtime = 5_f64 * N::SYNTHESIS_PER_SECOND_OF_RUNTIME as f64;
            // unwrap: `MAX_CERTIFICATES` is defined for every consensus height.
            let max_certificates = consensus_config_value!(N, MAX_CERTIFICATES, block_height).unwrap();
            let synthesis_per_certificate = synthesis_per_second_runtime / max_certificates as f64;
            Some((synthesis_per_certificate * Self::min_certificates(max_certificates) as f64) as u64)
        } else {
            None
        }
    }

    /// Returns the leader certificate.
    pub fn leader_certificate(&self) -> &BatchCertificate<N> {
        // Retrieve entry for the anchor round.
        let entry = self.subdag.iter().next_back();
        debug_assert!(entry.is_some(), "There must be at least one round of certificates");
        // Retrieve the certificates from the anchor round.
        let certificates = entry.expect("There must be one round in the subdag").1;
        debug_assert!(certificates.len() == 1, "There must be only one leader certificate, by definition");
        // Note: There is guaranteed to be only one leader certificate.
        certificates.iter().next().expect("There must be a leader certificate")
    }

    /// Returns the address of the leader.
    pub fn leader_address(&self) -> Address<N> {
        // Retrieve the leader address from the leader certificate.
        self.leader_certificate().author()
    }

    /// Returns the transmission IDs of the subdag (from earliest round to latest round).
    pub fn transmission_ids(&self) -> impl Iterator<Item = &TransmissionID<N>> {
        self.values().flatten().flat_map(BatchCertificate::transmission_ids)
    }

    /// Returns the timestamp of the anchor round, defined as the weighted median timestamp of the subdag.
    pub fn timestamp(&self, committee: &Committee<N>) -> i64 {
        // Retrieve the anchor round.
        let anchor_round = self.anchor_round();
        // Retrieve the timestamps and stakes of the certificates for `anchor_round` - 1.
        let timestamps_and_stakes = self
            .values()
            .flatten()
            .filter(|certificate| certificate.round() == anchor_round.saturating_sub(1))
            .map(|certificate| (certificate.timestamp(), committee.get_stake(certificate.author())))
            .collect::<Vec<_>>();

        // Return the weighted median timestamp.
        weighted_median(timestamps_and_stakes)
    }

    /// Returns the subdag root of the certificates.
    pub fn to_subdag_root(&self) -> Result<Field<N>> {
        // Prepare the leaves.
        let leaves = cfg_iter!(self.subdag)
            .map(|(_, certificates)| {
                certificates.iter().flat_map(|certificate| certificate.id().to_bits_le()).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Compute the subdag root.
        Ok(*N::merkle_tree_bhp::<SUBDAG_CERTIFICATES_DEPTH>(&leaves)?.root())
    }
}

impl<N: Network> Deref for Subdag<N> {
    type Target = BTreeMap<u64, IndexSet<BatchCertificate<N>>>;

    /// Returns the batch certificates.
    fn deref(&self) -> &Self::Target {
        &self.subdag
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{network::MainnetV0, prelude::TestRng};

    use snarkvm_ledger_narwhal_batch_certificate::test_helpers::*;

    use indexmap::{IndexSet, indexset};

    type CurrentNetwork = MainnetV0;

    /// Orders the given subDAG using the same left-to-right DFS traversal as the Narwhal block producer.
    pub fn order_subdag_with_dfs<N: Network>(
        subdag: &BTreeMap<u64, IndexSet<BatchCertificate<N>>>,
    ) -> BTreeMap<u64, IndexSet<BatchCertificate<N>>> {
        super::order_subdag_with_dfs(subdag)
    }

    /// Returns a sample subdag, sampled at random.
    pub fn sample_subdag(rng: &mut TestRng) -> Subdag<CurrentNetwork> {
        const F: usize = 1;
        const AVAILABILITY_THRESHOLD: usize = F + 1;
        const QUORUM_THRESHOLD: usize = 2 * F + 1;

        // Initialize the map for the subdag.
        let mut subdag = BTreeMap::<u64, IndexSet<_>>::new();

        // Initialize the starting round.
        let starting_round = {
            loop {
                let round = rng.random_range(2..u64::MAX);
                if round % 2 == 0 {
                    break round;
                }
            }
        };

        // Process the earliest round.
        let mut previous_certificate_ids = IndexSet::new();
        for _ in 0..AVAILABILITY_THRESHOLD {
            let certificate = sample_batch_certificate_for_round(starting_round, rng);
            previous_certificate_ids.insert(certificate.id());
            subdag.entry(starting_round).or_default().insert(certificate);
        }

        // Process the middle round.
        let mut previous_certificate_ids_2 = IndexSet::new();
        for _ in 0..QUORUM_THRESHOLD {
            let certificate = sample_batch_certificate_for_round_with_previous_certificate_ids(
                starting_round + 1,
                previous_certificate_ids.clone(),
                rng,
            );
            previous_certificate_ids_2.insert(certificate.id());
            subdag.entry(starting_round + 1).or_default().insert(certificate);
        }

        // Process the latest round.
        let certificate = sample_batch_certificate_for_round_with_previous_certificate_ids(
            starting_round + 2,
            previous_certificate_ids_2,
            rng,
        );
        subdag.insert(starting_round + 2, indexset![certificate]);

        // Return the subdag.
        Subdag::from(subdag).unwrap()
    }

    /// Returns a list of sample subdags, sampled at random.
    pub fn sample_subdags(rng: &mut TestRng) -> Vec<Subdag<CurrentNetwork>> {
        // Initialize a sample vector.
        let mut sample = Vec::with_capacity(10);
        // Append sample subdags.
        for _ in 0..10 {
            sample.push(sample_subdag(rng));
        }
        // Return the sample vector.
        sample
    }

    /// Constructs a subdag (via `from_unchecked`) that contains `cert_count` certificates
    /// placed in a single even-numbered round.  The DAG structure is not valid, but
    /// `spend_limit` only inspects certificate counts, so this is sufficient for unit tests.
    pub fn subdag_with_cert_count(cert_count: usize, rng: &mut TestRng) -> Subdag<CurrentNetwork> {
        let mut certs = IndexSet::new();
        for _ in 0..cert_count {
            // Round 2 is arbitrary; any even round keeps the anchor-round invariant if desired.
            certs.insert(sample_batch_certificate_for_round(2, rng));
        }
        let mut map = BTreeMap::new();
        map.insert(2u64, certs);
        Subdag::from_unchecked(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::ConsensusVersion;
    use snarkvm_ledger_narwhal_batch_header::BatchHeader;

    use crate::test_helpers::subdag_with_cert_count;

    type CurrentNetwork = console::network::MainnetV0;

    const ITERATIONS: u64 = 100;

    #[test]
    fn test_max_certificates() {
        // Determine the maximum number of certificates in a block.
        let max_certificates_per_block =
            BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS * CurrentNetwork::LATEST_MAX_CERTIFICATES() as usize;

        // Note: The maximum number of certificates in a block must be able to be Merklized.
        assert!(
            max_certificates_per_block <= 2u32.checked_pow(SUBDAG_CERTIFICATES_DEPTH as u32).unwrap() as usize,
            "The maximum number of certificates in a block is too large"
        );
    }

    #[test]
    fn test_weighted_median_simple() {
        // Test a simple case with equal weights.
        let data = vec![(1, 10), (2, 10), (3, 10)];
        assert_eq!(weighted_median(data), 2);

        // Test a case with a single element.
        let data = vec![(5, 10)];
        assert_eq!(weighted_median(data), 5);

        // Test a case with an even number of elements
        let data = vec![(1, 10), (2, 30), (3, 20), (4, 40)];
        assert_eq!(weighted_median(data), 3);

        // Test a case with a skewed weight.
        let data = vec![(100, 100), (200, 10000), (300, 500)];
        assert_eq!(weighted_median(data), 200);

        // Test a case with a empty set.
        assert_eq!(weighted_median(vec![]), 0);

        // Test a case where there is possible truncation.
        let data = vec![(1, 1), (2, 1), (3, 1), (4, 1), (5, 1)];
        assert_eq!(weighted_median(data), 3);

        // Test a case where weights of 0 do not affect the median.
        let data = vec![(1, 10), (2, 0), (3, 0), (4, 0), (5, 20), (6, 0), (7, 10)];
        assert_eq!(weighted_median(data), 5);
    }

    #[test]
    fn test_weighted_median_range() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let data: Vec<(i64, u64)> =
                (0..10).map(|_| (rng.random_range(1..100), rng.random_range(10..100))).collect();
            let min = data.iter().min_by_key(|x| x.0).unwrap().0;
            let max = data.iter().max_by_key(|x| x.0).unwrap().0;
            let median = weighted_median(data);
            assert!(median >= min && median <= max);
        }
    }

    #[test]
    fn test_weighted_median_scaled_weights() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let data: Vec<(i64, u64)> =
                (0..10).map(|_| (rng.random_range(1..100), rng.random_range(10..100) * 2)).collect();
            let scaled_data: Vec<(i64, u64)> = data.iter().map(|&(t, s)| (t, s * 10)).collect();

            if weighted_median(data.clone()) != weighted_median(scaled_data.clone()) {
                println!("data: {data:?}");
                println!("scaled_data: {scaled_data:?}");
            }
            assert_eq!(weighted_median(data), weighted_median(scaled_data));
        }
    }

    #[test]
    fn test_certificate_order_consensus_gate() {
        let mut rng = TestRng::default();
        let canonical_subdag = test_helpers::sample_subdag(&mut rng);
        let canonical_root =
            canonical_subdag.to_subdag_root().expect("A valid sample subdag must have a computable root");

        // Reverse a round containing multiple certificates.
        let mut reordered_subdag = canonical_subdag.subdag.clone();
        let certificates = reordered_subdag
            .values_mut()
            .find(|certificates| certificates.len() > 1)
            .expect("The sample subdag must contain a round with multiple certificates");
        *certificates = certificates.iter().rev().cloned().collect();

        // The legacy structural check intentionally remains order-insensitive.
        let reordered_subdag =
            Subdag::from(reordered_subdag).expect("Legacy consensus must accept a structurally valid reordered subdag");
        let reordered_root =
            reordered_subdag.to_subdag_root().expect("A structurally valid subdag must have a computable root");
        assert_ne!(canonical_root, reordered_root, "The subdag root depends on certificate insertion order");

        // Enforce canonical certificate order only once V18 activates.
        let v18_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18)
            .expect("Mainnet must define a V18 activation height");
        assert!(
            canonical_subdag.check_certificate_order(v18_height).is_ok(),
            "A canonically ordered subdag must be accepted"
        );
        if v18_height > 0 {
            assert!(
                reordered_subdag.check_certificate_order(v18_height - 1).is_ok(),
                "Legacy consensus must preserve the historical order-insensitive behavior"
            );
        }
        assert_eq!(
            reordered_subdag
                .check_certificate_order(v18_height)
                .expect_err("V18 must reject a non-canonically ordered subdag")
                .to_string(),
            format!("Subdag certificates are not canonically ordered in block {v18_height}")
        );
    }

    /// `synthesis_limit` must return `None` for any block height that predates V18.
    #[test]
    fn test_synthesis_limit_returns_none_before_v18() {
        let v18_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap();
        let mut rng = TestRng::default();
        let subdag = test_helpers::sample_subdag(&mut rng);

        assert!(subdag.synthesis_limit(0).is_none(), "height 0 must return None");
        if v18_height > 0 {
            assert!(subdag.synthesis_limit(v18_height - 1).is_none(), "height V18-1 must return None");
        }
    }

    /// `synthesis_limit` must return `Some` from V18 through the first V19 block.
    #[test]
    fn test_synthesis_limit_returns_some_from_v18_through_first_v19_block() {
        let v18_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap();
        let v19_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V19).unwrap();
        let mut rng = TestRng::default();
        let subdag = test_helpers::sample_subdag(&mut rng);

        assert!(subdag.synthesis_limit(v18_height).is_some(), "height V18 must return Some");
        assert!(
            subdag.synthesis_limit(v19_height).is_some(),
            "the first V19 block must retain the block-wide synthesis limit"
        );
        if v19_height > v18_height.saturating_add(1) {
            assert!(
                subdag.synthesis_limit(v18_height.saturating_add(1)).is_some(),
                "height V18+1 must return Some while still in V18"
            );
        }
    }

    /// `synthesis_limit` must return `None` after the first V19 block.
    #[test]
    fn test_synthesis_limit_returns_none_after_first_v19_block() {
        let v19_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V19).unwrap();
        // When V19 is unreleased (`u32::MAX`), there is no subsequent height to check.
        if v19_height == u32::MAX {
            return;
        }
        let mut rng = TestRng::default();
        let subdag = test_helpers::sample_subdag(&mut rng);

        assert!(subdag.synthesis_limit(v19_height.saturating_add(1)).is_none(), "height V19+1 must return None");
    }

    /// `spend_limit` must return `None` for any block height that predates V16.
    #[test]
    fn test_spend_limit_returns_none_before_v16() {
        let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
        let mut rng = TestRng::default();
        let subdag = test_helpers::sample_subdag(&mut rng);

        assert!(subdag.spend_limit(0).is_none(), "height 0 must return None");
        if v16_height > 0 {
            assert!(subdag.spend_limit(v16_height - 1).is_none(), "height V16-1 must return None");
        }
    }

    /// `spend_limit` must return `Some` for any block height at or after V16.
    #[test]
    fn test_spend_limit_returns_some_at_and_after_v16() {
        let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
        let mut rng = TestRng::default();
        let subdag = test_helpers::sample_subdag(&mut rng);

        assert!(subdag.spend_limit(v16_height).is_some(), "height V16 must return Some");
        assert!(subdag.spend_limit(v16_height.saturating_add(1)).is_some(), "height V16+1 must return Some");
        assert!(subdag.spend_limit(u32::MAX).is_some(), "u32::MAX must return Some");
    }

    /// A subdag with zero certificates must produce a spend limit of 0 at V16.
    #[test]
    fn test_spend_limit_zero_certificates() {
        let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
        // from_unchecked bypasses structural validation; spend_limit only reads cert counts.
        let empty_subdag: Subdag<CurrentNetwork> = Subdag::from_unchecked(BTreeMap::new());
        assert_eq!(empty_subdag.spend_limit(v16_height), Some(0));
    }

    /// Doubling the number of certificates must double the spend limit.
    #[test]
    fn test_spend_limit_proportional_to_cert_count() {
        let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
        let mut rng = TestRng::default();

        let n: usize = 10;
        let subdag_n = subdag_with_cert_count(n, &mut rng);
        let subdag_2n = subdag_with_cert_count(2 * n, &mut rng);

        let limit_n = subdag_n.spend_limit(v16_height).unwrap();
        let limit_2n = subdag_2n.spend_limit(v16_height).unwrap();

        assert!(limit_2n == 2 * limit_n, "limit_2n={limit_2n} limit_n={limit_n}");
    }

    /// `spend_limit` must be monotonically non-decreasing as certificate count grows.
    #[test]
    fn test_spend_limit_monotone_in_cert_count() {
        let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
        let mut rng = TestRng::default();

        let mut previous = 0u64;
        for n in 0..=20 {
            let limit = subdag_with_cert_count(n, &mut rng).spend_limit(v16_height).unwrap();
            assert!(limit >= previous, "spend_limit must not decrease: n={n}, limit={limit}, previous={previous}");
            previous = limit;
        }
    }

    /// Minimum certificates must be equal to 2*(f+1) for N=3f+1+k with 0<=k<3.
    #[test]
    fn test_min_certificates() {
        for n in 1u16..=200 {
            let n_u64 = n as u64;
            let min_certs = n_u64.saturating_add(2).saturating_div(3).saturating_mul(2);
            let f = n_u64.saturating_sub(1) / 3;
            assert_eq!(min_certs, 2 * (f + 1), "min_certificates must equal 2*(f+1) for N={n}");
            assert_eq!(Subdag::<CurrentNetwork>::min_certificates(n), min_certs);
        }
    }
}
