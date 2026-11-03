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
mod to_id;

#[cfg(any(test, feature = "prop-tests"))]
pub mod prop_tests;

use console::{
    prelude::*,
    program::{Literal, LiteralType},
    types::{Address, Field},
};
use snarkvm_ledger_narwhal_batch_header::BatchHeader;

use indexmap::IndexMap;
use std::collections::HashSet;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// The minimum self bond for a validator to join the committee
pub const MIN_VALIDATOR_SELF_STAKE: u64 = 100_000_000u64; // microcredits
/// The minimum amount of stake required for a validator to bond.
pub const MIN_VALIDATOR_STAKE: u64 = 10_000_000_000_000u64; // microcredits
/// The minimum amount of stake required for a delegator to bond.
pub const MIN_DELEGATOR_STAKE: u64 = 10_000_000_000u64; // microcredits
/// The maximum number of delegators.
pub const MAX_DELEGATORS: u32 = 100_000u32;

#[derive(Clone, PartialEq, Eq)]
pub struct Committee<N: Network> {
    /// The committee ID, defined as the hash of the starting round, members, and total stake.
    id: Field<N>,
    /// The round number (of the block) at which this committee was created (always even).
    starting_round: u64,
    /// A map of `address` to `(stake, is_open, commission)` state.
    members: IndexMap<Address<N>, (u64, bool, u8)>,
    /// The total stake of all `members`.
    total_stake: u64,
}

impl<N: Network> Committee<N> {
    /// The committee lookback range.
    pub const COMMITTEE_LOOKBACK_RANGE: u64 = BatchHeader::<N>::MAX_GC_ROUNDS as u64;

    /// The maximum number of members that may be in a committee.
    pub fn max_committee_size() -> u16 {
        N::LATEST_MAX_CERTIFICATES()
    }

    /// Initializes a new `Committee` instance.
    pub fn new_genesis(members: IndexMap<Address<N>, (u64, bool, u8)>) -> Result<Self> {
        // Return the new committee.
        Self::new(0u64, members)
    }

    /// Initializes a new `Committee` instance.
    pub fn new(starting_round: u64, members: IndexMap<Address<N>, (u64, bool, u8)>) -> Result<Self> {
        // Ensure there are at least 3 members.
        ensure!(members.len() >= 3, "Committee must have at least 3 members");
        // Ensure there are no more than the maximum number of members.
        ensure!(
            members.len() <= Self::max_committee_size() as usize,
            "Committee must have no more than {} members",
            Self::max_committee_size()
        );
        // Ensure all members have the minimum required stake.
        ensure!(
            members.values().all(|(stake, _, _)| *stake >= MIN_VALIDATOR_STAKE),
            "All members must have at least {MIN_VALIDATOR_STAKE} microcredits in stake"
        );
        // Ensure all members have a commission percentage within 100%.
        ensure!(
            members.values().all(|(_, _, commission)| *commission <= 100),
            "All members must have a commission percentage less than or equal to 100"
        );
        // Compute the total stake of the committee for this round.
        let total_stake = Self::compute_total_stake(&members)?;
        // Compute the committee ID.
        let id = Self::compute_committee_id(starting_round, &members, total_stake)?;
        #[cfg(feature = "metrics")]
        snarkvm_metrics::gauge(snarkvm_metrics::committee::TOTAL_STAKE, total_stake as f64);
        // Return the new committee.
        Ok(Self { id, starting_round, members, total_stake })
    }
}

impl<N: Network> Committee<N> {
    /// Returns the committee ID.
    pub const fn id(&self) -> Field<N> {
        self.id
    }

    /// Returns the round number (of the block) at which this committee was created (always even).
    pub const fn starting_round(&self) -> u64 {
        self.starting_round
    }

    /// Returns the committee members alongside their stake.
    pub const fn members(&self) -> &IndexMap<Address<N>, (u64, bool, u8)> {
        &self.members
    }

    /// Returns the number of validators in the committee.
    pub fn num_members(&self) -> usize {
        self.members.len()
    }

    /// Returns `true` if the given address is in the committee.
    pub fn is_committee_member(&self, address: Address<N>) -> bool {
        self.members.contains_key(&address)
    }

    /// Returns `true` if the given address is in the committee and is open.
    pub fn is_committee_member_open(&self, address: Address<N>) -> bool {
        self.members.get(&address).copied().unwrap_or_default().1
    }

    /// Returns the amount of stake for the given address.
    pub fn get_stake(&self, address: Address<N>) -> u64 {
        self.members.get(&address).copied().unwrap_or_default().0
    }

    /// Returns `true` if the combined stake for the given addresses reaches the availability threshold.
    /// This method takes in a `HashSet` to guarantee that the given addresses are unique.
    pub fn is_availability_threshold_reached(&self, addresses: &HashSet<Address<N>>) -> bool {
        let mut stake = 0u64;
        // Compute the combined stake for the given addresses.
        for address in addresses {
            // Accumulate the stake, checking for overflow.
            stake = stake.saturating_add(self.get_stake(*address));
        }
        // Return whether the combined stake reaches the availability threshold.
        stake >= self.availability_threshold()
    }

    /// Returns `true` if the combined stake for the given addresses reaches the quorum threshold.
    /// This method takes in a `HashSet` to guarantee that the given addresses are unique.
    pub fn is_quorum_threshold_reached(&self, addresses: &HashSet<Address<N>>) -> bool {
        let mut stake = 0u64;
        // Compute the combined stake for the given addresses.
        for address in addresses {
            // Accumulate the stake, checking for overflow.
            stake = stake.saturating_add(self.get_stake(*address));
        }
        // Return whether the combined stake reaches the quorum threshold.
        stake >= self.quorum_threshold()
    }

    /// Returns the amount of stake required to reach the availability threshold `(f + 1)`.
    pub fn availability_threshold(&self) -> u64 {
        // Assuming `N = 3f + 1 + k`, where `0 <= k < 3`,
        // then `(N + 2) / 3 = f + 1 + k/3 = f + 1`.
        self.total_stake().saturating_add(2).saturating_div(3)
    }

    /// Returns the amount of stake required to reach a quorum threshold `(N - f)`.
    pub fn quorum_threshold(&self) -> u64 {
        // Assuming `N = 3f + 1 + k`, where `0 <= k < 3`,
        // then `2N/3 + 1 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f`.
        // In the line above, `/` means integer division.
        self.total_stake().saturating_mul(2).saturating_div(3).saturating_add(1)
    }

    /// Returns the total amount of stake in the committee.
    pub const fn total_stake(&self) -> u64 {
        self.total_stake
    }
}

impl<N: Network> Committee<N> {
    /// Returns the leader address for the current round.
    /// Note: This method returns a deterministic result that is SNARK-friendly.
    pub fn get_leader(&self, current_round: u64) -> Result<Address<N>> {
        // Ensure the current round is at least the starting round.
        ensure!(current_round >= self.starting_round, "Current round must be at least the starting round");
        // Retrieve the total stake of the committee.
        let total_stake = self.total_stake();
        // Construct the round seed.
        let seed = [current_round].map(Field::from_u64);
        // Hash the round seed.
        let hash = Literal::Field(N::hash_to_group_psd4(&seed)?.to_x_coordinate());
        // Compute the stake index from the hash output.
        let stake_index = match hash.cast_lossy(LiteralType::U64)? {
            Literal::U64(output) => (*output) % total_stake,
            _ => bail!("BFT failed to downcast the hash output to a U64 literal"),
        };

        // Initialize a tracker for the leader.
        let mut leader = None;
        // Initialize a tracker for the current stake index.
        let mut current_stake_index = 0u64;
        // Sort the committee members.
        let candidates = self.sorted_members();
        // Determine the leader of the previous round.
        for (candidate, (stake, _, _)) in candidates {
            // Increment the current stake index by the candidate's stake.
            current_stake_index = current_stake_index.saturating_add(stake);
            // If the current stake index is greater than or equal to the stake index,
            // set the leader to the candidate, and break.
            if current_stake_index >= stake_index {
                leader = Some(candidate);
                break;
            }
        }
        // Note: This is guaranteed to be safe.
        Ok(leader.unwrap())
    }

    /// Returns the committee members sorted by their address' x-coordinate in decreasing order.
    /// Note: This ensures the method returns a deterministic result that is SNARK-friendly.
    fn sorted_members(&self) -> indexmap::map::IntoIter<Address<N>, (u64, bool, u8)> {
        let members = self.members.clone();
        // Note: The use of 'sorted_unstable_by' is safe here because the addresses are guaranteed to be unique.
        members.sorted_unstable_by(|address1, (_, _, _), address2, (_, _, _)| {
            address2.to_x_coordinate().cmp(&address1.to_x_coordinate())
        })
    }
}

impl<N: Network> Committee<N> {
    /// Compute the total stake of the given members.
    fn compute_total_stake(members: &IndexMap<Address<N>, (u64, bool, u8)>) -> Result<u64> {
        let mut power = 0u64;
        for (stake, _, _) in members.values() {
            // Accumulate the stake, checking for overflow.
            power = match power.checked_add(*stake) {
                Some(power) => power,
                None => bail!("Failed to calculate total stake - overflow detected"),
            };
        }
        Ok(power)
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{
        account::{Address, PrivateKey},
        prelude::TestRng,
    };

    use indexmap::IndexMap;
    use rand_distr::{Distribution, Exp};

    type CurrentNetwork = console::network::MainnetV0;

    /// Samples a list of random committees.
    pub fn sample_committees(rng: &mut TestRng) -> Vec<Committee<CurrentNetwork>> {
        // Sample the number of committees.
        let num_committees = rng.random_range(10..=100);
        // Sample the committees.
        (0..num_committees).map(|_| sample_committee(rng)).collect()
    }

    /// Samples a random committee.
    pub fn sample_committee(rng: &mut TestRng) -> Committee<CurrentNetwork> {
        sample_committee_for_round(1, rng)
    }

    /// Samples a random committee with random commissions.
    pub fn sample_committee_with_commissions(rng: &mut TestRng) -> Committee<CurrentNetwork> {
        // Sample the members.
        let mut members = IndexMap::new();
        for index in 0..4 {
            let is_open = rng.random();
            let commission = match index {
                0 => 0,
                1 => 100,
                _ => rng.random_range(0..=100),
            };
            members
                .insert(Address::<CurrentNetwork>::new(rng.random()), (2 * MIN_VALIDATOR_STAKE, is_open, commission));
        }
        // Return the committee.
        Committee::<CurrentNetwork>::new(1, members).unwrap()
    }

    /// Samples a random committee for a given round.
    pub fn sample_committee_for_round(round: u64, rng: &mut TestRng) -> Committee<CurrentNetwork> {
        sample_committee_for_round_and_size(round, 4, rng)
    }

    /// Samples a random committee for a given round and number of members.
    pub fn sample_committee_for_round_and_size(
        round: u64,
        num_members: u16,
        rng: &mut TestRng,
    ) -> Committee<CurrentNetwork> {
        // Sample the members.
        let mut members = IndexMap::new();
        for _ in 0..num_members {
            let is_open = rng.random();
            members.insert(Address::<CurrentNetwork>::new(rng.random()), (2 * MIN_VALIDATOR_STAKE, is_open, 0));
        }
        // Return the committee.
        Committee::<CurrentNetwork>::new(round, members).unwrap()
    }

    /// Generates a committee for the specified round, and private keys for its members.
    ///
    /// This is slower than `sample_committee_for_round` or `sample_committee_for_round_and_size` due to the additional key generation.
    pub fn sample_committee_and_keys_for_round(
        round: u64,
        num_members: usize,
        rng: &mut TestRng,
    ) -> (Committee<CurrentNetwork>, Vec<PrivateKey<CurrentNetwork>>) {
        // Sample the members.
        let mut members = IndexMap::with_capacity(num_members);
        let mut private_keys = Vec::with_capacity(num_members);
        for _ in 0..num_members {
            let private_key = PrivateKey::new(rng).unwrap();
            let address = Address::try_from(private_key).unwrap();
            let is_open = rng.random();
            private_keys.push(private_key);
            members.insert(address, (2 * MIN_VALIDATOR_STAKE, is_open, 0));
        }
        // Return the committee and keys.
        (Committee::<CurrentNetwork>::new(round, members).unwrap(), private_keys)
    }

    /// Samples a random committee for a given round and members.
    pub fn sample_committee_for_round_and_members(
        round: u64,
        members: Vec<Address<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> Committee<CurrentNetwork> {
        // Sample the members.
        let mut committee_members = IndexMap::new();
        for member in members {
            let is_open = rng.random();
            committee_members.insert(member, (2 * MIN_VALIDATOR_STAKE, is_open, 0));
        }
        // Return the committee.
        Committee::<CurrentNetwork>::new(round, committee_members).unwrap()
    }

    /// Samples a committee where all validators have the same stake.
    pub fn sample_committee_equal_stake_committee(num_members: u16, rng: &mut TestRng) -> Committee<CurrentNetwork> {
        assert!(num_members >= 4);
        // Sample the members.
        let mut members = IndexMap::new();
        // Add in the minimum and maximum staked nodes.
        members.insert(Address::<CurrentNetwork>::new(rng.random()), (MIN_VALIDATOR_STAKE, false, 0));
        while members.len() < num_members as usize - 1 {
            let stake = MIN_VALIDATOR_STAKE;
            let is_open = rng.random();
            members.insert(Address::<CurrentNetwork>::new(rng.random()), (stake, is_open, 0));
        }
        // Return the committee.
        Committee::<CurrentNetwork>::new(1, members).unwrap()
    }

    /// Samples a random committee.
    #[allow(clippy::cast_possible_truncation)]
    pub fn sample_committee_custom(num_members: u16, rng: &mut TestRng) -> Committee<CurrentNetwork> {
        assert!(num_members >= 3);
        // Set the maximum amount staked in the node.
        const MAX_STAKE: u64 = 100_000_000_000_000;
        // Initialize the Exponential distribution.
        let distribution = Exp::new(2.0).unwrap();
        // Initialize maximum stake range.
        let range = (MAX_STAKE - MIN_VALIDATOR_STAKE) as f64;
        // Sample the members.
        let mut members = IndexMap::new();
        // Add in the minimum and maximum staked nodes.
        members.insert(Address::<CurrentNetwork>::new(rng.random()), (MIN_VALIDATOR_STAKE, false, 0));
        while members.len() < num_members as usize - 1 {
            loop {
                let stake = MIN_VALIDATOR_STAKE as f64 + range * distribution.sample(rng);
                if stake >= MIN_VALIDATOR_STAKE as f64 && stake <= MAX_STAKE as f64 {
                    let is_open = rng.random();
                    members.insert(Address::<CurrentNetwork>::new(rng.random()), (stake as u64, is_open, 0));
                    break;
                }
            }
        }
        members.insert(Address::<CurrentNetwork>::new(rng.random()), (MAX_STAKE, false, 0));
        // Return the committee.
        Committee::<CurrentNetwork>::new(1, members).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::prelude::TestRng;

    use parking_lot::RwLock;
    use std::sync::Arc;

    type CurrentNetwork = console::network::MainnetV0;

    /// Checks the leader distribution.
    fn check_leader_distribution(committee: Committee<CurrentNetwork>, num_rounds: u64, tolerance_percent: f64) {
        // Initialize a tracker for the leaders.
        let leaders = Arc::new(RwLock::new(IndexMap::<Address<CurrentNetwork>, i64>::new()));
        // Iterate through the rounds.
        cfg_into_iter!(1..=num_rounds).for_each(|round| {
            // Compute the leader.
            let leader = committee.get_leader(round).unwrap();
            // Increment the leader count for the current leader.
            leaders.write().entry(leader).or_default().add_assign(1);
        });
        let leaders = leaders.read();
        // Ensure the leader distribution is uniform.
        for (i, (address, (stake, _, _))) in committee.members.iter().enumerate() {
            // Get the leader count for the validator.
            let Some(leader_count) = leaders.get(address) else {
                println!("{i}: 0 rounds");
                continue;
            };
            // Compute the target leader percentage.
            let target_percent = *stake as f64 / committee.total_stake() as f64 * 100f64;
            // Compute the actual leader percentage for the validator.
            let leader_percent = (*leader_count as f64 / num_rounds as f64) * 100f64;
            // Compute the error percentage from the target.
            let error_percent = (leader_percent - target_percent) / target_percent * 100f64;

            // Print the results.
            let stake = stake / 1_000_000; // credits
            println!("{i}: {stake}, {leader_count}, {target_percent:.3}%, {leader_percent:.3}%, {error_percent:.2}%");
            if target_percent > 0.5 {
                assert!(error_percent.abs() < tolerance_percent);
            }
        }
    }

    #[test]
    fn test_get_leader_distribution_simple() {
        // Initialize the RNG.
        let rng = &mut TestRng::default();
        // Set the number of rounds.
        const NUM_ROUNDS: u64 = 256 * 100;
        // Sample a committee.
        let committee = crate::test_helpers::sample_committee(rng);
        // Check the leader distribution.
        check_leader_distribution(committee, NUM_ROUNDS, 2.5);
    }

    #[test]
    fn test_get_leader_distribution() {
        // Initialize the RNG.
        let rng = &mut TestRng::default();
        // Set the number of rounds.
        const NUM_ROUNDS: u64 = 256 * 2_000;
        // Sample the number of members.
        let num_members = rng.random_range(3..=Committee::<CurrentNetwork>::max_committee_size());
        // Sample a committee.
        let committee = crate::test_helpers::sample_committee_custom(num_members, rng);
        // Check the leader distribution.
        check_leader_distribution(committee, NUM_ROUNDS, 5.0);
    }

    #[test]
    fn test_sorted_members() {
        // Initialize the RNG.
        let rng = &mut TestRng::default();
        // Sample a committee.
        let committee =
            crate::test_helpers::sample_committee_custom(Committee::<CurrentNetwork>::max_committee_size(), rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Sort the members.
        let sorted_members = committee.sorted_members().collect::<Vec<_>>();
        println!("sorted_members: {}ms", timer.elapsed().as_millis());
        // Check that the members are sorted based on our sorting criteria.
        for i in 0..sorted_members.len() - 1 {
            let (address1, (_, _, _)) = sorted_members[i];
            let (address2, (_, _, _)) = sorted_members[i + 1];
            assert!(address1.to_x_coordinate() > address2.to_x_coordinate());
        }
    }
}
