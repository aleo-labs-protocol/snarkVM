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

use console::{account::Address, network::prelude::*};
use snarkvm_ledger_committee::{Committee, MIN_DELEGATOR_STAKE};

use indexmap::IndexMap;
use std::sync::atomic::AtomicU64;

#[cfg(feature = "locktick")]
use locktick::parking_lot::Mutex;
#[cfg(not(feature = "locktick"))]
use parking_lot::Mutex;
#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// A safety bound (sanity-check) for the coinbase reward.
const MAX_COINBASE_REWARD: u64 = snarkvm_ledger_block::MAX_COINBASE_REWARD; // Coinbase reward at block 1.

/// Returns the updated stakers reflecting the staking rewards for the given committee, block reward,
/// and validator commission rates.
///
/// The staking reward for validators is defined as: `block_reward * stake / total_stake + commission_to_recieve`.
/// The commission to receive for validators is defined as: `block_reward * (total_stake_delegated / total_stake) * (rate / 100)`.
///
/// The staking reward for delegators is defined as: `block_reward * stake / total_stake - commission_to_pay`.
/// The commission to pay for delegators is defined as: `block_reward * (stake / total_stake) * (rate / 100)`
///
/// This method ensures that stakers who are bonded to validators with more than **25%**
/// of the total stake will not receive a staking reward. In addition, this method
/// ensures delegators who have less than 10,000 credits are not eligible for a staking reward.
///
/// The choice of 25% is to ensure at least 4 validators are operational at any given time.
/// Our security model tolerates Byzantines behavior by validators staking up to f stake,
/// where f = max{m: integer | m < N/3}, N being the total amount staked.
/// Therefore, 1 Byzantine validator out of 4 equal-staked validators will be tolerated.
pub fn staking_rewards<N: Network>(
    stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
    committee: &Committee<N>,
    block_reward: u64,
) -> IndexMap<Address<N>, (Address<N>, u64)> {
    // If the list of stakers is empty, there is no stake, or the block reward is 0, return the stakers.
    if stakers.is_empty() || committee.total_stake() == 0 || block_reward == 0 {
        return stakers.clone();
    }

    // First, validate all validators and create a map of valid validators.
    let valid_validators: IndexMap<_, _> = committee
        .members()
        .iter()
        .filter_map(|(validator, (validator_stake, _is_open, commission_rate))| {
            // Skip validators with invalid commission rates.
            if *commission_rate > 100 {
                error!("Commission rate ({commission_rate}) is greater than 100 - skipping validator {validator}");
                return None;
            }
            // Skip validators with more than 25% of total stake.
            if *validator_stake > committee.total_stake().saturating_div(4) {
                trace!("Validator {validator} has more than 25% of the total stake - skipping all stakers");
                return None;
            }
            Some((*validator, (*validator_stake, *commission_rate)))
        })
        .collect();

    // Track validators not in committee as well as their stake.
    // Pre-allocating with an expected capacity prevents reallocation while the mutex is held.
    let hashset_capacity = committee.members().len();
    let missing_validators = Mutex::new(std::collections::HashSet::<Address<N>>::with_capacity(hashset_capacity));
    let invalid_validator_stake = AtomicU64::new(0);

    // Compute the updated stakers.
    let staking_rewards = cfg_iter!(stakers)
        .map(|(staker, (validator, stake))| {
            // If the validator is not in the valid validators list, skip the staker.
            let Some((validator_stake, commission_rate)) = valid_validators.get(validator) else {
                // Log validator not in committee.
                if tracing::enabled!(tracing::Level::TRACE) && !committee.members().contains_key(validator) {
                    let mut logged = missing_validators.lock();
                    if logged.insert(*validator) {
                        trace!("Validator {validator} is not in the committee - skipping all stakers");
                    }
                    invalid_validator_stake.fetch_add(*stake, std::sync::atomic::Ordering::Relaxed);
                }
                return (*staker, (*validator, *stake));
            };

            // If the staker has less than the minimum required stake, skip the staker, unless the staker is the validator.
            if *stake < MIN_DELEGATOR_STAKE && *staker != *validator {
                trace!("Staker has less than {MIN_DELEGATOR_STAKE} microcredits - skipping {staker}");
                return (*staker, (*validator, *stake));
            }

            // Compute the numerator.
            let numerator = (block_reward as u128).saturating_mul(*stake as u128);
            // Compute the denominator.
            // Note: We guarantee this denominator cannot be 0 (as we return early if the total stake is 0).
            let denominator = committee.total_stake() as u128;
            // Compute the quotient.
            let quotient = numerator.saturating_div(denominator);
            // Ensure the staking reward is within a safe bound.
            if quotient > MAX_COINBASE_REWARD as u128 {
                error!("Staking reward ({quotient}) is too large - skipping {staker}");
                return (*staker, (*validator, *stake));
            }
            // Cast the staking reward as a u64.
            // Note: This '.expect' is guaranteed to be safe, as we ensure the quotient is within a safe bound.
            let staking_reward = u64::try_from(quotient).expect("Staking reward is too large");

            // Update the staking reward with the commission.
            //
            // Note: This approach to computing commissions is far more computationally-efficient,
            // however it does introduce a small (deterministic) precision error that is accepted for the
            // sake of performance. There is a negligible difference (at most 100 microcredits per delegator)
            // between the validators (+) and the delegators (-) in the allocated commission difference.
            let staking_reward_after_commission = match staker == validator {
                // If the staker is the validator, add the total commission to the staking reward.
                true => {
                    // Calculate the total stake delegated to the validator.
                    let total_delegated_stake = validator_stake.saturating_sub(*stake);
                    // Compute the numerator.
                    let numerator = (block_reward as u128).saturating_mul(total_delegated_stake as u128);
                    // Compute the quotient. This quotient is the total staking reward recieved by delegators.
                    let quotient = numerator.saturating_div(denominator);
                    // Compute the commission.
                    let total_commission_to_receive =
                        quotient.saturating_mul(*commission_rate as u128).saturating_div(100u128);
                    // Cast the commission as a u64.
                    // Note: This '.expect' is guaranteed to be safe, as we ensure the commission is within a safe bound.
                    let total_commission_to_receive =
                        u64::try_from(total_commission_to_receive).expect("Commission is too large");

                    // Add the commission to the validator staking reward.
                    staking_reward.saturating_add(total_commission_to_receive)
                }
                // If the staker is a delegator, subtract the commission from the staking reward.
                false => {
                    // Calculate the commission.
                    let commission = quotient.saturating_mul(*commission_rate as u128).saturating_div(100u128);
                    // Cast the commission as a u64.
                    // Note: This '.expect' is guaranteed to be safe, as we ensure the quotient is within a safe bound.
                    let commission_to_pay = u64::try_from(commission).expect("Commission is too large");

                    // Subtract the commission from the delegator staking reward.
                    staking_reward.saturating_sub(commission_to_pay)
                }
            };
            // Return the staker and the updated stake.
            (*staker, (*validator, stake.saturating_add(staking_reward_after_commission)))
        })
        .collect();

    if tracing::enabled!(tracing::Level::TRACE) {
        let invalid_validator_stake = invalid_validator_stake.load(std::sync::atomic::Ordering::Relaxed);
        trace!("Total stake invalidated due to validator not in committee: {invalid_validator_stake}");
    }

    // Return the result.
    staking_rewards
}

/// Returns each staker's reward at this block, as `(staker, (validator, reward))`.
///
/// `next_stakers` is the map already produced by [`staking_rewards`]. A staker who receives
/// nothing, or who is absent from `next_stakers`, is stored with reward `0`.
pub fn staking_rewards_historical_mapping<N: Network>(
    stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
    next_stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
) -> IndexMap<Address<N>, (Address<N>, u64)> {
    stakers
        .iter()
        .map(|(staker, (validator, stake))| {
            let reward = next_stakers.get(staker).map(|(_, new_stake)| new_stake.saturating_sub(*stake)).unwrap_or(0);
            (*staker, (*validator, reward))
        })
        .collect()
}

/// Returns the proving rewards for a given coinbase reward and list of prover solutions.
/// The prover reward is defined as: `puzzle_reward * (proof_target / combined_proof_target)`.
pub fn proving_rewards<N: Network>(
    proof_targets: Vec<(Address<N>, u64)>,
    puzzle_reward: u64,
) -> IndexMap<Address<N>, u64> {
    // Compute the combined proof target. Using '.sum' here is safe because we sum u64s into a u128.
    let combined_proof_target = proof_targets.iter().map(|(_, t)| *t as u128).sum::<u128>();

    // If the list of solutions is empty, the combined proof target is 0, or the puzzle reward is 0, return an empty map.
    if proof_targets.is_empty() || combined_proof_target == 0 || puzzle_reward == 0 {
        return Default::default();
    }

    // Initialize a vector to store the proving rewards.
    let mut rewards = IndexMap::<_, u64>::with_capacity(proof_targets.len());

    // Calculate the rewards for the individual provers.
    for (address, proof_target) in proof_targets {
        // Compute the numerator.
        let numerator = (puzzle_reward as u128).saturating_mul(proof_target as u128);
        // Compute the denominator.
        // Note: We guarantee this denominator cannot be 0 (to prevent a div by 0).
        let denominator = combined_proof_target.max(1);
        // Compute the quotient.
        let quotient = numerator.saturating_div(denominator);
        // Ensure the proving reward is within a safe bound.
        if quotient > MAX_COINBASE_REWARD as u128 {
            error!("Prover reward ({quotient}) is too large - skipping solution from {address}");
            continue;
        }
        // Cast the proving reward as a u64.
        // Note: This '.expect' is guaranteed to be safe, as we ensure the quotient is within a safe bound.
        let prover_reward = u64::try_from(quotient).expect("Prover reward is too large");
        // If there is a proving reward, append it to the vector.
        if prover_reward > 0 {
            // Add the proving reward to the prover.
            let entry = rewards.entry(address).or_default();
            *entry = entry.saturating_add(prover_reward);
        }
    }

    // Return the proving rewards.
    rewards
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::prelude::TestRng;

    use indexmap::indexmap;

    type CurrentNetwork = console::network::MainnetV0;

    const ITERATIONS: usize = 10;

    #[test]
    fn test_staking_rewards() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee_with_commissions(rng);
        // Sample a random block reward.
        let block_reward = rng.random_range(0..MAX_COINBASE_REWARD);
        // Retrieve an address.
        let address = *committee.members().iter().next().unwrap().0;

        for _ in 0..ITERATIONS {
            // Sample a random stake.
            let stake = rng.random_range(MIN_DELEGATOR_STAKE..committee.total_stake());
            // Construct the stakers.
            let stakers = indexmap! {address => (address, stake)};
            let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, block_reward);
            assert_eq!(next_stakers.len(), 1);
            let (candidate_address, (candidate_validator, candidate_stake)) = next_stakers.into_iter().next().unwrap();
            assert_eq!(candidate_address, address);
            assert_eq!(candidate_validator, address);
            let reward = block_reward as u128 * stake as u128 / committee.total_stake() as u128;
            assert_eq!(candidate_stake, stake + u64::try_from(reward).unwrap(), "stake: {stake}, reward: {reward}");
        }
    }

    #[test]
    fn test_staking_rewards_to_validator_not_in_committee() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee(rng);
        let fake_committee = snarkvm_ledger_committee::test_helpers::sample_committee(rng);
        // Sample a random block reward.
        let block_reward = rng.random_range(0..MAX_COINBASE_REWARD);

        // Generate the stakers
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Generate stakers for a non-existent committee, to ensure they are not rewarded.
        let stakers_fake = crate::committee::test_helpers::to_stakers(fake_committee.members(), rng);
        let all_stakers: IndexMap<Address<CurrentNetwork>, (Address<CurrentNetwork>, u64)> =
            stakers.clone().into_iter().chain(stakers_fake.clone()).collect();

        // Start a timer.
        let timer = std::time::Instant::now();

        let next_stakers = staking_rewards::<CurrentNetwork>(&all_stakers, &committee, block_reward);
        println!("staking_rewards: {}ms", timer.elapsed().as_millis());
        assert_eq!(next_stakers.len(), all_stakers.len());
        for ((staker, (validator, stake)), (next_staker, (next_validator, next_stake))) in
            all_stakers.into_iter().zip(next_stakers)
        {
            assert_eq!(staker, next_staker);
            assert_eq!(validator, next_validator);
            // If the validator is not in the committee, the stake should not change.
            if !committee.members().contains_key(&validator) {
                assert_eq!(stake, next_stake, "stake: {stake}, reward should be 0");
            } else {
                // Otherwise, the stake should increase.
                let reward = block_reward as u128 * stake as u128 / committee.total_stake() as u128;
                assert_eq!(stake + u64::try_from(reward).unwrap(), next_stake, "stake: {stake}, reward: {reward}");
            }
        }
    }

    #[test]
    fn test_staking_rewards_commission() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee_with_commissions(rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Sample a random block reward.
        let block_reward = rng.random_range(0..MAX_COINBASE_REWARD);
        // Create a map of validators to commissions
        let commissions: IndexMap<Address<CurrentNetwork>, u8> =
            committee.members().iter().map(|(address, (_, _, commission))| (*address, *commission)).collect();
        // Print the commissions from the indexmap
        println!("commissions: {commissions:?}");
        // Create a map of validators to the sum of their commissions
        let mut total_commissions: IndexMap<Address<CurrentNetwork>, u64> = Default::default();

        // Start a timer.
        let timer = std::time::Instant::now();
        // Compute the staking rewards.
        let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, block_reward);
        println!("staking_rewards: {}ms", timer.elapsed().as_millis());
        assert_eq!(next_stakers.len(), stakers.len());
        for ((staker, (validator, stake)), (next_staker, (next_validator, next_stake))) in
            stakers.clone().into_iter().zip(next_stakers.clone())
        {
            assert_eq!(staker, next_staker);
            assert_eq!(validator, next_validator);

            let commission_rate = commissions.get(&validator).copied().unwrap_or(0);

            if staker == validator {
                // Calculate the total stake delegated to the validator.
                let total_stake = committee.get_stake(validator);
                let total_delegated_stake = total_stake.saturating_sub(stake);

                // Calculate the commission to receive.
                let reward = block_reward as u128 * total_delegated_stake as u128 / committee.total_stake() as u128;
                let commission_to_receive = reward * commission_rate as u128 / 100;

                total_commissions.insert(validator, u64::try_from(commission_to_receive).unwrap());
                assert_eq!(
                    stake + u64::try_from(reward + commission_to_receive).unwrap(),
                    next_stake,
                    "stake: {stake}, reward: {reward}, commission_to_receive: {commission_to_receive}, commission_rate: {commission_rate}"
                );
            } else {
                // Calculate the commission to pay the validator.
                let reward = block_reward as u128 * stake as u128 / committee.total_stake() as u128;
                let commission_to_pay = reward * commission_rate as u128 / 100;

                assert_eq!(
                    stake + u64::try_from(reward - commission_to_pay).unwrap(),
                    next_stake,
                    "stake: {stake}, reward: {reward}, commission_to_pay: {commission_to_pay}, commission_rate: {commission_rate}"
                );
            }
        }

        assert_eq!(
            total_commissions.len(),
            committee.members().len(),
            "total_commissions.len() != committee.members().len()"
        );

        // For each staker that is a validator, ensure the next staker = reward + commission.
        for (validator, commission) in total_commissions {
            let (_, stake) = stakers.get(&validator).unwrap();
            let (_, next_stake) = next_stakers.get(&validator).unwrap();
            let reward = block_reward as u128 * *stake as u128 / committee.total_stake() as u128;
            let expected_stake = stake + commission + u64::try_from(reward).unwrap();
            assert_eq!(*next_stake, expected_stake, "stake: {stake}, commission: {commission}");
        }
    }

    #[test]
    fn test_staking_rewards_large() {
        let rng = &mut TestRng::default();

        // Sample a random block reward.
        let block_reward = rng.random_range(0..MAX_COINBASE_REWARD);
        // Sample a committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 25, rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Compute the staking rewards.
        let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, block_reward);
        println!("staking_rewards: {}ms", timer.elapsed().as_millis());
        assert_eq!(next_stakers.len(), stakers.len());
        for ((staker, (validator, stake)), (next_staker, (next_validator, next_stake))) in
            stakers.into_iter().zip(next_stakers)
        {
            assert_eq!(staker, next_staker);
            assert_eq!(validator, next_validator);
            let reward = block_reward as u128 * stake as u128 / committee.total_stake() as u128;
            assert_eq!(stake + u64::try_from(reward).unwrap(), next_stake, "stake: {stake}, reward: {reward}");
        }
    }

    #[test]
    fn test_staking_rewards_when_delegator_is_under_min_yields_no_reward() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee(rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Sample a random block reward.
        let block_reward = rng.random_range(0..MAX_COINBASE_REWARD);
        // Retrieve an address of a delegator that isn't a validator
        let address = *stakers.iter().find(|(address, _)| !committee.is_committee_member(**address)).unwrap().0;

        for _ in 0..ITERATIONS {
            // Sample a random stake.
            let stake = rng.random_range(0..MIN_DELEGATOR_STAKE);
            // Construct the stakers.
            let stakers = indexmap! {address => (address, stake)};
            let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, block_reward);
            assert_eq!(next_stakers.len(), 1);
            let (candidate_address, (candidate_validator, candidate_stake)) = next_stakers.into_iter().next().unwrap();
            assert_eq!(candidate_address, address);
            assert_eq!(candidate_validator, address);
            assert_eq!(candidate_stake, stake);
        }
    }

    #[test]
    fn test_staking_rewards_cannot_exceed_coinbase_reward() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee(rng);
        // Retrieve an address.
        let address = *committee.members().iter().next().unwrap().0;

        // Construct the stakers.
        let stakers = indexmap![address => (address, MIN_DELEGATOR_STAKE)];
        // Check that a maxed out coinbase reward, returns empty.
        let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, u64::MAX);
        assert_eq!(stakers, next_stakers);

        // Ensure a staking reward that is too large, renders no rewards.
        for _ in 0..ITERATIONS {
            // Sample a random overly-large block reward.
            let block_reward = rng.random_range(MAX_COINBASE_REWARD..u64::MAX);
            // Sample a random stake.
            let stake = rng.random_range(MIN_DELEGATOR_STAKE..u64::MAX);
            // Construct the stakers.
            let stakers = indexmap![address => (address, stake)];
            // Check that an overly large block reward fails.
            let next_stakers = staking_rewards::<CurrentNetwork>(&stakers, &committee, block_reward);
            assert_eq!(stakers, next_stakers);
        }
    }

    #[test]
    fn test_staking_rewards_is_empty() {
        let rng = &mut TestRng::default();
        // Sample a random committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee(rng);

        // Compute the staking rewards (empty).
        let rewards = staking_rewards::<CurrentNetwork>(&indexmap![], &committee, rng.random());
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_proving_rewards() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random address.
            let address = Address::rand(rng);
            // Sample a random puzzle reward.
            let puzzle_reward = rng.random_range(0..MAX_COINBASE_REWARD);

            let rewards = proving_rewards::<CurrentNetwork>(vec![(address, u64::MAX)], puzzle_reward);
            assert_eq!(rewards.len(), 1);
            let (candidate_address, candidate_amount) = rewards.into_iter().next().unwrap();
            assert_eq!(candidate_address, address);
            assert!(candidate_amount <= puzzle_reward);
        }
    }

    #[test]
    fn test_proving_rewards_cannot_exceed_coinbase_reward() {
        let rng = &mut TestRng::default();

        // Ensure a proving reward that is too large, renders no rewards.
        for _ in 0..ITERATIONS {
            // Sample a random address.
            let address = Address::rand(rng);
            // Sample a random overly-large puzzle reward.
            let puzzle_reward = rng.random_range(MAX_COINBASE_REWARD..u64::MAX);
            // Sample a random proof target.
            let proof_target = rng.random_range(0..u64::MAX);
            // Check that a maxed out proof target fails.
            let rewards = proving_rewards::<CurrentNetwork>(vec![(address, proof_target)], puzzle_reward);
            assert!(rewards.is_empty());
        }
    }

    #[test]
    fn test_proving_rewards_is_empty() {
        let rng = &mut TestRng::default();
        // Sample a random address.
        let address = Address::rand(rng);

        // Compute the proving rewards (empty).
        let rewards = proving_rewards::<CurrentNetwork>(vec![], rng.random());
        assert!(rewards.is_empty());

        // Check that a maxed out coinbase reward, returns empty.
        let rewards = proving_rewards::<CurrentNetwork>(vec![(address, 2)], u64::MAX);
        assert!(rewards.is_empty());

        // Ensure a 0 coinbase reward case is empty.
        let rewards = proving_rewards::<CurrentNetwork>(vec![(address, 2)], 0);
        assert!(rewards.is_empty());
    }

    #[test]
    fn test_historical_mapping_uses_the_supplied_next_stake() {
        let rng = &mut TestRng::default();
        let staker = Address::<CurrentNetwork>::rand(rng);
        let missing = Address::<CurrentNetwork>::rand(rng);
        let validator = Address::<CurrentNetwork>::rand(rng);
        let current = indexmap! { staker => (validator, 10u64), missing => (validator, 4) };
        // The next stake is supplied by the caller. This function does not recompute it.
        let next = indexmap! { staker => (validator, 15u64) };
        let rewards = staking_rewards_historical_mapping(&current, &next);
        assert_eq!(rewards[&staker], (validator, 5));
        assert_eq!(rewards[&missing], (validator, 0));
    }
}
