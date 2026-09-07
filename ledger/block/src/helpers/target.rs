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

use console::prelude::{ConsensusVersion, Network, Result, consensus_config_value_by_version, ensure};

/// A safety bound (sanity-check) for the coinbase reward.
pub const MAX_COINBASE_REWARD: u64 = 190_258_739; // Coinbase reward at block 1.

/// A the maximum block interval in seconds. This is used to upper bound the block interval in the V2 block reward calculation to
/// prevent the block reward from becoming too large in the event of a long block interval.
const V2_MAX_BLOCK_INTERVAL: i64 = 60; // 1 minute.
/// A the minimum block interval in seconds. This is used to lower bound the block interval in the V2 block reward calculation to
/// prevent the block reward from becoming too small in the event of an extremely short block interval.
const V2_MIN_BLOCK_INTERVAL: i64 = 1; // 1 second.

/// The number of seconds in a year with 365 days. Leap years are ignored for simplicity.
const SECONDS_IN_A_YEAR: u32 = 60 * 60 * 24 * 365;

/// Calculate the block reward based on the network’s consensus version, determined by the given block height.
/// If the block height is at or beyond the max supply limit height, the block reward is zero.
pub fn block_reward<N: Network>(
    block_height: u32,
    total_supply: u64,
    block_time: u16,
    time_since_last_block: i64,
    coinbase_reward: u64,
    transaction_fees: u64,
) -> Result<u64> {
    // If the height is at or beyond the max supply limit height, set rewards to zero.
    if block_height >= N::MAX_SUPPLY_LIMIT_HEIGHT {
        return Ok(0);
    }

    // Determine which block reward version to use.
    let consensus_version = N::CONSENSUS_VERSION(block_height)?;
    match consensus_version == ConsensusVersion::V1 {
        true => Ok(block_reward_v1(total_supply, block_time, coinbase_reward, transaction_fees)),
        false => Ok(block_reward_v2(total_supply, time_since_last_block, coinbase_reward, transaction_fees)),
    }
}

/// Calculate the V1 block reward, given the total supply, block time, coinbase reward, and transaction fees.
///     R_staking = floor((0.05 * S) / H_Y1) + CR / 3 + TX_F.
///     S = Total supply.
///     H_Y1 = Expected block height at year 1.
///     CR = Coinbase reward.
///     TX_F = Transaction fees.
pub const fn block_reward_v1(total_supply: u64, block_time: u16, coinbase_reward: u64, transaction_fees: u64) -> u64 {
    // Compute the expected block height at year 1.
    let block_height_at_year_1 = block_height_at_year(block_time, 1);
    // Compute the annual reward: (0.05 * S).
    let annual_reward = total_supply / 20;
    // Compute the block reward: (0.05 * S) / H_Y1.
    let block_reward = annual_reward / block_height_at_year_1 as u64;
    // Return the sum of the block reward, coinbase reward, and transaction fees.
    block_reward + (coinbase_reward / 3) + transaction_fees
}

/// Calculate the V2 block reward, given the total supply, block interval, coinbase reward, and transaction fees.
///     R_staking = floor((0.05 * S) * clamp(I, MIN_BI, MAX_BI) / S_Y) + CR / 3 + TX_F.
///     S = Total supply.
///     I = Seconds elapsed since last block.
///     S_Y = Seconds in a year (31536000).
///     CR = Coinbase reward.
///     TX_F = Transaction fees.
///     MIN_BI = Minimum block interval.
///     MAX_BI = Maximum block interval.
pub fn block_reward_v2(
    total_supply: u64,
    time_since_last_block: i64,
    coinbase_reward: u64,
    transaction_fees: u64,
) -> u64 {
    // Compute the annual reward: (0.05 * S).
    let annual_reward = total_supply / 20;
    // Compute the seconds since last block with a maximum of `V2_MAX_BLOCK_INTERVAL` seconds and minimum of `V2_MIN_BLOCK_INTERVAL` seconds;
    let time_since_last_block = time_since_last_block.clamp(V2_MIN_BLOCK_INTERVAL, V2_MAX_BLOCK_INTERVAL);
    // Compute the block reward: (0.05 * S) * min(max(I, MIN_BLOCK_INTERVAL), MAX_BLOCK_INTERVAL) / S_Y.
    let block_reward = annual_reward * time_since_last_block as u64 / SECONDS_IN_A_YEAR as u64;
    // Return the sum of the block reward, coinbase reward, and transaction fees.
    block_reward + (coinbase_reward / 3) + transaction_fees
}

/// Calculate the puzzle reward, given the coinbase reward.
/// The puzzle reward is 2/3 of the total coinbase reward and paid out to the provers. The other 1/3 of
/// the coinbase reward is included in the block reward and paid out to stakers.
pub const fn puzzle_reward(coinbase_reward: u64) -> u64 {
    // Return the coinbase reward multiplied by 2 and divided by 3.
    coinbase_reward.saturating_mul(2).saturating_div(3)
}

/// Calculate the coinbase reward based on the network’s consensus version, determined by the given block height.
/// If the block height is at or beyond the max supply limit height, the coinbase reward is zero.
pub fn coinbase_reward<N: Network>(
    block_height: u32,
    block_timestamp: i64,
    genesis_timestamp: i64,
    starting_supply: u64,
    anchor_time: u16,
    anchor_height: u32,
    block_time: u16,
    combined_proof_target: u128,
    cumulative_proof_target: u64,
    coinbase_target: u64,
) -> Result<u64> {
    // If the height is at or beyond the max supply limit height, set rewards to zero.
    if block_height >= N::MAX_SUPPLY_LIMIT_HEIGHT {
        return Ok(0);
    }

    // Determine which coinbase reward version to use.
    let consensus_version = N::CONSENSUS_VERSION(block_height)?;
    if consensus_version == ConsensusVersion::V1 {
        coinbase_reward_v1(
            block_height,
            starting_supply,
            anchor_height,
            block_time,
            combined_proof_target,
            cumulative_proof_target,
            coinbase_target,
        )
    } else {
        coinbase_reward_v2(
            block_timestamp,
            genesis_timestamp,
            starting_supply,
            anchor_time,
            combined_proof_target,
            cumulative_proof_target,
            coinbase_target,
        )
    }
}

/// Calculates the V1 coinbase reward for a given block.
///     R_coinbase = R_anchor(H) * min(P, C_R) / C
///     R_anchor = Anchor reward at block height.
///     H = Current block height.
///     P = Combined proof target.
///     C_R = Remaining coinbase target.
///     C = Coinbase target.
pub fn coinbase_reward_v1(
    block_height: u32,
    starting_supply: u64,
    anchor_height: u32,
    block_time: u16,
    combined_proof_target: u128,
    cumulative_proof_target: u64,
    coinbase_target: u64,
) -> Result<u64> {
    // Compute the remaining coinbase target.
    let remaining_coinbase_target = coinbase_target.saturating_sub(cumulative_proof_target);
    // Compute the remaining proof target.
    let remaining_proof_target = combined_proof_target.min(remaining_coinbase_target as u128);

    // Compute the anchor block reward.
    let anchor_block_reward = anchor_block_reward_at_height(block_height, starting_supply, anchor_height, block_time);

    // Calculate the coinbase reward.
    let reward = anchor_block_reward.saturating_mul(remaining_proof_target).saturating_div(coinbase_target as u128);

    // Ensure the coinbase reward is less than the maximum coinbase reward.
    ensure!(reward <= MAX_COINBASE_REWARD as u128, "Coinbase reward ({reward}) exceeds maximum {MAX_COINBASE_REWARD}");

    // Return the coinbase reward.
    // Note: This '.expect' is guaranteed to be safe, as we ensure the reward is within a safe bound.
    Ok(u64::try_from(reward).expect("Coinbase reward exceeds u64::MAX"))
}

/// Calculates the V2 coinbase reward for a given block.
///     R_coinbase = R_anchor(H) * min(P, C_R) / C
///     R_anchor = Anchor reward at block height.
///     H = Current block height.
///     P = Combined proof target.
///     C_R = Remaining coinbase target.
///     C = Coinbase target.
pub fn coinbase_reward_v2(
    block_timestamp: i64,
    genesis_timestamp: i64,
    starting_supply: u64,
    anchor_time: u16,
    combined_proof_target: u128,
    cumulative_proof_target: u64,
    coinbase_target: u64,
) -> Result<u64> {
    // Compute the remaining coinbase target.
    let remaining_coinbase_target = coinbase_target.saturating_sub(cumulative_proof_target);
    // Compute the remaining proof target.
    let remaining_proof_target = combined_proof_target.min(remaining_coinbase_target as u128);

    // Compute the anchor block reward.
    let anchor_block_reward =
        anchor_block_reward_at_timestamp(block_timestamp, genesis_timestamp, starting_supply, anchor_time);

    // Calculate the coinbase reward.
    let reward = anchor_block_reward.saturating_mul(remaining_proof_target).saturating_div(coinbase_target as u128);

    // Ensure the coinbase reward is less than the maximum coinbase reward.
    ensure!(reward <= MAX_COINBASE_REWARD as u128, "Coinbase reward ({reward}) exceeds maximum {MAX_COINBASE_REWARD}");

    // Return the coinbase reward.
    // Note: This '.expect' is guaranteed to be safe, as we ensure the reward is within a safe bound.
    Ok(u64::try_from(reward).expect("Coinbase reward exceeds u64::MAX"))
}

/// Calculates the anchor block reward for the given block height.
/// The anchor block reward is upper bound of the coinbase reward for the given block before
/// calculating the final pro-rata coinbase reward based on the targets.
///     R_anchor = max(floor((2 * S * H_A * H_R) / (H_Y10 * (H_Y10 + 1))), R_Y9).
///     S = Starting supply.
///     H_A = Anchor block height.
///     H_R = Remaining number of blocks until year 10.
///     H_Y10 = Expected block height at year 10.
///     R_Y9 = Reward at year 9.
fn anchor_block_reward_at_height(block_height: u32, starting_supply: u64, anchor_height: u32, block_time: u16) -> u128 {
    // A helper function to calculate the reward at a given block height, without the year 9 baseline.
    const fn block_reward_at_height(height: u32, starting_supply: u64, anchor_height: u32, block_time: u16) -> u128 {
        // Calculate the block height at year 10.
        let block_height_at_year_10 = block_height_at_year(block_time, 10) as u128;
        // Compute the remaining blocks until year 10.
        let num_remaining_blocks_to_year_10 = block_height_at_year_10.saturating_sub(height as u128);
        // Compute the numerator.
        let numerator = 2 * starting_supply as u128 * anchor_height as u128 * num_remaining_blocks_to_year_10;
        // Compute the denominator.
        let denominator = block_height_at_year_10 * (block_height_at_year_10 + 1);
        // Compute the quotient.
        numerator / denominator
    }

    // Calculate the block height at year 9.
    let block_height_at_year_9 = block_height_at_year(block_time, 9);
    // Compute the unadjusted reward at year 9.
    let reward_at_year_9 = block_reward_at_height(block_height_at_year_9, starting_supply, anchor_height, block_time);
    // Compute the unadjusted reward at the given block height.
    let reward_at_block_height = block_reward_at_height(block_height, starting_supply, anchor_height, block_time);
    // Compute the anchor block reward.
    reward_at_block_height.max(reward_at_year_9)
}

/// Calculates the anchor block reward for the given block timestamp.
/// The anchor block reward is upper bound of the coinbase reward for the given block before
/// calculating the final pro-rata coinbase reward based on the targets.
/// This function uses timestamp rather than block height to determine the reward in order to combat
/// the volatility of block times and better align with human timescales.
///     R_anchor = max(floor((2 * S * T_A * T_R) / (T_Y10 * (T_Y10 + 1))), R_Y9).
///     S = Starting supply.
///     T_A = Anchor block time.
///     T_R = Remaining number of seconds until year 10.
///     T_Y10 = Number of seconds elapsed in 10 years.
///     R_Y9 = Reward at year 9.
fn anchor_block_reward_at_timestamp(
    block_timestamp: i64,
    genesis_timestamp: i64,
    starting_supply: u64,
    anchor_time: u16,
) -> u128 {
    // A helper function to calculate the reward at a given block timestamp, without the year 9 baseline.
    const fn block_reward_at_timestamp(
        block_timestamp: i64,
        genesis_timestamp: i64,
        starting_supply: u64,
        anchor_time: u16,
    ) -> u128 {
        // Calculate the timestamp at year 10.
        let timestamp_at_year_10 = timestamp_at_year(genesis_timestamp, 10) as u128;
        // Calculate the number of seconds elapsed in 10 years.
        let number_of_seconds_in_10_years = (SECONDS_IN_A_YEAR as u128).saturating_mul(10);
        // Compute the remaining seconds until year 10.
        let num_remaining_seconds_to_year_10 = timestamp_at_year_10.saturating_sub(block_timestamp as u128);

        // Compute the numerator.
        // Note that we perform a `saturating_div(10)` on the `anchor_time` in the numerator and the `number_of_seconds_in_10_years` denominator.
        // This is done to match the truncation of `anchor_block_reward_at_height` in an attempt to
        // keep the reward more consistent between the two functions.
        let numerator =
            2 * starting_supply as u128 * anchor_time.saturating_div(10) as u128 * num_remaining_seconds_to_year_10;
        // Compute the denominator.
        let denominator = number_of_seconds_in_10_years * (number_of_seconds_in_10_years.saturating_div(10) + 1);
        // Compute the quotient.
        numerator / denominator
    }

    // Calculate the timestamp at year 9.
    let timestamp_at_year_9 = timestamp_at_year(genesis_timestamp, 9);
    // Compute the unadjusted reward at year 9.
    let reward_at_year_9 =
        block_reward_at_timestamp(timestamp_at_year_9, genesis_timestamp, starting_supply, anchor_time);
    // Compute the unadjusted reward at the given block timestamp.
    let reward_at_block_timestamp =
        block_reward_at_timestamp(block_timestamp, genesis_timestamp, starting_supply, anchor_time);
    // Compute the anchor block reward.
    reward_at_block_timestamp.max(reward_at_year_9)
}

/// Returns the timestamp for a given year, relative to the genesis timestamp.
/// We assume a year is 365 days and ignore leap years for simplicity.
const fn timestamp_at_year(genesis_timestamp: i64, num_years: u32) -> i64 {
    // Calculate the number of seconds elapsed in `num_years`.
    let seconds_elapsed = SECONDS_IN_A_YEAR.saturating_mul(num_years);
    // Return the timestamp for the given year.
    genesis_timestamp.saturating_add(seconds_elapsed as i64)
}

/// Returns the block height after a given number of years for a specific block time.
const fn block_height_at_year(block_time: u16, num_years: u32) -> u32 {
    // Calculate the one-year block height.
    let block_height_at_year_1 = SECONDS_IN_A_YEAR / block_time as u32;
    // Return the block height for the given number of years.
    block_height_at_year_1 * num_years
}

/// Calculate the coinbase target for the given block timestamps and target.
pub fn coinbase_target(
    previous_target: u64,
    previous_block_timestamp: i64,
    block_timestamp: i64,
    anchor_time: u16,
    num_blocks_per_epoch: u32,
    genesis_target: u64,
) -> Result<u64> {
    // Compute the half life.
    let half_life = num_blocks_per_epoch.saturating_div(2).saturating_mul(anchor_time as u32);
    // Compute the new coinbase target.
    let candidate_target =
        retarget(previous_target, previous_block_timestamp, block_timestamp, anchor_time, half_life, true)?;
    // Return the new coinbase target, floored at the genesis target.
    Ok(candidate_target.max(genesis_target))
}

/// Calculate the minimum proof target for the given coinbase target.
pub fn proof_target(coinbase_target: u64, genesis_proof_target: u64, max_solutions_as_power_of_two: u8) -> u64 {
    coinbase_target
        .checked_shr(max_solutions_as_power_of_two as u32)
        .map(|target| target.saturating_add(1))
        .unwrap_or(genesis_proof_target)
}

/// Retarget algorithm using fixed point arithmetic from https://www.reference.cash/protocol/forks/2020-11-15-asert.
///     T_{i+1} = T_i * 2^(INV * (D - A) / TAU).
///     T_i = Current target.
///     D = Drift, defined as the number of blocks elapsed.
///     A = Anchor timestamp, defined as expected number of seconds elapsed.
///     TAU = Rate of doubling (or half-life) in seconds.
///     INV = {-1, 1} depending on whether the target is increasing or decreasing.
fn retarget(
    previous_target: u64,
    previous_block_timestamp: i64,
    block_timestamp: i64,
    anchor_time: u16,
    half_life: u32,
    is_inverse: bool,
) -> Result<u64> {
    // Determine the block time elapsed (in seconds) since the previous block.
    // Note: This operation includes a safety check for a repeat block timestamp.
    let block_time_elapsed = block_timestamp.saturating_sub(previous_block_timestamp).max(1);
    // Compute the drift.
    let mut drift = block_time_elapsed.saturating_sub(anchor_time as i64);

    // If the drift is zero, return the previous target.
    if drift == 0 {
        return Ok(previous_target);
    }

    // Negate the drift if the inverse flag is set.
    if is_inverse {
        drift *= -1;
    }

    // Constants used for fixed point arithmetic.
    const RBITS: u32 = 16;
    const RADIX: u128 = 1 << RBITS;

    // Compute the exponent factor, and decompose it into integral & fractional parts for fixed point arithmetic.
    let (integral, fractional) = {
        // Calculate the exponent factor.
        let exponent = (RADIX as i128).saturating_mul(drift as i128) / half_life as i128;

        // Decompose into the integral and fractional parts.
        let integral = exponent >> RBITS;
        let fractional = (exponent - (integral << RBITS)) as u128;
        ensure!(fractional < RADIX, "Fractional part is not within the fixed point size");
        ensure!(exponent == (integral * (RADIX as i128) + fractional as i128), "Exponent is decomposed incorrectly");

        (integral, fractional)
    };

    // Approximate the fractional multiplier as 2^RBITS * 2^fractional, where:
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3)
    let fractional_multiplier = RADIX
        + ((195_766_423_245_049_u128 * fractional
            + 971_821_376_u128 * fractional.pow(2)
            + 5_127_u128 * fractional.pow(3)
            + 2_u128.pow(RBITS * 3 - 1))
            >> (RBITS * 3));

    // Cast the previous coinbase target from a u64 to a u128.
    // The difficulty target must allow for leading zeros to account for overflows;
    // an additional 64-bits for the leading zeros suffices.
    let candidate_target = (previous_target as u128).saturating_mul(fractional_multiplier);

    // Calculate the new difficulty.
    // Shift the target to multiply by 2^(integer) / RADIX.
    let shifts = integral - RBITS as i128;
    let mut candidate_target = if shifts < 0 {
        match candidate_target.checked_shr(u32::try_from(-shifts)?) {
            Some(target) => core::cmp::max(target, 1),
            None => 1,
        }
    } else {
        match candidate_target.checked_shl(u32::try_from(shifts)?) {
            Some(target) => core::cmp::max(target, 1),
            None => u64::MAX as u128,
        }
    };

    // Cap the target at `u64::MAX` if it has overflowed.
    candidate_target = core::cmp::min(candidate_target, u64::MAX as u128);

    // Ensure that the leading 64 bits are zeros.
    ensure!(candidate_target.checked_shr(64) == Some(0), "The target has overflowed");
    // Cast the new target down from a u128 to a u64.
    Ok(u64::try_from(candidate_target)?)
}

/// This function calculates the next targets for the given attributes:
///     `latest_cumulative_proof_target`: The latest cumulative proof target.
///     `combined_proof_target`: The combined proof target of solutions in the block.
///     `latest_coinbase_target`: The latest coinbase target.
///     `last_coinbase_target`: The coinbase target for the last coinbase.
///     `last_coinbase_timestamp`: The timestamp for the last coinbase.
///     `next_timestamp`: The timestamp for the next block.
///
/// Returns the following as a tuple:
///     `next_coinbase_target` - The next coinbase target.
///     `next_proof_target` - The next proof target.
///     `next_cumulative_proof_target` - The next cumulative proof target.
///     `next_cumulative_weight` - The next cumulative weight.
///     `next_last_coinbase_target` - The next last coinbase target.
///     `next_last_coinbase_timestamp` - The next last coinbase timestamp.
pub fn to_next_targets<N: Network>(
    consensus_version: ConsensusVersion,
    latest_cumulative_proof_target: u128,
    combined_proof_target: u128,
    latest_coinbase_target: u64,
    latest_cumulative_weight: u128,
    last_coinbase_target: u64,
    last_coinbase_timestamp: i64,
    next_timestamp: i64,
) -> Result<(u64, u64, u128, u128, u64, i64)> {
    // Compute the coinbase target threshold.
    let latest_coinbase_threshold = latest_coinbase_target.saturating_div(2) as u128;
    // Compute the next cumulative proof target.
    let next_cumulative_proof_target = latest_cumulative_proof_target.saturating_add(combined_proof_target);
    // Determine if the coinbase target threshold is reached.
    let is_coinbase_threshold_reached = next_cumulative_proof_target >= latest_coinbase_threshold;
    // Look up the anchor time for the active consensus version.
    let anchor_time = consensus_config_value_by_version!(N, ANCHOR_TIMES, consensus_version)
        .ok_or_else(|| anyhow::anyhow!("No anchor time defined for consensus version {consensus_version}"))?;
    // Construct the next coinbase target.
    let next_coinbase_target = coinbase_target(
        last_coinbase_target,
        last_coinbase_timestamp,
        next_timestamp,
        anchor_time,
        N::NUM_BLOCKS_PER_EPOCH,
        N::GENESIS_COINBASE_TARGET,
    )?;
    // Construct the next proof target.
    let next_proof_target =
        proof_target(next_coinbase_target, N::GENESIS_PROOF_TARGET, N::MAX_SOLUTIONS_AS_POWER_OF_TWO);

    // Update the next cumulative proof target, if necessary.
    let next_cumulative_proof_target = match is_coinbase_threshold_reached {
        true => 0,
        false => next_cumulative_proof_target,
    };

    // Compute the next cumulative weight.
    let next_cumulative_weight = latest_cumulative_weight.saturating_add(combined_proof_target);

    // Construct the next last coinbase target and next last coinbase timestamp.
    let (next_last_coinbase_target, next_last_coinbase_timestamp) = match is_coinbase_threshold_reached {
        true => (next_coinbase_target, next_timestamp),
        false => (last_coinbase_target, last_coinbase_timestamp),
    };

    Ok((
        next_coinbase_target,
        next_proof_target,
        next_cumulative_proof_target,
        next_cumulative_weight,
        next_last_coinbase_target,
        next_last_coinbase_timestamp,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::{MainnetV0, TestnetV0, prelude::*};

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u32 = 1000;

    const EXPECTED_ANCHOR_BLOCK_REWARD_AT_BLOCK_1: u128 = MAX_COINBASE_REWARD as u128;
    const EXPECTED_STAKING_REWARD: u64 = 23_782_343;
    const EXPECTED_COINBASE_REWARD_AT_BLOCK_1: u64 = MAX_COINBASE_REWARD;
    const EXPECTED_MAX_STAKING_REWARD: u64 = 142_694_063;

    #[test]
    #[cfg(not(feature = "test"))]
    fn test_consensus_heights_are_network_specific() -> Result<()> {
        // The network crate is a dependency here, so its non-test implementation is exercised.
        for _ in 0..2 {
            assert_eq!(TestnetV0::CONSENSUS_VERSION_HEIGHTS(), &TestnetV0::_CONSENSUS_VERSION_HEIGHTS);
            assert_eq!(CanaryV0::CONSENSUS_VERSION_HEIGHTS(), &CanaryV0::_CONSENSUS_VERSION_HEIGHTS);
            assert_eq!(MainnetV0::CONSENSUS_VERSION_HEIGHTS(), &MainnetV0::_CONSENSUS_VERSION_HEIGHTS);

            for (version, height) in MainnetV0::_CONSENSUS_VERSION_HEIGHTS {
                assert_eq!(MainnetV0::CONSENSUS_HEIGHT(version)?, height);
            }
        }
        Ok(())
    }

    #[test]
    fn test_anchor_block_reward_v1() {
        // Check the anchor block reward at block 1.
        let reward_at_block_1 = anchor_block_reward_at_height(
            1,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
        );
        assert_eq!(reward_at_block_1, EXPECTED_ANCHOR_BLOCK_REWARD_AT_BLOCK_1);

        // A helper function to check the the reward at the first expected block of a given year.
        fn check_reward_at_year(year: u32, expected_reward: u128) {
            let reward_at_year = anchor_block_reward_at_height(
                block_height_at_year(CurrentNetwork::BLOCK_TIME, year),
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::ANCHOR_HEIGHT,
                CurrentNetwork::BLOCK_TIME,
            );
            assert_eq!(reward_at_year, expected_reward);
        }

        // Check the anchor block reward at the start of years 1 through 15.
        check_reward_at_year(1, 171_232_871);
        check_reward_at_year(2, 152_206_996);
        check_reward_at_year(3, 133_181_122);
        check_reward_at_year(4, 114_155_247);
        check_reward_at_year(5, 95_129_372);
        check_reward_at_year(6, 76_103_498);
        check_reward_at_year(7, 57_077_623);
        check_reward_at_year(8, 38_051_749);
        check_reward_at_year(9, 19_025_874);
        check_reward_at_year(10, 19_025_874);
        check_reward_at_year(11, 19_025_874);
        check_reward_at_year(12, 19_025_874);
        check_reward_at_year(13, 19_025_874);
        check_reward_at_year(14, 19_025_874);
        check_reward_at_year(15, 19_025_874);

        // Calculate the block height at year 9.
        let block_height_at_year_9 = block_height_at_year(CurrentNetwork::BLOCK_TIME, 9);

        // Ensure that the reward is decreasing for blocks before year 9.
        let mut previous_reward = reward_at_block_1;
        let anchor_height = CurrentNetwork::ANCHOR_HEIGHT as usize;
        for height in (2..block_height_at_year_9).step_by(anchor_height).skip(1) {
            let reward = anchor_block_reward_at_height(
                height,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::ANCHOR_HEIGHT,
                CurrentNetwork::BLOCK_TIME,
            );
            assert!(reward < previous_reward, "Failed on block height {height}");
            previous_reward = reward;
        }

        // Ensure that the reward is 19_025_874 for blocks after year 9.
        for height in block_height_at_year_9..(block_height_at_year_9 + ITERATIONS) {
            let reward = anchor_block_reward_at_height(
                height,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::ANCHOR_HEIGHT,
                CurrentNetwork::BLOCK_TIME,
            );
            assert_eq!(reward, 19_025_874);
        }
    }

    #[test]
    fn test_anchor_block_reward_v2() {
        // Check the anchor block reward at block 1.
        let reward_at_block_1 = anchor_block_reward_at_timestamp(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
        );
        assert_eq!(reward_at_block_1, EXPECTED_ANCHOR_BLOCK_REWARD_AT_BLOCK_1);

        // A helper function to check the the reward at the first expected block of a given year.
        fn check_reward_at_year(year: u32, expected_reward: u128) {
            let reward_at_year = anchor_block_reward_at_timestamp(
                timestamp_at_year(CurrentNetwork::GENESIS_TIMESTAMP, year),
                CurrentNetwork::GENESIS_TIMESTAMP,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::REWARD_ANCHOR_TIME,
            );
            assert_eq!(reward_at_year, expected_reward);
        }

        // Check the anchor block reward at the start of years 1 through 15.
        check_reward_at_year(1, 171_232_871);
        check_reward_at_year(2, 152_206_996);
        check_reward_at_year(3, 133_181_122);
        check_reward_at_year(4, 114_155_247);
        check_reward_at_year(5, 95_129_372);
        check_reward_at_year(6, 76_103_498);
        check_reward_at_year(7, 57_077_623);
        check_reward_at_year(8, 38_051_749);
        check_reward_at_year(9, 19_025_874);
        check_reward_at_year(10, 19_025_874);
        check_reward_at_year(11, 19_025_874);
        check_reward_at_year(12, 19_025_874);
        check_reward_at_year(13, 19_025_874);
        check_reward_at_year(14, 19_025_874);
        check_reward_at_year(15, 19_025_874);

        // Calculate the timestamp at year 9.
        let timestamp_at_year_9 = timestamp_at_year(CurrentNetwork::GENESIS_TIMESTAMP, 9);

        // Ensure that the reward is decreasing for blocks before year 9.
        let mut previous_reward = reward_at_block_1;
        let anchor_time = CurrentNetwork::REWARD_ANCHOR_TIME as usize;
        for timestamp in (CurrentNetwork::GENESIS_TIMESTAMP..timestamp_at_year_9).step_by(anchor_time).skip(1) {
            let reward = anchor_block_reward_at_timestamp(
                timestamp,
                CurrentNetwork::GENESIS_TIMESTAMP,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::REWARD_ANCHOR_TIME,
            );
            assert!(reward < previous_reward, "Failed on timestamp {timestamp}");
            previous_reward = reward;
        }

        // Ensure that the reward is 19_025_874 for blocks after year 9.
        for timestamp in timestamp_at_year_9..(timestamp_at_year_9 + ITERATIONS as i64) {
            let reward = anchor_block_reward_at_timestamp(
                timestamp,
                CurrentNetwork::GENESIS_TIMESTAMP,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::REWARD_ANCHOR_TIME,
            );
            assert_eq!(reward, 19_025_874);
        }
    }

    #[test]
    fn test_total_anchor_block_reward_v1() {
        // A helper function used to add the anchor block reward for a given range of block heights.
        fn add_anchor_block_reward(total_reward: &mut u128, start_height: u32, end_height: u32) {
            for height in start_height..end_height {
                *total_reward += anchor_block_reward_at_height(
                    height,
                    CurrentNetwork::STARTING_SUPPLY,
                    CurrentNetwork::ANCHOR_HEIGHT,
                    CurrentNetwork::BLOCK_TIME,
                );
            }
        }

        // Initialize the total reward.
        let mut total_reward = 0;

        // A helper function to check the sum of all possible anchor rewards over a given year.
        let mut check_sum_of_anchor_rewards = |year: u32, expected_reward: u128| {
            assert!(year > 0, "Year must be greater than 0");
            let end_height = block_height_at_year(CurrentNetwork::BLOCK_TIME, year);
            let start_height = std::cmp::max(1, block_height_at_year(CurrentNetwork::BLOCK_TIME, year - 1));
            add_anchor_block_reward(&mut total_reward, start_height, end_height);
            assert_eq!(total_reward, expected_reward);
        };

        // Check the sum of all anchor block rewards at block at year 1.
        check_sum_of_anchor_rewards(1, 569999799602807);
        // Check the sum of all anchor block rewards at block at year 2.
        check_sum_of_anchor_rewards(2, 1079999791366949);
        // Check the sum of all anchor block rewards at block at year 3.
        check_sum_of_anchor_rewards(3, 1529999785033683);
        // Check the sum of all anchor block rewards at block at year 4.
        check_sum_of_anchor_rewards(4, 1919999780603002);
        // Check the sum of all anchor block rewards at block at year 5.
        check_sum_of_anchor_rewards(5, 2249999778074916);
        // Check the sum of all anchor block rewards at block at year 6.
        check_sum_of_anchor_rewards(6, 2519999777449404);
        // Check the sum of all anchor block rewards at block at year 7.
        check_sum_of_anchor_rewards(7, 2729999778726485);
        // Check the sum of all anchor block rewards at block at year 8.
        check_sum_of_anchor_rewards(8, 2879999781906155);
        // Check the sum of all anchor block rewards at block at year 9.
        check_sum_of_anchor_rewards(9, 2969999786988413);
        // Check the sum of all anchor block rewards at block at year 10.
        check_sum_of_anchor_rewards(10, 3029999783234813);
        // Check the sum of all anchor block rewards at block at year 11.
        check_sum_of_anchor_rewards(11, 3089999779481213);
        // Check the sum of all anchor block rewards at block at year 12.
        check_sum_of_anchor_rewards(12, 3149999775727613);
        // Check the sum of all anchor block rewards at block at year 13.
        check_sum_of_anchor_rewards(13, 3209999771974013);
        // Check the sum of all anchor block rewards at block at year 14.
        check_sum_of_anchor_rewards(14, 3269999768220413);
        // Check the sum of all anchor block rewards at block at year 15.
        check_sum_of_anchor_rewards(15, 3329999764466813);
    }

    #[test]
    fn test_total_anchor_block_reward_v2() {
        // A helper function used to add the anchor block reward for a given range of block timestamps.
        fn add_anchor_block_reward(total_reward: &mut u128, start_timestamp: i64, end_timestamp: i64) {
            for timestamp in (start_timestamp..end_timestamp).step_by(CurrentNetwork::BLOCK_TIME as usize) {
                *total_reward += anchor_block_reward_at_timestamp(
                    timestamp,
                    CurrentNetwork::GENESIS_TIMESTAMP,
                    CurrentNetwork::STARTING_SUPPLY,
                    CurrentNetwork::REWARD_ANCHOR_TIME,
                );
            }
        }

        // Initialize the total reward.
        let mut total_reward = 0;

        // A helper function to check the sum of all possible anchor rewards over a given year.
        let mut check_sum_of_anchor_rewards = |year: u32, expected_reward: u128| {
            assert!(year > 0, "Year must be greater than 0");
            let end_timestamp = timestamp_at_year(CurrentNetwork::GENESIS_TIMESTAMP, year);
            let start_timestamp = std::cmp::max(
                CurrentNetwork::GENESIS_TIMESTAMP,
                timestamp_at_year(CurrentNetwork::GENESIS_TIMESTAMP, year - 1),
            );
            add_anchor_block_reward(&mut total_reward, start_timestamp, end_timestamp);
            // println!("year {year}, total_reward: {total_reward} expected_reward: {expected_reward}")
            assert_eq!(total_reward, expected_reward);
        };

        // Check the sum of all anchor block rewards at block at year 1.
        check_sum_of_anchor_rewards(1, 569999989861552);
        // Check the sum of all anchor block rewards at block at year 2.
        check_sum_of_anchor_rewards(2, 1079999981625694);
        // Check the sum of all anchor block rewards at block at year 3.
        check_sum_of_anchor_rewards(3, 1529999975292428);
        // Check the sum of all anchor block rewards at block at year 4.
        check_sum_of_anchor_rewards(4, 1919999970861747);
        // Check the sum of all anchor block rewards at block at year 5.
        check_sum_of_anchor_rewards(5, 2249999968333661);
        // Check the sum of all anchor block rewards at block at year 6.
        check_sum_of_anchor_rewards(6, 2519999967708149);
        // Check the sum of all anchor block rewards at block at year 7.
        check_sum_of_anchor_rewards(7, 2729999968985230);
        // Check the sum of all anchor block rewards at block at year 8.
        check_sum_of_anchor_rewards(8, 2879999972164900);
        // Check the sum of all anchor block rewards at block at year 9.
        check_sum_of_anchor_rewards(9, 2969999977247158);
        // Check the sum of all anchor block rewards at block at year 10.
        check_sum_of_anchor_rewards(10, 3029999973493558);
        // Check the sum of all anchor block rewards at block at year 11.
        check_sum_of_anchor_rewards(11, 3089999969739958);
        // Check the sum of all anchor block rewards at block at year 12.
        check_sum_of_anchor_rewards(12, 3149999965986358);
        // Check the sum of all anchor block rewards at block at year 13.
        check_sum_of_anchor_rewards(13, 3209999962232758);
        // Check the sum of all anchor block rewards at block at year 14.
        check_sum_of_anchor_rewards(14, 3269999958479158);
        // Check the sum of all anchor block rewards at block at year 15.
        check_sum_of_anchor_rewards(15, 3329999954725558);
    }

    #[test]
    fn test_block_reward() {
        let mut rng = TestRng::default();

        // Ensure that a block height of `TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap()` uses block reward V2.
        let time_since_last_block = rng.random_range(1..=V2_MAX_BLOCK_INTERVAL);
        let reward = block_reward::<TestnetV0>(
            TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap(),
            TestnetV0::STARTING_SUPPLY,
            TestnetV0::BLOCK_TIME,
            time_since_last_block,
            0,
            0,
        )
        .unwrap();
        let expected_reward = block_reward_v2(TestnetV0::STARTING_SUPPLY, time_since_last_block, 0, 0);
        assert_eq!(reward, expected_reward);

        for _ in 0..100 {
            // Check that the block reward is correct for the first consensus version.
            let consensus_v1_height = rng.random_range(0..TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap());
            let consensus_v1_reward = block_reward::<TestnetV0>(
                consensus_v1_height,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::BLOCK_TIME,
                0,
                0,
                0,
            )
            .unwrap();
            let expected_reward = block_reward_v1(TestnetV0::STARTING_SUPPLY, TestnetV0::BLOCK_TIME, 0, 0);
            assert_eq!(consensus_v1_reward, expected_reward);

            // Check that the block reward is correct for the second consensus version.
            let consensus_v2_height = rng.random_range(
                TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap()..TestnetV0::MAX_SUPPLY_LIMIT_HEIGHT,
            );
            let time_since_last_block = rng.random_range(1..=V2_MAX_BLOCK_INTERVAL);
            let consensus_v2_reward = block_reward::<TestnetV0>(
                consensus_v2_height,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::BLOCK_TIME,
                time_since_last_block,
                0,
                0,
            )
            .unwrap();
            let expected_reward = block_reward_v2(TestnetV0::STARTING_SUPPLY, time_since_last_block, 0, 0);
            assert_eq!(consensus_v2_reward, expected_reward);

            // Check that the block reward is 0 after the max supply limit height.
            let after_max_supply_limit_height = rng.random_range(TestnetV0::MAX_SUPPLY_LIMIT_HEIGHT..u32::MAX);
            let block_reward = block_reward::<TestnetV0>(
                after_max_supply_limit_height,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::BLOCK_TIME,
                time_since_last_block,
                0,
                0,
            )
            .unwrap();
            assert_eq!(block_reward, 0);
        }
    }

    #[test]
    fn test_block_reward_v1() {
        let reward = block_reward_v1(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME, 0, 0);
        assert_eq!(reward, EXPECTED_STAKING_REWARD);

        // Increasing the anchor time will increase the reward.
        let larger_reward = block_reward_v1(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME + 1, 0, 0);
        assert!(reward < larger_reward);

        // Decreasing the anchor time will decrease the reward.
        let smaller_reward = block_reward_v1(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME - 1, 0, 0);
        assert!(reward > smaller_reward);
    }

    #[test]
    fn test_block_reward_v2() {
        let reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME as i64, 0, 0);
        assert_eq!(reward, EXPECTED_STAKING_REWARD);

        // Increasing the anchor time will increase the reward.
        let larger_reward =
            block_reward_v2(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME as i64 + 1, 0, 0);
        assert!(reward < larger_reward);

        // Decreasing the anchor time will decrease the reward.
        let smaller_reward =
            block_reward_v2(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME as i64 - 1, 0, 0);
        assert!(reward > smaller_reward);

        // Increasing the block interval past `V2_MAX_BLOCK_INTERVAL` does not increase the reward.
        let max_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, V2_MAX_BLOCK_INTERVAL, 0, 0);
        assert_eq!(max_reward, EXPECTED_MAX_STAKING_REWARD);
        let equivalent_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, V2_MAX_BLOCK_INTERVAL + 1, 0, 0);
        assert_eq!(max_reward, equivalent_reward);

        // Test that there is a minimum block reward when the time since last block is 1 second.
        let min_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, 1, 0, 0);
        let equivalent_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, 0, 0, 0);
        assert_eq!(min_reward, equivalent_reward);
    }

    #[test]
    fn test_block_reward_v1_vs_v2() {
        let mut rng = TestRng::default();

        // Declare a tolerance for reward divergence between v1 and v2 due to truncation.
        const TOLERANCE: f64 = 0.001; // 0.1% tolerance

        // Expect that the v2 block reward is equivalent to the v1 block reward if the `CurrentNetwork::BLOCK_TIME` is fixed.
        let reward_v1 = block_reward_v1(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME, 0, 0);
        assert_eq!(reward_v1, EXPECTED_STAKING_REWARD);
        let reward_v2 = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, CurrentNetwork::BLOCK_TIME as i64, 0, 0);
        assert_eq!(reward_v1, reward_v2);

        // Decreasing the time since last block based on `CurrentNetwork::BLOCK_TIME` will proportionally reduce the v2 rewards.
        let shorter_time = CurrentNetwork::BLOCK_TIME / 2;
        let smaller_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, shorter_time as i64, 0, 0);
        let expected_reward = EXPECTED_STAKING_REWARD / 2;
        assert!((smaller_reward as f64 - expected_reward as f64).abs() / expected_reward as f64 <= TOLERANCE);

        // Increasing the time since last block based on `CurrentNetwork::BLOCK_TIME` will proportionally increase the v2 rewards (up to a certain cap).
        let longer_time = CurrentNetwork::BLOCK_TIME * 2;
        let larger_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, longer_time as i64, 0, 0);
        let expected_reward = EXPECTED_STAKING_REWARD * 2;
        assert!((larger_reward as f64 - expected_reward as f64).abs() / expected_reward as f64 <= TOLERANCE);

        for _ in 0..10 {
            // Randomly sample the time factor.
            let factor = rng.random_range(1..10);

            // Ensure that scaling the time elapsed down scales the reward down proportionally.
            let shorter_time = CurrentNetwork::BLOCK_TIME / factor;
            let time_factor: f64 = CurrentNetwork::BLOCK_TIME as f64 / shorter_time as f64;
            let smaller_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, shorter_time as i64, 0, 0);
            let expected_reward = (EXPECTED_STAKING_REWARD as f64 / time_factor) as u64;
            assert!((smaller_reward as f64 - expected_reward as f64).abs() / expected_reward as f64 <= TOLERANCE);

            // Ensure that scaling the time elapsed up scales the reward up proportionally (up to a certain cap).
            let longer_time = CurrentNetwork::BLOCK_TIME * factor;
            let time_factor: f64 = longer_time as f64 / CurrentNetwork::BLOCK_TIME as f64;
            let larger_reward = block_reward_v2(CurrentNetwork::STARTING_SUPPLY, longer_time as i64, 0, 0);
            let expected_reward = (EXPECTED_STAKING_REWARD as f64 * time_factor) as u64;
            match longer_time as i64 > V2_MAX_BLOCK_INTERVAL {
                true => assert_eq!(larger_reward, EXPECTED_MAX_STAKING_REWARD),
                false => {
                    assert!((larger_reward as f64 - expected_reward as f64).abs() / expected_reward as f64 <= TOLERANCE)
                }
            }
        }
    }

    #[test]
    fn test_coinbase_reward() {
        let mut rng = TestRng::default();

        // Ensure that a block height of `TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap()` uses coinbase reward V2.
        let block_timestamp = TestnetV0::GENESIS_TIMESTAMP.saturating_add(
            TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap().saturating_mul(TestnetV0::BLOCK_TIME as u32)
                as i64,
        );
        let reward = coinbase_reward::<TestnetV0>(
            TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap(),
            block_timestamp,
            TestnetV0::GENESIS_TIMESTAMP,
            TestnetV0::STARTING_SUPPLY,
            TestnetV0::REWARD_ANCHOR_TIME,
            TestnetV0::ANCHOR_HEIGHT,
            TestnetV0::BLOCK_TIME,
            1,
            0,
            1,
        )
        .unwrap();
        let expected_reward = coinbase_reward_v2(
            block_timestamp,
            TestnetV0::GENESIS_TIMESTAMP,
            TestnetV0::STARTING_SUPPLY,
            TestnetV0::REWARD_ANCHOR_TIME,
            1,
            0,
            1,
        )
        .unwrap();
        assert_eq!(reward, expected_reward);

        for _ in 0..100 {
            // Check that the block reward is correct for the first consensus version.
            let consensus_v1_height = rng.random_range(0..TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap());
            let block_timestamp = TestnetV0::GENESIS_TIMESTAMP
                .saturating_add(consensus_v1_height.saturating_mul(TestnetV0::BLOCK_TIME as u32) as i64);
            let consensus_v1_reward = coinbase_reward::<TestnetV0>(
                consensus_v1_height,
                block_timestamp,
                TestnetV0::GENESIS_TIMESTAMP,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::REWARD_ANCHOR_TIME,
                TestnetV0::ANCHOR_HEIGHT,
                TestnetV0::BLOCK_TIME,
                1,
                0,
                1,
            )
            .unwrap();
            let expected_reward = coinbase_reward_v1(
                consensus_v1_height,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::ANCHOR_HEIGHT,
                TestnetV0::BLOCK_TIME,
                1,
                0,
                1,
            )
            .unwrap();
            assert_eq!(consensus_v1_reward, expected_reward);

            // Check that the block reward is correct for the second consensus version.
            let consensus_v2_height = rng.random_range(
                TestnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V2).unwrap()..TestnetV0::MAX_SUPPLY_LIMIT_HEIGHT,
            );
            let block_timestamp = TestnetV0::GENESIS_TIMESTAMP
                .saturating_add(consensus_v2_height.saturating_mul(TestnetV0::BLOCK_TIME as u32) as i64);
            let consensus_v2_reward = coinbase_reward::<TestnetV0>(
                consensus_v2_height,
                block_timestamp,
                TestnetV0::GENESIS_TIMESTAMP,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::REWARD_ANCHOR_TIME,
                TestnetV0::ANCHOR_HEIGHT,
                TestnetV0::BLOCK_TIME,
                1,
                0,
                1,
            )
            .unwrap();
            let expected_reward = coinbase_reward_v2(
                block_timestamp,
                TestnetV0::GENESIS_TIMESTAMP,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::REWARD_ANCHOR_TIME,
                1,
                0,
                1,
            )
            .unwrap();
            assert_eq!(consensus_v2_reward, expected_reward);

            // Check that the coinbase reward is 0 after the max supply limit height.
            let after_max_supply_limit_height = rng.random_range(TestnetV0::MAX_SUPPLY_LIMIT_HEIGHT..u32::MAX);
            let coinbase_reward = coinbase_reward::<TestnetV0>(
                after_max_supply_limit_height,
                block_timestamp,
                TestnetV0::GENESIS_TIMESTAMP,
                TestnetV0::STARTING_SUPPLY,
                TestnetV0::REWARD_ANCHOR_TIME,
                TestnetV0::ANCHOR_HEIGHT,
                TestnetV0::BLOCK_TIME,
                1,
                0,
                1,
            )
            .unwrap();
            assert_eq!(coinbase_reward, 0);
        }
    }

    #[test]
    fn test_coinbase_reward_v1() {
        let coinbase_target: u64 = 10000;
        let combined_proof_target: u128 = coinbase_target as u128;

        let reward = coinbase_reward_v1(
            1,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            combined_proof_target,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(reward, EXPECTED_COINBASE_REWARD_AT_BLOCK_1);

        // Halving the combined proof target halves the reward.
        let smaller_reward = coinbase_reward_v1(
            1,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            combined_proof_target / 2,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(smaller_reward, reward / 2);

        // Halving the remaining coinbase target halves the reward.
        let smaller_reward = coinbase_reward_v1(
            1,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            combined_proof_target,
            coinbase_target / 2,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(smaller_reward, reward / 2);

        // Dramatically increasing the combined proof target greater than the remaining coinbase target will not increase the reward.
        let equivalent_reward = coinbase_reward_v1(
            1,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            u128::MAX,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(reward, equivalent_reward);

        // Decreasing the combined proof target to 0 will result in a reward of 0.
        let zero_reward = coinbase_reward_v1(
            1,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            0,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(zero_reward, 0);

        // Increasing the cumulative proof target beyond the coinbase target will result in a reward of 0.
        let zero_reward = coinbase_reward_v1(
            1,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            1,
            coinbase_target + 1,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(zero_reward, 0);
    }

    #[test]
    fn test_coinbase_reward_v2() {
        let coinbase_target: u64 = 10000;
        let combined_proof_target: u128 = coinbase_target as u128;

        let reward = coinbase_reward_v2(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            combined_proof_target,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(reward, EXPECTED_COINBASE_REWARD_AT_BLOCK_1);

        // Halving the combined proof target halves the reward.
        let smaller_reward = coinbase_reward_v2(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            combined_proof_target / 2,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(smaller_reward, reward / 2);

        // Halving the remaining coinbase target halves the reward.
        let smaller_reward = coinbase_reward_v2(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            combined_proof_target,
            coinbase_target / 2,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(smaller_reward, reward / 2);

        // Dramatically increasing the combined proof target greater than the remaining coinbase target will not increase the reward.
        let equivalent_reward = coinbase_reward_v2(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            u128::MAX,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(reward, equivalent_reward);

        // Decreasing the combined proof target to 0 will result in a reward of 0.
        let zero_reward = coinbase_reward_v2(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            0,
            0,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(zero_reward, 0);

        // Increasing the cumulative proof target beyond the coinbase target will result in a reward of 0.
        let zero_reward = coinbase_reward_v2(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            1,
            coinbase_target + 1,
            coinbase_target,
        )
        .unwrap();
        assert_eq!(zero_reward, 0);
    }

    #[test]
    fn test_coinbase_reward_v1_remaining_target() {
        let mut rng = TestRng::default();

        fn compute_coinbase_reward(
            combined_proof_target: u64,
            cumulative_proof_target: u64,
            coinbase_target: u64,
        ) -> u64 {
            coinbase_reward_v1(
                1,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::ANCHOR_HEIGHT,
                CurrentNetwork::BLOCK_TIME,
                combined_proof_target as u128,
                cumulative_proof_target,
                coinbase_target,
            )
            .unwrap()
        }

        // Sample the starting conditions.
        let coinbase_target: u64 = rng.random_range(1_000_000..1_000_000_000_000_000);
        let cumulative_proof_target = coinbase_target / 2;
        let combined_proof_target = coinbase_target / 4;
        let reward = compute_coinbase_reward(combined_proof_target, cumulative_proof_target, coinbase_target);

        for _ in 0..ITERATIONS {
            // Check that as long as the sum of the combined proof target and cumulative proof target is less than the coinbase target,
            // the reward remains the same.
            // Intuition: Staying below the coinbase target preserves the reward for the combined proof target.
            let equivalent_reward = compute_coinbase_reward(
                combined_proof_target,
                rng.random_range(0..(coinbase_target - combined_proof_target)),
                coinbase_target,
            );
            assert_eq!(reward, equivalent_reward);

            // Check that increasing the cumulative proof target to devalue the combined proof target will decrease the reward.
            // Intuition: Overflowing the coinbase target crowds out the combined proof target, leading to less reward for the combined proof target.
            let lower_reward = compute_coinbase_reward(
                combined_proof_target,
                rng.random_range((coinbase_target - combined_proof_target + 1)..coinbase_target),
                coinbase_target,
            );
            assert!(lower_reward < reward);

            // Check that increasing the combined proof target increases the reward.
            // Intuition: If a prover contributes more proof target, they should be rewarded more.
            let larger_reward = compute_coinbase_reward(
                rng.random_range(combined_proof_target + 1..u64::MAX),
                cumulative_proof_target,
                coinbase_target,
            );
            assert!(reward < larger_reward);
        }
    }

    #[test]
    fn test_coinbase_reward_v2_remaining_target() {
        let mut rng = TestRng::default();

        fn compute_coinbase_reward(
            combined_proof_target: u64,
            cumulative_proof_target: u64,
            coinbase_target: u64,
        ) -> u64 {
            coinbase_reward_v2(
                CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
                CurrentNetwork::GENESIS_TIMESTAMP,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                combined_proof_target as u128,
                cumulative_proof_target,
                coinbase_target,
            )
            .unwrap()
        }

        // Sample the starting conditions.
        let coinbase_target: u64 = rng.random_range(1_000_000..1_000_000_000_000_000);
        let cumulative_proof_target = coinbase_target / 2;
        let combined_proof_target = coinbase_target / 4;
        let reward = compute_coinbase_reward(combined_proof_target, cumulative_proof_target, coinbase_target);

        for _ in 0..ITERATIONS {
            // Check that as long as the sum of the combined proof target and cumulative proof target is less than the coinbase target,
            // the reward remains the same.
            // Intuition: Staying below the coinbase target preserves the reward for the combined proof target.
            let equivalent_reward = compute_coinbase_reward(
                combined_proof_target,
                rng.random_range(0..(coinbase_target - combined_proof_target)),
                coinbase_target,
            );
            assert_eq!(reward, equivalent_reward);

            // Check that increasing the cumulative proof target to devalue the combined proof target will decrease the reward.
            // Intuition: Overflowing the coinbase target crowds out the combined proof target, leading to less reward for the combined proof target.
            let lower_reward = compute_coinbase_reward(
                combined_proof_target,
                rng.random_range((coinbase_target - combined_proof_target + 1)..coinbase_target),
                coinbase_target,
            );
            assert!(lower_reward < reward);

            // Check that increasing the combined proof target increases the reward.
            // Intuition: If a prover contributes more proof target, they should be rewarded more.
            let larger_reward = compute_coinbase_reward(
                rng.random_range(combined_proof_target + 1..u64::MAX),
                cumulative_proof_target,
                coinbase_target,
            );
            assert!(reward < larger_reward);
        }
    }

    #[test]
    fn test_coinbase_reward_v1_up_to_year_10() {
        let block_height_at_year_10 = block_height_at_year(CurrentNetwork::BLOCK_TIME, 10);

        let mut block_height = 1;

        let mut previous_reward = coinbase_reward_v1(
            block_height,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            1,
            0,
            1,
        )
        .unwrap();

        block_height += 1;

        let mut total_reward = previous_reward;

        let coinbase_target = CurrentNetwork::ANCHOR_HEIGHT as u64;
        let mut cumulative_proof_target = 0;

        let mut hit_500m = false;
        let mut hit_1b = false;

        while block_height < block_height_at_year_10 {
            let reward = coinbase_reward_v1(
                block_height,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::ANCHOR_HEIGHT,
                CurrentNetwork::BLOCK_TIME,
                1,
                cumulative_proof_target,
                coinbase_target,
            )
            .unwrap();
            assert!(reward <= previous_reward);

            total_reward += reward;
            previous_reward = reward;
            block_height += 1;

            // Update the cumulative proof target.
            cumulative_proof_target = match cumulative_proof_target + 1 {
                cumulative_proof_target if cumulative_proof_target == coinbase_target => 0,
                cumulative_proof_target => cumulative_proof_target,
            };

            if !hit_500m && total_reward > 500_000_000_000_000 {
                println!("500M credits block height is {block_height}");
                assert_eq!(block_height, 5_786_964, "Update me if my parameters have changed");
                hit_500m = true;
            } else if !hit_1b && total_reward > 1_000_000_000_000_000 {
                println!("1B credits block height is {block_height}");
                assert_eq!(block_height, 13_328_683, "Update me if my parameters have changed");
                hit_1b = true;
            }
        }

        assert_eq!(total_reward, 1_514_999_979_651_171, "Update me if my parameters have changed");
    }

    #[test]
    fn test_coinbase_reward_v2_up_to_year_10() {
        let block_height_at_year_10 = timestamp_at_year(CurrentNetwork::GENESIS_TIMESTAMP, 10);

        let mut timestamp = CurrentNetwork::GENESIS_TIMESTAMP;

        let mut previous_reward = coinbase_reward_v2(
            CurrentNetwork::GENESIS_TIMESTAMP + CurrentNetwork::BLOCK_TIME as i64,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            1,
            0,
            1,
        )
        .unwrap();

        timestamp += CurrentNetwork::BLOCK_TIME as i64;

        let mut total_reward = previous_reward;

        let coinbase_target = CurrentNetwork::ANCHOR_HEIGHT as u64;
        let mut cumulative_proof_target = 0;

        let mut hit_500m = false;
        let mut hit_1b = false;

        while timestamp < block_height_at_year_10 {
            let reward = coinbase_reward_v2(
                timestamp,
                CurrentNetwork::GENESIS_TIMESTAMP,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                1,
                cumulative_proof_target,
                coinbase_target,
            )
            .unwrap();
            assert!(reward <= previous_reward);

            total_reward += reward;
            previous_reward = reward;
            timestamp += CurrentNetwork::BLOCK_TIME as i64;

            // Update the cumulative proof target.
            cumulative_proof_target = match cumulative_proof_target + 1 {
                cumulative_proof_target if cumulative_proof_target == coinbase_target => 0,
                cumulative_proof_target => cumulative_proof_target,
            };

            if !hit_500m && total_reward > 500_000_000_000_000 {
                println!("500M credits block timestamp is {timestamp}");
                assert_eq!(timestamp, 1783331630, "Update me if my parameters have changed");
                hit_500m = true;
            } else if !hit_1b && total_reward > 1_000_000_000_000_000 {
                println!("1B credits block timestamp is {timestamp}");
                assert_eq!(timestamp, 1858748810, "Update me if my parameters have changed");
                hit_1b = true;
            }
        }

        assert_eq!(total_reward, 1_515_000_074_780_540, "Update me if my parameters have changed");
    }

    #[test]
    fn test_coinbase_reward_v1_after_year_10() {
        let mut rng = TestRng::default();

        let block_height_at_year_10 = block_height_at_year(CurrentNetwork::BLOCK_TIME, 10);

        // Check that the block at year 10 has a reward of 19.
        let reward = coinbase_reward_v1(
            block_height_at_year_10,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::ANCHOR_HEIGHT,
            CurrentNetwork::BLOCK_TIME,
            1,
            0,
            1,
        )
        .unwrap();
        assert_eq!(reward, 19_025_874);

        // Check that the subsequent blocks have an anchor reward of 19 and reward less than or equal to 19.
        for _ in 0..ITERATIONS {
            let block_height: u32 = rng.random_range(block_height_at_year_10..block_height_at_year_10 * 10);
            let coinbase_target = rng.random_range(1_000_000..1_000_000_000_000_000);
            let cumulative_proof_target = rng.random_range(0..coinbase_target);
            let combined_proof_target = rng.random_range(0..coinbase_target as u128);

            let anchor_reward = anchor_block_reward_at_height(
                block_height,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::ANCHOR_HEIGHT,
                CurrentNetwork::BLOCK_TIME,
            );
            assert_eq!(anchor_reward, 19_025_874);

            let reward = coinbase_reward_v1(
                block_height,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::ANCHOR_HEIGHT,
                CurrentNetwork::BLOCK_TIME,
                combined_proof_target,
                cumulative_proof_target,
                coinbase_target,
            )
            .unwrap();
            assert!(reward <= 19_025_874);
        }
    }

    #[test]
    fn test_coinbase_reward_v2_after_year_10() {
        let mut rng = TestRng::default();

        let timestamp_at_year_10 = timestamp_at_year(CurrentNetwork::GENESIS_TIMESTAMP, 10);

        // Check that the block at year 10 has a reward of 19.
        let reward = coinbase_reward_v2(
            timestamp_at_year_10,
            CurrentNetwork::GENESIS_TIMESTAMP,
            CurrentNetwork::STARTING_SUPPLY,
            CurrentNetwork::REWARD_ANCHOR_TIME,
            1,
            0,
            1,
        )
        .unwrap();
        assert_eq!(reward, 19_025_874);

        // Check that the subsequent blocks have an anchor reward of 19 and reward less than or equal to 19.
        for _ in 0..ITERATIONS {
            let timestamp: i64 = rng.random_range(timestamp_at_year_10..timestamp_at_year_10 * 10);
            let coinbase_target = rng.random_range(1_000_000..1_000_000_000_000_000);
            let cumulative_proof_target = rng.random_range(0..coinbase_target);
            let combined_proof_target = rng.random_range(0..coinbase_target as u128);

            let anchor_reward = anchor_block_reward_at_timestamp(
                timestamp,
                CurrentNetwork::GENESIS_TIMESTAMP,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::REWARD_ANCHOR_TIME,
            );
            assert_eq!(anchor_reward, 19_025_874);

            let reward = coinbase_reward_v2(
                timestamp,
                CurrentNetwork::GENESIS_TIMESTAMP,
                CurrentNetwork::STARTING_SUPPLY,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                combined_proof_target,
                cumulative_proof_target,
                coinbase_target,
            )
            .unwrap();
            assert!(reward <= 19_025_874);
        }
    }

    fn check_total_supply_cap<N: Network>() {
        const AVG_BLOCK_TIME: i64 = 3;

        let blocks_per_year = block_height_at_year(AVG_BLOCK_TIME as u16, 1);

        // The tracking state for the simluation
        let mut total_supply = N::STARTING_SUPPLY;
        let mut total_block_rewards = 0u64;
        let mut total_coinbase_rewards = 0u64;
        let mut block_height = 1u32;
        let mut latest_timetamp = 0;

        // Iterate until we reach 5 billion credits
        while total_supply < N::MAX_SUPPLY {
            // Calculate the block reward.
            let block_reward =
                block_reward::<N>(block_height, N::STARTING_SUPPLY, N::BLOCK_TIME, AVG_BLOCK_TIME, 0, 0).unwrap();

            // Calculate the coinbase reward.
            let timestamp = N::GENESIS_TIMESTAMP + (block_height as i64 * AVG_BLOCK_TIME);
            let coinbase_reward = coinbase_reward::<N>(
                block_height,
                timestamp,
                N::GENESIS_TIMESTAMP,
                N::STARTING_SUPPLY,
                N::REWARD_ANCHOR_TIME,
                N::ANCHOR_HEIGHT,
                N::BLOCK_TIME,
                1,
                0,
                1,
            )
            .unwrap();

            // Calculate the average expected coinbase reward per block based on the retargeting interval.
            // This is the upper bound, because we consider hitting 50% of the coinbase target eligible for retargeting.
            let avg_coinbase_reward_per_block = coinbase_reward * AVG_BLOCK_TIME as u64 / N::REWARD_ANCHOR_TIME as u64;

            // Update the trackers.
            block_height += 1;
            total_block_rewards += block_reward;
            total_coinbase_rewards += avg_coinbase_reward_per_block;
            total_supply += block_reward + avg_coinbase_reward_per_block;
            latest_timetamp = timestamp;
        }

        println!(
            "At block height {block_height} (year {}, timestamp: {latest_timetamp}), total block rewards is {total_block_rewards}, total coinbase rewards is {total_coinbase_rewards}, total supply is {total_supply} credits",
            block_height / blocks_per_year
        );

        // Check that block height matches the expected max supply limit height.
        assert_eq!(block_height, N::MAX_SUPPLY_LIMIT_HEIGHT);
        assert_eq!(N::MAX_SUPPLY_LIMIT_HEIGHT, 263_527_685);
    }

    #[test]
    fn test_total_supply_cap() {
        check_total_supply_cap::<CanaryV0>();
        check_total_supply_cap::<TestnetV0>();
        check_total_supply_cap::<MainnetV0>();
    }

    #[test]
    fn test_targets() {
        let mut rng = TestRng::default();

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;

        fn test_new_targets(rng: &mut TestRng, minimum_coinbase_target: u64) {
            let previous_coinbase_target: u64 = rng.random_range(minimum_coinbase_target..u64::MAX);
            let previous_prover_target = proof_target(
                previous_coinbase_target,
                CurrentNetwork::GENESIS_PROOF_TARGET,
                CurrentNetwork::MAX_SOLUTIONS_AS_POWER_OF_TWO,
            );

            let previous_timestamp = rng.random();

            // Targets stay the same when the drift is as expected.
            let next_timestamp = previous_timestamp + CurrentNetwork::REWARD_ANCHOR_TIME as i64;
            let new_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();
            let new_prover_target = proof_target(
                new_coinbase_target,
                CurrentNetwork::GENESIS_PROOF_TARGET,
                CurrentNetwork::MAX_SOLUTIONS_AS_POWER_OF_TWO,
            );
            assert_eq!(new_coinbase_target, previous_coinbase_target);
            assert_eq!(new_prover_target, previous_prover_target);

            // Targets decrease (easier) when the drift is greater than expected.
            let new_timestamp = previous_timestamp + 2 * CurrentNetwork::REWARD_ANCHOR_TIME as i64;
            let new_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                new_timestamp,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();
            let new_prover_target = proof_target(
                new_coinbase_target,
                CurrentNetwork::GENESIS_PROOF_TARGET,
                CurrentNetwork::MAX_SOLUTIONS_AS_POWER_OF_TWO,
            );
            assert!(new_coinbase_target < previous_coinbase_target);
            assert!(new_prover_target < previous_prover_target);

            // Targets increase (harder) when the drift is less than expected.
            let next_timestamp = previous_timestamp + (CurrentNetwork::REWARD_ANCHOR_TIME / 2) as i64;
            let new_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();
            let new_prover_target = proof_target(
                new_coinbase_target,
                CurrentNetwork::GENESIS_PROOF_TARGET,
                CurrentNetwork::MAX_SOLUTIONS_AS_POWER_OF_TWO,
            );

            assert!(new_coinbase_target > previous_coinbase_target);
            assert!(new_prover_target > previous_prover_target);
        }

        for _ in 0..ITERATIONS {
            test_new_targets(&mut rng, minimum_coinbase_target);
        }
    }

    #[test]
    fn test_target_halving() {
        let mut rng = TestRng::default();

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;

        for _ in 0..ITERATIONS {
            let previous_coinbase_target: u64 = rng.random_range(minimum_coinbase_target..u64::MAX);
            let previous_timestamp = rng.random();

            let half_life = CurrentNetwork::NUM_BLOCKS_PER_EPOCH
                .saturating_div(2)
                .saturating_mul(CurrentNetwork::REWARD_ANCHOR_TIME as u32) as i64;

            // New coinbase target is greater than half if the drift equals the half life.
            let next_timestamp = previous_timestamp + half_life;
            let next_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();

            assert!(next_coinbase_target > previous_coinbase_target / 2);

            // New coinbase target is halved if the drift is 1 anchor height past the half life.
            let next_timestamp = previous_timestamp + half_life + CurrentNetwork::REWARD_ANCHOR_TIME as i64;
            let next_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();

            assert_eq!(next_coinbase_target, previous_coinbase_target / 2);

            // New coinbase target is less than half if the drift is more than 1 anchor height past the half life.
            let next_timestamp = previous_timestamp + half_life + 2 * CurrentNetwork::REWARD_ANCHOR_TIME as i64;
            let next_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();

            assert!(next_coinbase_target < previous_coinbase_target / 2);
        }
    }

    #[test]
    fn test_target_doubling() {
        let mut rng = TestRng::default();

        // The custom block height drift that is faster than the anchor time.
        const ANCHOR_TIME_DELTA: i64 = 15;
        // The expected number of blocks before the coinbase target is doubled.
        const EXPECTED_NUM_BLOCKS_TO_DOUBLE: u32 = 451;

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;

        let initial_coinbase_target: u64 = rng.random_range(minimum_coinbase_target..u64::MAX / 2);
        let initial_timestamp: i64 = rng.random();

        let mut previous_coinbase_target: u64 = initial_coinbase_target;
        let mut previous_timestamp = initial_timestamp;
        let mut num_blocks = 0;

        while previous_coinbase_target < initial_coinbase_target * 2 {
            // Targets increase (harder) when the timestamp is less than expected.
            let next_timestamp = previous_timestamp + ANCHOR_TIME_DELTA;
            let next_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                CurrentNetwork::REWARD_ANCHOR_TIME,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();

            assert!(next_coinbase_target > previous_coinbase_target);

            previous_coinbase_target = next_coinbase_target;
            previous_timestamp = next_timestamp;
            num_blocks += 1;
        }

        let seconds = previous_timestamp - initial_timestamp;
        println!(
            "For drifts of {ANCHOR_TIME_DELTA} seconds and epochs of {} blocks, doubling the coinbase target took {num_blocks} blocks. ({seconds} seconds)",
            CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
        );

        assert_eq!(EXPECTED_NUM_BLOCKS_TO_DOUBLE, num_blocks);
    }

    #[test]
    fn test_to_next_targets_meets_threshold() {
        let mut rng = TestRng::default();

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;

        for _ in 0..ITERATIONS {
            // Sample the initial values.
            let latest_coinbase_target = rng.random_range(minimum_coinbase_target..u64::MAX / 2);
            let threshold = latest_coinbase_target as u128 / 2;
            let last_coinbase_target = rng.random_range(minimum_coinbase_target..latest_coinbase_target);
            let last_coinbase_timestamp = rng.random_range(0..i64::MAX / 2);
            let next_timestamp = last_coinbase_timestamp + 100;
            let latest_cumulative_weight = rng.random_range(0..u128::MAX / 2);

            // Sample a cumulative proof target and combined proof target pair that meets the threshold.
            let latest_cumulative_proof_target = rng.random_range(0..threshold);
            let combined_proof_target =
                rng.random_range(threshold.saturating_sub(latest_cumulative_proof_target)..u128::MAX);

            assert!(latest_cumulative_proof_target.saturating_add(combined_proof_target) >= threshold);

            // Calculate the next targets.
            let (
                _,
                _,
                next_cumulative_proof_target,
                next_cumulative_weight,
                next_last_coinbase_target,
                next_last_coinbase_timestamp,
            ) = to_next_targets::<CurrentNetwork>(
                ConsensusVersion::V1,
                latest_cumulative_proof_target,
                combined_proof_target,
                latest_coinbase_target,
                latest_cumulative_weight,
                last_coinbase_target,
                last_coinbase_timestamp,
                next_timestamp,
            )
            .unwrap();

            // Check that meeting the target threshold does the following:
            // 1. Resets the next_cumulative_proof_target.
            // 2. Updates the last_coinbase_target.
            // 3. Updates the last_coinbase_timestamp.
            assert_eq!(next_cumulative_proof_target, 0);
            assert_ne!(next_last_coinbase_target, last_coinbase_target);
            assert_eq!(next_last_coinbase_timestamp, next_timestamp);

            // Check that the cumulative_weight is updated correctly.
            assert_eq!(next_cumulative_weight, latest_cumulative_weight.saturating_add(combined_proof_target));
        }
    }

    #[test]
    fn test_to_next_targets_does_not_meet_threshold() {
        let mut rng = TestRng::default();

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;

        for _ in 0..ITERATIONS {
            // Sample the initial values.
            let latest_coinbase_target = rng.random_range(minimum_coinbase_target..u64::MAX / 2);
            let threshold = latest_coinbase_target as u128 / 2;
            let last_coinbase_target = rng.random_range(minimum_coinbase_target..latest_coinbase_target);
            let last_coinbase_timestamp = rng.random_range(0..i64::MAX / 2);
            let next_timestamp = last_coinbase_timestamp + 100;
            let latest_cumulative_weight = rng.random_range(0..u128::MAX / 2);

            // Sample a cumulative proof target and combined proof target pair that meets the threshold.
            let latest_cumulative_proof_target = rng.random_range(0..threshold);
            let combined_proof_target = rng.random_range(0..threshold.saturating_sub(latest_cumulative_proof_target));

            assert!(latest_cumulative_proof_target.saturating_add(combined_proof_target) < threshold);

            // Calculate the next targets.
            let (
                _,
                _,
                next_cumulative_proof_target,
                next_cumulative_weight,
                next_last_coinbase_target,
                next_last_coinbase_timestamp,
            ) = to_next_targets::<CurrentNetwork>(
                ConsensusVersion::V1,
                latest_cumulative_proof_target,
                combined_proof_target,
                latest_coinbase_target,
                latest_cumulative_weight,
                last_coinbase_target,
                last_coinbase_timestamp,
                next_timestamp,
            )
            .unwrap();

            // Check that missing the target threshold does the following:
            // 1. Does not reset the next_cumulative_proof_target.
            // 2. Does not update the last_coinbase_target.
            // 3. Does not update the last_coinbase_timestamp.
            assert_eq!(next_cumulative_proof_target, latest_cumulative_proof_target + combined_proof_target);
            assert_eq!(next_last_coinbase_target, last_coinbase_target);
            assert_eq!(next_last_coinbase_timestamp, last_coinbase_timestamp);

            // Check that the cumulative_weight is updated correctly.
            assert_eq!(next_cumulative_weight, latest_cumulative_weight.saturating_add(combined_proof_target));
        }
    }

    #[test]
    fn test_to_next_targets_v15_anchor_time() {
        // With V15, anchor_time = 35 instead of 25.
        // Verify that calling to_next_targets with V15 produces a different
        // coinbase target than V1 when timestamps cause retargeting.
        let last_coinbase_target = CurrentNetwork::GENESIS_COINBASE_TARGET;
        let last_coinbase_timestamp = 0i64;
        let next_timestamp = 32i64; // 32 seconds — between 25s (V1 anchor time) and 35s (V15 anchor time)

        let (coinbase_target_v1, _, _, _, _, _) = to_next_targets::<CurrentNetwork>(
            ConsensusVersion::V1,
            0,
            0,
            last_coinbase_target,
            0,
            last_coinbase_target,
            last_coinbase_timestamp,
            next_timestamp,
        )
        .unwrap();

        let (coinbase_target_v15, _, _, _, _, _) = to_next_targets::<CurrentNetwork>(
            ConsensusVersion::V15,
            0,
            0,
            last_coinbase_target,
            0,
            last_coinbase_target,
            last_coinbase_timestamp,
            next_timestamp,
        )
        .unwrap();

        assert_ne!(
            coinbase_target_v1, coinbase_target_v15,
            "V15 should use anchor_time=35 and produce a different coinbase target than V1 (anchor_time=25)"
        );
    }

    #[test]
    fn test_target_anchor_time_sensitivity() {
        // Covers three timestamp diff regimes to show how anchor_time governs retargeting direction.
        // diff < anchor_time → blocks are fast → target increases (harder).
        // diff > anchor_time → blocks are slow → target decreases (easier).
        //
        // FAST  (diff=10):  10 < 25 < 35  → target increases for both V1 and V15.
        // MID   (diff=32):  25 < 32 < 35  → target decreases for V1, increases for V15.
        // SLOW  (diff=50):  25 < 35 < 50  → target decreases for both V1 and V15.
        const DIFF_FAST: i64 = 10;
        const DIFF_MID: i64 = 32;
        const DIFF_SLOW: i64 = 50;

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;
        let mut rng = TestRng::default();
        let previous_coinbase_target: u64 = rng.random_range(minimum_coinbase_target..u64::MAX / 2);
        let previous_timestamp: i64 = rng.random();

        let anchor_time_v1 = CurrentNetwork::REWARD_ANCHOR_TIME;
        let anchor_time_v15 = CurrentNetwork::ANCHOR_TIMES[1].1;

        // Confirm the regimes are set up correctly relative to each anchor time.
        assert!(DIFF_FAST < anchor_time_v1 as i64 && DIFF_FAST < anchor_time_v15 as i64);
        assert!(DIFF_MID > anchor_time_v1 as i64 && DIFF_MID < anchor_time_v15 as i64);
        assert!(DIFF_SLOW > anchor_time_v1 as i64 && DIFF_SLOW > anchor_time_v15 as i64);

        let call = |diff: i64, anchor_time: u16| {
            coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                previous_timestamp + diff,
                anchor_time,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap()
        };

        // FAST (diff=10): both anchor times see fast blocks → both targets increase.
        // V15 increases more: 10/35 is a smaller ratio than 10/25.
        let fast_v1 = call(DIFF_FAST, anchor_time_v1);
        let fast_v15 = call(DIFF_FAST, anchor_time_v15);
        assert!(fast_v1 > previous_coinbase_target);
        assert!(fast_v15 > previous_coinbase_target);
        assert!(fast_v15 > fast_v1);

        // MID (diff=32): only V15 still sees fast blocks → V1 decreases, V15 increases.
        let mid_v1 = call(DIFF_MID, anchor_time_v1);
        let mid_v15 = call(DIFF_MID, anchor_time_v15);
        assert!(mid_v1 < previous_coinbase_target);
        assert!(mid_v15 > previous_coinbase_target);
        assert!(mid_v15 > mid_v1);

        // SLOW (diff=50): both anchor times see slow blocks → both targets decrease.
        // V15 decreases less: 50/35 is a smaller ratio than 50/25.
        let slow_v1 = call(DIFF_SLOW, anchor_time_v1);
        let slow_v15 = call(DIFF_SLOW, anchor_time_v15);
        assert!(slow_v1 < previous_coinbase_target);
        assert!(slow_v15 < previous_coinbase_target);
        assert!(slow_v15 > slow_v1);
    }

    #[test]
    fn test_target_halving_changes_with_anchor_time() {
        let mut rng = TestRng::default();

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;
        let previous_coinbase_target: u64 = rng.random_range(minimum_coinbase_target..u64::MAX);
        let previous_timestamp: i64 = rng.random();

        let anchor_time_v1 = CurrentNetwork::REWARD_ANCHOR_TIME;
        let anchor_time_v15 = CurrentNetwork::ANCHOR_TIMES[1].1;

        // Compute the half life for each anchor time.
        let half_life_v1 =
            CurrentNetwork::NUM_BLOCKS_PER_EPOCH.saturating_div(2).saturating_mul(anchor_time_v1 as u32) as i64;
        let half_life_v15 =
            CurrentNetwork::NUM_BLOCKS_PER_EPOCH.saturating_div(2).saturating_mul(anchor_time_v15 as u32) as i64;

        // A larger anchor time means a longer half life.
        assert!(half_life_v15 > half_life_v1);

        // At the V1 halving point (half_life_v1 + anchor_time_v1), anchor_time=25 halves the target.
        let next_timestamp = previous_timestamp + half_life_v1 + anchor_time_v1 as i64;
        let target_v1_at_v1_halving = coinbase_target(
            previous_coinbase_target,
            previous_timestamp,
            next_timestamp,
            anchor_time_v1,
            CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
            CurrentNetwork::GENESIS_COINBASE_TARGET,
        )
        .unwrap();
        assert_eq!(target_v1_at_v1_halving, previous_coinbase_target / 2);

        // At the same timestamp, anchor_time=35 has not yet reached its own halving point,
        // so the target remains above half.
        let target_v15_at_v1_halving = coinbase_target(
            previous_coinbase_target,
            previous_timestamp,
            next_timestamp,
            anchor_time_v15,
            CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
            CurrentNetwork::GENESIS_COINBASE_TARGET,
        )
        .unwrap();
        assert!(target_v15_at_v1_halving > previous_coinbase_target / 2);

        // At the V15 halving point (half_life_v15 + anchor_time_v15), anchor_time=35 halves the target.
        let next_timestamp_v15 = previous_timestamp + half_life_v15 + anchor_time_v15 as i64;
        let target_v15_at_v15_halving = coinbase_target(
            previous_coinbase_target,
            previous_timestamp,
            next_timestamp_v15,
            anchor_time_v15,
            CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
            CurrentNetwork::GENESIS_COINBASE_TARGET,
        )
        .unwrap();
        assert_eq!(target_v15_at_v15_halving, previous_coinbase_target / 2);
    }

    #[test]
    fn test_target_doubling_changes_with_anchor_time() {
        let mut rng = TestRng::default();

        // The custom block height drift that is faster than both anchor times.
        const ANCHOR_TIME_DELTA: i64 = 15;

        let minimum_coinbase_target: u64 = 2u64.pow(10) - 1;
        let initial_coinbase_target: u64 = rng.random_range(minimum_coinbase_target..u64::MAX / 2);
        let initial_timestamp: i64 = rng.random();

        let anchor_time_v1 = CurrentNetwork::REWARD_ANCHOR_TIME;
        let anchor_time_v15 = CurrentNetwork::ANCHOR_TIMES[1].1;

        // Count blocks to double with anchor_time=25 (V1).
        let mut previous_coinbase_target = initial_coinbase_target;
        let mut previous_timestamp = initial_timestamp;
        let mut num_blocks_v1 = 0u32;
        while previous_coinbase_target < initial_coinbase_target * 2 {
            let next_timestamp = previous_timestamp + ANCHOR_TIME_DELTA;
            previous_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                anchor_time_v1,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();
            previous_timestamp = next_timestamp;
            num_blocks_v1 += 1;
        }

        // Count blocks to double with anchor_time=35 (V15).
        let mut previous_coinbase_target = initial_coinbase_target;
        let mut previous_timestamp = initial_timestamp;
        let mut num_blocks_v15 = 0u32;
        while previous_coinbase_target < initial_coinbase_target * 2 {
            let next_timestamp = previous_timestamp + ANCHOR_TIME_DELTA;
            previous_coinbase_target = coinbase_target(
                previous_coinbase_target,
                previous_timestamp,
                next_timestamp,
                anchor_time_v15,
                CurrentNetwork::NUM_BLOCKS_PER_EPOCH,
                CurrentNetwork::GENESIS_COINBASE_TARGET,
            )
            .unwrap();
            previous_timestamp = next_timestamp;
            num_blocks_v15 += 1;
        }

        // A larger anchor time shrinks the drift-to-anchor ratio (15/35 < 15/25),
        // so less blocks are needed to double the target.
        assert!(num_blocks_v15 < num_blocks_v1);
    }
}
