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

/// The stake required to land one solution per epoch at various points in time for mainnet.
pub(super) const MAINNET_STAKE_REQUIREMENTS_PER_SOLUTION: [(i64, u64); 9] = [
    (1754006399i64, 100_000_000_000u64),   /* 2025-07-31 23:59:59 UTC */
    (1761955199i64, 250_000_000_000u64),   /* 2025-10-31 23:59:59 UTC */
    (1769903999i64, 500_000_000_000u64),   /* 2026-01-31 23:59:59 UTC */
    (1777593599i64, 750_000_000_000u64),   /* 2026-04-30 23:59:59 UTC */
    (1785542399i64, 1_000_000_000_000u64), /* 2026-07-31 23:59:59 UTC */
    (1793491199i64, 1_250_000_000_000u64), /* 2026-10-31 23:59:59 UTC */
    (1801439999i64, 1_500_000_000_000u64), /* 2027-01-31 23:59:59 UTC */
    (1809129599i64, 2_000_000_000_000u64), /* 2027-04-30 23:59:59 UTC */
    (1817078399i64, 2_500_000_000_000u64), /* 2027-07-31 23:59:59 UTC */
];

/// The stake required to land one solution per epoch at various points in time for canary and testnet.
pub(super) const CANARY_AND_TESTNET_STAKE_REQUIREMENTS_PER_SOLUTION: [(i64, u64); 9] = [
    (1754006399i64, 1_000_000_000u64),  /* 2025-07-31 23:59:59 UTC */
    (1761955199i64, 2_500_000_000u64),  /* 2025-10-31 23:59:59 UTC */
    (1769903999i64, 5_000_000_000u64),  /* 2026-01-31 23:59:59 UTC */
    (1777593599i64, 7_500_000_000u64),  /* 2026-04-30 23:59:59 UTC */
    (1785542399i64, 10_000_000_000u64), /* 2026-07-31 23:59:59 UTC */
    (1793491199i64, 12_500_000_000u64), /* 2026-10-31 23:59:59 UTC */
    (1801439999i64, 15_000_000_000u64), /* 2027-01-31 23:59:59 UTC */
    (1809129599i64, 20_000_000_000u64), /* 2027-04-30 23:59:59 UTC */
    (1817078399i64, 25_000_000_000u64), /* 2027-07-31 23:59:59 UTC */
];

/// The stake required to land one solution per epoch at various points in time.
///
/// Each entry represents a threshold where, starting from the given timestamp,
/// a prover must have at least the specified amount of stake (in microcredits) to land one solution.
///
/// A prover with `n * stake` may land up to `n` solutions per epoch.
///
/// Format: `(timestamp, stake_required_per_solution)`
pub fn stake_requirements_per_solution<N: Network>() -> &'static [(i64, u64)] {
    match N::ID {
        console::network::MainnetV0::ID => &MAINNET_STAKE_REQUIREMENTS_PER_SOLUTION,
        console::network::TestnetV0::ID | console::network::CanaryV0::ID => {
            &CANARY_AND_TESTNET_STAKE_REQUIREMENTS_PER_SOLUTION
        }
        _ => &MAINNET_STAKE_REQUIREMENTS_PER_SOLUTION,
    }
}

/// Returns the maximum number of allowed solutions per epoch based on the provided stake and timestamp.
pub fn maximum_allowed_solutions_per_epoch<N: Network>(prover_stake: u64, current_time: i64) -> u64 {
    let stake_requirements = stake_requirements_per_solution::<N>();

    // If the block height is earlier than the starting enforcement, do not restrict the maximum number of solutions per epoch.
    if current_time < stake_requirements.first().map(|(t, _)| *t).unwrap_or(i64::MAX) {
        return u64::MAX;
    }

    // Find the minimum stake required for one solution per epoch.
    let minimum_stake_per_solution_per_epoch = match stake_requirements.binary_search_by_key(&current_time, |(t, _)| *t)
    {
        // If a stake limit was found at this height, return it.
        Ok(index) => stake_requirements[index].1,
        // If the specified height was not found, determine which limit to return.
        Err(index) => stake_requirements[index.saturating_sub(1)].1,
    };

    // Return the number of allowed solutions per epoch.
    prover_stake.saturating_div(minimum_stake_per_solution_per_epoch)
}

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Returns the number of remaining solutions a prover can submit in the current epoch,
    /// using the provided ledger timestamp instead of re-reading the current block.
    pub(crate) fn num_remaining_solutions_at_timestamp(
        &self,
        prover_address: &Address<N>,
        additional_solutions_in_block: u64,
        current_time: i64,
    ) -> u64 {
        // Fetch the prover's stake.
        let prover_stake = self.get_bonded_amount(prover_address).unwrap_or(0);

        // Determine the maximum number of solutions allowed based on this prover's stake.
        let maximum_allowed_solutions = maximum_allowed_solutions_per_epoch::<N>(prover_stake, current_time);

        // Fetch the number of solutions the prover has earned rewards for in the current epoch.
        let prover_num_solutions_in_epoch = *self.epoch_provers_cache.read().get(prover_address).unwrap_or(&0);

        // Calculate the total number of solutions the prover has submitted in the current epoch including the current block.
        let num_solutions = (prover_num_solutions_in_epoch as u64).saturating_add(additional_solutions_in_block);

        // Return the number of remaining solutions.
        maximum_allowed_solutions.saturating_sub(num_solutions)
    }

    /// Returns the number of remaining solutions a prover can submit in the current epoch.
    pub fn num_remaining_solutions(&self, prover_address: &Address<N>, additional_solutions_in_block: u64) -> u64 {
        self.num_remaining_solutions_at_timestamp(
            prover_address,
            additional_solutions_in_block,
            self.latest_timestamp(),
        )
    }

    /// Returns `true` if the given prover address has reached their solution limit for the current epoch,
    /// using the provided ledger timestamp instead of re-reading the current block.
    pub(crate) fn is_solution_limit_reached_at_timestamp(
        &self,
        prover_address: &Address<N>,
        additional_solutions_in_block: u64,
        current_time: i64,
    ) -> bool {
        self.num_remaining_solutions_at_timestamp(prover_address, additional_solutions_in_block, current_time) == 0
    }

    /// Returns `true` if the given prover address has reached their solution limit for the current epoch.
    pub fn is_solution_limit_reached(&self, prover_address: &Address<N>, additional_solutions_in_block: u64) -> bool {
        self.is_solution_limit_reached_at_timestamp(
            prover_address,
            additional_solutions_in_block,
            self.latest_timestamp(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{CurrentLedger, LedgerType};
    use std::{thread, time::Duration};

    type CurrentNetwork = console::network::MainnetV0;

    const ITERATIONS: u64 = 100;

    #[test]
    fn test_solution_limit_per_epoch() {
        let mut rng = TestRng::default();
        let stake_requirements = stake_requirements_per_solution::<CurrentNetwork>();

        for _ in 0..ITERATIONS {
            for window in stake_requirements.windows(2) {
                let (prev_time, stake_per_solution) = window[0];
                let (next_time, _) = window[1];

                // Choose a time strictly between the steps.
                let timestamp = rng.random_range(prev_time..next_time);
                // Generate a random prover stake.
                let prover_stake: u64 = rng.random();
                let expected_num_solutions = prover_stake / stake_per_solution;

                assert_eq!(
                    maximum_allowed_solutions_per_epoch::<CurrentNetwork>(prover_stake, timestamp),
                    expected_num_solutions,
                );
            }
        }
    }

    #[test]
    fn test_solution_limit_before_enforcement() {
        let mut rng = TestRng::default();
        let stake_requirements = stake_requirements_per_solution::<CurrentNetwork>();

        // Fetch the first timestamp from the table.
        let first_timestamp = stake_requirements.first().unwrap().0;
        let time_before_first = first_timestamp - 1;

        // Check that before enforcement, the number of solutions is unrestricted even without prover stake.
        let prover_stake = 0;
        assert_eq!(maximum_allowed_solutions_per_epoch::<CurrentNetwork>(prover_stake, time_before_first), u64::MAX);

        // Check that before enforcement, the number of solutions is unrestricted for any prover stake.
        for _ in 0..ITERATIONS {
            assert_eq!(
                maximum_allowed_solutions_per_epoch::<CurrentNetwork>(
                    rng.random(),
                    rng.random_range(0..time_before_first)
                ),
                u64::MAX
            );
        }
    }

    #[test]
    fn test_solution_limit_after_final_timestamp() {
        let mut rng = TestRng::default();
        let stake_requirements = stake_requirements_per_solution::<CurrentNetwork>();
        let (last_timestamp, stake_per_solution) = *stake_requirements.last().unwrap();

        // Check that all timestamps after the last one are treated as the last one.
        for _ in 0..ITERATIONS {
            let prover_stake: u64 = rng.random();
            let time_after_last = rng.random_range(last_timestamp..i64::MAX);
            let expected_num_solutions = prover_stake / stake_per_solution;

            assert_eq!(
                maximum_allowed_solutions_per_epoch::<CurrentNetwork>(prover_stake, time_after_last),
                expected_num_solutions
            );
        }
    }

    #[test]
    fn test_solution_limit_exact_timestamps() {
        let mut rng = TestRng::default();
        let stake_requirements = stake_requirements_per_solution::<CurrentNetwork>();
        // Check that the maximum allowed solutions per epoch is correct for each timestamp in the table.
        for &(timestamp, stake_per_solution) in stake_requirements.iter() {
            let expected_num_solutions = rng.random_range(1..=100);
            let prover_stake = expected_num_solutions * stake_per_solution;

            assert_eq!(
                maximum_allowed_solutions_per_epoch::<CurrentNetwork>(prover_stake, timestamp),
                expected_num_solutions,
            );
        }
    }

    #[test]
    fn test_solution_limit_helper_avoids_current_block_reentry_with_pending_writer() {
        let rng = &mut TestRng::default();

        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let validator_address = Address::try_from(&private_key).unwrap();
        let store = ConsensusStore::<CurrentNetwork, LedgerType>::open(StorageMode::new_test(None)).unwrap();
        let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();
        let ledger = CurrentLedger::load(genesis, StorageMode::new_test(None)).unwrap();

        let next_block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![], rng).unwrap();
        let expected = ledger.num_remaining_solutions(&validator_address, 0);

        // Mimic check_next_block() holding a read guard while a writer queues behind it.
        let latest_block = ledger.current_block.read();
        let latest_timestamp = latest_block.timestamp();

        let ledger_clone = ledger.clone();
        let next_block_clone = next_block.clone();
        let writer = thread::spawn(move || ledger_clone.advance_to_next_block(&next_block_clone));

        thread::sleep(Duration::from_millis(50));
        assert!(!writer.is_finished(), "advance_to_next_block should be waiting on current_block.write()");

        let actual = ledger.num_remaining_solutions_at_timestamp(&validator_address, 0, latest_timestamp);
        assert_eq!(actual, expected);
        assert_eq!(ledger.is_solution_limit_reached_at_timestamp(&validator_address, 0, latest_timestamp), actual == 0);

        drop(latest_block);
        writer.join().unwrap().unwrap();
    }
}
