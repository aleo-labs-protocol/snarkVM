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

#![allow(clippy::redundant_closure)]

use console::{
    account::Address,
    network::Network,
    prelude::{cfg_into_iter, cfg_iter, cfg_reduce},
    program::{Identifier, Literal, Plaintext, Value},
    types::{Boolean, U8, U64},
};
use snarkvm_ledger_committee::Committee;

use anyhow::{Result, bail, ensure};
use indexmap::{IndexMap, indexmap};
use std::str::FromStr;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// Returns the committee given the committee map from finalize storage.
pub fn committee_and_delegated_maps_into_committee<N: Network>(
    starting_round: u64,
    committee_map: Vec<(Plaintext<N>, Value<N>)>,
    delegated_map: Vec<(Plaintext<N>, Value<N>)>,
) -> Result<Committee<N>> {
    // Prepare the identifiers.
    let is_open_identifier: Identifier<N> = Identifier::from_str("is_open")?;
    let commission_identifier: Identifier<N> = Identifier::from_str("commission")?;

    // Extract the committee members.
    let committee_members: IndexMap<Address<N>, (u64, bool, u8)> = committee_map
        .iter()
        .map(|(key, value)| {
            // Extract the address from the key.
            let address = match key {
                Plaintext::Literal(Literal::Address(address), _) => address,
                _ => bail!("Invalid committee key (missing address) - {key}"),
            };

            // Extract the committee state from the value.
            let (is_open, commission) = match value {
                Value::Plaintext(Plaintext::Struct(state, _)) => {
                    // Extract the is_open flag from the value.
                    let is_open = match state.get(&is_open_identifier) {
                        Some(Plaintext::Literal(Literal::Boolean(is_open), _)) => **is_open,
                        _ => bail!("Invalid committee state (missing boolean) - {value}"),
                    };
                    // Extract the commission from the value.
                    let commission = match state.get(&commission_identifier) {
                        Some(Plaintext::Literal(Literal::U8(commission), _)) => **commission,
                        _ => bail!("Invalid committee state (missing commission) - {value}"),
                    };
                    // Return the committee state.
                    (is_open, commission)
                }
                _ => bail!("Invalid committee value (missing struct) - {value}"),
            };

            // Extract the microcredits for the address from the delegated map.
            let Some(microcredits) = delegated_map.iter().find_map(|(delegated_key, delegated_value)| {
                // Retrieve the delegated address.
                let delegated_address = match delegated_key {
                    Plaintext::Literal(Literal::Address(address), _) => Some(address),
                    _ => None,
                };
                // Check if the address matches.
                match delegated_address == Some(address) {
                    // Extract the microcredits from the value.
                    true => match delegated_value {
                        Value::Plaintext(Plaintext::Literal(Literal::U64(microcredits), _)) => Some(**microcredits),
                        _ => None,
                    },
                    false => None,
                }
            }) else {
                bail!("Missing microcredits for committee member - {address}");
            };

            // Return the committee member.
            Ok((*address, (microcredits, is_open, commission)))
        })
        .collect::<Result<IndexMap<_, _>>>()?;

    // Return the committee.
    Committee::new(starting_round, committee_members)
}

/// Returns the stakers given the bonded map from finalize storage.
pub fn bonded_map_into_stakers<N: Network>(
    bonded_map: Vec<(Plaintext<N>, Value<N>)>,
) -> Result<IndexMap<Address<N>, (Address<N>, u64)>> {
    // Prepare the identifiers.
    let validator_identifier = Identifier::from_str("validator")?;
    let microcredits_identifier = Identifier::from_str("microcredits")?;

    // Convert the given key and value into a staker entry.
    let convert = |key, value| {
        // Extract the staker from the key.
        let address = match key {
            Plaintext::Literal(Literal::Address(address), _) => address,
            _ => bail!("Invalid bonded key (missing staker) - {key}"),
        };
        // Extract the bonded state from the value.
        match &value {
            Value::Plaintext(Plaintext::Struct(state, _)) => {
                // Extract the validator from the value.
                let validator = match state.get(&validator_identifier) {
                    Some(Plaintext::Literal(Literal::Address(validator), _)) => *validator,
                    _ => bail!("Invalid bonded state (missing validator) - {value}"),
                };
                // Extract the microcredits from the value.
                let microcredits = match state.get(&microcredits_identifier) {
                    Some(Plaintext::Literal(Literal::U64(microcredits), _)) => **microcredits,
                    _ => bail!("Invalid bonded state (missing microcredits) - {value}"),
                };
                // Return the bonded state.
                Ok((address, (validator, microcredits)))
            }
            _ => bail!("Invalid bonded value (missing struct) - {value}"),
        }
    };

    // Convert the bonded map into stakers.
    bonded_map.into_iter().map(|(key, value)| convert(key, value)).collect::<Result<IndexMap<_, _>>>()
}

/// Checks that the given committee from committee storage matches the given stakers.
pub fn ensure_stakers_matches<N: Network>(
    committee: &Committee<N>,
    stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
) -> Result<()> {
    // Construct the validator map.
    let validator_map: IndexMap<_, _> = cfg_reduce!(
        cfg_into_iter!(stakers)
            .map(|(_, (validator, microcredits))| {
                if committee.members().contains_key(validator) {
                    Some(indexmap! {*validator => *microcredits})
                } else {
                    None
                }
            })
            .flatten(),
        || IndexMap::new(),
        |mut acc, e| {
            for (validator, microcredits) in e {
                let entry: &mut u64 = acc.entry(validator).or_default();
                *entry = entry.saturating_add(microcredits);
            }
            acc
        }
    );

    // Compute the total microcredits.
    let total_microcredits =
        cfg_reduce!(cfg_iter!(validator_map).map(|(_, microcredits)| *microcredits), || 0u64, |a, b| {
            // Add the staker's microcredits to the total microcredits.
            a.saturating_add(b)
        });

    // Ensure the committee and committee map match.
    ensure!(committee.members().len() == validator_map.len(), "Committee and validator map length do not match");
    // Ensure the total microcredits match.
    ensure!(committee.total_stake() == total_microcredits, "Committee and validator map total stake do not match");

    // Iterate over the committee and ensure the committee and validators match.
    for (validator, (microcredits, _, _)) in committee.members() {
        let candidate_microcredits = validator_map.get(validator);
        ensure!(candidate_microcredits.is_some(), "A validator is missing in finalize storage");
        ensure!(
            *microcredits == *candidate_microcredits.unwrap(),
            "Committee contains an incorrect 'microcredits' amount from stakers"
        );
    }

    Ok(())
}

/// Returns the next committee, given the current committee and stakers.
pub fn to_next_committee<N: Network>(
    current_committee: &Committee<N>,
    next_round: u64,
    next_delegated: &IndexMap<Address<N>, u64>,
) -> Result<Committee<N>> {
    // Return the next committee.
    Committee::new(
        next_round,
        cfg_iter!(next_delegated)
            .flat_map(|(delegatee, microcredits)| {
                let Some((_, is_open, commission)) = current_committee.members().get(delegatee) else {
                    // Do nothing, as the delegatee is not part of the committee.
                    return None;
                };
                Some((*delegatee, (*microcredits, *is_open, *commission)))
            })
            .collect(),
    )
}

pub fn to_next_delegated<N: Network>(
    next_stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
) -> IndexMap<Address<N>, u64> {
    // Construct the delegated map.
    let delegated_map: IndexMap<Address<N>, u64> = cfg_reduce!(
        cfg_into_iter!(next_stakers).map(|(_, (delegatee, microcredits))| indexmap! {*delegatee => *microcredits}),
        || IndexMap::new(),
        |mut acc, e| {
            for (delegatee, microcredits) in e {
                let entry: &mut u64 = acc.entry(delegatee).or_default();
                *entry = entry.saturating_add(microcredits);
            }
            acc
        }
    );

    delegated_map
}

/// Returns the committee map, bonded map, and delegated map, given the committee and stakers.
pub fn to_next_committee_bonded_delegated_map<N: Network>(
    next_committee: &Committee<N>,
    next_stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
    next_delegated: &IndexMap<Address<N>, u64>,
) -> (Vec<(Plaintext<N>, Value<N>)>, Vec<(Plaintext<N>, Value<N>)>, Vec<(Plaintext<N>, Value<N>)>) {
    // Prepare the identifiers.
    let validator_identifier = Identifier::from_str("validator").expect("Failed to parse 'validator'");
    let microcredits_identifier = Identifier::from_str("microcredits").expect("Failed to parse 'microcredits'");
    let is_open_identifier = Identifier::from_str("is_open").expect("Failed to parse 'is_open'");
    let commission_identifier = Identifier::from_str("commission").expect("Failed to parse 'commission'");

    // Construct the committee map.
    let committee_map = cfg_iter!(next_committee.members())
        .map(|(validator, (_, is_open, commission))| {
            // Construct the committee state.
            let committee_state = indexmap! {
                is_open_identifier => Plaintext::from(Literal::Boolean(Boolean::new(*is_open))),
                commission_identifier => Plaintext::from(Literal::U8(U8::new(*commission))),
            };
            // Return the committee state.
            (
                Plaintext::from(Literal::Address(*validator)),
                Value::Plaintext(Plaintext::Struct(committee_state, Default::default())),
            )
        })
        .collect::<Vec<_>>();

    // Construct the bonded map.
    let bonded_map = cfg_iter!(next_stakers)
        .map(|(staker, (validator, microcredits))| {
            // Construct the bonded state.
            let bonded_state = indexmap! {
                validator_identifier => Plaintext::from(Literal::Address(*validator)),
                microcredits_identifier => Plaintext::from(Literal::U64(U64::new(*microcredits))),
            };
            // Return the bonded state.
            (
                Plaintext::from(Literal::Address(*staker)),
                Value::Plaintext(Plaintext::Struct(bonded_state, Default::default())),
            )
        })
        .collect::<Vec<_>>();

    // Construct the delegated map.
    let delegated_map = cfg_iter!(next_delegated)
        .map(|(delegatee, microcredits)| {
            (
                Plaintext::from(Literal::Address(*delegatee)),
                Value::Plaintext(Plaintext::Literal(Literal::U64(U64::new(*microcredits)), Default::default())),
            )
        })
        .collect::<Vec<_>>();

    (committee_map, bonded_map, delegated_map)
}

/// Returns the withdraw map, given the withdrawal addresses.
pub fn to_next_withdraw_map<N: Network>(
    withdrawal_addresses: &IndexMap<Address<N>, Address<N>>,
) -> Vec<(Plaintext<N>, Value<N>)> {
    cfg_iter!(withdrawal_addresses)
        .map(|(staker, withdraw_address)| {
            (
                Plaintext::from(Literal::Address(*staker)),
                Value::Plaintext(Plaintext::Literal(Literal::Address(*withdraw_address), Default::default())),
            )
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::vm::TestRng;
    use snarkvm_ledger_committee::{MIN_DELEGATOR_STAKE, MIN_VALIDATOR_STAKE};

    use rand::{CryptoRng, RngExt};

    /// Returns the stakers, given the map of `(validator, (microcredits, is_open, commission))` entries.
    /// This method simulates the existence of delegators for the members.
    pub(crate) fn to_stakers<N: Network, R: CryptoRng>(
        members: &IndexMap<Address<N>, (u64, bool, u8)>,
        rng: &mut R,
    ) -> IndexMap<Address<N>, (Address<N>, u64)> {
        members
            .into_iter()
            .flat_map(|(validator, (microcredits, _, _))| {
                // Keep a tally of the remaining microcredits.
                let remaining_microcredits = microcredits.saturating_sub(MIN_VALIDATOR_STAKE);
                // Set the staker amount to `MIN_DELEGATOR_STAKE` microcredits.
                let staker_amount = MIN_DELEGATOR_STAKE;
                // Determine the number of iterations.
                let num_iterations = (remaining_microcredits / staker_amount).saturating_sub(1);

                // Construct the map of stakers.
                let rngs = (0..num_iterations).map(|_| TestRng::from_seed(rng.random())).collect::<Vec<_>>();
                let mut stakers: IndexMap<_, _> = cfg_into_iter!(rngs)
                    .map(|mut rng| {
                        // Sample a random staker.
                        let staker = Address::<N>::new(rng.random());
                        // Output the staker.
                        (staker, (*validator, staker_amount))
                    })
                    .collect();

                // Insert the validator.
                stakers.insert(*validator, (*validator, MIN_VALIDATOR_STAKE));

                // Insert the last staker.
                let final_amount = remaining_microcredits.saturating_sub(num_iterations * staker_amount);
                if final_amount > 0 {
                    let staker = Address::<N>::new(rng.random());
                    stakers.insert(staker, (*validator, final_amount));
                }
                // Return the stakers.
                stakers
            })
            .collect()
    }

    /// Returns the validator delegation totals, given the map of `(validator, (microcredits, is_open, commission))` entries.
    /// This method simulates the existence of delegators for the members.
    pub(crate) fn to_delegations<N: Network>(
        members: &IndexMap<Address<N>, (u64, bool, u8)>,
    ) -> IndexMap<Address<N>, u64> {
        members.into_iter().map(|(validator, (microcredits, _, _))| (*validator, *microcredits)).collect()
    }

    /// Returns the withdrawal addresses, given the stakers.
    /// This method simulates the existence of unique withdrawal addresses for the stakers.
    pub(crate) fn to_withdraw_addresses<N: Network, R: CryptoRng>(
        stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
        rng: &mut R,
    ) -> IndexMap<Address<N>, Address<N>> {
        stakers
            .into_iter()
            .map(|(staker, _)| {
                // Sample a random withdraw address.
                let withdraw_address = Address::<N>::new(rng.random());
                // Return the withdraw address.
                (*staker, withdraw_address)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::prelude::TestRng;

    #[allow(unused_imports)]
    use rayon::prelude::*;
    use std::str::FromStr;

    /// Returns the committee map, given the map of `(validator, (microcredits, is_open, commission))` entries.
    fn to_committee_map<N: Network>(members: &IndexMap<Address<N>, (u64, bool, u8)>) -> Vec<(Plaintext<N>, Value<N>)> {
        members
            .par_iter()
            .map(|(validator, (_, is_open, commission))| {
                let is_open = Boolean::<N>::new(*is_open);
                let commission = U8::<N>::new(*commission);
                (
                    Plaintext::from(Literal::Address(*validator)),
                    Value::from_str(&format!("{{ is_open: {is_open}, commission: {commission} }}")).unwrap(),
                )
            })
            .collect()
    }

    /// Returns the delegated map, given the map of `(validator, (microcredits, is_open, commission))` entries.
    fn to_delegated_map<N: Network>(members: &IndexMap<Address<N>, (u64, bool, u8)>) -> Vec<(Plaintext<N>, Value<N>)> {
        members
            .par_iter()
            .map(|(validator, (microcredits, _, _))| {
                (
                    Plaintext::from(Literal::Address(*validator)),
                    Value::Plaintext(Plaintext::Literal(Literal::U64(U64::new(*microcredits)), Default::default())),
                )
            })
            .collect()
    }

    /// Returns the bonded map, given the staker, validator and microcredits.
    fn to_bonded_map<N: Network>(stakers: &IndexMap<Address<N>, (Address<N>, u64)>) -> Vec<(Plaintext<N>, Value<N>)> {
        // Prepare the identifiers.
        let validator_identifier = Identifier::from_str("validator").expect("Failed to parse 'validator'");
        let microcredits_identifier = Identifier::from_str("microcredits").expect("Failed to parse 'microcredits'");

        stakers
            .par_iter()
            .map(|(staker, (validator, microcredits))| {
                // Construct the bonded state.
                let bonded_state = indexmap! {
                    validator_identifier => Plaintext::from(Literal::Address(*validator)),
                    microcredits_identifier => Plaintext::from(Literal::U64(U64::new(*microcredits))),
                };
                // Return the bonded state.
                (
                    Plaintext::from(Literal::Address(*staker)),
                    Value::Plaintext(Plaintext::Struct(bonded_state, Default::default())),
                )
            })
            .collect()
    }

    /// Returns the withdrawal addresses given the withdraw map from finalize storage.
    pub fn withdraw_map_to_withdrawal_addresses<N: Network>(
        withdraw_map: Vec<(Plaintext<N>, Value<N>)>,
    ) -> Result<IndexMap<Address<N>, Address<N>>> {
        // Convert the given key and value into a staker entry.
        let convert = |key, value| {
            // Extract the staker from the key.
            let staker = match key {
                Plaintext::Literal(Literal::Address(address), _) => address,
                _ => bail!("Invalid withdraw key (missing staker) - {key}"),
            };

            // Extract the withdrawal address from the value.
            let withdrawal_address = match value {
                Value::Plaintext(Plaintext::Literal(Literal::Address(address), _)) => address,
                _ => bail!("Invalid withdraw value (missing address) - {key}"),
            };

            Ok((staker, withdrawal_address))
        };

        // Convert the withdraw map into withdrawal addresses.
        withdraw_map.into_iter().map(|(key, value)| convert(key, value)).collect::<Result<IndexMap<_, _>>>()
    }

    #[test]
    fn test_committee_and_delegated_maps_into_committee() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 25, rng);

        // Initialize the committee map.
        let committee_map = to_committee_map(committee.members());

        // Initialize the delegated map.
        let delegated_map = to_delegated_map(committee.members());

        // Start a timer.
        let timer = std::time::Instant::now();
        // Convert the committee map into a committee.
        let candidate_committee =
            committee_and_delegated_maps_into_committee(committee.starting_round(), committee_map, delegated_map)
                .unwrap();
        println!("committee_and_delegated_maps_into_committee: {}ms", timer.elapsed().as_millis());
        assert_eq!(candidate_committee, committee);
    }

    #[test]
    fn test_bonded_map_into_stakers() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 25, rng);
        // Convert the committee into stakers.
        let expected_stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Initialize the bonded map.
        let bonded_map = to_bonded_map(&expected_stakers);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Convert the bonded map into stakers.
        let candidate_stakers = bonded_map_into_stakers(bonded_map).unwrap();
        println!("bonded_map_into_stakers: {}ms", timer.elapsed().as_millis());
        assert_eq!(candidate_stakers.len(), expected_stakers.len());
        assert_eq!(candidate_stakers, expected_stakers);
    }

    #[test]
    fn test_ensure_stakers_matches() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 25, rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Ensure the stakers matches.
        let result = ensure_stakers_matches(&committee, &stakers);
        println!("ensure_stakers_matches: {}ms", timer.elapsed().as_millis());
        assert!(result.is_ok());
    }

    #[test]
    fn test_to_next_committee() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 25, rng);
        // Convert the committee into stakers.
        let _stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Convert the committee into delegations.
        let delegations = crate::committee::test_helpers::to_delegations(committee.members());

        // Start a timer.
        let timer = std::time::Instant::now();
        // Ensure the next committee matches the current committee.
        // Note: We can perform this check, in this specific case only, because we did not apply staking rewards.
        let next_committee = to_next_committee(&committee, committee.starting_round() + 1, &delegations).unwrap();
        println!("to_next_committee: {}ms", timer.elapsed().as_millis());
        assert_eq!(committee.starting_round() + 1, next_committee.starting_round());
        assert_eq!(committee.members(), next_committee.members());
    }

    #[test]
    fn test_to_next_committee_bonded_delegated_map() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee(rng);
        // Convert the committee into stakers.
        let stakers: IndexMap<Address<console::network::MainnetV0>, (Address<console::network::MainnetV0>, u64)> =
            crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Convert the committee into delegations.
        let delegations = crate::committee::test_helpers::to_delegations(committee.members());

        // Start a timer.
        let timer = std::time::Instant::now();
        // Ensure the next committee matches the current committee.
        // Note: We can perform this check, in this specific case only, because we did not apply staking rewards.
        let (committee_map, bonded_map, _) = to_next_committee_bonded_delegated_map(&committee, &stakers, &delegations);
        println!("to_next_committee_bonded_delegated_map: {}ms", timer.elapsed().as_millis());
        assert_eq!(committee_map, to_committee_map(committee.members()));
        assert_eq!(bonded_map, to_bonded_map(&stakers));
    }

    #[test]
    fn test_to_withdraw_map() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = snarkvm_ledger_committee::test_helpers::sample_committee(rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);

        // Construct the withdraw addresses.
        let withdrawal_addresses = crate::committee::test_helpers::to_withdraw_addresses(&stakers, rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Ensure the withdrawal map is correct.
        let withdrawal_map = to_next_withdraw_map(&withdrawal_addresses);
        println!("to_next_withdraw_map: {}ms", timer.elapsed().as_millis());
        assert_eq!(withdrawal_addresses, withdraw_map_to_withdrawal_addresses(withdrawal_map).unwrap());
    }
}
