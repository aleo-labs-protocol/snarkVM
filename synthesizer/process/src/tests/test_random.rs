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

use crate::Process;
use console::{
    account::{Address, PrivateKey},
    network::{MainnetV0, prelude::*},
};
use rand::seq::IteratorRandom;
use snarkvm_ledger_committee::{MIN_DELEGATOR_STAKE, MIN_VALIDATOR_SELF_STAKE, MIN_VALIDATOR_STAKE};
#[cfg(feature = "rocks")]
use snarkvm_ledger_store::{FinalizeMode, FinalizeStorage, FinalizeStore, atomic_finalize};
#[cfg(not(feature = "rocks"))]
use snarkvm_ledger_store::{
    FinalizeMode,
    FinalizeStorage,
    FinalizeStore,
    atomic_finalize,
    helpers::memory::FinalizeMemory,
};

use indexmap::{IndexMap, IndexSet};

use super::test_utils::*;

/// Returns `value` with probability 0.2, and a uniform value in the closed interval
/// [0, 1.2 * value] with probability 0.8.
fn random_below_with_blowup(value: u64, rng: &mut impl Rng) -> u64 {
    const BLOWUP: u64 = 20;
    let upper_bound = value + value / BLOWUP;

    match rng.random_range(0..100) {
        0..=79 => rng.random_range(0..=upper_bound),
        _ => value,
    }
}

/// If `default` is `Some(value)` this function returns `value` with probability
/// 0.8 and a uniformly random value in `values` with probability 0.2. If
/// `default` is `None`, it returns a uniformly random value from `values`.
fn random_with_default<'a, T>(
    values: impl Iterator<Item = &'a T>,
    default: Option<&'a T>,
    rng: &mut impl Rng,
) -> &'a T {
    match rng.random_range(0..100) {
        0..=79 => default.unwrap_or(values.choose(rng).unwrap()),
        _ => values.choose(rng).unwrap(),
    }
}

/// A bonding or unbonding operation.
#[derive(Clone)]
enum Operation {
    /// Bond funds as a validator.
    BondValidator {
        private_key: PrivateKey<MainnetV0>,
        withdrawal_address: Address<MainnetV0>,
        amount: u64,
        commission: u8,
    },
    /// Bond funds as a delegator.
    BondPublic {
        private_key: PrivateKey<MainnetV0>,
        validator_address: Address<MainnetV0>,
        withdrawal_address: Address<MainnetV0>,
        amount: u64,
    },
    /// Unbond funds.
    UnbondPublic { withdrawal_private_key: PrivateKey<MainnetV0>, staker_address: Address<MainnetV0>, amount: u64 },
}

impl Debug for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Operation::BondValidator { private_key, amount, .. } => {
                let validator_address = Address::<MainnetV0>::try_from(private_key).unwrap().to_string();
                write!(f, "BondValidator {{ {}, {amount} }}", &validator_address[..12])
            }
            Operation::BondPublic { private_key, validator_address, amount, .. } => {
                let delegator_address = Address::<MainnetV0>::try_from(private_key).unwrap().to_string();
                let validator_address = validator_address.to_string();
                write!(f, "BondPublic {{ {}, {}, {amount} }}", &delegator_address[..12], &validator_address[..12])
            }
            Operation::UnbondPublic { staker_address, amount, .. } => {
                let staker_address = staker_address.to_string();
                write!(f, "UnbondPublic {{ {}, {amount} }}", &staker_address[..12])
            }
        }
    }
}

impl Operation {
    /// Returns a random operation. Note that the operation may not be valid in
    /// the sense that it is not guaranteed to execute successfully.
    pub fn random(state: &State, rng: &mut impl Rng) -> Self {
        match rng.random_range(0..3) {
            0 => Operation::random_bond_validator(state, rng),
            1 => Operation::random_bond_public(state, rng),
            _ => Operation::random_unbond_public(state, rng),
        }
    }

    /// Returns a random `bond_validator` operation.
    fn random_bond_validator(state: &State, rng: &mut impl Rng) -> Self {
        let validator = state.stakers().choose(rng).unwrap();
        let account_balance = state.account_balance(validator.address());

        Operation::BondValidator {
            private_key: *validator.private_key(),
            withdrawal_address: *random_with_default(state.stakers(), Some(validator), rng).withdrawal_address(),
            amount: random_below_with_blowup(account_balance, rng),
            commission: random_below_with_blowup(100, rng) as u8,
        }
    }

    /// Returns a random `bond_public` operation.
    fn random_bond_public(state: &State, rng: &mut impl Rng) -> Self {
        let delegator = state.stakers().choose(rng).unwrap();
        let validator_addresses = state.stakers().map(|staker| staker.address());
        let default_address = state.bonded_to(delegator.address());
        let account_balance = state.account_balance(delegator.address());

        Operation::BondPublic {
            private_key: *delegator.private_key(),
            validator_address: *random_with_default(validator_addresses, default_address.as_ref(), rng),
            withdrawal_address: *random_with_default(state.stakers(), Some(delegator), rng).withdrawal_address(),
            amount: random_below_with_blowup(account_balance, rng),
        }
    }

    /// Returns a random `unbond_public` operation.
    fn random_unbond_public(state: &State, rng: &mut impl Rng) -> Self {
        let staker = state.stakers().choose(rng).unwrap();
        let withdrawal_private_key = match state.bonded_to(staker.address()) {
            Some(validator_address) => {
                let validator = state.staker_with_address(&validator_address).unwrap();
                [*staker.withdrawal_private_key(), *validator.withdrawal_private_key()].into_iter().choose(rng).unwrap()
            }
            None => *state.stakers().choose(rng).unwrap().withdrawal_private_key(),
        };
        let account_balance = state.account_balance(staker.address());

        Operation::UnbondPublic {
            withdrawal_private_key,
            staker_address: *staker.address(),
            amount: random_below_with_blowup(account_balance, rng),
        }
    }
}

/// A staker in the network with `(address, amount, withdrawal_private_key, withdrawal_address)`.
#[derive(Copy, Clone, Debug)]
struct Staker(PrivateKey<MainnetV0>, Address<MainnetV0>, PrivateKey<MainnetV0>, Address<MainnetV0>, u64);

impl Staker {
    fn private_key(&self) -> &PrivateKey<MainnetV0> {
        &self.0
    }

    fn address(&self) -> &Address<MainnetV0> {
        &self.1
    }

    fn withdrawal_private_key(&self) -> &PrivateKey<MainnetV0> {
        &self.2
    }

    fn withdrawal_address(&self) -> &Address<MainnetV0> {
        &self.3
    }

    fn initial_balance(&self) -> u64 {
        self.4
    }
}

#[derive(Default)]
struct State {
    /// Maps staker addresses to stakers in the system.
    stakers: IndexMap<Address<MainnetV0>, Staker>,
    /// Maps addresses to registered commissions.
    commissions: IndexMap<Address<MainnetV0>, u8>,
    /// Maps stakers to the corresponding validator.
    bonded_to: IndexMap<Address<MainnetV0>, Address<MainnetV0>>,
    /// Contains the bonded amount for each staker.
    bonded_amounts: IndexMap<Address<MainnetV0>, u64>,
    /// Contains the account balance for each staker.
    account_balances: IndexMap<Address<MainnetV0>, u64>,
    /// Contains the unbonding amount for each staker.
    unbonding_amounts: IndexMap<Address<MainnetV0>, u64>,
    /// Contains each staker who have had funds delegated to them at some point.
    /// (This is used to mimic the behavior of the `delegated_state` function.)
    has_delegated_state: IndexSet<Address<MainnetV0>>,
    // Contains the withdrawal address registered by each staker. (Note that
    // this may be different from the withdrawal address on the staker.)
    withdrawal_addresses: IndexMap<Address<MainnetV0>, Address<MainnetV0>>,
}

impl State {
    /// Returns a new [`State`] with `num_stakers` stakers.
    pub fn new<F: FinalizeStorage<MainnetV0>>(
        num_stakers: u32,
        store: &FinalizeStore<MainnetV0, F>,
        rng: &mut TestRng,
    ) -> Self {
        let (validators, _) = initialize_stakers(store, num_stakers, 0, rng).unwrap();
        let stakers: IndexMap<Address<MainnetV0>, Staker> = validators
            .into_iter()
            .map(|(private_key, (address, initial_balance, withdrawal_private_key, withdrawal_address))| {
                (address, Staker(private_key, address, withdrawal_private_key, withdrawal_address, initial_balance))
            })
            .collect();
        let account_balances = stakers.iter().map(|(address, staker)| (*address, staker.initial_balance())).collect();
        Self { stakers, account_balances, ..Default::default() }
    }

    /// An iterator over the set of potential stakers.
    fn stakers(&self) -> impl Iterator<Item = &Staker> {
        self.stakers.iter().map(|(_, staker)| staker)
    }

    /// Returns `true` if the address is in the committee.
    fn in_committee(&self, address: &Address<MainnetV0>) -> bool {
        self.delegated_amount(address) > MIN_VALIDATOR_STAKE
            && self.bonded_amount(address) > MIN_VALIDATOR_SELF_STAKE
            && self.bonded_to(address) == Some(*address)
    }

    /// Returns `true` if the address has bonded funds.
    fn is_bonded(&self, address: &Address<MainnetV0>) -> bool {
        self.bonded_to.contains_key(address)
    }

    /// Returns `true` if the address is unbonding.
    fn is_unbonding(&self, address: &Address<MainnetV0>) -> bool {
        self.unbonding_amounts.contains_key(address)
    }

    /// Returns `Some(validator_address)` if the given address has bonded funds
    /// to a validator, or `None` otherwise.
    fn bonded_to(&self, address: &Address<MainnetV0>) -> Option<Address<MainnetV0>> {
        self.bonded_to.get(address).copied()
    }

    /// Returns the amount (in microcredits) that the address has bonded.
    fn bonded_amount(&self, address: &Address<MainnetV0>) -> u64 {
        self.bonded_amounts.get(address).copied().unwrap_or_default()
    }

    /// Returns `Some((validator_address, amount))` if the given address has
    /// bonded `amount` microcredits to `validator_address`.
    fn bond_state(&self, address: &Address<MainnetV0>) -> Option<(Address<MainnetV0>, u64)> {
        self.bonded_to(address).zip(Some(self.bonded_amount(address)))
    }

    /// Returns the account balance (amount of available unbonded funds) of the
    /// given address.
    fn account_balance(&self, address: &Address<MainnetV0>) -> u64 {
        self.account_balances.get(address).copied().unwrap_or_default()
    }

    /// Returns `Some((amount, height))` if the given address is unbonding
    /// `amount` microcredits.
    fn unbond_state(&self, address: &Address<MainnetV0>) -> Option<(u64, u32)> {
        self.unbonding_amounts.get(address).copied().zip(Some(10360))
    }

    /// Returns the total amount of funds bonded to the given validator address.
    fn delegated_amount(&self, validator_address: &Address<MainnetV0>) -> u64 {
        self.stakers()
            .filter_map(|staker| {
                if self.bonded_to(staker.address()) == Some(*validator_address) {
                    Some(self.bonded_amount(staker.address()))
                } else {
                    None
                }
            })
            .sum()
    }

    /// Returns the total amount of funds bonded to the given validator address
    /// if it is non-zero, or `None`.
    fn delegated_state(&self, validator_address: &Address<MainnetV0>) -> Option<u64> {
        if self.has_delegated_state.contains(validator_address) {
            Some(self.delegated_amount(validator_address))
        } else {
            None
        }
    }

    /// Returns the staker with the given address.
    fn staker_with_address(&self, address: &Address<MainnetV0>) -> Option<Staker> {
        self.stakers.get(address).copied()
    }

    /// Returns the staker with the given private key.
    fn staker_with_private_key(&self, private_key: &PrivateKey<MainnetV0>) -> Option<Staker> {
        Address::try_from(private_key).ok().and_then(|address| self.stakers.get(&address)).copied()
    }

    /// Returns `Some(withdrawal_address)` if the address has registered a
    /// withdrawal address, or `None` if no withdrawal address is registered.
    fn withdrawal_address(&self, address: &Address<MainnetV0>) -> Option<Address<MainnetV0>> {
        self.withdrawal_addresses.get(address).copied()
    }

    /// Returns `Some(commission)` if the address has registered a commission,
    /// or `None` otherwise.
    fn commision(&self, address: &Address<MainnetV0>) -> Option<u8> {
        self.commissions.get(address).copied()
    }

    /// Rust reference implementation of the `bond_validator` validation.
    fn check_bond_validator(
        &self,
        private_key: &PrivateKey<MainnetV0>,
        withdrawal_address: &Address<MainnetV0>,
        amount: u64,
        commission: u8,
    ) -> Result<()> {
        let validator = self.staker_with_private_key(private_key).unwrap();

        // Amount is at least 1 credit.
        ensure!(amount >= 1_000_000u64);
        // Commision is at most 100%.
        ensure!(commission <= 100u8);
        // Validator has enough funds.
        ensure!(amount <= self.account_balance(validator.address()));

        if self.is_bonded(validator.address()) {
            // The validator is not bonded to someone else.
            ensure!(self.bonded_to(validator.address()) == Some(*validator.address()));
            // The withdrawal address is not updated.
            ensure!(self.withdrawal_address(validator.address()) == Some(*withdrawal_address));
            // The commission is not updated.
            ensure!(self.commision(validator.address()) == Some(commission));
        } else {
            // The initial bonded amount is at least 100 credits.
            ensure!(amount >= MIN_VALIDATOR_SELF_STAKE);
            // The total delegated amount is at least 10 000 000 credits.
            ensure!(self.delegated_amount(validator.address()) + amount >= MIN_VALIDATOR_STAKE);
            // The validator is not unbonding.
            ensure!(!self.is_unbonding(validator.address()));
            // The withdrawal address is not updated.
            ensure!(
                self.withdrawal_address(validator.address()).is_none()
                    || self.withdrawal_address(validator.address()) == Some(*withdrawal_address)
            );
        }
        Ok(())
    }

    /// Rust reference implementation of the `bond_public` validation.
    fn check_bond_public(
        &self,
        private_key: &PrivateKey<MainnetV0>,
        validator_address: &Address<MainnetV0>,
        withdrawal_address: &Address<MainnetV0>,
        amount: u64,
    ) -> Result<()> {
        let delegator = self.staker_with_private_key(private_key).unwrap();

        // Amount is at least 1 credit.
        ensure!(amount >= 1_000_000u64);
        // Delegator has enough funds.
        ensure!(amount <= self.account_balance(delegator.address()));
        // The delegator is different from the validator.
        ensure!(delegator.address() != validator_address);
        // The validator is not unbonding.
        ensure!(!self.is_unbonding(validator_address));

        if self.is_bonded(delegator.address()) {
            // The delegator is not bonded to someone else.
            ensure!(self.bonded_to(delegator.address()) == Some(*validator_address));
            // The withdrawal address is not updated.
            ensure!(self.withdrawal_address(delegator.address()) == Some(*withdrawal_address));
            // TODO: We don't currently track the `is_open` flag or the total number of delegators.
        } else {
            // The initial bonded amount is at least 10 000 000 credits.
            ensure!(amount >= MIN_DELEGATOR_STAKE);
            // The withdrawal address is not updated.
            ensure!(
                self.withdrawal_address(delegator.address()).is_none()
                    || self.withdrawal_address(delegator.address()) == Some(*withdrawal_address)
            );
        }
        Ok(())
    }

    /// Rust reference implementation of the `unbond_public` validation.
    fn check_unbond_public(
        &self,
        withdrawal_private_key: &PrivateKey<MainnetV0>,
        staker_address: &Address<MainnetV0>,
        amount: u64,
    ) -> Result<()> {
        let staker = self.staker_with_address(staker_address).unwrap();
        let validator_address = self.bonded_to(staker_address).ok_or(anyhow!("staker is not bonded"))?;
        let validator = self.staker_with_address(&validator_address).unwrap();
        let withdrawal_address = Address::try_from(withdrawal_private_key).unwrap();

        // The caller is the withdrawal address of the staker or the corresponding validator.
        ensure!(
            self.withdrawal_address(staker.address()) == Some(withdrawal_address)
                || self.withdrawal_address(validator.address()) == Some(withdrawal_address)
        );
        // The staker has bonded enough funds.
        ensure!(amount <= self.bonded_amount(staker_address));

        Ok(())
    }

    /// Rust reference implementation of the `bond_validator` state update.
    fn bond_validator(
        &mut self,
        private_key: &PrivateKey<MainnetV0>,
        withdrawal_address: &Address<MainnetV0>,
        amount: u64,
        commission: u8,
    ) {
        let validator = self.staker_with_private_key(private_key).unwrap();
        self.commissions.insert(*validator.address(), commission);
        self.withdrawal_addresses.insert(*validator.address(), *withdrawal_address);
        self.bonded_to.insert(*validator.address(), *validator.address());
        *self.bonded_amounts.entry(*validator.address()).or_default() += amount;
        self.account_balances[validator.address()] -= amount;
        self.has_delegated_state.insert(*validator.address());
    }

    /// Rust reference implementation of the `bond_public` state update.
    fn bond_public(
        &mut self,
        private_key: &PrivateKey<MainnetV0>,
        validator_address: &Address<MainnetV0>,
        withdrawal_address: &Address<MainnetV0>,
        amount: u64,
    ) {
        let delegator = self.staker_with_private_key(private_key).unwrap();
        self.bonded_to.insert(*delegator.address(), *validator_address);
        *self.bonded_amounts.entry(*delegator.address()).or_default() += amount;
        self.account_balances[delegator.address()] -= amount;
        self.withdrawal_addresses.insert(*delegator.address(), *withdrawal_address);
        self.has_delegated_state.insert(*validator_address);
    }

    /// Rust reference implementation of the `unbond_public` state update.
    fn unbond_public(
        &mut self,
        withdrawal_private_key: &PrivateKey<MainnetV0>,
        staker_address: &Address<MainnetV0>,
        amount: u64,
        _height: u64,
    ) {
        let staker = self.staker_with_address(staker_address).unwrap();
        let validator_address = self.bonded_to(staker_address).unwrap();
        let validator = self.staker_with_address(&validator_address).unwrap();
        let withdrawal_address = Address::try_from(withdrawal_private_key).unwrap();
        let validator_in_committee = self.in_committee(&validator_address);

        self.bonded_amounts[staker.address()] -= amount;
        *self.unbonding_amounts.entry(*staker.address()).or_default() += amount;

        if *staker_address != validator_address {
            // # Unbonding a delegator (staker != validator)
            //
            // - If the delegator stake falls below the minimum delegator stake,
            //   the delegators entire stake is unbonded.
            // - If the validator unbonds the delegator, the delegators entire
            //   stake is unbonded.
            //
            // - If the validator is in the committee *and* the total delegated
            //   stake falls below the minimum validator stake, the validators
            //   entire stake is unbonded.
            //
            // TODO: Can the `validator_in_committee` check be removed?
            if self.bonded_amount(staker.address()) < MIN_DELEGATOR_STAKE
                || self.withdrawal_address(&validator_address) == Some(withdrawal_address)
            {
                // The resulting stake is less than the minimum stake, *or* the
                // unbond operation is initiated by the validator.
                *self.unbonding_amounts.entry(*staker.address()).or_default() +=
                    self.bonded_amounts.swap_remove(staker.address()).unwrap();
                self.bonded_to.swap_remove(staker.address());
            }
            if validator_in_committee && self.delegated_amount(validator.address()) < MIN_VALIDATOR_STAKE {
                // The validator is in the committee *and* the total delegated
                // stake falls below the minimum validator stake.
                *self.unbonding_amounts.entry(*validator.address()).or_default() +=
                    self.bonded_amounts.swap_remove(validator.address()).unwrap();
                self.bonded_to.swap_remove(validator.address());
                self.commissions.swap_remove(validator.address());
            }
        } else {
            // # Unbonding a validator (staker == validator)
            //
            // - If the validator stake falls below the minimum self-stake, the
            //   validators entire stake is unbonded.
            // - If the total delegated stake falls below the minim validator
            //   stake, the validators entire stake is unbonded.
            if self.bonded_amount(staker.address()) < MIN_VALIDATOR_SELF_STAKE
                || self.delegated_amount(staker.address()) < MIN_VALIDATOR_STAKE
            {
                *self.unbonding_amounts.entry(*staker.address()).or_default() +=
                    self.bonded_amounts.swap_remove(staker.address()).unwrap();
                self.bonded_to.swap_remove(staker.address());
                self.commissions.swap_remove(staker.address());
            }
        }
    }

    /// Executes the given operation and updates the store or returns an error if
    /// the execution failed.
    pub fn execute_operation(&mut self, op: &Operation) -> Result<()> {
        match op {
            Operation::BondValidator { private_key, withdrawal_address, amount, commission } => {
                self.check_bond_validator(private_key, withdrawal_address, *amount, *commission)?;
                self.bond_validator(private_key, withdrawal_address, *amount, *commission);
            }
            Operation::BondPublic { private_key, validator_address, withdrawal_address, amount } => {
                self.check_bond_public(private_key, validator_address, withdrawal_address, *amount)?;
                self.bond_public(private_key, validator_address, withdrawal_address, *amount);
            }
            Operation::UnbondPublic { withdrawal_private_key, staker_address, amount } => {
                self.check_unbond_public(withdrawal_private_key, staker_address, *amount)?;
                self.unbond_public(withdrawal_private_key, staker_address, *amount, 10_000);
            }
        }
        Ok(())
    }
}

/// Executes the given operation and updates the store or returns an error if
/// the execution failed.
fn execute_operation<F: FinalizeStorage<MainnetV0>>(
    process: &Process<MainnetV0>,
    store: &FinalizeStore<MainnetV0, F>,
    op: &Operation,
    rng: &mut TestRng,
) -> Result<()> {
    match op {
        Operation::BondValidator { private_key, withdrawal_address, amount, commission } => {
            bond_validator(process, store, private_key, withdrawal_address, *amount, *commission, rng)?;
        }
        Operation::BondPublic { private_key, validator_address, withdrawal_address, amount } => {
            bond_public(process, store, private_key, validator_address, withdrawal_address, *amount, rng)?;
        }
        Operation::UnbondPublic { withdrawal_private_key, staker_address, amount } => {
            unbond_public(process, store, withdrawal_private_key, staker_address, *amount, 10_000, rng)?;
        }
    }
    Ok(())
}

/// Returns `Ok(())` if the given store is consistent with the current state.
fn validate_state<F: FinalizeStorage<MainnetV0>>(state: &State, store: &FinalizeStore<MainnetV0, F>) -> Result<()> {
    for staker in state.stakers() {
        // Account balances match.
        ensure!(account_balance(store, staker.address()).unwrap() == state.account_balance(staker.address()));
        // Bonded amounts and corresponding validator addresses match.
        ensure!(bond_state(store, staker.address()).unwrap() == state.bond_state(staker.address()));
        // Unbonding amounts match.
        ensure!(unbond_state(store, staker.address()).unwrap() == state.unbond_state(staker.address()));
        // Delegated amounts match.
        ensure!(delegated_state(store, staker.address()).unwrap() == state.delegated_state(staker.address()));
    }
    Ok(())
}

fn print_operations(ops: &[Operation]) {
    eprintln!("[💸]: Operations:");
    for (i, op) in ops.iter().enumerate() {
        eprintln!("      [{i}]: {op:?}");
    }
}

#[ignore] // Ignoring as it causes CI timeouts
#[test]
fn test_random_operations() {
    loop {
        let mut rng = TestRng::default();
        let process = Process::<MainnetV0>::load().unwrap();
        let (store, _) = sample_finalize_store!();
        let mut state = State::new(8, &store, &mut rng);

        let mut executed_ops = Vec::new();
        test_atomic_finalize!(store, FinalizeMode::RealRun, {
            while executed_ops.len() < 64 {
                let op = Operation::random(&state, &mut rng);
                let expected_result = state.execute_operation(&op);
                let actual_result = execute_operation(&process, &store, &op, &mut rng);

                if actual_result.is_ok() != expected_result.is_ok() {
                    eprintln!("[💥]: State divergence detected.");
                    eprintln!("      Expected result: {expected_result:?}");
                    eprintln!("      Actual result:   {actual_result:?}");
                    executed_ops.push(op);
                    print_operations(&executed_ops);
                    panic!();
                }
                if let Err(error) = validate_state(&state, &store) {
                    eprintln!("[💥]: State divergence detected.");
                    eprintln!("      Error: {error:?}");
                    executed_ops.push(op);
                    print_operations(&executed_ops);
                    panic!();
                }
                if actual_result.is_ok() {
                    executed_ops.push(op);
                }
            }
            Ok(())
        })
        .unwrap();
    }
}
