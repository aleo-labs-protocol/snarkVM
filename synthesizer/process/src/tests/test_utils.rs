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
use circuit::network::AleoV0;
use console::{
    account::{Address, PrivateKey},
    network::{MainnetV0, prelude::*},
    program::{Identifier, Literal, Plaintext, ProgramID, Value},
    types::U64,
};
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_ledger_query::Query;
use snarkvm_ledger_store::{BlockStore, FinalizeStorage, FinalizeStore, helpers::memory::BlockMemory};
use snarkvm_synthesizer_program::{FinalizeGlobalState, FinalizeStoreTrait, Program};

use indexmap::IndexMap;
use std::sync::OnceLock;

pub type CurrentNetwork = MainnetV0;
pub type CurrentAleo = AleoV0;

/// Returns a process loaded once and shared by every later caller in the same test process.
/// Only use it where the test never mutates the process, e.g. via `add_program` or `execute`.
pub fn shared_process() -> &'static Process<CurrentNetwork> {
    static PROCESS: OnceLock<Process<CurrentNetwork>> = OnceLock::new();
    PROCESS.get_or_init(|| Process::load().unwrap())
}

/// Samples a new finalize store.
macro_rules! sample_finalize_store {
    () => {{
        #[cfg(feature = "rocks")]
        let temp_dir = tempfile::tempdir().expect("Failed to open temporary directory");
        #[cfg(not(feature = "rocks"))]
        let temp_dir = ();

        #[cfg(feature = "rocks")]
        let store = FinalizeStore::<CurrentNetwork, snarkvm_ledger_store::helpers::rocksdb::FinalizeDB<_>>::open(
            temp_dir.path().to_owned(),
        )
        .unwrap();
        #[cfg(not(feature = "rocks"))]
        let store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(0u16).unwrap();

        (store, temp_dir)
    }};
}
pub(super) use sample_finalize_store;

macro_rules! test_atomic_finalize {
    ($store:ident, $mode:expr, $test:block) => {{
        // The test closure.
        let mut run = || -> Result<()> { atomic_finalize!($store, $mode, $test) };
        // Run the test.
        run()
    }};
}
pub(super) use test_atomic_finalize;

/// Samples a new finalize state.
fn sample_finalize_state(block_height: u32) -> FinalizeGlobalState {
    FinalizeGlobalState::from(block_height as u64, block_height, None, [0u8; 32], None, None)
}

/// Returns the `value` for the given `key` in the `mapping` for the given `program_id`.
fn get_mapping_value<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    program_id: &str,
    mapping: &str,
    key: Literal<N>,
) -> Result<Option<Value<N>>> {
    // Prepare the program ID, mapping name, and key.
    let program_id = ProgramID::from_str(program_id)?;
    let mapping = Identifier::from_str(mapping)?;
    let key = Plaintext::from(key);
    // Retrieve the value from the finalize store.
    match store.get_value_speculative(program_id, mapping, &key) {
        Ok(result) => Ok(result),
        Err(err) => bail!("Error getting value for program_id: {program_id}, mapping: {mapping}, key: {key}: {err}"),
    }
}

/// Get the current `account` mapping balance.
pub fn account_balance<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    address: &Address<N>,
) -> Result<u64> {
    // Retrieve the balance from the finalize store.
    match get_mapping_value(store, "credits.aleo", "account", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => Ok(*balance),
        _ => bail!("Missing or malformed account balance for {address}"),
    }
}

/// Get the current delegated state from the `delegated` mapping for the given validator address.
/// Returns the `delegated_state` as the number of microcredits delegated to the validator.
pub fn delegated_state<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    address: &Address<N>,
) -> Result<Option<u64>> {
    // Retrieve the delegated state from the finalize store.
    let state = match get_mapping_value(store, "credits.aleo", "delegated", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U64(microcredits), _))) => microcredits,
        None => return Ok(None),
        _ => bail!("Malformed delegate state for {address}"),
    };

    Ok(Some(*state))
}

/// Get the current bond state from the `bonding` mapping for the given staker address.
/// Returns the `bond_state` as a tuple of `(validator address, microcredits)`.
pub fn bond_state<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    address: &Address<N>,
) -> Result<Option<(Address<N>, u64)>> {
    // Retrieve the bond state from the finalize store.
    let state = match get_mapping_value(store, "credits.aleo", "bonded", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Struct(state, _))) => state,
        None => return Ok(None),
        _ => bail!("Malformed bond state for {address}"),
    };

    // Retrieve `validator` from the bond state.
    let validator = match state.get(&Identifier::from_str("validator")?) {
        Some(Plaintext::Literal(Literal::Address(address), _)) => *address,
        _ => bail!("`validator` not found for: {address}"),
    };

    // Retrieve `microcredits` from the bond state.
    let microcredits = match state.get(&Identifier::from_str("microcredits")?) {
        Some(Plaintext::Literal(Literal::U64(microcredits), _)) => **microcredits,
        _ => bail!("`microcredits` not found for: {address}"),
    };

    Ok(Some((validator, microcredits)))
}

/// Get the current unbonding state from the `unbonding` mapping for the given staker address.
/// Returns the `unbond_state` as a tuple of `(microcredits, unbond_height)`.
pub fn unbond_state<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    address: &Address<N>,
) -> Result<Option<(u64, u32)>> {
    // Retrieve the unbond state from the finalize store.
    let state = match get_mapping_value(store, "credits.aleo", "unbonding", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Struct(state, _))) => state,
        None => return Ok(None),
        _ => bail!("Malformed unbond state for {address}"),
    };

    // Retrieve `microcredits` from the bond state.
    let microcredits = match state.get(&Identifier::from_str("microcredits")?) {
        Some(Plaintext::Literal(Literal::U64(microcredits), _)) => **microcredits,
        _ => bail!("`microcredits` not found for: {address}"),
    };

    // Retrieve `height` from the bond state.
    let height = match state.get(&Identifier::from_str("height")?) {
        Some(Plaintext::Literal(Literal::U32(height), _)) => **height,
        _ => bail!("`height` not found for: {address}"),
    };

    Ok(Some((microcredits, height)))
}

/// Initializes the validator and delegator balances in the finalize store.
/// Returns the private keys, balances, withdrawal private keys and withdrawal addresses for the validators and delegators.
pub fn initialize_stakers<N: Network, F: FinalizeStorage<N>>(
    finalize_store: &FinalizeStore<N, F>,
    num_validators: u32,
    num_delegators: u32,
    rng: &mut TestRng,
) -> Result<(
    IndexMap<PrivateKey<N>, (Address<N>, u64, PrivateKey<N>, Address<N>)>,
    IndexMap<PrivateKey<N>, (Address<N>, u64)>,
)> {
    // Initialize the store for 'credits.aleo'.
    let program = Program::<N>::credits()?;
    for mapping in program.mappings().values() {
        // Ensure that all mappings are initialized.
        if !finalize_store.contains_mapping_confirmed(program.id(), mapping.name())? {
            // Initialize the mappings for 'credits.aleo'.
            finalize_store.initialize_mapping(*program.id(), *mapping.name())?;
        }
    }

    let mapping = Identifier::from_str("account")?;

    let mut validators: IndexMap<_, _> = Default::default();
    let mut delegators: IndexMap<_, _> = Default::default();

    // Initialize the balances for the validators and delegators.
    for i in 0..(num_validators + num_delegators) {
        // Initialize a new account.
        let private_key = PrivateKey::<N>::new(rng)?;
        let address = Address::try_from(&private_key)?;
        let balance = 100_000_000_000_000u64;

        // Add the balance directly to the finalize store.
        let key = Plaintext::from(Literal::Address(address));
        let value = Value::from(Literal::U64(U64::new(balance)));
        finalize_store.insert_key_value(*program.id(), mapping, key, value)?;
        assert_eq!(balance, account_balance(finalize_store, &address).unwrap());

        // Store the validator or delegator.
        if i < num_validators {
            // Validators are required to have a different withdrawal address
            let withdrawal_private_key = PrivateKey::<N>::new(rng)?;
            let withdrawal_address = Address::try_from(&withdrawal_private_key)?;
            // Insert the validator into the list of validators.
            validators.insert(private_key, (address, balance, withdrawal_private_key, withdrawal_address));
        } else {
            // Insert the delegator into the list of delegators.
            delegators.insert(private_key, (address, balance));
        }
    }

    Ok((validators, delegators))
}

fn execute_function<F: FinalizeStorage<CurrentNetwork>>(
    process: &Process<CurrentNetwork>,
    finalize_store: &FinalizeStore<CurrentNetwork, F>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    function: &str,
    inputs: &[String],
    block_height: Option<u32>,
    rng: &mut TestRng,
) -> Result<()> {
    // Construct the authorization.
    let authorization =
        process.authorize::<CurrentAleo, _>(caller_private_key, "credits.aleo", function, inputs.iter(), rng)?;

    // Construct the trace.
    let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng)?;

    // Construct the block store.
    // Use 0u16 as a valid in-memory StorageMode value instead of None
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(0u16)?;

    // Prepare the trace.
    trace.prepare(&Query::from(&block_store))?;

    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>(function, VarunaVersion::V1, rng)?;

    // Finalize the execution.
    let block_height = block_height.unwrap_or(1);

    // Add an atomic finalize wrapper around the finalize function.
    process.lock().finalize_execution(sample_finalize_state(block_height), finalize_store, &execution, None)?;

    Ok(())
}

/// Perform a `bond_validator`.
pub fn bond_validator<F: FinalizeStorage<CurrentNetwork>>(
    process: &Process<CurrentNetwork>,
    finalize_store: &FinalizeStore<CurrentNetwork, F>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    withdrawal_address: &Address<CurrentNetwork>,
    amount: u64,
    commission: u8,
    rng: &mut TestRng,
) -> Result<()> {
    execute_function(
        process,
        finalize_store,
        caller_private_key,
        "bond_validator",
        &[withdrawal_address.to_string(), format!("{amount}_u64"), format!("{commission}_u8")],
        None,
        rng,
    )
}

/// Perform a `bond_public`.
pub fn bond_public<F: FinalizeStorage<CurrentNetwork>>(
    process: &Process<CurrentNetwork>,
    finalize_store: &FinalizeStore<CurrentNetwork, F>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    validator_address: &Address<CurrentNetwork>,
    withdrawal_address: &Address<CurrentNetwork>,
    amount: u64,
    rng: &mut TestRng,
) -> Result<()> {
    execute_function(
        process,
        finalize_store,
        caller_private_key,
        "bond_public",
        &[validator_address.to_string(), withdrawal_address.to_string(), format!("{amount}_u64")],
        None,
        rng,
    )
}

/// Perform an `unbond_public`.
pub fn unbond_public<F: FinalizeStorage<CurrentNetwork>>(
    process: &Process<CurrentNetwork>,
    finalize_store: &FinalizeStore<CurrentNetwork, F>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    address: &Address<CurrentNetwork>,
    amount: u64,
    block_height: u32,
    rng: &mut TestRng,
) -> Result<()> {
    execute_function(
        process,
        finalize_store,
        caller_private_key,
        "unbond_public",
        &[address.to_string(), format!("{amount}_u64")],
        Some(block_height),
        rng,
    )
}
