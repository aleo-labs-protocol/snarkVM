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
use snarkvm_ledger_committee::{MIN_DELEGATOR_STAKE, MIN_VALIDATOR_SELF_STAKE, MIN_VALIDATOR_STAKE};
use snarkvm_ledger_query::Query;
use snarkvm_ledger_store::{
    BlockStore,
    FinalizeMode,
    FinalizeStorage,
    FinalizeStore,
    atomic_finalize,
    helpers::memory::{BlockMemory, FinalizeMemory},
};
use snarkvm_synthesizer_program::{FinalizeGlobalState, FinalizeStoreTrait, Program};
use snarkvm_synthesizer_snark::VerifyingKey;

use aleo_std::StorageMode;
use indexmap::IndexMap;

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

const NUM_BLOCKS_TO_UNLOCK: u32 = 360;
const TEST_COMMISSION: u8 = 5;

#[test]
fn test_credits_translation_verifying_key_is_loaded_and_updated() -> Result<()> {
    let credits_id = ProgramID::<CurrentNetwork>::from_str("credits.aleo")?;
    let credits_record_name = Identifier::from_str("credits")?;
    let raw_verifying_key = CurrentNetwork::translation_credits_verifying_key();
    let num_variables = raw_verifying_key.circuit_info.num_public_and_private_variables as u64;
    let expected = VerifyingKey::new(raw_verifying_key.clone(), num_variables);
    let process = Process::<CurrentNetwork>::load()?;

    assert_eq!(expected, process.get_verifying_key(credits_id, credits_record_name)?);

    process.remove_verifying_key(&credits_id, &credits_record_name)?;
    assert!(process.get_verifying_key(credits_id, credits_record_name).is_err());

    process.lock().update_credits_verifying_keys()?;
    assert_eq!(expected, process.get_verifying_key(credits_id, credits_record_name)?);
    Ok(())
}

/// Samples a new finalize store.
macro_rules! sample_finalize_store {
    () => {{
        #[cfg(feature = "rocks")]
        let store = FinalizeStore::<CurrentNetwork, snarkvm_ledger_store::helpers::rocksdb::FinalizeDB<_>>::open(
            std::sync::Arc::new(tempfile::tempdir().expect("Failed to open temporary directory")),
        )
        .unwrap();
        #[cfg(not(feature = "rocks"))]
        let store =
            FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(aleo_std::StorageMode::new_test(None)).unwrap();

        store
    }};
}

macro_rules! test_atomic_finalize {
    ($store:ident, $mode:expr, $test:block) => {{
        // The test closure.
        let mut run = || -> Result<()> { atomic_finalize!($store, $mode, $test) };
        // Run the test.
        run()
    }};
}

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
fn account_balance<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    address: &Address<N>,
) -> Result<u64> {
    // Retrieve the balance from the finalize store.
    match get_mapping_value(store, "credits.aleo", "account", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => Ok(*balance),
        _ => bail!("Missing or malformed account balance for {address}"),
    }
}

/// Get the current committee state from the `committee` mapping for the given validator address.
/// Returns the `committee_state` as a tuple of `(microcredits, is_open, commission)`.
fn committee_state<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    address: &Address<N>,
) -> Result<Option<(u64, bool, u8)>> {
    // Retrieve the committee state from the finalize store.
    let committee_state = match get_mapping_value(store, "credits.aleo", "committee", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Struct(state, _))) => state,
        None => return Ok(None),
        _ => bail!("Malformed committee state for {address}"),
    };

    // Retrieve the delegated microcredits from the finalize store.
    let staked_microcredits = match get_mapping_value(store, "credits.aleo", "delegated", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U64(microcredits), _))) => microcredits,
        None => return Ok(None),
        _ => bail!("Malformed delegate state for {address}"),
    };

    // Retrieve `commission` from the committee state.
    let commission = match committee_state.get(&Identifier::from_str("commission")?) {
        Some(Plaintext::Literal(Literal::U8(commission), _)) => **commission,
        _ => bail!("`commission` not found for: {address}"),
    };

    // Retrieve `is_open` from the committee state.
    let is_open = match committee_state.get(&Identifier::from_str("is_open")?) {
        Some(Plaintext::Literal(Literal::Boolean(is_open), _)) => **is_open,
        _ => bail!("`is_open` not found for: {address}"),
    };

    Ok(Some((*staked_microcredits, is_open, commission)))
}

/// Get the current delegated state from the `delegated` mapping for the given validator address.
/// Returns the `delegated_state` as the number of microcredits delegated to the validator.
fn delegated_state<N: Network, F: FinalizeStorage<N>>(
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
fn bond_state<N: Network, F: FinalizeStorage<N>>(
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
fn unbond_state<N: Network, F: FinalizeStorage<N>>(
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

/// Get the current withdrawal address from the `withdraw` mapping for the given staker address.
fn withdraw_state<N: Network, F: FinalizeStorage<N>>(
    store: &FinalizeStore<N, F>,
    address: &Address<N>,
) -> Result<Option<Address<N>>> {
    // Retrieve the withdraw state from the finalize store.
    let withdrawal_address = match get_mapping_value(store, "credits.aleo", "withdraw", Literal::Address(*address))? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::Address(withdrawal_address), _))) => withdrawal_address,
        None => return Ok(None),
        _ => bail!("Malformed withdraw state for {address}"),
    };

    Ok(Some(withdrawal_address))
}

/// Initialize an account with a given balance
fn initialize_account<N: Network, F: FinalizeStorage<N>>(
    finalize_store: &FinalizeStore<N, F>,
    address: &Address<N>,
    balance: u64,
) -> Result<()> {
    // Initialize the store for 'credits.aleo'.
    let program = Program::<N>::credits()?;
    for mapping in program.mappings().values() {
        // Ensure that all mappings are initialized.
        if !finalize_store.contains_mapping_confirmed(program.id(), mapping.name())? {
            // Initialize the mappings for 'credits.aleo'.
            finalize_store.initialize_mapping(*program.id(), *mapping.name())?;
        }
    }

    // Initialize the account with the given balance.
    let key = Plaintext::from(Literal::Address(*address));
    let value = Value::from(Literal::U64(U64::new(balance)));
    finalize_store.insert_key_value(
        ProgramID::from_str("credits.aleo")?,
        Identifier::from_str("account")?,
        key,
        value,
    )?;
    assert_eq!(balance, account_balance(finalize_store, address).unwrap());

    Ok(())
}

/// Initializes the validator and delegator balances in the finalize store.
/// Returns the private keys, balances, withdrawal private keys and withdrawal addresses for the validators and delegators.
fn initialize_stakers<N: Network, F: FinalizeStorage<N>>(
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
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None))?;

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
fn bond_validator<F: FinalizeStorage<CurrentNetwork>>(
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
fn bond_public<F: FinalizeStorage<CurrentNetwork>>(
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
fn unbond_public<F: FinalizeStorage<CurrentNetwork>>(
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

/// Perform a `set_validator_state`.
fn set_validator_state<F: FinalizeStorage<CurrentNetwork>>(
    process: &Process<CurrentNetwork>,
    finalize_store: &FinalizeStore<CurrentNetwork, F>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    is_open: bool,
    rng: &mut TestRng,
) -> Result<()> {
    execute_function(
        process,
        finalize_store,
        caller_private_key,
        "set_validator_state",
        &[format!("{is_open}")],
        None,
        rng,
    )
}

/// Perform a `claim_unbond_public`.
fn claim_unbond_public<F: FinalizeStorage<CurrentNetwork>>(
    process: &Process<CurrentNetwork>,
    finalize_store: &FinalizeStore<CurrentNetwork, F>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    address: &Address<CurrentNetwork>,
    block_height: u32,
    rng: &mut TestRng,
) -> Result<()> {
    execute_function(
        process,
        finalize_store,
        caller_private_key,
        "claim_unbond_public",
        &[address.to_string()],
        Some(block_height),
        rng,
    )
}

#[test]
fn test_credits_program_id_simple() {
    let program = Program::<CurrentNetwork>::credits().unwrap();

    // Ensure that the program is correct.
    assert_eq!(program.id().to_string(), "credits.aleo");
}

#[test]
fn test_bond_validator_simple() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();

    // Retrieve the account balance.
    let public_balance = account_balance(&store, validator_address).unwrap();

    // Prepare the validator amount.
    let amount = MIN_VALIDATOR_STAKE;

    // Sanity check the state before finalizing.
    assert_eq!(committee_state(&store, validator_address).unwrap(), None);
    assert_eq!(delegated_state(&store, validator_address).unwrap(), None);
    assert_eq!(bond_state(&store, validator_address).unwrap(), None);
    assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&store, validator_address).unwrap(), None);
    assert_eq!(account_balance(&store, validator_address).unwrap(), public_balance);

    /* Ensure bonding as a validator with the exact MIN_VALIDATOR_STAKE succeeds. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Perform the bond.
        bond_validator(&process, &store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((amount, true, TEST_COMMISSION)));
        assert_eq!(delegated_state(&store, validator_address).unwrap(), Some(amount));
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, validator_address).unwrap(), public_balance - amount);
        Ok(())
    })
    .unwrap();

    // Sanity check the state after finalizing.
    assert_eq!(committee_state(&store, validator_address).unwrap(), Some((amount, true, TEST_COMMISSION)));
    assert_eq!(delegated_state(&store, validator_address).unwrap(), Some(amount));
    assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, amount)));
    assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
    assert_eq!(account_balance(&store, validator_address).unwrap(), public_balance - amount);
}

#[test]
fn test_bond_public_with_minimum_bond() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validator and delegator keys
    let validator_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let validator_address = Address::try_from(&validator_private_key).unwrap();
    let withdrawal_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let withdrawal_address = Address::try_from(&withdrawal_private_key).unwrap();
    let delegator_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let delegator_address = Address::try_from(&delegator_private_key).unwrap();

    // Initialize the account balances
    let validator_balance = 1_000_000_000u64; // 1,000 credits
    let delegator_balance = 100_000_000_000_000u64;
    initialize_account(&store, &validator_address, validator_balance).unwrap();
    initialize_account(&store, &delegator_address, delegator_balance).unwrap();

    let delegator_amount = MIN_VALIDATOR_STAKE - MIN_VALIDATOR_SELF_STAKE;
    let validator_amount = MIN_VALIDATOR_SELF_STAKE;

    // Sanity check the state before finalizing.
    assert_eq!(committee_state(&store, &validator_address).unwrap(), None);
    assert_eq!(delegated_state(&store, &validator_address).unwrap(), None);
    assert_eq!(bond_state(&store, &validator_address).unwrap(), None);
    assert_eq!(unbond_state(&store, &validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&store, &validator_address).unwrap(), None);
    assert_eq!(account_balance(&store, &validator_address).unwrap(), validator_balance);
    assert_eq!(account_balance(&store, &delegator_address).unwrap(), delegator_balance);

    /*
    1. Delegator bonds to validator before validator is in the committee
    2. Validator can then bond_validator to join the committee
    */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Perform the bond public.
        bond_public(
            &process,
            &store,
            &delegator_private_key,
            &validator_address,
            &delegator_address,
            delegator_amount,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, &validator_address).unwrap(), None);
        assert_eq!(delegated_state(&store, &validator_address).unwrap(), Some(delegator_amount));
        assert_eq!(bond_state(&store, &delegator_address).unwrap(), Some((validator_address, delegator_amount)));
        assert_eq!(unbond_state(&store, &validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, &delegator_address).unwrap(), Some(delegator_address));

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, &delegator_address).unwrap(), delegator_balance - delegator_amount);

        // Perform the bond validator with the minimum self bond
        bond_validator(
            &process,
            &store,
            &validator_private_key,
            &withdrawal_address,
            validator_amount,
            TEST_COMMISSION,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(
            committee_state(&store, &validator_address).unwrap(),
            Some((validator_amount + delegator_amount, true, TEST_COMMISSION))
        );
        assert_eq!(delegated_state(&store, &validator_address).unwrap(), Some(validator_amount + delegator_amount));
        assert_eq!(bond_state(&store, &delegator_address).unwrap(), Some((validator_address, delegator_amount)));
        assert_eq!(unbond_state(&store, &validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, &validator_address).unwrap(), Some(withdrawal_address));
        assert_eq!(withdraw_state(&store, &delegator_address).unwrap(), Some(delegator_address));

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, &delegator_address).unwrap(), delegator_balance - delegator_amount);
        assert_eq!(account_balance(&store, &validator_address).unwrap(), validator_balance - validator_amount);

        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_below_min_stake_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();

    // Retrieve the account balance.
    let public_balance = account_balance(&store, validator_address).unwrap();

    /* Ensure bonding as a validator below the MIN_VALIDATOR_STAKE fails. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        let amount = rng.random_range(1_000_000..MIN_VALIDATOR_STAKE);
        let result =
            bond_validator(&process, &store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng);
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), None);

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, validator_address).unwrap(), public_balance);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_same_withdrawal_address_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, _)) = validators.first().unwrap();

    // Retrieve the account balance.
    let public_balance = account_balance(&store, validator_address).unwrap();

    /* Ensure bonding as a validator below the MIN_VALIDATOR_STAKE fails. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        let amount = MIN_VALIDATOR_STAKE;
        let result =
            bond_validator(&process, &store, validator_private_key, validator_address, amount, TEST_COMMISSION, rng);
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), None);

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, validator_address).unwrap(), public_balance);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_with_insufficient_funds_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();

    // Retrieve the account balance.
    let public_balance = account_balance(&store, validator_address).unwrap();

    /* Ensure bonding an amount larger than the account balance will fail. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        let amount = public_balance + 1;
        let result =
            bond_validator(&process, &store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng);
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(delegated_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), None);

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, validator_address).unwrap(), public_balance);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_different_commission_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();

    // Retrieve the account balance.
    let public_balance = account_balance(&store, validator_address).unwrap();

    /*  Ensure that bonding additional stake succeeds. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        /* First Bond */

        // Perform the first bond.
        let amount = MIN_VALIDATOR_STAKE;
        assert!(amount < public_balance);
        bond_validator(&process, &store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((amount, true, TEST_COMMISSION)));
        assert_eq!(delegated_state(&store, validator_address).unwrap(), Some(amount));
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let public_balance_1 = account_balance(&store, validator_address).unwrap();
        assert_eq!(public_balance_1, public_balance - amount);

        /* Second Bond */

        // Perform the second bond with a different commission
        let amount = MIN_VALIDATOR_STAKE;
        assert!(amount < public_balance);
        let result = bond_validator(
            &process,
            &store,
            validator_private_key,
            withdrawal_address,
            amount,
            TEST_COMMISSION + 1,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((amount, true, TEST_COMMISSION)));
        assert_eq!(delegated_state(&store, validator_address).unwrap(), Some(amount));
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let public_balance_2 = account_balance(&store, validator_address).unwrap();
        assert_eq!(public_balance_2, public_balance - amount);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_multiple_bonds() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();

    // Retrieve the account balance.
    let public_balance = account_balance(&store, validator_address).unwrap();

    /*  Ensure that bonding additional stake succeeds. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        /* First Bond */

        // Perform the first bond.
        let amount = MIN_VALIDATOR_STAKE;
        assert!(amount < public_balance);
        bond_validator(&process, &store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((amount, true, TEST_COMMISSION)));
        assert_eq!(delegated_state(&store, validator_address).unwrap(), Some(amount));
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let public_balance_1 = account_balance(&store, validator_address).unwrap();
        assert_eq!(public_balance_1, public_balance - amount);

        /* Second Bond */

        // Perform the second bond.
        let amount = MIN_VALIDATOR_STAKE;
        assert!(amount < public_balance_1);
        bond_validator(&process, &store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((amount * 2, true, TEST_COMMISSION)));
        assert_eq!(delegated_state(&store, validator_address).unwrap(), Some(amount * 2));
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, amount * 2)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let public_balance_2 = account_balance(&store, validator_address).unwrap();
        assert_eq!(public_balance_2, public_balance_1 - amount);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_to_other_validator_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&store, 2, 0, rng).unwrap();
    let mut validators = validators.into_iter();
    let (validator_private_key_1, (validator_address_1, _, _, withdrawal_address_1)) = validators.next().unwrap();
    let (validator_private_key_2, (validator_address_2, _, _, withdrawal_address_2)) = validators.next().unwrap();

    /* Ensure that bonding to another validator fails. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        /* Validator 1 */

        // Retrieve the account balance.
        let public_balance_1 = account_balance(&store, &validator_address_1).unwrap();
        let public_balance_2 = account_balance(&store, &validator_address_2).unwrap();

        // Perform the bond for validator 1.
        let amount = MIN_VALIDATOR_STAKE;
        bond_validator(&process, &store, &validator_private_key_1, &withdrawal_address_1, amount, TEST_COMMISSION, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, &validator_address_1).unwrap(), Some((amount, true, TEST_COMMISSION)));
        assert_eq!(committee_state(&store, &validator_address_2).unwrap(), None);
        assert_eq!(delegated_state(&store, &validator_address_1).unwrap(), Some(amount));
        assert_eq!(delegated_state(&store, &validator_address_2).unwrap(), None);
        assert_eq!(bond_state(&store, &validator_address_1).unwrap(), Some((validator_address_1, amount)));
        assert_eq!(bond_state(&store, &validator_address_2).unwrap(), None);
        assert_eq!(unbond_state(&store, &validator_address_1).unwrap(), None);
        assert_eq!(unbond_state(&store, &validator_address_2).unwrap(), None);
        assert_eq!(withdraw_state(&store, &validator_address_1).unwrap(), Some(withdrawal_address_1));
        assert_eq!(withdraw_state(&store, &validator_address_2).unwrap(), None);

        // Retrieve the account balance.
        assert_eq!(account_balance(&store, &validator_address_1).unwrap(), public_balance_1 - amount);
        assert_eq!(account_balance(&store, &validator_address_2).unwrap(), public_balance_2);

        /* Validator 2 */

        // Perform the bond for validator 2.
        let amount = MIN_VALIDATOR_STAKE;
        bond_validator(&process, &store, &validator_private_key_2, &withdrawal_address_2, amount, TEST_COMMISSION, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, &validator_address_1).unwrap(), Some((amount, true, TEST_COMMISSION)));
        assert_eq!(committee_state(&store, &validator_address_2).unwrap(), Some((amount, true, TEST_COMMISSION)));
        assert_eq!(delegated_state(&store, &validator_address_1).unwrap(), Some(amount));
        assert_eq!(delegated_state(&store, &validator_address_2).unwrap(), Some(amount));
        assert_eq!(bond_state(&store, &validator_address_1).unwrap(), Some((validator_address_1, amount)));
        assert_eq!(bond_state(&store, &validator_address_2).unwrap(), Some((validator_address_2, amount)));
        assert_eq!(unbond_state(&store, &validator_address_1).unwrap(), None);
        assert_eq!(unbond_state(&store, &validator_address_2).unwrap(), None);
        assert_eq!(withdraw_state(&store, &validator_address_1).unwrap(), Some(withdrawal_address_1));
        assert_eq!(withdraw_state(&store, &validator_address_2).unwrap(), Some(withdrawal_address_2));

        // Retrieve the account balance.
        assert_eq!(account_balance(&store, &validator_address_1).unwrap(), public_balance_1 - amount);
        assert_eq!(account_balance(&store, &validator_address_2).unwrap(), public_balance_2 - amount);

        /* Bond Validator 1 to Validator 2 */

        // Ensure that bonding to another validator fails.
        assert!(public_balance_1 > 2 * amount, "There is not enough balance to bond to another validator.");
        let result = bond_public(
            &process,
            &store,
            &validator_private_key_1,
            &validator_address_2,
            &validator_address_1,
            amount,
            rng,
        );
        assert!(result.is_err());
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_delegator_simple() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balances.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    // Bond the validator.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Prepare the delegator amount.
    let delegator_amount = MIN_DELEGATOR_STAKE;

    /* Ensure bonding a delegator with the exact MIN_DELEGATOR_STAKE succeeds. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Bond the delegator.
        bond_public(
            &process,
            &store,
            delegator_private_key,
            validator_address,
            delegator_address,
            delegator_amount,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let combined_amount = validator_amount + delegator_amount;
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((combined_amount, true, TEST_COMMISSION)));
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, delegator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Check that the balances are correct.
        assert_eq!(account_balance(&store, validator_address).unwrap(), validator_balance - validator_amount);
        assert_eq!(account_balance(&store, delegator_address).unwrap(), delegator_balance - delegator_amount);
        Ok(())
    })
    .unwrap();

    // Sanity check the state after finalizing.
    assert_eq!(account_balance(&store, delegator_address).unwrap(), delegator_balance - delegator_amount);
}

#[test]
fn test_bond_delegator_below_min_stake_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    /* Ensure bonding as a delegator below the MIN_DELEGATOR_STAKE fails. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Bond the validator.
        let validator_amount = MIN_VALIDATOR_STAKE;
        bond_validator(
            &process,
            &store,
            validator_private_key,
            withdrawal_address,
            validator_amount,
            TEST_COMMISSION,
            rng,
        )
        .unwrap();

        // Bond the delegator.
        let delegator_amount = rng.random_range(1_000_000..MIN_DELEGATOR_STAKE);
        let result = bond_public(
            &process,
            &store,
            delegator_private_key,
            validator_address,
            delegator_address,
            delegator_amount,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((validator_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), None);

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, validator_address).unwrap(), validator_balance - validator_amount);
        assert_eq!(account_balance(&store, delegator_address).unwrap(), delegator_balance);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_delegator_with_insufficient_funds_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    /* Ensure bonding an amount larger than the account balance will fail. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Bond the validator.
        let validator_amount = MIN_VALIDATOR_STAKE;
        bond_validator(
            &process,
            &store,
            validator_private_key,
            withdrawal_address,
            validator_amount,
            TEST_COMMISSION,
            rng,
        )
        .unwrap();

        // Bond the delegator.
        let delegator_amount = delegator_balance + 1;
        let result = bond_public(
            &process,
            &store,
            delegator_private_key,
            withdrawal_address,
            delegator_address,
            delegator_amount,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((validator_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), None);

        // Check that the account balance is correct.
        assert_eq!(account_balance(&store, validator_address).unwrap(), validator_balance - validator_amount);
        assert_eq!(account_balance(&store, delegator_address).unwrap(), delegator_balance);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_delegator_multiple_bonds() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    // Bond the validator.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    /* Ensure that bonding additional stake as a delegator succeeds. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        /* First Bond */

        // Perform the first bond.
        let delegator_amount = MIN_DELEGATOR_STAKE;
        assert!(delegator_amount < delegator_balance);
        bond_public(
            &process,
            &store,
            delegator_private_key,
            validator_address,
            delegator_address,
            delegator_amount,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let combined_amount = validator_amount + delegator_amount;
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((combined_amount, true, TEST_COMMISSION)));
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, delegator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_1 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_1 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_1, validator_balance - validator_amount);
        assert_eq!(delegator_balance_1, delegator_balance - delegator_amount);

        /* Second Bond */

        // Perform the second bond.
        let delegator_amount = MIN_DELEGATOR_STAKE;
        assert!(delegator_amount < delegator_balance_1);
        bond_public(
            &process,
            &store,
            delegator_private_key,
            validator_address,
            delegator_address,
            delegator_amount,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let combined_amount = validator_amount + delegator_amount + delegator_amount;
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((combined_amount, true, TEST_COMMISSION)));
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, 2 * delegator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_2 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_2 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_2, validator_balance_1);
        assert_eq!(delegator_balance_2, delegator_balance_1 - delegator_amount);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_and_delegator_multiple_times() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&finalize_store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balances.
    let validator_public_balance = account_balance(&finalize_store, validator_address).unwrap();
    let delegator_public_balance = account_balance(&finalize_store, delegator_address).unwrap();

    // Prepare the validator amount.
    let validator_amount = MIN_VALIDATOR_STAKE;
    // Perform the bond.
    bond_validator(
        &process,
        &finalize_store,
        validator_private_key,
        withdrawal_address,
        validator_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((validator_amount, true, TEST_COMMISSION))
    );
    assert_eq!(bond_state(&finalize_store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
    assert_eq!(unbond_state(&finalize_store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, validator_address).unwrap(), Some(*withdrawal_address));
    assert_eq!(
        account_balance(&finalize_store, validator_address).unwrap(),
        validator_public_balance - validator_amount
    );

    // Bond the delegator to the validator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    bond_public(
        &process,
        &finalize_store,
        delegator_private_key,
        validator_address,
        delegator_address,
        delegator_amount,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    let combined_amount = validator_amount + delegator_amount;
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((combined_amount, true, TEST_COMMISSION))
    );
    assert_eq!(bond_state(&finalize_store, delegator_address).unwrap(), Some((*validator_address, delegator_amount)));
    assert_eq!(unbond_state(&finalize_store, delegator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, delegator_address).unwrap(), Some(*delegator_address));
    assert_eq!(
        account_balance(&finalize_store, delegator_address).unwrap(),
        delegator_public_balance - delegator_amount
    );

    // Bond the validator again.
    bond_validator(
        &process,
        &finalize_store,
        validator_private_key,
        withdrawal_address,
        validator_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    let combined_amount = 2 * validator_amount + delegator_amount;
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((combined_amount, true, TEST_COMMISSION))
    );
    assert_eq!(
        bond_state(&finalize_store, validator_address).unwrap(),
        Some((*validator_address, 2 * validator_amount))
    );
    assert_eq!(unbond_state(&finalize_store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, validator_address).unwrap(), Some(*withdrawal_address));
    assert_eq!(
        account_balance(&finalize_store, validator_address).unwrap(),
        validator_public_balance - (2 * validator_amount)
    );

    // Bond the delegator to the validator again.
    bond_public(
        &process,
        &finalize_store,
        delegator_private_key,
        validator_address,
        delegator_address,
        delegator_amount,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    let combined_amount = 2 * (validator_amount + delegator_amount);
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((combined_amount, true, TEST_COMMISSION))
    );
    assert_eq!(
        bond_state(&finalize_store, delegator_address).unwrap(),
        Some((*validator_address, 2 * delegator_amount))
    );
    assert_eq!(unbond_state(&finalize_store, delegator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, delegator_address).unwrap(), Some(*delegator_address));
    assert_eq!(
        account_balance(&finalize_store, delegator_address).unwrap(),
        delegator_public_balance - (2 * delegator_amount)
    );
}

#[test]
fn test_bond_delegator_to_multiple_validators_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 2, 1, rng).unwrap();
    let mut validators = validators.into_iter();
    let (validator_private_key_1, (validator_address_1, _, _, withdrawal_address_1)) = validators.next().unwrap();
    let (validator_private_key_2, (validator_address_2, _, _, withdrawal_address_2)) = validators.next().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_1_balance = account_balance(&store, &validator_address_1).unwrap();
    let validator_2_balance = account_balance(&store, &validator_address_2).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    // Bond validator 1.
    let validator_1_amount = MIN_VALIDATOR_STAKE;
    bond_validator(
        &process,
        &store,
        &validator_private_key_1,
        &withdrawal_address_1,
        validator_1_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    // Bond validator 2.
    let validator_2_amount = MIN_VALIDATOR_STAKE;
    bond_validator(
        &process,
        &store,
        &validator_private_key_2,
        &withdrawal_address_2,
        validator_2_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    /* Ensure bonding a delegator to multiple validators fails. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        /* First Bond */

        // Perform the first bond.
        let delegator_amount = MIN_DELEGATOR_STAKE;
        assert!(delegator_amount < delegator_balance);
        bond_public(
            &process,
            &store,
            delegator_private_key,
            &validator_address_1,
            delegator_address,
            delegator_amount,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let combined_amount = validator_1_amount + delegator_amount;
        assert_eq!(
            committee_state(&store, &validator_address_1).unwrap(),
            Some((combined_amount, true, TEST_COMMISSION))
        );
        assert_eq!(
            committee_state(&store, &validator_address_2).unwrap(),
            Some((validator_2_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, &validator_address_1).unwrap(), Some((validator_address_1, validator_1_amount)));
        assert_eq!(bond_state(&store, &validator_address_2).unwrap(), Some((validator_address_2, validator_2_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((validator_address_1, delegator_amount)));
        assert_eq!(unbond_state(&store, &validator_address_1).unwrap(), None);
        assert_eq!(unbond_state(&store, &validator_address_2).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, &validator_address_1).unwrap(), Some(withdrawal_address_1));
        assert_eq!(withdraw_state(&store, &validator_address_2).unwrap(), Some(withdrawal_address_2));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_1_balance_1 = account_balance(&store, &validator_address_1).unwrap();
        let validator_2_balance_1 = account_balance(&store, &validator_address_2).unwrap();
        let delegator_balance_1 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_1_balance_1, validator_1_balance - validator_1_amount);
        assert_eq!(validator_2_balance_1, validator_2_balance - validator_2_amount);
        assert_eq!(delegator_balance_1, delegator_balance - delegator_amount);

        /* Second Bond */

        // Perform the second bond.
        let delegator_amount = MIN_DELEGATOR_STAKE;
        assert!(delegator_amount < delegator_balance_1);
        let result = bond_public(
            &process,
            &store,
            delegator_private_key,
            &validator_address_2,
            delegator_address,
            delegator_amount,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let combined_amount = validator_1_amount + delegator_amount;
        assert_eq!(
            committee_state(&store, &validator_address_1).unwrap(),
            Some((combined_amount, true, TEST_COMMISSION))
        );
        assert_eq!(
            committee_state(&store, &validator_address_2).unwrap(),
            Some((validator_2_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, &validator_address_1).unwrap(), Some((validator_address_1, validator_1_amount)));
        assert_eq!(bond_state(&store, &validator_address_2).unwrap(), Some((validator_address_2, validator_2_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((validator_address_1, delegator_amount)));
        assert_eq!(unbond_state(&store, &validator_address_1).unwrap(), None);
        assert_eq!(unbond_state(&store, &validator_address_2).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, &validator_address_1).unwrap(), Some(withdrawal_address_1));
        assert_eq!(withdraw_state(&store, &validator_address_2).unwrap(), Some(withdrawal_address_2));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_1_balance_2 = account_balance(&store, &validator_address_1).unwrap();
        let validator_2_balance_2 = account_balance(&store, &validator_address_2).unwrap();
        let delegator_balance_1 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_1_balance_2, validator_1_balance_1);
        assert_eq!(validator_2_balance_2, validator_2_balance_1);
        assert_eq!(delegator_balance_1, delegator_balance_1);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_unbond_validator() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, withdrawal_private_key, withdrawal_address)) =
        validators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();

    // Perform the bond.
    let validator_amount = 3 * MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    /* Ensure the validator can unbond their entire balance. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        /* First Unbond */

        // Perform the first unbond.
        let unbond_amount_1 = MIN_VALIDATOR_STAKE;
        let block_height_1 = rng.random_range(1..100);
        unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount_1,
            block_height_1,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let decremented_amount = validator_amount - unbond_amount_1;
        let unlock_height = block_height_1 + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((decremented_amount, true, TEST_COMMISSION))
        );
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, decremented_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), Some((unbond_amount_1, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let validator_balance_1 = account_balance(&store, validator_address).unwrap();
        assert_eq!(validator_balance_1, validator_balance - validator_amount);

        /* Second Unbond */

        // Perform the second unbond.
        let unbond_amount_2 = MIN_VALIDATOR_STAKE;
        let block_height_2 = rng.random_range(block_height_1..1000);
        unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount_2,
            block_height_2,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let decremented_amount = validator_amount - unbond_amount_1 - unbond_amount_2;
        let unbond_combined_amount = unbond_amount_1 + unbond_amount_2;
        let unlock_height = block_height_2 + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((decremented_amount, true, TEST_COMMISSION))
        );
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, decremented_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), Some((unbond_combined_amount, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let validator_balance_2 = account_balance(&store, validator_address).unwrap();
        assert_eq!(validator_balance_2, validator_balance_1);

        /* Third Unbond */

        // Perform the third unbond, which should unbond all remaining stake.
        let unbond_amount_3 = 1; // Notice: This is 1 credit, when the remaining is MIN_VALIDATOR_STAKE.
        let block_height_3 = rng.random_range(block_height_2..10000);
        unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount_3,
            block_height_3,
            rng,
        )
        .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let unlock_height = block_height_3 + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), Some((validator_amount, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let validator_balance_3 = account_balance(&store, validator_address).unwrap();
        assert_eq!(validator_balance_3, validator_balance_2);

        /* Fourth Unbond */

        // Perform the fourth unbond, which should fail (as there is no stake left).
        let unbond_amount_4 = 1;
        let block_height_4 = rng.random_range(block_height_3..100000);
        let result = unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount_4,
            block_height_4,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), Some((validator_amount, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let validator_balance_4 = account_balance(&store, validator_address).unwrap();
        assert_eq!(validator_balance_4, validator_balance_3);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_bond_validator_fails_if_unbonding_state() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, withdrawal_private_key, withdrawal_address)) =
        validators.first().unwrap();

    // Perform the bond.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    /* Ensure the validator can unbond their entire balance. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Ensure the validator is part of the committee and bonded correctly
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((validator_amount, true, TEST_COMMISSION))
        );
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Perform the unbond
        let block_height = rng.random_range(1..100);
        unbond_public(&process, &store, withdrawal_private_key, validator_address, validator_amount, block_height, rng)
            .unwrap();

        // Ensure unbonding the validator removed them from the committee and updated state correctly
        let unlock_height = block_height + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), Some((validator_amount, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Try bond_validator again, should fail due to unbonding state
        let rebonding_result = bond_validator(
            &process,
            &store,
            validator_private_key,
            withdrawal_address,
            validator_amount,
            TEST_COMMISSION,
            rng,
        );
        assert!(rebonding_result.is_err());

        // Ensure the error wasn't due to insufficient balance
        let validator_balance = account_balance(&store, validator_address).unwrap();
        assert!(validator_balance > MIN_VALIDATOR_STAKE);

        // Ensure the validator didn't reenter the committee
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);

        // Claim Unbond Public to clear unbonding state
        claim_unbond_public(&process, &store, validator_private_key, validator_address, unlock_height, rng).unwrap();

        // Try bond_validator again with new commission, should succeed
        let new_commission = TEST_COMMISSION + 1;
        bond_validator(
            &process,
            &store,
            validator_private_key,
            withdrawal_address,
            validator_amount,
            new_commission,
            rng,
        )
        .unwrap();

        // Ensure the validator is part of the committee and bonded correctly
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((validator_amount, true, new_commission)));
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_unbond_validator_fails_if_unbonding_beyond_their_stake() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, withdrawal_private_key, withdrawal_address)) =
        validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    // Bond the validator.
    let validator_amount = 2 * MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    /* Ensure the validator cannot unbond more than their stake. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Perform the unbond.
        let unbond_amount = validator_amount + 1;
        let block_height = rng.random_range(1..100);
        let result = unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount,
            block_height,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((validator_amount, true, TEST_COMMISSION))
        );
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

        // Retrieve the account balance.
        let validator_balance_1 = account_balance(&store, validator_address).unwrap();
        assert_eq!(validator_balance_1, validator_balance - validator_amount);
        Ok(())
    })
    .unwrap();

    // Bond the delegator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    bond_public(&process, &store, delegator_private_key, validator_address, delegator_address, delegator_amount, rng)
        .unwrap();

    /* Ensure the validator cannot unbond more than their stake. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Perform the unbond.
        let unbond_amount = validator_amount + 1;
        let block_height = rng.random_range(1..100);
        let result = unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount,
            block_height,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let combined_amount = validator_amount + delegator_amount;
        assert_eq!(committee_state(&store, validator_address).unwrap(), Some((combined_amount, true, TEST_COMMISSION)));
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, delegator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_1 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_1 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_1, validator_balance - validator_amount);
        assert_eq!(delegator_balance_1, delegator_balance - delegator_amount);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_unbond_validator_continues_if_there_is_a_delegator() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, withdrawal_private_key, withdrawal_address)) =
        validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    // Bond the validator.
    let validator_amount = 2 * MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Bond the delegator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    bond_public(&process, &store, delegator_private_key, validator_address, delegator_address, delegator_amount, rng)
        .unwrap();

    /* Ensure the validator can fully-unbond if there remains a delegator. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Perform the first unbond.
        let unbond_amount_1 = MIN_VALIDATOR_STAKE;
        let block_height_1 = rng.random_range(1..100);
        unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount_1,
            block_height_1,
            rng,
        )
        .unwrap();

        // Perform the second unbond.
        let unbond_amount_2 = MIN_DELEGATOR_STAKE + 2;
        let block_height_2 = rng.random_range(block_height_1..1000);
        let result = unbond_public(
            &process,
            &store,
            withdrawal_private_key,
            validator_address,
            unbond_amount_2,
            block_height_2,
            rng,
        );
        assert!(result.is_ok());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let unlock_height = block_height_2 + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(delegated_state(&store, validator_address).unwrap(), Some(delegator_amount));
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, delegator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), Some((validator_amount, unlock_height)));
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_1 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_1 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_1, validator_balance - validator_amount);
        assert_eq!(delegator_balance_1, delegator_balance - delegator_amount);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_unbond_delegator() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    // Bond the validator.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Bond the delegator.
    let delegator_amount = 3 * MIN_DELEGATOR_STAKE;
    bond_public(&process, &store, delegator_private_key, validator_address, delegator_address, delegator_amount, rng)
        .unwrap();

    /* Ensure the delegator can unbond their entire balance. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        /* First Unbond */

        // Perform the first unbond.
        let unbond_amount_1 = MIN_DELEGATOR_STAKE;
        let block_height_1 = rng.random_range(1..100);
        unbond_public(&process, &store, delegator_private_key, delegator_address, unbond_amount_1, block_height_1, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let decremented_amount = validator_amount + delegator_amount - unbond_amount_1;
        let decremented_delegator = delegator_amount - unbond_amount_1;
        let unlock_height = block_height_1 + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((decremented_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, decremented_delegator)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), Some((unbond_amount_1, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_1 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_1 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_1, validator_balance - validator_amount);
        assert_eq!(delegator_balance_1, delegator_balance - delegator_amount);

        /* Second Unbond */

        // Perform the second unbond.
        let unbond_amount_2 = MIN_DELEGATOR_STAKE;
        let block_height_2 = rng.random_range(block_height_1..1000);
        unbond_public(&process, &store, delegator_private_key, delegator_address, unbond_amount_2, block_height_2, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let decremented_amount = decremented_amount - unbond_amount_2;
        let decremented_delegator = decremented_delegator - unbond_amount_2;
        let unbond_combined_amount = unbond_amount_1 + unbond_amount_2;
        let unlock_height = block_height_2 + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((decremented_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, decremented_delegator)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), Some((unbond_combined_amount, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_2 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_2 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_2, validator_balance_1);
        assert_eq!(delegator_balance_2, delegator_balance_1);

        /* Third Unbond */

        // Perform the third unbond, which should unbond all remaining stake.
        let unbond_amount_3 = 1; // Notice: This is 1 credit, when the remaining is MIN_DELEGATOR_STAKE.
        let block_height_3 = rng.random_range(block_height_2..10000);
        unbond_public(&process, &store, delegator_private_key, delegator_address, unbond_amount_3, block_height_3, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        let unlock_height = block_height_3 + NUM_BLOCKS_TO_UNLOCK;
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((validator_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), Some((delegator_amount, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_3 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_3 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_3, validator_balance_2);
        assert_eq!(delegator_balance_3, delegator_balance_2);

        /* Fourth Unbond */

        // Perform the fourth unbond, which should fail (as there is no stake left).
        let unbond_amount_4 = 1;
        let block_height_4 = rng.random_range(block_height_3..100000);
        let result = unbond_public(
            &process,
            &store,
            delegator_private_key,
            delegator_address,
            unbond_amount_4,
            block_height_4,
            rng,
        );
        assert!(result.is_err());

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((validator_amount, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
        assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), Some((delegator_amount, unlock_height)));
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        // Retrieve the account balance.
        let validator_balance_4 = account_balance(&store, validator_address).unwrap();
        let delegator_balance_4 = account_balance(&store, delegator_address).unwrap();
        assert_eq!(validator_balance_4, validator_balance_3);
        assert_eq!(delegator_balance_4, delegator_balance_3);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_unbond_delegator_without_validator() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (_, (validator_address, _, _, _)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Bond the delegator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    bond_public(&process, &store, delegator_private_key, validator_address, delegator_address, delegator_amount, rng)
        .unwrap();

    /* Ensure the delegator can unbond their entire balance. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Perform the unbond.
        let block_height = rng.random_range(1..100);
        unbond_public(&process, &store, delegator_private_key, delegator_address, delegator_amount, block_height, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(
            unbond_state(&store, delegator_address).unwrap(),
            Some((delegator_amount, block_height + NUM_BLOCKS_TO_UNLOCK))
        );
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        Ok(())
    })
    .unwrap();
}

#[test]
fn test_unbond_delegator_removes_validator_with_insufficient_stake() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();
    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Bond the delegator.
    let delegator_amount = MIN_VALIDATOR_STAKE - MIN_VALIDATOR_SELF_STAKE;
    bond_public(&process, &store, delegator_private_key, validator_address, delegator_address, delegator_amount, rng)
        .unwrap();

    // Bond the validator
    bond_validator(
        &process,
        &store,
        validator_private_key,
        withdrawal_address,
        MIN_VALIDATOR_SELF_STAKE,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    /* Ensure the delegator can unbond their entire balance. */
    test_atomic_finalize!(store, FinalizeMode::RealRun, {
        // Ensure that the validator is part of the committee and correctly bonded
        assert_eq!(
            committee_state(&store, validator_address).unwrap(),
            Some((MIN_VALIDATOR_STAKE, true, TEST_COMMISSION))
        );
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(
            bond_state(&store, validator_address).unwrap(),
            Some((*validator_address, MIN_VALIDATOR_SELF_STAKE))
        );
        assert_eq!(bond_state(&store, delegator_address).unwrap(), Some((*validator_address, delegator_amount)));
        assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
        assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        let block_height = rng.random_range(1..100);
        unbond_public(&process, &store, delegator_private_key, delegator_address, delegator_amount, block_height, rng)
            .unwrap();

        // Check that the committee, bond, unbond, and withdraw states are correct.
        assert_eq!(committee_state(&store, validator_address).unwrap(), None);
        assert_eq!(committee_state(&store, delegator_address).unwrap(), None);
        assert_eq!(bond_state(&store, validator_address).unwrap(), None);
        assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
        assert_eq!(
            unbond_state(&store, validator_address).unwrap(),
            Some((MIN_VALIDATOR_SELF_STAKE, block_height + NUM_BLOCKS_TO_UNLOCK))
        );
        assert_eq!(
            unbond_state(&store, delegator_address).unwrap(),
            Some((delegator_amount, block_height + NUM_BLOCKS_TO_UNLOCK))
        );
        assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
        assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*delegator_address));

        Ok(())
    })
    .unwrap();
}

#[test]
fn test_unbond_delegator_as_validator() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&finalize_store, 2, 1, rng).unwrap();
    let mut validators = validators.into_iter();
    let (validator_private_key_1, (validator_address_1, _, withdrawal_private_key_1, withdrawal_address_1)) =
        validators.next().unwrap();
    let (validator_private_key_2, (_, _, withdrawal_private_key_2, withdrawal_address_2)) = validators.next().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    /* Ensure unbonding a delegator as an open validator fails. */

    // Bond the validators.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(
        &process,
        &finalize_store,
        &validator_private_key_1,
        &withdrawal_address_1,
        validator_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();
    bond_validator(
        &process,
        &finalize_store,
        &validator_private_key_2,
        &withdrawal_address_2,
        validator_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    // Bond the delegator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    bond_public(
        &process,
        &finalize_store,
        delegator_private_key,
        &validator_address_1,
        delegator_address,
        delegator_amount,
        rng,
    )
    .unwrap();

    // Set the validator `is_open` state to `false`.
    set_validator_state(&process, &finalize_store, &validator_private_key_1, false, rng).unwrap();

    /* Ensure unbonding a delegator for another closed validator fails. */

    // Ensure that unbonding a delegator as an open validator fails.
    let block_height = rng.random_range(1..100);

    assert!(
        unbond_public(&process, &finalize_store, &withdrawal_private_key_2, delegator_address, 0u64, block_height, rng)
            .is_err()
    );

    /* Ensure unbonding a delegator as a closed validator succeeds. */

    // Ensure that unbonding a delegator as a closed validator succeeds.
    unbond_public(&process, &finalize_store, &withdrawal_private_key_1, delegator_address, 0u64, block_height, rng)
        .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    assert_eq!(
        committee_state(&finalize_store, &validator_address_1).unwrap(),
        Some((validator_amount, false, TEST_COMMISSION))
    );
    assert_eq!(bond_state(&finalize_store, delegator_address).unwrap(), None);
    assert_eq!(unbond_state(&finalize_store, delegator_address).unwrap().unwrap().0, delegator_amount);
    assert_eq!(withdraw_state(&finalize_store, delegator_address).unwrap(), Some(*delegator_address));
}

#[test]
fn test_claim_unbond() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the validators and delegators.
    let (validators, _) = initialize_stakers(&finalize_store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, withdrawal_private_key, withdrawal_address)) =
        validators.first().unwrap();

    // Perform the bond.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(
        &process,
        &finalize_store,
        validator_private_key,
        withdrawal_address,
        validator_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    /* Ensure claiming an unbond fails when no unbond_state exists. */

    assert!(claim_unbond_public(&process, &finalize_store, validator_private_key, validator_address, 1, rng).is_err());

    // Perform the unbond.
    unbond_public(&process, &finalize_store, withdrawal_private_key, validator_address, validator_amount, 1, rng)
        .unwrap();
    let unbond_height = unbond_state(&finalize_store, validator_address).unwrap().unwrap().1;

    /* Ensure claiming an unbond before the unlock height fails. */

    assert!(
        claim_unbond_public(
            &process,
            &finalize_store,
            validator_private_key,
            validator_address,
            unbond_height - 1,
            rng
        )
        .is_err()
    );

    /* Ensure that claiming an unbond after the unlock height succeeds. */
    let random_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    claim_unbond_public(&process, &finalize_store, &random_private_key, validator_address, unbond_height, rng).unwrap();
    assert_eq!(account_balance(&finalize_store, withdrawal_address).unwrap(), validator_amount);
}

#[test]
fn test_set_validator_state() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the validators.
    let (validators, _) = initialize_stakers(&finalize_store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();

    /* Ensure calling `set_validator_state` succeeds. */

    // Perform the bond.
    let amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &finalize_store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng)
        .unwrap();

    // Check that the validator state is correct.
    assert_eq!(committee_state(&finalize_store, validator_address).unwrap(), Some((amount, true, TEST_COMMISSION)));

    // Set the validator `is_open` state to `false`.
    set_validator_state(&process, &finalize_store, validator_private_key, false, rng).unwrap();
    assert_eq!(committee_state(&finalize_store, validator_address).unwrap(), Some((amount, false, TEST_COMMISSION)));

    // Set the validator state `is_open` to `false` again.
    set_validator_state(&process, &finalize_store, validator_private_key, false, rng).unwrap();
    assert_eq!(committee_state(&finalize_store, validator_address).unwrap(), Some((amount, false, TEST_COMMISSION)));

    // Set the validator `is_open` state back to `true`.
    set_validator_state(&process, &finalize_store, validator_private_key, true, rng).unwrap();
    assert_eq!(committee_state(&finalize_store, validator_address).unwrap(), Some((amount, true, TEST_COMMISSION)));
}

#[test]
fn test_set_validator_state_for_non_validator_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    /* Ensure calling `set_validator_state` as a non-validator fails. */

    // Initialize a new private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Set the validator state to `false`.
    assert!(set_validator_state(&process, &finalize_store, &private_key, false, rng).is_err());
}

#[test]
fn test_bonding_existing_stakers_to_closed_validator() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&finalize_store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balances.
    let validator_public_balance = account_balance(&finalize_store, validator_address).unwrap();
    let delegator_public_balance = account_balance(&finalize_store, delegator_address).unwrap();

    // Prepare the validator amount.
    let validator_amount = MIN_VALIDATOR_STAKE;
    // Perform the bond.
    bond_validator(
        &process,
        &finalize_store,
        validator_private_key,
        withdrawal_address,
        validator_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((validator_amount, true, TEST_COMMISSION))
    );
    assert_eq!(bond_state(&finalize_store, validator_address).unwrap(), Some((*validator_address, validator_amount)));
    assert_eq!(unbond_state(&finalize_store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, validator_address).unwrap(), Some(*withdrawal_address));
    assert_eq!(
        account_balance(&finalize_store, validator_address).unwrap(),
        validator_public_balance - validator_amount
    );

    // Bond the delegator to the validator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    bond_public(
        &process,
        &finalize_store,
        delegator_private_key,
        validator_address,
        delegator_address,
        delegator_amount,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    let combined_amount = validator_amount + delegator_amount;
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((combined_amount, true, TEST_COMMISSION))
    );
    assert_eq!(bond_state(&finalize_store, delegator_address).unwrap(), Some((*validator_address, delegator_amount)));
    assert_eq!(unbond_state(&finalize_store, delegator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, delegator_address).unwrap(), Some(*delegator_address));
    assert_eq!(
        account_balance(&finalize_store, delegator_address).unwrap(),
        delegator_public_balance - delegator_amount
    );

    // Set the validator `is_open` state to `false`.
    set_validator_state(&process, &finalize_store, validator_private_key, false, rng).unwrap();

    /* Ensure bonding to a closed validator succeeds for the existing stakers. */

    // Bond the validator again.
    bond_validator(
        &process,
        &finalize_store,
        validator_private_key,
        withdrawal_address,
        validator_amount,
        TEST_COMMISSION,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    let combined_amount = 2 * validator_amount + delegator_amount;
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((combined_amount, false, TEST_COMMISSION))
    );
    assert_eq!(
        bond_state(&finalize_store, validator_address).unwrap(),
        Some((*validator_address, 2 * validator_amount))
    );
    assert_eq!(unbond_state(&finalize_store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, validator_address).unwrap(), Some(*withdrawal_address));
    assert_eq!(
        account_balance(&finalize_store, validator_address).unwrap(),
        validator_public_balance - (2 * validator_amount)
    );

    // Bond the delegator to the validator again.
    bond_public(
        &process,
        &finalize_store,
        delegator_private_key,
        validator_address,
        delegator_address,
        delegator_amount,
        rng,
    )
    .unwrap();

    // Check that the committee, bond, unbond, and withdraw states are correct.
    let combined_amount = 2 * (validator_amount + delegator_amount);
    assert_eq!(
        committee_state(&finalize_store, validator_address).unwrap(),
        Some((combined_amount, false, TEST_COMMISSION))
    );
    assert_eq!(
        bond_state(&finalize_store, delegator_address).unwrap(),
        Some((*validator_address, 2 * delegator_amount))
    );
    assert_eq!(unbond_state(&finalize_store, delegator_address).unwrap(), None);
    assert_eq!(withdraw_state(&finalize_store, delegator_address).unwrap(), Some(*delegator_address));
    assert_eq!(
        account_balance(&finalize_store, delegator_address).unwrap(),
        delegator_public_balance - (2 * delegator_amount)
    );
}

#[test]
fn test_bonding_new_staker_to_closed_validator_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<CurrentNetwork, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&finalize_store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    /* Ensure bonding to a closed validator fails. */

    // Perform the bond.
    let amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &finalize_store, validator_private_key, withdrawal_address, amount, TEST_COMMISSION, rng)
        .unwrap();

    // Set the validator `is_open` state to `false`.
    set_validator_state(&process, &finalize_store, validator_private_key, false, rng).unwrap();

    // Ensure that new delegators can't bond to the validator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    assert!(
        bond_public(
            &process,
            &finalize_store,
            delegator_private_key,
            validator_address,
            delegator_address,
            delegator_amount,
            rng
        )
        .is_err()
    );
}

// All the the above test cases use the same staker and withdraw addresses.
// The following test check the functionality of the withdraw address using a different staker and withdraw address.

#[test]
fn test_claim_unbond_public_to_withdrawal_address() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, withdrawal_private_key, withdrawal_address)) =
        validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();
    let delegator_balance = account_balance(&store, delegator_address).unwrap();

    // Initialize new withdrawal addresses.
    let delegator_withdraw_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let delegator_withdrawal_address = Address::try_from(&delegator_withdraw_private_key).unwrap();

    // Bond the validator the withdrawal address.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Bond the delegator to the validator.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    bond_public(
        &process,
        &store,
        delegator_private_key,
        validator_address,
        &delegator_withdrawal_address,
        delegator_amount,
        rng,
    )
    .unwrap();

    // Unbond the delegator completely.
    unbond_public(&process, &store, &delegator_withdraw_private_key, delegator_address, delegator_amount, 1, rng)
        .unwrap();
    let unbond_height = unbond_state(&store, delegator_address).unwrap().unwrap().1;

    // Check that the bond, unbond, and withdraw states are correct.
    assert_eq!(account_balance(&store, delegator_address).unwrap(), delegator_balance - delegator_amount);
    assert!(account_balance(&store, &delegator_withdrawal_address).is_err());
    assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
    assert_eq!(unbond_state(&store, delegator_address).unwrap().unwrap().0, delegator_amount);
    assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(delegator_withdrawal_address));

    /* Ensure that claiming an unbond after the unlock height succeeds. */
    claim_unbond_public(&process, &store, delegator_private_key, delegator_address, unbond_height, rng).unwrap();

    // Check that the bond, unbond, and withdraw states are correct.
    assert_eq!(account_balance(&store, delegator_address).unwrap(), delegator_balance - delegator_amount);
    assert_eq!(account_balance(&store, &delegator_withdrawal_address).unwrap(), delegator_amount);
    assert_eq!(bond_state(&store, delegator_address).unwrap(), None);
    assert_eq!(unbond_state(&store, delegator_address).unwrap(), None);
    assert_eq!(withdraw_state(&store, delegator_address).unwrap(), None);

    // Unbond the validator completely.
    unbond_public(&process, &store, withdrawal_private_key, validator_address, validator_amount, unbond_height, rng)
        .unwrap();
    let unbond_height = unbond_state(&store, validator_address).unwrap().unwrap().1;

    // Check that the bond, unbond, and withdraw states are correct.
    assert_eq!(account_balance(&store, validator_address).unwrap(), validator_balance - validator_amount);
    assert!(account_balance(&store, withdrawal_address).is_err());
    assert_eq!(bond_state(&store, validator_address).unwrap(), None);
    assert_eq!(unbond_state(&store, validator_address).unwrap().unwrap().0, validator_amount);
    assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

    /* Ensure that claiming an unbond after the unlock height succeeds. */
    claim_unbond_public(&process, &store, validator_private_key, validator_address, unbond_height, rng).unwrap();

    // Check that the bond, unbond, and withdraw states are correct.
    assert_eq!(account_balance(&store, validator_address).unwrap(), validator_balance - validator_amount);
    assert_eq!(account_balance(&store, withdrawal_address).unwrap(), validator_amount);
    assert_eq!(bond_state(&store, validator_address).unwrap(), None);
    assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&store, validator_address).unwrap(), None);
}

#[test]
fn test_bonding_multiple_stakers_to_same_withdrawal_address() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, delegators) = initialize_stakers(&store, 1, 1, rng).unwrap();
    let (validator_private_key, (validator_address, _, _, withdrawal_address)) = validators.first().unwrap();
    let (delegator_private_key, (delegator_address, _)) = delegators.first().unwrap();

    // Bond the validator the withdrawal address.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Prepare the delegator amount.
    let delegator_amount = MIN_DELEGATOR_STAKE;
    // Bond the delegator the same withdrawal address.
    bond_public(&process, &store, delegator_private_key, validator_address, withdrawal_address, delegator_amount, rng)
        .unwrap();

    // Check that the withdraw state is correct.
    assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));
    assert_eq!(withdraw_state(&store, delegator_address).unwrap(), Some(*withdrawal_address));
}

#[test]
fn test_claim_unbond_public_removes_withdraw_mapping() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (validator_address, _, withdrawal_private_key, withdrawal_address)) =
        validators.first().unwrap();

    // Retrieve the account balance.
    let validator_balance = account_balance(&store, validator_address).unwrap();

    // Bond the validator the withdrawal address.
    let validator_amount = MIN_VALIDATOR_STAKE * 2;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Unbond half of the validator's stake.
    let unbond_amount = validator_amount / 2;
    unbond_public(&process, &store, withdrawal_private_key, validator_address, unbond_amount, 1, rng).unwrap();
    let unbond_height = unbond_state(&store, validator_address).unwrap().unwrap().1;

    /* Ensure that claiming an unbond after the unlock height succeeds. */
    claim_unbond_public(&process, &store, validator_private_key, validator_address, unbond_height, rng).unwrap();

    // Check that the account, bond, unbond, and withdraw states are correct.
    assert_eq!(account_balance(&store, validator_address).unwrap(), validator_balance - validator_amount);
    assert_eq!(account_balance(&store, withdrawal_address).unwrap(), unbond_amount);
    assert_eq!(
        bond_state(&store, validator_address).unwrap(),
        Some((*validator_address, validator_amount - unbond_amount))
    );
    assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&store, validator_address).unwrap(), Some(*withdrawal_address));

    // Unbond the remaining validator stake.
    unbond_public(&process, &store, withdrawal_private_key, validator_address, unbond_amount, unbond_height, rng)
        .unwrap();
    let unbond_height = unbond_state(&store, validator_address).unwrap().unwrap().1;

    /* Ensure that claiming an unbond after the unlock height succeeds. */
    claim_unbond_public(&process, &store, validator_private_key, validator_address, unbond_height, rng).unwrap();

    // Check that the account, bond, unbond, and withdraw states are correct.
    // The withdraw state should be removed after the last unbond is claimed.
    assert_eq!(account_balance(&store, validator_address).unwrap(), validator_balance - validator_amount);
    assert_eq!(account_balance(&store, withdrawal_address).unwrap(), validator_amount);
    assert_eq!(bond_state(&store, validator_address).unwrap(), None);
    assert_eq!(unbond_state(&store, validator_address).unwrap(), None);
    assert_eq!(withdraw_state(&store, validator_address).unwrap(), None);
}

#[test]
fn test_bond_validator_to_different_withdraw_address_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (_, _, _, withdrawal_address)) = validators.first().unwrap();

    // Bond the validator the withdrawal address.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Initialize a new withdraw address.
    let new_withdraw_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let new_withdraw_private_key = Address::try_from(&new_withdraw_private_key).unwrap();

    // Ensure that bonding to a different withdraw address fails.
    assert!(
        bond_validator(
            &process,
            &store,
            validator_private_key,
            &new_withdraw_private_key,
            validator_amount,
            TEST_COMMISSION,
            rng
        )
        .is_err()
    );
}

#[test]
fn test_bond_validator_with_different_commission_fails() {
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Initialize a new finalize store.
    let store = sample_finalize_store!();

    // Initialize the validators and delegators.
    let (validators, _) = initialize_stakers(&store, 1, 0, rng).unwrap();
    let (validator_private_key, (_, _, _, withdrawal_address)) = validators.first().unwrap();

    // Bond the validator the withdrawal address.
    let validator_amount = MIN_VALIDATOR_STAKE;
    bond_validator(&process, &store, validator_private_key, withdrawal_address, validator_amount, TEST_COMMISSION, rng)
        .unwrap();

    // Ensure that bonding to a different withdraw address fails.
    assert!(
        bond_validator(
            &process,
            &store,
            validator_private_key,
            withdrawal_address,
            validator_amount,
            TEST_COMMISSION + 1,
            rng
        )
        .is_err()
    );
}

// Test cases:

//   set_validator_state:
//   Validator can't bond to himself if closed.
//   Delegator can't bond to closed validator.

//  unbond_delegator_as_validator:
//  Validator can unbond delegator if closed.
//  Validator can't unbond delegator that is not bonded to him.
//  Validator can't unbond delegator if open.

//  Check that Validator/Delegator Unbonding updates the unbond height and updates the balance correctly.

// claim_unbond:
// Staker can claim unbond if the unbonding period has passed.
// Staker can't claim unbond if the unbonding period has not passed.

mod sanity_checks {
    use super::*;
    use crate::{Assignments, CallStack, Stack, tests::test_utils::shared_process};
    use circuit::Assignment;
    use console::{program::Request, types::Field};
    use snarkvm_synthesizer_program::StackTrait;

    fn get_assignment<N: Network, A: circuit::Aleo<Network = N>>(
        stack: &Stack<N>,
        private_key: &PrivateKey<N>,
        function_name: Identifier<N>,
        inputs: &[Value<N>],
        rng: &mut TestRng,
    ) -> Assignment<<N as Environment>::Field> {
        // Retrieve the program.
        let program = stack.program();
        // Get the program ID.
        let program_id = *program.id();
        // Retrieve the input types.
        let input_types = program.get_function(&function_name).unwrap().input_types();
        // Retrieve the program checksum, if the program has a constructor.
        let program_checksum = match stack.program().contains_constructor() {
            true => Some(stack.program_checksum_as_field().unwrap()),
            false => None,
        };
        // Sample 'root_tvk'.
        let root_tvk = None;
        // Set 'is_root' to true.
        let is_root = true;
        // Compute the request.
        let request = Request::sign(
            private_key,
            program_id,
            function_name,
            inputs.iter(),
            &input_types,
            root_tvk,
            is_root,
            program_checksum,
            false,
            rng,
        )
        .unwrap();
        // Initialize the assignments.
        let assignments = Assignments::<N>::default();
        // Initialize the call stack.
        let call_stack = CallStack::CheckDeployment(vec![request], *private_key, assignments.clone(), None, None, None);
        // Synthesize the circuit.
        let _response = stack.execute_function::<A, _>(call_stack, None, None, rng).unwrap();
        // Retrieve the assignment.
        assignments.read().last().unwrap().0.clone()
    }

    #[test]
    fn test_sanity_check_transfer_private() {
        let rng = &mut TestRng::default();

        // Initialize a new caller account.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let caller = Address::try_from(&private_key).unwrap();

        // Retrieve the stack.
        let stack = shared_process().get_stack(ProgramID::from_str("credits.aleo").unwrap()).unwrap();

        // Declare the function name.
        let function_name = Identifier::from_str("transfer_private").unwrap();

        // Declare the inputs.
        let r0 = Value::from_str(&format!(
            "{{ owner: {caller}.private, microcredits: 1_500_000_000_000_000_u64.private, _nonce: {}.public, _version: 1u8.public }}",
            console::types::Group::<CurrentNetwork>::zero()
        ))
        .unwrap();
        let r1 = Value::<CurrentNetwork>::from_str(&format!("{caller}")).unwrap();
        let r2 = Value::<CurrentNetwork>::from_str("1_500_000_000_000_000_u64").unwrap();

        // Compute the assignment.
        let assignment = get_assignment::<_, CurrentAleo>(&stack, &private_key, function_name, &[r0, r1, r2], rng);
        assert_eq!(18, assignment.num_public());
        assert_eq!(62398, assignment.num_private());
        assert_eq!(62461, assignment.num_constraints());
        assert_eq!((121399, 135544, 94473), assignment.num_nonzeros());
    }

    #[test]
    fn test_sanity_check_transfer_public() {
        let rng = &mut TestRng::default();

        // Initialize a new caller account.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let caller = Address::try_from(&private_key).unwrap();

        // Retrieve the stack.
        let stack = shared_process().get_stack(ProgramID::from_str("credits.aleo").unwrap()).unwrap();

        // Declare the function name.
        let function_name = Identifier::from_str("transfer_public").unwrap();

        // Declare the inputs.
        let r0 = Value::<CurrentNetwork>::from_str(&format!("{caller}")).unwrap();
        let r1 = Value::<CurrentNetwork>::from_str("1_500_000_000_000_000_u64").unwrap();

        // Compute the assignment.
        let assignment = get_assignment::<_, CurrentAleo>(&stack, &private_key, function_name, &[r0, r1], rng);
        assert_eq!(11, assignment.num_public());
        assert_eq!(12318, assignment.num_private());
        assert_eq!(12325, assignment.num_constraints());
        assert_eq!((28243, 38006, 16679), assignment.num_nonzeros());
    }

    #[test]
    fn test_sanity_check_transfer_public_as_signer() {
        let rng = &mut TestRng::default();

        // Initialize a new signer account.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let signer = Address::try_from(&private_key).unwrap();

        // Retrieve the stack.
        let stack = shared_process().get_stack(ProgramID::from_str("credits.aleo").unwrap()).unwrap();

        // Declare the function name.
        let function_name = Identifier::from_str("transfer_public_as_signer").unwrap();

        // Declare the inputs.
        let r0 = Value::<CurrentNetwork>::from_str(&format!("{signer}")).unwrap();
        let r1 = Value::<CurrentNetwork>::from_str("1_500_000_000_000_000_u64").unwrap();

        // Compute the assignment.
        let assignment = get_assignment::<_, CurrentAleo>(&stack, &private_key, function_name, &[r0, r1], rng);
        assert_eq!(11, assignment.num_public());
        assert_eq!(12323, assignment.num_private());
        assert_eq!(12330, assignment.num_constraints());
        assert_eq!((28257, 38029, 16684), assignment.num_nonzeros());
    }

    #[test]
    fn test_sanity_check_fee_private() {
        let rng = &mut TestRng::default();

        // Initialize a new caller account.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let caller = Address::try_from(&private_key).unwrap();

        // Retrieve the stack.
        let stack = shared_process().get_stack(ProgramID::from_str("credits.aleo").unwrap()).unwrap();

        // Declare the function name.
        let function_name = Identifier::from_str("fee_private").unwrap();

        // Declare the inputs.
        let r0 = Value::from_str(&format!(
            "{{ owner: {caller}.private, microcredits: 1_500_000_000_000_000_u64.private, _nonce: {}.public, _version: 1u8.public }}",
            console::types::Group::<CurrentNetwork>::zero()
        ))
        .unwrap();
        let r1 = Value::<CurrentNetwork>::from_str("1_000_000_000_000_000_u64").unwrap();
        let r2 = Value::<CurrentNetwork>::from_str("500_000_000_000_000_u64").unwrap();
        let r3 = Value::<CurrentNetwork>::from_str(&Field::<CurrentNetwork>::rand(rng).to_string()).unwrap();

        // Compute the assignment.
        let assignment = get_assignment::<_, CurrentAleo>(&stack, &private_key, function_name, &[r0, r1, r2, r3], rng);
        assert_eq!(16, assignment.num_public());
        assert_eq!(45456, assignment.num_private());
        assert_eq!(45502, assignment.num_constraints());
        assert_eq!((86974, 97373, 67786), assignment.num_nonzeros());
    }

    #[test]
    fn test_sanity_check_fee_public() {
        let rng = &mut TestRng::default();

        // Initialize a new caller account.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // Retrieve the stack.
        let stack = shared_process().get_stack(ProgramID::from_str("credits.aleo").unwrap()).unwrap();

        // Declare the function name.
        let function_name = Identifier::from_str("fee_public").unwrap();

        // Declare the inputs.
        let r0 = Value::<CurrentNetwork>::from_str("1_000_000_000_000_000_u64").unwrap();
        let r1 = Value::<CurrentNetwork>::from_str("500_000_000_000_000_u64").unwrap();
        let r2 = Value::<CurrentNetwork>::from_str(&Field::<CurrentNetwork>::rand(rng).to_string()).unwrap();

        // Compute the assignment.
        let assignment = get_assignment::<_, CurrentAleo>(&stack, &private_key, function_name, &[r0, r1, r2], rng);
        assert_eq!(12, assignment.num_public());
        assert_eq!(12920, assignment.num_private());
        assert_eq!(12930, assignment.num_constraints());
        assert_eq!((30587, 41288, 17213), assignment.num_nonzeros());
    }
}
