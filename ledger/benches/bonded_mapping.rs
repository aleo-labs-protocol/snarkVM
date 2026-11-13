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

#[macro_use]
extern crate criterion;

use snarkvm_console::{
    account::{Address, Field, PrivateKey},
    collections::U64,
    network::MainnetV0,
    program::{Identifier, Literal, Plaintext, ProgramID, Value},
};
use snarkvm_ledger_committee::{MAX_DELEGATORS, MIN_DELEGATOR_STAKE};
use snarkvm_ledger_store::ConsensusStore;
use snarkvm_synthesizer::VM;

use snarkvm_ledger_store::StorageMode;
#[cfg(not(feature = "rocks"))]
use snarkvm_ledger_store::helpers::memory::ConsensusMemory;
#[cfg(feature = "rocks")]
use snarkvm_ledger_store::helpers::rocksdb::ConsensusDB;

use criterion::Criterion;
use indexmap::indexmap;
use std::{str::FromStr, time::Duration};

pub type CurrentNetwork = MainnetV0;
#[cfg(feature = "rocks")]
pub type CurrentStorage = ConsensusDB<CurrentNetwork>;
#[cfg(not(feature = "rocks"))]
pub type CurrentStorage = ConsensusMemory<CurrentNetwork>;

pub const BONDED_INTERVALS: &[usize; 7] = &[10, 5_000, 10_000, 20_000, 40_000, 80_000, 100_000];

fn bench_bonded_mappings(c: &mut Criterion) {
    // Construct the credits.aleo program ID.
    let credits_program_id = ProgramID::from_str("credits.aleo").unwrap();
    // Construct the bonded mapping name.
    let bonded_mapping = Identifier::from_str("bonded").unwrap();
    // Construct the bond_state identifiers.
    let validator_identifier = Identifier::from_str("validator").unwrap();
    let microcredits_identifier = Identifier::from_str("microcredits").unwrap();
    // Create a DB store for the consensus.
    let store = ConsensusStore::<CurrentNetwork, CurrentStorage>::open(StorageMode::new_test(None)).unwrap();
    // Create a VM from the store.
    let vm = VM::from(store).unwrap();
    // Create a sample validator address.
    let validator_address =
        Address::from_str("aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px").unwrap();

    // Generate 100_000 bonded mapping entries.
    let bonded_map = (0..(MAX_DELEGATORS as u64))
        .map(|i| {
            // Generate a staker address.
            let private_key = PrivateKey::try_from(Field::from_u64(i)).unwrap();
            let staker_address = Address::<CurrentNetwork>::try_from(&private_key).unwrap();

            // Create the bonded state.
            let bonded_state = indexmap! {
                validator_identifier => Plaintext::from(Literal::Address(validator_address)),
                microcredits_identifier => Plaintext::from(Literal::U64(U64::new(MIN_DELEGATOR_STAKE))),
            };
            (
                Plaintext::from(Literal::Address(staker_address)),
                Value::Plaintext(Plaintext::Struct(bonded_state, Default::default())),
            )
        })
        .collect::<Vec<(Plaintext<CurrentNetwork>, Value<CurrentNetwork>)>>();

    // Get a key that exists within the bonded mapping.
    let private_key = PrivateKey::try_from(Field::from_u64(5)).unwrap();
    let staker_address = Address::<CurrentNetwork>::try_from(&private_key).unwrap();
    let key = Plaintext::from(Literal::Address(staker_address));

    // Insert increasing numbers of entries into the bonded mapping and bench get_value_speculative and get_value_confirmed at each interval.
    BONDED_INTERVALS.iter().for_each(|num_entries| {
        let entries = bonded_map.iter().take(*num_entries).cloned().collect::<Vec<_>>();
        vm.finalize_store().replace_mapping(credits_program_id, bonded_mapping, entries).unwrap();

        // Benchmark get_value_speculative on the bonded mapping.
        c.bench_function(&format!("bonded mapping - get_value_speculative - {num_entries} entries"), |b| {
            b.iter(|| {
                vm.finalize_store().get_value_speculative(credits_program_id, bonded_mapping, &key).unwrap();
            })
        });

        // Benchmark get_value_confirmed on the bonded mapping.
        c.bench_function(&format!("bonded mapping - get_value_confirmed - {num_entries} entries"), |b| {
            b.iter(|| {
                vm.finalize_store().get_value_confirmed(credits_program_id, bonded_mapping, &key).unwrap();
            })
        });
    });
}

criterion_group! {
    name = mappings;
    config = Criterion::default().sample_size(100).measurement_time(Duration::from_secs(10));
    targets = bench_bonded_mappings
}
criterion_main!(mappings);
