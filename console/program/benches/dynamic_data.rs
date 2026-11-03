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

use snarkvm_console_network::{MainnetV0, Network};
use snarkvm_console_program::{
    Argument,
    DynamicFuture,
    DynamicRecord,
    Entry,
    Future,
    Identifier,
    Literal,
    Plaintext,
    ProgramID,
};
use snarkvm_console_types::U64;
use snarkvm_utilities::{TestRng, Uniform};

use core::str::FromStr;
use criterion::Criterion;

type CurrentNetwork = MainnetV0;

fn bench_dynamic_future(c: &mut Criterion) {
    for count in [1, 4, 8, 16] {
        let args: Vec<Argument<CurrentNetwork>> =
            (0..count).map(|i| Argument::Plaintext(Plaintext::from_str(&format!("{i}u64")).unwrap())).collect();
        let future = Future::new(ProgramID::from_str("test.aleo").unwrap(), Identifier::from_str("foo").unwrap(), args);
        c.bench_function(&format!("DynamicFuture::from_future ({count} args)"), |b| {
            b.iter(|| DynamicFuture::from_future(&future).unwrap())
        });
    }
}

fn bench_dynamic_future_max_size(c: &mut Criterion) {
    // Build a maximum-sized array argument (512 field elements).
    let fields: Vec<String> = (0..CurrentNetwork::LATEST_MAX_ARRAY_ELEMENTS()).map(|j| format!("{j}field")).collect();
    let max_array_str = format!("[ {} ]", fields.join(", "));
    let max_array_arg = Argument::Plaintext(Plaintext::from_str(&max_array_str).unwrap());

    for count in [1, 2, 4, 8, 16] {
        let args: Vec<Argument<CurrentNetwork>> = (0..count).map(|_| max_array_arg.clone()).collect();
        let future = Future::new(ProgramID::from_str("test.aleo").unwrap(), Identifier::from_str("foo").unwrap(), args);
        c.bench_function(&format!("DynamicFuture::from_future ({count} max arrays)"), |b| {
            b.iter(|| DynamicFuture::from_future(&future).unwrap())
        });
    }
}

fn bench_dynamic_record(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    for num_entries in [1, 4, 8, 16, 32] {
        let mut data = indexmap::IndexMap::new();
        for i in 0..num_entries {
            let name = Identifier::from_str(&format!("entry_{i}")).unwrap();
            let entry = Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng))));
            data.insert(name, entry);
        }
        c.bench_function(&format!("DynamicRecord::merkleize_data ({num_entries} entries)"), |b| {
            b.iter(|| DynamicRecord::<CurrentNetwork>::merkleize_data(&data).unwrap())
        });
    }
}

fn bench_dynamic_record_max_size(c: &mut Criterion) {
    // Build a maximum-sized array plaintext (512 field elements).
    let fields: Vec<String> = (0..CurrentNetwork::LATEST_MAX_ARRAY_ELEMENTS()).map(|j| format!("{j}field")).collect();
    let max_array_str = format!("[ {} ]", fields.join(", "));
    let max_array_plaintext = Plaintext::<CurrentNetwork>::from_str(&max_array_str).unwrap();

    for num_entries in [1, 2, 4, 8, 16, 32] {
        let mut data = indexmap::IndexMap::new();
        for i in 0..num_entries {
            let name = Identifier::from_str(&format!("entry_{i}")).unwrap();
            let entry = Entry::Private(max_array_plaintext.clone());
            data.insert(name, entry);
        }
        c.bench_function(&format!("DynamicRecord::merkleize_data ({num_entries} max arrays)"), |b| {
            b.iter(|| DynamicRecord::<CurrentNetwork>::merkleize_data(&data).unwrap())
        });
    }
}

criterion_group! {
    name = dynamic_data;
    config = Criterion::default().sample_size(100);
    targets = bench_dynamic_future, bench_dynamic_future_max_size, bench_dynamic_record, bench_dynamic_record_max_size,
}

criterion_main!(dynamic_data);
