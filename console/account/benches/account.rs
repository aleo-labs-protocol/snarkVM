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

use snarkvm_console_account::{Address, PrivateKey, ViewKey};
use snarkvm_console_network::{MainnetV0, environment::prelude::*};

use criterion::Criterion;

type CurrentNetwork = MainnetV0;

fn account_private_key(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    c.bench_function("account_private_key", move |b| {
        b.iter(|| {
            let _private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        })
    });
}

fn account_view_key(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    c.bench_function("account_view_key", move |b| {
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        b.iter(|| {
            let _view_key = ViewKey::try_from(&private_key).unwrap();
        })
    });
}

fn account_address(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    c.bench_function("account_address", move |b| {
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        b.iter(|| {
            let _address = Address::try_from(&private_key).unwrap();
        })
    });
}

criterion_group! {
    name = account;
    config = Criterion::default().sample_size(10);
    targets = account_private_key, account_view_key, account_address
}

criterion_main!(account);
