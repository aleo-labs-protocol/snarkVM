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

//! The cost of proving `credits.aleo` transfers at the latest consensus version.

#[macro_use]
extern crate criterion;

mod transaction_common;

use snarkvm_console::{account::*, network::MainnetV0, program::Value};

use criterion::Criterion;
use std::time::Duration;

/// Fixed RNG seed so benchmark inputs are reproducible across runs.
const BENCH_RNG_SEED: u64 = 0xB34D_CAFE_CDEC_0123;

fn prove(c: &mut Criterion) {
    let rng = &mut TestRng::fixed(BENCH_RNG_SEED);

    let private_key = PrivateKey::<MainnetV0>::new(rng).unwrap();
    let address = Value::<MainnetV0>::from_str(&Address::try_from(&private_key).unwrap().to_string()).unwrap();
    let amount = Value::<MainnetV0>::from_str("1u64").unwrap();

    let (ledger, records) = transaction_common::initialize_vm(&private_key, rng);
    let vm = ledger.vm();

    // Proving takes seconds, so ten samples, criterion's minimum. A window larger than about one
    // iteration per sample multiplies the cost without resolving more; expect a warning that the
    // samples did not fit.
    let mut group = c.benchmark_group("prove");
    group.sample_size(10).measurement_time(Duration::from_secs(60));

    for (function, inputs) in [
        ("transfer_public", vec![address.clone(), amount.clone()]),
        ("transfer_private", vec![Value::Record(records[0].clone()), address, amount]),
    ] {
        let execute_authorization = vm.authorize(&private_key, "credits.aleo", function, inputs, rng).unwrap();
        let execution_id = execute_authorization.to_execution_id().unwrap();
        let fee_authorization = vm.authorize_fee_public(&private_key, 300000, 1000, execution_id, rng).unwrap();

        group.bench_function(format!("Transaction::Execute({function})"), |b| {
            b.iter(|| {
                vm.execute_authorization(
                    execute_authorization.replicate(),
                    Some(fee_authorization.replicate()),
                    None,
                    rng,
                )
                .unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, prove);

criterion_main!(benches);
