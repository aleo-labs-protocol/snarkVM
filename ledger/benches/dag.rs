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

use snarkvm_console::prelude::*;
use snarkvm_ledger::narwhal::subdag::test_helpers::sample_subdag;
use snarkvm_utilities::bytes::unchecked_deserialize;

use criterion::{Criterion, criterion_group, criterion_main};

/// Fixed RNG seed so benchmark inputs are reproducible across CI runs.
const BENCH_RNG_SEED: u64 = 0x00BA_6DAB_5EED_00D1;

/// Helper method to benchmark serialization.
fn bench_serialization<T: Serialize + DeserializeOwned + ToBytes + FromBytes + Clone>(
    c: &mut Criterion,
    name: &str,
    object: T,
) {
    ///////////////
    // Serialize //
    ///////////////

    // snarkvm_utilities::ToBytes
    c.bench_function(&format!("{name}::to_bytes_le"), |b| b.iter(|| object.to_bytes_le().unwrap()));

    // bincode::serialize
    c.bench_function(&format!("{name}::serialize (bincode)"), |b| b.iter(|| bincode::serialize(&object).unwrap()));

    // serde_json::to_string
    c.bench_function(&format!("{name}::to_string (serde_json)"), |b| {
        b.iter(|| serde_json::to_string(&object).unwrap())
    });

    /////////////////
    // Deserialize //
    /////////////////

    // snarkvm_utilities::FromBytes
    {
        let buffer = object.to_bytes_le().unwrap();
        c.bench_function(&format!("{name}::from_bytes_le"), |b| b.iter(|| T::from_bytes_le(&buffer).unwrap()));

        c.bench_function(&format!("{name}::from_bytes_le_unchecked"), |b| {
            b.iter(|| T::from_bytes_le_unchecked(&buffer).unwrap())
        });
    }

    // bincode::deserialize and unchecked_deserialize.
    {
        let buffer = bincode::serialize(&object).unwrap();
        c.bench_function(&format!("{name}::deserialize (bincode)"), |b| {
            b.iter(|| bincode::deserialize::<T>(&buffer).unwrap())
        });

        c.bench_function(&format!("{name}::unchecked_deserialize (bincode)"), |b| {
            b.iter(|| unchecked_deserialize::<T>(&buffer).unwrap())
        });
    }

    // serde_json::from_str
    {
        let object = serde_json::to_string(&object).unwrap();
        c.bench_function(&format!("{name}::from_str (serde_json)"), move |b| {
            b.iter(|| serde_json::from_str::<T>(&object).unwrap())
        });
    }
}

fn subdag_serialization(c: &mut Criterion) {
    let rng = &mut TestRng::fixed(BENCH_RNG_SEED);
    let subdag = sample_subdag(rng);
    let batch = subdag.iter().next().unwrap().1.iter().next().unwrap().clone();
    let batch_header = batch.batch_header().clone();

    bench_serialization(c, "BatchHeader", batch_header);
    bench_serialization(c, "BatchCertificate", batch);
    bench_serialization(c, "Subdag", subdag.clone());
}

criterion_group!(subdag, subdag_serialization);

criterion_main!(subdag);
