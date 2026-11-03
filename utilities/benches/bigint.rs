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

// Silences the false positives caused by black_box.
#![allow(clippy::unit_arg)]

use snarkvm_utilities::{BigInteger256, BigInteger384, TestRng};

use criterion::*;
use rand::RngExt;
use std::hint::black_box;

fn bigint_256(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    let n = 900_000;
    let values: Vec<BigInteger256> = (0..n).map(|_| rng.random()).collect();

    c.bench_function("bigint_256_cmp", |b| {
        b.iter_batched(
            || values.clone(),
            |mut data_to_sort| {
                data_to_sort.sort_unstable();
                black_box(data_to_sort)
            },
            criterion::BatchSize::LargeInput,
        )
    });
}

fn bigint_384(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    let n = 500_000;
    let values: Vec<BigInteger384> = (0..n).map(|_| rng.random()).collect();

    c.bench_function("bigint_384_cmp", |b| {
        b.iter_batched(
            || values.clone(),
            |mut data_to_sort| {
                data_to_sort.sort_unstable();
                black_box(data_to_sort)
            },
            criterion::BatchSize::LargeInput,
        )
    });
}

criterion_group! {
    name = bigint;
    config = Criterion::default();
    targets = bigint_256, bigint_384
}

criterion_main!(bigint);
