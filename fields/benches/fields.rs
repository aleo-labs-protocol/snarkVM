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

use snarkvm_fields::{Field, Fp256, Fp384, PrimeField};
use snarkvm_utilities::TestRng;

use criterion::*;
use rand::RngExt;
use std::{
    hint::black_box,
    ops::{AddAssign, MulAssign, SubAssign},
};

fn fp256(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    const N: usize = 1_000;

    let mut values = Vec::with_capacity(N);
    let mut arr = [0u8; 32];

    while values.len() < N {
        rng.fill(&mut arr);
        if let Some(v) = Fp256::<snarkvm_curves::bls12_377::FrParameters>::from_random_bytes(&arr) {
            values.push(v);
        }
    }

    c.bench_function("fp256_add_assign", |b| {
        b.iter(|| {
            for (mut v1, v2) in values.iter().cloned().zip(values.iter().skip(1)) {
                black_box(v1.add_assign(v2));
            }
        })
    });

    c.bench_function("fp256_sub_assign", |b| {
        b.iter(|| {
            for (mut v1, v2) in values.iter().cloned().zip(values.iter().skip(1)) {
                black_box(v1.sub_assign(v2));
            }
        })
    });

    c.bench_function("fp256_mul_assign", |b| {
        b.iter(|| {
            for (mut v1, v2) in values.iter().cloned().zip(values.iter().skip(1)) {
                black_box(v1.mul_assign(v2));
            }
        })
    });

    c.bench_function("fp256_inverse", |b| {
        b.iter(|| {
            for v in values.iter() {
                black_box(v.inverse());
            }
        })
    });

    c.bench_function("fp256_square_in_place", |b| {
        b.iter(|| {
            for mut v in values.iter().cloned() {
                black_box(v.square_in_place());
            }
        })
    });

    c.bench_function("fp256_to_bigint", |b| {
        b.iter(|| {
            for v in values.iter() {
                black_box(v.to_bigint());
            }
        })
    });
}

fn fp384(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    const N: usize = 1_000;

    let mut values = Vec::with_capacity(N);
    let mut arr = [0u8; 48];

    while values.len() < N {
        rng.fill(&mut arr[..32]);
        rng.fill(&mut arr[32..]);
        if let Some(v) = Fp384::<snarkvm_curves::bls12_377::FqParameters>::from_random_bytes(&arr) {
            values.push(v);
        }
    }

    c.bench_function("fp384_add_assign", |b| {
        b.iter(|| {
            for (mut v1, v2) in values.iter().cloned().zip(values.iter().skip(1)) {
                black_box(v1.add_assign(v2));
            }
        })
    });

    c.bench_function("fp384_sub_assign", |b| {
        b.iter(|| {
            for (mut v1, v2) in values.iter().cloned().zip(values.iter().skip(1)) {
                black_box(v1.sub_assign(v2));
            }
        })
    });

    c.bench_function("fp384_mul_assign", |b| {
        b.iter(|| {
            for (mut v1, v2) in values.iter().cloned().zip(values.iter().skip(1)) {
                black_box(v1.mul_assign(v2));
            }
        })
    });

    c.bench_function("fp384_inverse", |b| {
        b.iter(|| {
            for v in values.iter() {
                black_box(v.inverse());
            }
        })
    });

    c.bench_function("fp384_square_in_place", |b| {
        b.iter(|| {
            for mut v in values.iter().cloned() {
                black_box(v.square_in_place());
            }
        })
    });

    c.bench_function("fp384_to_bigint", |b| {
        b.iter(|| {
            for v in values.iter() {
                black_box(v.to_bigint());
            }
        })
    });
}

criterion_group! {
    name = fields;
    config = Criterion::default();
    targets = fp256, fp384
}

criterion_main!(fields);
