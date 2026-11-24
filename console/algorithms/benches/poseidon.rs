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

use snarkvm_console_algorithms::{Poseidon2, Poseidon4, Poseidon8};
use snarkvm_console_types::prelude::*;
use snarkvm_utilities::{TestRng, Uniform};

use criterion::Criterion;
use std::hint::black_box;
type F = Field<Console>;

fn poseidon2(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Poseidon2::<Console>::setup("Poseidon2").unwrap();

    let input = [F::rand(rng), F::rand(rng), F::rand(rng), F::rand(rng)];
    c.bench_function("Poseidon2 Hash 4 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon2 Hash 4 -> 2", |b| b.iter(|| hash.hash_many(&input, 2)));
    c.bench_function("Poseidon2 HashToGroup 4", |b| b.iter(|| hash.hash_to_group(&input)));

    let input: Vec<_> = (0..10).map(|_| F::rand(rng)).collect();
    c.bench_function("Poseidon2 Hash 10 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon2 Hash 10 -> 4", |b| b.iter(|| hash.hash_many(&input, 4)));
    c.bench_function("Poseidon2 Hash 10 -> 8", |b| b.iter(|| hash.hash_many(&input, 8)));
}

fn poseidon4(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Poseidon4::<Console>::setup("Poseidon4").unwrap();

    let input = [F::rand(rng), F::rand(rng), F::rand(rng), F::rand(rng)];
    c.bench_function("Poseidon4 Hash 4 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon4 Hash 4 -> 2", |b| b.iter(|| hash.hash_many(&input, 2)));
    c.bench_function("Poseidon4 HashToGroup 4", |b| b.iter(|| hash.hash_to_group(&input)));

    let input: Vec<_> = (0..10).map(|_| F::rand(rng)).collect();
    c.bench_function("Poseidon4 Hash 10 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon4 Hash 10 -> 4", |b| b.iter(|| hash.hash_many(&input, 4)));
    c.bench_function("Poseidon4 Hash 10 -> 8", |b| b.iter(|| hash.hash_many(&input, 8)));
}

fn poseidon8(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Poseidon8::<Console>::setup("Poseidon8").unwrap();

    let input = [F::rand(rng), F::rand(rng), F::rand(rng), F::rand(rng)];
    c.bench_function("Poseidon8 Hash 4 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon8 Hash 4 -> 2", |b| b.iter(|| hash.hash_many(&input, 2)));
    c.bench_function("Poseidon8 HashToGroup 4", |b| b.iter(|| hash.hash_to_group(&input)));

    let input: Vec<_> = (0..10).map(|_| F::rand(rng)).collect();
    c.bench_function("Poseidon8 Hash 10 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon8 Hash 10 -> 4", |b| b.iter(|| hash.hash_many(&input, 4)));
    c.bench_function("Poseidon8 Hash 10 -> 8", |b| b.iter(|| hash.hash_many(&input, 8)));
}

/// 8 hashes of 5 inputs, as the challenge of a signature takes, and of 16 inputs: one by one in the
/// `scalar` rows, and by `hash_8` in the `lanes` rows. Each row times all 8 hashes. A hash of 5
/// inputs takes one permutation after its cached first block, and a hash of 16 inputs takes two.
///
/// The `lanes` rows run only where `hash_8` runs the hashes in AVX-512 IFMA lanes: not on a CPU
/// without AVX-512 IFMA, and not with `SNARKVM_NO_IFMA` set.
fn poseidon8_x8(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Poseidon8::<Console>::setup("Poseidon8").unwrap();

    for len in [5, 16] {
        let inputs: [Vec<F>; 8] = std::array::from_fn(|_| (0..len).map(|_| F::rand(rng)).collect());
        let inputs = inputs.each_ref().map(Vec::as_slice);
        c.bench_function(&format!("Poseidon8 Hash {len} -> 1 x8 scalar"), |b| {
            b.iter(|| black_box(inputs).map(|input| hash.hash(input)))
        });
        if hash.hash_many_8_lanes(inputs, 1).is_some() {
            c.bench_function(&format!("Poseidon8 Hash {len} -> 1 x8 lanes"), |b| {
                b.iter(|| hash.hash_8(black_box(inputs)))
            });
        }
    }
}

criterion_group! {
    name = sponge;
    config = Criterion::default().sample_size(10);
    targets = poseidon2, poseidon4, poseidon8, poseidon8_x8,
}

criterion_main!(sponge);
