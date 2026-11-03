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
type F = Field<Console>;

fn poseidon2(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Poseidon2::<Console>::setup("Poseidon2").unwrap();

    let input = [F::rand(rng), F::rand(rng), F::rand(rng), F::rand(rng)];
    c.bench_function("Poseidon2 Hash 4 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon2 Hash 4 -> 2", |b| b.iter(|| hash.hash_many(&input, 2)));

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

    let input: Vec<_> = (0..10).map(|_| F::rand(rng)).collect();
    c.bench_function("Poseidon8 Hash 10 -> 1", |b| b.iter(|| hash.hash(&input)));
    c.bench_function("Poseidon8 Hash 10 -> 4", |b| b.iter(|| hash.hash_many(&input, 4)));
    c.bench_function("Poseidon8 Hash 10 -> 8", |b| b.iter(|| hash.hash_many(&input, 8)));
}

criterion_group! {
    name = sponge;
    config = Criterion::default().sample_size(10);
    targets = poseidon2, poseidon4, poseidon8,
}

criterion_main!(sponge);
