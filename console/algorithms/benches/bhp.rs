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

use snarkvm_console_algorithms::{BHP, BHP256, BHP512, BHP768, BHP1024};
use snarkvm_console_types::prelude::*;
use snarkvm_utilities::{TestRng, Uniform};

use criterion::Criterion;
use std::hint::black_box;

fn bhp256(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = BHP256::<Console>::setup("BHP256").unwrap();

    let input = (0..hash.window_size() as u64 * hash.num_windows() as u64).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP256 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));

    let input = (0..256).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP256 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}

fn bhp512(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = BHP512::<Console>::setup("BHP512").unwrap();

    let input = (0..hash.window_size() as u64 * hash.num_windows() as u64).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP512 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));

    let input = (0..512).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP512 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}

fn bhp768(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = BHP768::<Console>::setup("BHP768").unwrap();

    let input = (0..hash.window_size() as u64 * hash.num_windows() as u64).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP768 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));

    let input = (0..768).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP768 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}

fn bhp1024(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = BHP1024::<Console>::setup("BHP1024").unwrap();

    let input = (0..hash.window_size() as u64 * hash.num_windows() as u64).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP1024 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));

    let input = (0..1024).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("BHP1024 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}

fn bhp1024_large(c: &mut Criterion) {
    const SIZE_IN_BYTES: [usize; 4] =
        [1_000 /* 1 kB */, 10_000 /* 10 kB */, 100_000 /* 100 kB */, 1_000_000 /* 1 MB */];
    let rng = &mut TestRng::default();

    // Benchmark the BHP1024 hash function for different input sizes.
    for size in SIZE_IN_BYTES.iter() {
        let input = (0..size * 8).map(|_| bool::rand(rng)).collect::<Vec<_>>();
        c.bench_function(&format!("BHP1024 Hash - input size {size} bytes"), |b| {
            b.iter(|| BHP1024::<Console>::setup("BHP1024").unwrap().hash(&input))
        });
    }
}

/// 8 hashes of `len` bits, which take one iteration: one by one in the `scalar` row, and by `hash_8` in the `lanes`
/// row. Each row times all 8 hashes, on the next of 64 batches of random inputs.
///
/// The `lanes` row runs only where `hash_8` runs the hashes in AVX-512 IFMA lanes: not on a CPU without AVX-512
/// IFMA, and not with `SNARKVM_NO_IFMA` set.
fn bhp_x8_with<const NUM_WINDOWS: u8, const WINDOW_SIZE: u8>(c: &mut Criterion, name: &str, len: usize) {
    let rng = &mut TestRng::default();
    let hash = BHP::<Console, NUM_WINDOWS, WINDOW_SIZE>::setup(name).unwrap();

    let batches: Vec<[Vec<bool>; 8]> =
        (0..64).map(|_| std::array::from_fn(|_| (0..len).map(|_| bool::rand(rng)).collect())).collect();
    let batches: Vec<[&[bool]; 8]> = batches.iter().map(|batch| batch.each_ref().map(Vec::as_slice)).collect();
    let mut batches = batches.iter().cycle();
    // The iterator of a cycle over 64 batches never ends.
    let mut next = || *batches.next().unwrap();

    c.bench_function(&format!("{name} Hash - input size {len} x8 scalar"), |b| {
        b.iter(|| black_box(next()).map(|input| hash.hash(input)))
    });
    if hash.hash_8_lanes(next()).is_some() {
        c.bench_function(&format!("{name} Hash - input size {len} x8 lanes"), |b| {
            b.iter(|| hash.hash_8(black_box(next())))
        });
    }
}

fn bhp_x8(c: &mut Criterion) {
    // A Merkle path hash: a bit and two fields.
    bhp_x8_with::<6, 43>(c, "BHP512", 507);
    // A transition leaf hash: a bit, three bytes and a field.
    bhp_x8_with::<8, 54>(c, "BHP1024", 278);
}

criterion_group! {
    name = bhp;
    config = Criterion::default().sample_size(1000);
    targets = bhp256, bhp512, bhp768, bhp1024
}

criterion_group! {
    name = bhp_large;
    config = Criterion::default().sample_size(100);
    targets = bhp1024_large
}

criterion_group! {
    name = bhp_lanes;
    config = Criterion::default().sample_size(100);
    targets = bhp_x8
}

criterion_main!(bhp, bhp_large, bhp_lanes);
