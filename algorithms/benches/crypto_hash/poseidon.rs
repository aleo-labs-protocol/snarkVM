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

use snarkvm_algorithms::{AlgebraicSponge, crypto_hash::PoseidonSponge};
use snarkvm_curves::bls12_377::{Fq, FqParameters};
use snarkvm_fields::Fp384;
use snarkvm_utilities::{TestRng, Uniform};

use criterion::Criterion;
use std::{hint::black_box, ops::MulAssign, time::Duration};

fn sponge_2_1_absorb_100_native(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let mut sponge = PoseidonSponge::<Fq, 2, 1>::new();

    let mut input = Vec::with_capacity(100);
    for _ in 0..100 {
        input.push(Fq::rand(rng));
    }
    c.bench_function("PoseidonSponge<2, 1> Absorb 100 native", move |b| {
        b.iter(|| sponge.absorb_native_field_elements(&input))
    });
}

fn sponge_2_1_absorb_100_nonnative(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let mut sponge = PoseidonSponge::<Fq, 2, 1>::new();

    let mut input = Vec::with_capacity(100);
    for _ in 0..100 {
        input.push(Fp384::<FqParameters>::rand(rng));
    }
    c.bench_function("PoseidonSponge<2, 1> Absorb 100 nonnative", move |b| {
        b.iter(|| sponge.absorb_nonnative_field_elements(input.clone()))
    });
}

/// Measurement only (aleo-measurements `research/poseidon-mds-split/`): one
/// permutation of `PoseidonSponge<Fq, 2, 1>` with each form of the MDS step,
/// and an `Fq` multiplication as a control. The rows run in reverse order if
/// `PSD_ORDER` is `reverse`.
fn poseidon_mds(c: &mut Criterion) {
    let parameters = PoseidonSponge::<Fq, 2, 1>::sample_parameters();
    let rng = &mut TestRng::fixed(1);
    let mut base = PoseidonSponge::<Fq, 2, 1>::new_with_parameters(&parameters);
    base.absorb_native_field_elements(&[Fq::rand(rng), Fq::rand(rng)]);

    // Every form agrees with `permute` on a chain of 1,000 from the same state.
    let mut chains = [base.clone(), base.clone(), base.clone(), base.clone(), base.clone()];
    for _ in 0..1000 {
        chains[0].bench_permute();
        chains[1].bench_permute_vec();
        chains[2].bench_permute_smallvec();
        chains[3].bench_permute_array9();
        chains[4].bench_permute_split();
    }
    for chain in &chains[1..] {
        assert_eq!(chains[0].bench_state(), chain.bench_state());
    }
    assert_ne!(chains[0].bench_state(), base.bench_state());
    println!("psd: checks passed");

    let [mut permute, mut vec, mut smallvec, mut array9, mut split] = chains;
    let pairs: Vec<(Fq, Fq)> = (0..1000).map(|_| (Fq::rand(rng), Fq::rand(rng))).collect();
    let mut count = 0;

    type Row<'a> = Box<dyn FnMut(&mut Criterion) + 'a>;
    let mut rows: Vec<Row> = vec![
        Box::new(|c| {
            c.bench_function("psd/permute_vec", |b| {
                b.iter(|| {
                    vec.bench_permute_vec();
                    black_box(&vec);
                })
            });
        }),
        Box::new(|c| {
            c.bench_function("psd/permute_smallvec", |b| {
                b.iter(|| {
                    smallvec.bench_permute_smallvec();
                    black_box(&smallvec);
                })
            });
        }),
        Box::new(|c| {
            c.bench_function("psd/permute_array9", |b| {
                b.iter(|| {
                    array9.bench_permute_array9();
                    black_box(&array9);
                })
            });
        }),
        Box::new(|c| {
            c.bench_function("psd/permute_split", |b| {
                b.iter(|| {
                    split.bench_permute_split();
                    black_box(&split);
                })
            });
        }),
        Box::new(|c| {
            c.bench_function("psd/permute", |b| {
                b.iter(|| {
                    permute.bench_permute();
                    black_box(&permute);
                })
            });
        }),
        Box::new(|c| {
            c.bench_function("psd/fq_mul_assign", |b| {
                b.iter(|| {
                    let mut tmp = pairs[count].0;
                    tmp.mul_assign(&pairs[count].1);
                    count = (count + 1) % pairs.len();
                    tmp
                })
            });
        }),
    ];
    if std::env::var("PSD_ORDER").is_ok_and(|order| order == "reverse") {
        rows.reverse();
    }
    for row in &mut rows {
        row(c);
    }
}

criterion_group! {
    name = psd;
    config = Criterion::default().measurement_time(Duration::from_secs(5)).warm_up_time(Duration::from_secs(2));
    targets = poseidon_mds
}

criterion_group! {
    name = sponge;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = sponge_2_1_absorb_100_native, sponge_2_1_absorb_100_nonnative
}

criterion_main!(sponge, psd);
