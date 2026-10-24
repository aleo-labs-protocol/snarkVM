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

use snarkvm_algorithms::msm::*;
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{PrimeField, Zero};
use snarkvm_utilities::{BigInteger, BitIteratorBE, TestRng, Uniform};

use criterion::Criterion;

#[macro_use]
extern crate criterion;

fn create_scalar_bases<G: AffineCurve<ScalarField = F>, F: PrimeField>(size: usize) -> (Vec<G>, Vec<F::BigInteger>) {
    let mut rng = TestRng::default();

    let bases = std::iter::repeat_n((0..(size / 1000)).map(|_| G::rand(&mut rng)).collect::<Vec<_>>(), 1000)
        .flatten()
        .collect::<Vec<_>>();
    let scalars = (0..size).map(|_| F::rand(&mut rng).to_bigint()).collect::<Vec<_>>();
    (bases, scalars)
}

fn variable_base_bls12_377(c: &mut Criterion) {
    use snarkvm_curves::bls12_377::{Fr, G1Affine};
    let (bases, scalars) = create_scalar_bases::<G1Affine, Fr>(1_000_000);

    for size in [10_000, 100_000, 1_000_000] {
        c.bench_function(&format!("VariableBase MSM on BLS12-377 ({size})"), |b| {
            b.iter(|| VariableBase::msm(&bases[..size], &scalars[..size]))
        });
    }
}

fn variable_base_edwards_bls12(c: &mut Criterion) {
    use snarkvm_curves::edwards_bls12::{EdwardsAffine, Fr};
    let (bases, scalars) = create_scalar_bases::<EdwardsAffine, Fr>(1_000_000);

    for size in [10_000, 100_000, 1_000_000] {
        c.bench_function(&format!("Variable MSM on Edwards-BLS12 ({size})"), |b| {
            b.iter(|| VariableBase::msm(&bases[..size], &scalars[..size]))
        });
    }
}

/// The bit-serial Shamir loop `batched::msm` ran below 32 bases before Straus's
/// method replaced it, kept as the baseline arm.
fn double_and_add<G: AffineCurve>(
    bases: &[G],
    scalars: &[<G::ScalarField as PrimeField>::BigInteger],
) -> G::Projective {
    let num_bits = G::ScalarField::size_in_bits();
    let bigint_size = <G::ScalarField as PrimeField>::BigInteger::NUM_LIMBS * 64;
    let mut bits =
        scalars.iter().map(|s| BitIteratorBE::new(s.as_ref()).skip(bigint_size - num_bits)).collect::<Vec<_>>();
    let mut sum = G::Projective::zero();

    let mut encountered_one = false;
    for _ in 0..num_bits {
        if encountered_one {
            sum.double_in_place();
        }
        for (bits, base) in bits.iter_mut().zip(bases) {
            if let Some(true) = bits.next() {
                sum.add_assign_mixed(base);
                encountered_one = true;
            }
        }
    }
    sum
}

fn small_variable_base_bls12_377(c: &mut Criterion) {
    use snarkvm_curves::bls12_377::{Fr, G1Affine};
    let mut rng = TestRng::default();
    let bases = (0..1024).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
    let scalars = (0..1024).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();

    let mut group = c.benchmark_group("small_msm");
    group.sample_size(60);
    group.bench_function("glv_mul/1", |b| b.iter(|| bases[0].to_projective() * Fr::from_bigint(scalars[0]).unwrap()));
    for n in [1, 2, 3, 4, 5, 7, 13, 14, 25, 26, 31, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024] {
        let (bases, scalars) = (&bases[..n], &scalars[..n]);
        if n <= 32 {
            group.bench_function(format!("double_and_add/{n}"), |b| b.iter(|| double_and_add(bases, scalars)));
            group.bench_function(format!("straus4/{n}"), |b| b.iter(|| batched::straus::<G1Affine, 4>(bases, scalars)));
            group.bench_function(format!("straus6/{n}"), |b| b.iter(|| batched::straus::<G1Affine, 6>(bases, scalars)));
        }
        group.bench_function(format!("straus5/{n}"), |b| b.iter(|| batched::straus::<G1Affine, 5>(bases, scalars)));
        group.bench_function(format!("batched/{n}"), |b| b.iter(|| batched::msm(bases, scalars)));
    }
    group.finish();
}

criterion_group! {
    name = variable_base_group;
    config = Criterion::default().sample_size(10);
    targets = small_variable_base_bls12_377, variable_base_bls12_377, variable_base_edwards_bls12
}

criterion_main!(variable_base_group);
