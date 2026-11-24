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
use snarkvm_curves::{
    AffineCurve,
    ProjectiveCurve,
    bls12_377::{FqParameters, Fr, G1Affine, G1Projective},
};
use snarkvm_fields::{PrimeField, Zero};
use snarkvm_utilities::{BigInteger, BigInteger256, BitIteratorBE, TestRng, Uniform};

use criterion::Criterion;
use itertools::Itertools;
use rand::RngExt;

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

/// A bit-serial Shamir loop over all bases, the baseline arm of `small_msm`.
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
        for (bits, base) in bits.iter_mut().zip_eq(bases) {
            if let Some(true) = bits.next() {
                sum.add_assign_mixed(base);
                encountered_one = true;
            }
        }
    }
    sum
}

fn small_variable_base_bls12_377(c: &mut Criterion) {
    let mut rng = TestRng::default();
    let bases = (0..1024).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
    let scalars = (0..1024).map(|_| Fr::rand(&mut rng).to_bigint()).collect::<Vec<_>>();

    let mut group = c.benchmark_group("small_msm");
    group.sample_size(60);
    // `scalars[0]` is the big integer of a field element, so it is below the
    // modulus.
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

/// The scalar path of `batched::msm` below 32 bases: GLV `mul` for one base,
/// Straus otherwise.
fn scalar_msm(terms: &[(G1Affine, Fr)]) -> G1Projective {
    if let [(base, scalar)] = terms {
        return *base * *scalar;
    }
    let (bases, scalars): (Vec<_>, Vec<_>) = terms.iter().map(|(base, scalar)| (*base, scalar.to_bigint())).unzip();
    batched::straus::<G1Affine, 5>(&bases, &scalars)
}

/// `scalar_*` and `lanes_*` time one MSM of `n` random bases with random
/// scalars below 2^168 or 2^253 by the scalar path and by the lanes. `many/*`
/// times `VariableBase::msm_many` of MSMs of the listed sizes. Each row cycles
/// through `SAMPLES` inputs. The
/// `lanes_*` rows run only where `ifma::is_supported` is true: on a CPU without
/// AVX-512 IFMA, or with `SNARKVM_NO_IFMA` set, `many/*` times the scalar path.
fn lane_msm_bls12_377(c: &mut Criterion) {
    const SAMPLES: usize = 16;
    let mut rng = TestRng::default();
    let short = |rng: &mut TestRng| {
        // The top word is zero and the third is shifted to below 2^40, so the integer
        // is below 2^168 < r.
        Fr::from_bigint(BigInteger256::new([rng.random(), rng.random(), rng.random::<u64>() >> 24, 0])).unwrap()
    };
    let lanes = snarkvm_fields::ifma::is_supported::<FqParameters>();
    let mut group = c.benchmark_group("lane_msm");
    for bits in [168, 253] {
        for n in [1, 2, 3, 4, 5, 7, 13, 14, 17, 25, 26, 30] {
            let inputs: Vec<Vec<_>> = (0..SAMPLES)
                .map(|_| {
                    (0..n)
                        .map(|_| {
                            let scalar = if bits == 168 { short(&mut rng) } else { Fr::rand(&mut rng) };
                            (G1Affine::rand(&mut rng), scalar)
                        })
                        .collect()
                })
                .collect();
            let mut count = 0;
            group.bench_function(format!("scalar_{bits}/{n}"), |b| {
                b.iter(|| {
                    count = (count + 1) % SAMPLES;
                    scalar_msm(&inputs[count])
                })
            });
            if lanes && n > 1 {
                group.bench_function(format!("lanes_{bits}/{n}"), |b| {
                    b.iter(|| {
                        count = (count + 1) % SAMPLES;
                        // This row runs only where the lanes run, on two or more terms, and
                        // there `msm_lanes` returns one sum.
                        G1Affine::msm_lanes(&[&inputs[count]]).expect("needs AVX-512 IFMA and two terms")[0]
                    })
                });
            }
        }
    }
    for sizes in [&[13, 3, 1][..], &[17, 2, 1, 1, 2, 5], &[30, 3, 2, 2, 2, 5], &[10, 20, 30, 50]] {
        let inputs: Vec<Vec<Vec<_>>> = (0..SAMPLES)
            .map(|_| {
                sizes
                    .iter()
                    .map(|n| (0..*n).map(|_| (G1Affine::rand(&mut rng), Fr::rand(&mut rng))).collect())
                    .collect()
            })
            .collect();
        let mut count = 0;
        group.bench_function(format!("many/{sizes:?}"), |b| {
            b.iter(|| {
                count = (count + 1) % SAMPLES;
                let msms: Vec<&[_]> = inputs[count].iter().map(Vec::as_slice).collect();
                VariableBase::msm_many(&msms)
            })
        });
    }
    group.finish();
}

criterion_group! {
    name = lane_msm_group;
    config = Criterion::default().sample_size(30);
    targets = lane_msm_bls12_377
}

criterion_group! {
    name = variable_base_group;
    config = Criterion::default().sample_size(10);
    targets = small_variable_base_bls12_377, variable_base_bls12_377, variable_base_edwards_bls12
}

criterion_main!(variable_base_group, lane_msm_group);
