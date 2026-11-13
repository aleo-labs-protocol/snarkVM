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

pub mod batched;
pub mod standard;

#[cfg(target_arch = "x86_64")]
pub mod prefetch;

use snarkvm_curves::{bls12_377::G1Affine, traits::AffineCurve};
use snarkvm_fields::PrimeField;

use core::any::TypeId;

#[cfg(any(all(feature = "cuda", target_arch = "x86_64"), test))]
const DEFAULT_CUDA_MSM_THRESHOLD: usize = 1024;
#[cfg(all(feature = "cuda", target_arch = "x86_64"))]
const CUDA_MSM_THRESHOLD_ENV: &str = "SNARKVM_CUDA_MSM_THRESHOLD";

#[cfg(any(all(feature = "cuda", target_arch = "x86_64"), test))]
fn parse_cuda_msm_threshold(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|threshold| *threshold > 0)
        .unwrap_or(DEFAULT_CUDA_MSM_THRESHOLD)
}

#[cfg(any(all(feature = "cuda", target_arch = "x86_64"), test))]
fn should_use_cuda_msm(input_len: usize, threshold: usize) -> bool {
    input_len > threshold
}

#[cfg(all(feature = "cuda", target_arch = "x86_64"))]
fn cuda_msm_threshold() -> usize {
    static THRESHOLD: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

    *THRESHOLD.get_or_init(|| parse_cuda_msm_threshold(std::env::var(CUDA_MSM_THRESHOLD_ENV).ok().as_deref()))
}

pub struct VariableBase;

impl VariableBase {
    pub fn msm<G: AffineCurve>(bases: &[G], scalars: &[<G::ScalarField as PrimeField>::BigInteger]) -> G::Projective {
        // For BLS12-377, we perform variable base MSM using a batched addition
        // technique.
        if TypeId::of::<G>() == TypeId::of::<G1Affine>() {
            #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
            if should_use_cuda_msm(scalars.len(), cuda_msm_threshold()) {
                let result = snarkvm_algorithms_cuda::msm::<G, G::Projective, <G::ScalarField as PrimeField>::BigInteger>(
                    bases, scalars,
                );
                return crate::cuda_must_succeed!(result, "MSM");
            }
            batched::msm(bases, scalars)
        }
        // For all other curves, we perform variable base MSM using Pippenger's algorithm.
        else {
            standard::msm(bases, scalars)
        }
    }

    #[cfg(test)]
    fn msm_naive<G: AffineCurve>(bases: &[G], scalars: &[<G::ScalarField as PrimeField>::BigInteger]) -> G::Projective {
        use itertools::Itertools;
        use snarkvm_utilities::BitIteratorBE;

        bases.iter().zip_eq(scalars).map(|(base, scalar)| base.mul_bits(BitIteratorBE::new(*scalar))).sum()
    }

    #[cfg(test)]
    fn msm_naive_parallel<G: AffineCurve>(
        bases: &[G],
        scalars: &[<G::ScalarField as PrimeField>::BigInteger],
    ) -> G::Projective {
        use rayon::prelude::*;
        use snarkvm_utilities::BitIteratorBE;

        bases.par_iter().zip_eq(scalars).map(|(base, scalar)| base.mul_bits(BitIteratorBE::new(*scalar))).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_curves::bls12_377::{Fr, G1Affine};
    use snarkvm_fields::PrimeField;
    use snarkvm_utilities::rand::TestRng;

    #[test]
    fn cuda_msm_threshold_defaults_when_missing_or_invalid() {
        for value in [None, Some(""), Some("invalid"), Some("0"), Some(" 8192 ")] {
            assert_eq!(parse_cuda_msm_threshold(value), DEFAULT_CUDA_MSM_THRESHOLD);
        }
    }

    #[test]
    fn cuda_msm_threshold_accepts_positive_values() {
        assert_eq!(parse_cuda_msm_threshold(Some("8192")), 8192);
        assert_eq!(parse_cuda_msm_threshold(Some("1")), 1);
    }

    #[test]
    fn cuda_msm_dispatch_starts_above_the_threshold() {
        assert!(!should_use_cuda_msm(1024, DEFAULT_CUDA_MSM_THRESHOLD));
        assert!(should_use_cuda_msm(1025, DEFAULT_CUDA_MSM_THRESHOLD));
        assert!(!should_use_cuda_msm(8192, 8192));
        assert!(should_use_cuda_msm(8193, 8192));
    }

    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    use snarkvm_curves::ProjectiveCurve;

    fn create_scalar_bases<G: AffineCurve<ScalarField = F>, F: PrimeField>(
        rng: &mut TestRng,
        size: usize,
    ) -> (Vec<G>, Vec<F::BigInteger>) {
        let bases = (0..size).map(|_| G::rand(rng)).collect::<Vec<_>>();
        let scalars = (0..size).map(|_| F::rand(rng).to_bigint()).collect::<Vec<_>>();
        (bases, scalars)
    }

    #[test]
    fn test_msm() {
        use snarkvm_curves::ProjectiveCurve;

        let mut rng = TestRng::default();
        for msm_size in [1, 5, 10, 14, 15, 25, 31, 32, 33, 50, 100, 500, 1000] {
            let (bases, scalars) = create_scalar_bases::<G1Affine, Fr>(&mut rng, msm_size);

            let naive_a = VariableBase::msm_naive(bases.as_slice(), scalars.as_slice()).to_affine();
            let naive_b = VariableBase::msm_naive_parallel(bases.as_slice(), scalars.as_slice()).to_affine();
            assert_eq!(naive_a, naive_b, "MSM size: {msm_size}");

            let candidate = standard::msm(bases.as_slice(), scalars.as_slice()).to_affine();
            assert_eq!(naive_a, candidate, "MSM size: {msm_size}");

            let candidate = batched::msm(bases.as_slice(), scalars.as_slice()).to_affine();
            assert_eq!(naive_a, candidate, "MSM size: {msm_size}");
        }
    }

    /// Every size below the bucket method's cutoff, with the scalars a signed
    /// recoding mishandles first (zero, one, minus one, powers of two, the top
    /// of the field) mixed among random ones, a base at infinity, and a base
    /// that repeats.
    #[test]
    fn test_msm_small_edge_cases() {
        use snarkvm_curves::ProjectiveCurve;
        use snarkvm_fields::{Field, One, Zero};

        let two = Fr::from(2u64);
        let special = [
            Fr::zero(),
            Fr::one(),
            -Fr::one(),
            two,
            -two,
            Fr::from(15u64),
            Fr::from(17u64),
            Fr::from(u64::MAX),
            two.pow([63]),
            two.pow([64]),
            two.pow([128]),
            two.pow([252]),
            two.pow([252]) - Fr::one(),
            -two.pow([252]),
        ];

        let mut rng = TestRng::default();
        assert!(batched::msm::<G1Affine>(&[], &[]).is_zero());
        for msm_size in 1..32 {
            let (mut bases, mut scalars) = create_scalar_bases::<G1Affine, Fr>(&mut rng, msm_size);
            for (i, scalar) in scalars.iter_mut().enumerate().step_by(2) {
                *scalar = special[(i / 2 + msm_size) % special.len()].to_bigint();
            }
            if msm_size > 2 {
                bases[1] = G1Affine::zero();
                bases[2] = bases[0];
            }

            let naive = VariableBase::msm_naive(bases.as_slice(), scalars.as_slice()).to_affine();
            let candidate = batched::msm(bases.as_slice(), scalars.as_slice()).to_affine();
            assert_eq!(naive, candidate, "MSM size: {msm_size}");

            let all_special = special.iter().cycle().take(msm_size).map(|s| s.to_bigint()).collect::<Vec<_>>();
            let naive = VariableBase::msm_naive(bases.as_slice(), all_special.as_slice()).to_affine();
            let candidate = batched::msm(bases.as_slice(), all_special.as_slice()).to_affine();
            assert_eq!(naive, candidate, "MSM size: {msm_size}, special scalars");
        }
    }

    /// One base, at infinity or not, under the scalars of each one-base path:
    /// zero, one, reduced scalars, and unreduced scalars below `2^253`.
    #[test]
    fn test_msm_one_base() {
        use snarkvm_curves::ProjectiveCurve;
        use snarkvm_fields::{One, Zero};
        use snarkvm_utilities::{BigInteger, BigInteger256, Uniform};

        let mut rng = TestRng::default();
        let reduced = [Fr::zero(), Fr::one(), -Fr::one(), Fr::rand(&mut rng)].map(|s| s.to_bigint());

        let modulus = Fr::modulus();
        let mut modulus_plus_one = modulus;
        modulus_plus_one.add_nocarry(&BigInteger256::from(1u64));
        let mut modulus_plus_random = modulus;
        let mut offset = Fr::rand(&mut rng).to_bigint();
        offset.0[3] &= (1 << 58) - 1;
        modulus_plus_random.add_nocarry(&offset);
        let top = BigInteger256::new([u64::MAX, u64::MAX, u64::MAX, (1 << 61) - 1]);
        let unreduced = [modulus, modulus_plus_one, modulus_plus_random, top];
        assert!(unreduced.iter().all(|s| Fr::from_bigint(*s).is_none()));

        for base in [G1Affine::rand(&mut rng), G1Affine::zero()] {
            for scalar in reduced.iter().chain(&unreduced) {
                let naive = VariableBase::msm_naive(&[base], &[*scalar]).to_affine();
                let candidate = batched::msm(&[base], &[*scalar]).to_affine();
                assert_eq!(naive, candidate, "base: {base}, scalar: {scalar}");
            }
        }
    }

    /// Zero and unit scalars mixed with others, on more bases than scalars,
    /// give the naive sum over the first bases.
    #[test]
    fn test_msm_small_zero_and_unit_scalars() {
        use snarkvm_curves::ProjectiveCurve;
        use snarkvm_fields::{One, Zero};
        use snarkvm_utilities::Uniform;

        let mut rng = TestRng::default();
        let (bases, _) = create_scalar_bases::<G1Affine, Fr>(&mut rng, 6);
        let [zero, one, a, b] = [Fr::zero(), Fr::one(), Fr::rand(&mut rng), Fr::rand(&mut rng)].map(|s| s.to_bigint());
        for scalars in [
            vec![zero, zero],
            vec![one, one, one],
            vec![zero, a],
            vec![one, zero, a, b],
            vec![a, one, zero, b, one],
            vec![a, b],
        ] {
            let naive = VariableBase::msm_naive(&bases[..scalars.len()], &scalars).to_affine();
            assert_eq!(batched::msm(&bases, &scalars).to_affine(), naive, "scalars: {scalars:?}");
        }
    }

    /// Bases at infinity must survive the trip to the device.
    ///
    /// The device slot is wider than the host point, so a copy that misplaces
    /// the infinity flag turns the identity into an ordinary point. Random
    /// bases are never at infinity.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn test_msm_cuda_with_bases_at_infinity() {
        use snarkvm_fields::Zero;

        let mut rng = TestRng::default();
        for i in 11..15 {
            let (mut bases, scalars) = create_scalar_bases::<G1Affine, Fr>(&mut rng, 1 << i);
            for base in bases.iter_mut().step_by(7) {
                *base = G1Affine::zero();
            }
            let rust = standard::msm(bases.as_slice(), scalars.as_slice());
            let cuda = VariableBase::msm::<G1Affine>(bases.as_slice(), scalars.as_slice());
            assert_eq!(rust.to_affine(), cuda.to_affine(), "size {}", 1 << i);
        }
    }

    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn test_msm_cuda() {
        let mut rng = TestRng::default();
        for i in 2..17 {
            let (bases, scalars) = create_scalar_bases::<G1Affine, Fr>(&mut rng, 1 << i);
            let rust = standard::msm(bases.as_slice(), scalars.as_slice());
            let cuda = VariableBase::msm::<G1Affine>(bases.as_slice(), scalars.as_slice());
            assert_eq!(rust.to_affine(), cuda.to_affine());
        }
    }

    /// An MSM of no points returns zero with every coordinate written.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    #[allow(deprecated)]
    fn test_msm_cuda_of_no_points_is_zero() {
        use snarkvm_curves::bls12_377::G1Projective;
        use snarkvm_fields::Zero;
        use snarkvm_utilities::BigInteger256;

        let sum = snarkvm_algorithms_cuda::msm::<G1Affine, G1Projective, BigInteger256>(&[], &[])
            .unwrap_or_else(|e| panic!("{e}"));
        let zero = G1Projective::zero();
        assert_eq!((sum.x, sum.y, sum.z), (zero.x, zero.y, zero.z));
    }

    /// blst's routines run the ADX code only if its CPUID constructor is in the
    /// link.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn blst_runs_adx_on_a_cpu_with_it() {
        let adx = snarkvm_algorithms_cuda::blst_platform_cap() & 1 != 0;
        assert_eq!(adx, std::is_x86_feature_detected!("adx"));
    }
}
