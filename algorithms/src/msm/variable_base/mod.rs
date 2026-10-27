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

pub struct VariableBase;

impl VariableBase {
    pub fn msm<G: AffineCurve>(bases: &[G], scalars: &[<G::ScalarField as PrimeField>::BigInteger]) -> G::Projective {
        // For BLS12-377, we perform variable base MSM using a batched addition
        // technique.
        if TypeId::of::<G>() == TypeId::of::<G1Affine>() {
            #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
            // TODO SNP: where to set the threshold
            if scalars.len() > 1024 {
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

    /// Multi-scalar multiplications over field elements, several at once.
    ///
    /// Returns the sum of `base * scalar` over each of `msms`, in their
    /// order. Each MSM goes through [`Self::msm`], which picks its method by
    /// the MSM's size.
    pub fn msm_many<G: AffineCurve>(msms: &[&[(G, G::ScalarField)]]) -> Vec<G::Projective> {
        msms.iter()
            .map(|terms| {
                let (bases, scalars): (Vec<_>, Vec<_>) =
                    terms.iter().map(|(base, scalar)| (*base, scalar.to_bigint())).unzip();
                Self::msm(&bases, &scalars)
            })
            .collect()
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

    /// `msm_many` over MSMs of mixed sizes, with an empty MSM, a base at
    /// infinity and a zero scalar among them, gives each MSM's `msm`.
    #[test]
    fn test_msm_many() {
        use itertools::Itertools;
        use snarkvm_curves::ProjectiveCurve;
        use snarkvm_fields::Zero;
        use snarkvm_utilities::Uniform;

        let mut rng = TestRng::default();
        let mut msms: Vec<Vec<(G1Affine, Fr)>> = [0, 1, 2, 5, 31, 32, 64]
            .into_iter()
            .map(|n| (0..n).map(|_| (G1Affine::rand(&mut rng), Fr::rand(&mut rng))).collect())
            .collect();
        msms[3][2].0 = G1Affine::zero();
        msms[5][7].1 = Fr::zero();
        let slices: Vec<&[_]> = msms.iter().map(Vec::as_slice).collect();
        let sums = VariableBase::msm_many(&slices);
        assert_eq!(sums.len(), msms.len());
        for (msm, sum) in msms.iter().zip_eq(&sums) {
            let (bases, scalars): (Vec<_>, Vec<_>) =
                msm.iter().map(|(base, scalar)| (*base, scalar.to_bigint())).unzip();
            assert_eq!(sum.to_affine(), VariableBase::msm(&bases, &scalars).to_affine(), "{} bases", msm.len());
        }
    }

    /// `msm` and `batched::msm` on more bases than scalars sum over the
    /// first bases, one per scalar, below and above the bucket method's
    /// cutoff; `msm_many` of those pairs gives the same sum.
    #[test]
    fn test_msm_more_bases_than_scalars() {
        use snarkvm_curves::ProjectiveCurve;

        let mut rng = TestRng::default();
        for (num_bases, num_scalars) in [(5, 2), (40, 3), (40, 33)] {
            let (bases, _) = create_scalar_bases::<G1Affine, Fr>(&mut rng, num_bases);
            let (_, scalars) = create_scalar_bases::<G1Affine, Fr>(&mut rng, num_scalars);
            let naive = VariableBase::msm_naive(&bases[..num_scalars], &scalars).to_affine();
            let case = format!("{num_bases} bases, {num_scalars} scalars");
            assert_eq!(VariableBase::msm(&bases, &scalars).to_affine(), naive, "{case}");
            assert_eq!(batched::msm(&bases, &scalars).to_affine(), naive, "{case}");
            // `create_scalar_bases` draws each scalar below the modulus.
            let pairs: Vec<_> =
                bases.iter().zip(&scalars).map(|(base, scalar)| (*base, Fr::from_bigint(*scalar).unwrap())).collect();
            assert_eq!(VariableBase::msm_many(&[pairs.as_slice()])[0].to_affine(), naive, "{case}");
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
