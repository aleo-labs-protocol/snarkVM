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
use snarkvm_utilities::cfg_iter;

// `cfg_iter!` needs rayon only without the `serial` feature.
#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

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

    /// Multi-scalar multiplication over field elements.
    ///
    /// On the GPU path the digit-extraction kernel reduces the scalars out of
    /// Montgomery form. Elsewhere this converts them and calls [`Self::msm`].
    pub fn msm_field<G: AffineCurve>(bases: &[G], scalars: &[G::ScalarField]) -> G::Projective {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if TypeId::of::<G>() == TypeId::of::<G1Affine>() && scalars.len() > 1024 {
            let result = snarkvm_algorithms_cuda::msm::<G, G::Projective, G::ScalarField>(bases, scalars);
            return crate::cuda_must_succeed!(result, "MSM");
        }
        let bigints = cfg_iter!(scalars).map(|s| s.to_bigint()).collect::<Vec<_>>();
        Self::msm(bases, &bigints)
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
    use snarkvm_utilities::rand::Uniform;

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

    /// `msm_field` on Montgomery-form scalars matches `msm` on reduced ones.
    ///
    /// Sized over the `> 1024` threshold, because below it `msm_field` calls
    /// `msm`.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn test_msm_field_matches_msm() {
        let mut rng = TestRng::default();
        for i in 11..15 {
            let size = 1 << i;
            let bases = (0..size).map(|_| G1Affine::rand(&mut rng)).collect::<Vec<_>>();
            let fields = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let bigints = fields.iter().map(|s| s.to_bigint()).collect::<Vec<_>>();

            let reduced_on_the_cpu = VariableBase::msm::<G1Affine>(&bases, &bigints);
            let reduced_on_the_gpu = VariableBase::msm_field::<G1Affine>(&bases, &fields);
            assert_eq!(reduced_on_the_cpu.to_affine(), reduced_on_the_gpu.to_affine(), "size {size}");
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
