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

//! Here we construct a polynomial commitment that enables users to commit to a
//! single polynomial `p`, and then later provide an evaluation proof that
//! convinces verifiers that a claimed value `v` is the true evaluation of `p`
//! at a chosen point `x`. Our construction follows the template of the
//! construction proposed by Kate, Zaverucha, and Goldberg ([KZG11](http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf)).
//! This construction achieves extractability in the algebraic group model
//! (AGM).

use crate::{
    fft::{DensePolynomial, Polynomial},
    msm::VariableBase,
    polycommit::PCError,
};
use snarkvm_curves::traits::{AffineCurve, PairingCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::{One, PrimeField, Zero};
use snarkvm_utilities::{BitIteratorBE, cfg_iter, cfg_iter_mut, defer, rand::Uniform};

use anyhow::{Result, anyhow, ensure};
use core::{marker::PhantomData, ops::Mul};
use itertools::Itertools;
use rand::Rng;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

mod data_structures;
pub use data_structures::*;

use super::sonic_pc::LabeledPolynomialWithBasis;

#[derive(Debug, PartialEq, Eq)]
pub enum KZGDegreeBounds {
    All,
    Varuna,
    List(Vec<usize>),
    None,
}

impl KZGDegreeBounds {
    pub fn get_list<F: PrimeField>(&self, max_degree: usize) -> Vec<usize> {
        match self {
            KZGDegreeBounds::All => (0..max_degree).collect(),
            KZGDegreeBounds::Varuna => {
                // In Varuna, the degree bounds are all of the forms `domain_size - 2`.
                // Consider that we are using radix-2 FFT,
                // there are only a few possible domain sizes and therefore degree bounds.
                //
                // We do not consider mixed-radix FFT for simplicity, as the curves that we
                // are using have very high two-arity.

                let mut radix_2_possible_domain_sizes = vec![];

                let mut cur = 2usize;
                while cur - 2 <= max_degree {
                    radix_2_possible_domain_sizes.push(cur - 2);
                    cur *= 2;
                }

                radix_2_possible_domain_sizes
            }
            KZGDegreeBounds::List(v) => v.clone(),
            KZGDegreeBounds::None => vec![],
        }
    }
}

/// `KZG10` is an implementation of the polynomial commitment scheme of
/// [Kate, Zaverucha and Goldbgerg][kzg10]
///
/// [kzg10]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
#[derive(Clone, Debug)]
pub struct KZG10<E: PairingEngine>(PhantomData<E>);

impl<E: PairingEngine> KZG10<E> {
    /// Constructs public parameters when given as input the maximum degree
    /// `degree` for the polynomial commitment scheme.
    pub fn load_srs(max_degree: usize) -> Result<UniversalParams<E>, PCError> {
        let params = UniversalParams::load()?;
        params.download_powers_for(0..(max_degree + 1))?;
        Ok(params)
    }

    /// Outputs a commitment to `polynomial`.
    pub fn commit(
        powers: &Powers<E>,
        polynomial: &Polynomial<'_, E::Fr>,
        hiding_bound: Option<usize>,
        rng: Option<&mut dyn Rng>,
    ) -> Result<(KZGCommitment<E>, KZGRandomness<E>), PCError> {
        Self::check_degree_is_too_large(polynomial.degree(), powers.size())?;

        let commit_time = start_timer!(|| format!(
            "Committing to polynomial of degree {} with hiding_bound: {:?}",
            polynomial.degree(),
            hiding_bound,
        ));
        defer! { end_timer!(commit_time); }

        let mut commitment = match polynomial {
            Polynomial::Dense(polynomial) => {
                let (num_leading_zeros, plain_coeffs) = skip_leading_zeros(polynomial);

                let bases = &powers.powers_of_beta_g[num_leading_zeros..(num_leading_zeros + plain_coeffs.len())];

                let msm_time = start_timer!(|| "MSM to compute commitment to plaintext poly");
                let commitment = VariableBase::msm_field(bases, plain_coeffs);
                end_timer!(msm_time);

                commitment
            }
            Polynomial::Sparse(polynomial) => polynomial
                .coeffs()
                .map(|(i, coeff)| {
                    powers.powers_of_beta_g[*i].mul_bits(BitIteratorBE::new_without_leading_zeros(coeff.to_bigint()))
                })
                .sum(),
        };

        let mut randomness = KZGRandomness::empty();
        if let Some(hiding_degree) = hiding_bound {
            let mut rng = rng.ok_or(PCError::MissingRng)?;
            let sample_random_poly_time =
                start_timer!(|| format!("Sampling a random polynomial of degree {hiding_degree}"));
            defer! { end_timer!(sample_random_poly_time); }

            randomness = KZGRandomness::rand(hiding_degree, false, &mut rng);
            Self::check_hiding_bound(
                randomness.blinding_polynomial.degree(),
                powers.powers_of_beta_times_gamma_g.len(),
            )?;
        }

        let msm_time = start_timer!(|| "MSM to compute commitment to random poly");
        let random_commitment =
            VariableBase::msm_field(&powers.powers_of_beta_times_gamma_g, &randomness.blinding_polynomial.coeffs)
                .to_affine();
        end_timer!(msm_time);

        commitment.add_assign_mixed(&random_commitment);

        Ok((KZGCommitment(commitment.into()), randomness))
    }

    /// Outputs a commitment to `polynomial`.
    pub fn commit_lagrange(
        lagrange_basis: &LagrangeBasis<E>,
        evaluations: &[E::Fr],
        hiding_bound: Option<usize>,
        rng: Option<&mut dyn Rng>,
    ) -> Result<(KZGCommitment<E>, KZGRandomness<E>), PCError> {
        Self::check_degree_is_too_large(evaluations.len() - 1, lagrange_basis.size())?;
        assert_eq!(
            evaluations.len().checked_next_power_of_two().ok_or(PCError::LagrangeBasisSizeIsTooLarge)?,
            lagrange_basis.size()
        );

        let commit_time = start_timer!(|| format!(
            "Committing to polynomial of degree {} with hiding_bound: {:?}",
            evaluations.len() - 1,
            hiding_bound,
        ));
        defer! { end_timer!(commit_time); }

        let evaluations = evaluations.iter().map(|e| e.to_bigint()).collect::<Vec<_>>();
        let msm_time = start_timer!(|| "MSM to compute commitment to plaintext poly");
        let mut commitment = VariableBase::msm(&lagrange_basis.lagrange_basis_at_beta_g, &evaluations);
        end_timer!(msm_time);

        let mut randomness = KZGRandomness::empty();
        if let Some(hiding_degree) = hiding_bound {
            let mut rng = rng.ok_or(PCError::MissingRng)?;
            let sample_random_poly_time =
                start_timer!(|| format!("Sampling a random polynomial of degree {hiding_degree}"));
            defer! { end_timer!(sample_random_poly_time); }

            randomness = KZGRandomness::rand(hiding_degree, false, &mut rng);
            Self::check_hiding_bound(
                randomness.blinding_polynomial.degree(),
                lagrange_basis.powers_of_beta_times_gamma_g.len(),
            )?;
        }

        let msm_time = start_timer!(|| "MSM to compute commitment to random poly");
        let random_commitment = VariableBase::msm_field(
            &lagrange_basis.powers_of_beta_times_gamma_g,
            &randomness.blinding_polynomial.coeffs,
        )
        .to_affine();
        end_timer!(msm_time);

        commitment.add_assign_mixed(&random_commitment);

        Ok((KZGCommitment(commitment.into()), randomness))
    }

    /// Compute witness polynomial.
    ///
    /// The witness polynomial w(x) the quotient of the division (p(x) - p(z)) /
    /// (x - z) Observe that this quotient does not change with z because
    /// p(z) is the remainder term. We can therefore omit p(z) when computing
    /// the quotient.
    pub fn compute_witness_polynomial(
        polynomial: &DensePolynomial<E::Fr>,
        point: E::Fr,
        randomness: &KZGRandomness<E>,
    ) -> Result<(DensePolynomial<E::Fr>, Option<DensePolynomial<E::Fr>>), PCError> {
        let witness_time = start_timer!(|| "Computing witness polynomial");
        let (witness_polynomial, _) = polynomial.divide_by_monic_linear(point);
        end_timer!(witness_time);

        let random_witness_polynomial = if randomness.is_hiding() {
            let random_p = &randomness.blinding_polynomial;

            let witness_time = start_timer!(|| "Computing random witness polynomial");
            let (random_witness_polynomial, _) = random_p.divide_by_monic_linear(point);
            end_timer!(witness_time);
            Some(random_witness_polynomial)
        } else {
            None
        };

        Ok((witness_polynomial, random_witness_polynomial))
    }

    pub(crate) fn open_with_witness_polynomial(
        powers: &Powers<E>,
        point: E::Fr,
        randomness: &KZGRandomness<E>,
        witness_polynomial: &DensePolynomial<E::Fr>,
        hiding_witness_polynomial: Option<&DensePolynomial<E::Fr>>,
    ) -> Result<KZGProof<E>, PCError> {
        Self::check_degree_is_too_large(witness_polynomial.degree(), powers.size())?;
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros(witness_polynomial);

        let bases = &powers.powers_of_beta_g[num_leading_zeros..(num_leading_zeros + witness_coeffs.len())];

        let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
        let w = VariableBase::msm_field(bases, witness_coeffs);
        end_timer!(witness_comm_time);

        Ok(Self::finish_open(powers, point, randomness, w, hiding_witness_polynomial))
    }

    /// Finish an opening from an already-computed commitment `w` to the witness
    /// polynomial, adding the hiding term when `hiding_witness_polynomial` is
    /// given.
    pub(crate) fn finish_open(
        powers: &Powers<E>,
        point: E::Fr,
        randomness: &KZGRandomness<E>,
        mut w: E::G1Projective,
        hiding_witness_polynomial: Option<&DensePolynomial<E::Fr>>,
    ) -> KZGProof<E> {
        let random_v = if let Some(hiding_witness_polynomial) = hiding_witness_polynomial {
            let blinding_p = &randomness.blinding_polynomial;
            let blinding_eval_time = start_timer!(|| "Evaluating random polynomial");
            let blinding_evaluation = blinding_p.evaluate(point);
            end_timer!(blinding_eval_time);

            let witness_comm_time = start_timer!(|| "Computing commitment to random witness polynomial");
            w += &VariableBase::msm_field(&powers.powers_of_beta_times_gamma_g, &hiding_witness_polynomial.coeffs);
            end_timer!(witness_comm_time);
            Some(blinding_evaluation)
        } else {
            None
        };

        KZGProof { w: w.to_affine(), random_v }
    }

    /// On input a polynomial `p` in Lagrange basis, and a point `point`,
    /// outputs an evaluation proof for the same.
    pub fn open_lagrange(
        lagrange_basis: &LagrangeBasis<E>,
        domain_elements: &[E::Fr],
        evaluations: &[E::Fr],
        point: E::Fr,
        evaluation_at_point: E::Fr,
    ) -> Result<KZGProof<E>> {
        Self::check_degree_is_too_large(evaluations.len() - 1, lagrange_basis.size())?;
        // Ensure that the point is not in the domain
        if lagrange_basis.domain.evaluate_vanishing_polynomial(point).is_zero() {
            Err(anyhow!("Point cannot be in the domain"))?;
        }
        if evaluations.len().checked_next_power_of_two().ok_or_else(|| anyhow!("Evaluations length is too large"))?
            != lagrange_basis.size()
        {
            Err(anyhow!("`evaluations.len()` must equal `domain.size()`"))?;
        }

        let mut divisor_evals = cfg_iter!(domain_elements).map(|&e| e - point).collect::<Vec<_>>();
        snarkvm_fields::batch_inversion(&mut divisor_evals);
        ensure!(divisor_evals.len() == evaluations.len());
        cfg_iter_mut!(divisor_evals).zip_eq(evaluations).for_each(|(divisor_eval, &eval)| {
            *divisor_eval *= eval - evaluation_at_point;
        });
        let (witness_comm, _) = Self::commit_lagrange(lagrange_basis, &divisor_evals, None, None)?;

        Ok(KZGProof { w: witness_comm.0, random_v: None })
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    pub fn open(
        powers: &Powers<E>,
        polynomial: &DensePolynomial<E::Fr>,
        point: E::Fr,
        rand: &KZGRandomness<E>,
    ) -> Result<KZGProof<E>, PCError> {
        Self::check_degree_is_too_large(polynomial.degree(), powers.size())?;
        let open_time = start_timer!(|| format!("Opening polynomial of degree {}", polynomial.degree()));
        defer! { end_timer!(open_time); }

        let (witness_poly, hiding_witness_poly) = {
            let witness_time = start_timer!(|| "Computing witness polynomials");
            defer! { end_timer!(witness_time); }
            Self::compute_witness_polynomial(polynomial, point, rand)?
        };

        Self::open_with_witness_polynomial(powers, point, rand, &witness_poly, hiding_witness_poly.as_ref())
    }

    /// Verifies that `value` is the evaluation at `point` of the polynomial
    /// committed inside `commitment`.
    pub fn check(
        vk: &VerifierKey<E>,
        commitment: &KZGCommitment<E>,
        point: E::Fr,
        value: E::Fr,
        proof: &KZGProof<E>,
    ) -> Result<bool, PCError> {
        let check_time = start_timer!(|| "Checking evaluation");
        let mut inner = commitment.0.to_projective() - vk.g.to_projective().mul(value);
        if let Some(random_v) = proof.random_v {
            inner -= &vk.gamma_g.mul(random_v);
        }
        let lhs = E::pairing(inner, vk.h);

        let inner = vk.beta_h.to_projective() - vk.h.mul(point);
        let rhs = E::pairing(proof.w, inner);

        end_timer!(check_time, || format!("Result: {}", lhs == rhs));
        Ok(lhs == rhs)
    }

    /// Check that each `proof_i` in `proofs` is a valid proof of evaluation for
    /// `commitment_i` at `point_i`.
    pub fn batch_check<R: Rng>(
        vk: &VerifierKey<E>,
        commitments: &[KZGCommitment<E>],
        points: &[E::Fr],
        values: &[E::Fr],
        proofs: &[KZGProof<E>],
        rng: &mut R,
    ) -> Result<bool> {
        ensure!(commitments.len() == points.len());
        ensure!(commitments.len() == values.len());
        ensure!(commitments.len() == proofs.len());
        let check_time = start_timer!(|| format!("Checking {} evaluation proofs", commitments.len()));
        let g = vk.g.to_projective();
        let gamma_g = vk.gamma_g.to_projective();

        let mut total_c = <E::G1Projective>::zero();
        let mut total_w = <E::G1Projective>::zero();

        let combination_time = start_timer!(|| "Combining commitments and proofs");
        let mut randomizer = E::Fr::one();
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = E::Fr::zero();
        let mut gamma_g_multiplier = E::Fr::zero();
        for (((c, z), v), proof) in commitments.iter().zip_eq(points).zip_eq(values).zip_eq(proofs) {
            let w = proof.w;
            let mut temp = w.mul(*z);
            temp.add_assign_mixed(&c.0);
            let c = temp;
            g_multiplier += &(randomizer * v);
            if let Some(random_v) = proof.random_v {
                gamma_g_multiplier += &(randomizer * random_v);
            }
            total_c += &c.mul(randomizer);
            total_w += &w.mul(randomizer);
            // We don't need to sample randomizers from the full field,
            // only from 128-bit strings.
            randomizer = u128::rand(rng).into();
        }
        total_c -= &g.mul(g_multiplier);
        total_c -= &gamma_g.mul(gamma_g_multiplier);
        end_timer!(combination_time);

        let to_affine_time = start_timer!(|| "Converting results to affine for pairing");
        let affine_points = E::G1Projective::batch_normalization_into_affine(vec![-total_w, total_c]);
        let (total_w, total_c) = (affine_points[0], affine_points[1]);
        end_timer!(to_affine_time);

        let pairing_time = start_timer!(|| "Performing product of pairings");
        let result = E::product_of_pairings(
            [(&total_w.prepare(), &vk.prepared_beta_h), (&total_c.prepare(), &vk.prepared_h)].iter().copied(),
        )
        .is_one();
        end_timer!(pairing_time);
        end_timer!(check_time, || format!("Result: {result}"));
        Ok(result)
    }

    pub(crate) fn check_degree_is_too_large(degree: usize, num_powers: usize) -> Result<(), PCError> {
        let num_coefficients = degree + 1;
        if num_coefficients > num_powers {
            Err(PCError::TooManyCoefficients { num_coefficients, num_powers })
        } else {
            Ok(())
        }
    }

    pub(crate) fn check_hiding_bound(hiding_poly_degree: usize, num_powers: usize) -> Result<(), PCError> {
        if hiding_poly_degree == 0 {
            Err(PCError::HidingBoundIsZero)
        } else if hiding_poly_degree >= num_powers {
            // The above check uses `>=` because committing to a hiding poly with
            // degree `hiding_poly_degree` requires `hiding_poly_degree + 1` powers.
            Err(PCError::HidingBoundToolarge { hiding_poly_degree, num_powers })
        } else {
            Ok(())
        }
    }

    pub(crate) fn check_degrees_and_bounds<'a>(
        max_degree: usize,
        enforced_degree_bounds: Option<&[usize]>,
        p: impl Into<LabeledPolynomialWithBasis<'a, E::Fr>>,
    ) -> Result<(), PCError> {
        let p = p.into();
        if let Some(bound) = p.degree_bound() {
            let enforced_degree_bounds = enforced_degree_bounds.ok_or(PCError::UnsupportedDegreeBound(bound))?;

            if enforced_degree_bounds.binary_search(&bound).is_err() {
                Err(PCError::UnsupportedDegreeBound(bound))
            } else if bound < p.degree() || bound > max_degree {
                Err(PCError::IncorrectDegreeBound {
                    poly_degree: p.degree(),
                    degree_bound: p.degree_bound().unwrap(),
                    max_degree,
                    label: p.label().to_string(),
                })
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}

/// Trailing coefficients, and how many leading zeros were dropped to reach
/// them.
///
/// The coefficients stay in Montgomery form; the MSM converts them itself.
fn skip_leading_zeros<F: PrimeField>(p: &DensePolynomial<F>) -> (usize, &[F]) {
    if p.coeffs.is_empty() {
        (0, &[])
    } else {
        let num_leading_zeros = p.coeffs.iter().take_while(|c| c.is_zero()).count();
        (num_leading_zeros, &p.coeffs[num_leading_zeros..])
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_camel_case_types)]
    #![allow(clippy::needless_borrow)]
    use super::*;
    use snarkvm_curves::bls12_377::{Bls12_377, Fr};
    use snarkvm_utilities::rand::TestRng;

    use rand::RngExt;
    use std::borrow::Cow;

    type KZG_Bls12_377 = KZG10<Bls12_377>;

    impl<E: PairingEngine> KZG10<E> {
        /// Specializes the public parameters for a given maximum degree `d` for
        /// polynomials `d` should be less that `pp.max_degree()`.
        pub(crate) fn trim(
            pp: &UniversalParams<E>,
            mut supported_degree: usize,
            hiding_bound: Option<usize>,
        ) -> (Powers<'_, E>, VerifierKey<E>) {
            if supported_degree == 1 {
                supported_degree += 1;
            }
            let powers_of_beta_g = pp.powers_of_beta_g(0, supported_degree + 1).unwrap().to_vec();

            let powers_of_beta_times_gamma_g = if let Some(hiding_bound) = hiding_bound {
                (0..=(hiding_bound + 1)).map(|i| pp.powers_of_beta_times_gamma_g()[&i]).collect()
            } else {
                vec![]
            };

            let powers = Powers {
                powers_of_beta_g: Cow::Owned(powers_of_beta_g),
                powers_of_beta_times_gamma_g: Cow::Owned(powers_of_beta_times_gamma_g),
            };
            let vk = VerifierKey {
                g: pp.power_of_beta_g(0).unwrap(),
                gamma_g: pp.powers_of_beta_times_gamma_g()[&0],
                h: pp.h,
                beta_h: pp.beta_h(),
                prepared_h: pp.prepared_h.clone(),
                prepared_beta_h: pp.prepared_beta_h.clone(),
            };
            (powers, vk)
        }
    }

    /// The SRS's powers serialize back to the bytes of the parameter files
    /// they were loaded from.
    #[test]
    fn test_kzg10_universal_params_serialization() {
        use snarkvm_parameters::mainnet::{BetaH, Degree15};
        use snarkvm_utilities::CanonicalSerialize;

        let pp = KZG_Bls12_377::load_srs(4).unwrap();

        let mut powers_bytes = vec![];
        pp.powers_of_beta_g(0, 1 << 15).unwrap().serialize_uncompressed(&mut powers_bytes).unwrap();
        assert_eq!(powers_bytes, Degree15::load_bytes().unwrap());

        let mut beta_h_bytes = vec![];
        pp.beta_h().serialize_uncompressed(&mut beta_h_bytes).unwrap();
        assert_eq!(beta_h_bytes, BetaH::load_bytes().unwrap());
    }

    fn end_to_end_test_template<E: PairingEngine>() -> Result<(), PCError> {
        let rng = &mut TestRng::default();
        for _ in 0..100 {
            let degree = rng.random_range(2..20);
            let pp = KZG10::<E>::load_srs(degree)?;
            let hiding_bound = Some(1);
            let (ck, vk) = KZG10::trim(&pp, degree, hiding_bound);
            let p = DensePolynomial::rand(degree, rng);
            let (comm, rand) = KZG10::<E>::commit(&ck, &(&p).into(), hiding_bound, Some(rng))?;
            let point = E::Fr::rand(rng);
            let value = p.evaluate(point);
            let proof = KZG10::<E>::open(&ck, &p, point, &rand)?;
            assert!(
                KZG10::<E>::check(&vk, &comm, point, value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}, hiding_bound = {:?}",
                degree,
                p.degree(),
                hiding_bound,
            );
        }
        Ok(())
    }

    fn linear_polynomial_test_template<E: PairingEngine>() -> Result<(), PCError> {
        let rng = &mut TestRng::default();
        for _ in 0..100 {
            let degree = 50;
            let pp = KZG10::<E>::load_srs(degree)?;
            let hiding_bound = Some(1);
            let (ck, vk) = KZG10::trim(&pp, 2, hiding_bound);
            let p = DensePolynomial::rand(1, rng);
            let (comm, rand) = KZG10::<E>::commit(&ck, &(&p).into(), hiding_bound, Some(rng))?;
            let point = E::Fr::rand(rng);
            let value = p.evaluate(point);
            let proof = KZG10::<E>::open(&ck, &p, point, &rand)?;
            assert!(
                KZG10::<E>::check(&vk, &comm, point, value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}, hiding_bound = {:?}",
                degree,
                p.degree(),
                hiding_bound,
            );
        }
        Ok(())
    }

    fn batch_check_test_template<E: PairingEngine>() -> Result<(), PCError> {
        let rng = &mut TestRng::default();
        for _ in 0..10 {
            let hiding_bound = Some(1);
            let degree = rng.random_range(2..20);
            let pp = KZG10::<E>::load_srs(degree)?;
            let (ck, vk) = KZG10::trim(&pp, degree, hiding_bound);

            let mut comms = Vec::new();
            let mut values = Vec::new();
            let mut points = Vec::new();
            let mut proofs = Vec::new();

            for _ in 0..10 {
                let p = DensePolynomial::rand(degree, rng);
                let (comm, rand) = KZG10::<E>::commit(&ck, &(&p).into(), hiding_bound, Some(rng))?;
                let point = E::Fr::rand(rng);
                let value = p.evaluate(point);
                let proof = KZG10::<E>::open(&ck, &p, point, &rand)?;

                assert!(KZG10::<E>::check(&vk, &comm, point, value, &proof)?);
                comms.push(comm);
                values.push(value);
                points.push(point);
                proofs.push(proof);
            }
            assert!(KZG10::<E>::batch_check(&vk, &comms, &points, &values, &proofs, rng)?);
        }
        Ok(())
    }

    #[test]
    fn test_end_to_end() {
        end_to_end_test_template::<Bls12_377>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_linear_polynomial() {
        linear_polynomial_test_template::<Bls12_377>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_batch_check() {
        batch_check_test_template::<Bls12_377>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_degree_is_too_large() {
        let rng = &mut TestRng::default();

        let max_degree = 123;
        let pp = KZG_Bls12_377::load_srs(max_degree).unwrap();
        let (powers, _) = KZG_Bls12_377::trim(&pp, max_degree, None);

        let p = DensePolynomial::<Fr>::rand(max_degree + 1, rng);
        assert!(p.degree() > max_degree);
        assert!(KZG_Bls12_377::check_degree_is_too_large(p.degree(), powers.size()).is_err());
    }
}
