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

use crate::{
    fft::{
        DensePolynomial,
        EvaluationDomain,
        Evaluations as EvaluationsOnDomain,
        domain::{FFTPrecomputation, IFFTPrecomputation},
        polynomial::PolyMultiplier,
    },
    polycommit::sonic_pc::{LabeledPolynomial, PolynomialInfo, PolynomialLabel},
    snark::varuna::{
        SNARKMode,
        ahp::{AHPError, AHPForR1CS, CircuitId, indexer::CircuitInfo, verifier},
        matrices::MatrixEvals,
        prover,
        selectors::apply_randomized_selector,
        witness_label,
    },
};
use snarkvm_fields::{PrimeField, batch_inversion_and_mul};
use snarkvm_utilities::{ExecutionPool, defer};

use anyhow::Result;
use core::convert::TryInto;
use itertools::Itertools;
use rand::Rng;
use std::collections::BTreeMap;

type Sum<F> = F;
type Lhs<F> = DensePolynomial<F>;
type Apoly<F> = LabeledPolynomial<F>;
type Bpoly<F> = LabeledPolynomial<F>;
type Gpoly<F> = LabeledPolynomial<F>;

impl<F: PrimeField, SM: SNARKMode> AHPForR1CS<F, SM> {
    /// Output the number of oracles sent by the prover in the fourth round.
    pub const fn num_fourth_round_oracles(circuits: usize) -> usize {
        circuits * 3
    }

    /// Output the degree bounds of oracles in the fourth round.
    pub fn fourth_round_polynomial_info<'a>(
        circuits: impl Iterator<Item = (CircuitId, &'a CircuitInfo)>,
    ) -> BTreeMap<PolynomialLabel, PolynomialInfo> {
        circuits
            .flat_map(|(circuit_id, info)| {
                let non_zero_a_size = EvaluationDomain::<F>::compute_size_of_domain(info.num_non_zero_a).unwrap();
                let non_zero_b_size = EvaluationDomain::<F>::compute_size_of_domain(info.num_non_zero_b).unwrap();
                let non_zero_c_size = EvaluationDomain::<F>::compute_size_of_domain(info.num_non_zero_c).unwrap();
                [
                    PolynomialInfo::new(witness_label(circuit_id, "g_a", 0), Some(non_zero_a_size - 2), None),
                    PolynomialInfo::new(witness_label(circuit_id, "g_b", 0), Some(non_zero_b_size - 2), None),
                    PolynomialInfo::new(witness_label(circuit_id, "g_c", 0), Some(non_zero_c_size - 2), None),
                ]
                .into_iter()
                .map(|info| (info.label().into(), info))
            })
            .collect()
    }

    /// Output the fourth round message and the next state.
    pub fn prover_fourth_round<'a, R: Rng>(
        second_message: &verifier::SecondMessage<F>,
        third_message: &verifier::ThirdMessage<F>,
        mut state: prover::State<'a, F, SM>,
        _r: &mut R,
    ) -> Result<(prover::FourthMessage<F>, prover::FourthOracles<F>, prover::State<'a, F, SM>), AHPError> {
        let round_time = start_timer!(|| "AHP::Prover::FourthRound");
        defer! { end_timer!(round_time); }

        let verifier::SecondMessage { alpha, .. } = second_message;
        let verifier::ThirdMessage { beta } = third_message;

        let mut pool = ExecutionPool::with_capacity(3 * state.circuit_specific_states.len());

        let max_non_zero_domain_size = state.max_non_zero_domain;
        let matrix_labels = ["a", "b", "c"];
        for (&circuit, state_i) in &state.circuit_specific_states {
            let v_R_i_at_alpha = state_i.constraint_domain.evaluate_vanishing_polynomial(*alpha);
            let v_C_i_at_beta = state_i.variable_domain.evaluate_vanishing_polynomial(*beta);
            let v_R_i_alpha_v_C_i_beta = v_R_i_at_alpha * v_C_i_at_beta;
            let k_domains = [state_i.non_zero_a_domain, state_i.non_zero_b_domain, state_i.non_zero_c_domain];
            let ariths = [&circuit.a_arith, &circuit.b_arith, &circuit.c_arith];
            let id = circuit.id;

            for (matrix_label, non_zero_domain, arith) in itertools::izip!(matrix_labels, k_domains, ariths) {
                pool.add_job(move || {
                    let result = Self::calculate_matrix_sumcheck_witness(
                        matrix_label,
                        id,
                        state_i.constraint_domain,
                        state_i.variable_domain,
                        non_zero_domain,
                        arith,
                        *alpha,
                        *beta,
                        v_R_i_alpha_v_C_i_beta,
                        max_non_zero_domain_size,
                        &circuit.fft_precomputation,
                        &circuit.ifft_precomputation,
                    );
                    (circuit, result)
                });
            }
        }

        let mut sums = Vec::with_capacity(state.circuit_specific_states.len());
        let mut gs = BTreeMap::new();
        for ((circuit_a, results_a), (circuit_b, results_b), (circuit_c, results_c)) in
            pool.execute_all().into_iter().tuples()
        {
            assert_eq!(circuit_a, circuit_b);
            assert_eq!(circuit_a, circuit_c);
            let (sum_a, lhs_a, g_a, a_poly_a, b_poly_a) = results_a?;
            let (sum_b, lhs_b, g_b, a_poly_b, b_poly_b) = results_b?;
            let (sum_c, lhs_c, g_c, a_poly_c, b_poly_c) = results_c?;
            let matrix_sum = prover::message::MatrixSums { sum_a, sum_b, sum_c };
            sums.push(matrix_sum);
            state.circuit_specific_states.get_mut(circuit_a).unwrap().lhs_polynomials = Some([lhs_a, lhs_b, lhs_c]);
            state.circuit_specific_states.get_mut(circuit_a).unwrap().a_polys = Some([a_poly_a, a_poly_b, a_poly_c]);
            state.circuit_specific_states.get_mut(circuit_a).unwrap().b_polys = Some([b_poly_a, b_poly_b, b_poly_c]);
            let matrix_gs = prover::MatrixGs { g_a, g_b, g_c };
            gs.insert(circuit_a.id, matrix_gs);
        }

        let msg = prover::FourthMessage { sums };
        let oracles = prover::FourthOracles { gs };

        assert!(oracles.matches_info(&Self::fourth_round_polynomial_info(
            state.circuit_specific_states.keys().map(|c| (c.id, &c.index_info))
        )));

        Ok((msg, oracles, state))
    }

    #[allow(clippy::too_many_arguments)]
    fn calculate_matrix_sumcheck_witness(
        label: &str,
        id: CircuitId,
        constraint_domain: EvaluationDomain<F>,
        variable_domain: EvaluationDomain<F>,
        non_zero_domain: EvaluationDomain<F>,
        arithmetization: &MatrixEvals<F>,
        alpha: F,
        beta: F,
        v_R_i_alpha_v_C_i_beta: F,
        max_non_zero_domain: EvaluationDomain<F>,
        fft_precomputation: &FFTPrecomputation<F>,
        ifft_precomputation: &IFFTPrecomputation<F>,
    ) -> Result<(Sum<F>, Lhs<F>, Gpoly<F>, Apoly<F>, Bpoly<F>)> {
        let (row_on_K, col_on_K, row_col_val) =
            (&arithmetization.row, &arithmetization.col, &arithmetization.row_col_val);
        let R_size_C_size = constraint_domain.size_as_field_element * variable_domain.size_as_field_element;

        // The whole chain runs on the device: the evaluations, the
        // interpolations, the shift into g, the b*f multiply, the subtract and
        // the vanishing divide. With `cuda` on BLS12-377 this arm is
        // unconditional and has no host fallback; a device failure aborts. Unlike
        // the gate in `third.rs`, a one-element non-zero domain aborts here
        // rather than falling through to the host.
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if core::any::TypeId::of::<F>() == core::any::TypeId::of::<snarkvm_curves::bls12_377::Fr>() {
            let chain_time = start_timer!(|| format!("Round 4 chain on the device for {label}"));
            defer! { end_timer!(chain_time); }

            let domain = non_zero_domain.size();
            let lg_domain = domain.trailing_zeros();
            // deg(b*f) <= 2*domain - 2, so the quotient has at most domain - 1
            // coefficients. The device rejects a quotient with terms above
            // `q_len`, and the host trims what comes back.
            let q_len = domain - 1;
            let mut a_v = vec![F::zero(); domain];
            let mut b_v = vec![F::zero(); domain];
            let mut g_v = vec![F::zero(); domain - 1];
            let mut lhs_v = vec![F::zero(); q_len];
            let mut f0 = F::zero();
            let matrix_sumcheck_constants =
                v_R_i_alpha_v_C_i_beta * constraint_domain.size_inv * variable_domain.size_inv;
            let selector_mult = non_zero_domain.size_as_field_element * max_non_zero_domain.size_inv;
            let result = snarkvm_algorithms_cuda::fourth_round_chain(
                &mut a_v,
                &mut b_v,
                &mut g_v,
                &mut lhs_v,
                &mut f0,
                &row_on_K.evaluations,
                &col_on_K.evaluations,
                &row_col_val.evaluations,
                lg_domain,
                lg_domain + 1,
                &alpha,
                &beta,
                &matrix_sumcheck_constants,
                &R_size_C_size,
                &v_R_i_alpha_v_C_i_beta,
                &selector_mult,
            );
            crate::cuda_must_succeed!(result, "fourth_round_chain");

            // `from_coefficients_vec` trims, which g needs to pass
            // `check_degrees_and_bounds` against its degree bound.
            let g = DensePolynomial::from_coefficients_vec(g_v);
            let lhs = DensePolynomial::from_coefficients_vec(lhs_v);
            let g_label = format!("g_{label}");
            let g = LabeledPolynomial::new(witness_label(id, &g_label, 0), g, Some(non_zero_domain.size() - 2), None);
            let a_poly = LabeledPolynomial::new(
                format!("circuit_{id}_a_poly_{label}"),
                DensePolynomial::from_coefficients_vec(a_v),
                None,
                None,
            );
            let b_poly = LabeledPolynomial::new(
                format!("circuit_{id}_b_poly_{label}"),
                DensePolynomial::from_coefficients_vec(b_v),
                None,
                None,
            );
            assert!(lhs.degree() <= non_zero_domain.size() - 2);
            assert!(g.degree() <= non_zero_domain.size() - 2);
            return Ok((f0, lhs, g, a_poly, b_poly));
        }

        // Precompute (alpha - row[i]) * (beta - col[i]) once and reuse for both b_poly
        // evals and f inverses, saving K redundant field multiplications per
        // matrix.
        let cross_products: Vec<F> = row_on_K
            .evaluations
            .iter()
            .zip_eq(&col_on_K.evaluations)
            .map(|(&r, &c)| (alpha - r) * (beta - c))
            .collect();

        let mut job_pool = snarkvm_utilities::ExecutionPool::with_capacity(2);
        job_pool.add_job(|| {
            let a_poly_time = start_timer!(|| format!("Computing a poly for {label}"));
            let a_poly = {
                let evals = row_col_val.evaluations.iter().map(|v| v_R_i_alpha_v_C_i_beta * v).collect();
                EvaluationsOnDomain::from_vec_and_domain(evals, non_zero_domain)
                    .interpolate_with_pc(ifft_precomputation)
            };
            end_timer!(a_poly_time);
            a_poly
        });

        job_pool.add_job(|| {
            let b_poly_time = start_timer!(|| format!("Computing b poly for {label}"));
            let b_poly = {
                let evals: Vec<F> = cross_products.iter().map(|&cp| R_size_C_size * cp).collect();
                EvaluationsOnDomain::from_vec_and_domain(evals, non_zero_domain)
                    .interpolate_with_pc(ifft_precomputation)
            };
            end_timer!(b_poly_time);
            b_poly
        });
        let [a_poly, b_poly]: [_; 2] = job_pool.execute_all().try_into().unwrap();

        let f_evals_time = start_timer!(|| format!("Computing f evals on K for {label}"));
        // Move cross_products directly into inverses - no second pass over row/col
        // needed.
        let mut inverses = cross_products;

        let matrix_sumcheck_constants = v_R_i_alpha_v_C_i_beta * constraint_domain.size_inv * variable_domain.size_inv;
        batch_inversion_and_mul(&mut inverses, &matrix_sumcheck_constants);

        inverses.iter_mut().zip_eq(&row_col_val.evaluations).for_each(|(inv, v)| *inv *= v);
        let f_evals_on_K = inverses;

        end_timer!(f_evals_time);

        let f_poly_time = start_timer!(|| format!("Computing f poly for {label}"));
        // we define f as the rational equation for which we're running the sumcheck
        // protocol
        let f = EvaluationsOnDomain::from_vec_and_domain(f_evals_on_K, non_zero_domain)
            .interpolate_with_pc(ifft_precomputation);

        end_timer!(f_poly_time);
        let g = DensePolynomial::from_coefficients_slice(&f.coeffs[1..]);
        let mut h = &a_poly
            - &{
                let mut multiplier = PolyMultiplier::new();
                multiplier.add_polynomial_ref(&b_poly, "b");
                multiplier.add_polynomial_ref(&f, "f");
                multiplier.add_precomputation(fft_precomputation, ifft_precomputation);
                multiplier.multiply().unwrap()
            };

        let combiner = F::one(); // We are applying combiners in the fifth round when summing the witnesses
        let (lhs, remainder) =
            apply_randomized_selector(&mut h, combiner, &max_non_zero_domain, &non_zero_domain, false)?;
        assert!(remainder.is_none());

        let g_label = format!("g_{label}");
        let g = LabeledPolynomial::new(witness_label(id, &g_label, 0), g, Some(non_zero_domain.size() - 2), None);
        let a_poly = LabeledPolynomial::new(format!("circuit_{id}_a_poly_{label}"), a_poly, None, None);
        let b_poly = LabeledPolynomial::new(format!("circuit_{id}_b_poly_{label}"), b_poly, None, None);

        assert!(lhs.degree() <= non_zero_domain.size() - 2);
        assert!(g.degree() <= non_zero_domain.size() - 2);
        Ok((f.coeffs[0], lhs, g, a_poly, b_poly))
    }
}

/// `fourth_round_polys` against the host sequence it fuses: the cross
/// products, the batch inversion, the multiply by `row_col_val`, the scalings
/// and the three interpolations.
#[cfg(all(test, feature = "cuda", target_arch = "x86_64"))]
mod gpu_fourth_round_polys_contract {
    use crate::fft::{EvaluationDomain, Evaluations as EvaluationsOnDomain};
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::{One, Zero, batch_inversion_and_mul};
    use snarkvm_utilities::rand::{TestRng, Uniform};

    /// Pushes a message to `bad` for each way the device and host disagree.
    #[allow(clippy::too_many_arguments)]
    fn compare(
        bad: &mut Vec<String>,
        case: &str,
        lg: u32,
        row: &[Fr],
        col: &[Fr],
        rcv: &[Fr],
        alpha: Fr,
        beta: Fr,
        coeff: Fr,
        b_scale: Fr,
        a_scale: Fr,
    ) {
        let domain = EvaluationDomain::<Fr>::new(1usize << lg).unwrap();
        assert_eq!(domain.size(), 1usize << lg, "domain is the power of two, not len");
        let pc = domain.precompute_ifft();

        let cross: Vec<Fr> = row.iter().zip(col).map(|(&r, &c)| (alpha - r) * (beta - c)).collect();
        let want_b_evals: Vec<Fr> = cross.iter().map(|&cp| b_scale * cp).collect();
        let mut want_f_evals = cross;
        batch_inversion_and_mul(&mut want_f_evals, &coeff);
        want_f_evals.iter_mut().zip(rcv).for_each(|(inv, v)| *inv *= v);
        let want_a_evals: Vec<Fr> = rcv.iter().map(|v| a_scale * v).collect();

        let want_a = EvaluationsOnDomain::from_vec_and_domain(want_a_evals, domain).interpolate_with_pc(&pc);
        let want_b = EvaluationsOnDomain::from_vec_and_domain(want_b_evals, domain).interpolate_with_pc(&pc);
        let want_f = EvaluationsOnDomain::from_vec_and_domain(want_f_evals, domain).interpolate_with_pc(&pc);

        let domain_size = 1usize << lg;
        let mut got_a = vec![Fr::zero(); domain_size];
        let mut got_b = vec![Fr::zero(); domain_size];
        let mut got_f = vec![Fr::zero(); domain_size];
        if snarkvm_algorithms_cuda::fourth_round_polys(
            &mut got_a, &mut got_b, &mut got_f, row, col, rcv, lg, &alpha, &beta, &coeff, &b_scale, &a_scale,
        )
        .is_err()
        {
            bad.push(format!("{case}: the call failed"));
            return;
        }

        for (name, want, got) in
            [("a", &want_a.coeffs, &got_a), ("b", &want_b.coeffs, &got_b), ("f", &want_f.coeffs, &got_f)]
        {
            // `from_coefficients_vec` pops trailing zeros, so compare over the
            // host polynomial's length and require the rest to be zero.
            if want.len() > got.len() {
                bad.push(format!("{case} {name}: {} coeffs against {}", got.len(), want.len()));
                continue;
            }
            if let Some(i) = (0..want.len()).find(|&i| want[i] != got[i]) {
                bad.push(format!("{case} {name}: coeff {i} differs"));
            }
            if let Some(i) = (want.len()..got.len()).find(|&i| !got[i].is_zero()) {
                bad.push(format!("{case} {name}: coeff {i} past the degree is non-zero"));
            }
        }
    }

    /// Sizes include 2^17 and 2^18, the domains the prover uses, to catch
    /// grid or indexing faults that appear only at large sizes.
    #[test]
    fn fused_chain_matches_the_host_sequence() {
        let rng = &mut TestRng::default();
        let mut bad: Vec<String> = Vec::new();

        // `(lg, len)`. The last two cover `len < domain`, where the kernel
        // zeroes `[len, domain)` as `interpolate_with_pc` does with its resize.
        for (lg, len) in [
            (10u32, 1usize << 10),
            (12, 1 << 12),
            (17, 1 << 17),
            (18, 1 << 18),
            (12, (1 << 12) - 1),
            (17, (1 << 17) - 1025),
        ] {
            let row: Vec<Fr> = (0..len).map(|_| Fr::rand(rng)).collect();
            let col: Vec<Fr> = (0..len).map(|_| Fr::rand(rng)).collect();
            let rcv: Vec<Fr> = (0..len).map(|_| Fr::rand(rng)).collect();
            let (alpha, beta) = (Fr::rand(rng), Fr::rand(rng));
            let (coeff, b_scale, a_scale) = (Fr::rand(rng), Fr::rand(rng), Fr::rand(rng));
            let case = format!("lg {lg} len {len}");
            compare(&mut bad, &case, lg, &row, &col, &rcv, alpha, beta, coeff, b_scale, a_scale);
        }

        // Every failing case in one run, not just the first.
        assert!(bad.is_empty(), "{}", bad.join("; "));
    }

    /// `compare` with the cross products chosen directly: `col = beta - 1` and
    /// `row = alpha - v` give `cross = v`.
    fn agrees(bad: &mut Vec<String>, rng: &mut TestRng, v: Vec<Fr>, coeff: Fr, case: &str) {
        let (alpha, beta) = (Fr::rand(rng), Fr::rand(rng));
        let (b_scale, a_scale) = (Fr::rand(rng), Fr::rand(rng));
        let row: Vec<Fr> = v.iter().map(|&x| alpha - x).collect();
        let col = vec![beta - Fr::one(); v.len()];
        let rcv: Vec<Fr> = (0..v.len()).map(|_| Fr::rand(rng)).collect();
        // The interpolations fault on a one-element domain.
        let lg = v.len().next_power_of_two().trailing_zeros().max(1);
        let case = format!("{case} (len {})", v.len());
        compare(bad, &case, lg, &row, &col, &rcv, alpha, beta, coeff, b_scale, a_scale);
    }

    /// The batch inversion's edge cases.
    #[test]
    fn chosen_cross_products_match_the_host_sequence() {
        let rng = &mut TestRng::default();
        let bad = &mut Vec::new();
        let coeff = Fr::rand(rng);

        // Sizes around the scan's chunking: `prefix_op` picks a kernel arm by
        // block count.
        for len in [1usize, 2, 3, 31, 32, 33, 255, 4097] {
            let v = (0..len).map(|_| Fr::rand(rng)).collect();
            agrees(bad, rng, v, coeff, "random");
        }

        // Zeros, which the host leaves alone.
        agrees(bad, rng, vec![Fr::zero(); 8], coeff, "all zero");
        let v = vec![Fr::zero(), Fr::rand(rng), Fr::zero(), Fr::rand(rng)];
        agrees(bad, rng, v, coeff, "alternating zero");
        // Distinct values: with equal entries, an off-by-one in the scan's
        // indexing would go unseen.
        for (i, case) in [(0, "zero first"), (7, "zero inside"), (63, "zero last")] {
            let mut v: Vec<Fr> = (0..64).map(|_| Fr::rand(rng)).collect();
            v[i] = Fr::zero();
            agrees(bad, rng, v, coeff, case);
        }

        // Degenerate values.
        agrees(bad, rng, vec![Fr::one()], coeff, "single one");
        let v = vec![Fr::rand(rng)];
        agrees(bad, rng, v, Fr::one(), "unit coefficient");

        assert!(bad.is_empty(), "GPU disagreed on:\n  {}", bad.join("\n  "));
    }
}

/// The round-four chain's tail against the host: the shift into `g`, the `b*f`
/// multiply, the subtract, and the vanishing divide.
///
/// The reference starts from `fourth_round_polys`, not from
/// `interpolate_with_pc`, because the latter is itself a device call under
/// `cuda`. The interpolations are covered by
/// `fft::domain::test_fft_correctness_cuda`.
///
/// These tests drive the FFI function, not its caller, so a wrong
/// `selector_mult` at the call site shows up only as a verification failure.
#[cfg(all(test, feature = "cuda", target_arch = "x86_64"))]
mod gpu_fourth_round_chain_contract {
    use crate::{
        fft::{DensePolynomial, EvaluationDomain},
        snark::varuna::ahp::selectors::apply_randomized_selector,
    };
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::{One, Zero};
    use snarkvm_utilities::rand::{TestRng, Uniform};

    /// `cudaErrorAssert`, which the chain returns for a wrong proof rather than
    /// for wrong arguments.
    const CUDA_ERROR_ASSERT: i32 = 710;

    /// Schoolbook multiplication, because `PolyMultiplier` runs on the device
    /// under `cuda`. It is quadratic, which bounds the test sizes.
    fn naive_mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
        let mut out = vec![Fr::zero(); a.len() + b.len() - 1];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                out[i + j] += *x * y;
            }
        }
        out
    }

    #[test]
    fn chain_matches_the_host_tail() {
        let rng = &mut TestRng::default();
        let mut bad: Vec<String> = Vec::new();

        // `(lg, len)`. The last two cover `len < domain`, where the kernel
        // zeroes `[len, domain)`.
        for (lg, len) in
            [(5u32, 1usize << 5), (10, 1 << 10), (12, 1 << 12), (10, (1 << 10) - 7), (12, (1 << 12) - 1025)]
        {
            let domain_size = 1usize << lg;
            let non_zero_domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
            // Four times the source, so `selector_mult` is not one.
            let max_non_zero_domain = EvaluationDomain::<Fr>::new(domain_size * 4).unwrap();
            let selector_mult = non_zero_domain.size_as_field_element * max_non_zero_domain.size_inv;

            let row: Vec<Fr> = (0..len).map(|_| Fr::rand(rng)).collect();
            let col: Vec<Fr> = (0..len).map(|_| Fr::rand(rng)).collect();
            let rcv: Vec<Fr> = (0..len).map(|_| Fr::rand(rng)).collect();
            let (alpha, beta) = (Fr::rand(rng), Fr::rand(rng));
            let (coeff, b_scale) = (Fr::rand(rng), Fr::rand(rng));
            // `h = a - b*f` vanishes on the non-zero domain only when
            // `a_scale == b_scale * coeff`, as the prover's arguments satisfy.
            // Otherwise both host and device refuse the divide.
            let a_scale = b_scale * coeff;

            // The prefix, shared with `fourth_round_polys`.
            let mut want_a = vec![Fr::zero(); domain_size];
            let mut want_b = vec![Fr::zero(); domain_size];
            let mut want_f = vec![Fr::zero(); domain_size];
            if snarkvm_algorithms_cuda::fourth_round_polys(
                &mut want_a,
                &mut want_b,
                &mut want_f,
                &row,
                &col,
                &rcv,
                lg,
                &alpha,
                &beta,
                &coeff,
                &b_scale,
                &a_scale,
            )
            .is_err()
            {
                bad.push(format!("lg {lg} len {len}: the reference prefix failed"));
                continue;
            }

            // The host tail of `calculate_matrix_sumcheck_witness`.
            let product = naive_mul(&want_b, &want_f);
            let mut h: Vec<Fr> = product.iter().map(|c| -*c).collect();
            for (slot, a) in h.iter_mut().zip(&want_a) {
                *slot += a;
            }
            let mut h = DensePolynomial::from_coefficients_vec(h);
            let (want_lhs, remainder) =
                match apply_randomized_selector(&mut h, Fr::one(), &max_non_zero_domain, &non_zero_domain, false) {
                    Ok(v) => v,
                    Err(e) => {
                        bad.push(format!("lg {lg} len {len}: the host tail refused the divide ({e})"));
                        continue;
                    }
                };
            assert!(remainder.is_none(), "asked for no remainder witness");

            let mut got_a = vec![Fr::zero(); domain_size];
            let mut got_b = vec![Fr::zero(); domain_size];
            let mut got_g = vec![Fr::zero(); domain_size - 1];
            let mut got_lhs = vec![Fr::zero(); domain_size - 1];
            let mut got_f0 = Fr::zero();
            if snarkvm_algorithms_cuda::fourth_round_chain(
                &mut got_a,
                &mut got_b,
                &mut got_g,
                &mut got_lhs,
                &mut got_f0,
                &row,
                &col,
                &rcv,
                lg,
                lg + 1,
                &alpha,
                &beta,
                &coeff,
                &b_scale,
                &a_scale,
                &selector_mult,
            )
            .is_err()
            {
                bad.push(format!("lg {lg} len {len}: the chain failed"));
                continue;
            }

            // `a` and `b` come back untrimmed and domain-sized on both sides.
            if want_a != got_a {
                bad.push(format!("lg {lg} len {len} a: differs"));
            }
            if want_b != got_b {
                bad.push(format!("lg {lg} len {len} b: differs"));
            }
            // `g` is `f` without its constant term.
            if want_f[1..] != got_g[..] {
                bad.push(format!("lg {lg} len {len} g: differs"));
            }
            if want_f[0] != got_f0 {
                bad.push(format!("lg {lg} len {len} f0: differs"));
            }
            // `apply_randomized_selector` trims and the device does not, so
            // compare over the host length and require the rest to be zero.
            if want_lhs.coeffs.len() > got_lhs.len() {
                bad.push(format!("lg {lg} len {len} lhs: {} coeffs against {}", got_lhs.len(), want_lhs.coeffs.len()));
                continue;
            }
            if let Some(i) = (0..want_lhs.coeffs.len()).find(|&i| want_lhs.coeffs[i] != got_lhs[i]) {
                bad.push(format!("lg {lg} len {len} lhs: coeff {i} differs"));
            }
            if let Some(i) = (want_lhs.coeffs.len()..got_lhs.len()).find(|&i| !got_lhs[i].is_zero()) {
                bad.push(format!("lg {lg} len {len} lhs: coeff {i} past the degree is non-zero"));
            }
        }

        // Every failing case in one run, not just the first.
        assert!(bad.is_empty(), "{}", bad.join("; "));
    }

    /// A `q_len` short of the quotient must be refused, not silently truncated.
    ///
    /// Both the remainder and the tail checks fire here;
    /// `a_truncated_quotient_is_refused` separates them.
    #[test]
    fn a_short_q_len_is_refused() {
        let rng = &mut TestRng::default();
        let lg = 10u32;
        let domain_size = 1usize << lg;
        let non_zero = EvaluationDomain::<Fr>::new(domain_size).unwrap();
        let max_non_zero = EvaluationDomain::<Fr>::new(domain_size * 4).unwrap();
        let selector_mult = non_zero.size_as_field_element * max_non_zero.size_inv;

        let row: Vec<Fr> = (0..domain_size).map(|_| Fr::rand(rng)).collect();
        let col: Vec<Fr> = (0..domain_size).map(|_| Fr::rand(rng)).collect();
        let rcv: Vec<Fr> = (0..domain_size).map(|_| Fr::rand(rng)).collect();
        let (alpha, beta) = (Fr::rand(rng), Fr::rand(rng));
        let (coeff, b_scale) = (Fr::rand(rng), Fr::rand(rng));
        let a_scale = b_scale * coeff;

        let run = |q_len: usize| {
            let mut a = vec![Fr::zero(); domain_size];
            let mut b = vec![Fr::zero(); domain_size];
            let mut g = vec![Fr::zero(); domain_size - 1];
            let mut lhs = vec![Fr::zero(); q_len];
            let mut f0 = Fr::zero();
            snarkvm_algorithms_cuda::fourth_round_chain(
                &mut a,
                &mut b,
                &mut g,
                &mut lhs,
                &mut f0,
                &row,
                &col,
                &rcv,
                lg,
                lg + 1,
                &alpha,
                &beta,
                &coeff,
                &b_scale,
                &a_scale,
                &selector_mult,
            )
            .err()
            .map(|e| e.code)
        };

        assert_eq!(run(domain_size - 1), None, "the bound the prover passes must be accepted");
        for short in [domain_size / 2, 8, 1] {
            // `cudaErrorAssert` specifically, so a shape guard cannot pass this.
            assert_eq!(
                run(short),
                Some(CUDA_ERROR_ASSERT),
                "a q_len of {short} strands quotient coefficients and must be refused as a wrong proof"
            );
        }
    }

    /// A short `q_len` whose only witness is above the quotient.
    ///
    /// The remainder and tail checks of `d_vanishing_scaled` are independent.
    /// This builds an `h` whose remainder indices are all zero, so only the
    /// tail check can refuse it: `rcv` makes `a` the monomial
    /// `gamma * X^(n-2)`, and `a_scale` cancels that index against
    /// `(b*f)[2n-2]`.
    #[test]
    fn a_truncated_quotient_is_refused() {
        use snarkvm_fields::{FftField, Field};

        let rng = &mut TestRng::default();
        for lg in [5u32, 10] {
            let n = 1usize << lg;
            let w = Fr::get_root_of_unity(n).unwrap();

            let (alpha, beta) = (Fr::rand(rng), Fr::rand(rng));
            let row: Vec<Fr> = (0..n)
                .map(|_| {
                    let t = loop {
                        let x = Fr::rand(rng);
                        if !x.is_zero() {
                            break x;
                        }
                    };
                    alpha - t
                })
                .collect();
            let col: Vec<Fr> = (0..n).map(|_| beta - Fr::one()).collect();

            let gamma = Fr::rand(rng);
            let w_n2 = w.pow([(n - 2) as u64]);
            let mut power = Fr::one();
            let rcv: Vec<Fr> = (0..n)
                .map(|_| {
                    let v = gamma * power;
                    power *= w_n2;
                    v
                })
                .collect();

            let (coeff, b_scale) = (Fr::rand(rng), Fr::rand(rng));

            // The device's own prefix, to read `b` and `f` off it.
            let (mut r_poly, mut b_poly, mut f_poly) = (vec![Fr::zero(); n], vec![Fr::zero(); n], vec![Fr::zero(); n]);
            snarkvm_algorithms_cuda::fourth_round_polys(
                &mut r_poly,
                &mut b_poly,
                &mut f_poly,
                &row,
                &col,
                &rcv,
                lg,
                &alpha,
                &beta,
                &coeff,
                &b_scale,
                &Fr::one(),
            )
            .map_err(|e| e.code)
            .expect("the prefix must run");
            assert_eq!(r_poly[n - 2], gamma, "lg {lg}: a must interpolate to the monomial");
            assert!(
                (0..n).filter(|&i| i != n - 2).all(|i| r_poly[i].is_zero()),
                "lg {lg}: the monomial must have no other terms"
            );

            // `(b*f)[2n-2]` is `b[n-1] * f[n-1]`, and must be non-zero or there
            // is nothing above the quotient to find.
            let h_top = b_poly[n - 1] * f_poly[n - 1];
            assert!(!h_top.is_zero(), "lg {lg}: the tail coefficient must be non-zero");
            let a_scale = b_scale * coeff - h_top * gamma.inverse().unwrap();

            // Check the witness pattern on the host, because the error code
            // alone does not say which check fired.
            let prod = naive_mul(&b_poly, &f_poly);
            let h: Vec<Fr> = (0..2 * n)
                .map(|i| {
                    let a_i = if i < n { a_scale * r_poly[i] } else { Fr::zero() };
                    a_i - prod.get(i).copied().unwrap_or_else(Fr::zero)
                })
                .collect();
            for i in 0..n - 2 {
                assert!((h[i] + h[n + i]).is_zero(), "lg {lg}: remainder index {i} must vanish");
            }
            assert!(h[n - 2].is_zero(), "lg {lg}: the solved index must vanish");
            assert!(h[n - 1].is_zero(), "lg {lg}: the last remainder index must vanish");
            assert!(!h[2 * n - 2].is_zero(), "lg {lg}: the tail witness must be non-zero");
            assert!(h[2 * n - 1].is_zero(), "lg {lg}: nothing above the witness");

            let mut a = vec![Fr::zero(); n];
            let mut b = vec![Fr::zero(); n];
            let mut g = vec![Fr::zero(); n - 1];
            let mut lhs = vec![Fr::zero(); n - 2];
            let mut f0 = Fr::zero();
            let code = snarkvm_algorithms_cuda::fourth_round_chain(
                &mut a,
                &mut b,
                &mut g,
                &mut lhs,
                &mut f0,
                &row,
                &col,
                &rcv,
                lg,
                lg + 1,
                &alpha,
                &beta,
                &coeff,
                &b_scale,
                &a_scale,
                &Fr::one(),
            )
            .err()
            .map(|e| e.code);
            assert_eq!(
                code,
                Some(CUDA_ERROR_ASSERT),
                "lg {lg}: a quotient truncated at n-2 must be refused, and only the tail branch sees it"
            );
        }
    }
}
