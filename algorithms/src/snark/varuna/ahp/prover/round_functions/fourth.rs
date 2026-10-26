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
