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
        EvaluationDomain,
        domain::{FFTPrecomputation, IFFTPrecomputation},
    },
    polycommit::sonic_pc::{LCTerm, LabeledPolynomial, LinearCombination},
    r1cs::SynthesisError,
    snark::varuna::{
        SNARKMode,
        VarunaVersion,
        ahp::{AHPError, CircuitId, CircuitInfo, verifier},
        prover,
        selectors::precompute_selectors,
        verifier::{QueryPoints, select_third_round_challenges},
    },
};
use anyhow::{Result, anyhow, ensure};
use snarkvm_fields::{Field, PrimeField};
use snarkvm_utilities::defer;

use core::{borrow::Borrow, marker::PhantomData};
use itertools::Itertools;
use std::{collections::BTreeMap, fmt::Write};

/// The algebraic holographic proof defined in [CHMMVW19](https://eprint.iacr.org/2019/1047).
/// Currently, this AHP only supports inputs of size one
/// less than a power of 2 (i.e., of the form 2^n - 1).
pub struct AHPForR1CS<F: Field, SM: SNARKMode> {
    field: PhantomData<F>,
    mode: PhantomData<SM>,
}

pub(crate) fn witness_label(circuit_id: CircuitId, poly: &str, i: usize) -> String {
    let mut label = String::with_capacity(82 + poly.len());
    let _ = write!(&mut label, "circuit_{circuit_id}_{poly}_{i:0>8}");
    label
}

pub(crate) struct NonZeroDomains<F: PrimeField> {
    pub(crate) max_non_zero_domain: Option<EvaluationDomain<F>>,
    pub(crate) domain_a: EvaluationDomain<F>,
    pub(crate) domain_b: EvaluationDomain<F>,
    pub(crate) domain_c: EvaluationDomain<F>,
}

impl<F: PrimeField, SM: SNARKMode> AHPForR1CS<F, SM> {
    /// The linear combinations that are statically known to evaluate to zero.
    /// These correspond to the virtual commitments as noted in the Aleo varuna
    /// protocol docs
    pub const LC_WITH_ZERO_EVAL: [&'static str; 3] = ["matrix_sumcheck", "lineval_sumcheck", "rowcheck_zerocheck"];

    pub fn zk_bound() -> Option<usize> {
        SM::ZK.then_some(1)
    }

    /// Check that the (formatted) public input is of the form 2^n for some
    /// integer n.
    pub fn num_formatted_public_inputs_is_admissible(num_inputs: usize) -> Result<(), AHPError> {
        match num_inputs.count_ones() == 1 {
            true => Ok(()),
            false => Err(AHPError::InvalidPublicInputLength),
        }
    }

    /// Check that the (formatted) public input is of the form 2^n for some
    /// integer n.
    pub fn formatted_public_input_is_admissible(input: &[F]) -> Result<(), AHPError> {
        Self::num_formatted_public_inputs_is_admissible(input.len())
    }

    /// The maximum degree of polynomials produced by the indexer and prover
    /// of this protocol.
    /// The number of the variables must include the "one" variable. That is, it
    /// must be with respect to the number of formatted public inputs.
    pub fn max_degree(num_constraints: usize, num_variables: usize, num_non_zero: usize) -> Result<usize> {
        let zk_bound = Self::zk_bound().unwrap_or(0);
        let constraint_domain_size =
            EvaluationDomain::<F>::compute_size_of_domain(num_constraints).ok_or(AHPError::PolyTooLarge)?;
        let variable_domain_size =
            EvaluationDomain::<F>::compute_size_of_domain(num_variables).ok_or(AHPError::PolyTooLarge)?;
        let non_zero_domain_size =
            EvaluationDomain::<F>::compute_size_of_domain(num_non_zero).ok_or(AHPError::PolyTooLarge)?;

        // these should correspond with the bounds set in the <round>.rs files
        [
            2 * constraint_domain_size + 2 * zk_bound - 2,
            2 * variable_domain_size + 2 * zk_bound - 2,
            if SM::ZK { variable_domain_size + 3 } else { 0 }, // mask_poly
            variable_domain_size,
            constraint_domain_size,
            non_zero_domain_size - 1, // non-zero polynomials
        ]
        .iter()
        .max()
        .copied()
        .ok_or(anyhow!("Could not find max_degree"))
    }

    /// Get all the strict degree bounds enforced in the AHP.
    pub fn get_degree_bounds(info: &CircuitInfo) -> Result<[usize; 4]> {
        let num_variables = info.num_public_and_private_variables;
        let num_non_zero_a = info.num_non_zero_a;
        let num_non_zero_b = info.num_non_zero_b;
        let num_non_zero_c = info.num_non_zero_c;
        Ok([
            EvaluationDomain::<F>::compute_size_of_domain(num_variables).ok_or(SynthesisError::PolyTooLarge)? - 2,
            EvaluationDomain::<F>::compute_size_of_domain(num_non_zero_a).ok_or(SynthesisError::PolyTooLarge)? - 2,
            EvaluationDomain::<F>::compute_size_of_domain(num_non_zero_b).ok_or(SynthesisError::PolyTooLarge)? - 2,
            EvaluationDomain::<F>::compute_size_of_domain(num_non_zero_c).ok_or(SynthesisError::PolyTooLarge)? - 2,
        ])
    }

    pub(crate) fn cmp_non_zero_domains(
        info: &CircuitInfo,
        max_candidate: Option<EvaluationDomain<F>>,
    ) -> Result<NonZeroDomains<F>> {
        let domain_a = EvaluationDomain::new(info.num_non_zero_a).ok_or(SynthesisError::PolyTooLarge)?;
        let domain_b = EvaluationDomain::new(info.num_non_zero_b).ok_or(SynthesisError::PolyTooLarge)?;
        let domain_c = EvaluationDomain::new(info.num_non_zero_c).ok_or(SynthesisError::PolyTooLarge)?;
        let new_candidate = [domain_a, domain_b, domain_c]
            .into_iter()
            .max_by_key(|d| d.size())
            .ok_or(anyhow!("could not find max domain"))?;
        let mut max_non_zero_domain = Some(new_candidate);
        if let Some(max_candidate) = max_candidate
            && max_candidate.size() > new_candidate.size()
        {
            max_non_zero_domain = Some(max_candidate);
        }
        Ok(NonZeroDomains { max_non_zero_domain, domain_a, domain_b, domain_c })
    }

    pub fn fft_precomputation(
        constraint_domain_size: usize,
        variable_domain_size: usize,
        non_zero_a_domain_size: usize,
        non_zero_b_domain_size: usize,
        non_zero_c_domain_size: usize,
    ) -> Option<(FFTPrecomputation<F>, IFFTPrecomputation<F>)> {
        let largest_domain_size = [
            2 * constraint_domain_size,
            2 * variable_domain_size,
            2 * non_zero_a_domain_size,
            2 * non_zero_b_domain_size,
            2 * non_zero_c_domain_size,
        ]
        .into_iter()
        .max()?;
        let largest_mul_domain = EvaluationDomain::new(largest_domain_size)?;

        let fft_precomputation = largest_mul_domain.precompute_fft();
        let ifft_precomputation = fft_precomputation.to_ifft_precomputation();
        Some((fft_precomputation, ifft_precomputation))
    }

    /// Construct the linear combinations that are checked by the AHP.
    /// Public input should be unformatted.
    /// We construct the linear combinations as per section 5 of our protocol
    /// documentation. We can distinguish between:
    /// (1) simple commitments: $\{\cm{g_A}, \cm{g_B}, \cm{g_C}\}$ and
    /// $\{\cm{\hat{z}_{B,i,j}}\}_{i \in {[\mathcal{D}]}}$, $\cm{g_1}$
    /// (2) virtual commitments for the lincheck_sumcheck and matrix_sumcheck.
    /// These are linear combinations of the simple commitments
    #[allow(non_snake_case)]
    pub fn construct_linear_combinations<E: EvaluationsProvider<F>>(
        public_inputs: &BTreeMap<CircuitId, Vec<Vec<F>>>,
        evals: &E,
        prover_third_message: &prover::ThirdMessage<F>,
        prover_fourth_message: &prover::FourthMessage<F>,
        state: &verifier::State<F, SM>,
        varuna_version: VarunaVersion,
    ) -> Result<BTreeMap<String, LinearCombination<F>>> {
        ensure!(!public_inputs.is_empty());
        let max_constraint_domain = state.max_constraint_domain;
        let max_variable_domain = state.max_variable_domain;
        let max_non_zero_domain = state.max_non_zero_domain;
        let mut formatted_public_inputs = Vec::with_capacity(state.circuit_specific_states.len());
        for (circuit_id, circuit_state) in &state.circuit_specific_states {
            let input_domain = circuit_state.input_domain;
            let public_inputs_i = public_inputs[circuit_id]
                .iter()
                .map(|p| {
                    let public_input = prover::ConstraintSystem::format_public_input(p);
                    Self::formatted_public_input_is_admissible(&public_input)?;
                    Ok::<_, AHPError>(public_input)
                })
                .collect::<Result<Vec<_>, _>>()?;
            ensure!(public_inputs_i[0].len() == input_domain.size());
            formatted_public_inputs.push(public_inputs_i);
        }

        let verifier::FirstMessage { first_round_batch_combiners } = state.first_round_message.as_ref().unwrap();
        let verifier::ThirdMessage { beta } = state.third_round_message.unwrap();

        // Choose challenges based on the proof system version.
        let (alpha, third_round_batch_combiners, eta_a, eta_b, eta_c) = select_third_round_challenges(
            state.first_round_message.as_ref().unwrap(),
            state.second_round_message.as_ref().unwrap(),
            state.prepare_third_round_message.as_ref(),
            varuna_version,
        )
        .map_err(AHPError::AnyhowError)?;

        let batch_lineval_sum = prover_third_message.sum(&third_round_batch_combiners, eta_a, eta_b, eta_c)
            * state.max_variable_domain.size_inv;
        let verifier::FourthMessage { delta_a, delta_b, delta_c } = state.fourth_round_message.as_ref().unwrap();
        let sums_fourth_msg = &prover_fourth_message.sums;
        let gamma = state.gamma.unwrap();
        let challenges = QueryPoints::new(alpha, beta, gamma);

        let mut linear_combinations = BTreeMap::new();
        let constraint_domains = state.constraint_domains();
        let variable_domains = state.variable_domains();
        let non_zero_domains = state.non_zero_domains();
        let selectors = precompute_selectors(
            max_constraint_domain,
            constraint_domains,
            max_variable_domain,
            variable_domains,
            max_non_zero_domain,
            non_zero_domains,
            challenges,
        );

        // We're now going to calculate the rowcheck_zerocheck
        {
            let rowcheck_time = start_timer!(|| "Rowcheck");
            defer! { end_timer!(rowcheck_time); }

            let v_R_at_alpha_time = start_timer!(|| "v_R_at_alpha");
            let v_R_at_alpha = max_constraint_domain.evaluate_vanishing_polynomial(alpha);
            end_timer!(v_R_at_alpha_time);

            let rowcheck_zerocheck = {
                let mut rowcheck_zerocheck = LinearCombination::empty("rowcheck_zerocheck");
                for (i, (id, c)) in first_round_batch_combiners.iter().enumerate() {
                    let mut circuit_term = LinearCombination::empty(format!("rowcheck_zerocheck term {id}"));
                    let third_sums_i = &prover_third_message.sums[i];
                    let circuit_state = &state.circuit_specific_states[id];

                    for (j, instance_combiner) in c.instance_combiners.iter().enumerate() {
                        let mut rowcheck = LinearCombination::empty(format!("rowcheck term {id}"));
                        let sum_a_third = third_sums_i[j].sum_a;
                        let sum_b_third = third_sums_i[j].sum_b;
                        let sum_c_third = third_sums_i[j].sum_c;

                        rowcheck.add(sum_a_third * sum_b_third - sum_c_third, LCTerm::One);

                        circuit_term += (*instance_combiner, &rowcheck);
                    }
                    let constraint_domain = circuit_state.constraint_domain;
                    let selector = selectors
                        .get(&(max_constraint_domain.size, constraint_domain.size, alpha))
                        .ok_or(anyhow!("Could not find selector at alpha"))?;
                    circuit_term *= *selector;
                    rowcheck_zerocheck += (c.circuit_combiner, &circuit_term);
                }
                rowcheck_zerocheck.add(-v_R_at_alpha, "h_0");
                rowcheck_zerocheck
            };

            debug_assert!(evals.get_lc_eval(&rowcheck_zerocheck, alpha)?.is_zero());
            linear_combinations.insert("rowcheck_zerocheck".into(), rowcheck_zerocheck);
        }

        // Lineval sumcheck:
        {
            let lineval_time = start_timer!(|| "Lineval");
            defer! { end_timer!(lineval_time); }

            let g_1 = LinearCombination::new("g_1", [(F::one(), "g_1")]);

            let v_C_at_beta = max_variable_domain.evaluate_vanishing_polynomial(beta);

            let v_X_at_beta_time = start_timer!(|| "v_X_at_beta");
            let v_X_at_beta = state
                .circuit_specific_states
                .iter()
                .map(|(circuit_id, circuit_state)| {
                    let v_X_i_at_beta = circuit_state.input_domain.evaluate_vanishing_polynomial(beta);
                    (circuit_id, v_X_i_at_beta)
                })
                .collect::<BTreeMap<_, _>>();
            end_timer!(v_X_at_beta_time);

            let x_at_betas = state
                .circuit_specific_states
                .iter()
                .enumerate()
                .map(|(i, (circuit_id, circuit_state))| {
                    let lag_at_beta = circuit_state.input_domain.evaluate_all_lagrange_coefficients(beta);
                    let x_at_beta = formatted_public_inputs[i]
                        .iter()
                        .map(|x| x.iter().zip_eq(&lag_at_beta).map(|(x, l)| *x * l).sum::<F>())
                        .collect_vec();
                    (circuit_id, x_at_beta)
                })
                .collect::<BTreeMap<_, _>>();

            let g_1_at_beta = evals.get_lc_eval(&g_1, beta)?;

            // We're now going to calculate the lineval_sumcheck
            let lineval_sumcheck = {
                let mut lineval_sumcheck = LinearCombination::empty("lineval_sumcheck");
                if SM::ZK {
                    lineval_sumcheck.add(F::one(), "mask_poly");
                }
                for (i, (id, c)) in third_round_batch_combiners.iter().enumerate() {
                    let mut circuit_term = LinearCombination::empty(format!("lineval_sumcheck term {id}"));
                    let fourth_sums_i = &sums_fourth_msg[i];
                    let circuit_state = &state.circuit_specific_states[id];

                    for (j, instance_combiner) in c.instance_combiners.iter().enumerate() {
                        let w_j = witness_label(*id, "w", j);
                        let mut lineval = LinearCombination::empty(format!("lineval term {j}"));
                        let sum_a_fourth = fourth_sums_i.sum_a * circuit_state.non_zero_a_domain.size_as_field_element;
                        let sum_b_fourth = fourth_sums_i.sum_b * circuit_state.non_zero_b_domain.size_as_field_element;
                        let sum_c_fourth = fourth_sums_i.sum_c * circuit_state.non_zero_c_domain.size_as_field_element;

                        lineval.add(sum_a_fourth * eta_a * x_at_betas[id][j], LCTerm::One);
                        lineval.add(sum_a_fourth * eta_a * v_X_at_beta[id], w_j.clone());

                        lineval.add(sum_b_fourth * eta_b * x_at_betas[id][j], LCTerm::One);
                        lineval.add(sum_b_fourth * eta_b * v_X_at_beta[id], w_j.clone());

                        lineval.add(sum_c_fourth * eta_c * x_at_betas[id][j], LCTerm::One);
                        lineval.add(sum_c_fourth * eta_c * v_X_at_beta[id], w_j);

                        circuit_term += (*instance_combiner, &lineval);
                    }
                    let variable_domain = circuit_state.variable_domain;
                    let selector = selectors
                        .get(&(max_variable_domain.size, variable_domain.size, beta))
                        .ok_or(anyhow!("Could not find selector at beta"))?;
                    circuit_term *= *selector;

                    lineval_sumcheck += (c.circuit_combiner, &circuit_term);
                }
                lineval_sumcheck
                    .add(-v_C_at_beta, "h_1")
                    .add(-beta * g_1_at_beta, LCTerm::One)
                    .add(-batch_lineval_sum, LCTerm::One);
                lineval_sumcheck
            };
            debug_assert!(evals.get_lc_eval(&lineval_sumcheck, beta)?.is_zero());

            linear_combinations.insert("g_1".into(), g_1);
            linear_combinations.insert("lineval_sumcheck".into(), lineval_sumcheck);
        }

        //  Matrix sumcheck:
        {
            let matrix_sumcheck_time = start_timer!(|| "Matrix sumcheck");
            defer! { end_timer!(matrix_sumcheck_time); }
            let v_K_at_gamma = max_non_zero_domain.evaluate_vanishing_polynomial(gamma);
            let mut matrix_sumcheck = LinearCombination::empty("matrix_sumcheck");

            for (i, (&id, state_i)) in state.circuit_specific_states.iter().enumerate() {
                let v_R_i_at_alpha = state_i.constraint_domain.evaluate_vanishing_polynomial(alpha);
                let v_C_i_at_beta = state_i.variable_domain.evaluate_vanishing_polynomial(beta);
                let v_rc = v_R_i_at_alpha * v_C_i_at_beta;
                let rc =
                    state_i.constraint_domain.size_as_field_element * state_i.variable_domain.size_as_field_element;

                let matrices = ["a", "b", "c"];
                let deltas = [delta_a[i], delta_b[i], delta_c[i]];
                let non_zero_domains =
                    [&state_i.non_zero_a_domain, &state_i.non_zero_b_domain, &state_i.non_zero_c_domain];
                let sums = sums_fourth_msg[i].iter();

                ensure!(matrices.len() == sums.len());
                ensure!(matrices.len() == deltas.len());
                ensure!(matrices.len() == non_zero_domains.len());
                for (((m, sum), delta), non_zero_domain) in
                    matrices.into_iter().zip_eq(sums).zip_eq(deltas).zip_eq(non_zero_domains)
                {
                    let selector = selectors
                        .get(&(max_non_zero_domain.size, non_zero_domain.size, gamma))
                        .ok_or(anyhow!("Could not find selector at gamma"))?;
                    let label = "g_".to_string() + m;
                    let g_m_label = witness_label(id, &label, 0);
                    let g_m = LinearCombination::new(g_m_label.clone(), [(F::one(), g_m_label)]);
                    let g_m_at_gamma = evals.get_lc_eval(&g_m, gamma)?;

                    let (a_poly, b_poly) =
                        Self::construct_matrix_linear_combinations(evals, id, m, v_rc, challenges, rc)?;
                    let g_m_term = Self::construct_g_m_term(gamma, g_m_at_gamma, sum, *selector, a_poly, b_poly);

                    matrix_sumcheck += (delta, &g_m_term);

                    linear_combinations.insert(g_m.label.clone(), g_m);
                }
            }

            matrix_sumcheck -= &LinearCombination::new("h_2", [(v_K_at_gamma, "h_2")]);
            debug_assert!(evals.get_lc_eval(&matrix_sumcheck, gamma)?.is_zero());

            linear_combinations.insert("matrix_sumcheck".into(), matrix_sumcheck);
        }

        Ok(linear_combinations)
    }

    fn construct_g_m_term(
        gamma: F,
        g_m_at_gamma: F,
        sum: F,
        selector_at_gamma: F,
        a_poly: LinearCombination<F>,
        mut b_poly: LinearCombination<F>,
    ) -> LinearCombination<F> {
        let b_term = gamma * g_m_at_gamma + sum; // Xg_m(\gamma) + sum_m/|K_M|
        b_poly *= b_term;

        let mut lhs = a_poly;
        lhs -= &b_poly;
        lhs *= selector_at_gamma;
        lhs
    }

    fn construct_matrix_linear_combinations<E: EvaluationsProvider<F>>(
        evals: &E,
        id: CircuitId,
        matrix: &str,
        v_rc_at_alpha_beta: F,
        challenges: QueryPoints<F>,
        rc_size: F,
    ) -> Result<(LinearCombination<F>, LinearCombination<F>)> {
        let label_a_poly = format!("circuit_{id}_a_poly_{matrix}");
        let label_b_poly = format!("circuit_{id}_b_poly_{matrix}");
        let QueryPoints { alpha, beta, gamma } = challenges;

        // When running as the prover, who has access to a(X) and b(X), we directly
        // return those
        // `has_lc_eval`, not `get_lc_eval(..).is_ok()`: the question is whether the
        // polynomial is present, and the prover's implementation of the latter
        // answers it by evaluating the polynomial and throwing the value away.
        let a_poly = LinearCombination::new(label_a_poly.clone(), [(F::one(), label_a_poly.clone())]);
        let a_poly_eval_available = evals.has_lc_eval(&a_poly, gamma);
        let b_poly = LinearCombination::new(label_b_poly.clone(), [(F::one(), label_b_poly.clone())]);
        let b_poly_eval_available = evals.has_lc_eval(&b_poly, gamma);
        ensure!(a_poly_eval_available == b_poly_eval_available);
        if a_poly_eval_available && b_poly_eval_available {
            return Ok((a_poly, b_poly));
        };

        // When running as the verifier, we need to construct a(X) and b(X) from the
        // indexing polynomials
        let label_col = format!("circuit_{id}_col_{matrix}");
        let label_row = format!("circuit_{id}_row_{matrix}");
        let label_row_col = format!("circuit_{id}_row_col_{matrix}");
        // recall that row_col_val(X) is M_{i,j}*rowcol(X)
        let label_row_col_val = format!("circuit_{id}_row_col_val_{matrix}");
        let a = LinearCombination::new(label_a_poly, [(v_rc_at_alpha_beta, label_row_col_val)]);
        let mut b = LinearCombination::new(label_b_poly, [
            (alpha * beta, LCTerm::One),
            (-alpha, (label_col).into()),
            (-beta, (label_row).into()),
            (F::one(), (label_row_col).into()),
        ]);
        b *= rc_size;
        Ok((a, b))
    }
}

/// Abstraction that provides evaluations of (linear combinations of)
/// polynomials
///
/// Intended to provide a common interface for both the prover and the verifier
/// when constructing linear combinations via
/// `AHPForR1CS::construct_linear_combinations`.
pub trait EvaluationsProvider<F: PrimeField>: core::fmt::Debug {
    /// Get the evaluation of linear combination `lc` at `point`.
    fn get_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> Result<F>;

    /// Whether `get_lc_eval` would succeed, without computing the value.
    ///
    /// `construct_matrix_linear_combinations` has to know which side of the
    /// protocol it is running on, and asks by seeing whether an evaluation is
    /// available. Answering that with `get_lc_eval(..).is_ok()` costs a full
    /// evaluation of every named polynomial on the prover's implementation, and
    /// the value is then discarded.
    ///
    /// Implementations must agree with `get_lc_eval(..).is_ok()` exactly.
    fn has_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> bool;
}

/// The `EvaluationsProvider` used by the verifier
impl<F: PrimeField> EvaluationsProvider<F> for crate::polycommit::sonic_pc::Evaluations<F> {
    fn get_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> Result<F> {
        let key = (lc.label.clone(), point);
        self.get(&key).copied().ok_or_else(|| AHPError::MissingEval(lc.label.clone())).map_err(Into::into)
    }

    fn has_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> bool {
        self.get(&(lc.label.clone(), point)).is_some()
    }
}

/// The `EvaluationsProvider` used by the prover
impl<F, T> EvaluationsProvider<F> for Vec<T>
where
    F: PrimeField,
    T: Borrow<LabeledPolynomial<F>> + core::fmt::Debug,
{
    fn get_lc_eval(&self, lc: &LinearCombination<F>, point: F) -> Result<F> {
        let mut eval = F::zero();
        for (coeff, term) in lc.iter() {
            let value = if let LCTerm::PolyLabel(label) = term {
                self.iter()
                    .find(|p| (*p).borrow().label() == label)
                    .ok_or_else(|| AHPError::MissingEval(format!("Missing {} for {}", label, lc.label)))?
                    .borrow()
                    .evaluate(point)
            } else {
                ensure!(term.is_one());
                F::one()
            };
            eval += &(*coeff * value)
        }
        Ok(eval)
    }

    fn has_lc_eval(&self, lc: &LinearCombination<F>, _point: F) -> bool {
        // Mirrors the two ways `get_lc_eval` above can fail: a `PolyLabel` term
        // with no matching polynomial, and a non-`PolyLabel` term that is not
        // one. The point is irrelevant -- if the polynomial is here, it can be
        // evaluated anywhere.
        lc.iter().all(|(_, term)| match term {
            LCTerm::PolyLabel(label) => self.iter().any(|p| (*p).borrow().label() == label),
            other => other.is_one(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft::DensePolynomial;
    use snarkvm_curves::bls12_377::fr::Fr;
    use snarkvm_fields::{One, Zero};
    use snarkvm_utilities::rand::{TestRng, Uniform};

    /// `has_lc_eval` exists only as a cheap stand-in for
    /// `get_lc_eval(..).is_ok()`, so the property worth testing is that the two
    /// never disagree -- including on the inputs that make `get_lc_eval` fail.
    #[test]
    fn has_lc_eval_agrees_with_get_lc_eval() {
        let rng = &mut TestRng::default();
        let point = Fr::rand(rng);
        let polys: Vec<LabeledPolynomial<Fr>> = ["a", "b"]
            .into_iter()
            .map(|label| LabeledPolynomial::new(label.to_string(), DensePolynomial::rand(1 << 4, rng), None, None))
            .collect();

        let cases = [
            // Present, absent, mixed, and a bare `One` term, which `get_lc_eval`
            // resolves without consulting the provider at all.
            LinearCombination::new("present", [(Fr::one(), "a")]),
            LinearCombination::new("absent", [(Fr::one(), "nope")]),
            LinearCombination::new("both", [(Fr::one(), "a"), (Fr::one(), "b")]),
            LinearCombination::new("one_present_one_not", [(Fr::one(), "a"), (Fr::one(), "nope")]),
            LinearCombination::new("constant", [(Fr::one(), LCTerm::One)]),
            LinearCombination::empty("empty"),
        ];

        for lc in &cases {
            assert_eq!(polys.has_lc_eval(lc, point), polys.get_lc_eval(lc, point).is_ok(), "disagreed on {}", lc.label);
        }
    }

    #[test]
    fn test_summation() {
        let rng = &mut TestRng::default();
        let size = 1 << 4;
        let domain = EvaluationDomain::<Fr>::new(1 << 4).unwrap();
        let size_as_fe = domain.size_as_field_element;
        let poly = DensePolynomial::rand(size, rng);

        let mut sum: Fr = Fr::zero();
        for eval in domain.elements().map(|e| poly.evaluate(e)) {
            sum += &eval;
        }
        let first = poly.coeffs[0] * size_as_fe;
        let last = *poly.coeffs.last().unwrap() * size_as_fe;
        assert_eq!(sum, first + last);
    }
}
