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
    fft::EvaluationDomain,
    polycommit::sonic_pc::{LinearCombination, PolynomialInfo, PolynomialLabel},
    r1cs::{ConstraintSynthesizer, errors::SynthesisError},
    snark::varuna::{
        SNARKMode,
        ahp::{
            AHPForR1CS,
            indexer::{Circuit, CircuitId, CircuitInfo, ConstraintSystem as IndexerConstraintSystem},
        },
        matrices::{MatrixEvals, into_matrix_helper, matrix_evals},
        num_non_zero,
    },
};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{cfg_into_iter, defer, dev_println};

use anyhow::{Result, anyhow, ensure};
use core::marker::PhantomData;
use itertools::Itertools;
use std::collections::BTreeMap;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

use super::Matrix;

impl<F: PrimeField, SM: SNARKMode> AHPForR1CS<F, SM> {
    /// Generate the index polynomials for this constraint system.
    pub fn index<C: ConstraintSynthesizer<F>>(c: &C) -> Result<Circuit<F, SM>> {
        let IndexerState {
            constraint_domain,
            variable_domain,

            a,
            non_zero_a_domain,
            a_arith,

            b,
            non_zero_b_domain,
            b_arith,

            c,
            non_zero_c_domain,
            c_arith,

            index_info,
            id,
        } = Self::index_helper(c).map_err(|e| anyhow!("{e:?}"))?;

        let (fft_precomputation, ifft_precomputation) = {
            let fft_precomp_time = start_timer!(|| format!("Precomputing roots of unity {id}"));
            defer! { end_timer!(fft_precomp_time); }
            Self::fft_precomputation(
                constraint_domain.size(),
                variable_domain.size(),
                non_zero_a_domain.size(),
                non_zero_b_domain.size(),
                non_zero_c_domain.size(),
            )
            .ok_or(anyhow!("The polynomial degree is too large"))?
        };

        Ok(Circuit {
            index_info,
            a,
            b,
            c,
            a_arith,
            b_arith,
            c_arith,
            fft_precomputation,
            ifft_precomputation,
            id,
            _mode: PhantomData,
        })
    }

    pub fn index_polynomial_info<'a>(
        circuit_ids: impl Iterator<Item = &'a CircuitId> + 'a,
    ) -> BTreeMap<PolynomialLabel, PolynomialInfo> {
        let mut map = BTreeMap::new();
        for label in Self::index_polynomial_labels(&["a", "b", "c"], circuit_ids) {
            map.insert(label.clone(), PolynomialInfo::new(label, None, None));
        }
        map
    }

    pub fn index_polynomial_labels_single<'a>(
        matrix: &str,
        id: &'a CircuitId,
    ) -> impl ExactSizeIterator<Item = PolynomialLabel> + 'a {
        [
            format!("circuit_{id}_row_{matrix}"),
            format!("circuit_{id}_col_{matrix}"),
            format!("circuit_{id}_row_col_{matrix}"),
            format!("circuit_{id}_row_col_val_{matrix}"),
        ]
        .into_iter()
    }

    pub fn index_polynomial_labels<'a>(
        matrices: &'a [&str],
        ids: impl Iterator<Item = &'a CircuitId> + 'a,
    ) -> impl Iterator<Item = PolynomialLabel> + 'a {
        ids.flat_map(move |id| matrices.iter().flat_map(move |matrix| Self::index_polynomial_labels_single(matrix, id)))
    }

    /// Generate the indexed circuit evaluations for this constraint system.
    /// Used by both the Prover and Verifier
    pub(crate) fn index_helper<C: ConstraintSynthesizer<F>>(c: &C) -> Result<IndexerState<F>> {
        let index_time = start_timer!(|| "AHP::Index");
        defer! { end_timer!(index_time); }

        let mut ics = {
            let constraint_time = start_timer!(|| "Generating constraints");
            defer! { end_timer!(constraint_time); }
            let mut ics = IndexerConstraintSystem::new();
            c.generate_constraints(&mut ics)?;
            ics
        };

        let (a, b, c, num_public_variables, num_private_variables, num_constraints) = {
            let padding_time = start_timer!(|| "Padding matrices");
            defer! { end_timer!(padding_time); }
            // Given that we only use the matrix for indexing, the values we choose for
            // assignments don't matter
            let random_assignments = None;
            SM::ZK.then(|| {
                crate::snark::varuna::ahp::matrices::add_randomizing_variables::<_, _>(&mut ics, random_assignments)
            });

            crate::snark::varuna::ahp::matrices::pad_input_for_indexer_and_prover(&mut ics)?;

            let IndexerConstraintSystem { a, b, c, num_public_variables, num_private_variables, num_constraints } = ics;

            let a = into_matrix_helper(a, num_public_variables)?;
            let b = into_matrix_helper(b, num_public_variables)?;
            let c = into_matrix_helper(c, num_public_variables)?;

            (a, b, c, num_public_variables, num_private_variables, num_constraints)
        };

        let num_padded_public_variables = num_public_variables;
        let num_non_zero_a = num_non_zero(&a);
        let num_non_zero_b = num_non_zero(&b);
        let num_non_zero_c = num_non_zero(&c);

        // Instance variables (including 1) are padded; their concatenation with the
        // witness is not.
        let num_variables = num_padded_public_variables + num_private_variables;

        dev_println!("Number of padded public variables: {num_padded_public_variables}");
        dev_println!("Number of private variables: {num_private_variables}");
        dev_println!("Number of num_constraints: {num_constraints}");
        dev_println!("Number of non-zero entries in A: {num_non_zero_a}");
        dev_println!("Number of non-zero entries in B: {num_non_zero_b}");
        dev_println!("Number of non-zero entries in C: {num_non_zero_c}");

        Self::num_formatted_public_inputs_is_admissible(num_padded_public_variables)?;

        let index_info = CircuitInfo {
            num_public_inputs: num_padded_public_variables,
            num_public_and_private_variables: num_variables,
            num_constraints,
            num_non_zero_a,
            num_non_zero_b,
            num_non_zero_c,
        };

        // R_i, C_i and C_i[x] in the notation of the Varuna spec.
        let constraint_domain = EvaluationDomain::new(num_constraints).ok_or(SynthesisError::PolyTooLarge)?;
        let variable_domain = EvaluationDomain::new(num_variables).ok_or(SynthesisError::PolyTooLarge)?;
        let input_domain = EvaluationDomain::new(num_padded_public_variables).ok_or(SynthesisError::PolyTooLarge)?;

        // K_A, K_B and K_C in the notation of the Varuna spec.
        let non_zero_a_domain = EvaluationDomain::new(num_non_zero_a).ok_or(SynthesisError::PolyTooLarge)?;
        let non_zero_b_domain = EvaluationDomain::new(num_non_zero_b).ok_or(SynthesisError::PolyTooLarge)?;
        let non_zero_c_domain = EvaluationDomain::new(num_non_zero_c).ok_or(SynthesisError::PolyTooLarge)?;

        let constraint_domain_elements = constraint_domain.elements().collect::<Vec<_>>();
        let variable_domain_elements = variable_domain.elements().collect::<Vec<_>>();

        let [a_arith, b_arith, c_arith]: [_; 3] =
            cfg_into_iter!([(&a, &non_zero_a_domain), (&b, &non_zero_b_domain), (&c, &non_zero_c_domain)])
                .map(|(matrix, non_zero_domain)| {
                    matrix_evals(
                        matrix,
                        non_zero_domain,
                        &variable_domain,
                        &input_domain,
                        &constraint_domain_elements,
                        &variable_domain_elements,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .unwrap();

        let id = Circuit::<F, SM>::hash(&index_info, &a, &b, &c)?;

        Ok(IndexerState {
            constraint_domain,
            variable_domain,

            a,
            non_zero_a_domain,
            a_arith,

            b,
            non_zero_b_domain,
            b_arith,

            c,
            non_zero_c_domain,
            c_arith,

            index_info,
            id,
        })
    }

    /// Evaluate the index polynomials for this constraint system at the given
    /// point. Return the LinearCombination of the index polynomials and the
    /// sum of the evaluations.
    pub(crate) fn evaluate_index_polynomials(
        state: IndexerState<F>,
        id: &CircuitId,
        point: F,
        mut combiners: impl Iterator<Item = F>,
    ) -> Result<(LinearCombination<F>, F)> {
        let mut lc = LinearCombination::empty("circuit_check");
        let mut all_evals = Vec::with_capacity(3);
        let mut sum = F::zero();
        for (evals, domain, label) in [
            (state.a_arith, state.non_zero_a_domain, "a"),
            (state.b_arith, state.non_zero_b_domain, "b"),
            (state.c_arith, state.non_zero_c_domain, "c"),
        ] {
            let labels = Self::index_polynomial_labels_single(label, id);
            let lagrange_coefficients_at_point = domain.evaluate_all_lagrange_coefficients(point);
            let evals_at_point = evals.evaluate(&lagrange_coefficients_at_point)?;
            ensure!(labels.len() == evals_at_point.len());
            all_evals.push(labels.into_iter().zip_eq(evals_at_point));
        }
        let sorted_evals = all_evals.into_iter().flatten().sorted_unstable_by(|(l1, _), (l2, _)| l1.cmp(l2));
        for (label, eval) in sorted_evals {
            let combiner = combiners.next().ok_or(anyhow!("No combiner left"))?;
            lc.add(combiner, label.as_str());
            sum += eval * combiner;
        }
        ensure!(combiners.next().is_none(), "Found more combiners than sorted_evals");
        Ok((lc, sum))
    }
}

pub(crate) struct IndexerState<F: PrimeField> {
    // R_i in the Varuna spec
    constraint_domain: EvaluationDomain<F>,
    // C_i in the Varuna spec
    variable_domain: EvaluationDomain<F>,

    a: Matrix<F>,
    non_zero_a_domain: EvaluationDomain<F>,
    a_arith: MatrixEvals<F>,

    b: Matrix<F>,
    non_zero_b_domain: EvaluationDomain<F>,
    b_arith: MatrixEvals<F>,

    c: Matrix<F>,
    non_zero_c_domain: EvaluationDomain<F>,
    c_arith: MatrixEvals<F>,

    pub(crate) index_info: CircuitInfo,
    pub(crate) id: CircuitId,
}
