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

#![allow(non_snake_case)]

use crate::{
    fft::{EvaluationDomain, Evaluations as EvaluationsOnDomain},
    polycommit::sonic_pc::LabeledPolynomial,
    r1cs::{ConstraintSystem, Index as VarIndex},
    snark::varuna::{
        SNARKMode,
        ahp::{AHPForR1CS, CircuitId, indexer::Matrix},
    },
};
use snarkvm_fields::{Field, PrimeField};
use snarkvm_utilities::{cfg_into_iter, defer, serialize::*};

use anyhow::{Result, anyhow, ensure};

use itertools::Itertools;
#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

// This function converts a matrix output by Zexe's constraint infrastructure to
// the one used in this crate, i. e. sparse matrices. More specifically, it
// places private variables after public ones and, for each row, adds adds all
// coefficients multiplying the same variable.
pub(crate) fn into_matrix_helper<F: Field>(
    matrix: Vec<Vec<(F, VarIndex)>>,
    num_input_variables: usize,
) -> Result<Matrix<F>> {
    cfg_into_iter!(matrix)
        .map(|row| {
            let mut row_map = Vec::with_capacity(row.len());
            for (val, column) in row {
                ensure!(val != F::zero(), "matrix entries should be non-zero");
                let column = match column {
                    VarIndex::Public(i) => i,
                    VarIndex::Private(i) => num_input_variables + i,
                };
                match row_map.binary_search_by_key(&column, |(_, c)| *c) {
                    Ok(idx) => row_map[idx].0 += val,
                    Err(idx) => {
                        row_map.insert(idx, (val, column));
                    }
                }
            }
            Ok(row_map)
        })
        .collect()
}

/// Adds variables to randomize each z_M and preserve zero-knowledge
/// When no random assignments are passed, we use F::one()
pub(crate) fn add_randomizing_variables<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    rand_assignments: Option<[F; 3]>,
) -> Result<()> {
    let mut assignments = [F::one(); 3];
    if let Some(r) = rand_assignments {
        assignments = r;
    }

    let zk_vars = assignments
        .into_iter()
        .enumerate()
        .map(|(i, assignment)| cs.alloc(|| format!("random_{i}"), || Ok(assignment)))
        .collect::<Result<Vec<_>, _>>()?;
    cs.enforce(|| "constraint zk", |lc| lc + zk_vars[0], |lc| lc + zk_vars[1], |lc| lc + zk_vars[2]);
    Ok(())
}

/// Pads the public variables (including the constant 1, if present) up to the
/// closest power of two.
pub(crate) fn pad_input_for_indexer_and_prover<F: PrimeField, CS: ConstraintSystem<F>>(cs: &mut CS) -> Result<()> {
    let num_public_variables = cs.num_public_variables();

    let power_of_two =
        EvaluationDomain::<F>::new(num_public_variables).ok_or(anyhow!("Could not create EvaluationDomain"))?;

    // Allocated `zero` variables to pad the public input up to the next power of
    // two.
    let padded_size = power_of_two.size();
    if padded_size > num_public_variables {
        for i in 0..(padded_size - num_public_variables) {
            cs.alloc_input(|| format!("pad_input_{i}"), || Ok(F::zero()))?;
        }
    }
    Ok(())
}

/// Evaluations of the arithmetization of a matrix, i. e. of its `row`, `col`,
/// `row_col` and `row_col_val` polynomials.
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct MatrixEvals<F: PrimeField> {
    /// Evaluations of the `row` polynomial.
    // The k-th entry is the r_k-th element of the constraint domain R_i, where r_k is
    // the index of the row of the k-th non-zero entry in the matrix.
    pub row: EvaluationsOnDomain<F>,
    /// Evaluations of the `col` polynomial.
    // The k-th entry is the c_k-th entry of the variable domain C_i, analogously
    // to row.
    pub col: EvaluationsOnDomain<F>,
    /// Evaluations of the `row_col` polynomial.
    /// After indexing, we drop these evaluations to save space in the
    /// ProvingKey
    // The k-th element is the product of the k-th entries of row and col.
    pub row_col: Option<EvaluationsOnDomain<F>>,
    /// Evaluations of the `row_col_val` polynomial.
    // The k-th entry is the product of the k-th entry of row_col and the value
    // of the k-th non-zero entry in the matrix.
    pub row_col_val: EvaluationsOnDomain<F>,
}

impl<F: PrimeField> MatrixEvals<F> {
    pub(crate) fn evaluate(&self, lagrange_coefficients_at_point: &[F]) -> Result<[F; 4]> {
        Ok([
            self.row.evaluate_with_coeffs(lagrange_coefficients_at_point),
            self.col.evaluate_with_coeffs(lagrange_coefficients_at_point),
            self.row_col
                .as_ref()
                .ok_or("row_col evaluations are not available")
                .map_err(anyhow::Error::msg)?
                .evaluate_with_coeffs(lagrange_coefficients_at_point),
            self.row_col_val.evaluate_with_coeffs(lagrange_coefficients_at_point),
        ])
    }

    pub(crate) fn domain(&self) -> Result<EvaluationDomain<F>> {
        ensure!(self.row.domain() == self.col.domain());
        if let Some(row_col) = self.row_col.as_ref() {
            ensure!(self.row.domain() == row_col.domain());
        }
        ensure!(self.row.domain() == self.row_col_val.domain());
        Ok(self.row.domain())
    }
}

// Arithmetize the matrix into row, col, rowcol and rowcolval polynomials
pub(crate) fn matrix_evals<F: PrimeField>(
    matrix: &Matrix<F>,
    non_zero_domain: &EvaluationDomain<F>,
    variable_domain: &EvaluationDomain<F>,
    input_domain: &EvaluationDomain<F>,
    constraint_domain_elems: &[F],
    variable_domain_elems: &[F],
) -> Result<MatrixEvals<F>> {
    let lde_evals_time = start_timer!(|| "Computing row, col and val evals");

    // We are computing the arithmetization of `matrix`, that is, row, col, val,
    // rowcol and rowcolval as documented in `MatrixArithmetization`. They
    // satisfy:     M(a,b) = \sum_{k in K} val(k) * L^{R_i}_{row(k)}(a) *
    // L^{C_i}_{col(k)}(b)
    let mut row_indices = Vec::with_capacity(non_zero_domain.size());
    let mut col_indices = Vec::with_capacity(non_zero_domain.size());
    let mut row_col_indices = Vec::with_capacity(non_zero_domain.size());
    let mut row_col_vals = Vec::with_capacity(non_zero_domain.size());

    for (row_index, row) in matrix.iter().enumerate() {
        for (val, input_var_index) in row {
            let row_i = constraint_domain_elems[row_index];
            // Since the (padded) instance x lives in the subgroup C_i[x], i.
            // e. is interleaved in the full assignment vector z which lives in
            // C_i, the witness needs to be reindexed to occupy the remaining
            // positions in C_i.
            let col_i = variable_domain_elems[variable_domain.reindex_by_subdomain(input_domain, *input_var_index)?];

            row_indices.push(row_i);
            row_col_indices.push(row_i);
            col_indices.push(col_i);
            row_col_vals.push(*val);
        }
    }

    let non_zero_entries = row_indices.len();

    // Zip safety: we intentionally only multiply the first non_zero_entries
    row_col_indices.iter_mut().zip(&col_indices).for_each(|(rc, &col)| *rc *= col);
    row_col_vals.iter_mut().zip(&row_col_indices).for_each(|(v, rc)| *v *= rc);

    // Fill up the evaluations to the next power of two with entries at row 0 (1
    // in R_i), column 0 (1 in C_i) and value 0,
    let padding = non_zero_domain.size() - non_zero_entries;
    for _ in 0..padding {
        row_indices.push(F::one());
        col_indices.push(F::one());
        row_col_indices.push(F::one());
        row_col_vals.push(F::zero());
    }

    end_timer!(lde_evals_time);

    let row_evals_on_K = EvaluationsOnDomain::from_vec_and_domain(row_indices, *non_zero_domain);
    let col_evals_on_K = EvaluationsOnDomain::from_vec_and_domain(col_indices, *non_zero_domain);
    let row_col_evals_on_K = EvaluationsOnDomain::from_vec_and_domain(row_col_indices, *non_zero_domain);
    let row_col_val_evals_on_K = EvaluationsOnDomain::from_vec_and_domain(row_col_vals, *non_zero_domain);
    Ok(MatrixEvals {
        row: row_evals_on_K,
        col: col_evals_on_K,
        row_col: Some(row_col_evals_on_K),
        row_col_val: row_col_val_evals_on_K,
    })
}

// TODO for debugging: add test that checks result of arithmetize_matrix(M).
/// Contains information about the arithmetization of the matrices
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct MatrixArithmetization<F: PrimeField> {
    /// LDE of the row indices of M^*.
    // If the k-th non-zero entry in the matrix is in row r_k, `row` sends the
    // k-th element of the density domain K_M to the r_k-th element of the row
    // domain R_i.
    pub row: LabeledPolynomial<F>,
    /// LDE of the column indices of M^*.
    // Defined analogously to `row` but taking values in the variable domain C_i.
    pub col: LabeledPolynomial<F>,
    /// LDE of the vector containing entry-wise products of `row` and `col`.
    pub row_col: LabeledPolynomial<F>,
    /// LDE of the vector containing entry-wise products of `row`, `col` and the
    /// value of the non-zero entries of M.
    pub row_col_val: LabeledPolynomial<F>,
}

impl<F: PrimeField> MatrixArithmetization<F> {
    /// Create a new MatrixArithmetization
    pub fn new<SM: SNARKMode>(
        id: &CircuitId,
        label: &str,
        matrix_evals: &MatrixEvals<F>,
    ) -> Result<MatrixArithmetization<F>> {
        let (row, col, row_col, row_col_val) = {
            let interpolate_time = start_timer!(|| "Interpolating on K");
            defer! { end_timer!(interpolate_time); }
            let non_zero_domain = matrix_evals.domain()?;
            let row = matrix_evals.row.clone().interpolate();
            let col = matrix_evals.col.clone().interpolate();
            let row_col = if let Some(row_col) = matrix_evals.row_col.as_ref() {
                row_col.clone().interpolate()
            } else {
                ensure!(matrix_evals.row.evaluations.len() == matrix_evals.col.evaluations.len());
                let row_col_evals: Vec<F> = matrix_evals
                    .row
                    .evaluations
                    .iter()
                    .zip_eq(&matrix_evals.col.evaluations)
                    .map(|(&r, &c)| r * c)
                    .collect();
                EvaluationsOnDomain::<F>::from_vec_and_domain(row_col_evals, non_zero_domain).interpolate()
            };
            let row_col_val = matrix_evals.row_col_val.clone().interpolate();
            (row, col, row_col, row_col_val)
        };

        let mut labels = AHPForR1CS::<F, SM>::index_polynomial_labels_single(label, id);
        ensure!(labels.len() == 4);

        Ok(MatrixArithmetization {
            row: LabeledPolynomial::new(labels.next().unwrap(), row, None, None),
            col: LabeledPolynomial::new(labels.next().unwrap(), col, None, None),
            row_col: LabeledPolynomial::new(labels.next().unwrap(), row_col, None, None),
            row_col_val: LabeledPolynomial::new(labels.next().unwrap(), row_col_val, None, None),
        })
    }

    /// Iterate over the indexed polynomials.
    pub fn into_iter(self) -> impl ExactSizeIterator<Item = LabeledPolynomial<F>> {
        // Alphabetical order
        [self.col, self.row, self.row_col, self.row_col_val].into_iter()
    }
}

/// Compute the transpose of a sparse matrix
pub(crate) fn transpose<F: PrimeField>(
    matrix: &Matrix<F>,
    variable_domain: &EvaluationDomain<F>,
    input_domain: &EvaluationDomain<F>,
) -> Result<Matrix<F>> {
    // NOTE: we cannot preallocate the inner Vec because we don't know ahead of time
    // how many rows are used by which variables
    let mut transpose = vec![vec![]; variable_domain.size()];
    for (row_index, row) in matrix.iter().enumerate() {
        for (val, input_var_index) in row {
            let c_i = variable_domain.reindex_by_subdomain(input_domain, *input_var_index)?;
            transpose[c_i].push((*val, row_index));
        }
    }
    Ok(transpose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snark::varuna::{VarunaHidingMode, num_non_zero};
    use snarkvm_curves::bls12_377::Fr as F;
    use snarkvm_fields::{One, Zero};
    use std::{borrow::Cow, collections::HashMap};

    fn entry(matrix: &Matrix<F>, row: usize, col: usize) -> F {
        matrix[row].iter().find_map(|(f, i)| (i == &col).then_some(*f)).unwrap_or_else(F::zero)
    }

    #[test]
    fn check_arithmetization() {
        let a = vec![
            vec![(F::one(), 1), (F::one(), 2)],
            vec![(F::one(), 3)],
            vec![(F::one(), 3)],
            vec![(F::one(), 0), (F::one(), 1), (F::one(), 5)],
            vec![(F::one(), 1), (F::one(), 2), (F::one(), 6)],
            vec![(F::one(), 2), (F::one(), 5), (F::one(), 7)],
            vec![(F::one(), 3), (F::one(), 4), (F::one(), 6)],
            vec![(F::one(), 0), (F::one(), 6), (F::one(), 7)],
        ];

        let b = vec![
            vec![],
            vec![(F::one(), 1)],
            vec![(F::one(), 0)],
            vec![(F::one(), 2)],
            vec![(F::one(), 3)],
            vec![(F::one(), 4)],
            vec![(F::one(), 5)],
            vec![(F::one(), 6)],
        ];

        let c = vec![vec![], vec![(F::one(), 7)], vec![], vec![], vec![], vec![(F::one(), 3)], vec![], vec![]];

        let constraint_domain = EvaluationDomain::new(2 + 6).unwrap();
        let variable_domain = EvaluationDomain::new(2 + 6).unwrap();
        let input_domain = EvaluationDomain::new(2).unwrap();
        let inverse_map = constraint_domain.elements().enumerate().map(|(i, e)| (e, i)).collect::<HashMap<_, _>>();
        let elements = constraint_domain.elements().collect::<Vec<_>>();
        let reindexed_inverse_map = (0..constraint_domain.size())
            .map(|i| {
                let reindexed_i = constraint_domain.reindex_by_subdomain(&input_domain, i).unwrap();
                (elements[reindexed_i], i)
            })
            .collect::<HashMap<_, _>>();
        let constraint_domain_elements = constraint_domain.elements().collect::<Vec<_>>();
        let variable_domain_elements = if variable_domain == constraint_domain {
            Cow::from(&constraint_domain_elements)
        } else {
            Cow::from(variable_domain.elements().collect::<Vec<_>>())
        };
        for (matrix, label) in [(a, "a"), (b, "b"), (c, "c")] {
            let num_non_zero = num_non_zero(&matrix);
            let interpolation_domain = EvaluationDomain::new(num_non_zero).unwrap();

            let evals = matrix_evals(
                &matrix,
                &interpolation_domain,
                &variable_domain,
                &input_domain,
                &constraint_domain_elements,
                &variable_domain_elements,
            )
            .unwrap();
            let dummy_id = CircuitId([0; 32]);
            let arith = MatrixArithmetization::new::<VarunaHidingMode>(&dummy_id, label, &evals).unwrap();

            for (k_index, k) in interpolation_domain.elements().enumerate() {
                let row_val = arith.row.evaluate(k);
                let col_val = arith.col.evaluate(k);
                let row_col = arith.row_col.evaluate(k);

                let row_col_val = arith.row_col_val.evaluate(k);
                if k_index < num_non_zero {
                    let col = *dbg!(reindexed_inverse_map.get(&col_val).unwrap());
                    let row = *dbg!(inverse_map.get(&row_val).unwrap());
                    assert!(matrix[row].iter().any(|(_, c)| *c == col));
                    assert_eq!(row_col_val, entry(&matrix, row, col) * row_col);
                }
            }
        }
    }
}
