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

use snarkvm_console_types::prelude::*;
use snarkvm_fields::{PoseidonParameters, PrimeField};

/// The rounds of the Poseidon permutation, with the partial rounds rewritten into an equivalent,
/// cheaper form (Grassi et al., "Poseidon", Appendix B):
///
/// - A partial round's S-box only touches the first state element, so the constants it adds to
///   the other elements commute with it. They are moved through the MDS matrix into the next
///   round, and each partial round adds a single constant.
/// - A partial round's matrix `A` is factored as `A = M' * M''`, where `M''` is sparse (a dense
///   first row and first column, the identity elsewhere) and `M' = diag(1, A_hat)` commutes with
///   the next partial round. `M'` is folded into that round's matrix, so every partial round but
///   the last multiplies by a sparse matrix: `2t - 1` products instead of `t^2`.
///
/// The permutation's output is unchanged; the sponge tests check it against the reference rounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonRounds<F: PrimeField> {
    /// The S-box exponent.
    pub(super) alpha: u64,
    /// The MDS matrix of the full rounds.
    pub(super) mds: Vec<Vec<F>>,
    /// The constants of the full rounds before the partial rounds.
    pub(super) first_full_ark: Vec<Vec<F>>,
    /// The single constant of each partial round, for the first state element.
    pub(super) partial_ark: Vec<F>,
    /// The matrices of every partial round but the last.
    pub(super) partial_sparse: Vec<SparseMatrix<F>>,
    /// The matrix of the last partial round, including the factors carried from the rounds before.
    pub(super) last_partial_mds: Vec<Vec<F>>,
    /// The constants of the full rounds after the partial rounds, including those moved out of them.
    pub(super) last_full_ark: Vec<Vec<F>>,
}

/// A matrix with a dense first row and first column, and the identity elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMatrix<F: PrimeField> {
    /// The first row.
    pub(super) row: Vec<F>,
    /// The first column below the first row.
    pub(super) column: Vec<F>,
}

impl<F: PrimeField> PoseidonRounds<F> {
    /// Rewrites the rounds of the given parameters.
    pub fn new<const RATE: usize, const CAPACITY: usize>(
        parameters: &PoseidonParameters<F, RATE, CAPACITY>,
    ) -> Result<Self> {
        let width = RATE + CAPACITY;
        let full_rounds_over_2 = parameters.full_rounds / 2;
        let partial_rounds = parameters.partial_rounds;
        let mds = &parameters.mds;
        ensure!(parameters.full_rounds.is_multiple_of(2), "Poseidon needs an even number of full rounds");
        ensure!(full_rounds_over_2 > 0 && partial_rounds > 0, "Poseidon needs full and partial rounds");
        ensure!(parameters.ark.len() == parameters.full_rounds + partial_rounds, "Poseidon needs a constant per round");
        ensure!(parameters.ark.iter().all(|ark| ark.len() == width), "Poseidon round constants must match the width");
        ensure!(mds.len() == width && mds.iter().all(|row| row.len() == width), "Poseidon MDS must be square");

        // Move each partial round's constants, but the first, through the MDS matrix into the next round.
        let mut carry = vec![F::zero(); width];
        let mut partial_ark = Vec::with_capacity(partial_rounds);
        for ark in &parameters.ark[full_rounds_over_2..full_rounds_over_2 + partial_rounds] {
            let constants: Vec<F> = ark.iter().zip(&carry).map(|(constant, carried)| *constant + carried).collect();
            partial_ark.push(constants[0]);
            carry = mds.iter().map(|row| dot(&row[1..], &constants[1..])).collect();
        }
        let mut last_full_ark = parameters.ark[full_rounds_over_2 + partial_rounds..].to_vec();
        last_full_ark[0].iter_mut().zip(&carry).for_each(|(constant, carried)| *constant += carried);

        // Factor each partial round's matrix, and fold the dense factor into the next round's matrix.
        let mut current = mds.clone();
        let mut partial_sparse = Vec::with_capacity(partial_rounds - 1);
        for _ in 1..partial_rounds {
            let hat: Vec<Vec<F>> = current[1..].iter().map(|row| row[1..].to_vec()).collect();
            let hat_inverse = invert(&hat)?;
            let first_column: Vec<F> = current[1..].iter().map(|row| row[0]).collect();
            let column = hat_inverse.iter().map(|row| dot(row, &first_column)).collect();
            partial_sparse.push(SparseMatrix { row: current[0].clone(), column });
            // The next round's matrix is `MDS * diag(1, hat)`.
            current = mds
                .iter()
                .map(|row| {
                    let mut product = Vec::with_capacity(width);
                    product.push(row[0]);
                    for j in 0..width - 1 {
                        product
                            .push(hat.iter().zip(&row[1..]).fold(F::zero(), |sum, (hat_row, m)| sum + *m * hat_row[j]));
                    }
                    product
                })
                .collect();
        }

        Ok(Self {
            alpha: parameters.alpha,
            mds: mds.clone(),
            first_full_ark: parameters.ark[..full_rounds_over_2].to_vec(),
            partial_ark,
            partial_sparse,
            last_partial_mds: current,
            last_full_ark,
        })
    }
}

/// Returns the dot product of two equally long slices.
fn dot<F: PrimeField>(a: &[F], b: &[F]) -> F {
    a.iter().zip(b).fold(F::zero(), |sum, (x, y)| sum + *x * y)
}

/// Returns the inverse of a square matrix, by Gauss-Jordan elimination.
fn invert<F: PrimeField>(matrix: &[Vec<F>]) -> Result<Vec<Vec<F>>> {
    let n = matrix.len();
    let mut left = matrix.to_vec();
    let mut right: Vec<Vec<F>> =
        (0..n).map(|i| (0..n).map(|j| if i == j { F::one() } else { F::zero() }).collect()).collect();
    for column in 0..n {
        // Every square submatrix of an MDS matrix is invertible, so a pivot exists.
        let Some(pivot) = (column..n).find(|&row| !left[row][column].is_zero()) else {
            bail!("Poseidon partial rounds: a submatrix of the MDS matrix is singular");
        };
        left.swap(column, pivot);
        right.swap(column, pivot);
        let scale = left[column][column].inverse().ok_or_else(|| anyhow!("Poseidon partial rounds: zero pivot"))?;
        left[column].iter_mut().for_each(|x| *x *= scale);
        right[column].iter_mut().for_each(|x| *x *= scale);
        let (pivot_left, pivot_right) = (left[column].clone(), right[column].clone());
        for row in (0..n).filter(|&row| row != column) {
            let factor = left[row][column];
            if !factor.is_zero() {
                left[row].iter_mut().zip(&pivot_left).for_each(|(x, p)| *x -= factor * p);
                right[row].iter_mut().zip(&pivot_right).for_each(|(x, p)| *x -= factor * p);
            }
        }
    }
    Ok(right)
}
