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

use crate::{PoseidonParameters, PrimeField};

use itertools::Itertools;

/// The partial rounds of a Poseidon permutation, rewritten as in the appendix on efficient partial
/// rounds of [GKRRS19][poseidon], so that each partial round adds one round constant and multiplies
/// the state by a sparse matrix.
///
/// The permutation equals the dense one when the last full round before the partial rounds
/// multiplies by `first_matrix` in place of the MDS matrix, and the first full round after them
/// adds `last_ark` in place of its round constants.
///
/// [poseidon]: https://eprint.iacr.org/2019/458
#[derive(Debug)]
pub struct PoseidonSparseRounds<F: PrimeField> {
    /// The matrix of the last full round before the partial rounds.
    first_matrix: Vec<Vec<F>>,
    /// The partial rounds, in order.
    rounds: Vec<PoseidonSparseRound<F>>,
    /// The round constants of the first full round after the partial rounds.
    last_ark: Vec<F>,
}

/// A partial round: add `constant` to the first state element, apply the S-box to it, and multiply
/// the state by the matrix whose first row is `row`, whose first column below the first row is
/// `column`, and which is the identity elsewhere.
#[derive(Debug)]
pub struct PoseidonSparseRound<F: PrimeField> {
    constant: F,
    row: Vec<F>,
    column: Vec<F>,
}

impl<F: PrimeField> PoseidonSparseRounds<F> {
    /// Returns the partial rounds of `parameters`, or `None` if the parameters have no partial
    /// rounds, no full round before them, a round constant or MDS row whose length is not the state
    /// width, or an MDS matrix whose lower-right block of width `RATE` is singular.
    ///
    /// The matrices and round constants of the result have the state width `RATE + 1`, and it has
    /// `parameters.partial_rounds` rounds.
    pub fn new<const RATE: usize>(parameters: &PoseidonParameters<F, RATE, 1>) -> Option<Self> {
        let width = RATE + 1;
        let PoseidonParameters { full_rounds, partial_rounds, ark, mds, .. } = parameters;
        let first_partial_round = full_rounds / 2;
        let last_partial_round = first_partial_round + partial_rounds;
        if first_partial_round == 0
            || *partial_rounds == 0
            || ark.len() < full_rounds + partial_rounds
            || ark.iter().take(full_rounds + partial_rounds).any(|row| row.len() != width)
            || mds.len() != width
            || mds.iter().any(|row| row.len() != width)
        {
            return None;
        }
        let dot = |a: &[F], b: &[F]| a.iter().zip_eq(b).map(|(a, b)| *a * b).sum::<F>();
        let mds_hat = mds[1..].iter().map(|row| row[1..].to_vec()).collect::<Vec<_>>();
        let mds_hat_inverse = invert(&mds_hat)?;

        // In a partial round, the round constants of every state element but the first commute
        // with the S-box, so they move through the MDS matrix into the next round's constants.
        let mut constants = Vec::with_capacity(*partial_rounds);
        let mut carry = vec![F::zero(); width];
        for round_constants in &ark[first_partial_round..last_partial_round] {
            let mut sum = round_constants.iter().zip_eq(&carry).map(|(a, b)| *a + b).collect::<Vec<_>>();
            constants.push(sum[0]);
            sum[0] = F::zero();
            carry = mds.iter().map(|row| dot(row, &sum)).collect();
        }
        let last_ark = ark[last_partial_round].iter().zip_eq(&carry).map(|(a, b)| *a + b).collect();

        // From the last partial round to the first, diag(1, X) times the MDS matrix is the round's
        // sparse matrix times diag(1, X * mds_hat), with X = I in the last round. Each
        // diag(1, X * mds_hat) commutes with the constant and the S-box of its round, so it moves
        // into the round before, and diag(1, mds_hat^partial_rounds) multiplies the MDS matrix of
        // the last full round. In the iteration for the k-th partial round from the end, `row` is
        // mds[0][1..] times mds_hat^-k, `column` is mds_hat^(k-1) times the first column of mds
        // below its first row, and `lower_rows` is mds_hat^k times mds[1..].
        let mut rows = Vec::with_capacity(*partial_rounds);
        let mut columns = Vec::with_capacity(*partial_rounds);
        let mut row = mds[0][1..].to_vec();
        let mut column = mds[1..].iter().map(|row| row[0]).collect::<Vec<_>>();
        let mut lower_rows = mds[1..].to_vec();
        for _ in 0..*partial_rounds {
            row = (0..RATE).map(|j| row.iter().zip_eq(&mds_hat_inverse).map(|(a, b)| *a * b[j]).sum()).collect();
            rows.push(std::iter::once(mds[0][0]).chain(row.iter().copied()).collect::<Vec<_>>());
            let next_column = mds_hat.iter().map(|mds_hat_row| dot(mds_hat_row, &column)).collect();
            columns.push(std::mem::replace(&mut column, next_column));
            lower_rows = mds_hat
                .iter()
                .map(|mds_hat_row| {
                    (0..width).map(|j| mds_hat_row.iter().zip_eq(&lower_rows).map(|(a, b)| *a * b[j]).sum()).collect()
                })
                .collect();
        }
        let first_matrix = std::iter::once(mds[0].clone()).chain(lower_rows).collect();
        let rounds = constants
            .into_iter()
            .zip_eq(rows.into_iter().rev())
            .zip_eq(columns.into_iter().rev())
            .map(|((constant, row), column)| PoseidonSparseRound { constant, row, column })
            .collect();

        Some(Self { first_matrix, rounds, last_ark })
    }

    /// Returns the matrix of the last full round before the partial rounds.
    pub fn first_matrix(&self) -> &[Vec<F>] {
        &self.first_matrix
    }

    /// Returns the partial rounds, in order.
    pub fn rounds(&self) -> &[PoseidonSparseRound<F>] {
        &self.rounds
    }

    /// Returns the round constants of the first full round after the partial rounds.
    pub fn last_ark(&self) -> &[F] {
        &self.last_ark
    }
}

impl<F: PrimeField> PoseidonSparseRound<F> {
    /// Returns the round constant of the first state element.
    pub fn constant(&self) -> F {
        self.constant
    }

    /// Returns the first row of the round's matrix.
    pub fn row(&self) -> &[F] {
        &self.row
    }

    /// Returns the first column of the round's matrix below its first row.
    pub fn column(&self) -> &[F] {
        &self.column
    }
}

/// Returns the inverse of the square matrix `matrix`, or `None` if it is singular.
fn invert<F: PrimeField>(matrix: &[Vec<F>]) -> Option<Vec<Vec<F>>> {
    let n = matrix.len();
    let mut matrix = matrix.to_vec();
    let mut inverse = (0..n)
        .map(|i| (0..n).map(|j| if i == j { F::one() } else { F::zero() }).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    for column in 0..n {
        let pivot = (column..n).find(|&row| !matrix[row][column].is_zero())?;
        matrix.swap(column, pivot);
        inverse.swap(column, pivot);
        let scale = matrix[column][column].inverse()?;
        matrix[column].iter_mut().chain(inverse[column].iter_mut()).for_each(|x| *x *= scale);
        let (pivot_row, pivot_inverse_row) = (matrix[column].clone(), inverse[column].clone());
        for row in (0..n).filter(|&row| row != column) {
            let factor = matrix[row][column];
            for (x, y) in matrix[row].iter_mut().zip_eq(&pivot_row) {
                *x -= factor * y;
            }
            for (x, y) in inverse[row].iter_mut().zip_eq(&pivot_inverse_row) {
                *x -= factor * y;
            }
        }
    }
    Some(inverse)
}
