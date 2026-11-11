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

use snarkvm_curves::bls12_377::Fq;
use snarkvm_fields::{One, PoseidonDefaultField, PoseidonParameters, PoseidonSparseRounds, Zero};
use snarkvm_utilities::{TestRng, Uniform};

use itertools::Itertools;

/// Checks the shapes of the partial rounds of `parameters`, and that the row of the last partial
/// round below its first element, times the lower-right block of width `RATE` of the MDS matrix,
/// is the first row of the MDS matrix below its first element.
fn check_parameters<const RATE: usize>(parameters: &PoseidonParameters<Fq, RATE, 1>) {
    let width = RATE + 1;
    let mds = &parameters.mds;
    let sparse_rounds = PoseidonSparseRounds::new(parameters).unwrap();
    assert_eq!(sparse_rounds.first_matrix().len(), width);
    assert!(sparse_rounds.first_matrix().iter().all(|row| row.len() == width));
    assert_eq!(sparse_rounds.first_matrix()[0], mds[0]);
    assert_eq!(sparse_rounds.last_ark().len(), width);
    assert_eq!(sparse_rounds.rounds().len(), parameters.partial_rounds);
    for round in sparse_rounds.rounds() {
        assert_eq!(round.row().len(), width);
        assert_eq!(round.row()[0], mds[0][0]);
        assert_eq!(round.column().len(), RATE);
    }
    // Below its first element, the row of the last partial round is mds[0][1..] times mds_hat^-1.
    let row = &sparse_rounds.rounds().last().unwrap().row()[1..];
    for j in 1..width {
        let product: Fq = row.iter().zip_eq(&mds[1..]).map(|(a, mds_row)| *a * mds_row[j]).sum();
        assert_eq!(product, mds[0][j]);
    }
}

/// Checks the partial rounds of parameters with random round constants and a random MDS matrix.
fn check_random_matrix<const RATE: usize>(rng: &mut TestRng) {
    let mut random_matrix = |rows: usize| (0..rows).map(|_| (0..RATE + 1).map(|_| Fq::rand(rng)).collect()).collect();
    let ark = random_matrix(39);
    let mds = random_matrix(RATE + 1);
    check_parameters(&PoseidonParameters::<Fq, RATE, 1> { full_rounds: 8, partial_rounds: 31, alpha: 17, ark, mds });
}

#[test]
fn test_sparse_rounds_default_parameters() {
    check_parameters(&Fq::default_poseidon_parameters::<2>().unwrap());
    check_parameters(&Fq::default_poseidon_parameters::<4>().unwrap());
    check_parameters(&Fq::default_poseidon_parameters::<8>().unwrap());
}

#[test]
fn test_sparse_rounds_random_matrix() {
    let rng = &mut TestRng::default();
    check_random_matrix::<1>(rng);
    check_random_matrix::<2>(rng);
    check_random_matrix::<3>(rng);
    check_random_matrix::<4>(rng);
    check_random_matrix::<5>(rng);
    check_random_matrix::<6>(rng);
    check_random_matrix::<7>(rng);
    check_random_matrix::<8>(rng);
}

#[test]
fn test_sparse_rounds_zero_pivot() {
    // The lower-right block [[0, 1], [1, 1]] has a zero first pivot, so inverting it swaps rows.
    let rng = &mut TestRng::default();
    let mut parameters = Fq::default_poseidon_parameters::<2>().unwrap();
    parameters.mds = vec![
        vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)],
        vec![Fq::rand(rng), Fq::zero(), Fq::one()],
        vec![Fq::rand(rng), Fq::one(), Fq::one()],
    ];
    check_parameters(&parameters);
}

#[test]
fn test_sparse_rounds_fallback() {
    let rng = &mut TestRng::default();
    let default = Fq::default_poseidon_parameters::<2>().unwrap();
    let mut no_full_rounds = default.clone();
    no_full_rounds.full_rounds = 0;
    let mut one_full_round = default.clone();
    one_full_round.full_rounds = 1;
    let mut no_partial_rounds = default.clone();
    no_partial_rounds.partial_rounds = 0;
    let mut singular = default.clone();
    singular.mds[2] = vec![Fq::rand(rng), singular.mds[1][1], singular.mds[1][2]];
    let mut short_ark = default.clone();
    short_ark.ark.pop();
    let mut long_ark_row = default.clone();
    long_ark_row.ark[38].push(Fq::one());
    let mut short_mds_row = default.clone();
    short_mds_row.mds[1].pop();
    let mut extra_mds_row = default.clone();
    extra_mds_row.mds.push(vec![Fq::one(); 3]);
    let cases = [
        no_full_rounds,
        one_full_round,
        no_partial_rounds,
        singular,
        short_ark,
        long_ark_row,
        short_mds_row,
        extra_mds_row,
    ];
    for parameters in cases {
        assert!(PoseidonSparseRounds::new(&parameters).is_none(), "{parameters:?}");
    }
    assert!(PoseidonSparseRounds::new(&default).is_some());
}
