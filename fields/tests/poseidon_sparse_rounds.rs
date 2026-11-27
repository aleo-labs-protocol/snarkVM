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

use snarkvm_curves::bls12_377::{Fq, Fr, FrParameters};
use snarkvm_fields::{
    Field,
    One,
    PoseidonDefaultField,
    PoseidonParameters,
    PoseidonSparseRounds,
    Zero,
    ifma,
    invert_matrix,
};
use snarkvm_utilities::{TestRng, Uniform};

use rand::RngExt;

use itertools::Itertools;
use std::sync::Arc;

/// Checks the shapes of the partial rounds of `parameters`, and that the row of the last partial
/// round below its first element, times the lower-right block of width `RATE` of the MDS matrix,
/// is the first row of the MDS matrix below its first element.
fn check_parameters<const RATE: usize>(parameters: PoseidonParameters<Fq, RATE, 1>) {
    let width = RATE + 1;
    let parameters = Arc::new(parameters);
    let mds = &parameters.mds;
    let sparse_rounds = PoseidonSparseRounds::new(&parameters).unwrap();
    assert!(Arc::ptr_eq(sparse_rounds.parameters(), &parameters));
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
    check_parameters(PoseidonParameters::<Fq, RATE, 1> { full_rounds: 8, partial_rounds: 31, alpha: 17, ark, mds });
}

#[test]
fn test_sparse_rounds_default_parameters() {
    check_parameters(Fq::default_poseidon_parameters::<2>().unwrap());
    check_parameters(Fq::default_poseidon_parameters::<4>().unwrap());
    check_parameters(Fq::default_poseidon_parameters::<8>().unwrap());
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
    check_parameters(parameters);
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
        assert!(PoseidonSparseRounds::new(&Arc::new(parameters.clone())).is_none(), "{parameters:?}");
    }
    assert!(PoseidonSparseRounds::new(&Arc::new(default)).is_some());
}

#[test]
fn test_invert_matrix() {
    let rng = &mut TestRng::default();
    for n in 1..=8 {
        let matrix = (0..n).map(|_| (0..n).map(|_| Fq::rand(rng)).collect_vec()).collect_vec();
        let inverse = invert_matrix(&matrix).unwrap();
        for (i, row) in matrix.iter().enumerate() {
            for j in 0..n {
                let product: Fq = row.iter().zip_eq(&inverse).map(|(a, b)| *a * b[j]).sum();
                assert_eq!(product, if i == j { Fq::one() } else { Fq::zero() });
            }
        }
        let mut singular = matrix.clone();
        let factor = if n == 1 { Fq::zero() } else { Fq::from(2u8) };
        singular[n - 1] = singular[0].iter().map(|x| *x * factor).collect();
        assert!(invert_matrix(&singular).is_none());
    }
    // A zero first pivot needs a row swap.
    let matrix = vec![vec![Fq::zero(), Fq::one()], vec![Fq::one(), Fq::one()]];
    let inverse = invert_matrix(&matrix).unwrap();
    assert_eq!(inverse, vec![vec![-Fq::one(), Fq::one()], vec![Fq::one(), Fq::zero()]]);
}

/// Whether `ifma::poseidon_permute_8` runs on this CPU, from the CPU's features and the
/// environment.
fn lanes_expected() -> bool {
    #[cfg(target_arch = "x86_64")]
    let expected = std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512ifma")
        && std::env::var_os("SNARKVM_NO_IFMA").is_none_or(|value| value.is_empty());
    #[cfg(not(target_arch = "x86_64"))]
    let expected = false;
    expected
}

/// Applies the permutation of `parameters` to `state`, with the MDS matrix in every round.
fn permute_dense<const RATE: usize>(parameters: &PoseidonParameters<Fr, RATE, 1>, state: &mut [Fr]) {
    let first_partial_round = parameters.full_rounds / 2;
    let partial_rounds = first_partial_round..first_partial_round + parameters.partial_rounds;
    for round in 0..parameters.full_rounds + parameters.partial_rounds {
        for (x, c) in state.iter_mut().zip_eq(&parameters.ark[round]) {
            *x += c;
        }
        let s_boxes = if partial_rounds.contains(&round) { 1 } else { state.len() };
        for x in &mut state[..s_boxes] {
            *x = x.pow([parameters.alpha]);
        }
        let next = parameters.mds.iter().map(|row| row.iter().zip_eq(&*state).map(|(m, x)| *m * x).sum()).collect_vec();
        state.copy_from_slice(&next);
    }
}

/// Checks `Fr::poseidon_permute_8` on the 8 states `states`, `chain` times in a row, against
/// `permute_dense` on each state: every element of every lane, by its words, so an element that
/// is not canonical fails. Where the lanes do not run, checks that the hook declines and leaves
/// the states as they are.
fn check_permute_8(sparse_rounds: &PoseidonSparseRounds<Fr, 8>, states: &[[Fr; 9]; 8], chain: usize) {
    let mut lanes: [[Fr; 8]; 9] = std::array::from_fn(|j| std::array::from_fn(|l| states[l][j]));
    let mut expected = *states;
    for step in 0..chain {
        let before = lanes;
        let ran = Fr::poseidon_permute_8(sparse_rounds, &mut lanes);
        assert_eq!(ran.is_some(), lanes_expected());
        if ran.is_none() {
            assert_eq!(lanes, before);
            return;
        }
        for (l, state) in expected.iter_mut().enumerate() {
            permute_dense(sparse_rounds.parameters(), state);
            for (j, x) in state.iter().enumerate() {
                assert_eq!(lanes[j][l], *x, "step {step}, lane {l}, element {j}, from {states:?}");
            }
        }
    }
}

/// Checks `Fr::poseidon_permute_8` for `parameters`: on states of 0, 1 and p - 1 with one element
/// set apart, a different one in each lane; on states that mix those with random elements; on
/// random states; and on chains of permutations.
fn check_permute_8_parameters(parameters: PoseidonParameters<Fr, 8, 1>, rng: &mut TestRng) {
    let sparse_rounds = PoseidonSparseRounds::new(&Arc::new(parameters)).unwrap();
    let edges = [Fr::zero(), Fr::one(), -Fr::one()];
    for (a, b) in edges.into_iter().cartesian_product(edges) {
        for offset in 0..9 {
            let states = std::array::from_fn(|l| std::array::from_fn(|j| if (l + offset) % 9 == j { b } else { a }));
            check_permute_8(&sparse_rounds, &states, 1);
        }
    }
    for _ in 0..50 {
        let states = std::array::from_fn(|_| {
            std::array::from_fn(|_| if rng.random_bool(0.5) { edges[rng.random_range(0..3)] } else { Fr::rand(rng) })
        });
        check_permute_8(&sparse_rounds, &states, 1);
    }
    for chain in [1, 1, 1, 1, 2, 5, 50] {
        let states = std::array::from_fn(|_| std::array::from_fn(|_| Fr::rand(rng)));
        check_permute_8(&sparse_rounds, &states, chain);
    }
}

/// Returns parameters of rate 8 with the given rounds, the S-box `x^17`, round constants that are
/// each `p - 1` with probability `extreme` and random otherwise, and an MDS matrix whose entries
/// are each `p - 1` with probability `extreme / 3` and random otherwise. The lower-right block of
/// width 8 of the matrix is invertible, so the parameters have sparse partial rounds.
fn parameters_with_rounds(
    full_rounds: usize,
    partial_rounds: usize,
    extreme: f64,
    rng: &mut TestRng,
) -> PoseidonParameters<Fr, 8, 1> {
    let mut matrix = |rows: usize, extreme: f64| -> Vec<Vec<Fr>> {
        let mut entry = || if rng.random_bool(extreme) { -Fr::one() } else { Fr::rand(rng) };
        (0..rows).map(|_| (0..9).map(|_| entry()).collect()).collect()
    };
    let ark = matrix(full_rounds + partial_rounds, extreme);
    loop {
        let mds = matrix(9, extreme / 3.0);
        let block = mds[1..].iter().map(|row| row[1..].to_vec()).collect_vec();
        if invert_matrix(&block).is_some() {
            return PoseidonParameters { full_rounds, partial_rounds, alpha: 17, ark, mds };
        }
    }
}

#[test]
fn test_poseidon_permute_8_supported() {
    assert_eq!(ifma::is_supported_fp256::<FrParameters>(), lanes_expected());
}

#[test]
fn test_poseidon_permute_8_default_parameters() {
    let rng = &mut TestRng::default();
    check_permute_8_parameters(Fr::default_poseidon_parameters::<8>().unwrap(), rng);
}

#[test]
fn test_poseidon_permute_8_round_counts() {
    let rng = &mut TestRng::default();
    for (full_rounds, partial_rounds) in [(2, 1), (3, 4), (5, 3), (8, 31), (8, 64), (10, 40)] {
        for extreme in [0.0, 0.5, 1.0] {
            check_permute_8_parameters(parameters_with_rounds(full_rounds, partial_rounds, extreme, rng), rng);
        }
    }
}

/// Every round constant is `p - 1`, and every state element enters as `p - 1`: the largest
/// integers that enter the lanes, with the most partial rounds that they take.
#[test]
fn test_poseidon_permute_8_largest_constants() {
    let rng = &mut TestRng::default();
    let sparse_rounds = PoseidonSparseRounds::new(&Arc::new(parameters_with_rounds(8, 64, 1.0, rng))).unwrap();
    check_permute_8(&sparse_rounds, &[[-Fr::one(); 9]; 8], 3);
}

#[test]
fn test_poseidon_permute_8_refusals() {
    let rng = &mut TestRng::default();
    let default = Fr::default_poseidon_parameters::<8>().unwrap();
    let sparse = |parameters: PoseidonParameters<Fr, 8, 1>| PoseidonSparseRounds::new(&Arc::new(parameters)).unwrap();
    let state: [[Fr; 8]; 10] = std::array::from_fn(|_| std::array::from_fn(|_| Fr::rand(rng)));

    // The S-box is not `x^17`; there are more than 64 partial rounds.
    let other_alpha = PoseidonParameters { alpha: 5, ..default.clone() };
    for parameters in [other_alpha, parameters_with_rounds(8, 65, 0.0, rng)] {
        let mut lanes = state;
        assert!(Fr::poseidon_permute_8(&sparse(parameters), &mut lanes[..9]).is_none());
        assert_eq!(lanes, state);
    }

    // The state has an element too few or too many.
    let sparse_rounds = sparse(default);
    for len in [0, 8, 10] {
        let mut lanes = state;
        assert!(Fr::poseidon_permute_8(&sparse_rounds, &mut lanes[..len]).is_none());
        assert_eq!(lanes, state);
    }

    // The rate is not 8.
    for_rate::<2>(rng);
    for_rate::<4>(rng);
    for_rate::<7>(rng);
    fn for_rate<const RATE: usize>(rng: &mut TestRng) {
        let parameters = Arc::new(Fr::default_poseidon_parameters::<RATE>().unwrap());
        let sparse_rounds = PoseidonSparseRounds::new(&parameters).unwrap();
        for len in [RATE + 1, 9] {
            let state: Vec<[Fr; 8]> = (0..len).map(|_| std::array::from_fn(|_| Fr::rand(rng))).collect();
            let mut lanes = state.clone();
            assert!(Fr::poseidon_permute_8(&sparse_rounds, &mut lanes).is_none());
            assert_eq!(lanes, state);
        }
    }

    // A field without the lanes declines.
    let parameters = Arc::new(Fq::default_poseidon_parameters::<8>().unwrap());
    let sparse_rounds = PoseidonSparseRounds::new(&parameters).unwrap();
    let mut lanes: [[Fq; 8]; 9] = std::array::from_fn(|_| std::array::from_fn(|_| Fq::rand(rng)));
    assert!(Fq::poseidon_permute_8(&sparse_rounds, &mut lanes).is_none());

    // With the lanes, the default parameters run.
    let mut lanes = state;
    assert_eq!(Fr::poseidon_permute_8(&sparse_rounds_of_default(), &mut lanes[..9]).is_some(), lanes_expected());
    fn sparse_rounds_of_default() -> PoseidonSparseRounds<Fr, 8> {
        PoseidonSparseRounds::new(&Arc::new(Fr::default_poseidon_parameters::<8>().unwrap())).unwrap()
    }
}
