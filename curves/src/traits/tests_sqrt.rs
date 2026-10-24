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

//! Differential tests for `sqrt`.
//!
//! `sqrt` must return the same element as `sarkar_reference`, not merely one of the two roots.
//! `sarkar_reference` is a direct, table-free implementation of Sarkar's Algorithm 1.

use crate::{
    bls12_377::{Fq, Fr},
    edwards_bls12::Fr as EdwardsFr,
};
use snarkvm_fields::{
    ExponentSchedule,
    FftField,
    FftParameters,
    Field,
    LegendreSymbol,
    PrimeField,
    SqrtTables,
    SquareRootField,
    Zero,
};
use snarkvm_utilities::{BigInteger, TestRng, Uniform};

use rand::RngExt;

/// The number of random residues, and separately of random non-residues, checked per field.
const RANDOM_INPUTS: usize = 10_000;

fn two_adicity<F: FftField>() -> u32 {
    <F as FftField>::FftParameters::TWO_ADICITY
}

/// Sarkar, "Computing square roots faster than the Tonelli-Shanks/Bernstein algorithm",
/// https://eprint.iacr.org/2020/1407.pdf, Algorithm 1 with the modification of Section 2.1.
fn sarkar_reference<F: PrimeField + SquareRootField>(a: &F) -> Option<F> {
    match a.legendre() {
        LegendreSymbol::Zero => Some(*a),
        LegendreSymbol::QuadraticNonResidue => None,
        LegendreSymbol::QuadraticResidue => {
            let n = two_adicity::<F>() as u64;
            // `powers[i]` is `g^(2^i)` for the 2-adic root of unity `g`.
            let powers: Vec<F> = std::iter::successors(Some(F::two_adic_root_of_unity()), |g| Some(g.square()))
                .take(n as usize)
                .collect();
            let v = a.pow(F::trace_minus_one_div_two());
            let x = *a * v.square();

            let k = (n - 1).isqrt();
            let k_2 = if n.is_multiple_of(2) { k / 2 } else { (n - 1) % k };
            let k_1 = k - k_2;
            let l_minus_one_times_k = n - 1 - k_2;
            let l_minus_one = l_minus_one_times_k / k;
            let l = l_minus_one + 1;

            let l_s = || std::iter::repeat_n(l_minus_one, k_1 as usize).chain(std::iter::repeat_n(l, k_2 as usize));

            let mut l_sum = 0;
            let x_s = l_s().take((k as usize) - 1).map(|l| {
                l_sum += l;
                x.pow([2u64.pow((n - 1 - l_sum) as u32)])
            });
            let x_s = x_s.chain(Some(x));

            let find = |delta: F| -> u64 {
                let mut mu = delta;
                let mut i = 0;
                while mu != -F::one() {
                    mu.square_in_place();
                    i += 1;
                }
                i
            };

            let eval = |mut delta: F| -> u64 {
                let mut s = 0u64;
                while delta != F::one() {
                    let i = find(delta);
                    let n_minus_one_minus_i = n - 1 - i;
                    s += 2u64.pow(n_minus_one_minus_i as u32);
                    if i > 0 {
                        delta *= powers[n_minus_one_minus_i as usize];
                    } else {
                        delta = -delta;
                    }
                }
                s
            };

            let calculate_gamma = |i: usize, q_s: &[u64], last: bool| -> F {
                let mut gamma = F::one();
                if i != 0 {
                    q_s.iter().zip(l_s()).enumerate().for_each(|(j, (q, l))| {
                        let mut kappa = l_s().take(j).sum::<u64>() + 1 + l_s().skip(i + 1).sum::<u64>();
                        if last {
                            kappa -= 1;
                        }
                        let mut value = *q;
                        (0..l as usize).for_each(|k| {
                            if value & 1 == 1 {
                                gamma *= powers[(kappa as usize) + k];
                            }
                            value = value.wrapping_shr(1u32);
                        });
                    });
                }
                gamma
            };

            let mut q_s = Vec::<u64>::with_capacity(k as usize);
            let two_to_n_minus_l = 2u64.pow((n - l) as u32);
            let two_to_n_minus_l_minus_one = 2u64.pow((n - l_minus_one) as u32);
            x_s.enumerate().for_each(|(i, x)| {
                let gamma = calculate_gamma(i, &q_s, false);
                let alpha = x * gamma;
                q_s.push(eval(alpha) / if i < k_1 as usize { two_to_n_minus_l_minus_one } else { two_to_n_minus_l });
            });

            let gamma = calculate_gamma(k as usize, &q_s, true);
            Some(*a * v * gamma)
        }
    }
}

/// Checks `sqrt` against the reference and against the definition of a square root.
fn check<F: PrimeField + SquareRootField>(a: &F) {
    let root = a.sqrt();
    assert_eq!(root, sarkar_reference(a), "sqrt({a}) differs from the reference");
    match a.legendre() {
        LegendreSymbol::Zero => assert_eq!(root, Some(F::zero()), "sqrt(0) is not Some(0)"),
        LegendreSymbol::QuadraticNonResidue => assert_eq!(root, None, "sqrt({a}) is not None for a non-square"),
        LegendreSymbol::QuadraticResidue => {
            assert_eq!(root.map(|root| root.square()), Some(*a), "sqrt({a})^2 != {a}")
        }
    }
}

/// Returns a mask of the low `bits` bits, for `bits < 64`.
fn ones(bits: u32) -> u64 {
    (1u64 << bits) - 1
}

/// Returns `t^-1 mod 2^64` for odd `t`.
fn inverse_mod_2_64(t: u64) -> u64 {
    assert_eq!(t & 1, 1);
    // Each Newton step doubles the number of correct low bits, starting from 3.
    (0..6).fold(t, |inv, _| inv.wrapping_mul(2u64.wrapping_sub(t.wrapping_mul(inv))))
}

/// Returns an element `a` whose 2-adic part `a^t` equals `g^e`, where `g` is the 2-adic root of unity
/// and `t` is the odd part of `p - 1`. The odd-order part of `a` is `r^(2^n)`.
fn with_two_adic_log<F: PrimeField + SquareRootField>(e: u64, r: F) -> F {
    let n = two_adicity::<F>();
    let t_inv = inverse_mod_2_64(F::trace().as_ref()[0]);
    let exponent = e.wrapping_mul(t_inv) & ones(n);
    let odd_part = (0..n).fold(r, |r, _| r.square());
    odd_part * F::two_adic_root_of_unity().pow([exponent])
}

/// The 2-adic logarithms that exercise every window boundary: zero, every single bit,
/// every contiguous run of ones, and the extremes.
fn structured_logs(n: u32) -> Vec<u64> {
    let mut logs = vec![0, 1, 2, ones(n), ones(n) - 1];
    for low in 0..n {
        logs.push(1 << low);
        for high in low + 1..=n {
            logs.push(ones(high) & !ones(low));
        }
    }
    logs
}

fn check_field<F: PrimeField + SquareRootField>(rng: &mut TestRng) {
    let n = two_adicity::<F>();
    let g = F::two_adic_root_of_unity();

    check(&F::zero());
    check(&F::one());
    check(&-F::one());
    check(&F::multiplicative_generator());
    check(&g);
    // Every `g^(2^i)` and its negation.
    for power in std::iter::successors(Some(g), |g| Some(g.square())).take(n as usize + 1) {
        check(&power);
        check(&-power);
    }

    // Controlled 2-adic logarithms, each with two different odd-order parts.
    for e in structured_logs(n) {
        for r in [F::one(), F::rand(rng)] {
            let a = with_two_adic_log(e, r);
            assert_eq!(a.legendre().is_qr(), e.is_multiple_of(2));
            check(&a);
        }
    }
    for _ in 0..200 {
        check(&with_two_adic_log(rng.random::<u64>() & ones(n), F::rand(rng)));
    }

    // Every byte at every bit position, with all other bits zero and with all other bits one.
    let r = F::rand(rng);
    for start in 0..n {
        let byte = ones(n) & (ones(8) << start);
        for digit in 0..256 {
            let digit = byte & (digit << start);
            for e in [digit, digit | (ones(n) & !byte)] {
                check(&with_two_adic_log(e, r));
            }
        }
    }

    // Random residues and non-residues.
    let (mut residues, mut non_residues) = (0, 0);
    while residues < RANDOM_INPUTS || non_residues < RANDOM_INPUTS {
        let a = F::rand(rng);
        if a.legendre().is_qr() {
            if residues < RANDOM_INPUTS {
                check(&a);
                check(&a.square());
                residues += 1;
            }
        } else if non_residues < RANDOM_INPUTS {
            check(&a);
            non_residues += 1;
        }
    }
}

/// Checks `ExponentSchedule` against `pow` for small exponents, exponents with trailing zeros,
/// and dense, sparse and random multi-limb exponents.
fn check_exponent_schedule<F: Field>(rng: &mut TestRng) {
    let mut exponents: Vec<Vec<u64>> = (1..=4096).map(|e| vec![e]).collect();
    exponents.extend([
        vec![1 << 63],
        vec![u64::MAX],
        vec![0, 1],
        vec![0, 1 << 63],
        vec![u64::MAX, u64::MAX],
        vec![0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa, 0x5555_5555_5555_5555],
        vec![0, 0, 0, 0, 0, 1 << 63],
    ]);
    for _ in 0..200 {
        let mut limbs: Vec<u64> = (0..rng.random_range(1..=6)).map(|_| rng.random()).collect();
        limbs[0] &= u64::MAX << rng.random_range(0..64);
        *limbs.last_mut().unwrap() |= 1 << 63;
        exponents.push(limbs);
    }
    for limbs in exponents {
        let u = F::rand(rng);
        assert_eq!(ExponentSchedule::new(&limbs).pow(&u), u.pow(&limbs), "u^{limbs:?}");
    }
}

#[test]
fn test_exponent_schedule_bls12_377_fq() {
    check_exponent_schedule::<Fq>(&mut TestRng::default());
}

#[test]
fn test_exponent_schedule_bls12_377_fr() {
    check_exponent_schedule::<Fr>(&mut TestRng::default());
}

#[test]
fn test_sqrt_matches_reference_bls12_377_fq() {
    check_field::<Fq>(&mut TestRng::default());
}

#[test]
fn test_sqrt_matches_reference_bls12_377_fr() {
    check_field::<Fr>(&mut TestRng::default());
}

/// Edwards-BLS12 Fr has 2-adicity 1, so a square `a` has the root `a^((p+1)/4)`.
/// `sqrt` does not compile for this field, so the tables are tested directly.
#[test]
fn test_sqrt_tables_edwards_bls12_fr() {
    let rng = &mut TestRng::default();
    assert_eq!(two_adicity::<EdwardsFr>(), 1);
    let tables = SqrtTables::<EdwardsFr>::new();
    let mut p_plus_one_div_four = EdwardsFr::modulus_minus_one_div_two();
    p_plus_one_div_four.add_nocarry(&1u64.into());
    p_plus_one_div_four.div2();

    assert_eq!(tables.sqrt(&EdwardsFr::zero()), Some(EdwardsFr::zero()));
    let (mut residues, mut non_residues) = (0, 0);
    while residues < RANDOM_INPUTS || non_residues < RANDOM_INPUTS {
        let a = EdwardsFr::rand(rng);
        if a.legendre().is_qr() {
            let root = a.pow(p_plus_one_div_four);
            assert_eq!(root.square(), a);
            assert_eq!(tables.sqrt(&a), Some(root));
            residues += 1;
        } else {
            assert_eq!(tables.sqrt(&a), None);
            non_residues += 1;
        }
    }
}

/// Returns a key that is distinct on the roots of unity of order `2^8`, which the tables of BLS12-377
/// Fq and Fr hold, and sends every other element to the key of `1`. A look-up of a non-root then
/// always matches a slot by key.
fn colliding_key<F: PrimeField>(element: &F) -> u64 {
    let key = |element: &F| element.to_bigint().as_ref()[0];
    if element.pow([256]).is_one() { key(element) } else { key(&F::one()) }
}

/// Checks `SqrtTables::sqrt` with `colliding_key` on random elements: it returns `None` exactly when
/// the Legendre symbol is -1, and otherwise the root of `sqrt`.
fn check_key_collisions<F: PrimeField + SquareRootField>(rng: &mut TestRng) {
    let tables = SqrtTables::<F>::with_key(colliding_key::<F>);
    for _ in 0..2 * RANDOM_INPUTS {
        let a = F::rand(rng);
        let root = tables.sqrt(&a);
        assert_eq!(root.is_none(), a.legendre().is_qnr(), "SqrtTables::sqrt({a}) misclassifies {a}");
        assert_eq!(root, a.sqrt(), "SqrtTables::sqrt({a}) differs from sqrt");
    }
}

#[test]
fn test_sqrt_tables_key_collisions_bls12_377_fq() {
    check_key_collisions::<Fq>(&mut TestRng::default());
}

#[test]
fn test_sqrt_tables_key_collisions_bls12_377_fr() {
    check_key_collisions::<Fr>(&mut TestRng::default());
}
