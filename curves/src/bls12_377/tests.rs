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

#![allow(unused_imports)]
use crate::{
    bls12_377::{
        Bls12_377,
        Fq,
        Fq2,
        Fq2Parameters,
        Fq6,
        Fq6Parameters,
        Fq12,
        Fq12Parameters,
        FqParameters,
        Fr,
        FrParameters,
        G1Affine,
        G1Projective,
        G2Affine,
        G2Projective,
        g1::Bls12_377G1Parameters,
        g2::Bls12_377G2Parameters,
    },
    templates::{short_weierstrass_jacobian::tests::sw_tests, twisted_edwards_extended::tests::edwards_test},
    traits::{
        AffineCurve,
        PairingEngine,
        ProjectiveCurve,
        ShortWeierstrassParameters,
        tests_field::{
            bench_sqrt,
            field_serialization_test,
            field_test,
            fp256_inverse_test,
            fp384_inverse_test,
            frobenius_test,
            primefield_test,
            random_sqrt_tonelli_tests,
            sqrt_field_test,
        },
        tests_group::*,
        tests_projective::curve_tests,
    },
};
use snarkvm_fields::{
    FftField,
    FftParameters,
    Field,
    FieldParameters,
    Fp2Parameters,
    LegendreSymbol::*,
    One,
    PrimeField,
    SquareRootField,
    Zero,
    fp6_3over2::Fp6Parameters,
};
use snarkvm_utilities::{
    BitIteratorBE,
    biginteger::{BigInteger, BigInteger256, BigInteger384},
    rand::{TestRng, Uniform},
};

use rand::RngExt;
use std::{
    cmp::Ordering,
    ops::{AddAssign, Mul, MulAssign, SubAssign},
};

pub(crate) const ITERATIONS: usize = 10;

#[test]
fn test_bls12_377_fr() {
    let mut rng = TestRng::default();

    for _ in 0..ITERATIONS {
        let a: Fr = rng.random();
        let b: Fr = rng.random();
        field_test(a, b, &mut rng);
        primefield_test::<Fr>(&mut rng);
        sqrt_field_test(b, &mut rng);
        field_serialization_test::<Fr>(&mut rng);
    }
}

#[test]
fn test_bls12_377_fr_inverse() {
    fp256_inverse_test::<FrParameters>(&mut TestRng::default());
}

#[test]
fn test_bls12_377_fq() {
    let mut rng = TestRng::default();

    for _ in 0..ITERATIONS {
        let a: Fq = rng.random();
        let b: Fq = rng.random();
        field_test(a, b, &mut rng);
        primefield_test::<Fq>(&mut rng);
        sqrt_field_test(a, &mut rng);
        field_serialization_test::<Fq>(&mut rng);
    }
}

#[test]
fn test_bls12_377_fq_inverse() {
    fp384_inverse_test::<FqParameters>(&mut TestRng::default());
}

#[test]
fn test_bls12_377_fq2() {
    let mut rng = TestRng::default();

    for _ in 0..ITERATIONS {
        let a: Fq2 = rng.random();
        let b: Fq2 = rng.random();
        field_test(a, b, &mut rng);
        sqrt_field_test(a, &mut rng);
    }
    frobenius_test::<Fq2, _>(Fq::characteristic(), 13, &mut rng);
    field_serialization_test::<Fq2>(&mut rng);
}

#[test]
fn test_bls12_377_fq6() {
    let mut rng = TestRng::default();

    for _ in 0..ITERATIONS {
        let g: Fq6 = rng.random();
        let h: Fq6 = rng.random();
        field_test(g, h, &mut rng);
    }
    frobenius_test::<Fq6, _>(Fq::characteristic(), 13, &mut rng);
    field_serialization_test::<Fq6>(&mut rng);
}

#[test]
fn test_bls12_377_fq12() {
    let mut rng = TestRng::default();

    for _ in 0..ITERATIONS {
        let g: Fq12 = rng.random();
        let h: Fq12 = rng.random();
        field_test(g, h, &mut rng);
    }
    frobenius_test::<Fq12, _>(Fq::characteristic(), 13, &mut rng);
    field_serialization_test::<Fq12>(&mut rng);
}

#[test]
fn test_fq_repr_from() {
    assert_eq!(BigInteger384::from(100), BigInteger384([100, 0, 0, 0, 0, 0]));
}

#[test]
fn test_fq_repr_is_odd() {
    assert!(!BigInteger384::from(0).is_odd());
    assert!(BigInteger384::from(0).is_even());
    assert!(BigInteger384::from(1).is_odd());
    assert!(!BigInteger384::from(1).is_even());
    assert!(!BigInteger384::from(324834872).is_odd());
    assert!(BigInteger384::from(324834872).is_even());
    assert!(BigInteger384::from(324834873).is_odd());
    assert!(!BigInteger384::from(324834873).is_even());
}

#[test]
fn test_fq_repr_is_zero() {
    assert!(BigInteger384::from(0).is_zero());
    assert!(!BigInteger384::from(1).is_zero());
    assert!(!BigInteger384([0, 0, 0, 0, 1, 0]).is_zero());
}

#[test]
fn test_fq_is_half() {
    assert_eq!(Fq::half(), Fq::one().double().inverse().unwrap());
}

#[test]
fn test_fr_sum_of_products() {
    let mut rng = TestRng::default();
    for i in [2, 4, 8, 16, 32] {
        let a = (0..i).map(|_| rng.random()).collect::<Vec<_>>();
        let b = (0..i).map(|_| rng.random()).collect::<Vec<_>>();
        assert_eq!(Fr::sum_of_products(&a, &b), a.into_iter().zip(b).map(|(a, b)| a * b).sum());
    }
}

#[test]
fn test_fq_sum_of_products() {
    let mut rng = TestRng::default();
    for i in [2, 4, 8, 16, 32] {
        let a = (0..i).map(|_| rng.random()).collect::<Vec<_>>();
        let b = (0..i).map(|_| rng.random()).collect::<Vec<_>>();
        assert_eq!(Fq::sum_of_products(&a, &b), a.into_iter().zip(b).map(|(a, b)| a * b).sum());
    }
}

#[test]
fn test_fq_repr_num_bits() {
    let mut a = BigInteger384::from(0);
    assert_eq!(0, a.num_bits());
    a = BigInteger384::from(1);
    for i in 1..385 {
        assert_eq!(i, a.num_bits());
        a.mul2();
    }
    assert_eq!(0, a.num_bits());
}

#[test]
fn test_fq_add_assign() {
    // Test associativity

    let mut rng = TestRng::default();

    for _ in 0..1000 {
        // Generate a, b, c and ensure (a + b) + c == a + (b + c).
        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let c = Fq::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(b);
        tmp1.add_assign(c);

        let mut tmp2 = b;
        tmp2.add_assign(c);
        tmp2.add_assign(a);

        assert!(tmp1.is_valid());
        assert!(tmp2.is_valid());
        assert_eq!(tmp1, tmp2);
    }
}

#[test]
fn test_fq_sub_assign() {
    let mut rng = TestRng::default();

    for _ in 0..1000 {
        // Ensure that (a - b) + (b - a) = 0.
        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.sub_assign(&b);

        let mut tmp2 = b;
        tmp2.sub_assign(&a);

        tmp1.add_assign(tmp2);
        assert!(tmp1.is_zero());
    }
}

#[test]
fn test_fq_mul_assign() {
    let mut rng = TestRng::default();

    for _ in 0..1000000 {
        // Ensure that (a * b) * c = a * (b * c)
        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        let c = Fq::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.mul_assign(&b);
        tmp1.mul_assign(&c);

        let mut tmp2 = b;
        tmp2.mul_assign(&c);
        tmp2.mul_assign(&a);

        assert_eq!(tmp1, tmp2);
    }

    for _ in 0..1000000 {
        // Ensure that r * (a + b + c) = r*a + r*b + r*c

        let r = Fq::rand(&mut rng);
        let mut a = Fq::rand(&mut rng);
        let mut b = Fq::rand(&mut rng);
        let mut c = Fq::rand(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(b);
        tmp1.add_assign(c);
        tmp1.mul_assign(&r);

        a.mul_assign(&r);
        b.mul_assign(&r);
        c.mul_assign(&r);

        a.add_assign(b);
        a.add_assign(c);

        assert_eq!(tmp1, a);
    }
}

#[test]
fn test_fq_squaring() {
    let mut rng = TestRng::default();

    for _ in 0..1000000 {
        // Ensure that (a * a) = a^2
        let a = Fq::rand(&mut rng);

        let mut tmp = a;
        tmp.square_in_place();

        let mut tmp2 = a;
        tmp2.mul_assign(&a);

        assert_eq!(tmp, tmp2);
    }
}

#[test]
fn test_fq_inverse() {
    assert!(Fq::zero().inverse().is_none());

    let mut rng = TestRng::default();

    let one = Fq::one();

    for _ in 0..1000 {
        // Ensure that a * a^-1 = 1
        let mut a = Fq::rand(&mut rng);
        let ainv = a.inverse().unwrap();
        a.mul_assign(&ainv);
        assert_eq!(a, one);
    }
}

#[test]
fn test_fq_double_in_place() {
    let mut rng = TestRng::default();

    for _ in 0..1000 {
        // Ensure doubling a is equivalent to adding a to itself.
        let mut a = Fq::rand(&mut rng);
        let mut b = a;
        b.add_assign(a);
        a.double_in_place();
        assert_eq!(a, b);
    }
}

#[test]
fn test_fq_negate() {
    {
        let a = -Fq::zero();

        assert!(a.is_zero());
    }

    let mut rng = TestRng::default();

    for _ in 0..1000 {
        // Ensure (a - (-a)) = 0.
        let mut a = Fq::rand(&mut rng);
        let b = -a;
        a.add_assign(b);

        assert!(a.is_zero());
    }
}

#[test]
fn test_fq_pow() {
    let mut rng = TestRng::default();

    for i in 0..1000 {
        // Exponentiate by various small numbers and ensure it consists with repeated
        // multiplication.
        let a = Fq::rand(&mut rng);
        let target = a.pow([i]);
        let mut c = Fq::one();
        for _ in 0..i {
            c.mul_assign(&a);
        }
        assert_eq!(c, target);
    }

    for _ in 0..1000 {
        // Exponentiating by the modulus should have no effect in a prime field.
        let a = Fq::rand(&mut rng);

        assert_eq!(a, a.pow(Fq::characteristic()));
    }
}

#[test]
fn test_fq_sqrt() {
    let mut rng = TestRng::default();

    assert_eq!(Fq::zero().sqrt().unwrap(), Fq::zero());

    for _ in 0..1000 {
        // Ensure sqrt(a^2) = a or -a
        let a = Fq::rand(&mut rng);
        let nega = -a;
        let mut b = a;
        b.square_in_place();

        let b = b.sqrt().unwrap();

        assert!(a == b || nega == b);
    }

    for _ in 0..1000 {
        // Ensure sqrt(a)^2 = a for random a
        let a = Fq::rand(&mut rng);

        if let Some(mut tmp) = a.sqrt() {
            tmp.square_in_place();

            assert_eq!(a, tmp);
        }
    }
}

#[test]
fn test_fq_sqrt_tonelli() {
    let mut rng = TestRng::default();

    random_sqrt_tonelli_tests::<Fq>(&mut rng);
}

#[test]
fn test_fr_sqrt_tonelli() {
    let mut rng = TestRng::default();

    random_sqrt_tonelli_tests::<Fr>(&mut rng);
}

#[test]
fn test_fq_bench_sqrt() {
    let mut rng = TestRng::default();

    bench_sqrt::<Fq>(&mut rng);
}

#[test]
fn test_fr_bench_sqrt() {
    let mut rng = TestRng::default();

    bench_sqrt::<Fr>(&mut rng);
}

#[test]
fn test_fq_num_bits() {
    assert_eq!(FqParameters::MODULUS_BITS, 377);
    assert_eq!(FqParameters::CAPACITY, 376);
}

#[test]
fn test_fq_root_of_unity() {
    assert_eq!(FqParameters::TWO_ADICITY, 46);
    assert_eq!(
        Fq::multiplicative_generator().pow([
            0x7510c00000021423,
            0x88bee82520005c2d,
            0x67cc03d44e3c7bcd,
            0x1701b28524ec688b,
            0xe9185f1443ab18ec,
            0x6b8
        ]),
        Fq::two_adic_root_of_unity()
    );
    assert_eq!(Fq::two_adic_root_of_unity().pow([1 << FqParameters::TWO_ADICITY]), Fq::one());
    assert!(Fq::multiplicative_generator().sqrt().is_none());
}

#[test]
fn test_fq_ordering() {
    // BigInteger384's ordering is well-tested, but we still need to make sure the
    // Fq elements aren't being compared in Montgomery form.
    for i in 0..100 {
        assert!(
            Fq::from_bigint(BigInteger384::from(i + 1)).unwrap() > Fq::from_bigint(BigInteger384::from(i)).unwrap()
        );
    }
}

#[test]
fn test_fq_legendre() {
    assert_eq!(QuadraticResidue, Fq::one().legendre());
    assert_eq!(Zero, Fq::zero().legendre());
    assert_eq!(QuadraticResidue, Fq::from_bigint(BigInteger384::from(4)).unwrap().legendre());
    assert_eq!(QuadraticNonResidue, Fq::from_bigint(BigInteger384::from(5)).unwrap().legendre());
}

#[test]
fn test_fq2_ordering() {
    let mut a = Fq2::new(Fq::zero(), Fq::zero());
    let mut b = a;

    assert!(a.cmp(&b) == Ordering::Equal);
    b.c0.add_assign(Fq::one());
    assert!(a.cmp(&b) == Ordering::Less);
    a.c0.add_assign(Fq::one());
    assert!(a.cmp(&b) == Ordering::Equal);
    b.c1.add_assign(Fq::one());
    assert!(a.cmp(&b) == Ordering::Less);
    a.c0.add_assign(Fq::one());
    assert!(a.cmp(&b) == Ordering::Less);
    a.c1.add_assign(Fq::one());
    assert!(a.cmp(&b) == Ordering::Greater);
    b.c0.add_assign(Fq::one());
    assert!(a.cmp(&b) == Ordering::Equal);
}

#[test]
fn test_fq2_basics() {
    assert_eq!(Fq2::new(Fq::zero(), Fq::zero(),), Fq2::zero());
    assert_eq!(Fq2::new(Fq::one(), Fq::zero(),), Fq2::one());
    assert!(Fq2::zero().is_zero());
    assert!(!Fq2::one().is_zero());
    assert!(!Fq2::new(Fq::zero(), Fq::one(),).is_zero());
}

#[test]
fn test_fq2_legendre() {
    assert_eq!(Zero, Fq2::zero().legendre());
    // i^2 = -1
    let mut m1 = -Fq2::one();
    assert_eq!(QuadraticResidue, m1.legendre());
    m1 = Fq6Parameters::mul_fp2_by_nonresidue(&m1);
    assert_eq!(QuadraticNonResidue, m1.legendre());
}

#[test]
fn test_fq2_mul_nonresidue() {
    let mut rng = TestRng::default();

    let nqr = Fq2::new(Fq::zero(), Fq::one());

    let quadratic_non_residue = Fq2::new(Fq2Parameters::QUADRATIC_NONRESIDUE.0, Fq2Parameters::QUADRATIC_NONRESIDUE.1);
    for _ in 0..1000 {
        let mut a = Fq2::rand(&mut rng);
        let mut b = a;
        a = quadratic_non_residue * a;
        b.mul_assign(&nqr);

        assert_eq!(a, b);
    }
}

#[test]
fn test_fq6_mul_by_1() {
    let mut rng = TestRng::default();

    for _ in 0..1000 {
        let c1 = Fq2::rand(&mut rng);
        let mut a = Fq6::rand(&mut rng);
        let mut b = a;

        a.mul_by_1(&c1);
        b.mul_assign(&Fq6::new(Fq2::zero(), c1, Fq2::zero()));

        assert_eq!(a, b);
    }
}

#[test]
fn test_fq6_mul_by_01() {
    let mut rng = TestRng::default();

    for _ in 0..1000 {
        let c0 = Fq2::rand(&mut rng);
        let c1 = Fq2::rand(&mut rng);
        let mut a = Fq6::rand(&mut rng);
        let mut b = a;

        a.mul_by_01(&c0, &c1);
        b.mul_assign(&Fq6::new(c0, c1, Fq2::zero()));

        assert_eq!(a, b);
    }
}

#[test]
fn test_fq12_mul_by_014() {
    let mut rng = TestRng::default();

    for _ in 0..1000 {
        let c0 = Fq2::rand(&mut rng);
        let c1 = Fq2::rand(&mut rng);
        let c5 = Fq2::rand(&mut rng);
        let mut a = Fq12::rand(&mut rng);
        let mut b = a;

        a.mul_by_014(&c0, &c1, &c5);
        b.mul_assign(&Fq12::new(Fq6::new(c0, c1, Fq2::zero()), Fq6::new(Fq2::zero(), c5, Fq2::zero())));

        assert_eq!(a, b);
    }
}

#[test]
fn test_fq12_mul_by_034() {
    let mut rng = TestRng::default();

    for _ in 0..1000 {
        let c0 = Fq2::rand(&mut rng);
        let c3 = Fq2::rand(&mut rng);
        let c4 = Fq2::rand(&mut rng);
        let mut a = Fq12::rand(&mut rng);
        let mut b = a;

        a.mul_by_034(&c0, &c3, &c4);
        b = fq12_schoolbook(&b, &Fq12::new(Fq6::new(c0, Fq2::zero(), Fq2::zero()), Fq6::new(c3, c4, Fq2::zero())));

        assert_eq!(a, b);
    }
}

/// The elements at the edges of the lane kernel's input range: 0, 1, 2, -1, -2, and the
/// Montgomery words 1, 2, p - 1 and R^2.
fn fq_edge_elements() -> Vec<Fq> {
    let mut p_minus_1 = FqParameters::MODULUS;
    p_minus_1.sub_noborrow(&BigInteger384::from(1));
    let montgomery = |w: BigInteger384| -> Fq { snarkvm_fields::field!(Fq, w) };
    vec![
        Fq::zero(),
        Fq::one(),
        Fq::from(2u64),
        -Fq::one(),
        -Fq::from(2u64),
        montgomery(BigInteger384::from(1)),
        montgomery(BigInteger384::from(2)),
        montgomery(p_minus_1),
        montgomery(FqParameters::R2),
    ]
}

/// Schoolbook product in Fq6 = Fq2[v] / (v^3 - xi), from Fq2 products only.
fn fq6_schoolbook(a: &Fq6, b: &Fq6) -> Fq6 {
    let xi = Fq6Parameters::mul_fp2_by_nonresidue;
    Fq6::new(
        a.c0 * b.c0 + xi(&(a.c1 * b.c2 + a.c2 * b.c1)),
        a.c0 * b.c1 + a.c1 * b.c0 + xi(&(a.c2 * b.c2)),
        a.c0 * b.c2 + a.c1 * b.c1 + a.c2 * b.c0,
    )
}

/// Schoolbook product in Fq12 = Fq6[w] / (w^2 - v), from `fq6_schoolbook` only.
fn fq12_schoolbook(a: &Fq12, b: &Fq12) -> Fq12 {
    let v = |x: Fq6| Fq6::new(Fq6Parameters::mul_fp2_by_nonresidue(&x.c2), x.c0, x.c1);
    Fq12::new(
        fq6_schoolbook(&a.c0, &b.c0) + v(fq6_schoolbook(&a.c1, &b.c1)),
        fq6_schoolbook(&a.c0, &b.c1) + fq6_schoolbook(&a.c1, &b.c0),
    )
}

/// The 12 coefficients of `x`, in the order `c0.c0.c0`, `c0.c0.c1`, `c0.c1.c0`, ..., `c1.c2.c1`.
fn fq12_coefficients(x: &Fq12) -> impl Iterator<Item = Fq> {
    [x.c0, x.c1].into_iter().flat_map(|x| [x.c0, x.c1, x.c2]).flat_map(|x| [x.c0, x.c1])
}

/// Returns 0 or p - 1.
fn fq_zero_or_minus_one(rng: &mut TestRng) -> Fq {
    if rng.random_bool(0.5) { -Fq::one() } else { Fq::zero() }
}

/// Returns one of `edges` or a random element.
fn fq_edge_or_random(rng: &mut TestRng, edges: &[Fq]) -> Fq {
    if rng.random_bool(0.5) { edges[rng.random_range(0..edges.len())] } else { Fq::rand(rng) }
}

/// Whether the lanes run on this CPU.
fn lanes_supported() -> bool {
    snarkvm_fields::ifma::is_supported::<FqParameters>()
}

/// The element whose coefficients are `c`, in the order of `fq12_coefficients`.
fn fq12_from_coefficients(c: [Fq; 12]) -> Fq12 {
    let fq6 = |c: &[Fq]| Fq6::new(Fq2::new(c[0], c[1]), Fq2::new(c[2], c[3]), Fq2::new(c[4], c[5]));
    Fq12::new(fq6(&c[..6]), fq6(&c[6..]))
}

/// Checks `a * b` and, if `a == b`, `a.square()` against `fq12_schoolbook` through the `Fq12`
/// API, and that every coefficient of the product is canonical.
fn check_fq12_mul(a: &Fq12, b: &Fq12) {
    let expected = fq12_schoolbook(a, b);
    let mut c = *a;
    c *= b;
    assert_eq!(c, expected, "{a} * {b}");
    let mut scalar = *a;
    scalar.mul_assign_scalar(b);
    assert_eq!(scalar, expected, "{a} * {b} by the scalar path");
    assert!(fq12_coefficients(&c).all(|x| x.is_valid()), "{a} * {b}");
    if a == b {
        assert_eq!(a.square(), expected, "{a} squared");
        let mut d = *a;
        d.square_in_place();
        assert_eq!(d, expected, "{a} squared in place");
    }
}

/// `e(G1 generator, G2 generator)`, as the hex of its `to_bytes_le`.
const PAIRING_OF_GENERATORS: &str = concat!(
    "4c9b02ed807521637429bab75573514bfd46e7ac3b68bce149ea99ec7a3ca8a10e717554d44fa544a910b6a68ce13601",
    "44bade45b2e7f8ab5d8831e7dd0c0782bad392cbac0c68853c579f7948d6dff9ea733597c11814e2a38ab639a4437800",
    "4d00d020f6fb29e524f59d5ca3eeb2ac8cb3f400b1ee69b4f9646919d9fe95c28b923604d3c3382131e721b13c3d0401",
    "e70b852425b201025cff3033bb6cd18a9c77e6c1775a94543cca3e947ac4d428f99c3e715b2af374182fc1a1c6866701",
    "0dcc2d59f05f533e11373551a1e9a34cfdd910ea702cebd57950acae019b411776c8b512526aeb77758ad87cd1933500",
    "89a40bbf0f2575850cb749e96fdfa565b710d304b5df99ecaa7bb7a4bdd7e63546ecf2290adc2e5247fe1b8d1997ef00",
    "a935bcc1d1d182cd1ea21c47dd3e0d59344202489799be898114f255853908b952f49c4ca5de2074bfefb25d231f9900",
    "d035577107267ab0466dfa759e30ab29bdc1f4fc9d24a431e9eff91ad05623f21cfdd291d7795fc8544c6bd2c70fb000",
    "75394a71e15e901a0485611e1214f4d1ae0bf818e2b81182e5be85d2591320ddbb0ed9822cf56d2a1609b078d404c700",
    "92127497958ac652fb20cf2decadb7f64316d33d7f5b59045f5f3d8d899829e224209001a18dfbc534fba6cfd60e4d01",
    "4646d58f5709fbc0f5146d32432cceeaed06ba8ea7dfcc95c552fec3bf42336cd0706ec65adf7ba209c5fe94ff6b1b01",
    "f0c0fcb90b760f5a742032c0962a483c6b5fc104667f4db87510906678c98dcc33bbbdc1096edc8fc9d8c13cbc508400",
);

#[test]
fn test_pairing_of_generators() {
    use snarkvm_utilities::ToBytes;

    let e = Bls12_377::pairing(G1Affine::prime_subgroup_generator(), G2Affine::prime_subgroup_generator());
    let hex: String = e.to_bytes_le().unwrap().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, PAIRING_OF_GENERATORS);
}

#[test]
fn test_fq_ifma_supported() {
    #[cfg(target_arch = "x86_64")]
    let expected = std::is_x86_feature_detected!("avx512f")
        && std::is_x86_feature_detected!("avx512ifma")
        && std::env::var_os("SNARKVM_NO_IFMA").is_none_or(|value| value.is_empty());
    #[cfg(not(target_arch = "x86_64"))]
    let expected = false;
    assert_eq!(lanes_supported(), expected);
}

#[test]
fn test_fq12_mul_assign_lanes() {
    let mut rng = TestRng::default();
    let edges = fq_edge_elements();

    // The tower of Fq12 runs in lanes exactly where the field does, and the hook multiplies in it.
    assert_eq!(Fq2Parameters::NONRESIDUE, -Fq::from(5u64));
    assert_eq!(Fq6Parameters::NONRESIDUE, Fq2::new(Fq::zero(), Fq::one()));
    assert_eq!(snarkvm_fields::ifma::is_supported_tower::<Fq12Parameters, FqParameters>(), lanes_supported());

    // Every coefficient equal, for every pair of edge elements: the largest operand sums.
    for x in &edges {
        for y in &edges {
            check_fq12_mul(&fq12_from_coefficients([*x; 12]), &fq12_from_coefficients([*y; 12]));
        }
    }

    // The 12 coefficients each 0 or p - 1, in 64 patterns, against themselves and against a
    // random element.
    for _ in 0..64 {
        let a = fq12_from_coefficients(std::array::from_fn(|_| fq_zero_or_minus_one(&mut rng)));
        check_fq12_mul(&a, &a);
        check_fq12_mul(&a, &Fq12::rand(&mut rng));
    }

    // Edge elements mixed with random ones across the coefficients.
    for _ in 0..2_000 {
        let mut pick = || fq_edge_or_random(&mut rng, &edges);
        let a = fq12_from_coefficients(std::array::from_fn(|_| pick()));
        let b = fq12_from_coefficients(std::array::from_fn(|_| pick()));
        check_fq12_mul(&a, &b);
    }

    // Random elements, and a product with itself.
    for _ in 0..2_000 {
        let a = Fq12::rand(&mut rng);
        check_fq12_mul(&a, &Fq12::rand(&mut rng));
        check_fq12_mul(&a, &a);
    }
}

#[test]
fn test_g1_projective_glv() {
    let mut rng = TestRng::default();

    let point = G1Projective::rand(&mut rng);
    let scalar = Fr::rand(&mut rng);
    let affine = point.to_affine();
    assert_eq!(point.mul(scalar), affine.mul(scalar));
    assert_eq!(affine.mul(scalar), affine.mul_bits(BitIteratorBE::new_without_leading_zeros(scalar.to_bigint())));
}

#[test]
fn test_g1_projective_curve() {
    let mut rng = TestRng::default();

    curve_tests::<G1Projective>(&mut rng);
    sw_tests::<Bls12_377G1Parameters>(&mut rng);
}

#[test]
fn test_g1_projective_group() {
    let mut rng = TestRng::default();

    let a: G1Projective = rng.random();
    let b: G1Projective = rng.random();
    projective_test(a, b, &mut rng);
}

#[test]
fn test_g1_serialization_round_trip() {
    serialization_round_trip_test::<G1Affine>();
}

#[test]
fn test_g1_generator() {
    let generator = G1Affine::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn test_g2_projective_curve() {
    let mut rng = TestRng::default();

    curve_tests::<G2Projective>(&mut rng);
    sw_tests::<Bls12_377G2Parameters>(&mut rng);
}

#[test]
fn test_g2_projective_group() {
    let mut rng = TestRng::default();

    let a: G2Projective = rng.random();
    let b: G2Projective = rng.random();
    projective_test(a, b, &mut rng);
}

#[test]
fn test_g2_serialization_round_trip() {
    serialization_round_trip_test::<G2Affine>();
}

#[test]
fn test_g2_generator() {
    let generator = G2Affine::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn test_bilinearity() {
    let mut rng = TestRng::default();

    let a: G1Projective = rng.random();
    let b: G2Projective = rng.random();
    let s: Fr = rng.random();

    let sa = a * s;
    let sb = b * s;

    let ans1 = Bls12_377::pairing(sa, b);
    let ans2 = Bls12_377::pairing(a, sb);
    let ans3 = Bls12_377::pairing(a, b).pow(s.to_bigint());

    assert_eq!(ans1, ans2);
    assert_eq!(ans2, ans3);

    assert_ne!(ans1, Fq12::one());
    assert_ne!(ans2, Fq12::one());
    assert_ne!(ans3, Fq12::one());

    assert_eq!(ans1.pow(Fr::characteristic()), Fq12::one());
    assert_eq!(ans2.pow(Fr::characteristic()), Fq12::one());
    assert_eq!(ans3.pow(Fr::characteristic()), Fq12::one());
}
