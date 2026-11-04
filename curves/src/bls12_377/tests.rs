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
        Bls12_377Parameters,
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
    templates::{
        bls12::{Bls12Parameters, G1Prepared, G2Prepared},
        short_weierstrass_jacobian::tests::sw_tests,
        twisted_edwards_extended::tests::edwards_test,
    },
    traits::{
        AffineCurve,
        PairingCurve,
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

/// `Fq12::cyclotomic_square`'s formula from Fq2 operations only: with `z_0 = c0.c0`,
/// `z_1 = c1.c1`, `z_2 = c1.c0`, `z_3 = c0.c2`, `z_4 = c0.c1` and `z_5 = c1.c2`, each pair
/// `(A, B) = (z_{2g}, z_{2g+1})` gives `t_e = A^2 + u B^2` and `t_o = 2 A B`.
fn fq12_cyclotomic_square_reference(x: &Fq12) -> Fq12 {
    let u = Fq6Parameters::mul_fp2_by_nonresidue;
    let t = |a: Fq2, b: Fq2| (a.square() + u(&b.square()), (a * b).double());
    let (t0, t1) = t(x.c0.c0, x.c1.c1);
    let (t2, t3) = t(x.c1.c0, x.c0.c2);
    let (t4, t5) = t(x.c0.c1, x.c1.c2);
    let three = |t: Fq2| t.double() + t;
    Fq12::new(
        Fq6::new(three(t0) - x.c0.c0.double(), three(t2) - x.c0.c1.double(), three(t4) - x.c0.c2.double()),
        Fq6::new(three(u(&t5)) + x.c1.c0.double(), three(t1) + x.c1.c1.double(), three(t3) + x.c1.c2.double()),
    )
}

/// `Fq12::cyclotomic_exp` from `fq12_cyclotomic_square_reference` and `fq12_schoolbook`.
fn fq12_cyclotomic_exp_reference(x: &Fq12, exp: &[u64]) -> Fq12 {
    let mut res = Fq12::one();
    for bit in BitIteratorBE::new_without_leading_zeros(exp) {
        res = fq12_cyclotomic_square_reference(&res);
        if bit {
            res = fq12_schoolbook(&res, x);
        }
    }
    res
}

/// Returns `f^((p^6 - 1)(p^2 + 1))` for a random `f`: the easy part of the final exponentiation,
/// which lies in the cyclotomic subgroup.
fn fq12_cyclotomic_element(rng: &mut TestRng) -> Fq12 {
    let f = Fq12::rand(rng);
    let mut r = f;
    r.conjugate();
    // A random element is nonzero.
    r = fq12_schoolbook(&r, &f.inverse().unwrap());
    let mut s = r;
    s.frobenius_map(2);
    fq12_schoolbook(&s, &r)
}

/// Inputs for the cyclotomic squaring and exponentiation: every coefficient equal to an edge
/// element, the 12 coefficients each 0 or p - 1 in 64 patterns, edge elements mixed with random
/// ones, random elements and elements of the cyclotomic subgroup.
fn fq12_cyclotomic_inputs(rng: &mut TestRng) -> Vec<Fq12> {
    let edges = fq_edge_elements();
    let mut inputs: Vec<Fq12> = edges.iter().map(|x| fq12_from_coefficients([*x; 12])).collect();
    for _ in 0..64 {
        inputs.push(fq12_from_coefficients(std::array::from_fn(|_| fq_zero_or_minus_one(rng))));
    }
    for _ in 0..200 {
        let mut pick = || fq_edge_or_random(rng, &edges);
        inputs.push(fq12_from_coefficients(std::array::from_fn(|_| pick())));
    }
    inputs.extend((0..200).map(|_| Fq12::rand(rng)));
    inputs.extend((0..50).map(|_| fq12_cyclotomic_element(rng)));
    inputs
}

#[test]
fn test_fq12_cyclotomic_square() {
    let mut rng = TestRng::default();

    for x in fq12_cyclotomic_inputs(&mut rng) {
        let expected = fq12_cyclotomic_square_reference(&x);
        let c = x.cyclotomic_square();
        assert_eq!(c, expected, "{x}");
        assert!(fq12_coefficients(&c).all(|x| x.is_valid()), "{x}");
    }

    // On the cyclotomic subgroup, the formula squares.
    for _ in 0..10 {
        let x = fq12_cyclotomic_element(&mut rng);
        assert_eq!(x.cyclotomic_square(), fq12_schoolbook(&x, &x));
    }
}

#[test]
fn test_fq12_cyclotomic_exp() {
    let mut rng = TestRng::default();
    let x = Bls12_377Parameters::X;
    let mut exponents: Vec<Vec<u64>> = vec![
        vec![],
        vec![0],
        vec![0, 0],
        vec![1],
        vec![2],
        vec![3],
        vec![u64::MAX],
        vec![1 << 63],
        vec![0, 1],
        vec![u64::MAX, u64::MAX],
        vec![5, 0, 0],
        x.to_vec(),
    ];
    exponents.extend((0..20).map(|_| vec![rng.random::<u64>() >> rng.random_range(0..64)]));
    exponents.extend((0..5).map(|_| vec![rng.random::<u64>(), rng.random::<u64>()]));

    for (i, x) in fq12_cyclotomic_inputs(&mut rng).into_iter().enumerate() {
        // Every exponent for a subset of the inputs, and a random one for the rest.
        let chosen = if i % 25 == 0 {
            &exponents[..]
        } else {
            let j = rng.random_range(0..exponents.len());
            &exponents[j..=j]
        };
        for exp in chosen {
            let c = x.cyclotomic_exp(exp);
            assert_eq!(c, fq12_cyclotomic_exp_reference(&x, exp), "{x} ^ {exp:?}");
            assert!(fq12_coefficients(&c).all(|x| x.is_valid()), "{x} ^ {exp:?}");
            assert_eq!(x.cyclotomic_exp_scalar(exp), c, "{x} ^ {exp:?} by the scalar path");
        }
    }

    // On the cyclotomic subgroup, the chain exponentiates.
    for _ in 0..3 {
        let a = fq12_cyclotomic_element(&mut rng);
        assert_eq!(a.cyclotomic_exp(x), a.pow(x));
    }
}

/// A G1 point and the line coefficients of its G2 point, as `ifma::miller_loop_fp12` takes them.
type Pair<'a> = snarkvm_fields::ifma::MillerLoopPair<'a, Fq2Parameters>;

/// A `Pair` that owns its point and lines.
type OwnedPair = ([Fq; 2], Vec<(Fq2, Fq2, Fq2)>);

/// `Bls12::ell` for the D-type twist, from `fq12_schoolbook`.
fn ell_reference(f: &Fq12, (c0, c1, c2): &(Fq2, Fq2, Fq2), [x, y]: [&Fq; 2]) -> Fq12 {
    let (mut c0, mut c1) = (*c0, *c1);
    c0.mul_by_fp(y);
    c1.mul_by_fp(x);
    fq12_schoolbook(f, &Fq12::new(Fq6::new(c0, Fq2::zero(), Fq2::zero()), Fq6::new(c1, *c2, Fq2::zero())))
}

/// The loop of `Bls12::miller_loop` from `f`, before its final conjugation, from `fq12_schoolbook`
/// and `ell_reference`.
fn miller_loop_reference(mut f: Fq12, x: &[u64], pairs: &[Pair<'_>]) -> Fq12 {
    let mut k = 0;
    for bit in BitIteratorBE::new(x).skip(1) {
        f = fq12_schoolbook(&f, &f);
        for _ in 0..1 + bit as usize {
            for (point, lines) in pairs {
                f = ell_reference(&f, &lines[k], *point);
            }
            k += 1;
        }
    }
    f
}

/// The number of lines the loop of `Bls12::miller_loop` takes from each pair for `x`.
fn miller_loop_lines(x: &[u64]) -> usize {
    BitIteratorBE::new(x).skip(1).map(|bit| 1 + bit as usize).sum()
}

/// Runs `snarkvm_fields::ifma::miller_loop_fp12` from `f` and checks it against
/// `miller_loop_reference` where it runs.
fn check_miller_loop_fp12(f: &Fq12, x: &[u64], pairs: &[Pair<'_>]) {
    let c = snarkvm_fields::ifma::miller_loop_fp12(f, x, pairs);
    assert_eq!(c.is_some(), lanes_supported() && !x.is_empty());
    if let Some(c) = c {
        assert_eq!(c, miller_loop_reference(*f, x, pairs), "x {x:?}, {} pairs", pairs.len());
        assert!(fq12_coefficients(&c).all(|x| x.is_valid()), "x {x:?}, {} pairs", pairs.len());
    }
}

#[test]
fn test_fq12_miller_loop_lanes() {
    let mut rng = TestRng::default();
    let edges = fq_edge_elements();
    // `n` pairs whose point and line coefficients `element` draws, with the lines the loop takes
    // for `x`.
    let pairs = |rng: &mut TestRng, n: usize, x: &[u64], element: &dyn Fn(&mut TestRng) -> Fq| -> Vec<OwnedPair> {
        (0..n)
            .map(|_| {
                let mut fq2 = || Fq2::new(element(rng), element(rng));
                let lines = (0..miller_loop_lines(x)).map(|_| (fq2(), fq2(), fq2())).collect();
                ([element(rng), element(rng)], lines)
            })
            .collect()
    };
    let check = |f: &Fq12, x: &[u64], pairs: &[OwnedPair]| {
        let pairs: Vec<Pair<'_>> = pairs.iter().map(|([x, y], lines)| ([x, y], lines.as_slice())).collect();
        check_miller_loop_fp12(f, x, &pairs);
    };
    let random = |rng: &mut TestRng| Fq::rand(rng);

    // Every number of pairs up to 8, with random elements, for short exponents, exponents of
    // several words and with leading zeros, and the curve's.
    let mut exponents: Vec<Vec<u64>> = vec![
        vec![0],
        vec![1],
        vec![2],
        vec![3],
        vec![0b1011],
        vec![1 << 63 | 0b101],
        vec![5, 0],
        vec![0, 1],
        vec![0x8000_0000_0000_0003, 0b11],
        Bls12_377Parameters::X.to_vec(),
    ];
    exponents.extend((0..4).map(|_| vec![rng.random::<u64>() >> rng.random_range(52..64)]));
    for x in &exponents {
        for n in 0..=8 {
            check(&Fq12::rand(&mut rng), x, &pairs(&mut rng, n, x, &random));
        }
    }
    for n in [1, 2, 6] {
        let x = Bls12_377Parameters::X;
        check(&Fq12::one(), x, &pairs(&mut rng, n, x, &random));
    }

    // Every coefficient of `f`, of the lines and of the points equal to an edge element, for each
    // pair of edge elements.
    let x = [0b1011];
    for a in &edges {
        for b in &edges {
            check(&fq12_from_coefficients([*a; 12]), &x, &pairs(&mut rng, 3, &x, &|_| *b));
        }
    }

    // The coefficients of `f`, the lines and the points each 0 or p - 1 in random patterns, and edge
    // elements mixed with random ones.
    let pick = |rng: &mut TestRng| fq_edge_or_random(rng, &edges);
    for element in [&fq_zero_or_minus_one as &dyn Fn(&mut TestRng) -> Fq, &pick] {
        for _ in 0..40 {
            let f = fq12_from_coefficients(std::array::from_fn(|_| element(&mut rng)));
            let n = rng.random_range(1..=4);
            check(&f, &x, &pairs(&mut rng, n, &x, element));
        }
    }

    // An empty exponent is left to the caller.
    check(&Fq12::rand(&mut rng), &[], &pairs(&mut rng, 1, &[], &random));
}

/// Runs `snarkvm_fields::ifma::miller_loop_fp12` from an `f` whose first squaring in IFMA lanes
/// takes the real part of `c0.c0` to `-59.998 p` before `below_2p`.
///
/// The lanes hold a coefficient `x` as an integer congruent to `x K`, `K = 2^416`. For the
/// squaring's operands, `mont_n` returns an integer in `[0, p + 2^-28 p)`, congruent to `x y K`
/// for the lanes of `x` and `y`. With `F_k = (a_k, b_k)` the Fp2 coefficient of `w^k` and `P(F)`
/// the kernel product of `a` and `b`, that real part is
/// `10 (P(F_1 + F_2) + P(F_1 + F_4) + P(F_4 + F_5) + P(F_2 + F_5)) + 4 P(F_0) + S(F_0)`
/// `- 10 (P(F_1) + P(F_2) + P(F_3) + P(F_4) + P(F_5) + P(F_1 + F_2 + F_4 + F_5))`,
/// with `S(F_0)` that of `a_0 + b_0` and `a_0 - 5 b_0`, so it is above `-60 (p + 2^-28 p)`. Here
/// `a_k b_k K = -1` for `k > 0`, `P(F_1 + F_2 + F_4 + F_5)` is congruent to `-d` with `d < 2^366`,
/// and the added products are congruent to values below 2^360.
#[test]
fn test_fq12_miller_loop_lanes_square_extreme() {
    // Each word array is below p, so `from_bigint` returns `Some`.
    let fq = |w: [u64; 6]| Fq::from_bigint(BigInteger384(w)).unwrap();
    let r = fq([
        0x03b133d785431441,
        0xf38970778dd5a099,
        0x341482310a31aeb2,
        0xa52d3c89ce948422,
        0xb956f8d025e11b53,
        0x000d2e45cf10c793,
    ]);
    let s = fq([
        0x34be9545a2427f10,
        0x6a40bc98e70f9810,
        0x3a35165e1a8bec94,
        0xd19c595ab5512e1b,
        0x4a4b6e0dd3143e07,
        0x00a7e1455185eecf,
    ]);
    let f0 = Fq2::new(
        fq([
            0x9c143f9930f980f0,
            0x1b3db2540f87199b,
            0xcaa403154582d8d3,
            0xe20d479f28999d7a,
            0x4a85cca8e922c510,
            0x018d60235136ee8a,
        ]),
        fq([
            0x6c4c6fab9af04187,
            0x7e95b4fb6e442a26,
            0xd2dc06898bb66311,
            0x3031ac447d6ed8a4,
            0x33449bd54e111018,
            0x013ea5dd61b661d0,
        ]),
    );
    let k = Fq::from(2u64).pow([416]);
    // `a K` is nonzero, so it has an inverse.
    let coefficient = |a: Fq| Fq2::new(a, -(a * k).inverse().unwrap());
    let [f1, f2, f3, f4, f5] = [Fq::one(), r, Fq::one(), r, r * s].map(coefficient);

    let product = |a: Fq, b: Fq| a * b * k;
    let fp2_product = |x: Fq2| product(x.c0, x.c1);
    let added = [
        fp2_product(f1 + f2),
        fp2_product(f1 + f4),
        fp2_product(f4 + f5),
        fp2_product(f2 + f5),
        fp2_product(f0),
        product(f0.c0 + f0.c1, f0.c0 - Fq::from(5u64) * f0.c1),
    ];
    assert!(added.iter().all(|x| x.to_bigint().num_bits() <= 360));
    assert!((-fp2_product(f1 + f2 + f4 + f5)).to_bigint().num_bits() <= 366);

    check_miller_loop_fp12(&Fq12::new(Fq6::new(f0, f2, f4), Fq6::new(f1, f3, f5)), &[1], &[]);
}

type PreparedPair = (G1Prepared<Bls12_377Parameters>, G2Prepared<Bls12_377Parameters>);

/// Returns `n` pairs of random points with their prepared forms, the G1 point of pair `i` at
/// infinity where `zero_g1` contains `i`, and the G2 point where `zero_g2` does.
fn prepared_pairs(rng: &mut TestRng, n: usize, zero_g1: &[usize], zero_g2: &[usize]) -> Vec<PreparedPair> {
    (0..n)
        .map(|i| {
            let p = if zero_g1.contains(&i) { G1Affine::zero() } else { G1Projective::rand(rng).to_affine() };
            let q = if zero_g2.contains(&i) { G2Affine::zero() } else { G2Projective::rand(rng).to_affine() };
            (p.prepare(), q.prepare())
        })
        .collect()
}

/// `Bls12::miller_loop` from `miller_loop_reference`, over the pairs without a point at infinity.
fn miller_loop_of_pairs_reference(pairs: &[PreparedPair]) -> Fq12 {
    let pairs: Vec<Pair<'_>> = pairs
        .iter()
        .filter(|(p, q)| !p.is_zero() && !q.is_zero())
        .map(|(p, q)| ([&p.0.x, &p.0.y], q.ell_coeffs.as_slice()))
        .collect();
    let mut f = miller_loop_reference(Fq12::one(), Bls12_377Parameters::X, &pairs);
    if Bls12_377Parameters::X_IS_NEGATIVE {
        f.conjugate();
    }
    f
}

#[test]
fn test_miller_loop() {
    let mut rng = TestRng::default();

    // Every number of pairs up to 8, with points at infinity in G1, in G2, in both, or in none.
    for n in 0..=8 {
        for (zero_g1, zero_g2) in [(vec![], vec![]), (vec![0], vec![]), (vec![], vec![n / 2]), (vec![1, 3], vec![3, 5])]
        {
            let pairs = prepared_pairs(&mut rng, n, &zero_g1, &zero_g2);
            let f = Bls12_377::miller_loop(pairs.iter().map(|(p, q)| (p, q)));
            assert_eq!(
                f,
                miller_loop_of_pairs_reference(&pairs),
                "{n} pairs, zero G1 {zero_g1:?}, zero G2 {zero_g2:?}"
            );
            assert!(fq12_coefficients(&f).all(|x| x.is_valid()));
        }
    }
    assert_eq!(Bls12_377::miller_loop(std::iter::empty()), Fq12::one());

    // The pairing and the product of pairings against the reference Miller loop.
    for n in [1, 2, 6] {
        let pairs = prepared_pairs(&mut rng, n, &[], &[]);
        // The Miller loop of points not at infinity is nonzero, so it has an inverse.
        let expected = Bls12_377::final_exponentiation(&miller_loop_of_pairs_reference(&pairs)).unwrap();
        assert_eq!(Bls12_377::product_of_pairings(pairs.iter().map(|(p, q)| (p, q))), expected, "{n} pairs");
    }
    let (p, q) = (G1Projective::rand(&mut rng).to_affine(), G2Projective::rand(&mut rng).to_affine());
    // As above.
    let expected =
        Bls12_377::final_exponentiation(&miller_loop_of_pairs_reference(&[(p.prepare(), q.prepare())])).unwrap();
    assert_eq!(Bls12_377::pairing(p, q), expected);
}

#[test]
fn test_bls12_377_miller_loop_lanes() {
    let mut rng = TestRng::default();
    let pairs = prepared_pairs(&mut rng, 2, &[], &[]);
    let prepared: Vec<_> = pairs.iter().map(|(p, q)| (p, q)).collect();
    let lines: Vec<Pair<'_>> = pairs.iter().map(|(p, q)| ([&p.0.x, &p.0.y], q.ell_coeffs.as_slice())).collect();

    // The hook and the scalar path give the value of the loop.
    let expected = miller_loop_of_pairs_reference(&pairs);
    assert_eq!(Bls12_377Parameters::miller_loop_fp12(&prepared), expected);
    assert_eq!(Bls12_377::miller_loop_scalar(&prepared), expected);

    // The lanes run exactly where they are supported.
    let run = |lines: &[Pair<'_>]| snarkvm_fields::ifma::miller_loop_fp12(&Fq12::one(), Bls12_377Parameters::X, lines);
    let in_lanes = lanes_supported().then_some(expected);
    assert_eq!(run(&lines), in_lanes);

    // Coefficients past the ones the loop takes are not read; with one fewer, the lanes decline.
    let coefficients = &pairs[1].1.ell_coeffs;
    let mut long = coefficients.clone();
    long.push((Fq2::rand(&mut rng), Fq2::rand(&mut rng), Fq2::rand(&mut rng)));
    assert_eq!(run(&[lines[0], (lines[1].0, &long)]), in_lanes);
    let short = &coefficients[..coefficients.len() - 1];
    assert_eq!(run(&[lines[0], (lines[1].0, short)]), None);
}

#[test]
#[should_panic(expected = "called `Option::unwrap()` on a `None` value")]
fn test_miller_loop_short_coefficients() {
    let p = G1Affine::prime_subgroup_generator().prepare();
    let mut q = G2Affine::prime_subgroup_generator().prepare();
    q.ell_coeffs.pop();
    let _ = Bls12_377::miller_loop(std::iter::once((&p, &q)));
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
