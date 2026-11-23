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
        msm_lane_outputs,
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
            fp256_scalar_path_test,
            fp384_edge_values,
            fp384_inverse_test,
            fp384_scalar_path_test,
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
    Compress,
    Validate,
    biginteger::{BigInteger, BigInteger256, BigInteger384},
    rand::{TestRng, Uniform},
    serialize::{CanonicalDeserialize, CanonicalSerialize},
};

use rand::RngExt;
use std::{
    cmp::Ordering,
    ops::{AddAssign, Mul, MulAssign, SubAssign},
    str::FromStr,
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
fn test_bls12_377_fr_scalar_path() {
    fp256_scalar_path_test::<FrParameters>(&mut TestRng::default());
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
    for i in [2, 4, 8, 12] {
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

/// Returns `n` copies of the element whose Montgomery limbs are `[2^64 - 19, 0, 0, 0]`, and `n` copies
/// of the one whose Montgomery limbs are `p - 1`, which bring the accumulator of `sum_of_products`
/// close to its bound in the first round.
fn fr_sum_of_products_edge(n: usize) -> (Vec<Fr>, Vec<Fr>) {
    let mut top = FrParameters::MODULUS;
    top.sub_noborrow(&BigInteger256::from(1u64));
    let small = BigInteger256::new([u64::MAX - 18, 0, 0, 0]);
    (vec![snarkvm_fields::field!(Fr, small); n], vec![snarkvm_fields::field!(Fr, top); n])
}

/// `fr_sum_of_products_edge` for `Fq`.
fn fq_sum_of_products_edge(n: usize) -> (Vec<Fq>, Vec<Fq>) {
    let mut top = FqParameters::MODULUS;
    top.sub_noborrow(&BigInteger384::from(1u64));
    let small = BigInteger384::new([u64::MAX - 18, 0, 0, 0, 0, 0]);
    (vec![snarkvm_fields::field!(Fq, small); n], vec![snarkvm_fields::field!(Fq, top); n])
}

#[test]
fn test_fr_sum_of_products_at_limit() {
    let (a, b) = fr_sum_of_products_edge(12);
    assert_eq!(Fr::sum_of_products(&a, &b), a.into_iter().zip(b).map(|(a, b)| a * b).sum());
}

#[test]
#[should_panic(expected = "too many terms")]
fn test_fr_sum_of_products_above_limit() {
    let (a, b) = fr_sum_of_products_edge(13);
    let _ = Fr::sum_of_products(&a, &b);
}

#[test]
fn test_fr_sum_of_products_shorter_slice_sets_the_terms() {
    let (a, b) = fr_sum_of_products_edge(13);
    let expected = a[..12].iter().zip(&b).map(|(a, b)| *a * b).sum();
    assert_eq!(Fr::sum_of_products(&a[..12], &b), expected);
    assert_eq!(Fr::sum_of_products(&a, &b[..12]), expected);
}

#[test]
fn test_fq_sum_of_products_shorter_slice_sets_the_terms() {
    let (a, b) = fq_sum_of_products_edge(152);
    let expected = a[..151].iter().zip(&b).map(|(a, b)| *a * b).sum();
    assert_eq!(Fq::sum_of_products(&a[..151], &b), expected);
    assert_eq!(Fq::sum_of_products(&a, &b[..151]), expected);
}

#[test]
fn test_fq_sum_of_products_at_limit() {
    let (a, b) = fq_sum_of_products_edge(151);
    assert_eq!(Fq::sum_of_products(&a, &b), a.into_iter().zip(b).map(|(a, b)| a * b).sum());
}

#[test]
#[should_panic(expected = "too many terms")]
fn test_fq_sum_of_products_above_limit() {
    let (a, b) = fq_sum_of_products_edge(152);
    let _ = Fq::sum_of_products(&a, &b);
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
fn test_fq2_sqrt_of_nonresidue() {
    // u^2 = (NONRESIDUE, 0), and NONRESIDUE is a QNR in Fq.
    let u = Fq2::new(Fq::zero(), Fq::one());
    let a = Fq2::new(Fq2Parameters::NONRESIDUE, Fq::zero());
    assert_eq!(u.square(), a);
    assert!(Fq2Parameters::NONRESIDUE.legendre().is_qnr());

    let root = a.sqrt().expect("(NONRESIDUE, 0) is a square in Fq2");
    assert!(root == u || root == -u);
}

#[test]
fn test_fq2_sqrt_of_purely_imaginary_squares() {
    let mut rng = TestRng::default();

    for _ in 0..1000 {
        // (0, d)^2 = (NONRESIDUE * d^2, 0), whose first coordinate is a QNR in Fq for nonzero d.
        let elem = Fq2::new(Fq::zero(), Fq::rand(&mut rng));
        let root = elem.square().sqrt().expect("a square has a square root");
        assert!(root == elem || root == -elem);
    }
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

/// Projects a nonzero `f` into the cyclotomic subgroup via `f^((p^6 - 1)(p^2 + 1))`.
fn fq12_cyclotomic_project(f: &Fq12) -> Option<Fq12> {
    let f_inv = f.inverse()?;
    let mut r = *f;
    r.conjugate();
    r = fq12_schoolbook(&r, &f_inv);
    let mut s = r;
    s.frobenius_map(2);
    Some(fq12_schoolbook(&s, &r))
}

/// Returns `f^((p^6 - 1)(p^2 + 1))` for a random `f`: the easy part of the final exponentiation,
/// which lies in the cyclotomic subgroup.
fn fq12_cyclotomic_element(rng: &mut TestRng) -> Fq12 {
    // A random element is nonzero.
    fq12_cyclotomic_project(&Fq12::rand(rng)).unwrap()
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
        vec![0x0002_aaaa_aaaa_0000],
        vec![0x0002_aaaa_aaaa_0001],
        vec![u64::MAX],
        vec![1 << 63],
        vec![0, 1],
        vec![u64::MAX, u64::MAX],
        vec![5, 0, 0],
        x.to_vec(),
    ];
    exponents.extend((0..20).map(|_| vec![rng.random::<u64>() >> rng.random_range(0..64)]));
    exponents.extend((0..5).map(|_| vec![rng.random::<u64>(), rng.random::<u64>()]));

    let raw_inputs = fq12_cyclotomic_inputs(&mut rng);

    // The IFMA lane program evaluates the uncompressed Granger-Scott chain, so where it runs it
    // matches `fq12_cyclotomic_exp_reference` on arbitrary limb-edge inputs as well.
    if lanes_supported() {
        for (i, x) in raw_inputs.iter().enumerate() {
            // Every exponent for a subset of the inputs, and a random one for the rest.
            let chosen = if i % 25 == 0 {
                &exponents[..]
            } else {
                let j = rng.random_range(0..exponents.len());
                &exponents[j..=j]
            };
            for exp in chosen {
                let c = x.cyclotomic_exp(exp);
                assert_eq!(c, fq12_cyclotomic_exp_reference(x, exp), "{x} ^ {exp:?}");
                assert!(fq12_coefficients(&c).all(|x| x.is_valid()), "{x} ^ {exp:?}");
            }
        }
    }

    // On the cyclotomic subgroup (and boundary elements `0` and `1`), both the IFMA Granger-Scott
    // lanes and the Karabina compressed scalar path match `fq12_cyclotomic_exp_reference` and `pow`.
    let mut cyclotomic_inputs = vec![Fq12::zero(), Fq12::one()];
    cyclotomic_inputs.extend(raw_inputs.iter().take(80).filter_map(fq12_cyclotomic_project));
    cyclotomic_inputs.extend((0..64).map(|_| fq12_cyclotomic_element(&mut rng)));

    for (i, a) in cyclotomic_inputs.iter().enumerate() {
        let chosen = if i % 10 == 0 {
            &exponents[..]
        } else {
            let j = rng.random_range(0..exponents.len());
            &exponents[j..=j]
        };
        for exp in chosen {
            let expected = fq12_cyclotomic_exp_reference(a, exp);
            let c = a.cyclotomic_exp(exp);
            let s = a.cyclotomic_exp_scalar(exp);
            assert_eq!(c, expected, "{a} ^ {exp:?}");
            assert_eq!(s, expected, "{a} ^ {exp:?} by the scalar path");
            assert_eq!(a.pow(exp), expected, "{a} ^ {exp:?} by pow");
            assert!(fq12_coefficients(&c).all(|x| x.is_valid()), "{a} ^ {exp:?}");
            assert!(fq12_coefficients(&s).all(|x| x.is_valid()), "{a} ^ {exp:?} by the scalar path");
        }
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
fn test_g2_from_x_coordinate_with_imaginary_y() {
    let fq = |s: &str| Fq::from_str(s).expect("the literal is a canonical Fq element");
    let x = Fq2::new(
        fq(
            "80453520267516129593051327224590975620090736720770429508396740963130851304924183393465498314279415142214774756387",
        ),
        fq(
            "208004220316808651132818824654517262152313755570600949882521492435178790612687529516238401457775909276130267505865",
        ),
    );

    // x^3 + b = (c0, 0) with c0 a QNR in Fq, so every y on the curve is purely imaginary.
    let rhs = x.square() * x + Bls12_377G2Parameters::WEIERSTRASS_B;
    assert!(rhs.c1.is_zero());
    assert!(rhs.c0.legendre().is_qnr());

    let p = G2Affine::from_x_coordinate(x, true).expect("x has an on-curve point");
    assert!(p.y.c0.is_zero());
    assert!(p.is_on_curve());
    assert_eq!(G2Affine::from_x_coordinate(x, false), Some(-p));

    // The point is outside the prime-order subgroup, so only an unchecked decode accepts it.
    let mut bytes = Vec::new();
    p.serialize_with_mode(&mut bytes, Compress::Yes).unwrap();
    assert_eq!(G2Affine::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::No).unwrap(), p);
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

/// Returns the `Fq` whose Montgomery limbs are `limbs`, which must be below the modulus.
fn fq_from_limbs(limbs: [u64; 6]) -> Fq {
    let fq = snarkvm_fields::field!(Fq, BigInteger384(limbs));
    assert!(fq.is_valid());
    fq
}

/// Returns `Fq` values at the edges of the Montgomery limbs.
fn fq_limb_edges() -> [Fq; 9] {
    let p = FqParameters::MODULUS.0;
    let mut below_p = p;
    below_p[0] -= 1;
    [
        Fq::zero(),
        Fq::one(),
        -Fq::one(),
        fq_from_limbs([1, 0, 0, 0, 0, 0]),
        fq_from_limbs([2, 0, 0, 0, 0, 0]),
        fq_from_limbs(below_p),
        fq_from_limbs([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, p[5] - 1]),
        fq_from_limbs([0, 0, 0, 0, 0, p[5] - 1]),
        fq_from_limbs([u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0]),
    ]
}

#[test]
fn test_bls12_377_fq_scalar_path() {
    fp384_scalar_path_test::<FqParameters>(&mut TestRng::default());
}

/// Checks that `Fq::sum_of_products` of `N` terms returns the limbs of the Rust body.
fn fq_sum_of_products_matches_scalar<const N: usize>() {
    let check = |a: [Fq; N], b: [Fq; N]| {
        let sum = Fq::sum_of_products(&a, &b);
        let scalar = Fq::sum_of_products_scalar(&a, &b);
        assert_eq!((sum.0).0, (scalar.0).0, "{a:?} . {b:?}");
    };
    // Every choice of limb edges for the `2 N` operands, as the base-9 digits of `i`.
    let edges = fq_limb_edges();
    for i in 0..edges.len().pow(2 * N as u32) {
        let digit = |k: usize| edges[i / edges.len().pow(k as u32) % edges.len()];
        check(std::array::from_fn(digit), std::array::from_fn(|k| digit(N + k)));
    }
    let mut rng = TestRng::default();
    let edges = fp384_edge_values::<FqParameters>();
    for _ in 0..400_000 {
        let mut pick = || fq_edge_or_random(&mut rng, &edges);
        check(std::array::from_fn(|_| pick()), std::array::from_fn(|_| pick()));
    }
    for _ in 0..200_000 {
        let mut pick = || Fq::rand(&mut rng);
        check(std::array::from_fn(|_| pick()), std::array::from_fn(|_| pick()));
    }
}

#[test]
fn test_fq_sum_of_products_takes_the_shorter_length() {
    let mut rng = TestRng::default();
    let a: [Fq; 4] = std::array::from_fn(|_| Fq::rand(&mut rng));
    let b: [Fq; 4] = std::array::from_fn(|_| Fq::rand(&mut rng));
    for i in 0..=4 {
        for j in 0..=4 {
            let terms = i.min(j);
            let expected = Fq::sum_of_products_scalar(&a[..terms], &b[..terms]);
            assert_eq!(Fq::sum_of_products(&a[..i], &b[..j]), expected, "{i} and {j} elements");
        }
    }
}

#[test]
fn test_fq_sum_of_products_matches_scalar() {
    fq_sum_of_products_matches_scalar::<2>();
}

#[test]
fn test_fq_sum_of_three_products_matches_scalar() {
    fq_sum_of_products_matches_scalar::<3>();
}

/// Returns `sum_j 16^(n - 1 - j) (digits[j][0] P + digits[j][1] phi(P))` by double-and-add.
fn glv_digits_reference(point: &G1Affine, digits: &[[i8; 2]]) -> G1Projective {
    let phi = Bls12_377G1Parameters::glv_endomorphism(*point);
    let mut acc = G1Projective::zero();
    for [d1, d2] in digits {
        for _ in 0..4 {
            acc.double_in_place();
        }
        for (d, base) in [(d1, point), (d2, &phi)] {
            let term = base.mul_bits(BitIteratorBE::new_without_leading_zeros([d.unsigned_abs() as u64]));
            acc += if *d < 0 { -term } else { term };
        }
    }
    acc
}

/// Returns the signed 4-bit windows of `k`, the most significant first.
fn signed_windows_reference(k: i128) -> Vec<i8> {
    let (mut m, mut windows) = (k.unsigned_abs(), vec![]);
    while m != 0 {
        let w = (m & 15) as i8;
        let d = if w >= 8 { w - 16 } else { w };
        windows.push(if k < 0 { -d } else { d });
        m = (m as i128 - d as i128) as u128 >> 4;
    }
    windows.reverse();
    windows
}

/// Returns the digits of `ifma::glv_mul_8` for `lanes[l] = (a, b)` in lane `l`: `a` in the first half
/// and `b` in the second, each the most significant first and aligned at the end.
fn glv_lane_digits(lanes: &[(Vec<i8>, Vec<i8>); 8]) -> Vec<[[i8; 8]; 2]> {
    let len = lanes.iter().map(|(a, b)| a.len().max(b.len())).max().unwrap_or(0);
    let mut digits = vec![[[0; 8]; 2]; len];
    for (lane, (a, b)) in lanes.iter().enumerate() {
        for (half, windows) in [a, b].into_iter().enumerate() {
            for (i, d) in windows.iter().enumerate() {
                digits[len - windows.len() + i][half][lane] = *d;
            }
        }
    }
    digits
}

/// The eigenvalue of `phi` on G1, as a signed integer: `phi(P) = LAMBDA P`.
fn glv_lambda() -> i128 {
    use crate::templates::bls12::Bls12Parameters;
    let x = crate::bls12_377::Bls12_377Parameters::X[0] as i128;
    let g = G1Affine::prime_subgroup_generator();
    // The two roots of `t^2 + t + 1` mod r are `x^2 - 1` and `-x^2`.
    let lambda = x * x - 1;
    let words = [lambda as u64, (lambda >> 64) as u64];
    let phi = Bls12_377G1Parameters::glv_endomorphism(g);
    if g.mul_bits(BitIteratorBE::new_without_leading_zeros(words)) == phi.to_projective() { lambda } else { -(x * x) }
}

/// The point `(-1, 0)` of order 2 and `(0, 1)` of order 3 of `y^2 = x^3 + 1`, outside G1.
fn g1_small_order_points() -> [G1Affine; 2] {
    [G1Affine::new(-Fq::one(), Fq::zero(), false), G1Affine::new(Fq::zero(), Fq::one(), false)]
}

/// Returns 8 random points of G1.
fn random_g1_slot(rng: &mut TestRng) -> [G1Affine; 8] {
    std::array::from_fn(|_| G1Affine::rand(rng))
}

/// `check_fq_glv_mul_8_slots` with one slot, whose lane `l` takes the digits `lanes[l]`.
fn check_fq_glv_mul_8_one_slot(points: &[G1Affine; 8], lanes: &[(Vec<i8>, Vec<i8>); 8], exceptional: u8) {
    check_fq_glv_mul_8_slots(std::slice::from_ref(points), &glv_lane_digits(lanes), exceptional);
}

#[test]
fn test_fq_glv_mul_8() {
    let mut rng = TestRng::default();
    let random_digit = |rng: &mut TestRng| rng.random_range(-8i8..=8);

    // No digits: the sum is the point at infinity in every lane.
    check_fq_glv_mul_8_slots(std::slice::from_ref(&random_g1_slot(&mut rng)), &[], 0);

    // Random digits, with lanes that start at different windows and in either half.
    for _ in 0..100 {
        let points = random_g1_slot(&mut rng);
        let len = rng.random_range(1..40);
        let lanes = std::array::from_fn(|_| {
            let (la, lb) = (rng.random_range(0..=len), rng.random_range(0..=len));
            ((0..la).map(|_| random_digit(&mut rng)).collect(), (0..lb).map(|_| random_digit(&mut rng)).collect())
        });
        check_fq_glv_mul_8_one_slot(&points, &lanes, 0);
    }

    // Digits of 8 and -8 in every window, and a single digit of 1 at the end (a scalar of 1).
    let lanes: [(Vec<i8>, Vec<i8>); 8] = std::array::from_fn(|lane| match lane {
        0 => (vec![8; 33], vec![-8; 33]),
        1 => (vec![-8; 33], vec![8; 33]),
        2 => (vec![1], vec![]),
        3 => (vec![], vec![1]),
        4 => (vec![-1], vec![0]),
        5 => (vec![8, 0, 0, -8], vec![0, 0, 0, 0]),
        6 => (vec![0; 33], vec![0; 33]),
        _ => (vec![7, -7, 1, 0, 3], vec![-1, 2, -8, 8, 0]),
    });
    check_fq_glv_mul_8_one_slot(&random_g1_slot(&mut rng), &lanes, 0);

    // The cases the formulas exclude. `LAMBDA P = phi(P)`, so the digits of `(LAMBDA, 1)` add
    // `phi(P)` to itself at the last window, and those of `(LAMBDA, -1)` add `-phi(P)` to `phi(P)`.
    // With one more window, the ladder goes on from that sum. The points of order 2 and 3, and
    // `(0, 1)`, the coordinates of the point at infinity, meet them in the table.
    let lambda = signed_windows_reference(glv_lambda());
    let then = |mut a: Vec<i8>, b: i8| {
        let mut b = vec![0; a.len() - 1].into_iter().chain([b]).collect::<Vec<_>>();
        a.push(3);
        b.push(5);
        (a, b)
    };
    let mut points = random_g1_slot(&mut rng);
    let [order_2, order_3] = g1_small_order_points();
    (points[4], points[5], points[6]) = (order_2, order_3, G1Affine::zero());
    let lanes: [(Vec<i8>, Vec<i8>); 8] = std::array::from_fn(|lane| match lane {
        0 => (lambda.clone(), vec![1]),
        1 => (lambda.clone(), vec![-1]),
        2 => then(lambda.clone(), 1),
        3 => then(lambda.clone(), -1),
        4..=6 => (vec![5, 1], vec![3]),
        _ => (vec![2, -3], vec![1, 4]),
    });
    check_fq_glv_mul_8_one_slot(&points, &lanes, 0b0111_1111);
    // The same cases with the exceptional lanes moved, so each lane meets one.
    let points: [G1Affine; 8] = std::array::from_fn(|lane| points[(lane + 3) % 8]);
    let lanes: [(Vec<i8>, Vec<i8>); 8] = std::array::from_fn(|lane| lanes[(lane + 3) % 8].clone());
    check_fq_glv_mul_8_one_slot(&points, &lanes, 0b1110_1111);
}

/// A random scalar below 2^168, as the sponge squeezes for a challenge.
fn short_scalar(rng: &mut TestRng) -> Fr {
    // The top word is zero and the third is shifted to below 2^40, so the integer is below
    // 2^168 < r.
    Fr::from_bigint(BigInteger256::new([rng.random(), rng.random(), rng.random::<u64>() >> 24, 0])).unwrap()
}

/// A random G1 point with a scalar below 2^168, a product of two such scalars, or a full scalar.
fn random_g1_term(rng: &mut TestRng) -> (G1Affine, Fr) {
    let base = G1Projective::rand(rng).to_affine();
    let scalar = match rng.random_range(0..3) {
        0 => short_scalar(rng),
        1 => short_scalar(rng) * short_scalar(rng),
        _ => Fr::rand(rng),
    };
    (base, scalar)
}

/// The edge terms: the generator with the scalars zero, one, minus one and two; the point at
/// infinity; the generator with a random scalar, and its negation with another.
fn g1_edge_terms(rng: &mut TestRng) -> [(G1Affine, Fr); 8] {
    let g = G1Affine::prime_subgroup_generator();
    [
        (g, Fr::zero()),
        (g, Fr::one()),
        (g, -Fr::one()),
        (g, Fr::from(2u64)),
        (G1Affine::zero(), Fr::rand(rng)),
        (G1Affine::zero(), Fr::zero()),
        (g, Fr::rand(rng)),
        (-g, Fr::rand(rng)),
    ]
}

/// Checks `ifma::glv_mul_8` with one slot per entry of `points` against the sum over the slots of
/// `glv_digits_reference`, in every lane. The lanes in `exceptional` must return `Z = 0`.
fn check_fq_glv_mul_8_slots(points: &[[G1Affine; 8]], digits: &[[[i8; 8]; 2]], exceptional: u8) {
    let coordinates: Vec<_> = points.iter().map(|slot| slot.map(|p| [p.x, p.y])).collect();
    // `digits` holds the windows most significant first, with each window's slots in order;
    // `glv_mul_8` takes each slot's windows, the least significant first.
    let per_slot: Vec<Vec<_>> =
        (0..points.len()).map(|k| digits.chunks_exact(points.len()).rev().map(|window| window[k]).collect()).collect();
    let slices: Vec<_> = per_slot.iter().map(Vec::as_slice).collect();
    let out = snarkvm_fields::ifma::glv_mul_8(&coordinates, &Bls12_377G1Parameters::PHI, &slices);
    assert_eq!(out.is_some(), lanes_supported());
    let Some(out) = out else {
        return;
    };
    let slots = points.len();
    for (lane, [x, y, z]) in out.into_iter().enumerate() {
        let expected: G1Projective = (0..slots)
            .map(|k| {
                let lane_digits: Vec<[i8; 2]> =
                    digits.chunks_exact(slots).map(|w| [w[k][0][lane], w[k][1][lane]]).collect();
                glv_digits_reference(&points[k][lane], &lane_digits)
            })
            .sum();
        if exceptional >> lane & 1 == 1 || expected.is_zero() {
            assert!(z.is_zero(), "{slots} slots, lane {lane}: Z is not zero");
        } else {
            assert!(!z.is_zero(), "{slots} slots, lane {lane}: Z is zero");
            assert_eq!(G1Projective::new(x, y, z), expected, "{slots} slots, lane {lane}");
        }
    }
}

#[test]
fn test_fq_glv_mul_8_slots() {
    let mut rng = TestRng::default();

    // Random digits, with lanes and slots that start at different windows and in either half.
    for slots in 1..=5 {
        check_fq_glv_mul_8_slots(&vec![random_g1_slot(&mut rng); slots], &vec![[[0; 8]; 2]; 2 * slots], 0);
        for _ in 0..20 {
            let points: Vec<_> = (0..slots).map(|_| random_g1_slot(&mut rng)).collect();
            let len = rng.random_range(1..36);
            let mut digits = vec![[[0i8; 8]; 2]; len * slots];
            for d in digits.iter_mut().flatten().flatten() {
                // Leading zeros in about a third of the windows.
                if rng.random_range(0..3) > 0 {
                    *d = rng.random_range(-8i8..=8);
                }
            }
            check_fq_glv_mul_8_slots(&points, &digits, 0);
        }
    }

    // The cases the formulas exclude, between slots: in lane 0 slot 1 adds `3 P` to the `3 P` of
    // slot 0, and in lane 1 `-3 P`; in lanes 2 and 3 the table of slot 1 meets a point of order 2
    // and the point at infinity, though its digits are zero. Lanes 4 to 7 hold random digits.
    let [order_2, _] = g1_small_order_points();
    let mut points = vec![random_g1_slot(&mut rng), random_g1_slot(&mut rng)];
    points[1][0] = points[0][0];
    points[1][1] = -points[0][1];
    points[1][2] = order_2;
    points[1][3] = G1Affine::zero();
    // Three windows of two slots: `digits[2 w + k][half][lane]`.
    let mut digits = vec![[[0i8; 8]; 2]; 2 * 3];
    digits[0][0][..4].fill(3);
    digits[1][0][..2].fill(3);
    for (w, window) in digits.chunks_exact_mut(2).enumerate() {
        window[0][0][4..].fill(3);
        window[0][1][4..].fill(-5);
        window[1][1][4..].fill([1, -8, 7][w]);
    }
    check_fq_glv_mul_8_slots(&points, &digits, 0b0000_1111);
}

#[test]
fn test_g1_msm_lanes() {
    let mut rng = TestRng::default();
    let reference = |msm: &[(G1Affine, Fr)]| msm.iter().map(|(base, scalar)| *base * *scalar).sum::<G1Projective>();
    let check = |msms: &[Vec<(G1Affine, Fr)>]| {
        let slices: Vec<&[(G1Affine, Fr)]> = msms.iter().map(Vec::as_slice).collect();
        let nonzero = msms.iter().flatten().filter(|(base, scalar)| !base.is_zero() && !scalar.is_zero()).count();
        match G1Affine::msm_lanes(&slices) {
            None => assert!(!lanes_supported() || nonzero < 2, "{nonzero} terms"),
            Some(sums) => {
                assert!(lanes_supported() && nonzero >= 2, "{nonzero} terms");
                assert_eq!(sums.len(), msms.len());
                for (i, (msm, sum)) in msms.iter().zip(&sums).enumerate() {
                    assert_eq!(*sum, reference(msm), "MSM {i} of {} terms", msm.len());
                }
            }
        }
    };
    let random_msm = |rng: &mut TestRng, n: usize| (0..n).map(|_| random_g1_term(rng)).collect::<Vec<_>>();

    // One MSM of each size up to 40, and sizes that `lane_calls` splits.
    for n in (0..=40).chain([64, 65, 100]) {
        check(&[random_msm(&mut rng, n)]);
    }
    // Several MSMs at once: the sizes a check runs, more MSMs than lanes, and random sizes.
    for sizes in
        [&[2, 5][..], &[13, 3, 1], &[17, 2, 1, 1, 2, 5], &[30, 3, 2, 2, 2, 5], &[1, 1], &[1; 9], &[0, 3, 0], &[1; 20]]
    {
        check(&sizes.iter().map(|n| random_msm(&mut rng, *n)).collect::<Vec<_>>());
    }
    for _ in 0..30 {
        let k = rng.random_range(1..=10);
        check(
            &(0..k)
                .map(|_| {
                    let n = rng.random_range(0..=12);
                    random_msm(&mut rng, n)
                })
                .collect::<Vec<_>>(),
        );
    }

    // The edge terms among random terms, at every offset.
    let edges = g1_edge_terms(&mut rng);
    for start in 0..edges.len() {
        for n in [2, 3, 5, 8, 11, 13, 25] {
            let mut msm = random_msm(&mut rng, n);
            for (i, edge) in edges.iter().cycle().skip(start).take(n.min(edges.len())).enumerate() {
                if i % 2 == 0 {
                    msm[i] = *edge;
                }
            }
            check(&[msm.clone(), random_msm(&mut rng, 3)]);
            check(&[msm]);
        }
    }
    for n in [2, 7, 16] {
        check(&[edges.iter().copied().cycle().take(n).collect()]);
    }

    // A base and its negation with the same scalar in one lane. With 16 terms and 4 streams per
    // lane, terms `t` and `t + 8` share a lane, and the second cancels the first; with 2 terms and
    // one stream, a base and the same base.
    let mut msm = random_msm(&mut rng, 16);
    for t in 0..8 {
        msm[t + 8] = (-msm[t].0, msm[t].1);
    }
    check(&[msm.clone()]);
    assert!(reference(&msm).is_zero());
    let term = random_g1_term(&mut rng);
    check(&[vec![term, term]]);
    check(&[vec![term, (-term.0, term.1)]]);

    // The lanes return other projective coordinates than the scalar path, so this checks that
    // `msm_lanes` runs them exactly where the lanes are supported, and that no lane of these
    // random terms has `Z = 0`.
    for n in [2, 5, 13, 25] {
        let msm = random_msm(&mut rng, n);
        match G1Affine::msm_lanes(&[&msm]) {
            Some(sums) => {
                assert!(lanes_supported() && sums[0].z != reference(&msm).z, "{n} terms");
                let outputs = msm_lane_outputs(&[&msm]).unwrap();
                assert!(outputs.iter().flatten().all(|(sum, [.., z])| sum.is_none() || !z.is_zero()), "{n} terms");
            }
            None => assert!(!lanes_supported(), "{n} terms"),
        }
    }
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "prime-order subgroup")]
fn test_g1_msm_lanes_rejects_a_base_outside_g1() {
    let [outside, _] = g1_small_order_points();
    let _ = G1Affine::msm_lanes(&[&[(outside, Fr::one()), (outside, Fr::one())]]);
}

#[test]
fn test_bls12_377_cyclotomic_karabina_edge_exponents() {
    let mut rng = TestRng::default();

    let exponents: &[&[u64]] = &[
        &[],
        &[0u64],
        &[0u64, 0u64],
        &[1u64],
        &[2u64],
        &[3u64],
        &[1u64 << 46],
        &[1u64 << 63],
        &[0u64, 1u64],
        &[5u64, 0u64, 0u64],
        // 17 set bits with bit 0 clear (regression test for the 16-slot batch boundary).
        &[0x0002_aaaa_aaaa_0000u64],
        // 18 set bits with bit 0 set (crosses the 16-slot batch boundary into a second batch).
        &[0x0002_aaaa_aaaa_0001u64],
        &[0xaaaa_aaaa_aaaa_aaabu64],
        Bls12_377Parameters::X,
        &[u64::MAX],
        &[u64::MAX, u64::MAX],
    ];

    for _ in 0..24 {
        let g = fq12_cyclotomic_element(&mut rng);
        assert_eq!(g.cyclotomic_square(), g.square());

        for &exp in exponents {
            let expected = g.pow(exp);
            assert_eq!(g.cyclotomic_exp(exp), expected);
            assert_eq!(g.cyclotomic_exp_scalar(exp), expected);
        }
    }

    // Boundary elements (`1` and `0`, where `z2 == z3 == 0`).
    for elem in [Fq12::one(), Fq12::zero()] {
        for &exp in exponents {
            let expected = elem.pow(exp);
            assert_eq!(elem.cyclotomic_exp(exp), expected);
            assert_eq!(elem.cyclotomic_exp_scalar(exp), expected);
        }
    }
}

/// Tests Karabina's secondary `z2 == 0, z3 != 0` decompression branch (`gnark-crypto#874`) on an
/// explicit nontrivial cyclotomic element `g in G_{Phi_6(q^2)}` constructed in polynomial time.
///
/// Setting `z2 = 0` in Karabina's cyclotomic equations and `g * conj(g) = 1` defines the genus-0
/// rational curve `u * z3^3 - 6 * z3 * z4 + 8 * z4^3 = 0` over `Fq2` (`u^2 = -5`). Parameterizing
/// by `z3 = lam * z4` with `lam = 1 + u` (`D = u * lam^3 + 8 = 10 + 6 * u != 0`) gives:
///   `z0 = (u * lam^3 - 4) / D`, `z1 = 4 * tau / D`, `z2 = 0`,
///   `z3 = 6 * lam^2 / D`, `z4 = 6 * lam / D`, `z5 = 2 * lam * tau / D`,
/// where `tau^2 = 3 * (u * lam^3 - 1) / u` in `Fq2`.
///
/// Raising `g` to `2^-46 mod (q^4 - q^2 + 1)` yields `h_x in G_{Phi_6(q^2)}` with `h_x.c1.c0 != 0`
/// whose 46th squaring lands directly on `g` (`z2 == 0, z3 != 0`) at bit 46 of `Bls12_377Parameters::X`.
#[test]
fn test_bls12_377_cyclotomic_karabina_z2_zero_z3_nonzero() {
    // Each literal word array is strictly below `FqParameters::MODULUS`, so `from_bigint` returns `Some`.
    let fq = |w: [u64; 6]| Fq::from_bigint(BigInteger384(w)).unwrap();
    let fq2 = |c0: [u64; 6], c1: [u64; 6]| Fq2::new(fq(c0), fq(c1));

    let u = Fq2::new(Fq::zero(), Fq::one());
    let lam = Fq2::new(Fq::one(), Fq::one());
    let lam2 = lam.square();
    let ulam3 = Fq6Parameters::mul_fp2_by_nonresidue(&(lam2 * lam));
    let tau = fq2(
        [
            0xcef3249d486c5423,
            0x30f38d622f94f9f8,
            0x1207392bc4d9b5c6,
            0x11d210e43fae9ab5,
            0xca63c5b50553ea97,
            0x019dbaeaaeed10de,
        ],
        [
            0x74a5e079a09ff796,
            0x7989676925fbe15b,
            0x04e0950a48db7621,
            0x40f31fe55a723ed4,
            0x9b14b874bac4b587,
            0x017da7dad854be67,
        ],
    );
    // `u = (0, 1)` is nonzero in `Fq2`, so `u.inverse()` returns `Some`.
    assert_eq!(tau.square(), Fq2::from(3u64) * (ulam3 - Fq2::one()) * u.inverse().unwrap());

    // `u * lam^3 + 8 = 10 + 6 * u != 0`, so `inverse()` returns `Some`.
    let d_inv = (ulam3 + Fq2::from(8u64)).inverse().unwrap();
    let z0 = (ulam3 - Fq2::from(4u64)) * d_inv;
    let z1 = Fq2::from(4u64) * tau * d_inv;
    let z2 = Fq2::zero();
    let z3 = Fq2::from(6u64) * lam2 * d_inv;
    let z4 = Fq2::from(6u64) * lam * d_inv;
    let z5 = Fq2::from(2u64) * lam * tau * d_inv;
    let g = Fq12::new(Fq6::new(z0, z4, z3), Fq6::new(z2, z1, z5));

    // Verify `g != +-1`, `z2 == 0`, `z3 != 0`, and membership in `G_{Phi_6(q^2)}` (`g^(q^4 - q^2 + 1) == 1`).
    assert_ne!(g, Fq12::one());
    assert_ne!(g, -Fq12::one());
    assert!(g.c1.c0.is_zero());
    assert!(!g.c0.c2.is_zero());
    let assert_in_cyclotomic_subgroup = |el: Fq12| {
        let mut conj = el;
        conj.conjugate();
        assert_eq!(el * conj, Fq12::one());
        let mut frob2 = el;
        frob2.frobenius_map(2);
        let mut frob4 = el;
        frob4.frobenius_map(4);
        assert_eq!(frob4 * el, frob2);
    };
    assert_in_cyclotomic_subgroup(g);

    // `h_x = g^(2^-46 mod (q^4 - q^2 + 1))` in `G_{Phi_6(q^2)}`: its 45th squaring `h1` satisfies
    // `h1^2 == g`, and its 46th squaring hits `g` (`z2 == 0, z3 != 0`) at bit 46 of `Bls12_377Parameters::X`.
    let h_x = Fq12::new(
        Fq6::new(
            fq2(
                [
                    0x9a4b3ee0bdca69fa,
                    0x0ba6a502d9c9ee79,
                    0xa309cffe3582708f,
                    0x6e4f4442a1ed4e04,
                    0xaa4ac4a6b4562ae0,
                    0x00cfe3a5190fc4c7,
                ],
                [
                    0xbb260d6a66adf90d,
                    0xfb347ce1899cca4b,
                    0xc64f68c01010409c,
                    0x07a0f266d23c8e97,
                    0x094dd828c7bf97c0,
                    0x00429d4f6ab17474,
                ],
            ),
            fq2(
                [
                    0xbaf90c0015a1425e,
                    0x5aabf182e1439262,
                    0x78c1219d8cadaa6a,
                    0xc754ec97df7ff2e5,
                    0x841ddfb643bfceba,
                    0x01905f33bc82d032,
                ],
                [
                    0x5843aacf409b7f9f,
                    0x974631225aeaa8a5,
                    0x1e2da5c7e5a4a82c,
                    0x20ca181cfe53dc6d,
                    0x3342179937dbf9e0,
                    0x004c71095edae832,
                ],
            ),
            fq2(
                [
                    0x9653c98adc370388,
                    0xaa868d2e0906f0a0,
                    0x6a7acc19d5978006,
                    0xa1d1b56b0486423d,
                    0x6ae879a673754853,
                    0x00dcffe7c75b6ede,
                ],
                [
                    0x8371d0b811e966b6,
                    0x3c17596e8651f95f,
                    0xd22e215be9f5742f,
                    0x2890481e1bec6e36,
                    0x22bee49aac9ef567,
                    0x00f607021cb11bbb,
                ],
            ),
        ),
        Fq6::new(
            fq2(
                [
                    0x24f89b07e2585b2e,
                    0x590fe57357891a3c,
                    0x3e10f8ee2a7f5dfa,
                    0x727304625b6a4d8a,
                    0x05bbb406d6dd995c,
                    0x00c8f655d497a60a,
                ],
                [
                    0xe722cb56749548c0,
                    0x46992627f99f0522,
                    0xba7311972b169452,
                    0x6e7d1a18b04c7b83,
                    0x665c890a04331509,
                    0x00f60b9eabb3af34,
                ],
            ),
            fq2(
                [
                    0xfd4e62c56afb4e99,
                    0x36257b0cc2a1fbd1,
                    0x5c80aac4a08047b7,
                    0x663bfb3b4b20ee12,
                    0x4faee0524d1b44e9,
                    0x008afd51fc678fe3,
                ],
                [
                    0x2299273976b9a2b4,
                    0xbfa4a248eb6dd311,
                    0x9af74c6b8ee80e8a,
                    0x08ed67201081edcd,
                    0xaf48cb50ad45e414,
                    0x0154f5332fe612e5,
                ],
            ),
            fq2(
                [
                    0x6c40dd23f21a0b4c,
                    0x959f4355b52ca9bb,
                    0x04b43fa8633415e9,
                    0xa08b6619b68d6858,
                    0x69e174f48be4cd73,
                    0x009a82211acb2c5c,
                ],
                [
                    0x9160206be677bd88,
                    0xb618ffc757b65507,
                    0x9dd98f4e321d1536,
                    0x4d89c91bac85c741,
                    0x7da1b7a7833e53d6,
                    0x0115d2e32de5b363,
                ],
            ),
        ),
    );
    assert_in_cyclotomic_subgroup(h_x);
    assert!(!h_x.c1.c0.is_zero());

    let h1 = h_x.pow([1u64 << 45]);
    assert!(!h1.c1.c0.is_zero());
    assert_eq!(h1.square(), g);
    assert_eq!(h1.cyclotomic_square(), g);

    // Exercise the `z2 == 0, z3 != 0` decompression branch alone (`[2]`), with bit 0 (`[3]`),
    // in a multi-bit batch (`[0b10110]`), and on `Bls12_377Parameters::X` itself (`h_x`).
    for (base, exp) in [
        (h1, &[2u64][..]),
        (h1, &[3u64][..]),
        (h1, &[0b10110u64][..]),
        (g, Bls12_377Parameters::X),
        (h_x, Bls12_377Parameters::X),
        (h_x, &[0x0002_aaaa_aaaa_0000u64][..]),
    ] {
        let expected = base.pow(exp);
        assert_eq!(base.cyclotomic_exp(exp), expected);
        assert_eq!(base.cyclotomic_exp_scalar(exp), expected);
    }
    assert_eq!(h1.cyclotomic_exp_scalar(&[2u64]), g);
}
