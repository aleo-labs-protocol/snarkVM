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

use std::{io::Cursor, marker::PhantomData};

use snarkvm_fields::{
    FftField,
    Field,
    Fp256,
    Fp256Parameters,
    Fp384,
    Fp384Parameters,
    LegendreSymbol,
    PrimeField,
    SquareRootField,
    batch_inversion,
    traits::{FftParameters, FieldParameters},
};
use snarkvm_utilities::{
    biginteger::BigInteger,
    rand::{TestRng, Uniform},
    serialize::{CanonicalDeserialize, Flags, SWFlags},
};

use rand::RngExt;

pub const ITERATIONS: u32 = 10;

fn random_negation_tests<F: Field, R: RngExt>(rng: &mut R) {
    for _ in 0..ITERATIONS {
        let a = F::rand(rng);
        let mut b = -a;
        b += &a;

        assert!(b.is_zero());
    }
}

fn random_addition_tests<F: Field, R: RngExt>(rng: &mut R) {
    for _ in 0..ITERATIONS {
        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = F::rand(rng);

        let t0 = (a + b) + c; // (a + b) + c

        let t1 = (a + c) + b; // (a + c) + b

        let t2 = (b + c) + a; // (b + c) + a

        assert_eq!(t0, t1);
        assert_eq!(t1, t2);
    }
}

fn random_subtraction_tests<F: Field, R: RngExt>(rng: &mut R) {
    for _ in 0..ITERATIONS {
        let a = F::rand(rng);
        let b = F::rand(rng);

        let t0 = a - b; // (a - b)

        let mut t1 = b; // (b - a)
        t1 -= &a;

        let mut t2 = t0; // (a - b) + (b - a) = 0
        t2 += &t1;

        assert!(t2.is_zero());
    }
}

fn random_multiplication_tests<F: Field, R: RngExt>(rng: &mut R) {
    for _ in 0..ITERATIONS {
        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = F::rand(rng);

        let mut t0 = a; // (a * b) * c
        t0 *= &b;
        t0 *= &c;

        let mut t1 = a; // (a * c) * b
        t1 *= &c;
        t1 *= &b;

        let mut t2 = b; // (b * c) * a
        t2 *= &c;
        t2 *= &a;

        assert_eq!(t0, t1);
        assert_eq!(t1, t2);
    }
}

fn random_inversion_tests<F: Field, R: RngExt>(rng: &mut R) {
    assert!(F::zero().inverse().is_none());

    for _ in 0..ITERATIONS {
        let mut a = F::rand(rng);
        let b = a.inverse().unwrap(); // probabilistically nonzero
        a *= &b;

        assert_eq!(a, F::one());
    }
}

fn random_doubling_tests<F: Field, R: RngExt>(rng: &mut R) {
    for _ in 0..ITERATIONS {
        let mut a = F::rand(rng);
        let mut b = a;
        a += &b;
        b.double_in_place();

        assert_eq!(a, b);
    }
}

fn random_squaring_tests<F: Field, R: RngExt>(rng: &mut R) {
    for _ in 0..ITERATIONS {
        let mut a = F::rand(rng);
        let mut b = a;
        a *= &b;
        b.square_in_place();

        assert_eq!(a, b);
    }
}

fn random_expansion_tests<F: Field, R: RngExt>(rng: &mut R) {
    for _ in 0..ITERATIONS {
        // Compare (a + b)(c + d) and (a*c + b*c + a*d + b*d)

        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = F::rand(rng);
        let d = F::rand(rng);

        let mut t0 = a;
        t0 += &b;
        let mut t1 = c;
        t1 += &d;
        t0 *= &t1;

        let mut t2 = a;
        t2 *= &c;
        let mut t3 = b;
        t3 *= &c;
        let mut t4 = a;
        t4 *= &d;
        let mut t5 = b;
        t5 *= &d;

        t2 += &t3;
        t2 += &t4;
        t2 += &t5;

        assert_eq!(t0, t2);
    }

    for _ in 0..ITERATIONS {
        // Compare (a + b)c and (a*c + b*c)

        let a = F::rand(rng);
        let b = F::rand(rng);
        let c = F::rand(rng);

        let t0 = (a + b) * c;
        let t2 = a * c + (b * c);

        assert_eq!(t0, t2);
    }
}

fn random_string_tests<F: PrimeField>(rng: &mut TestRng) {
    {
        let a = "84395729384759238745923745892374598234705297301958723458712394587103249587213984572934750213947582345792304758273458972349582734958273495872304598234";
        let b = "38495729084572938457298347502349857029384609283450692834058293405982304598230458230495820394850293845098234059823049582309485203948502938452093482039";
        let c = "3248875134290623212325429203829831876024364170316860259933542844758450336418538569901990710701240661702808867062612075657861768196242274635305077449545396068598317421057721935408562373834079015873933065667961469731886739181625866970316226171512545167081793907058686908697431878454091011239990119126";

        let mut a = F::from_str(a).map_err(|_| ()).unwrap();
        let b = F::from_str(b).map_err(|_| ()).unwrap();
        let c = F::from_str(c).map_err(|_| ()).unwrap();

        a *= &b;

        assert_eq!(a, c);
    }

    assert!(F::from_str("").is_err());
    assert!(F::from_str("0").map_err(|_| ()).unwrap().is_zero());
    assert!(F::from_str("00").is_err());
    assert!(F::from_str("00000000000").is_err());

    for _ in 0..ITERATIONS {
        let n: u64 = rng.random();

        let a = F::from_str(&format!("{n}")).map_err(|_| ()).unwrap();
        let b = F::from_bigint(n.into()).unwrap();

        assert_eq!(a, b);
    }

    for _ in 0..ITERATIONS {
        let a = F::rand(rng);

        let reference = a.to_string();
        let candidate = F::from_str(&reference).map_err(|_| panic!()).unwrap().to_string();
        assert_eq!(reference, candidate);
    }
}

fn random_sqrt_tests<F: SquareRootField>(rng: &mut TestRng) {
    for _ in 0..ITERATIONS {
        let a = F::rand(rng);
        let b = a.square();
        assert_eq!(b.legendre(), LegendreSymbol::QuadraticResidue);

        let b = b.sqrt().unwrap();
        assert!(a == b || a == -b);
    }

    let mut c = F::one();
    for _ in 0..ITERATIONS {
        let mut b = c.square();
        assert_eq!(b.legendre(), LegendreSymbol::QuadraticResidue);

        b = b.sqrt().unwrap();

        if b != c {
            b = -b;
        }

        assert_eq!(b, c);

        c += &F::one();
    }
}

pub fn random_sqrt_tonelli_tests<F: PrimeField + SquareRootField>(rng: &mut TestRng) {
    // Randomly check field elements on the `sqrt` operation.
    for _ in 0..10_000 {
        // Sample the expected square root.
        let expected_sqrt = F::rand(rng);

        // Compute the starting value.
        let given = expected_sqrt.square();
        // Ensure the starting value is a quadratic residue.
        assert_eq!(given.legendre(), LegendreSymbol::QuadraticResidue);

        // Compute the candidate square root.
        let candidate_a = given.sqrt().unwrap();
        assert!(expected_sqrt == candidate_a || expected_sqrt == -candidate_a);

        // Compute the Tonelli-Shanks square root.
        let candidate_b = check_tonelli_shanks_sqrt_for_testing(&given).unwrap();
        assert!(expected_sqrt == candidate_b || expected_sqrt == -candidate_b);

        // Ensure the two candidate square roots are equivalent.
        assert!(candidate_a == candidate_b || -candidate_a == candidate_b)
    }

    // Start at 1.
    let mut expected_sqrt = F::one();

    // For each iteration, increment the field element by 1 and check the `sqrt` operation.
    for _ in 0..1_000 {
        // Compute the starting value.
        let given = expected_sqrt.square();
        assert_eq!(given.legendre(), LegendreSymbol::QuadraticResidue);

        // Compute the candidate square root.
        let candidate_a = given.sqrt().unwrap();
        assert!(expected_sqrt == candidate_a || expected_sqrt == -candidate_a);

        // Compute the Tonelli-Shanks square root.
        let candidate_b = check_tonelli_shanks_sqrt_for_testing(&given).unwrap();
        assert!(expected_sqrt == candidate_b || expected_sqrt == -candidate_b);

        // Increment by 1.
        expected_sqrt += &F::one();
    }

    // Start at 1.
    let mut given = F::one();

    // Linearly check equivalence.
    for _ in 0..1_000 {
        // Compute the candidate square root.
        let candidate_a = given.sqrt();
        // Compute the Tonelli-Shanks square root.
        let candidate_b = check_tonelli_shanks_sqrt_for_testing(&given);

        // Ensure the two candidate square roots are equivalent.
        match candidate_a {
            Some(candidate_a) => assert!(Some(candidate_a) == candidate_b || Some(-candidate_a) == candidate_b),
            None => assert_eq!(candidate_a, candidate_b),
        };

        // Increment by 1.
        given += &F::one();
    }

    // Start at 1.
    let mut given = F::one();

    // Linearly check equivalence.
    for _ in 0..1_000 {
        // Compute the candidate square root.
        let candidate_a = given.sqrt();
        // Compute the Tonelli-Shanks square root.
        let candidate_b = check_tonelli_shanks_sqrt_for_testing(&given);

        // Ensure the two candidate square roots are equivalent.
        match candidate_a {
            Some(candidate_a) => assert!(Some(candidate_a) == candidate_b || Some(-candidate_a) == candidate_b),
            None => assert_eq!(candidate_a, candidate_b),
        };

        // Decrement by 1.
        given -= &F::one();
    }
}

#[cfg(test)]
pub(crate) fn bench_sqrt<F: PrimeField + SquareRootField>(rng: &mut TestRng) {
    const ITERATIONS: usize = 100_000;

    let mut profile_a = Vec::with_capacity(ITERATIONS);
    let mut profile_b = Vec::with_capacity(ITERATIONS);

    // Randomly check the performance of the `sqrt` operation.
    for _ in 0..ITERATIONS {
        // Sample the expected square root.
        let expected_sqrt = F::rand(rng);

        // Compute the starting value.
        let given = expected_sqrt.square();
        // Ensure the starting value is a quadratic residue.
        assert_eq!(given.legendre(), LegendreSymbol::QuadraticResidue);

        // Compute the candidate square root.
        let timer = std::time::Instant::now();
        let _candidate_a = given.sqrt();
        let time_a = timer.elapsed().as_nanos();
        profile_a.push(time_a);

        // Compute the Tonelli-Shanks square root.
        let timer = std::time::Instant::now();
        let _candidate_b = check_tonelli_shanks_sqrt_for_testing(&given);
        let time_b = timer.elapsed().as_nanos();
        profile_b.push(time_b);
    }

    let num_a = profile_a.len() as u128;
    let num_b = profile_b.len() as u128;

    let avg_time_a = profile_a.into_iter().reduce(|a, b| a.checked_add(b).unwrap()).unwrap() / num_a;
    let avg_time_b = profile_b.into_iter().reduce(|a, b| a.checked_add(b).unwrap()).unwrap() / num_b;

    println!("{avg_time_a} vs. {avg_time_b} ({}%)", avg_time_b.saturating_sub(avg_time_a) * 100 / avg_time_a);
    assert!(avg_time_a <= avg_time_b, "This is an acceptable failure. It is for a timer.");
}

/// Returns the square root using the Tonelli-Shanks algorithm.
#[cfg(test)]
#[inline]
fn check_tonelli_shanks_sqrt_for_testing<F: PrimeField + SquareRootField>(field: &F) -> Option<F> {
    use snarkvm_fields::LegendreSymbol::*;
    // https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
    // Actually this is just normal Tonelli-Shanks; since `P::Generator`
    // is a quadratic non-residue, `P::ROOT_OF_UNITY = P::GENERATOR ^ t`
    // is also a quadratic non-residue (since `t` is odd).
    match field.legendre() {
        Zero => Some(*field),
        QuadraticNonResidue => None,
        QuadraticResidue => {
            let mut z = F::two_adic_root_of_unity();
            let mut w = field.pow(<F as PrimeField>::Parameters::T_MINUS_ONE_DIV_TWO);
            let mut x = w * field;
            let mut b = x * w;

            let mut v = <F as FftField>::FftParameters::TWO_ADICITY as usize;
            // t = self^t
            #[cfg(debug_assertions)]
            {
                let mut check = b;
                for _ in 0..(v - 1) {
                    check.square_in_place();
                }
                if !check.is_one() {
                    panic!("Input is not a square root, but it passed the QR test")
                }
            }

            while !b.is_one() {
                let mut k = 0usize;

                let mut b2k = b;
                while !b2k.is_one() {
                    // invariant: b2k = b^(2^k) after entering this loop
                    b2k.square_in_place();
                    k += 1;
                }

                let j = v - k - 1;
                w = z;
                for _ in 0..j {
                    w.square_in_place();
                }

                z = w.square();
                b *= &z;
                x *= &w;
                v = k;
            }

            Some(x)
        }
    }
}

#[allow(clippy::eq_op)]
pub fn field_test<F: Field>(a: F, b: F, rng: &mut TestRng) {
    let zero = F::zero();
    assert!(zero == zero);
    assert!(zero.is_zero()); // true
    assert!(!zero.is_one()); // false

    let one = F::one();
    assert!(one == one);
    assert!(!one.is_zero()); // false
    assert!(one.is_one()); // true
    assert_eq!(zero + one, one);

    let two = one + one;
    assert!(two == two);
    assert_ne!(zero, two);
    assert_ne!(one, two);

    // a == a
    assert!(a == a);
    // a + 0 = a
    assert_eq!(a + zero, a);
    // a - 0 = a
    assert_eq!(a - zero, a);
    // a - a = 0
    assert_eq!(a - a, zero);
    // 0 - a = -a
    assert_eq!(zero - a, -a);
    // a.double() = a + a
    assert_eq!(a.double(), a + a);
    // b.double() = b + b
    assert_eq!(b.double(), b + b);
    // a + b = b + a
    assert_eq!(a + b, b + a);
    // a - b = -(b - a)
    assert_eq!(a - b, -(b - a));
    // (a + b) + a = a + (b + a)
    assert_eq!((a + b) + a, a + (b + a));
    // (a + b).double() = (a + b) + (b + a)
    assert_eq!((a + b).double(), (a + b) + (b + a));
    assert_eq!(F::half(), F::one().double().inverse().unwrap());

    // a * 0 = 0
    assert_eq!(a * zero, zero);
    // a * 1 = a
    assert_eq!(a * one, a);
    // a * 2 = a.double()
    assert_eq!(a * two, a.double());
    // a * a^-1 = 1
    assert_eq!(a * a.inverse().unwrap(), one);
    // a * a = a^2
    assert_eq!(a * a, a.square());
    // a * a * a = a^3
    assert_eq!(a * (a * a), a.pow([0x3, 0x0, 0x0, 0x0]));
    // a * b = b * a
    assert_eq!(a * b, b * a);
    // (a * b) * a = a * (b * a)
    assert_eq!((a * b) * a, a * (b * a));
    // (a + b)^2 = a^2 + 2ab + b^2
    assert_eq!((a + b).square(), a.square() + ((a * b) + (a * b)) + b.square());
    // (a - b)^2 = (-(b - a))^2
    assert_eq!((a - b).square(), (-(b - a)).square());

    for len in 0..10 {
        let mut a = Vec::new();
        let mut b = Vec::new();
        for _ in 0..len {
            a.push(F::rand(rng));
            b.push(F::rand(rng));
            assert_eq!(F::sum_of_products(&a, &b), a.iter().zip(b.iter()).map(|(x, y)| *x * y).sum());
        }
    }

    random_negation_tests::<F, _>(rng);
    random_addition_tests::<F, _>(rng);
    random_subtraction_tests::<F, _>(rng);
    random_multiplication_tests::<F, _>(rng);
    random_inversion_tests::<F, _>(rng);
    random_doubling_tests::<F, _>(rng);
    random_squaring_tests::<F, _>(rng);
    random_expansion_tests::<F, _>(rng);

    assert!(F::zero().is_zero());
    {
        let z = -F::zero();
        assert!(z.is_zero());
    }

    assert!(F::zero().inverse().is_none());

    // Multiplication by zero
    {
        let a = F::rand(rng) * F::zero();
        assert!(a.is_zero());
    }

    // Addition by zero
    {
        let mut a = F::rand(rng);
        let copy = a;
        a += &F::zero();
        assert_eq!(a, copy);
    }
}

pub fn fft_field_test<F: PrimeField + FftField>() {
    let modulus_minus_one_div_two = F::from_bigint(F::modulus_minus_one_div_two()).unwrap();
    assert!(!modulus_minus_one_div_two.is_zero());

    // modulus - 1 == 2^s * t
    // => t == (modulus - 1) / 2^s
    // => t == [(modulus - 1) / 2] * [1 / 2^(s-1)]
    let two_adicity = F::FftParameters::TWO_ADICITY;
    assert!(two_adicity > 0);
    let two_s_minus_one = F::from(2_u32).pow([(two_adicity - 1) as u64]);
    let trace = modulus_minus_one_div_two * two_s_minus_one.inverse().unwrap();
    assert_eq!(trace, F::from_bigint(F::trace()).unwrap());

    // (trace - 1) / 2 == trace_minus_one_div_two
    let trace_minus_one_div_two = F::from_bigint(F::trace_minus_one_div_two()).unwrap();
    assert!(!trace_minus_one_div_two.is_zero());
    assert_eq!((trace - F::one()) / F::one().double(), trace_minus_one_div_two);

    // multiplicative_generator^trace == root of unity
    let generator = F::multiplicative_generator();
    assert!(!generator.is_zero());
    let two_adic_root_of_unity = F::two_adic_root_of_unity();
    assert!(!two_adic_root_of_unity.is_zero());
    assert_eq!(two_adic_root_of_unity.pow([1 << two_adicity]), F::one());
    assert_eq!(generator.pow(trace.to_bigint().as_ref()), two_adic_root_of_unity);
}

pub fn primefield_test<F: PrimeField>(rng: &mut TestRng) {
    let one = F::one();
    assert_eq!(F::from_bigint(one.to_bigint()).unwrap(), one);
    assert_eq!(F::from_str("1").ok().unwrap(), one);
    assert_eq!(F::from_str(&one.to_string()).ok().unwrap(), one);

    let two = F::one().double();
    assert_eq!(F::from_bigint(two.to_bigint()).unwrap(), two);
    assert_eq!(F::from_str("2").ok().unwrap(), two);
    assert_eq!(F::from_str(&two.to_string()).ok().unwrap(), two);

    random_string_tests::<F>(rng);
    fft_field_test::<F>();
}

pub fn sqrt_field_test<F: SquareRootField>(elem: F, rng: &mut TestRng) {
    let square = elem.square();
    let sqrt = square.sqrt().unwrap();
    assert!(sqrt == elem || sqrt == -elem);
    if let Some(sqrt) = elem.sqrt() {
        assert!(sqrt.square() == elem);
    }
    random_sqrt_tests::<F>(rng);
}

pub fn frobenius_test<F: Field, C: AsRef<[u64]>>(characteristic: C, maxpower: usize, rng: &mut TestRng) {
    for _ in 0..ITERATIONS {
        let a = F::rand(rng);

        let mut a_0 = a;
        a_0.frobenius_map(0);
        assert_eq!(a, a_0);

        let mut a_q = a.pow(&characteristic);
        for power in 1..maxpower {
            let mut a_qi = a;
            a_qi.frobenius_map(power);
            assert_eq!(a_qi, a_q);

            a_q = a_q.pow(&characteristic);
        }
    }
}
pub fn field_serialization_test<F: Field>(rng: &mut TestRng) {
    use snarkvm_utilities::serialize::{Compress, Validate};
    let modes = [
        (Compress::No, Validate::No),
        (Compress::Yes, Validate::No),
        (Compress::Yes, Validate::Yes),
        (Compress::No, Validate::Yes),
    ];

    for _ in 0..ITERATIONS {
        let a = F::rand(rng);
        for (compress, validate) in modes {
            let serialized_size = a.serialized_size(compress);
            let mut serialized = vec![0u8; serialized_size];
            let mut cursor = Cursor::new(&mut serialized);
            a.serialize_with_mode(&mut cursor, compress).unwrap();
            let serialized2 = bincode::serialize(&a).unwrap();
            assert_eq!(serialized, serialized2);

            let mut cursor = Cursor::new(&serialized[..]);
            let b = F::deserialize_with_mode(&mut cursor, compress, validate).unwrap();
            let c: F = bincode::deserialize(&serialized).unwrap();
            assert_eq!(a, b);
            assert_eq!(a, c);
        }
        {
            let mut serialized = vec![0u8; a.uncompressed_size()];
            let mut cursor = Cursor::new(&mut serialized[..]);
            a.serialize_uncompressed(&mut cursor).unwrap();
            let mut cursor = Cursor::new(&serialized[..]);
            let b = F::deserialize_uncompressed(&mut cursor).unwrap();
            assert_eq!(a, b);
        }

        {
            let mut serialized = vec![0u8; F::one().serialized_size_with_flags::<SWFlags>()];
            let mut cursor = Cursor::new(&mut serialized[..]);
            a.serialize_with_flags(&mut cursor, SWFlags::from_y_sign(true)).unwrap();
            let mut cursor = Cursor::new(&serialized[..]);
            let (b, flags) = F::deserialize_with_flags::<_, SWFlags>(&mut cursor).unwrap();
            assert_eq!(flags.is_positive(), Some(true));
            assert!(!flags.is_infinity());
            assert_eq!(a, b);
        }
        #[derive(Default, Clone, Copy, Debug)]
        struct DummyFlags;
        impl Flags for DummyFlags {
            const BIT_SIZE: usize = 200;

            fn u8_bitmask(&self) -> u8 {
                0
            }

            fn from_u8(_value: u8) -> Option<Self> {
                Some(DummyFlags)
            }

            fn from_u8_remove_flags(_value: &mut u8) -> Option<Self> {
                Some(DummyFlags)
            }
        }

        use snarkvm_utilities::serialize::SerializationError;
        {
            let mut serialized = vec![0; F::one().serialized_size_with_flags::<DummyFlags>()];
            assert!(matches!(
                a.serialize_with_flags(&mut serialized[..], DummyFlags).unwrap_err(),
                SerializationError::NotEnoughSpace
            ));
            assert!(matches!(
                F::deserialize_with_flags::<_, DummyFlags>(&serialized[..]).unwrap_err(),
                SerializationError::NotEnoughSpace
            ));
        }

        {
            for (compress, validate) in modes {
                let mut serialized = vec![0; F::one().serialized_size(compress) - 1];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a.serialize_with_mode(&mut cursor, compress).unwrap_err();
                let mut cursor = Cursor::new(&serialized[..]);
                <F as CanonicalDeserialize>::deserialize_with_mode(&mut cursor, compress, validate).unwrap_err();
            }
        }
    }
}

pub fn fp256_inverse_test<P: Fp256Parameters>(rng: &mut TestRng) {
    inverse_test(rng, |x| Fp256::<P>(x, PhantomData), |a| a.0);
}

pub fn fp384_inverse_test<P: Fp384Parameters>(rng: &mut TestRng) {
    inverse_test(rng, |x| Fp384::<P>(x, PhantomData), |a| a.0);
}

/// `raw` makes an element from its Montgomery representation, and `repr` returns that representation.
fn inverse_test<F: PrimeField>(
    rng: &mut TestRng,
    raw: impl Fn(F::BigInteger) -> F,
    repr: impl Fn(&F) -> F::BigInteger,
) {
    let modulus = F::Parameters::MODULUS;
    assert_eq!(modulus.as_ref()[0].wrapping_mul(F::Parameters::INV.wrapping_neg()), 1);

    let check = |a: F| {
        if a.is_zero() {
            return;
        }
        // `a` is nonzero.
        let inverse = a.inverse().unwrap();
        assert!(repr(&inverse) < modulus, "{:?}", repr(&a));
        assert_eq!(a * inverse, F::one(), "{:?}", repr(&a));
    };
    let one = F::BigInteger::from(1);
    let bits = 64 * F::BigInteger::NUM_LIMBS as u32;

    let mut edges = vec![F::Parameters::R, F::Parameters::R2];
    for k in 0..bits {
        let mut power = one;
        power.muln(k);
        let (mut below, mut above) = (power, power);
        below.sub_noborrow(&one);
        above.add_nocarry(&one);
        edges.extend([power, below, above]);
    }
    for i in 1..=64 {
        let mut near_p = modulus;
        near_p.sub_noborrow(&F::BigInteger::from(i));
        edges.push(near_p);
    }
    for edge in edges.into_iter().filter(|e| *e < modulus) {
        check(raw(edge));
        if let Some(canonical) = F::from_bigint(edge) {
            check(canonical);
        }
    }
    for i in 0..10_000 {
        let mut short = F::BigInteger::rand(rng);
        short.divn(i % bits);
        if short < modulus {
            check(raw(short));
        }
        check(F::rand(rng));
    }

    let mut values: Vec<F> = (0..1000).map(|i| if i % 97 == 0 { F::zero() } else { F::rand(rng) }).collect();
    let originals = values.clone();
    batch_inversion(&mut values);
    for (original, inverse) in originals.iter().zip(&values) {
        assert_eq!(*original * inverse, if original.is_zero() { F::zero() } else { F::one() });
    }
}
