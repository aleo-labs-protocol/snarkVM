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

use crate::{
    edwards_bls12::*,
    templates::twisted_edwards_extended::tests::{edwards_test, montgomery_conversion_test},
    traits::{
        AffineCurve,
        MontgomeryParameters,
        ProjectiveCurve,
        TwistedEdwardsParameters,
        tests_field::{field_serialization_test, field_test, fp256_inverse_test, primefield_test},
        tests_group::*,
        tests_projective::curve_tests,
    },
};
use snarkvm_fields::{Field, LegendreSymbol, One, SquareRootField, Zero};
use snarkvm_utilities::{
    BitIteratorBE,
    ToBytes,
    rand::{TestRng, Uniform},
    to_bytes_le,
};

use core::str::FromStr;
use rand::RngExt;

#[test]
fn test_edwards_bls12_fr() {
    let mut rng = TestRng::default();

    let a: Fr = rng.random();
    let b: Fr = rng.random();
    field_test(a, b, &mut rng);
    primefield_test::<Fr>(&mut rng);
    field_serialization_test::<Fr>(&mut rng);
}

#[test]
fn test_edwards_bls12_fr_inverse() {
    fp256_inverse_test::<FrParameters>(&mut TestRng::default());
}

#[test]
fn test_edwards_bls12_fq() {
    let mut rng = TestRng::default();

    let a: Fq = rng.random();
    let b: Fq = rng.random();
    field_test(a, b, &mut rng);
    primefield_test::<Fq>(&mut rng);
    field_serialization_test::<Fq>(&mut rng);
}

#[test]
fn test_projective_curve() {
    let mut rng = TestRng::default();

    curve_tests::<EdwardsProjective>(&mut rng);
    edwards_test::<EdwardsParameters>(&mut rng);
}

#[test]
fn test_projective_group() {
    let mut rng = TestRng::default();

    for _i in 0..10 {
        let a = rng.random();
        let b = rng.random();
        projective_test::<EdwardsProjective>(a, b, &mut rng);
    }
}

#[test]
fn test_affine_group() {
    let mut rng = TestRng::default();

    for _i in 0..10 {
        let a: EdwardsAffine = rng.random();
        affine_test::<EdwardsAffine>(a);
    }
}

#[test]
fn test_serialization_round_trip() {
    serialization_round_trip_test::<EdwardsAffine>();
}

#[test]
fn test_generator() {
    let generator = EdwardsAffine::prime_subgroup_generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}

/// Facts about the curve that the proof of `Affine::quartic_character` needs.
#[test]
fn test_quartic_character_curve_shape() {
    let one = Fq::one();
    let d = EdwardsParameters::EDWARDS_D;
    assert_eq!(EdwardsParameters::EDWARDS_A, -one);
    assert_eq!(EdwardsParameters::COFACTOR, &[4]);
    assert_eq!(d.legendre(), LegendreSymbol::QuadraticNonResidue);
    assert_eq!((one + d).legendre(), LegendreSymbol::QuadraticNonResidue);
    assert_eq!(EdwardsParameters::SQRT_MINUS_ONE.square(), -one);
    // `(1 + i)^4 = -4`, the value of the character's argument at the identity.
    assert_eq!((one + EdwardsParameters::SQRT_MINUS_ONE).pow([4u64]), -Fq::from(4u8));
    assert!(Fr::characteristic()[0] & 1 == 1);
    // `4 * MODULUS_MINUS_ONE_DIV_FOUR + 1 = q`.
    // The exponent has the four limbs of the modulus.
    let exponent: &[u64; 4] = EdwardsParameters::MODULUS_MINUS_ONE_DIV_FOUR.try_into().unwrap();
    let mut q = [0u64; 4];
    let mut carry = 1u64;
    for (limb, exponent_limb) in q.iter_mut().zip(exponent) {
        *limb = (exponent_limb << 2) | carry;
        carry = exponent_limb >> 62;
    }
    assert_eq!(carry, 0);
    assert_eq!(&q, Fq::characteristic());
}

/// Checks the stored schedule for `MODULUS_MINUS_ONE_DIV_FOUR` against `pow`.
#[test]
fn test_modulus_minus_one_div_four_schedule() {
    const ITERATIONS: usize = 1000;
    let mut rng = TestRng::default();
    let schedule = EdwardsParameters::modulus_minus_one_div_four_schedule();
    let exponent = EdwardsParameters::MODULUS_MINUS_ONE_DIV_FOUR;
    let i = EdwardsParameters::SQRT_MINUS_ONE;

    let edge_cases = [Fq::zero(), Fq::one(), -Fq::one(), i, -i];
    for u in edge_cases.into_iter().chain((0..ITERATIONS).map(|_| rng.random())) {
        assert_eq!(schedule.pow(&u), u.pow(exponent), "u = {u}");
    }
}

/// Checks the character and the decode against plain double-and-add over every outcome, on the x-coordinates of:
/// the torsion points, `x = 1`, `x = -1`, random field elements, and subgroup points plus each torsion point.
#[test]
fn test_subgroup_point_from_x_coordinate_matches_double_and_add() {
    const ITERATIONS: usize = 1000;
    let mut rng = TestRng::default();
    let i = EdwardsParameters::SQRT_MINUS_ONE;

    let in_subgroup = |point: &EdwardsAffine| {
        let mut acc = EdwardsProjective::zero();
        for bit in BitIteratorBE::new(Fr::characteristic()) {
            acc.double_in_place();
            if bit {
                acc.add_assign_mixed(point);
            }
        }
        acc.is_zero()
    };

    // The counts of `[no y, character 0, character i or -i, character 1, character -1]`.
    let mut outcomes = [0usize; 5];
    let mut check = |x: Fq| {
        let decoded = EdwardsAffine::subgroup_point_from_x_coordinate(x);
        let Some((p1, p2)) = EdwardsAffine::pair_from_x_coordinate(x) else {
            assert_eq!(decoded, None);
            outcomes[0] += 1;
            return;
        };
        assert!(p1.is_on_curve() && p2.is_on_curve());
        assert!(p1.y <= p2.y);
        let (p1_in, p2_in) = (in_subgroup(&p1), in_subgroup(&p2));
        let character = p1.quartic_character();
        if character.is_zero() {
            assert_eq!(p1.x, i);
            assert!(!p1_in && !p2_in && decoded.is_none());
            outcomes[1] += 1;
        } else if character == i || character == -i {
            assert!(!p1_in && !p2_in && decoded.is_none());
            assert_eq!(
                (Fq::one() - EdwardsParameters::EDWARDS_D * x.square()).legendre(),
                LegendreSymbol::QuadraticNonResidue
            );
            outcomes[2] += 1;
        } else if character.is_one() {
            assert!(p1_in && !p2_in);
            assert_eq!(decoded, Some(p1));
            outcomes[3] += 1;
        } else {
            assert_eq!(character, -Fq::one());
            assert!(!p1_in && p2_in);
            assert_eq!(decoded, Some(p2));
            outcomes[4] += 1;
        }
    };

    for x in [Fq::zero(), Fq::one(), -Fq::one(), i, -i] {
        check(x);
    }
    let t4 = EdwardsAffine::from_coordinates_unchecked((i, Fq::zero())).to_projective();
    let torsion = [EdwardsProjective::zero(), t4.double(), t4, -t4];
    for _ in 0..ITERATIONS {
        check(rng.random());
        let point: EdwardsProjective = rng.random();
        for torsion in torsion {
            check((point + torsion).to_affine().x);
        }
    }
    assert!(outcomes.iter().all(|count| *count > 0), "outcomes: {outcomes:?}");
}

/// Fixes the decode's result at the edge cases of the character.
#[test]
fn test_subgroup_point_from_x_coordinate_edge_cases() {
    let i = EdwardsParameters::SQRT_MINUS_ONE;

    // The candidates at `x = 0` are `(0, 1)`, the identity, and `(0, -1)`, which has order two.
    let (p1, p2) = EdwardsAffine::pair_from_x_coordinate(Fq::zero()).unwrap();
    assert_eq!((p1.y, p2.y), (Fq::one(), -Fq::one()));
    assert_eq!(p1.quartic_character(), Fq::one());
    assert_eq!(EdwardsAffine::subgroup_point_from_x_coordinate(Fq::zero()), Some(EdwardsAffine::zero()));

    // The only point at `x = i` is `(i, 0)`, where the character is zero.
    let (p1, p2) = EdwardsAffine::pair_from_x_coordinate(i).unwrap();
    assert_eq!(p1, p2);
    assert!(p1.y.is_zero());
    assert!(p1.quartic_character().is_zero());
    assert_eq!(EdwardsAffine::subgroup_point_from_x_coordinate(i), None);

    // The only point at `x = -i` is `(-i, 0)`, where the character is `i` or `-i`.
    let (p1, p2) = EdwardsAffine::pair_from_x_coordinate(-i).unwrap();
    assert_eq!(p1, p2);
    assert_eq!(p1.quartic_character().square(), -Fq::one());
    assert_eq!(EdwardsAffine::subgroup_point_from_x_coordinate(-i), None);

    // `x = 1` and `x = -1` give `y^2 = 2 / (1 - d)`, which is not a square on this curve.
    assert!(EdwardsAffine::pair_from_x_coordinate(Fq::one()).is_none());
    assert!(EdwardsAffine::pair_from_x_coordinate(-Fq::one()).is_none());

    // `1 - d * x^2` has no root, because `d` is a non-square. The unwrap holds because `d` is non-zero.
    assert!(EdwardsParameters::EDWARDS_D.inverse().unwrap().sqrt().is_none());
}

/// Checks the decode and the character against `IsInSubGroup` of gnark-crypto `77390410395a`
/// (`ecc/bls12-377/twistededwards/subgroup.go`), on the vectors in `resources/gnark_subgroup_vectors.txt`.
/// Each line is `x -` if `x` has no point, and otherwise `x y in_y in_neg_y`: `y` is the smaller root as an integer,
/// and `in_y`, `in_neg_y` are `IsInSubGroup` on `(x, y)` and `(x, -y)` as `0` or `1`.
/// The x-coordinates are `0`, `1`, `-1`, `i`, `-i`, random field elements, and those of `P`, `P + (0, -1)`
/// and `P ± (i, 0)` for random subgroup points `P`.
#[test]
fn test_subgroup_point_from_x_coordinate_matches_gnark() {
    let vectors = include_str!("resources/gnark_subgroup_vectors.txt");

    // The counts of `[no y, neither candidate accepted, p1 accepted, p2 accepted]`.
    let mut outcomes = [0usize; 4];
    for line in vectors.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let x = Fq::from_str(fields[0]).unwrap();
        let decoded = EdwardsAffine::subgroup_point_from_x_coordinate(x);
        let Some((p1, p2)) = EdwardsAffine::pair_from_x_coordinate(x) else {
            assert_eq!(fields[1..], ["-"], "x = {x}");
            assert_eq!(decoded, None);
            outcomes[0] += 1;
            continue;
        };
        let [y, p1_in, p2_in] = fields[1..] else { panic!("x = {x} has a point, but the line is {line:?}") };
        assert_eq!((p1.y, p2.y), (Fq::from_str(y).unwrap(), -Fq::from_str(y).unwrap()), "x = {x}");
        let bit = |bit: &str| match bit {
            "0" => false,
            "1" => true,
            _ => panic!("unexpected line {line:?}"),
        };
        let (p1_in, p2_in) = (bit(p1_in), bit(p2_in));
        assert!(!(p1_in && p2_in), "x = {x}");
        assert_eq!(p1.quartic_character().is_one(), p1_in, "x = {x}");
        assert_eq!(p2.quartic_character().is_one(), p2_in, "x = {x}");
        let (expected, outcome) = match (p1_in, p2_in) {
            (true, _) => (Some(p1), 2),
            (_, true) => (Some(p2), 3),
            _ => (None, 1),
        };
        assert_eq!(decoded, expected, "x = {x}");
        outcomes[outcome] += 1;
    }
    assert!(outcomes.iter().all(|count| *count > 0), "outcomes: {outcomes:?}");
}

#[test]
fn test_conversion() {
    let mut rng = TestRng::default();

    let a: EdwardsAffine = rng.random();
    let b: EdwardsAffine = rng.random();
    assert_eq!(a.to_projective().to_affine(), a);
    assert_eq!(b.to_projective().to_affine(), b);
}

#[test]
fn test_montgomery_conversion() {
    montgomery_conversion_test::<EdwardsParameters>();
}

#[test]
#[allow(clippy::many_single_char_names)]
fn test_edwards_to_montgomery_point() {
    let mut rng = TestRng::default();

    let a: EdwardsAffine = rng.random();
    let (x, y) = (a.x, a.y);

    // Montgomery element (u, v)
    let (u, v) = {
        let numerator = Fq::one() + y;
        let denominator = Fq::one() - y;

        let u = numerator * (denominator.inverse().unwrap());
        let v = numerator * ((denominator * x).inverse().unwrap());
        (u, v)
    };

    // Ensure (u, v) is a valid Montgomery element
    {
        const A: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_A;
        const B: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_B;

        // Enforce B * v^2 == u^3 + A * u^2 + u
        let v2 = v.square();
        let u2 = u.square();
        let u3 = u2 * u;
        assert_eq!(B * v2, u3 + (A * u2) + u);
    }

    // Edwards element (x, y)
    let (x_reconstructed, y_reconstructed) = {
        let x = u * v.inverse().unwrap();

        let numerator = u - Fq::one();
        let denominator = u + Fq::one();
        let y = numerator * denominator.inverse().unwrap();

        (x, y)
    };

    assert_eq!(x, x_reconstructed);
    assert_eq!(y, y_reconstructed);
}

#[ignore]
#[test]
fn print_montgomery_to_weierstrass_parameters() {
    const A: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_A;
    const B: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_B;

    let two = Fq::one() + Fq::one();
    let three = Fq::one() + two;
    let nine = three + (three + three);
    let twenty_seven = nine + (nine + nine);

    let a2 = A.square();
    let a3 = A * a2;
    let b2 = B.square();
    let b3 = B * b2;

    // Let a = (3 - A^2) / (3 * B^2).
    let numerator = three - a2;
    let denominator = three * b2;
    let a = numerator * denominator.inverse().unwrap();

    // Let b = (2 * A^3 - 9 * A) / (27 * B^3).
    let numerator = (two * a3) - (nine * A);
    let denominator = twenty_seven * b3;
    let b = numerator * denominator.inverse().unwrap();

    println!("A - {a}\nB - {b}");
}

#[test]
#[allow(clippy::many_single_char_names)]
fn test_isomorphism() {
    let mut rng = TestRng::default();

    // Sample a random Fr element.
    let fr_element: Fr = Fr::rand(&mut rng);

    println!("Starting Fr element is - {fr_element:?}");

    // Map it to its corresponding Fq element.
    let fq_element = {
        let output = Fq::from_random_bytes(&to_bytes_le![fr_element].unwrap());
        assert!(output.is_some());
        output.unwrap()
    };

    println!("Starting Fq element is {fq_element:?}");

    // Declare the parameters for the Montgomery equation: B * v^2 == u^3 + A * u^2 + u.
    const A: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_A;
    const B: Fq = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_B;

    // Compute the parameters for the alternate Montgomery form: v^2 == u^3 + A * u^2 + B * u.
    let (a, b) = {
        let a = A * B.inverse().unwrap();
        let b = Fq::one() * B.square().inverse().unwrap();
        (a, b)
    };

    // Compute the mapping from Fq to E(Fq) as an alternate Montgomery element (u, v).
    let (u, v) = {
        // Let r = element.
        let r = fq_element;

        // Let u = D.
        let u = <EdwardsParameters as TwistedEdwardsParameters>::EDWARDS_D;

        // Let ur2 = u * r^2;
        let ur2 = r.square() * u;

        {
            // Verify r is nonzero.
            assert!(!r.is_zero());

            // Verify u is a quadratic nonresidue.
            assert!(u.legendre().is_qnr());

            // Verify 1 + ur^2 != 0.
            assert_ne!(Fq::one() + ur2, Fq::zero());

            // Verify A^2 * ur^2 != B(1 + ur^2)^2.
            let a2 = a.square();
            assert_ne!(a2 * ur2, (Fq::one() + ur2).square() * b);
        }

        // Let v = -A / (1 + ur^2).
        let v = (Fq::one() + ur2).inverse().unwrap() * (-a);

        // Let e = legendre(v^3 + Av^2 + Bv).
        let v2 = v.square();
        let v3 = v2 * v;
        let av2 = a * v2;
        let bv = b * v;
        let e = (v3 + (av2 + bv)).legendre();

        // Let x = ev - ((1 - e) * A/2).
        let two = Fq::one().double();
        let x = match e {
            LegendreSymbol::Zero => -(a * two.inverse().unwrap()),
            LegendreSymbol::QuadraticResidue => v,
            LegendreSymbol::QuadraticNonResidue => (-v) - a,
        };

        // Let y = -e * sqrt(x^3 + Ax^2 + Bx).
        let x2 = x.square();
        let x3 = x2 * x;
        let ax2 = a * x2;
        let bx = b * x;
        let value = (x3 + (ax2 + bx)).sqrt().unwrap();
        let y = match e {
            LegendreSymbol::Zero => Fq::zero(),
            LegendreSymbol::QuadraticResidue => -value,
            LegendreSymbol::QuadraticNonResidue => value,
        };

        (x, y)
    };

    // Ensure (u, v) is a valid alternate Montgomery element.
    {
        // Enforce v^2 == u^3 + A * u^2 + B * u
        let v2 = v.square();
        let u2 = u.square();
        let u3 = u2 * u;
        assert_eq!(v2, u3 + (a * u2) + (b * u));
    }

    // Convert the alternate Montgomery element (u, v) to Montgomery element (s, t).
    let (s, t) = {
        let s = u * B;
        let t = v * B;

        // Ensure (s, t) is a valid Montgomery element
        {
            // Enforce B * t^2 == s^3 + A * s^2 + s
            let t2 = t.square();
            let s2 = s.square();
            let s3 = s2 * s;
            assert_eq!(B * t2, s3 + (A * s2) + s);
        }

        (s, t)
    };

    // Convert the Montgomery element (s, t) to the twisted Edwards element (x, y).
    let (x, y) = {
        let x = s * t.inverse().unwrap();

        let numerator = s - Fq::one();
        let denominator = s + Fq::one();
        let y = numerator * denominator.inverse().unwrap();

        (x, y)
    };

    let group = EdwardsAffine::new(x, y, x * y);

    println!("{group:?}");

    // Convert the twisted Edwards element (x, y) to the alternate Montgomery element (u, v)
    let (u_reconstructed, v_reconstructed) = {
        let numerator = Fq::one() + y;
        let denominator = Fq::one() - y;

        let u = numerator * (denominator.inverse().unwrap());
        let v = numerator * ((denominator * x).inverse().unwrap());

        // Ensure (u, v) is a valid Montgomery element
        {
            // Enforce B * v^2 == u^3 + A * u^2 + u
            let v2 = v.square();
            let u2 = u.square();
            let u3 = u2 * u;
            assert_eq!(B * v2, u3 + (A * u2) + u);
        }

        let u = u * B.inverse().unwrap();
        let v = v * B.inverse().unwrap();

        // Ensure (u, v) is a valid alternate Montgomery element.
        {
            // Enforce v^2 == u^3 + A * u^2 + B * u
            let v2 = v.square();
            let u2 = u.square();
            let u3 = u2 * u;
            assert_eq!(v2, u3 + (a * u2) + (b * u));
        }

        (u, v)
    };

    assert_eq!(u, u_reconstructed);
    assert_eq!(v, v_reconstructed);

    let fq_element_reconstructed = {
        let x = u_reconstructed;

        // Let u = D.
        let u = <EdwardsParameters as TwistedEdwardsParameters>::EDWARDS_D;

        {
            // Verify u is a quadratic nonresidue.
            assert!(u.legendre().is_qnr());

            // Verify that x != -A.
            assert_ne!(x, -a);

            // Verify that if y is 0, then x is 0.
            if y.is_zero() {
                assert!(x.is_zero());
            }

            // Verify -ux(x + A) is a residue.
            assert_eq!((-(u * x) * (x + a)).legendre(), LegendreSymbol::QuadraticResidue);
        }

        println!("\ngroup legendre - {:?}", y.legendre());

        // Let value1 = sqrt(-x / ((x + A) * u)).
        let numerator = -x;
        let denominator = (x + a) * u;
        let value1 = (numerator * denominator.inverse().unwrap()).sqrt();

        // Let value2 = sqrt(-(x + A) / ux)).
        let numerator = -x - a;
        let denominator = x * u;
        let value2 = (numerator * denominator.inverse().unwrap()).sqrt();

        let mut recovered_value = None;

        if let Some(value) = value1 {
            if fq_element == value {
                println!("SUCCESS 1");
                recovered_value = Some(value);
            } else if fq_element == -value {
                println!("SUCCESS 2");
                recovered_value = Some(-value);
            }
        }

        if let Some(value) = value2 {
            if fq_element == value {
                println!("SUCCESS 3");
                recovered_value = Some(value)
            } else if fq_element == -value {
                println!("SUCCESS 4");
                recovered_value = Some(-value);
            }
        }

        if recovered_value.is_none() {
            println!("FAILED");
            panic!()
        }

        recovered_value.unwrap()
    };

    let fr_element_reconstructed = {
        let output = Fr::from_random_bytes(&to_bytes_le![fq_element_reconstructed].unwrap());
        assert!(output.is_some());
        output.unwrap()
    };

    assert_eq!(fr_element, fr_element_reconstructed);
}
