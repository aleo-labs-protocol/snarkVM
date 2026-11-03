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

use core::fmt::Debug;
use std::io::Cursor;

use proptest::{prelude::any, test_runner::TestRunner};

use crate::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{One, PrimeField, Zero};
use snarkvm_utilities::{
    Compress,
    Validate,
    rand::{TestRng, Uniform},
    serialize::{CanonicalDeserialize, CanonicalSerialize},
};

#[allow(clippy::eq_op)]
pub fn affine_test<G: AffineCurve>(a: G) {
    let zero = G::zero();
    let fr_zero = G::ScalarField::zero();
    let fr_one = G::ScalarField::one();
    assert!(zero == zero);
    assert!(zero.is_zero()); // true
    assert_eq!(a * fr_one, a);
    assert_eq!(a.mul(fr_zero), zero);

    // a == a
    assert!(a == a);
    assert_eq!(a.mul_by_cofactor_to_projective(), a.mul_by_cofactor());
    assert_eq!(a.mul_by_cofactor_inv().mul_by_cofactor(), a);
}

#[allow(clippy::eq_op)]
pub fn projective_test<G: ProjectiveCurve>(a: G, mut b: G, rng: &mut TestRng) {
    let zero = G::zero();
    let fr_zero = G::ScalarField::zero();
    let fr_one = G::ScalarField::one();
    let fr_two = fr_one + fr_one;
    assert!(zero == zero);
    assert!(zero.is_zero()); // true
    assert_eq!(a.mul(fr_one), a);
    assert_eq!(a.mul(fr_two), a + a);
    assert_eq!(a.mul(fr_zero), zero);
    assert_eq!(a.mul(fr_zero) - a, -a);
    assert_eq!(a.mul(fr_one) - a, zero);
    assert_eq!(a.mul(fr_two) - a, a);

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

    // Check that double_in_place and double give the same result
    let original_b = b;
    b.double_in_place();
    assert_eq!(original_b.double(), b);

    let fr_rand1 = G::ScalarField::rand(rng);
    let fr_rand2 = G::ScalarField::rand(rng);
    let a_rand1 = a.mul(fr_rand1);
    let a_rand2 = a.mul(fr_rand2);
    let fr_three = fr_two + fr_rand1;
    let a_two = a.mul(fr_two);
    assert_eq!(a_two, a.double(), "(a * 2)  != a.double()");
    let a_six = a.mul(fr_three * fr_two);
    assert_eq!(a_two.mul(fr_three), a_six, "(a * 2) * 3 != a * (2 * 3)");

    assert_eq!(a_rand1.mul(fr_rand2), a_rand2.mul(fr_rand1), "(a * r1) * r2 != (a * r2) * r1");
    assert_eq!(a_rand2.mul(fr_rand1), a.mul(fr_rand1 * fr_rand2), "(a * r2) * r1 != a * (r1 * r2)");
    assert_eq!(a_rand1.mul(fr_rand2), a.mul(fr_rand1 * fr_rand2), "(a * r1) * r2 != a * (r1 * r2)");
}

/// Every combination of `Compress` and `Validate` that a caller can ask for.
///
/// Neither enum implements `Debug`, so each mode carries the name it is reported
/// under when an assertion below fails.
const SERIALIZATION_MODES: [(Compress, Validate, &str); 4] = [
    (Compress::Yes, Validate::Yes, "Compress::Yes, Validate::Yes"),
    (Compress::Yes, Validate::No, "Compress::Yes, Validate::No"),
    (Compress::No, Validate::Yes, "Compress::No, Validate::Yes"),
    (Compress::No, Validate::No, "Compress::No, Validate::No"),
];

/// Asserts that `value` survives serialization followed by deserialization
/// unchanged, in every mode, and that `serialized_size` agrees with the number
/// of bytes actually written.
///
/// `label` identifies the point in the failure message; a shrunk proptest case
/// reports a scalar, and the degenerate cases report a name.
fn assert_round_trips<T>(value: &T, label: &str)
where
    T: CanonicalSerialize + CanonicalDeserialize + Eq + Debug,
{
    for (compress, validate, mode) in SERIALIZATION_MODES {
        let claimed_size = value.serialized_size(compress);
        let mut bytes = Vec::with_capacity(claimed_size);
        value
            .serialize_with_mode(&mut bytes, compress)
            .unwrap_or_else(|e| panic!("{label}: serialization failed ({mode}): {e:?}"));

        assert_eq!(
            bytes.len(),
            claimed_size,
            "{label}: serialized_size reported {claimed_size} bytes ({mode}), but {} were written",
            bytes.len()
        );

        let recovered = T::deserialize_with_mode(&mut Cursor::new(&bytes[..]), compress, validate)
            .unwrap_or_else(|e| panic!("{label}: the deserializer rejected this library's own output ({mode}): {e:?}"));

        assert_eq!(&recovered, value, "{label}: round trip changed the value ({mode})");
    }
}

/// Asserts that a point round trips in both its affine and its projective form.
fn assert_point_round_trips<G: AffineCurve>(point: G, label: &str) {
    assert_round_trips(&point, &format!("{label} (affine)"));
    assert_round_trips(&point.to_projective(), &format!("{label} (projective)"));
}

/// Serializing a curve point and deserializing the result must return that same
/// point, for every point the serializer accepts and every mode the caller can
/// ask for.
///
/// Every point covered here is in the prime-order subgroup. Each round trip is
/// asserted under `Validate::Yes` as well as `Validate::No`, and `Validate::Yes`
/// rejects anything outside the subgroup, so the order-2 and order-4 points
/// cannot be driven through this harness. The per-curve-family harnesses cover
/// them instead, under `Validate::No`.
pub fn serialization_round_trip_test<G: AffineCurve>() {
    degenerate_serialization_round_trip_test::<G>();

    let mut runner = TestRunner::deterministic();
    runner
        .run(&any::<[u8; 32]>(), |seed| {
            let scalar = G::ScalarField::from_bytes_le_mod_order(&seed);
            assert_point_round_trips((G::prime_subgroup_generator() * scalar).to_affine(), &format!("{scalar}"));
            Ok(())
        })
        .unwrap();
}

/// The points a random scalar will not produce in any practical number of runs.
///
/// The identity is the one that matters most: it is the only point whose
/// coordinates carry no information, so it is the point whose encoding a
/// canonicality check is most likely to tighten, and a random scalar reaches it
/// with probability `1/r`.
fn degenerate_serialization_round_trip_test<G: AffineCurve>() {
    let generator = G::prime_subgroup_generator();

    assert_point_round_trips(G::zero(), "identity");
    assert_point_round_trips(generator, "generator");
    assert_point_round_trips(-generator, "negated generator");

    // Small multiples, which shrinking drives towards and which a proptest seed
    // of 32 random bytes will not otherwise produce.
    let mut multiple = G::Projective::zero();
    for i in 0..8u8 {
        assert_point_round_trips(multiple.to_affine(), &format!("generator * {i}"));
        multiple.add_assign_mixed(&generator);
    }

    // The largest scalar, reached from the other end of the field.
    assert_point_round_trips((generator * (-G::ScalarField::one())).to_affine(), "generator * (r - 1)");

    // A projective point that has not been normalized takes a different path
    // through serialization than one that has.
    let unnormalized = generator.to_projective().double();
    assert!(!unnormalized.is_normalized(), "the doubled generator was expected to be unnormalized");
    assert_round_trips(&unnormalized, "unnormalized projective");
}
