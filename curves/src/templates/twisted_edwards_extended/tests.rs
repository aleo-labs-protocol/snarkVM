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

use std::io::Cursor;

use super::{Affine, Projective};

use snarkvm_utilities::{
    Compress,
    TestRng,
    ToBytes,
    Validate,
    rand::Uniform,
    serialize::{CanonicalDeserialize, CanonicalSerialize},
    to_bytes_le,
};

use crate::traits::{AffineCurve, MontgomeryParameters, ProjectiveCurve, TwistedEdwardsParameters};
use snarkvm_fields::{Field, One, PrimeField, Zero};

pub const ITERATIONS: usize = 10;

pub fn montgomery_conversion_test<P>()
where
    P: TwistedEdwardsParameters,
{
    // A = 2 * (a + d) / (a - d)
    let a =
        P::BaseField::one().double() * (P::EDWARDS_A + P::EDWARDS_D) * (P::EDWARDS_A - P::EDWARDS_D).inverse().unwrap();
    // B = 4 / (a - d)
    let b = P::BaseField::one().double().double() * (P::EDWARDS_A - P::EDWARDS_D).inverse().unwrap();

    assert_eq!(a, P::MontgomeryParameters::MONTGOMERY_A);
    assert_eq!(b, P::MontgomeryParameters::MONTGOMERY_B);
}

pub fn edwards_test<P: TwistedEdwardsParameters>(rng: &mut TestRng)
where
    P::BaseField: PrimeField,
{
    edwards_curve_serialization_test::<P>(rng);
    edwards_from_random_bytes::<P>(rng);
    edwards_from_x_and_y_coordinates::<P>(rng);
    edwards_non_canonical_identity_is_rejected::<P>();
    edwards_order_two_point_round_trips::<P>();
}

/// Returns `(0, -1)`, the order-two point.
///
/// `x = 0` gives `y^2 = 1` on every twisted Edwards curve, so this point and the
/// identity `(0, 1)` are the two solutions there, and both are on the curve.
fn order_two_point<P: TwistedEdwardsParameters>() -> Affine<P> {
    Affine::<P>::new(P::BaseField::zero(), -P::BaseField::one(), P::BaseField::zero())
}

/// The identity must have exactly one compressed encoding.
///
/// A compressed encoding carries `x` plus a flag naming the sign of `y`. At
/// `x = 0` the flag is the only thing separating the identity from
/// [`order_two_point`], so a deserializer that ignores it there gives the
/// identity two spellings, and anything that hashes those bytes disagrees with
/// anything that hashes a re-serialization.
///
/// This is the twisted Edwards counterpart of
/// `sw_non_canonical_infinity_is_rejected`.
pub fn edwards_non_canonical_identity_is_rejected<P: TwistedEdwardsParameters>() {
    // The canonical identity encoding: x = 0 carrying the default flag.
    let mut canonical = Vec::new();
    Affine::<P>::zero().serialize_with_mode(&mut canonical, Compress::Yes).unwrap();

    // The same x with the opposite flag, which lives in the high bit of the
    // last byte. This names (0, -1), not the identity.
    let mut non_canonical = canonical.clone();
    let last = non_canonical.len() - 1;
    non_canonical[last] ^= 1 << 7;
    assert_ne!(non_canonical, canonical);

    // Validate does not implement Debug, and the mode matters to the report:
    // the identity is in the prime-order subgroup, so this must be settled by
    // the encoding rather than by the subgroup check.
    for (validate, mode) in [(Validate::Yes, "Validate::Yes"), (Validate::No, "Validate::No")] {
        // The canonical encoding must keep working. A fix that rejected both
        // would break every serialized identity in existence, and that should
        // fail loudly rather than pass quietly.
        let point = Affine::<P>::deserialize_with_mode(Cursor::new(&canonical[..]), Compress::Yes, validate).unwrap();
        assert!(point.is_zero(), "the canonical identity encoding must still deserialize ({mode})");

        // The flag-set encoding may be rejected, or may decode to (0, -1). What
        // it must never be is a second way to write the identity.
        if let Ok(point) = Affine::<P>::deserialize_with_mode(Cursor::new(&non_canonical[..]), Compress::Yes, validate)
        {
            assert!(
                !point.is_zero(),
                "a non-canonical identity encoding was accepted ({mode}).\n\
                 The encodings differ only in the flag byte, {:#04x} against the canonical {:#04x},\n\
                 so those are two ways to write one value.",
                non_canonical[last],
                canonical[last],
            );
        }
    }
}

/// The serializer accepts [`order_two_point`], so the deserializer must return
/// it unchanged.
///
/// It sits outside the prime-order subgroup, so `Validate::Yes` rejects it by
/// design; the round trip is asserted under `Validate::No`, where the subgroup
/// check is not what is being measured.
pub fn edwards_order_two_point_round_trips<P: TwistedEdwardsParameters>() {
    let order_two = order_two_point::<P>();
    assert!(order_two.is_on_curve(), "(0, -1) must be on the curve");
    assert!(!order_two.is_zero(), "(0, -1) must be distinct from the identity");
    assert!(
        !order_two.is_in_correct_subgroup_assuming_on_curve(),
        "(0, -1) has order two, so it must be outside the prime-order subgroup"
    );

    for (compress, mode) in [(Compress::Yes, "Compress::Yes"), (Compress::No, "Compress::No")] {
        let mut bytes = Vec::new();
        order_two.serialize_with_mode(&mut bytes, compress).unwrap();

        let recovered = Affine::<P>::deserialize_with_mode(Cursor::new(&bytes[..]), compress, Validate::No).unwrap();
        assert_eq!(recovered, order_two, "(0, -1) did not survive a round trip ({mode})");
    }
}

pub fn edwards_curve_serialization_test<P: TwistedEdwardsParameters>(rng: &mut TestRng) {
    let modes = [
        (Compress::Yes, Validate::Yes),
        (Compress::No, Validate::No),
        (Compress::Yes, Validate::No),
        (Compress::No, Validate::Yes),
    ];
    for (compress, validate) in modes {
        let buf_size = Affine::<P>::zero().serialized_size(compress);

        for _ in 0..10 {
            let a = Projective::<P>::rand(rng);
            let a = a.to_affine();
            {
                let mut serialized = vec![0; buf_size];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a.serialize_with_mode(&mut cursor, compress).unwrap();

                let mut cursor = Cursor::new(&serialized[..]);
                let b = Affine::<P>::deserialize_with_mode(&mut cursor, compress, validate).unwrap();
                assert_eq!(a, b);
            }

            {
                let mut a_copy = a;
                // If we negate the y-coordinate, the point is no longer in the prime-order subgroup,
                // and so this should error when `validate == Validate::Yes`.
                a_copy.y = -a.y;
                a_copy.t = a_copy.x * a_copy.y;
                let mut serialized = vec![0; buf_size];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a_copy.serialize_with_mode(&mut cursor, compress).unwrap();
                let mut cursor = Cursor::new(&serialized[..]);

                let b = Affine::<P>::deserialize_with_mode(&mut cursor, compress, validate);
                if validate == Validate::Yes {
                    b.unwrap_err();
                } else {
                    assert_eq!(a_copy, b.unwrap());
                }
            }

            {
                let a = Affine::<P>::zero();
                let mut serialized = vec![0; buf_size];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a.serialize_with_mode(&mut cursor, compress).unwrap();
                let mut cursor = Cursor::new(&serialized[..]);
                let b = Affine::<P>::deserialize_with_mode(&mut cursor, compress, validate).unwrap();
                assert_eq!(a, b);
            }

            {
                let a = Affine::<P>::zero();
                let mut serialized = vec![0; buf_size - 1];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a.serialize_with_mode(&mut cursor, compress).unwrap_err();
            }

            {
                let serialized = vec![0; buf_size - 1];
                let mut cursor = Cursor::new(&serialized[..]);
                Affine::<P>::deserialize_with_mode(&mut cursor, compress, validate).unwrap_err();
            }

            {
                let mut serialized = vec![0; a.uncompressed_size()];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a.serialize_uncompressed(&mut cursor).unwrap();

                let mut cursor = Cursor::new(&serialized[..]);
                let b = Affine::<P>::deserialize_uncompressed(&mut cursor).unwrap();
                assert_eq!(a, b);
            }

            {
                let mut a_copy = a;
                a_copy.y = -a.y;
                a_copy.t = a_copy.x * a_copy.y;
                let mut serialized = vec![0; a.uncompressed_size()];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a_copy.serialize_uncompressed(&mut cursor).unwrap();
                let mut cursor = Cursor::new(&serialized[..]);
                let _ = Affine::<P>::deserialize_uncompressed(&mut cursor).unwrap_err();
                let b = Affine::<P>::deserialize_uncompressed_unchecked(&*serialized).unwrap();
                assert_eq!(a_copy, b);
            }

            {
                let a = Affine::<P>::zero();
                let mut serialized = vec![0; a.uncompressed_size()];
                let mut cursor = Cursor::new(&mut serialized[..]);
                a.serialize_uncompressed(&mut cursor).unwrap();
                let mut cursor = Cursor::new(&serialized[..]);
                let b = Affine::<P>::deserialize_uncompressed(&mut cursor).unwrap();
                assert_eq!(a, b);
            }
        }
    }
}

pub fn edwards_from_random_bytes<P: TwistedEdwardsParameters>(rng: &mut TestRng)
where
    P::BaseField: PrimeField,
{
    let buf_size = Affine::<P>::zero().compressed_size();

    for _ in 0..ITERATIONS {
        let a = Projective::<P>::rand(rng);
        let a = a.to_affine();
        {
            let mut serialized = vec![0; buf_size];
            let mut cursor = Cursor::new(&mut serialized[..]);
            a.serialize_compressed(&mut cursor).unwrap();

            let mut cursor = Cursor::new(&serialized[..]);
            let p1 = Affine::<P>::deserialize_compressed(&mut cursor).unwrap();
            let p2 = Affine::<P>::from_random_bytes(&serialized).unwrap();
            assert_eq!(p1, p2);
        }
    }

    for _ in 0..ITERATIONS {
        let biginteger = <<Affine<P> as AffineCurve>::BaseField as PrimeField>::BigInteger::rand(rng);
        let mut bytes = to_bytes_le![biginteger].unwrap();
        let mut g = Affine::<P>::from_random_bytes(&bytes);
        while g.is_none() {
            bytes.iter_mut().for_each(|i| *i = i.wrapping_sub(1));
            g = Affine::<P>::from_random_bytes(&bytes);
        }
        let _g = g.unwrap();
    }
}

pub fn edwards_from_x_and_y_coordinates<P: TwistedEdwardsParameters>(rng: &mut TestRng)
where
    P::BaseField: PrimeField,
{
    for _ in 0..ITERATIONS {
        let a = Projective::<P>::rand(rng);
        let a = a.to_affine();
        {
            let x = a.x;

            let a1 = Affine::<P>::from_x_coordinate(x, true).unwrap();
            let a2 = Affine::<P>::from_x_coordinate(x, false).unwrap();

            assert!(a == a1 || a == a2);

            let (b2, b1) = Affine::<P>::pair_from_x_coordinate(x).unwrap();

            assert_eq!(a1, b1);
            assert_eq!(a2, b2);
        }
        {
            let y = a.y;

            let a1 = Affine::<P>::from_y_coordinate(y, true).unwrap();
            let a2 = Affine::<P>::from_y_coordinate(y, false).unwrap();

            assert!(a == a1 || a == a2);
        }
    }
}
