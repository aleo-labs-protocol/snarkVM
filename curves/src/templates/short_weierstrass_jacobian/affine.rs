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
    impl_sw_curve_serializer,
    templates::short_weierstrass_jacobian::Projective,
    traits::{AffineCurve, ProjectiveCurve, ShortWeierstrassParameters as Parameters},
};
use snarkvm_fields::{Field, One, SquareRootField, Zero};
use snarkvm_utilities::{FromBytes, ToBytes, bititerator::BitIteratorBE, rand::Uniform, serialize::*};

use rand::{
    Rng,
    RngExt,
    distr::{Distribution, StandardUniform},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    io::{Error, ErrorKind, Read, Result as IoResult, Write},
    ops::{Mul, Neg},
};

// The CUDA FFI reads this by bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Affine<P: Parameters> {
    pub x: P::BaseField,
    pub y: P::BaseField,
    pub infinity: bool,
}

impl<P: Parameters> Affine<P> {
    #[inline]
    pub const fn new(x: P::BaseField, y: P::BaseField, infinity: bool) -> Self {
        Self { x, y, infinity }
    }
}

impl<P: Parameters> Zero for Affine<P> {
    #[inline]
    fn zero() -> Self {
        Self::new(P::BaseField::zero(), P::BaseField::one(), true)
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.infinity
    }
}

impl<P: Parameters> Default for Affine<P> {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl<P: Parameters> Display for Affine<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if self.infinity { write!(f, "Affine(Infinity)") } else { write!(f, "Affine(x={}, y={})", self.x, self.y) }
    }
}

impl<P: Parameters> PartialEq<Projective<P>> for Affine<P> {
    fn eq(&self, other: &Projective<P>) -> bool {
        other.eq(self)
    }
}

impl<P: Parameters> AffineCurve for Affine<P> {
    type BaseField = P::BaseField;
    type Coordinates = (Self::BaseField, Self::BaseField, bool);
    type Projective = Projective<P>;
    type ScalarField = P::ScalarField;

    /// Initializes a new affine group element from the given coordinates.
    fn from_coordinates(coordinates: Self::Coordinates) -> Option<Self> {
        let (x, y, infinity) = coordinates;
        let point = Self { x, y, infinity };
        // Check that the point is on the curve, and in the correct subgroup.
        match point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
            true => Some(point),
            false => None,
        }
    }

    /// Initializes a new affine group element from the given coordinates.
    /// Note: The resulting point is **not** enforced to be on the curve or in the correct subgroup.
    fn from_coordinates_unchecked(coordinates: Self::Coordinates) -> Self {
        let (x, y, infinity) = coordinates;
        Self { x, y, infinity }
    }

    #[inline]
    fn cofactor() -> &'static [u64] {
        P::COFACTOR
    }

    #[inline]
    fn prime_subgroup_generator() -> Self {
        Self::new(P::AFFINE_GENERATOR_COEFFS.0, P::AFFINE_GENERATOR_COEFFS.1, false)
    }

    #[inline]
    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::BaseField::from_random_bytes_with_flags::<SWFlags>(bytes).and_then(|(x, flags)| {
            // If x is valid and is zero and only the infinity flag is set, then parse this
            // point as infinity. For all other choices, get the original point.
            if x.is_zero() && flags.is_infinity() {
                Some(Self::zero())
            } else if let Some(is_positive_y) = flags.is_positive() {
                Self::from_x_coordinate(x, is_positive_y) // Unwrap is safe because it's not zero.
            } else {
                None
            }
        })
    }

    /// Attempts to construct an affine point given an x-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    fn from_x_coordinate(x: Self::BaseField, greatest: bool) -> Option<Self> {
        // Compute x^3 + ax + b
        let x3b = P::add_b(&((x.square() * x) + P::mul_by_a(&x)));

        x3b.sqrt().map(|y| {
            let negy = -y;

            let y = if (y < negy) ^ greatest { y } else { negy };
            Self::new(x, y, false)
        })
    }

    /// Attempts to construct both possible affine points given an x-coordinate.
    /// Points are not guaranteed to be in the prime order subgroup.
    ///
    /// The affine points returned should be in lexicographically growing order.
    ///
    /// Calling this should be equivalent (but likely more performant) to
    /// `(AffineCurve::from_x_coordinate(x, false), AffineCurve::from_x_coordinate(x, true))`.
    #[inline]
    fn pair_from_x_coordinate(x: Self::BaseField) -> Option<(Self, Self)> {
        Self::from_x_coordinate(x, false).map(|p1| (p1, Self::new(p1.x, -p1.y, false)))
    }

    /// Attempts to construct an affine point given a y-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    fn from_y_coordinate(_y: Self::BaseField, _greatest: bool) -> Option<Self> {
        unimplemented!()
    }

    fn mul_bits(&self, bits: impl Iterator<Item = bool>) -> Projective<P> {
        let mut output = Projective::zero();
        for i in bits.skip_while(|b| !b) {
            output.double_in_place();
            if i {
                output.add_assign_mixed(self);
            }
        }
        output
    }

    fn mul_by_cofactor_to_projective(&self) -> Self::Projective {
        self.mul_bits(BitIteratorBE::new_without_leading_zeros(P::COFACTOR))
    }

    fn mul_by_cofactor_inv(&self) -> Self {
        (*self * P::COFACTOR_INV).into()
    }

    #[inline]
    fn to_projective(&self) -> Projective<P> {
        (*self).into()
    }

    fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
        P::is_in_correct_subgroup_assuming_on_curve(self)
    }

    fn to_x_coordinate(&self) -> Self::BaseField {
        self.x
    }

    fn to_y_coordinate(&self) -> Self::BaseField {
        self.y
    }

    /// Checks that the current point is on the elliptic curve.
    fn is_on_curve(&self) -> bool {
        if self.is_zero() {
            true
        } else {
            // Check that the point is on the curve
            let y2 = self.y.square();
            let x3b = P::add_b(&((self.x.square() * self.x) + P::mul_by_a(&self.x)));
            y2 == x3b
        }
    }

    /// Performs the first half of batch addition in-place:
    ///     `lambda` := `(y2 - y1) / (x2 - x1)`,
    /// for two given affine points.
    fn batch_add_loop_1(a: &mut Self, b: &mut Self, half: &Self::BaseField, inversion_tmp: &mut Self::BaseField) {
        if a.is_zero() || b.is_zero() {
        } else if a.x == b.x {
            // Double
            // In our model, we consider self additions rare.
            // So we consider it inconsequential to make them more expensive
            // This costs 1 modular mul more than a standard squaring,
            // and one amortised inversion
            if a.y == b.y {
                // Compute one half (1/2) and cache it.

                let x_sq = b.x.square();
                b.x -= &b.y; // x - y
                a.x = b.y.double(); // denominator = 2y
                a.y = x_sq.double() + x_sq + P::WEIERSTRASS_A; // numerator = 3x^2 + a
                b.y -= &(a.y * half); // y - (3x^2 + a)/2
                a.y *= *inversion_tmp; // (3x^2 + a) * tmp
                *inversion_tmp *= &a.x; // update tmp
            } else {
                // No inversions take place if either operand is zero
                a.infinity = true;
                b.infinity = true;
            }
        } else {
            // We can recover x1 + x2 from this. Note this is never 0.
            a.x -= &b.x; // denominator = x1 - x2
            a.y -= &b.y; // numerator = y1 - y2
            a.y *= *inversion_tmp; // (y1 - y2)*tmp
            *inversion_tmp *= &a.x // update tmp
        }
    }

    /// Performs the second half of batch addition in-place:
    ///     `x3` := `lambda^2 - x1 - x2`
    ///     `y3` := `lambda * (x1 - x3) - y1`.
    fn batch_add_loop_2(a: &mut Self, b: Self, inversion_tmp: &mut Self::BaseField) {
        if a.is_zero() {
            *a = b;
        } else if !b.is_zero() {
            let lambda = a.y * *inversion_tmp;
            *inversion_tmp *= &a.x; // Remove the top layer of the denominator

            // x3 = l^2 - x1 - x2 or for squaring: 2y + l^2 + 2x - 2y = l^2 - 2x
            a.x += &b.x.double();
            a.x = lambda.square() - a.x;
            // y3 = l*(x2 - x3) - y2 or
            // for squaring: (3x^2 + a)/2y(x - y - x3) - (y - (3x^2 + a)/2) = l*(x - x3) - y
            a.y = lambda * (b.x - a.x) - b.y;
        }
    }
}

impl<P: Parameters> Neg for Affine<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        if !self.is_zero() { Self::new(self.x, -self.y, false) } else { self }
    }
}

impl<P: Parameters> Mul<P::ScalarField> for Affine<P> {
    type Output = Projective<P>;

    fn mul(self, other: P::ScalarField) -> Self::Output {
        self.to_projective().mul(other)
    }
}

impl<P: Parameters> ToBytes for Affine<P> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.x.write_le(&mut writer)?;
        self.y.write_le(&mut writer)?;
        self.infinity.write_le(writer)
    }
}

impl<P: Parameters> FromBytes for Affine<P> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let x = P::BaseField::read_le(&mut reader)?;
        let y = P::BaseField::read_le(&mut reader)?;
        let infinity = bool::read_le(&mut reader)?;

        if infinity != x.is_zero() && y.is_one() {
            return Err(Error::new(ErrorKind::InvalidData, "Infinity flag is not valid"));
        }
        Ok(Self::new(x, y, infinity))
    }
}

impl<P: Parameters> Distribution<Affine<P>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Affine<P> {
        loop {
            let x = P::BaseField::rand(rng);
            let greatest = rng.random();

            if let Some(p) = Affine::from_x_coordinate(x, greatest) {
                return p.mul_by_cofactor();
            }
        }
    }
}

// The projective point X, Y, Z is represented in the affine coordinates as X/Z^2, Y/Z^3.
impl<P: Parameters> From<Projective<P>> for Affine<P> {
    #[inline]
    fn from(p: Projective<P>) -> Affine<P> {
        if p.is_zero() {
            Affine::zero()
        } else if p.z.is_one() {
            // If Z is one, the point is already normalized.
            Affine::new(p.x, p.y, false)
        } else {
            // Z is nonzero, so it must have an inverse in a field.
            let zinv = p.z.inverse().unwrap();
            let zinv_squared = zinv.square();

            // X/Z^2
            let x = p.x * zinv_squared;

            // Y/Z^3
            let y = p.y * (zinv_squared * zinv);

            Affine::new(x, y, false)
        }
    }
}

impl_sw_curve_serializer!(Parameters);
