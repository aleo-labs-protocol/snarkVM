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
    impl_edwards_curve_serializer,
    templates::twisted_edwards_extended::Projective,
    traits::{AffineCurve, ProjectiveCurve, TwistedEdwardsParameters as Parameters},
};
use snarkvm_fields::{Field, One, PrimeField, SquareRootField, Zero};
use snarkvm_utilities::{FromBytes, ToBytes, bititerator::BitIteratorBE, rand::Uniform, serialize::*};

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    io::{Read, Result as IoResult, Write},
    ops::{Mul, Neg},
};

use rand::{
    Rng,
    RngExt,
    distr::{Distribution, StandardUniform},
};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Affine<P: Parameters> {
    pub x: P::BaseField,
    pub y: P::BaseField,
    pub t: P::BaseField,
}

impl<P: Parameters> Affine<P> {
    #[inline]
    pub fn new(x: P::BaseField, y: P::BaseField, t: P::BaseField) -> Self {
        Self { x, y, t }
    }
}

impl<P: Parameters> Zero for Affine<P> {
    #[inline]
    fn zero() -> Self {
        Self::new(P::BaseField::zero(), P::BaseField::one(), P::BaseField::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.x.is_zero() & self.y.is_one()
    }
}

impl<P: Parameters> PartialEq<Projective<P>> for Affine<P> {
    fn eq(&self, other: &Projective<P>) -> bool {
        other.eq(self)
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
        write!(f, "Affine(x={}, y={})", self.x, self.y)
    }
}

impl<P: Parameters> AffineCurve for Affine<P> {
    type BaseField = P::BaseField;
    type Coordinates = (Self::BaseField, Self::BaseField);
    type Projective = Projective<P>;
    type ScalarField = P::ScalarField;

    /// Initializes a new affine group element from the given coordinates.
    fn from_coordinates(coordinates: Self::Coordinates) -> Option<Self> {
        let (x, y) = coordinates;
        let point = Self { x, y, t: x * y };
        // Check that the point is on the curve, and in the correct subgroup.
        match point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve() {
            true => Some(point),
            false => None,
        }
    }

    /// Initializes a new affine group element from the given coordinates.
    /// Note: The resulting point is **not** enforced to be on the curve or in the correct subgroup.
    fn from_coordinates_unchecked(coordinates: Self::Coordinates) -> Self {
        let (x, y) = coordinates;
        Self { x, y, t: x * y }
    }

    #[inline]
    fn cofactor() -> &'static [u64] {
        P::COFACTOR
    }

    #[inline]
    fn prime_subgroup_generator() -> Self {
        Self::new(
            P::AFFINE_GENERATOR_COEFFS.0,
            P::AFFINE_GENERATOR_COEFFS.1,
            P::AFFINE_GENERATOR_COEFFS.0 * P::AFFINE_GENERATOR_COEFFS.1,
        )
    }

    #[inline]
    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::BaseField::from_random_bytes_with_flags::<EdwardsFlags>(bytes).and_then(|(x, flags)| {
            // If x is valid and is zero, then parse this point as infinity.
            if x.is_zero() { Some(Self::zero()) } else { Self::from_x_coordinate(x, flags.is_positive()) }
        })
    }

    /// Attempts to construct an affine point given an x-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    #[inline]
    fn from_x_coordinate(x: Self::BaseField, greatest: bool) -> Option<Self> {
        // y = sqrt( (a * x^2 - 1)  / (d * x^2 - 1) )
        let x2 = x.square();
        let one = Self::BaseField::one();
        let numerator = P::mul_by_a(&x2) - one;
        let denominator = P::EDWARDS_D * x2 - one;
        let y2 = denominator.inverse().map(|denom| denom * numerator);
        y2.and_then(|y2| y2.sqrt()).map(|y| {
            let negy = -y;
            let y = if (y < negy) ^ greatest { y } else { negy };
            Self::new(x, y, x * y)
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
        Self::from_x_coordinate(x, false).map(|p1| (p1, Self::new(p1.x, -p1.y, -p1.t)))
    }

    /// Attempts to construct an affine point given a y-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    #[inline]
    fn from_y_coordinate(y: Self::BaseField, greatest: bool) -> Option<Self> {
        // x = sqrt( (1 - y^2) / (a - d * y^2) )
        let y2 = y.square();
        let one = Self::BaseField::one();
        let numerator = one - y2;
        let denominator = P::mul_by_a(&one) - (P::EDWARDS_D * y2);
        let x2 = denominator.inverse().map(|denom| denom * numerator);
        x2.and_then(|x2| x2.sqrt()).map(|x| {
            let negx = -x;
            let x = if (x < negx) ^ greatest { x } else { negx };
            Self::new(x, y, x * y)
        })
    }

    #[inline]
    fn mul_bits(&self, bits: impl Iterator<Item = bool>) -> Projective<P> {
        let mut res = Projective::zero();
        for i in bits {
            res.double_in_place();
            if i {
                res.add_assign_mixed(self)
            }
        }
        res
    }

    fn mul_by_cofactor_to_projective(&self) -> Self::Projective {
        self.mul_bits(BitIteratorBE::new(P::COFACTOR))
    }

    fn mul_by_cofactor_inv(&self) -> Self {
        (*self * P::COFACTOR_INV).into()
    }

    fn to_projective(&self) -> Projective<P> {
        (*self).into()
    }

    fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
        self.mul_bits(BitIteratorBE::new(P::ScalarField::characteristic())).is_zero()
    }

    fn to_x_coordinate(&self) -> Self::BaseField {
        self.x
    }

    fn to_y_coordinate(&self) -> Self::BaseField {
        self.y
    }

    /// Checks that the current point is on the elliptic curve.
    fn is_on_curve(&self) -> bool {
        let x2 = self.x.square();
        let y2 = self.y.square();

        let lhs = y2 + P::mul_by_a(&x2);
        let rhs = P::BaseField::one() + (P::EDWARDS_D * (x2 * y2));

        lhs == rhs
    }

    /// Performs the first half of batch addition in-place.
    fn batch_add_loop_1(a: &mut Self, b: &mut Self, _half: &Self::BaseField, inversion_tmp: &mut Self::BaseField) {
        if !a.is_zero() && !b.is_zero() {
            let y1y2 = a.y * b.y;
            let x1x2 = a.x * b.x;

            a.x = (a.x + a.y) * (b.x + b.y) - y1y2 - x1x2;
            a.y = y1y2;
            if !P::EDWARDS_A.is_zero() {
                a.y -= &P::mul_by_a(&x1x2);
            }

            let dx1x2y1y2 = P::EDWARDS_D * y1y2 * x1x2;

            let inversion_mul_d = *inversion_tmp * dx1x2y1y2;

            a.x *= &(*inversion_tmp - inversion_mul_d);
            a.y *= &(*inversion_tmp + inversion_mul_d);

            b.x = Self::BaseField::one() - dx1x2y1y2.square();

            *inversion_tmp *= &b.x;
            b.t = b.x * b.y;
        }
    }

    /// Performs the second half of batch addition in-place.
    fn batch_add_loop_2(a: &mut Self, b: Self, inversion_tmp: &mut Self::BaseField) {
        if a.is_zero() {
            *a = b;
        } else if !b.is_zero() {
            a.x *= *inversion_tmp;
            a.y *= *inversion_tmp;
            *inversion_tmp *= &b.x;
            a.t = a.x * a.y;
        }
    }
}

impl<P: Parameters> Neg for Affine<P> {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(-self.x, self.y, -self.t)
    }
}

impl<P: Parameters> Mul<P::ScalarField> for Affine<P> {
    type Output = Projective<P>;

    fn mul(self, other: P::ScalarField) -> Self::Output {
        self.mul_bits(BitIteratorBE::new(other.to_bigint()))
    }
}

impl<P: Parameters> ToBytes for Affine<P> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.x.write_le(&mut writer)?;
        self.y.write_le(&mut writer)
    }
}

impl<P: Parameters> FromBytes for Affine<P> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let x = P::BaseField::read_le(&mut reader)?;
        let y = P::BaseField::read_le(&mut reader)?;
        Ok(Self::new(x, y, x * y))
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

// The projective point X, Y, T, Z is represented in the affine coordinates as X/Z, Y/Z.
impl<P: Parameters> From<Projective<P>> for Affine<P> {
    fn from(p: Projective<P>) -> Affine<P> {
        if p.is_zero() {
            Affine::zero()
        } else if p.z.is_one() {
            // If Z is one, the point is already normalized.
            Affine::new(p.x, p.y, p.t)
        } else {
            // Z is nonzero, so it must have an inverse in a field.
            let z_inv = p.z.inverse().unwrap();
            let x = p.x * z_inv;
            let y = p.y * z_inv;
            let t = p.t * z_inv;
            Affine::new(x, y, t)
        }
    }
}

impl_edwards_curve_serializer!(Parameters);
