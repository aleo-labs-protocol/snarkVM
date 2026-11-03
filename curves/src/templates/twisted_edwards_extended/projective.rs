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
    templates::twisted_edwards_extended::Affine,
    traits::{AffineCurve, ProjectiveCurve, TwistedEdwardsParameters as Parameters},
};
use snarkvm_fields::{Field, One, PrimeField, Zero, impl_add_sub_from_field_ref};
use snarkvm_utilities::{FromBytes, ToBytes, bititerator::BitIteratorBE, rand::Uniform};

use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use rand::{
    Rng,
    RngExt,
    distr::{Distribution, StandardUniform},
};
use std::io::{Read, Result as IoResult, Write};

#[derive(Copy, Clone, Debug)]
pub struct Projective<P: Parameters> {
    pub x: P::BaseField,
    pub y: P::BaseField,
    pub t: P::BaseField,
    pub z: P::BaseField,
}

impl<P: Parameters> Projective<P> {
    #[inline]
    pub const fn new(x: P::BaseField, y: P::BaseField, t: P::BaseField, z: P::BaseField) -> Self {
        Self { x, y, t, z }
    }
}

impl<P: Parameters> Zero for Projective<P> {
    fn zero() -> Self {
        Self::new(P::BaseField::zero(), P::BaseField::one(), P::BaseField::zero(), P::BaseField::one())
    }

    fn is_zero(&self) -> bool {
        self.x.is_zero() && self.y == self.z && !self.y.is_zero() && self.t.is_zero()
    }
}

impl<P: Parameters> Default for Projective<P> {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl<P: Parameters> Display for Projective<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.to_affine())
    }
}

impl<P: Parameters> Hash for Projective<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_affine().hash(state);
    }
}

impl<P: Parameters> Eq for Projective<P> {}

impl<P: Parameters> PartialEq for Projective<P> {
    fn eq(&self, other: &Self) -> bool {
        if self.is_zero() {
            return other.is_zero();
        }

        if other.is_zero() {
            return false;
        }

        // x1/z1 == x2/z2  <==> x1 * z2 == x2 * z1
        (self.x * other.z) == (other.x * self.z) && (self.y * other.z) == (other.y * self.z)
    }
}

impl<P: Parameters> PartialEq<Affine<P>> for Projective<P> {
    fn eq(&self, other: &Affine<P>) -> bool {
        if self.is_zero() {
            return other.is_zero();
        }

        if other.is_zero() {
            return false;
        }

        // x1/z1 == x2/z2  <==> x1 * z2 == x2 * z1
        self.x == (other.x * self.z) && self.y == (other.y * self.z)
    }
}

impl<P: Parameters> Distribution<Projective<P>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Projective<P> {
        loop {
            let x = P::BaseField::rand(rng);
            let greatest = rng.random();

            if let Some(p) = Affine::from_x_coordinate(x, greatest) {
                return p.mul_by_cofactor_to_projective();
            }
        }
    }
}

impl<P: Parameters> ToBytes for Projective<P> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.x.write_le(&mut writer)?;
        self.y.write_le(&mut writer)?;
        self.t.write_le(&mut writer)?;
        self.z.write_le(writer)
    }
}

impl<P: Parameters> FromBytes for Projective<P> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let x = P::BaseField::read_le(&mut reader)?;
        let y = P::BaseField::read_le(&mut reader)?;
        let t = P::BaseField::read_le(&mut reader)?;
        let z = P::BaseField::read_le(reader)?;
        Ok(Self::new(x, y, t, z))
    }
}

impl<P: Parameters> ProjectiveCurve for Projective<P> {
    type Affine = Affine<P>;
    type BaseField = P::BaseField;
    type ScalarField = P::ScalarField;

    fn prime_subgroup_generator() -> Self {
        Affine::prime_subgroup_generator().into()
    }

    fn is_normalized(&self) -> bool {
        self.z.is_one()
    }

    fn batch_normalization(v: &mut [Self]) {
        // Montgomery's Trick and Fast Implementation of Masked AES
        // Genelle, Prouff and Quisquater
        // Section 3.2

        // First pass: compute [a, ab, abc, ...]
        let mut prod = Vec::with_capacity(v.len());
        let mut tmp = P::BaseField::one();
        for g in v
            .iter_mut()
            // Ignore normalized elements
            .filter(|g| !g.is_normalized())
        {
            tmp.mul_assign(&g.z);
            prod.push(tmp);
        }

        // Invert `tmp`.
        tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

        // Second pass: iterate backwards to compute inverses
        for (g, s) in v
            .iter_mut()
            // Backwards
            .rev()
            // Ignore normalized elements
            .filter(|g| !g.is_normalized())
            // Backwards, skip last element, fill in one for last term.
            .zip(
                prod.into_iter()
                    .rev()
                    .skip(1)
                    .chain(Some(P::BaseField::one())),
            )
        {
            // tmp := tmp * g.z; g.z := tmp * s = 1/z
            let newtmp = tmp * g.z;
            g.z = tmp * s;
            tmp = newtmp;
        }

        // Perform affine transformations
        for g in v.iter_mut().filter(|g| !g.is_normalized()) {
            g.x *= &g.z; // x/z
            g.y *= &g.z;
            g.t *= &g.z;
            g.z = P::BaseField::one(); // z = 1
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn add_assign_mixed(&mut self, other: &Self::Affine) {
        // A = X1*X2
        let a = self.x * other.x;
        // B = Y1*Y2
        let b = self.y * other.y;
        // C = T1*d*T2
        let c = P::EDWARDS_D * self.t * other.t;
        // D = Z1
        let d = self.z;
        // E = (X1+Y1)*(X2+Y2)-A-B
        let e = (self.x + self.y) * (other.x + other.y) - a - b;
        // F = D-C
        let f = d - c;
        // G = D+C
        let g = d + c;
        // H = B-a*A
        let h = b - P::mul_by_a(&a);
        // X3 = E*F
        self.x = e * f;
        // Y3 = G*H
        self.y = g * h;
        // T3 = E*H
        self.t = e * h;
        // Z3 = F*G
        self.z = f * g;
    }

    #[inline]
    fn double(&self) -> Self {
        let mut result = *self;
        result.double_in_place();
        result
    }

    #[inline]
    fn double_in_place(&mut self) {
        // See "Twisted Edwards Curves Revisited"
        // Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson
        // 3.3 Doubling in E^e
        // Source: https://www.hyperelliptic.org/EFD/g1p/data/twisted/extended/doubling/dbl-2008-hwcd

        // A = X1^2
        let a = self.x.square();
        // B = Y1^2
        let b = self.y.square();
        // C = 2 * Z1^2
        let c = self.z.square().double();
        // D = a * A
        let d = P::mul_by_a(&a);
        // E = (X1 + Y1)^2 - A - B
        let e = (self.x + self.y).square() - a - b;
        // G = D + B
        let g = d + b;
        // F = G - C
        let f = g - c;
        // H = D - B
        let h = d - b;
        // X3 = E * F
        self.x = e * f;
        // Y3 = G * H
        self.y = g * h;
        // T3 = E * H
        self.t = e * h;
        // Z3 = F * G
        self.z = f * g;
    }

    fn to_affine(&self) -> Affine<P> {
        (*self).into()
    }
}

impl<P: Parameters> Neg for Projective<P> {
    type Output = Self;

    fn neg(mut self) -> Self {
        self.x = -self.x;
        self.t = -self.t;
        self
    }
}

impl_add_sub_from_field_ref!(Projective, Parameters);

impl<'a, P: Parameters> Add<&'a Self> for Projective<P> {
    type Output = Self;

    fn add(self, other: &'a Self) -> Self {
        let mut copy = self;
        copy += other;
        copy
    }
}

impl<'a, P: Parameters> AddAssign<&'a Self> for Projective<P> {
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, other: &'a Self) {
        // See "Twisted Edwards Curves Revisited"
        // Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson
        // 3.1 Unified Addition in E^e

        // A = x1 * x2
        let a = self.x * other.x;

        // B = y1 * y2
        let b = self.y * other.y;

        // C = d * t1 * t2
        let c = P::EDWARDS_D * self.t * other.t;

        // D = z1 * z2
        let d = self.z * other.z;

        // H = B - aA
        let h = b - P::mul_by_a(&a);

        // E = (x1 + y1) * (x2 + y2) - A - B
        let e = (self.x + self.y) * (other.x + other.y) - a - b;

        // F = D - C
        let f = d - c;

        // G = D + C
        let g = d + c;

        // x3 = E * F
        self.x = e * f;

        // y3 = G * H
        self.y = g * h;

        // t3 = E * H
        self.t = e * h;

        // z3 = F * G
        self.z = f * g;
    }
}

impl<'a, P: Parameters> Sub<&'a Self> for Projective<P> {
    type Output = Self;

    fn sub(self, other: &'a Self) -> Self {
        let mut copy = self;
        copy -= other;
        copy
    }
}

impl<'a, P: Parameters> SubAssign<&'a Self> for Projective<P> {
    fn sub_assign(&mut self, other: &'a Self) {
        *self += &(-(*other));
    }
}

impl<P: Parameters> Mul<P::ScalarField> for Projective<P> {
    type Output = Self;

    /// Performs scalar multiplication of this element.
    #[allow(clippy::suspicious_arithmetic_impl)]
    #[inline]
    fn mul(self, other: P::ScalarField) -> Self {
        let mut res = Self::zero();

        let mut found_one = false;

        for i in BitIteratorBE::new(other.to_bigint()) {
            if found_one {
                res.double_in_place();
            } else {
                found_one = i;
            }

            if i {
                res += self;
            }
        }

        res
    }
}

impl<P: Parameters> MulAssign<P::ScalarField> for Projective<P> {
    /// Performs scalar multiplication of this element.
    fn mul_assign(&mut self, other: P::ScalarField) {
        *self = *self * other
    }
}

// The affine point (X, Y) is represented in the Extended Projective coordinates with Z = 1.
impl<P: Parameters> From<Affine<P>> for Projective<P> {
    fn from(p: Affine<P>) -> Projective<P> {
        Self::new(p.x, p.y, p.x * p.y, P::BaseField::one())
    }
}
