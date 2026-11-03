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
    templates::short_weierstrass_jacobian::Affine,
    traits::{AffineCurve, ProjectiveCurve, ShortWeierstrassParameters as Parameters},
};
use snarkvm_fields::{Field, One, Zero, impl_add_sub_from_field_ref};
use snarkvm_utilities::{FromBytes, ToBytes, rand::Uniform};

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

// The CUDA FFI reads this by bytes.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Projective<P: Parameters> {
    pub x: P::BaseField,
    pub y: P::BaseField,
    pub z: P::BaseField,
}

impl<P: Parameters> Projective<P> {
    pub const fn new(x: P::BaseField, y: P::BaseField, z: P::BaseField) -> Self {
        Self { x, y, z }
    }
}

impl<P: Parameters> Zero for Projective<P> {
    // The point at infinity is always represented by Z = 0.
    #[inline]
    fn zero() -> Self {
        Self::new(P::BaseField::zero(), P::BaseField::one(), P::BaseField::zero())
    }

    // The point at infinity is always represented by Z = 0.
    #[inline]
    fn is_zero(&self) -> bool {
        self.z.is_zero()
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

        // The points (X, Y, Z) and (X', Y', Z')
        // are equal when (X * Z^2) = (X' * Z'^2)
        // and (Y * Z^3) = (Y' * Z'^3).
        let z1 = self.z.square();
        let z2 = other.z.square();

        !(self.x * z2 != other.x * z1 || self.y * (z2 * other.z) != other.y * (z1 * self.z))
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

        // The points (X, Y, Z) and (X', Y', Z')
        // are equal when (X * Z^2) = (X' * Z'^2)
        // and (Y * Z^3) = (Y' * Z'^3).
        let z1 = self.z.square();
        (self.x == other.x * z1) & (self.y == other.y * z1 * self.z)
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
        self.z.write_le(writer)
    }
}

impl<P: Parameters> FromBytes for Projective<P> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let x = P::BaseField::read_le(&mut reader)?;
        let y = P::BaseField::read_le(&mut reader)?;
        let z = P::BaseField::read_le(reader)?;
        Ok(Self::new(x, y, z))
    }
}

impl<P: Parameters> ProjectiveCurve for Projective<P> {
    type Affine = Affine<P>;
    type BaseField = P::BaseField;
    type ScalarField = P::ScalarField;

    #[inline]
    fn prime_subgroup_generator() -> Self {
        Affine::prime_subgroup_generator().into()
    }

    #[inline]
    fn is_normalized(&self) -> bool {
        self.is_zero() || self.z.is_one()
    }

    /// TODO (howardwu): This method can likely be sped up.
    #[inline]
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
        v.iter_mut().filter(|g| !g.is_normalized()).for_each(|g| {
            // Perform affine transformations
            let z2 = g.z.square(); // 1/z
            g.x *= &z2; // x/z^2
            g.y *= &(z2 * g.z); // y/z^3
            g.z = P::BaseField::one(); // z = 1
        });
    }

    #[allow(clippy::many_single_char_names)]
    fn add_assign_mixed(&mut self, other: &Self::Affine) {
        if other.is_zero() {
            return;
        }

        if self.is_zero() {
            self.x = other.x;
            self.y = other.y;
            self.z = P::BaseField::one();
            return;
        }

        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
        // Works for all curves.

        // Z1Z1 = Z1^2
        let z1z1 = self.z.square();

        // U2 = X2*Z1Z1
        let u2 = other.x * z1z1;

        // S2 = Y2*Z1*Z1Z1
        let s2 = (other.y * self.z) * z1z1;

        if self.x == u2 && self.y == s2 {
            // The two points are equal, so we double.
            self.double_in_place();
        } else {
            // If we're adding -a and a together, self.z becomes zero as H becomes zero.

            // H = U2-X1
            let mut h = u2;
            h -= &self.x;

            // HH = H^2
            let hh = h.square();

            // I = 4*HH
            let mut i = hh;
            i.double_in_place();
            i.double_in_place();

            // J = H*I
            let mut j = h;
            j *= &i;

            // r = 2*(S2-Y1)
            let mut r = s2;
            r -= &self.y;
            r.double_in_place();

            // V = X1*I
            let mut v = self.x;
            v *= &i;

            // X3 = r^2 - J - 2*V
            self.x = r.square();
            self.x -= &j;
            self.x -= &v.double();

            // Y3 = r*(V-X3)-2*Y1*J
            self.y = P::BaseField::sum_of_products(&[r, -self.y.double()], &[(v - self.x), j]);

            // Z3 = (Z1+H)^2-Z1Z1-HH
            self.z += &h;
            self.z.square_in_place();
            self.z -= &z1z1;
            self.z -= &hh;
        }
    }

    #[inline]
    fn double(&self) -> Self {
        let mut tmp = *self;
        tmp.double_in_place();
        tmp
    }

    #[inline]
    fn double_in_place(&mut self) {
        if self.is_zero() {
            return;
        }

        if P::WEIERSTRASS_A.is_zero() {
            // A = X1^2
            let mut a = self.x.square();

            // B = Y1^2
            let b = self.y.square();

            // C = B^2
            let mut c = b.square();

            // D = 2*((X1+B)2-A-C)
            let d = ((self.x + b).square() - a - c).double();

            // E = 3*A
            let old_a = a;
            a.double_in_place();
            let e = old_a + a;

            // F = E^2
            let f = e.square();

            // Z3 = 2*Y1*Z1
            self.z *= &self.y;
            self.z.double_in_place();

            // X3 = F-2*D
            self.x = f - d.double();

            // Y3 = E*(D-X3)-8*C
            c.double_in_place();
            c.double_in_place();
            c.double_in_place();
            self.y = (d - self.x) * e - c;
        } else {
            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
            // XX = X1^2
            let xx = self.x.square();

            // YY = Y1^2
            let yy = self.y.square();

            // YYYY = YY^2
            let mut yyyy = yy.square();

            // ZZ = Z1^2
            let zz = self.z.square();

            // S = 2*((X1+YY)^2-XX-YYYY)
            let s = ((self.x + yy).square() - xx - yyyy).double();

            // M = 3*XX+a*ZZ^2
            let m = xx.double() + xx + P::mul_by_a(&zz.square());

            // T = M^2-2*S
            let t = m.square() - s.double();

            // X3 = T
            self.x = t;
            // Y3 = M*(S-T)-8*YYYY
            let old_y = self.y;
            yyyy.double_in_place();
            yyyy.double_in_place();
            yyyy.double_in_place();
            self.y = m * (s - t) - yyyy;
            // Z3 = (Y1+Z1)^2-YY-ZZ
            self.z = (old_y + self.z).square() - yy - zz;
        }
    }

    #[inline]
    fn to_affine(&self) -> Affine<P> {
        (*self).into()
    }
}

impl<P: Parameters> Neg for Projective<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        if !self.is_zero() { Self::new(self.x, -self.y, self.z) } else { self }
    }
}

impl_add_sub_from_field_ref!(Projective, Parameters);

impl<'a, P: Parameters> Add<&'a Self> for Projective<P> {
    type Output = Self;

    #[inline]
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
        if self.is_zero() {
            *self = *other;
            return;
        }

        if other.is_zero() {
            return;
        }

        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
        // Works for all curves.

        // Z1Z1 = Z1^2
        let z1z1 = self.z.square();

        // Z2Z2 = Z2^2
        let z2z2 = other.z.square();

        // U1 = X1*Z2Z2
        let u1 = self.x * z2z2;

        // U2 = X2*Z1Z1
        let u2 = other.x * z1z1;

        // S1 = Y1*Z2*Z2Z2
        let s1 = self.y * other.z * z2z2;

        // S2 = Y2*Z1*Z1Z1
        let s2 = other.y * self.z * z1z1;

        if u1 == u2 && s1 == s2 {
            // The two points are equal, so we double.
            self.double_in_place();
        } else {
            // If we're adding -a and a together, self.z becomes zero as H becomes zero.

            // H = U2-U1
            let h = u2 - u1;

            // I = (2*H)^2
            let i = (h.double()).square();

            // J = H*I
            let j = h * i;

            // r = 2*(S2-S1)
            let r = (s2 - s1).double();

            // V = U1*I
            let v = u1 * i;

            // X3 = r^2 - J - 2*V
            self.x = r.square() - j - (v.double());

            // Y3 = r*(V - X3) - 2*S1*J
            self.y = P::BaseField::sum_of_products(&[r, -s1.double()], &[(v - self.x), j]);

            // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H
            self.z = ((self.z + other.z).square() - z1z1 - z2z2) * h;
        }
    }
}

impl<'a, P: Parameters> Sub<&'a Self> for Projective<P> {
    type Output = Self;

    #[inline]
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
        P::mul_projective(self, other)
    }
}

impl<P: Parameters> MulAssign<P::ScalarField> for Projective<P> {
    /// Performs scalar multiplication of this element.
    fn mul_assign(&mut self, other: P::ScalarField) {
        *self = *self * other
    }
}

/// The affine point X, Y is represented in the Jacobian coordinates with Z = 1.
impl<P: Parameters> From<Affine<P>> for Projective<P> {
    #[inline]
    fn from(p: Affine<P>) -> Projective<P> {
        if p.is_zero() { Self::zero() } else { Self::new(p.x, p.y, P::BaseField::one()) }
    }
}
