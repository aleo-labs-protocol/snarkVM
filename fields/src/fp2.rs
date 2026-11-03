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

use crate::{Field, LegendreSymbol, One, PrimeField, SquareRootField, Zero};
use snarkvm_utilities::{
    FromBytes,
    ToBits,
    ToBytes,
    rand::Uniform,
    serialize::{SerializationError, *},
};

use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::{Ord, Ordering, PartialOrd},
    fmt::Debug,
    hash::Hash,
    io::{Read, Result as IoResult, Write},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub trait Fp2Parameters:
    'static + Copy + Clone + Default + Debug + PartialEq + Eq + Hash + Serialize + for<'a> Deserialize<'a> + Send + Sync
{
    type Fp: PrimeField;

    /// Coefficients for the Frobenius automorphism.
    const FROBENIUS_COEFF_FP2_C1: [Self::Fp; 2];

    const NONRESIDUE: Self::Fp;

    const QUADRATIC_NONRESIDUE: (Self::Fp, Self::Fp);

    #[inline(always)]
    fn mul_fp_by_nonresidue(fe: &Self::Fp) -> Self::Fp {
        Self::NONRESIDUE * fe
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fp2<P: Fp2Parameters> {
    pub c0: P::Fp,
    pub c1: P::Fp,
}

impl<P: Fp2Parameters> Fp2<P> {
    /// Initializes a `Fp2` element from two `Fp` elements.
    pub const fn new(c0: P::Fp, c1: P::Fp) -> Self {
        Fp2 { c0, c1 }
    }
}

impl<P: Fp2Parameters> Fp2<P> {
    /// Norm of Fp2 over Fp: Norm(a) = a.x^2 - beta * a.y^2
    pub fn norm(&self) -> P::Fp {
        let t0 = self.c0.square();
        let mut t1 = self.c1.square();
        t1 = -P::mul_fp_by_nonresidue(&t1);
        t1.add_assign(t0);
        t1
    }

    pub fn mul_by_fp(&mut self, element: &P::Fp) {
        self.c0.mul_assign(element);
        self.c1.mul_assign(element);
    }
}

impl<P: Fp2Parameters> Zero for Fp2<P> {
    fn zero() -> Self {
        Fp2::new(P::Fp::zero(), P::Fp::zero())
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }
}
impl<P: Fp2Parameters> One for Fp2<P> {
    fn one() -> Self {
        Fp2::new(P::Fp::one(), P::Fp::zero())
    }

    fn is_one(&self) -> bool {
        self.c0.is_one() && self.c1.is_zero()
    }
}

impl<P: Fp2Parameters> Field for Fp2<P> {
    type BasePrimeField = P::Fp;

    fn from_base_prime_field(other: Self::BasePrimeField) -> Self {
        Self::new(other, P::Fp::zero())
    }

    #[inline]
    fn characteristic<'a>() -> &'a [u64] {
        P::Fp::characteristic()
    }

    fn double(&self) -> Self {
        let mut result = *self;
        result.double_in_place();
        result
    }

    fn double_in_place(&mut self) {
        self.c0.double_in_place();
        self.c1.double_in_place();
    }

    fn square(&self) -> Self {
        let mut result = *self;
        result.square_in_place();
        result
    }

    #[inline]
    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        let split_at = bytes.len() / 2;
        if let Some(c0) = P::Fp::from_random_bytes(&bytes[..split_at])
            && let Some((c1, flags)) = P::Fp::from_random_bytes_with_flags::<F>(&bytes[split_at..])
        {
            return Some((Fp2::new(c0, c1), flags));
        }
        None
    }

    #[inline]
    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_random_bytes_with_flags::<EmptyFlags>(bytes).map(|f| f.0)
    }

    fn square_in_place(&mut self) -> &mut Self {
        // v0 = c0 - c1
        let mut v0 = self.c0 - self.c1;
        // v3 = c0 - beta * c1
        let v3 = self.c0 - P::mul_fp_by_nonresidue(&self.c1);
        // v2 = c0 * c1
        let v2 = self.c0 * self.c1;

        // v0 = (v0 * v3) + v2
        v0 *= &v3;
        v0 += &v2;

        self.c1 = v2.double();
        self.c0 = v0 + P::mul_fp_by_nonresidue(&v2);

        self
    }

    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            // Guide to Pairing-based Cryptography, Algorithm 5.19.
            // v0 = c0.square()
            let mut v0 = self.c0.square();
            // v1 = c1.square()
            let v1 = self.c1.square();
            // v0 = v0 - beta * v1
            v0 -= &P::mul_fp_by_nonresidue(&v1);
            v0.inverse().map(|v1| {
                let c0 = self.c0 * v1;
                let c1 = -(self.c1 * v1);
                Self::new(c0, c1)
            })
        }
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        if let Some(inverse) = self.inverse() {
            *self = inverse;
            Some(self)
        } else {
            None
        }
    }

    fn frobenius_map(&mut self, power: usize) {
        self.c1.mul_assign(&P::FROBENIUS_COEFF_FP2_C1[power % 2]);
    }
}

impl<P: Fp2Parameters> SquareRootField for Fp2<P>
where
    P::Fp: SquareRootField,
{
    fn legendre(&self) -> LegendreSymbol {
        self.norm().legendre()
    }

    fn sqrt(&self) -> Option<Self> {
        use crate::LegendreSymbol::*;
        if self.c1.is_zero() {
            return self.c0.sqrt().map(|c0| Self::new(c0, P::Fp::zero()));
        }
        match self.legendre() {
            // Square root based on the complex method. See
            // https://eprint.iacr.org/2012/685.pdf (page 15, algorithm 8)
            Zero => Some(*self),
            QuadraticNonResidue => None,
            QuadraticResidue => {
                let two_inv = P::Fp::half();
                let alpha = self.norm().sqrt().expect("We are in the QR case, the norm should have a square root");
                let mut delta = (alpha + self.c0) * two_inv;
                if delta.legendre().is_qnr() {
                    delta -= &alpha;
                }
                let c0 = delta.sqrt().expect("Delta must have a square root");
                let c0_inv = c0.inverse().expect("c0 must have an inverse");
                Some(Self::new(c0, self.c1 * two_inv * c0_inv))
            }
        }
    }

    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        (*self).sqrt().map(|sqrt| {
            *self = sqrt;
            self
        })
    }
}

/// `Fp2` elements are ordered lexicographically.
impl<P: Fp2Parameters> Ord for Fp2<P> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        match self.c1.cmp(&other.c1) {
            Ordering::Greater => Ordering::Greater,
            Ordering::Less => Ordering::Less,
            Ordering::Equal => self.c0.cmp(&other.c0),
        }
    }
}

impl<P: Fp2Parameters> PartialOrd for Fp2<P> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: Fp2Parameters> From<u128> for Fp2<P> {
    fn from(other: u128) -> Self {
        Self::new(other.into(), P::Fp::zero())
    }
}

impl<P: Fp2Parameters> From<u64> for Fp2<P> {
    fn from(other: u64) -> Self {
        Self::new(other.into(), P::Fp::zero())
    }
}

impl<P: Fp2Parameters> From<u32> for Fp2<P> {
    fn from(other: u32) -> Self {
        Self::new(other.into(), P::Fp::zero())
    }
}

impl<P: Fp2Parameters> From<u16> for Fp2<P> {
    fn from(other: u16) -> Self {
        Self::new(other.into(), P::Fp::zero())
    }
}

impl<P: Fp2Parameters> From<u8> for Fp2<P> {
    fn from(other: u8) -> Self {
        Self::new(other.into(), P::Fp::zero())
    }
}

impl<P: Fp2Parameters> ToBits for Fp2<P> {
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        self.c0.write_bits_le(vec);
        self.c1.write_bits_le(vec);
    }

    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        self.c0.write_bits_be(vec);
        self.c1.write_bits_be(vec);
    }
}

impl<P: Fp2Parameters> ToBytes for Fp2<P> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.c0.write_le(&mut writer)?;
        self.c1.write_le(writer)
    }
}

impl<P: Fp2Parameters> FromBytes for Fp2<P> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let c0 = P::Fp::read_le(&mut reader)?;
        let c1 = P::Fp::read_le(reader)?;
        Ok(Fp2::new(c0, c1))
    }
}

impl<P: Fp2Parameters> Neg for Fp2<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        let mut res = self;
        res.c0 = res.c0.neg();
        res.c1 = res.c1.neg();
        res
    }
}

impl<P: Fp2Parameters> Distribution<Fp2<P>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Fp2<P> {
        Fp2::new(Uniform::rand(rng), Uniform::rand(rng))
    }
}

impl_add_sub_from_field_ref!(Fp2, Fp2Parameters);
impl_mul_div_from_field_ref!(Fp2, Fp2Parameters);

impl<P: Fp2Parameters> Add<&'_ Fp2<P>> for Fp2<P> {
    type Output = Self;

    #[inline]
    fn add(self, other: &Self) -> Self {
        let mut result = self;
        result.add_assign(other);
        result
    }
}

impl<P: Fp2Parameters> Sub<&'_ Fp2<P>> for Fp2<P> {
    type Output = Self;

    #[inline]
    fn sub(self, other: &Self) -> Self {
        let mut result = self;
        result.sub_assign(&other);
        result
    }
}

impl<P: Fp2Parameters> Mul<&'_ Fp2<P>> for Fp2<P> {
    type Output = Self;

    #[inline]
    fn mul(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(&other);
        result
    }
}

impl<P: Fp2Parameters> Div<&'_ Fp2<P>> for Fp2<P> {
    type Output = Self;

    #[inline]
    fn div(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(&other.inverse().unwrap());
        result
    }
}

impl<P: Fp2Parameters> AddAssign<&'_ Self> for Fp2<P> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        self.c0.add_assign(other.c0);
        self.c1.add_assign(other.c1);
    }
}

impl<P: Fp2Parameters> SubAssign<&'_ Self> for Fp2<P> {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        self.c0.sub_assign(&other.c0);
        self.c1.sub_assign(&other.c1);
    }
}

impl<P: Fp2Parameters> MulAssign<&'_ Self> for Fp2<P> {
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn mul_assign(&mut self, other: &Self) {
        *self = Self::new(
            P::Fp::sum_of_products(&[self.c0, P::mul_fp_by_nonresidue(&self.c1)], &[other.c0, other.c1]),
            P::Fp::sum_of_products(&[self.c0, self.c1], &[other.c1, other.c0]),
        )
    }
}

impl<P: Fp2Parameters> DivAssign<&'_ Self> for Fp2<P> {
    #[inline]
    fn div_assign(&mut self, other: &Self) {
        self.mul_assign(&other.inverse().unwrap());
    }
}

impl<P: Fp2Parameters> std::fmt::Display for Fp2<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fp2({} + {} * u)", self.c0, self.c1)
    }
}

impl<P: Fp2Parameters> CanonicalSerializeWithFlags for Fp2<P> {
    #[inline]
    fn serialize_with_flags<W: Write, F: Flags>(&self, mut writer: W, flags: F) -> Result<(), SerializationError> {
        CanonicalSerialize::serialize_uncompressed(&self.c0, &mut writer)?;
        self.c1.serialize_with_flags(&mut writer, flags)?;
        Ok(())
    }

    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        self.c0.uncompressed_size() + self.c1.serialized_size_with_flags::<F>()
    }
}

impl<P: Fp2Parameters> CanonicalSerialize for Fp2<P> {
    #[inline]
    fn serialize_with_mode<W: Write>(&self, writer: W, _compress: Compress) -> Result<(), SerializationError> {
        self.serialize_with_flags(writer, EmptyFlags)
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.c0.serialized_size(compress) + self.c1.serialized_size(compress)
    }
}

impl<P: Fp2Parameters> CanonicalDeserializeWithFlags for Fp2<P> {
    #[inline]
    fn deserialize_with_flags<R: Read, F: Flags>(mut reader: R) -> Result<(Self, F), SerializationError> {
        let c0: P::Fp = CanonicalDeserialize::deserialize_uncompressed(&mut reader)?;
        let (c1, flags): (P::Fp, _) = CanonicalDeserializeWithFlags::deserialize_with_flags(&mut reader)?;
        Ok((Fp2::new(c0, c1), flags))
    }
}
impl<P: Fp2Parameters> Valid for Fp2<P> {
    fn check(&self) -> Result<(), snarkvm_utilities::SerializationError> {
        Ok(())
    }

    fn batch_check<'a>(
        _batch: impl Iterator<Item = &'a Self> + Send,
    ) -> Result<(), snarkvm_utilities::SerializationError>
    where
        Self: 'a,
    {
        Ok(())
    }
}

impl<P: Fp2Parameters> CanonicalDeserialize for Fp2<P> {
    #[inline]
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let c0 = P::Fp::deserialize_with_mode(&mut reader, compress, validate)?;
        let c1 = P::Fp::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Fp2::new(c0, c1))
    }
}
