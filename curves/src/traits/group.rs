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

use crate::{PairingEngine, templates::short_weierstrass_jacobian};
use snarkvm_fields::{Field, PrimeField, SquareRootField, Zero};
use snarkvm_utilities::{FromBytes, ToBytes, rand::Uniform, serialize::*};

use core::{
    fmt::{Debug, Display},
    hash::Hash,
    iter,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use serde::{Serialize, de::DeserializeOwned};

/// Projective representation of an elliptic curve point guaranteed to be in the prime order subgroup.
pub trait ProjectiveCurve:
    CanonicalSerialize
    + CanonicalDeserialize
    + Copy
    + Clone
    + Debug
    + Display
    + Default
    + FromBytes
    + Send
    + Sync
    + 'static
    + Eq
    + Hash
    + Neg<Output = Self>
    + Uniform
    + Zero
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self::ScalarField, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self::ScalarField>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + PartialEq<Self::Affine>
    + Sized
    + ToBytes
    + iter::Sum
    + From<<Self as ProjectiveCurve>::Affine>
{
    type Affine: AffineCurve<Projective = Self, ScalarField = Self::ScalarField> + From<Self> + Into<Self>;
    type BaseField: Field;
    type ScalarField: PrimeField + SquareRootField + Into<<Self::ScalarField as PrimeField>::BigInteger>;

    /// Returns a fixed generator of unknown exponent.
    #[must_use]
    fn prime_subgroup_generator() -> Self;

    /// Normalizes a slice of projective elements so that
    /// conversion to affine is cheap.
    fn batch_normalization(v: &mut [Self]);

    /// Normalizes a slice of projective elements and outputs a vector
    /// containing the affine equivalents.
    fn batch_normalization_into_affine(mut v: Vec<Self>) -> Vec<Self::Affine> {
        Self::batch_normalization(&mut v);
        v.into_iter().map(|v| v.into()).collect()
    }

    /// Checks if the point is already "normalized" so that
    /// cheap affine conversion is possible.
    #[must_use]
    fn is_normalized(&self) -> bool;

    /// Adds an affine element to this element.
    fn add_assign_mixed(&mut self, other: &Self::Affine);

    /// Adds an affine element to this element.
    fn add_mixed(&self, other: &Self::Affine) -> Self {
        let mut copy = *self;
        copy.add_assign_mixed(other);
        copy
    }

    /// Adds an affine element to this element.
    fn sub_assign_mixed(&mut self, other: &Self::Affine) {
        self.add_assign_mixed(&-*other);
    }

    /// Returns `self + self`.
    #[must_use]
    fn double(&self) -> Self;

    /// Sets `self := self + self`.
    fn double_in_place(&mut self);

    /// Converts this element into its affine representation.
    #[must_use]
    #[allow(clippy::wrong_self_convention)]
    fn to_affine(&self) -> Self::Affine;
}

/// Affine representation of an elliptic curve point guaranteed to be
/// in the correct prime order subgroup.
#[allow(clippy::wrong_self_convention)]
pub trait AffineCurve:
    CanonicalSerialize
    + CanonicalDeserialize
    + Copy
    + Clone
    + Debug
    + Display
    + Default
    + FromBytes
    + Send
    + Sync
    + 'static
    + Eq
    + Hash
    + Neg<Output = Self>
    + Uniform
    + PartialEq<Self::Projective>
    + Mul<Self::ScalarField, Output = Self::Projective>
    + Sized
    + Serialize
    + DeserializeOwned
    + ToBytes
    + From<<Self as AffineCurve>::Projective>
    + Zero
{
    type Projective: ProjectiveCurve<Affine = Self, ScalarField = Self::ScalarField> + From<Self> + Into<Self>;
    type BaseField: Field + SquareRootField;
    type ScalarField: PrimeField + SquareRootField + Into<<Self::ScalarField as PrimeField>::BigInteger>;
    type Coordinates;

    /// Initializes a new affine group element from the given coordinates.
    fn from_coordinates(coordinates: Self::Coordinates) -> Option<Self>;

    /// Initializes a new affine group element from the given coordinates.
    /// Note: The resulting point is **not** enforced to be on the curve or in the correct subgroup.
    fn from_coordinates_unchecked(coordinates: Self::Coordinates) -> Self;

    /// Returns the cofactor of the curve.
    fn cofactor() -> &'static [u64];

    /// Returns a fixed generator of unknown exponent.
    #[must_use]
    fn prime_subgroup_generator() -> Self;

    /// Attempts to construct an affine point given an x-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    fn from_x_coordinate(x: Self::BaseField, greatest: bool) -> Option<Self>;

    /// Attempts to construct both possible affine points given an x-coordinate.
    /// Points are not guaranteed to be in the prime order subgroup.
    ///
    /// The affine points returned should be in lexicographically growing order.
    ///
    /// Calling this should be equivalent (but likely more performant) to
    /// `(AffineCurve::from_x_coordinate(x, false), AffineCurve::from_x_coordinate(x, true))`.
    fn pair_from_x_coordinate(x: Self::BaseField) -> Option<(Self, Self)>;

    /// Attempts to construct an affine point given a y-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    fn from_y_coordinate(y: Self::BaseField, greatest: bool) -> Option<Self>;

    /// Multiply this element by the cofactor and output the
    /// resulting projective element.
    #[must_use]
    fn mul_by_cofactor_to_projective(&self) -> Self::Projective;

    /// Converts this element into its projective representation.
    #[must_use]
    fn to_projective(&self) -> Self::Projective;

    /// Returns a group element if the set of bytes forms a valid group element,
    /// otherwise returns None. This function is primarily intended for sampling
    /// random group elements from a hash-function or RNG output.
    fn from_random_bytes(bytes: &[u8]) -> Option<Self>;

    /// Multiply this element by a big-endian boolean representation of
    /// an integer.
    fn mul_bits(&self, bits: impl Iterator<Item = bool>) -> Self::Projective;

    /// Multiply this element by the cofactor.
    #[must_use]
    fn mul_by_cofactor(&self) -> Self {
        self.mul_by_cofactor_to_projective().into()
    }

    /// Multiply this element by the inverse of the cofactor modulo the size of
    /// `Self::ScalarField`.
    #[must_use]
    fn mul_by_cofactor_inv(&self) -> Self;

    /// Checks that the point is in the prime order subgroup given the point on the curve.
    #[must_use]
    fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool;

    /// Returns the x-coordinate of the point.
    #[must_use]
    fn to_x_coordinate(&self) -> Self::BaseField;

    /// Returns the y-coordinate of the point.
    #[must_use]
    fn to_y_coordinate(&self) -> Self::BaseField;

    /// Checks that the current point is on the elliptic curve.
    fn is_on_curve(&self) -> bool;

    /// Performs the first half of batch addition in-place.
    fn batch_add_loop_1(
        a: &mut Self,
        b: &mut Self,
        half: &Self::BaseField, // The value 2.inverse().
        inversion_tmp: &mut Self::BaseField,
    );

    /// Performs the second half of batch addition in-place.
    fn batch_add_loop_2(a: &mut Self, b: Self, inversion_tmp: &mut Self::BaseField);
}

pub trait PairingCurve: AffineCurve {
    type Engine: PairingEngine<Fr = Self::ScalarField>;
    type Prepared: CanonicalSerialize
        + CanonicalDeserialize
        + ToBytes
        + FromBytes
        + PartialEq
        + Eq
        + Default
        + Clone
        + Send
        + Sync
        + Debug
        + 'static;
    type PairWith: PairingCurve<PairWith = Self>;
    type PairingResult: Field;

    /// Prepares this element for pairing purposes.
    #[must_use]
    fn prepare(&self) -> Self::Prepared;

    /// Perform a pairing
    #[must_use]
    fn pairing_with(&self, other: &Self::PairWith) -> Self::PairingResult;
}

pub trait ModelParameters: 'static + Copy + Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Sized {
    type BaseField: Field + SquareRootField;
    type ScalarField: PrimeField + SquareRootField + Into<<Self::ScalarField as PrimeField>::BigInteger>;
}

pub trait ShortWeierstrassParameters: ModelParameters {
    /// The coefficient `A` of the short Weierstrass curve.
    const WEIERSTRASS_A: Self::BaseField;
    /// The coefficient `B` of the short Weierstrass curve.
    const WEIERSTRASS_B: Self::BaseField;
    /// The cofactor of the short Weierstrass curve.
    const COFACTOR: &'static [u64];
    /// The cofactor inverse of the short Weierstrass curve.
    const COFACTOR_INV: Self::ScalarField;
    /// The affine generator of the short Weierstrass curve.
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField);

    const PHI: Self::BaseField;

    // Decomposition parameters
    /// Q1 = x^2 * R / q
    const Q1: [u64; 4] = [9183663392111466540, 12968021215939883360, 3, 0];
    /// Q2 = R / q = 13
    const Q2: [u64; 4] = [13, 0, 0, 0];
    /// B1 = x^2 - 1
    const B1: Self::ScalarField;
    /// B2 = x^2
    const B2: Self::ScalarField;
    /// R128 = 2^128 - 1
    const R128: Self::ScalarField;
    /// HALF_R = 2^256 / 2
    const HALF_R: [u64; 8] = [0, 0, 0, 0x8000000000000000, 0, 0, 0, 0];

    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        let mut copy = *elem;
        copy *= &Self::WEIERSTRASS_A;
        copy
    }

    #[inline(always)]
    fn add_b(elem: &Self::BaseField) -> Self::BaseField {
        let mut copy = *elem;
        copy += &Self::WEIERSTRASS_B;
        copy
    }

    fn is_in_correct_subgroup_assuming_on_curve(p: &short_weierstrass_jacobian::Affine<Self>) -> bool;

    fn glv_endomorphism(p: short_weierstrass_jacobian::Affine<Self>) -> short_weierstrass_jacobian::Affine<Self>;

    fn mul_projective(
        p: short_weierstrass_jacobian::Projective<Self>,
        by: Self::ScalarField,
    ) -> short_weierstrass_jacobian::Projective<Self>;
}

pub trait TwistedEdwardsParameters: ModelParameters {
    /// The coefficient `A` of the twisted Edwards curve.
    const EDWARDS_A: Self::BaseField;
    /// The coefficient `D` of the twisted Edwards curve.
    const EDWARDS_D: Self::BaseField;
    /// The cofactor of the twisted Edwards curve.
    const COFACTOR: &'static [u64];
    /// The cofactor inverse of the twisted Edwards curve.
    const COFACTOR_INV: Self::ScalarField;
    /// The affine generator of the twisted Edwards curve.
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField);

    type MontgomeryParameters: MontgomeryParameters<BaseField = Self::BaseField>;

    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        let mut copy = *elem;
        copy *= &Self::EDWARDS_A;
        copy
    }
}

pub trait MontgomeryParameters: ModelParameters {
    /// The coefficient `A` of the Montgomery curve.
    const MONTGOMERY_A: Self::BaseField;
    /// The coefficient `B` of the Montgomery curve.
    const MONTGOMERY_B: Self::BaseField;

    type TwistedEdwardsParameters: TwistedEdwardsParameters<BaseField = Self::BaseField>;
}
