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

use crate::traits::{AffineCurve, PairingCurve, ProjectiveCurve};
use snarkvm_fields::{Field, PrimeField, SquareRootField, ToConstraintField};

use core::{fmt::Debug, hash::Hash, iter};

/// This trait is sealed. Only snarkVM implements it.
pub trait PairingEngine:
    crate::sealed::Sealed + Sized + 'static + Copy + Debug + PartialEq + Eq + Hash + Sync + Send
{
    /// This is the scalar field of the G1/G2 groups.
    type Fr: PrimeField + SquareRootField + Into<<Self::Fr as PrimeField>::BigInteger>;

    /// The projective representation of an element in G1.
    type G1Projective: ProjectiveCurve<BaseField = Self::Fq, ScalarField = Self::Fr, Affine = Self::G1Affine>
        + From<Self::G1Affine>;

    /// The affine representation of an element in G1.
    type G1Affine: AffineCurve<BaseField = Self::Fq, ScalarField = Self::Fr, Projective = Self::G1Projective>
        + PairingCurve<PairWith = Self::G2Affine, PairingResult = Self::Fqk>
        + From<Self::G1Projective>
        + ToConstraintField<Self::Fq>;

    /// The projective representation of an element in G2.
    type G2Projective: ProjectiveCurve<BaseField = Self::Fqe, ScalarField = Self::Fr, Affine = Self::G2Affine>
        + From<Self::G2Affine>;

    /// The affine representation of an element in G2.
    type G2Affine: AffineCurve<BaseField = Self::Fqe, ScalarField = Self::Fr, Projective = Self::G2Projective>
        + PairingCurve<PairWith = Self::G1Affine, PairingResult = Self::Fqk>
        + From<Self::G2Projective>
        + ToConstraintField<Self::Fq>;

    /// The base field that hosts G1.
    type Fq: PrimeField + SquareRootField;

    /// The extension field that hosts G2.
    type Fqe: SquareRootField;

    /// The extension field that hosts the target group of the pairing.
    type Fqk: Field;

    /// Perform a miller loop with some number of (G1, G2) pairs.
    #[must_use]
    fn miller_loop<'a, I>(i: I) -> Self::Fqk
    where
        I: Iterator<
            Item = (&'a <Self::G1Affine as PairingCurve>::Prepared, &'a <Self::G2Affine as PairingCurve>::Prepared),
        >;

    /// Perform final exponentiation of the result of a miller loop.
    #[must_use]
    fn final_exponentiation(_: &Self::Fqk) -> Option<Self::Fqk>;

    /// Computes a product of pairings.
    #[must_use]
    fn product_of_pairings<'a, I>(i: I) -> Self::Fqk
    where
        I: Iterator<
            Item = (&'a <Self::G1Affine as PairingCurve>::Prepared, &'a <Self::G2Affine as PairingCurve>::Prepared),
        >,
    {
        Self::final_exponentiation(&Self::miller_loop(i)).unwrap()
    }

    /// Performs multiple pairing operations
    #[must_use]
    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        Self::final_exponentiation(&Self::miller_loop(iter::once((&p.into().prepare(), &q.into().prepare())))).unwrap()
    }
}
