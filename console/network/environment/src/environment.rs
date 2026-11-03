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

use crate::prelude::{Deserialize, DeserializeOwned, Serialize};
use snarkvm_curves::{
    AffineCurve,
    MontgomeryParameters,
    PairingEngine,
    ProjectiveCurve,
    TwistedEdwardsParameters,
    bls12_377::Bls12_377,
    edwards_bls12::{EdwardsAffine, EdwardsParameters},
};
use snarkvm_fields::{PrimeField, SquareRootField};
use snarkvm_utilities::BigInteger;

use core::{fmt::Debug, hash::Hash};
use zeroize::Zeroize;

pub trait Environment:
    'static + Copy + Clone + Debug + PartialEq + Eq + Hash + Serialize + DeserializeOwned + Send + Sync
{
    type Affine: AffineCurve<
            Projective = Self::Projective,
            BaseField = Self::Field,
            ScalarField = Self::Scalar,
            Coordinates = (Self::Field, Self::Field),
        >;
    type BigInteger: BigInteger;
    type Field: PrimeField<BigInteger = Self::BigInteger> + SquareRootField + Copy + Zeroize;
    type PairingCurve: PairingEngine<Fr = Self::Field>;
    type Projective: ProjectiveCurve<Affine = Self::Affine, BaseField = Self::Field, ScalarField = Self::Scalar>;
    type Scalar: PrimeField<BigInteger = Self::BigInteger> + Copy + Zeroize;

    /// The coefficient `A` of the twisted Edwards curve.
    const EDWARDS_A: Self::Field;
    /// The coefficient `D` of the twisted Edwards curve.
    const EDWARDS_D: Self::Field;

    /// The coefficient `A` of the Montgomery curve.
    const MONTGOMERY_A: Self::Field;
    /// The coefficient `B` of the Montgomery curve.
    const MONTGOMERY_B: Self::Field;

    /// The maximum number of bytes allowed in a string.
    const MAX_STRING_BYTES: u32 = u8::MAX as u32;

    /// Halts the program from further synthesis, evaluation, and execution in the current environment.
    fn halt<S: Into<String>, T>(message: S) -> T {
        panic!("{}", message.into())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Console;

impl Environment for Console {
    type Affine = EdwardsAffine;
    type BigInteger = <Self::Field as PrimeField>::BigInteger;
    type Field = <Self::Affine as AffineCurve>::BaseField;
    type PairingCurve = Bls12_377;
    type Projective = <Self::Affine as AffineCurve>::Projective;
    type Scalar = <Self::Affine as AffineCurve>::ScalarField;

    /// The coefficient `A` of the twisted Edwards curve.
    const EDWARDS_A: Self::Field = <EdwardsParameters as TwistedEdwardsParameters>::EDWARDS_A;
    /// The coefficient `D` of the twisted Edwards curve.
    const EDWARDS_D: Self::Field = <EdwardsParameters as TwistedEdwardsParameters>::EDWARDS_D;
    /// The coefficient `A` of the Montgomery curve.
    const MONTGOMERY_A: Self::Field = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_A;
    /// The coefficient `B` of the Montgomery curve.
    const MONTGOMERY_B: Self::Field = <EdwardsParameters as MontgomeryParameters>::MONTGOMERY_B;
}
