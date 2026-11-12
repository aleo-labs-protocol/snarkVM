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
    bls12_377::{
        Fq,
        Fq2Parameters,
        Fq6Parameters,
        Fq12,
        Fq12Parameters,
        g1::Bls12_377G1Parameters,
        g2::Bls12_377G2Parameters,
    },
    templates::bls12::{
        Bls12,
        Bls12Parameters,
        G1Affine as Bls12G1Affine,
        G1Prepared,
        G1Projective as Bls12G1Projective,
        G2Affine as Bls12G2Affine,
        G2Prepared,
        G2Projective as Bls12G2Projective,
        TwistType,
    },
    traits::{PairingCurve, PairingEngine},
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Bls12_377Parameters;

impl crate::sealed::Sealed for Bls12_377Parameters {}

impl Bls12Parameters for Bls12_377Parameters {
    type Fp = Fq;
    type Fp12Params = Fq12Parameters;
    type Fp2Params = Fq2Parameters;
    type Fp6Params = Fq6Parameters;
    type G1Parameters = Bls12_377G1Parameters;
    type G2Parameters = Bls12_377G2Parameters;

    const TWIST_TYPE: TwistType = TwistType::D;
    const X: &'static [u64] = &[0x8508c00000000001];
    /// `x` is positive.
    const X_IS_NEGATIVE: bool = false;
}

pub type Bls12_377 = Bls12<Bls12_377Parameters>;

pub type G1Affine = Bls12G1Affine<Bls12_377Parameters>;
pub type G1Projective = Bls12G1Projective<Bls12_377Parameters>;

impl PairingCurve for G1Affine {
    type Engine = Bls12_377;
    type PairWith = G2Affine;
    type PairingResult = Fq12;
    type Prepared = G1Prepared<Bls12_377Parameters>;

    fn prepare(&self) -> Self::Prepared {
        Self::Prepared::from_affine(*self)
    }

    fn pairing_with(&self, other: &Self::PairWith) -> Self::PairingResult {
        Bls12_377::pairing(*self, *other)
    }
}

pub type G2Affine = Bls12G2Affine<Bls12_377Parameters>;
pub type G2Projective = Bls12G2Projective<Bls12_377Parameters>;

impl PairingCurve for G2Affine {
    type Engine = Bls12_377;
    type PairWith = G1Affine;
    type PairingResult = Fq12;
    type Prepared = G2Prepared<Bls12_377Parameters>;

    fn prepare(&self) -> Self::Prepared {
        Self::Prepared::from_affine(*self)
    }

    fn pairing_with(&self, other: &Self::PairWith) -> Self::PairingResult {
        Bls12_377::pairing(*other, *self)
    }
}
