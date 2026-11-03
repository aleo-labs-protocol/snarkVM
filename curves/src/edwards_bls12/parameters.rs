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
    edwards_bls12::{Fq, Fr},
    errors::GroupError,
    templates::twisted_edwards_extended::{Affine, Projective},
    traits::{AffineCurve, ModelParameters, MontgomeryParameters, TwistedEdwardsParameters},
};
use snarkvm_fields::field;
use snarkvm_utilities::biginteger::BigInteger256;

use std::str::FromStr;

pub type EdwardsAffine = Affine<EdwardsParameters>;
pub type EdwardsProjective = Projective<EdwardsParameters>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct EdwardsParameters;

impl ModelParameters for EdwardsParameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

impl TwistedEdwardsParameters for EdwardsParameters {
    type MontgomeryParameters = EdwardsParameters;

    /// Generated randomly
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) = (GENERATOR_X, GENERATOR_Y);
    /// COFACTOR = 4
    const COFACTOR: &'static [u64] = &[4];
    /// COFACTOR_INV = 527778859339273151515551558673846658209717731602102048798421311598680340096
    const COFACTOR_INV: Fr = field!(
        Fr,
        BigInteger256([10836190823041854989, 14880086764632731920, 5023208332782666747, 239524813690824359,])
    );
    /// EDWARDS_A = -1
    const EDWARDS_A: Fq =
        field!(Fq, BigInteger256([0x8cf500000000000e, 0xe75281ef6000000e, 0x49dc37a90b0ba012, 0x55f8b2c6e710ab9,]));
    /// EDWARDS_D = 3021
    const EDWARDS_D: Fq =
        field!(Fq, BigInteger256([0xd047ffffffff5e30, 0xf0a91026ffff57d2, 0x9013f560d102582, 0x9fd242ca7be5700,]));

    /// Multiplication by `a` is just negation.
    /// Is `a` 1 or -1?
    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        -*elem
    }
}

impl MontgomeryParameters for EdwardsParameters {
    type TwistedEdwardsParameters = EdwardsParameters;

    /// MONTGOMERY_A = 3990301581132929505568273333084066329187552697088022219156688740916631500114
    ///              = 0x8D26E3FADA9010A26949031ECE3971B93952AD84D4753DDEDB748DA37E8F552
    const MONTGOMERY_A: Fq = field!(
        Fq,
        BigInteger256([
            13800168384327121454u64,
            6841573379969807446u64,
            12529593083398462246u64,
            853978956621483129u64,
        ])
    );
    /// MONTGOMERY_B = 4454160168295440918680551605697480202188346638066041608778544715000777738925
    ///              = 0x9D8F71EEC83A44C3A1FBCEC6F5418E5C6154C2682B8AC231C5A3725C8170AAD
    const MONTGOMERY_B: Fq = field!(
        Fq,
        BigInteger256([
            7239382437352637935u64,
            14509846070439283655u64,
            5083066350480839936u64,
            1265663645916442191u64,
        ])
    );
}

impl FromStr for EdwardsAffine {
    type Err = GroupError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        s = s.trim();
        if s.is_empty() {
            return Err(GroupError::ParsingEmptyString);
        }
        if s.len() < 3 {
            return Err(GroupError::InvalidString);
        }
        if !(s.starts_with('(') && s.ends_with(')')) {
            return Err(GroupError::InvalidString);
        }
        let mut point = Vec::new();
        for substr in s.split(['(', ')', ',', ' ']) {
            if !substr.is_empty() {
                point.push(Fq::from_str(substr)?);
            }
        }
        if point.len() != 2 {
            return Err(GroupError::InvalidGroupElement);
        }
        let point = EdwardsAffine::new(point[0], point[1], point[0] * point[1]);

        if !point.is_on_curve() { Err(GroupError::InvalidGroupElement) } else { Ok(point) }
    }
}

/// GENERATOR_X =
/// 1540945439182663264862696551825005342995406165131907382295858612069623286213
const GENERATOR_X: Fq =
    field!(Fq, BigInteger256([15976313411695170452, 17230178952810798400, 11626259175167078036, 678729006091608048]));

/// GENERATOR_Y =
/// 8003546896475222703853313610036801932325312921786952001586936882361378122196
const GENERATOR_Y: Fq =
    field!(Fq, BigInteger256([926786653590077393, 18147000980977651608, 13077459464847727671, 1231472949076376191]));
