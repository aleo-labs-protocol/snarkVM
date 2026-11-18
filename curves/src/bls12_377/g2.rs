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

use snarkvm_fields::{Field, PrimeField, Zero, field};
use snarkvm_utilities::{
    BigInteger,
    BitIteratorBE,
    biginteger::{BigInteger256, BigInteger384},
};

use crate::{
    AffineCurve,
    ProjectiveCurve,
    bls12_377::{Fq, Fq2, Fr, g1::Bls12_377G1Parameters},
    traits::{ModelParameters, ShortWeierstrassParameters},
};

use std::ops::Neg;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Bls12_377G2Parameters;

impl crate::sealed::Sealed for Bls12_377G2Parameters {}

impl ModelParameters for Bls12_377G2Parameters {
    type BaseField = Fq2;
    type ScalarField = Fr;
}

impl ShortWeierstrassParameters for Bls12_377G2Parameters {
    /// AFFINE_GENERATOR_COEFFS = (G2_GENERATOR_X, G2_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) = (G2_GENERATOR_X, G2_GENERATOR_Y);
    /// B1 = x^2 - 1
    const B1: Fr = field!(
        Fr,
        BigInteger256([12574070832645531618, 10005695704657941814, 1564543351912391449, 657300228442948690])
    );
    /// B2 = x^2
    const B2: Fr = field!(
        Fr,
        BigInteger256([2417046298041509844, 11783911742408086824, 14689097366802547462, 270119112518072728])
    );
    /// COFACTOR =
    /// 7923214915284317143930293550643874566881017850177945424769256759165301436616933228209277966774092486467289478618404761412630691835764674559376407658497
    const COFACTOR: &'static [u64] = &[
        0x0000000000000001,
        0x452217cc90000000,
        0xa0f3622fba094800,
        0xd693e8c36676bd09,
        0x8c505634fae2e189,
        0xfbb36b00e1dcc40c,
        0xddd88d99a6f6a829,
        0x26ba558ae9562a,
    ];
    /// COFACTOR_INV = COFACTOR^{-1} mod r
    ///              = 6764900296503390671038341982857278410319949526107311149686707033187604810669
    const COFACTOR_INV: Fr = field!(
        Fr,
        BigInteger256([15499857013495546999, 4613531467548868169, 14546778081091178013, 549402535258503313,])
    );
    const PHI: Fq2 = field!(
        Fq2,
        field!(Fq, BigInteger384([0, 0, 0, 0, 0, 0])),
        field!(
            Fq,
            BigInteger384([
                0x2c766f925a7b8727,
                0x03d7f6b0253d58b5,
                0x838ec0deec122131,
                0xbd5eb3e9f658bb10,
                0x6942bd126ed3e52e,
                0x01673786dd04ed6a,
            ])
        ),
    );
    /// R128 = 2^128 - 1
    const R128: Fr = field!(
        Fr,
        BigInteger256([13717662654766427599, 14709524173037165000, 15342848074630952979, 736762107895475646])
    );
    /// WEIERSTRASS_A = [0, 0]
    const WEIERSTRASS_A: Fq2 = field!(Fq2, Bls12_377G1Parameters::WEIERSTRASS_A, Bls12_377G1Parameters::WEIERSTRASS_A,);
    // As per https://eprint.iacr.org/2012/072.pdf,
    // this curve has b' = b/i, where b is the COEFF_B of G1, and x^6 -i is
    // the irreducible poly used to extend from Fp2 to Fp12.
    // In our case, i = u (App A.3, T_6).
    /// WEIERSTRASS_B = [0,
    /// 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906]
    const WEIERSTRASS_B: Fq2 = field!(
        Fq2,
        field!(Fq, BigInteger384([0, 0, 0, 0, 0, 0])),
        field!(
            Fq,
            BigInteger384([
                9255502405446297221,
                10229180150694123945,
                9215585410771530959,
                13357015519562362907,
                5437107869987383107,
                16259554076827459,
            ])
        ),
    );

    #[inline(always)]
    fn mul_by_a(_: &Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }

    fn is_in_correct_subgroup_assuming_on_curve(
        p: &crate::templates::short_weierstrass_jacobian::Affine<Self>,
    ) -> bool {
        p.mul_bits(BitIteratorBE::new(Self::ScalarField::characteristic())).is_zero()
    }

    fn glv_endomorphism(
        mut p: crate::templates::short_weierstrass_jacobian::Affine<Self>,
    ) -> crate::templates::short_weierstrass_jacobian::Affine<Self> {
        p.x.mul_by_fp(&Self::PHI.c1);
        p
    }

    fn mul_projective(
        p: crate::templates::short_weierstrass_jacobian::Projective<Self>,
        by: Self::ScalarField,
    ) -> crate::templates::short_weierstrass_jacobian::Projective<Self> {
        type ScalarBigInt = <Fr as PrimeField>::BigInteger;

        /// The scalar multiplication window size.
        const GLV_WINDOW_SIZE: usize = 4;

        /// The table size, used for w-ary NAF recoding.
        const TABLE_SIZE: i64 = 1 << (GLV_WINDOW_SIZE + 1);
        const HALF_TABLE_SIZE: i64 = 1 << (GLV_WINDOW_SIZE);
        const MASK_FOR_MOD_TABLE_SIZE: u64 = (TABLE_SIZE as u64) - 1;
        /// The GLV table length.
        const L: usize = 1 << (GLV_WINDOW_SIZE - 1);

        let decomposition = by.decompose(&Self::Q1, &Self::Q2, Self::B1, Self::B2, Self::R128, &Self::HALF_R);

        // Prepare tables.
        let mut t_1 = Vec::with_capacity(L);
        let double = crate::templates::short_weierstrass_jacobian::Affine::<Self>::from(p.double());
        t_1.push(p);
        for i in 1..L {
            t_1.push(t_1[i - 1].add_mixed(&double));
        }
        let t_1 =
            crate::templates::short_weierstrass_jacobian::Projective::<Self>::batch_normalization_into_affine(t_1);

        let t_2 = t_1.iter().copied().map(Self::glv_endomorphism).collect::<Vec<_>>();

        let mod_signed = |d| {
            let d_mod_window_size = i64::try_from(d & MASK_FOR_MOD_TABLE_SIZE).unwrap();
            if d_mod_window_size >= HALF_TABLE_SIZE { d_mod_window_size - TABLE_SIZE } else { d_mod_window_size }
        };
        let to_wnaf = |e: Self::ScalarField| -> Vec<i32> {
            let mut naf = vec![];
            let mut e = e.to_bigint();
            while !e.is_zero() {
                let next = if e.is_odd() {
                    let naf_sign = mod_signed(e.as_ref()[0]);
                    if naf_sign < 0 {
                        e.add_nocarry(&ScalarBigInt::from(-naf_sign as u64));
                    } else {
                        e.sub_noborrow(&ScalarBigInt::from(naf_sign as u64));
                    }
                    naf_sign.try_into().unwrap()
                } else {
                    0
                };
                naf.push(next);
                e.div2();
            }

            naf
        };

        let wnaf = |k1: Self::ScalarField, k2: Self::ScalarField, s1: bool, s2: bool| -> (Vec<i32>, Vec<i32>) {
            let mut wnaf_1 = to_wnaf(k1);
            let mut wnaf_2 = to_wnaf(k2);

            if s1 {
                wnaf_1.iter_mut().for_each(|e| *e = -*e);
            }
            if !s2 {
                wnaf_2.iter_mut().for_each(|e| *e = -*e);
            }

            (wnaf_1, wnaf_2)
        };

        let naf_add = |table: &[crate::templates::short_weierstrass_jacobian::Affine<Self>],
                       naf: i32,
                       acc: &mut crate::templates::short_weierstrass_jacobian::Projective<Self>| {
            if naf != 0 {
                let mut p_1 = table[(naf.abs() >> 1) as usize];
                if naf < 0 {
                    p_1 = p_1.neg();
                }
                acc.add_assign_mixed(&p_1);
            }
        };

        // Recode scalars.
        let (naf_1, naf_2) = wnaf(decomposition.0, decomposition.1, decomposition.2, decomposition.3);
        let max_len = naf_1.len().max(naf_2.len());
        let mut acc = crate::templates::short_weierstrass_jacobian::Projective::<Self>::zero();
        for i in (0..max_len).rev() {
            if i < naf_1.len() {
                naf_add(&t_1, naf_1[i], &mut acc)
            }

            if i < naf_2.len() {
                naf_add(&t_2, naf_2[i], &mut acc)
            }

            if i != 0 {
                acc.double_in_place();
            }
        }

        acc
    }
}

pub const G2_GENERATOR_X: Fq2 = field!(Fq2, G2_GENERATOR_X_C0, G2_GENERATOR_X_C1);
pub const G2_GENERATOR_Y: Fq2 = field!(Fq2, G2_GENERATOR_Y_C0, G2_GENERATOR_Y_C1);

///
/// G2_GENERATOR_X_C0 =
/// 170590608266080109581922461902299092015242589883741236963254737235977648828052995125541529645051927918098146183295
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bls12_377` for tests.
///
pub const G2_GENERATOR_X_C0: Fq = field!(
    Fq,
    BigInteger384::new([
        1394603105513884269,
        11069732150289508451,
        4261960060090787184,
        13457254148541472797,
        3177258746859163322,
        82258727112085846
    ])
);

///
/// G2_GENERATOR_X_C1 =
/// 83407003718128594709087171351153471074446327721872642659202721143408712182996929763094113874399921859453255070254
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bls12_377` for tests.
///
pub const G2_GENERATOR_X_C1: Fq = field!(
    Fq,
    BigInteger384::new([
        12672065269715576738,
        3451530808602826578,
        9486610028138952262,
        5031487885431614078,
        9858745210421513581,
        63301617551232910
    ])
);

///
/// G2_GENERATOR_Y_C0 =
/// 1843833842842620867708835993770650838640642469700861403869757682057607397502738488921663703124647238454792872005
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bls12_377` for tests.
///
pub const G2_GENERATOR_Y_C0: Fq = field!(
    Fq,
    BigInteger384::new([
        1855632670224768760,
        2989378521406112342,
        9748867374972564648,
        3204895972998458874,
        16520689795595505429,
        61918742406142643
    ])
);

///
/// G2_GENERATOR_Y_C1 =
/// 33145532013610981697337930729788870077912093258611421158732879580766461459275194744385880708057348608045241477209
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bls12_377` for tests.
///
pub const G2_GENERATOR_Y_C1: Fq = field!(
    Fq,
    BigInteger384::new([
        1532128906028652860,
        14539073382194201855,
        10828918286556702479,
        14664598863867299115,
        483199896405477997,
        73741830940675480
    ])
);
