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

use serde::{Deserialize, Serialize};

use snarkvm_fields::{Field, Fp2, Fp2Parameters, field};
use snarkvm_utilities::biginteger::BigInteger384 as BigInteger;

use crate::bls12_377::Fq;

pub type Fq2 = Fp2<Fq2Parameters>;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fq2Parameters;

impl snarkvm_fields::sealed_parameters::Sealed for Fq2Parameters {}

impl Fp2Parameters for Fq2Parameters {
    type Fp = Fq;

    /// Coefficients for the Frobenius automorphism.
    const FROBENIUS_COEFF_FP2_C1: [Fq; 2] = [
        // NONRESIDUE**(((q^0) - 1) / 2)
        field!(
            Fq,
            BigInteger([
                0x2cdffffffffff68,
                0x51409f837fffffb1,
                0x9f7db3a98a7d3ff2,
                0x7b4e97b76e7c6305,
                0x4cf495bf803c84e8,
                0x8d6661e2fdf49a,
            ])
        ),
        // NONRESIDUE**(((q^1) - 1) / 2)
        field!(
            Fq,
            BigInteger([
                0x823ac00000000099,
                0xc5cabdc0b000004f,
                0x7f75ae862f8c080d,
                0x9ed4423b9278b089,
                0x79467000ec64c452,
                0x120d3e434c71c50,
            ])
        ),
    ];
    /// NONRESIDUE = -5
    const NONRESIDUE: Fq = field!(
        Fq,
        BigInteger([
            0xfc0b8000000002fa,
            0x97d39cf6e000018b,
            0x2072420fbfa05044,
            0xcbbcbd50d97c3802,
            0xbaf1ec35813f9eb,
            0x9974a2c0945ad2,
        ])
    );
    /// QUADRATIC_NONRESIDUE = U
    const QUADRATIC_NONRESIDUE: (Fq, Fq) = (
        field!(Fq, BigInteger([0, 0, 0, 0, 0, 0])),
        field!(
            Fq,
            BigInteger([
                202099033278250856u64,
                5854854902718660529u64,
                11492539364873682930u64,
                8885205928937022213u64,
                5545221690922665192u64,
                39800542322357402u64,
            ])
        ),
    );

    #[inline(always)]
    fn mul_fp_by_nonresidue(fe: &Self::Fp) -> Self::Fp {
        let original = fe;
        let mut fe = -fe.double();
        fe.double_in_place();
        fe - original
    }
}
