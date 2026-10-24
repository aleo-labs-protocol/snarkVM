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

use std::sync::OnceLock;

use snarkvm_fields::{
    FftParameters,
    FieldParameters,
    Fp256,
    Fp256Parameters,
    PoseidonDefaultParameters,
    PoseidonDefaultParametersEntry,
    SqrtTables,
};
use snarkvm_utilities::biginteger::BigInteger256 as BigInteger;

/// BLS12-377 scalar field.
///
/// Roots of unity computed from modulus and R using this sage code:
///
/// ```r,ignore
/// q = 8444461749428370424248824938781546531375899335154063827935233455917409239041
/// R = 6014086494747379908336260804527802945383293308637734276299549080986809532403 # Montgomery R
/// s = 47
/// o = q - 1
/// F = GF(q)
/// g = F.multiplicative_generator()
/// assert g.multiplicative_order() == o
/// g2 = g ** (o/2**s)
/// assert g2.multiplicative_order() == 2**s
/// def into_chunks(val, width, n):
///     return [int(int(val) // (2 ** (width * i)) % 2 ** width) for i in range(n)]
/// print("Gen (g % q): ", g % q)
/// print("Gen (g * R % q): ", g * R % q)
/// print("Gen into_chunks(g * R % q): ", into_chunks(g * R % q, 64, 4))
/// print("2-adic gen (g2 % q): ", g2 % q)
/// print("2-adic gen (g2 * R % q): ", g2 * R % q)
/// print("2-adic gen into_chunks(g2 * R % q): ", into_chunks(g2 * R % q, 64, 4))
/// ```
pub type Fr = Fp256<FrParameters>;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrParameters;

impl Fp256Parameters for FrParameters {
    fn sqrt_tables() -> &'static SqrtTables<Fr> {
        static TABLES: OnceLock<SqrtTables<Fr>> = OnceLock::new();
        TABLES.get_or_init(SqrtTables::<Fr>::new)
    }
}

impl FftParameters for FrParameters {
    type BigInteger = BigInteger;

    #[rustfmt::skip]
    const TWO_ADICITY: u32 = 47;
    /// TWO_ADIC_ROOT_OF_UNITY = 8065159656716812877374967518403273466521432693661810619979959746626482506078
    /// Encoded in Montgomery form, the value is
    /// (8065159656716812877374967518403273466521432693661810619979959746626482506078 * R % q) =
    /// 7039866554349711480672062101017509031917008525101396696252683426045173093960
    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger([
        12646347781564978760u64,
        6783048705277173164u64,
        268534165941069093u64,
        1121515446318641358u64,
    ]);
}

impl FieldParameters for FrParameters {
    #[rustfmt::skip]
    const CAPACITY: u32 = Self::MODULUS_BITS - 1;
    /// GENERATOR = 22
    /// Encoded in Montgomery form, so the value is
    /// (22 * R) % q = 5642976643016801619665363617888466827793962762719196659561577942948671127251
    #[rustfmt::skip]
    const GENERATOR: BigInteger = BigInteger([
        2984901390528151251u64,
        10561528701063790279u64,
        5476750214495080041u64,
        898978044469942640u64,
    ]);
    #[rustfmt::skip]
    const INV: u64 = 725501752471715839u64;
    /// MODULUS = 8444461749428370424248824938781546531375899335154063827935233455917409239041
    #[rustfmt::skip]
    const MODULUS: BigInteger = BigInteger([
        725501752471715841u64,
        6461107452199829505u64,
        6968279316240510977u64,
        1345280370688173398u64,
    ]);
    #[rustfmt::skip]
    const MODULUS_BITS: u32 = 253;
    /// (r - 1)/2 =
    /// 4222230874714185212124412469390773265687949667577031913967616727958704619520
    #[rustfmt::skip]
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0x8508c00000000000,
        0xacd53b7f68000000,
        0x305a268f2e1bd800,
        0x955b2af4d1652ab,
    ]);
    #[rustfmt::skip]
    const R: BigInteger = BigInteger([
        9015221291577245683u64,
        8239323489949974514u64,
        1646089257421115374u64,
        958099254763297437u64,
    ]);
    #[rustfmt::skip]
    const R2: BigInteger = BigInteger([
        2726216793283724667u64,
        14712177743343147295u64,
        12091039717619697043u64,
        81024008013859129u64,
    ]);
    #[rustfmt::skip]
    const REPR_SHAVE_BITS: u32 = 3;
    // T and T_MINUS_ONE_DIV_TWO, where r - 1 = 2^s * t

    /// t = (r - 1) / 2^s =
    /// 60001509534603559531609739528203892656505753216962260608619555
    #[rustfmt::skip]
    const T: BigInteger = BigInteger([
        0xedfda00000021423,
        0x9a3cb86f6002b354,
        0xcabd34594aacc168,
        0x2556,
    ]);
    /// (t - 1) / 2 =
    /// 30000754767301779765804869764101946328252876608481130304309777
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        0x76fed00000010a11,
        0x4d1e5c37b00159aa,
        0x655e9a2ca55660b4,
        0x12ab,
    ]);
}

impl PoseidonDefaultParameters for FrParameters {
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultParametersEntry; 7] = [
        PoseidonDefaultParametersEntry::new(2, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(3, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(4, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(5, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(6, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(7, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(8, 17, 8, 31, 0),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_fields::{FftField, Field};

    #[test]
    fn test_two_adic_root_of_unity() {
        let expected = Fr::multiplicative_generator().pow(FrParameters::T);
        assert_eq!(expected, Fr::two_adic_root_of_unity());
    }
}
