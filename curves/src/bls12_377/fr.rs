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
    const POWERS_OF_ROOTS_OF_UNITY: &'static [BigInteger] = &[
        BigInteger([12646347781564978760, 6783048705277173164, 268534165941069093, 1121515446318641358]),
        BigInteger([9908812190343590727, 989981212292874635, 13217848517394370016, 313220887743686251]),
        BigInteger([4570942453055933478, 14327950181157151272, 8177734713484223276, 732395113570565582]),
        BigInteger([7547026561639937065, 11733968610145256351, 8343216976141027051, 576989125389526455]),
        BigInteger([15503117548499178639, 2308620569553928151, 16285062430639685160, 103769458534362861]),
        BigInteger([8608407781632583430, 6271302370352858992, 1070338101025660973, 538942973387907962]),
        BigInteger([6401736382236295208, 1153288719752352283, 14823640363840104239, 499246014633910619]),
        BigInteger([17833850933386010261, 6090852137313170745, 12528041030915574153, 857737301371729770]),
        BigInteger([1982048757083514280, 12158391317477180280, 13684570609270614441, 840786117129730731]),
        BigInteger([18189047035874409266, 10063848728508956944, 18125989563719264563, 109154778261203350]),
        BigInteger([4145860318443588715, 480045415555849201, 15185689511254420012, 997424544238423752]),
        BigInteger([12380934610292147810, 14921791250714101079, 7953234348116523713, 740566716969780590]),
        BigInteger([17523206016699816339, 8210268852326501515, 12102826939441359278, 69320453637394156]),
        BigInteger([13184634841845083965, 5035641472528052881, 10848835132746879957, 1093292728521196096]),
        BigInteger([3644591431389930536, 17535182174514028817, 2333780137994975086, 1211430046545197955]),
        BigInteger([15764618857955124109, 17001304349044012093, 11249158843350648159, 1304234597518548509]),
        BigInteger([17023740166556598291, 17327346947230052231, 15227607426000437488, 524356170404741496]),
        BigInteger([15508095723619167236, 8916154698977858924, 4872918458681303657, 507246242966933127]),
        BigInteger([13933261170268378635, 6975150440507062408, 285981162592700355, 909990229706841196]),
        BigInteger([1796369225555089555, 18439169056424861976, 8554690303853538396, 739593369575156928]),
        BigInteger([8849035624997270559, 11082174508102696985, 5797273297011026936, 458094565250654809]),
        BigInteger([5944936778479914843, 369725202543584470, 22913969483319861, 1123237285519395196]),
        BigInteger([8228193452833987056, 3247446711273005067, 7285244012699814841, 165660218100066147]),
        BigInteger([16110965290454180518, 5418683100417587062, 11303731202360030209, 290121373407754357]),
        BigInteger([10742665076645341070, 7056370150642984550, 12615465793934837989, 548498362185685512]),
        BigInteger([8097456064175987351, 10585807130451162109, 5877015307964227995, 477368390704686837]),
        BigInteger([15676770081073062471, 12262153699415403306, 7528677848461606057, 649917933945894399]),
        BigInteger([18271947154240526633, 11103933895114620578, 16558660923152452318, 925331653431062360]),
        BigInteger([3907589926240897769, 11045697709584246531, 90835143142482923, 870886311473863909]),
        BigInteger([3528144693560331180, 11121597045360901952, 11405196888439666838, 670327805282996966]),
        BigInteger([13456528212939925364, 9040660049171970165, 4374817133042500768, 422841521572866881]),
        BigInteger([17220360707710309003, 7704697058569325505, 14703012148831508770, 113932329837224644]),
        BigInteger([15456395681208503803, 6416534260312397167, 4409371950760456950, 855302230113322418]),
        BigInteger([14648805411005782346, 659899539555743592, 13712138229698623536, 688628542983365223]),
        BigInteger([17553691999655354057, 12414962864428128502, 12778610342023380950, 309906985245362430]),
        BigInteger([13671771363231792901, 13550649581906397391, 14960300922341772840, 197239424530289859]),
        BigInteger([14840183457516239942, 7651729362259515675, 11442121706837547178, 409184120412760908]),
        BigInteger([5849560869621087513, 6649867980513935874, 16080766030443795594, 905356649678185654]),
        BigInteger([13302147401216114106, 3611900969696901525, 3470557722594359823, 950175460673052306]),
        BigInteger([16339580035428004219, 4845663562592066382, 6914211203719332907, 510216861370749871]),
        BigInteger([2145222547635311650, 10230679325758658394, 7207487648880633871, 209805430256584658]),
        BigInteger([9208812316068886018, 11169310505015993932, 8317257015293247865, 1090372203370214591]),
        BigInteger([18408280738886485821, 14547869021980959191, 6047025381655759581, 725535874718029226]),
        BigInteger([1670730338129557402, 7866724895305809984, 10026936948289003902, 781269171506367679]),
        BigInteger([4882877962169421051, 8060560647985508350, 4729166814476724001, 1147730753089737444]),
        BigInteger([5461406015399410446, 5014654494648953692, 8156709087178280082, 1299557346046566890]),
    ];
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
    use snarkvm_fields::{FftField, Field, PrimeField};

    #[test]
    fn test_powers_of_root_of_unity() {
        let two = Fr::from(2u8);

        // Compute the expected powers of root of unity.
        let root_of_unity = Fr::two_adic_root_of_unity();
        let powers = (0..FrParameters::TWO_ADICITY - 1)
            .map(|i| root_of_unity.pow(two.pow(Fr::from(i as u64).to_bigint()).to_bigint()))
            .collect::<Vec<_>>();
        assert_eq!(powers[0], Fr::two_adic_root_of_unity());

        // Ensure the correct number of powers of root of unity are present.
        assert_eq!(FrParameters::POWERS_OF_ROOTS_OF_UNITY.len() as u64, (FrParameters::TWO_ADICITY - 1) as u64);
        assert_eq!(FrParameters::POWERS_OF_ROOTS_OF_UNITY.len(), powers.len());

        // Ensure the expected and candidate powers match.
        for (expected, candidate) in powers.iter().zip(FrParameters::POWERS_OF_ROOTS_OF_UNITY) {
            // println!("BigInteger({:?}),", expected.0.0);
            println!("{:?} =?= {:?}", expected.0, candidate);
            assert_eq!(&expected.0, candidate);
        }
    }

    #[test]
    fn test_two_adic_root_of_unity() {
        let expected = Fr::multiplicative_generator().pow(FrParameters::T);
        assert_eq!(expected, Fr::two_adic_root_of_unity());
    }
}
