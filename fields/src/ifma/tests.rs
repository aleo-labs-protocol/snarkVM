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

//! The kernel edge cases, the reductions on every multiple of `p` they accept, and `mul_8`, 8
//! independent products through `mont`, as the oracle for the kernel against the scalar product.

use super::{
    cyclotomic::pair_sums,
    is_supported,
    kernel::{below_2p, canonical, canonical_vectors, mont, quotient_estimate, shift_left},
    layout::{
        MASK,
        Z,
        element_words,
        lane_words,
        limbs,
        limbs_shifted_32,
        modulus,
        permute_z,
        radix_52,
        splat,
        to_array,
        vector,
        words,
    },
};
use crate::{
    FftParameters,
    FieldParameters,
    Fp384,
    Fp384Parameters,
    One,
    PoseidonDefaultParameters,
    PoseidonDefaultParametersEntry,
    Zero,
};
use snarkvm_utilities::{
    BigInteger,
    BigInteger384,
    rand::{TestRng, Uniform},
};

use rand::RngExt;
use std::arch::x86_64::*;

/// The BLS12-377 base field, with the constants of `snarkvm_curves::bls12_377::FqParameters`
/// but for the FFT roots, which no test here reads. The crate's own `Fp384` is not the one its
/// dev-dependency on `snarkvm-curves` instantiates, so the tests cannot take `Fq` from there.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
struct FqParameters;

type Fq = Fp384<FqParameters>;

impl Fp384Parameters for FqParameters {}

impl PoseidonDefaultParameters for FqParameters {
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultParametersEntry; 7] = [
        PoseidonDefaultParametersEntry::new(2, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(3, 5, 8, 56, 0),
        PoseidonDefaultParametersEntry::new(4, 5, 8, 56, 0),
        PoseidonDefaultParametersEntry::new(5, 5, 8, 57, 0),
        PoseidonDefaultParametersEntry::new(6, 5, 8, 57, 0),
        PoseidonDefaultParametersEntry::new(7, 5, 8, 57, 0),
        PoseidonDefaultParametersEntry::new(8, 5, 8, 57, 0),
    ];
}

impl FftParameters for FqParameters {
    type BigInteger = BigInteger384;

    const POWERS_OF_ROOTS_OF_UNITY: &'static [BigInteger384] = &[];
    const TWO_ADICITY: u32 = 46;
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger384 = BigInteger384([
        2022196864061697551,
        17419102863309525423,
        8564289679875062096,
        17152078065055548215,
        17966377291017729567,
        68610905582439508,
    ]);
}

impl FieldParameters for FqParameters {
    const CAPACITY: u32 = Self::MODULUS_BITS - 1;
    const GENERATOR: BigInteger384 = BigInteger384([
        0xfc0b8000000002fa,
        0x97d39cf6e000018b,
        0x2072420fbfa05044,
        0xcbbcbd50d97c3802,
        0xbaf1ec35813f9eb,
        0x9974a2c0945ad2,
    ]);
    const INV: u64 = 9586122913090633727;
    const MODULUS: BigInteger384 = BigInteger384(MODULI[0]);
    const MODULUS_BITS: u32 = 377;
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger384 = BigInteger384([
        0x4284600000000000,
        0xb85aea218000000,
        0x8f79b117dd04a400,
        0x8d116cf9807a89c7,
        0x631d82e03650a49d,
        0xd71d230be28875,
    ]);
    const R: BigInteger384 = BigInteger384([
        202099033278250856,
        5854854902718660529,
        11492539364873682930,
        8885205928937022213,
        5545221690922665192,
        39800542322357402,
    ]);
    const R2: BigInteger384 = BigInteger384([
        0xb786686c9400cd22,
        0x329fcaab00431b1,
        0x22a5f11162d6b46d,
        0xbfdf7d03827dc3ac,
        0x837e92f041790bf9,
        0x6dfccb1e914b88,
    ]);
    const REPR_SHAVE_BITS: u32 = 7;
    const T: BigInteger384 = BigInteger384([
        0x7510c00000021423,
        0x88bee82520005c2d,
        0x67cc03d44e3c7bcd,
        0x1701b28524ec688b,
        0xe9185f1443ab18ec,
        0x6b8,
    ]);
    const T_MINUS_ONE_DIV_TWO: BigInteger384 = BigInteger384([
        0xba88600000010a11,
        0xc45f741290002e16,
        0xb3e601ea271e3de6,
        0xb80d94292763445,
        0x748c2f8a21d58c76,
        0x35c,
    ]);
}

/// The BLS12-377 base field modulus, and the moduli at the bounds of `mul_assign_fp12`.
const MODULI: [[u64; 6]; 3] = [
    [
        0x8508c00000000001,
        0x170b5d4430000000,
        0x1ef3622fba094800,
        0x1a22d9f300f5138f,
        0xc63b05c06ca1493b,
        0x01ae3a4617c510ea,
    ],
    [1, 0, 0, 0, 0, 1 << 46],
    [u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, (1 << 57) - 1],
];

/// Runs `check`, which needs at most AVX-512F and AVX-512 IFMA, where `is_supported` is true.
fn run_check(check: unsafe fn(&mut TestRng)) {
    if is_supported::<FqParameters>() {
        // SAFETY: `is_supported` detected both target features.
        unsafe { check(&mut TestRng::default()) };
    }
}

/// Returns `a[i] * b[i]` for each `i`, or `None` if `is_supported::<P>()` is false.
fn mul_8<P: Fp384Parameters>(a: &[Fp384<P>; 8], b: &[Fp384<P>; 8]) -> Option<[Fp384<P>; 8]> {
    if !is_supported::<P>() {
        return None;
    }
    // SAFETY: `is_supported` detected both target features that `mul_8_avx512` enables.
    Some(unsafe { mul_8_avx512(a, b) })
}

/// Returns `a[i] * b[i]` for each `i`. Requires `P::MODULUS_BITS <= 377`.
///
/// `a[i]` enters the kernel as the integer `a[i] R 2^32`, below 2^409, and `b[i]` as `b[i] R`,
/// with R = 2^384. The kernel divides by 2^416, so it returns `a[i] b[i] R`, the Montgomery form
/// of the product.
///
/// # Safety
///
/// The CPU supports AVX-512F and AVX-512 IFMA.
#[target_feature(enable = "avx512f,avx512ifma")]
unsafe fn mul_8_avx512<P: Fp384Parameters>(a: &[Fp384<P>; 8], b: &[Fp384<P>; 8]) -> [Fp384<P>; 8] {
    let p = modulus::<P>();
    let n0 = _mm512_set1_epi64((P::INV & MASK) as i64);

    let a = limbs_shifted_32(&element_words(a.each_ref()));
    let b = limbs(&element_words(b.each_ref()));
    // SAFETY: this function enables both target features that `mont` requires.
    let c = unsafe { mont(&a, &b, &p, n0) };
    let w = words(&c).map(|v| to_array(v));
    std::array::from_fn(|l| crate::field!(Fp384, BigInteger384(std::array::from_fn(|j| w[j][l]))))
}

/// The elements at the edges of the kernel's input range: 0, 1, 2, -1, -2, and the Montgomery
/// words 1, 2, p - 1 and R^2.
fn fq_edge_elements() -> Vec<Fq> {
    let mut p_minus_1 = FqParameters::MODULUS;
    p_minus_1.sub_noborrow(&BigInteger384::from(1));
    let montgomery = |w: BigInteger384| -> Fq { crate::field!(Fq, w) };
    vec![
        Fq::zero(),
        Fq::one(),
        Fq::from(2u64),
        -Fq::one(),
        -Fq::from(2u64),
        montgomery(BigInteger384::from(1)),
        montgomery(BigInteger384::from(2)),
        montgomery(p_minus_1),
        montgomery(FqParameters::R2),
    ]
}

fn check_fq_mul_8(a: &[Fq; 8], b: &[Fq; 8]) {
    let Some(c) = mul_8(a, b) else {
        return;
    };
    for i in 0..8 {
        assert!(c[i].is_valid(), "lane {i}: {} * {}", a[i], b[i]);
        assert_eq!(c[i], a[i] * b[i], "lane {i}: {} * {}", a[i], b[i]);
    }
}

#[test]
fn test_mul_8() {
    let mut rng = TestRng::default();

    // Every ordered pair of edge elements, in every lane.
    let edges = fq_edge_elements();
    let pairs: Vec<(Fq, Fq)> = edges.iter().flat_map(|a| edges.iter().map(move |b| (*a, *b))).collect();
    for offset in 0..8 {
        for chunk in pairs.chunks(8) {
            let a = std::array::from_fn(|i| chunk[(i + offset) % chunk.len()].0);
            let b = std::array::from_fn(|i| chunk[(i + offset) % chunk.len()].1);
            check_fq_mul_8(&a, &b);
        }
    }

    // Edge elements mixed with random ones across the lanes.
    for _ in 0..10_000 {
        let pick = |rng: &mut TestRng| {
            if rng.random_bool(0.25) { edges[rng.random_range(0..edges.len())] } else { Fq::rand(rng) }
        };
        let a = std::array::from_fn(|_| pick(&mut rng));
        let b = std::array::from_fn(|_| pick(&mut rng));
        check_fq_mul_8(&a, &b);
    }

    // Random elements only.
    for _ in 0..10_000 {
        let a = std::array::from_fn(|_| Fq::rand(&mut rng));
        let b = std::array::from_fn(|_| Fq::rand(&mut rng));
        check_fq_mul_8(&a, &b);
    }
}

#[test]
fn test_quotient_estimate() {
    let r = BigInteger384::from(1).to_biguint() << 416u32;
    for p in &MODULI {
        let q = quotient_estimate(p);
        let p = BigInteger384(*p).to_biguint();
        assert!(p.clone() * q <= r && p * (q + 1) > r, "{q}");
    }
}

/// The residues the reductions take: 0, 1, `p - 1` and 61 random values below `p`.
fn residues(rng: &mut TestRng) -> Vec<[u64; 6]> {
    let mut p_minus_1 = MODULI[0];
    p_minus_1[0] -= 1;
    [[0; 6], [1, 0, 0, 0, 0, 0], p_minus_1].into_iter().chain((0..61).map(|_| Fq::rand(rng).0.0)).collect()
}

/// Returns `k p + r` as 8 lane limbs: `r_j + k p_j`, as signed limbs, for `k < 0`, and the limbs
/// of the integer, below 2^416, otherwise.
fn lane_limbs(k: i64, r: &[u64; 6]) -> [u64; 8] {
    let p = MODULI[0];
    if k < 0 {
        let (r, p) = (radix_52(r), radix_52(&p));
        std::array::from_fn(|j| (r[j] as i64 + k * p[j] as i64) as u64)
    } else {
        let x = BigInteger384(p).to_biguint() * (k as u64) + BigInteger384(*r).to_biguint();
        let mut words = [0; 7];
        for (w, d) in words.iter_mut().zip(x.to_u64_digits()) {
            *w = d;
        }
        radix_52(&words)
    }
}

/// Returns the vectors whose lane `l` holds `k p + r[l]`, as `lane_limbs` gives it.
#[target_feature(enable = "avx512f")]
fn lanes(k: i64, r: &[[u64; 6]]) -> [__m512i; 8] {
    let limbs: Vec<[u64; 8]> = r.iter().map(|r| lane_limbs(k, r)).collect();
    std::array::from_fn(|j| vector(std::array::from_fn(|l| limbs.get(l).map_or(0, |v| v[j]))))
}

#[test]
fn test_canonical() {
    run_check(check_canonical);
}

/// Checks `canonical` on `k p + r` for every `k` in `[-64, 64)` and every residue of `residues`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn check_canonical(rng: &mut TestRng) {
    let (p, (offset, estimate)) = (modulus::<FqParameters>(), canonical_vectors::<FqParameters>());
    let rs = residues(rng);
    for k in -64i64..64 {
        for r in rs.chunks(8) {
            let c = canonical(&lanes(k, r), &p, &offset, estimate).map(|v| to_array(v));
            for (l, r) in r.iter().enumerate() {
                let got: [u64; 8] = std::array::from_fn(|j| c[j][l]);
                assert_eq!(got, radix_52(r), "k = {k}, lane {l}");
            }
        }
    }
}

#[test]
fn test_below_2p() {
    run_check(check_below_2p);
}

/// Checks `below_2p` with the offset `64 p`: see `check_below_2p_with`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn check_below_2p(rng: &mut TestRng) {
    let (offset, _) = canonical_vectors::<FqParameters>();
    check_below_2p_with(rng, &offset, 64, (1 << 33) - 1);
}

/// Checks `below_2p` with `offset` on `k p + r` for `k` in `[-m, m)`, at `2^32 - 1`, `2^32`, `top`
/// and at 32 random values up to `top`, and every residue of `residues`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn check_below_2p_with(rng: &mut TestRng, offset: &[__m512i; 8], m: i64, top: i64) {
    let (p, (_, estimate)) = (modulus::<FqParameters>(), canonical_vectors::<FqParameters>());
    let rs = residues(rng);
    let ks: Vec<i64> =
        (-m..m).chain([(1 << 32) - 1, 1 << 32, top]).chain((0..32).map(|_| rng.random_range(0..=top))).collect();
    for k in ks {
        for r in rs.chunks(8) {
            let c = below_2p(&lanes(k, r), &p, offset, estimate).map(|v| to_array(v));
            for (l, r) in r.iter().enumerate() {
                let got: [u64; 8] = std::array::from_fn(|j| c[j][l]);
                assert!(got == radix_52(r) || got == lane_limbs(1, r), "k = {k}, lane {l}");
            }
        }
    }
}

#[test]
fn test_below_2p_offset_128p() {
    run_check(check_below_2p_offset_128p);
}

/// Checks `below_2p` with the offset `128 p`, the Miller loop squaring's: see `check_below_2p_with`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn check_below_2p_offset_128p(rng: &mut TestRng) {
    let offset = splat(&radix_52(&shift_left(&MODULI[0], 7)));
    check_below_2p_with(rng, &offset, 128, (1 << 33) - 129);
}

#[test]
fn test_shift_left() {
    for p in &MODULI {
        for s in [1, 6] {
            assert_eq!(BigInteger384(shift_left(p, s)).to_biguint(), BigInteger384(*p).to_biguint() << s);
        }
    }
}

#[test]
fn test_permute_z() {
    run_check(check_permute_z);
}

/// Checks `permute_z` on vectors whose lane `l` of vector `k` holds `100 k + l` in `e` and
/// `100 k + 8 + l` in `f`: lane `t` of the result holds `100 k + index[t]`, or zero at `Z`.
#[target_feature(enable = "avx512f")]
fn check_permute_z(_: &mut TestRng) {
    let e: [__m512i; 8] = std::array::from_fn(|k| vector(std::array::from_fn(|l| (100 * k + l) as u64)));
    let f: [__m512i; 8] = std::array::from_fn(|k| vector(std::array::from_fn(|l| (100 * k + 8 + l) as u64)));
    for index in [[3, Z, 15, 8, Z, 0, 7, 9], [Z; 8], [0, 1, 2, 3, 4, 5, 6, 7], [8, 9, 10, 11, 12, 13, 14, 15]] {
        let v = permute_z(&e, index, &f).map(|v| to_array(v));
        for (k, v) in v.iter().enumerate() {
            let expected: [u64; 8] = std::array::from_fn(|t| if index[t] == Z { 0 } else { 100 * k as u64 + index[t] });
            assert_eq!(*v, expected, "{index:?}, vector {k}");
        }
    }
}

#[test]
fn test_lane_words() {
    run_check(check_lane_words);
}

/// Checks `lane_words` on 12 random elements: lane `l` of word `w` holds word `w` of element
/// `index[l]`, or zero at `Z`.
#[target_feature(enable = "avx512f")]
fn check_lane_words(rng: &mut TestRng) {
    let x: [Fq; 12] = std::array::from_fn(|_| Fq::rand(rng));
    let x_ref = x.each_ref();
    for index in [[0, 1, 8, 9, 6, 7, 4, 5], [2, 3, 10, 11, Z, Z, Z, Z], [11, Z, 0, Z, 5, Z, 10, Z]] {
        let v = lane_words(&x_ref, index).map(|v| to_array(v));
        for (w, v) in v.iter().enumerate() {
            let expected: [u64; 8] =
                std::array::from_fn(|l| if index[l] == Z { 0 } else { x[index[l] as usize].0.0[w] });
            assert_eq!(*v, expected, "{index:?}, word {w}");
        }
    }
}

#[test]
fn test_pair_sums() {
    run_check(check_pair_sums);
}

/// Checks `pair_sums` with `e` and `o` at 0, `p - 1`, `2 p - 1`, `floor(16 p / 5)` and random
/// values below `2 p`, in every lane of the mask and outside it.
#[target_feature(enable = "avx512f")]
fn check_pair_sums(rng: &mut TestRng) {
    let p16 = BigInteger384(shift_left(&MODULI[0], 4));
    let mut p_minus_1 = BigInteger384(MODULI[0]);
    p_minus_1.sub_noborrow(&BigInteger384::from(1));
    let mut two_p_minus_1 = BigInteger384(MODULI[0]);
    two_p_minus_1.mul2();
    two_p_minus_1.sub_noborrow(&BigInteger384::from(1));
    // `floor(16 p / 5)`, by long division of the words from the top.
    let mut bound = p16;
    let mut remainder = 0u128;
    for w in bound.0.iter_mut().rev() {
        let value = remainder << 64 | *w as u128;
        *w = (value / 5) as u64;
        remainder = value % 5;
    }
    let mut values = vec![BigInteger384::from(0), p_minus_1, two_p_minus_1, bound];
    values.extend((0..12).map(|_| {
        let mut x = Fq::rand(rng).0;
        x.mul2();
        x.add_nocarry(&BigInteger384::from(rng.random_range(0..2u64)));
        x
    }));
    let pairs: Vec<(BigInteger384, BigInteger384)> =
        values.iter().flat_map(|e| values.iter().map(move |o| (*e, *o))).collect();
    let p16_lanes = splat(&radix_52(&p16.0));
    for k in [0u8, 0xFF, 0b1010_1010, 0b1000_1010] {
        for chunk in pairs.chunks(8) {
            let (es, os): (Vec<[u64; 6]>, Vec<[u64; 6]>) = chunk.iter().map(|(e, o)| (e.0, o.0)).unzip();
            let v = pair_sums(&lanes(0, &es), &lanes(0, &os), k, &p16_lanes).map(|v| to_array(v));
            for (l, (e, o)) in chunk.iter().enumerate() {
                let mut expected = *e;
                if k >> l & 1 == 1 {
                    let mut five = *o;
                    five.muln(2);
                    five.add_nocarry(o);
                    expected.add_nocarry(&p16);
                    expected.sub_noborrow(&five);
                } else {
                    expected.add_nocarry(o);
                }
                let got: [u64; 8] = std::array::from_fn(|j| v[j][l]);
                assert_eq!(got, radix_52(&expected.0), "mask {k:#b}, lane {l}: {e} and {o}");
            }
        }
    }
}
