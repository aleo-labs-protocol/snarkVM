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

use snarkvm_fields::{
    Fp2Parameters,
    field,
    fp6_3over2::{Fp6, Fp6Parameters},
};
use snarkvm_utilities::biginteger::BigInteger384;

use crate::bls12_377::{Fq, Fq2, Fq2Parameters, Fq2Unreduced, P2_2, P2_4, P2_6, P2_10, P2_12, P2_20, P2_30};

pub type Fq6 = Fp6<Fq6Parameters>;

/// Unreduced 768-bit cubic-over-quadratic extension element (`c0 + c1 * v + c2 * v^2`, `v^3 = u`).
#[derive(Copy, Clone)]
pub(crate) struct Fq6Unreduced {
    pub(crate) c0: Fq2Unreduced,
    pub(crate) c1: Fq2Unreduced,
    pub(crate) c2: Fq2Unreduced,
}

impl Fq6Unreduced {
    /// Unreduced Karatsuba multiplication (`6` unreduced `Fq2` muls = `18` 6x6 muls, zero Montgomery reductions).
    /// Output bounds: every `.c0 < 36 * p^2` and every `.c1 < 20 * p^2`.
    #[inline]
    pub(crate) fn mul(a: &Fq6, b: &Fq6) -> Self {
        let v0 = Fq2Unreduced::mul(&a.c0, &b.c0);
        let v1 = Fq2Unreduced::mul(&a.c1, &b.c1);
        let v2 = Fq2Unreduced::mul(&a.c2, &b.c2);

        let t0 = Fq2Unreduced::mul(&(a.c1 + a.c2), &(b.c1 + b.c2));
        let t1 = Fq2Unreduced::mul(&(a.c0 + a.c1), &(b.c0 + b.c1));
        let t2 = Fq2Unreduced::mul(&(a.c0 + a.c2), &(b.c0 + b.c2));

        let s0 = t0.sub2_with_bias(&v1, &v2, &P2_12, &P2_4);
        let c0 = v0.add(&s0.mul_by_u(&P2_30));

        let s1 = t1.sub2_with_bias(&v0, &v1, &P2_12, &P2_4);
        let c1 = s1.add(&v2.mul_by_u(&P2_10));

        let c2 = t2.sub2_with_bias(&v0, &v2, &P2_12, &P2_4).add(&v1);
        Self { c0, c1, c2 }
    }

    /// Unreduced sparse multiplication `a * (c0 + c1 * v)` (`5` unreduced `Fq2` muls, zero Montgomery reductions).
    /// Output bounds: every `.c0 < 26 * p^2` and every `.c1 < 14 * p^2`, with `out.c2 < (18, 6) * p^2`.
    #[inline]
    pub(crate) fn mul_by_01(a: &Fq6, c0: &Fq2, c1: &Fq2) -> Self {
        let aa = Fq2Unreduced::mul(&a.c0, c0);
        let bb = Fq2Unreduced::mul(&a.c1, c1);

        let t1 = Fq2Unreduced::mul(&(a.c1 + a.c2), c1);
        let s1 = t1.sub_with_bias(&bb, &P2_6, &P2_2);
        let out_c0 = aa.add(&s1.mul_by_u(&P2_20));

        let t3 = Fq2Unreduced::mul(&(a.c0 + a.c2), c0);
        let out_c2 = t3.sub_with_bias(&aa, &P2_6, &P2_2).add(&bb);

        let t2 = Fq2Unreduced::mul(&(a.c0 + a.c1), &(*c0 + c1));
        let out_c1 = t2.sub2_with_bias(&aa, &bb, &P2_12, &P2_4);

        Self { c0: out_c0, c1: out_c1, c2: out_c2 }
    }

    #[inline(always)]
    pub(crate) fn add(&self, other: &Self) -> Self {
        Self { c0: self.c0.add(&other.c0), c1: self.c1.add(&other.c1), c2: self.c2.add(&other.c2) }
    }

    #[inline(always)]
    pub(crate) fn reduce(self) -> Fq6 {
        Fq6::new(self.c0.reduce(), self.c1.reduce(), self.c2.reduce())
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fq6Parameters;

impl snarkvm_fields::sealed_parameters::Sealed for Fq6Parameters {}

impl Fp6Parameters for Fq6Parameters {
    type Fp2Params = Fq2Parameters;

    const FROBENIUS_COEFF_FP6_C1: [Fq2; 6] = [
        // Fp2::NONRESIDUE^(((q^0) - 1) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x2cdffffffffff68,
                    0x51409f837fffffb1,
                    0x9f7db3a98a7d3ff2,
                    0x7b4e97b76e7c6305,
                    0x4cf495bf803c84e8,
                    0x8d6661e2fdf49a,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^(((q^1) - 1) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x5892506da58478da,
                    0x133366940ac2a74b,
                    0x9b64a150cdf726cf,
                    0x5cc426090a9c587e,
                    0x5cf848adfdcd640c,
                    0x4702bf3ac02380,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^(((q^2) - 1) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0xdacd106da5847973,
                    0xd8fe2454bac2a79a,
                    0x1ada4fd6fd832edc,
                    0xfb9868449d150908,
                    0xd63eb8aeea32285e,
                    0x167d6a36f873fd0,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^(((q^3) - 1) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x823ac00000000099,
                    0xc5cabdc0b000004f,
                    0x7f75ae862f8c080d,
                    0x9ed4423b9278b089,
                    0x79467000ec64c452,
                    0x120d3e434c71c50,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^(((q^4) - 1) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x2c766f925a7b8727,
                    0x3d7f6b0253d58b5,
                    0x838ec0deec122131,
                    0xbd5eb3e9f658bb10,
                    0x6942bd126ed3e52e,
                    0x1673786dd04ed6a,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^(((q^5) - 1) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0xaa3baf925a7b868e,
                    0x3e0d38ef753d5865,
                    0x4191258bc861923,
                    0x1e8a71ae63e00a87,
                    0xeffc4d11826f20dc,
                    0x4663a2a83dd119,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
    ];
    const FROBENIUS_COEFF_FP6_C2: [Fq2; 6] = [
        // Fp2::NONRESIDUE^((2*(q^0) - 2) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x2cdffffffffff68,
                    0x51409f837fffffb1,
                    0x9f7db3a98a7d3ff2,
                    0x7b4e97b76e7c6305,
                    0x4cf495bf803c84e8,
                    0x8d6661e2fdf49a,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^((2*(q^1) - 2) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0xdacd106da5847973,
                    0xd8fe2454bac2a79a,
                    0x1ada4fd6fd832edc,
                    0xfb9868449d150908,
                    0xd63eb8aeea32285e,
                    0x167d6a36f873fd0,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^((2*(q^2) - 2) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x2c766f925a7b8727,
                    0x3d7f6b0253d58b5,
                    0x838ec0deec122131,
                    0xbd5eb3e9f658bb10,
                    0x6942bd126ed3e52e,
                    0x1673786dd04ed6a,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^((2*(q^3) - 2) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x2cdffffffffff68,
                    0x51409f837fffffb1,
                    0x9f7db3a98a7d3ff2,
                    0x7b4e97b76e7c6305,
                    0x4cf495bf803c84e8,
                    0x8d6661e2fdf49a,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^((2*(q^4) - 2) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0xdacd106da5847973,
                    0xd8fe2454bac2a79a,
                    0x1ada4fd6fd832edc,
                    0xfb9868449d150908,
                    0xd63eb8aeea32285e,
                    0x167d6a36f873fd0,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
        // Fp2::NONRESIDUE^((2*(q^5) - 2) / 3)
        field!(
            Fq2,
            field!(
                Fq,
                BigInteger384([
                    0x2c766f925a7b8727,
                    0x3d7f6b0253d58b5,
                    0x838ec0deec122131,
                    0xbd5eb3e9f658bb10,
                    0x6942bd126ed3e52e,
                    0x1673786dd04ed6a,
                ])
            ),
            field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0])),
        ),
    ];
    /// NONRESIDUE = U
    const NONRESIDUE: Fq2 = field!(
        Fq2,
        field!(Fq, BigInteger384([0, 0, 0, 0, 0, 0])),
        field!(
            Fq,
            BigInteger384([
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
    fn mul_fp2_by_nonresidue(fe: &Fq2) -> Fq2 {
        // Karatsuba multiplication with constant other = u.
        let c0 = Fq2Parameters::mul_fp_by_nonresidue(&fe.c1);
        let c1 = fe.c0;
        field!(Fq2, c0, c1)
    }

    #[inline]
    fn mul_assign_fp6(a: &mut Fq6, b: &Fq6) {
        *a = Fq6Unreduced::mul(a, b).reduce();
    }

    /// Lazy-reduced Chung-Hasan SQR2 squaring (`3` unreduced `Fq2` squares + `2` unreduced `Fq2` muls,
    /// `6` Montgomery reductions; all limbs `< 42 * p^2 < p * 2^384`).
    #[inline]
    fn square_in_place_fp6(a: &mut Fq6) {
        let s0 = Fq2Unreduced::square(&a.c0);
        let ab = Fq2Unreduced::mul(&a.c0, &a.c1);
        let s1 = ab.add(&ab);
        let s2 = Fq2Unreduced::square(&(a.c0 - a.c1 + a.c2));
        let bc = Fq2Unreduced::mul(&a.c1, &a.c2);
        let s3 = bc.add(&bc);
        let s4 = Fq2Unreduced::square(&a.c2);

        let c0 = s0.add(&s3.mul_by_u(&P2_20));
        let c1 = s1.add(&s4.mul_by_u(&P2_10));
        let c2 = s1.add(&s2).add(&s3).sub2_with_bias(&s0, &s4, &P2_12, &P2_4);

        *a = Fq6Unreduced { c0, c1, c2 }.reduce();
    }

    #[inline]
    fn mul_by_01_fp6(a: &mut Fq6, c0: &Fq2, c1: &Fq2) {
        *a = Fq6Unreduced::mul_by_01(a, c0, c1).reduce();
    }
}

#[cfg(test)]
mod test {
    use snarkvm_fields::{One, Zero};
    use snarkvm_utilities::rand::{TestRng, Uniform};

    use super::*;

    #[test]
    fn test_fq2_mul_nonresidue() {
        let mut rng = TestRng::default();

        let nqr = Fq2::new(Fq::zero(), Fq::one());
        println!("One: {:?}", Fq::one());

        for _ in 0..1000 {
            let mut a = Fq2::rand(&mut rng);
            let mut b = a;
            a *= &Fq6Parameters::NONRESIDUE;
            b *= &nqr;

            assert_eq!(a, b);
        }
    }
}
