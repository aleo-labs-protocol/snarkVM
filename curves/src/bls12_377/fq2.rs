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

/// Unreduced 768-bit quadratic extension element over `Fq` (`c0 + c1 * u`, `u^2 = -5`).
#[derive(Copy, Clone)]
pub(crate) struct Fq2Unreduced {
    pub(crate) c0: [u64; 12],
    pub(crate) c1: [u64; 12],
}

pub(crate) const P2_2: [u64; 12] = Fq::modulus_sq_mul(2);
pub(crate) const P2_4: [u64; 12] = Fq::modulus_sq_mul(4);
pub(crate) const P2_5: [u64; 12] = Fq::modulus_sq_mul(5);
pub(crate) const P2_6: [u64; 12] = Fq::modulus_sq_mul(6);
pub(crate) const P2_10: [u64; 12] = Fq::modulus_sq_mul(10);
pub(crate) const P2_12: [u64; 12] = Fq::modulus_sq_mul(12);
pub(crate) const P2_16: [u64; 12] = Fq::modulus_sq_mul(16);
pub(crate) const P2_20: [u64; 12] = Fq::modulus_sq_mul(20);
pub(crate) const P2_30: [u64; 12] = Fq::modulus_sq_mul(30);
pub(crate) const P2_32: [u64; 12] = Fq::modulus_sq_mul(32);
pub(crate) const P2_36: [u64; 12] = Fq::modulus_sq_mul(36);
pub(crate) const P2_40: [u64; 12] = Fq::modulus_sq_mul(40);
pub(crate) const P2_72: [u64; 12] = Fq::modulus_sq_mul(72);
pub(crate) const P2_100: [u64; 12] = Fq::modulus_sq_mul(100);

impl Fq2Unreduced {
    /// Unreduced Karatsuba multiplication (`3` 6x6 products, zero Montgomery reductions).
    /// Output bounds: `c0 < 6 * p^2`, `c1 < 2 * p^2`.
    #[inline(always)]
    pub(crate) fn mul(a: &Fq2, b: &Fq2) -> Self {
        let u0 = Fq::mul_unreduced(&a.c0.0.0, &b.c0.0.0);
        let u1 = Fq::mul_unreduced(&a.c1.0.0, &b.c1.0.0);
        let sa = Fq::add_nocarry_limbs(&a.c0.0.0, &a.c1.0.0);
        let sb = Fq::add_nocarry_limbs(&b.c0.0.0, &b.c1.0.0);
        let u2 = Fq::mul_unreduced(&sa, &sb);

        let u1_5 = Fq::mul5_768(&u1);
        let c0 = Fq::sub_768(&Fq::add_768(&u0, &P2_5), &u1_5);
        let c1 = Fq::sub_768(&Fq::sub_768(&u2, &u0), &u1);
        Self { c0, c1 }
    }

    /// Unreduced symmetric squaring (`3` 6x6 symmetric squarings = `63` `mac`s, zero Montgomery reductions).
    /// Output bounds: `c0 < 6 * p^2`, `c1 < 2 * p^2`.
    #[inline(always)]
    pub(crate) fn square(a: &Fq2) -> Self {
        let s0 = Fq::square_unreduced(&a.c0.0.0);
        let s1 = Fq::square_unreduced(&a.c1.0.0);
        let sa = Fq::add_nocarry_limbs(&a.c0.0.0, &a.c1.0.0);
        let s01 = Fq::square_unreduced(&sa);

        let s1_5 = Fq::mul5_768(&s1);
        let c0 = Fq::sub_768(&Fq::add_768(&s0, &P2_5), &s1_5);
        let c1 = Fq::sub_768(&Fq::sub_768(&s01, &s0), &s1);
        Self { c0, c1 }
    }

    #[inline(always)]
    pub(crate) fn add(&self, other: &Self) -> Self {
        Self { c0: Fq::add_768(&self.c0, &other.c0), c1: Fq::add_768(&self.c1, &other.c1) }
    }

    #[inline(always)]
    pub(crate) fn sub_with_bias(&self, other: &Self, bias_c0: &[u64; 12], bias_c1: &[u64; 12]) -> Self {
        Self {
            c0: Fq::sub_768(&Fq::add_768(&self.c0, bias_c0), &other.c0),
            c1: Fq::sub_768(&Fq::add_768(&self.c1, bias_c1), &other.c1),
        }
    }

    #[inline(always)]
    pub(crate) fn sub2_with_bias(&self, x: &Self, y: &Self, bias_c0: &[u64; 12], bias_c1: &[u64; 12]) -> Self {
        Self {
            c0: Fq::sub_768(&Fq::sub_768(&Fq::add_768(&self.c0, bias_c0), &x.c0), &y.c0),
            c1: Fq::sub_768(&Fq::sub_768(&Fq::add_768(&self.c1, bias_c1), &x.c1), &y.c1),
        }
    }

    /// Multiplies `(c0 + c1 * u)` by `u` (`u^2 = -5`), using `bias_5c1 >= 5 * c1`.
    #[inline(always)]
    pub(crate) fn mul_by_u(&self, bias_5c1: &[u64; 12]) -> Self {
        Self { c0: Fq::sub_768(bias_5c1, &Fq::mul5_768(&self.c1)), c1: self.c0 }
    }

    #[inline(always)]
    pub(crate) fn reduce(self) -> Fq2 {
        Fq2::new(Fq::mont_reduce_limbs(self.c0), Fq::mont_reduce_limbs(self.c1))
    }
}

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

    /// On x86-64 targets with `adx` and `bmi2`, delegates to `Fp2::mul_assign_scalar` so `Fq2`
    /// multiplication uses two-term `Fq::sum_of_products` (`mulx`/`adcx`/`adox` CIOS); on other
    /// targets, uses 768-bit lazy-reduced Karatsuba (`Fq2Unreduced::mul`).
    #[inline]
    fn mul_assign_fp2(a: &mut Fq2, b: &Fq2) {
        #[cfg(all(
            target_arch = "x86_64",
            target_pointer_width = "64",
            target_feature = "adx",
            target_feature = "bmi2"
        ))]
        {
            a.mul_assign_scalar(b);
        }
        #[cfg(not(all(
            target_arch = "x86_64",
            target_pointer_width = "64",
            target_feature = "adx",
            target_feature = "bmi2"
        )))]
        {
            *a = Fq2Unreduced::mul(a, b).reduce();
        }
    }

    /// Complex squaring for `NONRESIDUE = -5`:
    /// `c1 = (2 * c0) * c1`, `c0 = (c0 - c1) * (c0 + 5 * c1) - 2 * c1` (`2` `Fq` muls, zero 768-bit stack spills).
    #[inline]
    fn square_in_place_fp2(a: &mut Fq2) {
        let c0_2 = a.c0.double();
        let c1 = c0_2 * a.c1;
        let c1_2 = a.c1.double();
        let c1_5 = c1_2.double() + a.c1;
        let v0 = (a.c0 - a.c1) * (a.c0 + c1_5);
        let c0 = v0 - c1.double();
        *a = Fq2::new(c0, c1);
    }
}
