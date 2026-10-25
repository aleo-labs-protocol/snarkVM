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
    FftField,
    Field,
    FieldError,
    FieldParameters,
    LegendreSymbol,
    One,
    PoseidonDefaultField,
    PoseidonDefaultParameters,
    PrimeField,
    SquareRootField,
    Zero,
};
use snarkvm_utilities::{
    FromBytes,
    ToBits,
    ToBytes,
    biginteger::{BigInteger as _BigInteger, BigInteger384 as BigInteger, arithmetic as fa},
    serialize::CanonicalDeserialize,
};

use std::{
    cmp::{Ord, Ordering, PartialOrd},
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hint::select_unpredictable,
    io::{Read, Result as IoResult, Write},
    marker::PhantomData,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    str::FromStr,
};
use zeroize::Zeroize;

pub trait Fp384Parameters: FieldParameters<BigInteger = BigInteger> {}

// The CUDA FFI reads this by bytes.
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash, Zeroize)]
#[repr(transparent)]
pub struct Fp384<P: Fp384Parameters>(pub BigInteger, #[doc(hidden)] pub PhantomData<P>);

impl<P: Fp384Parameters> Fp384<P> {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.0 < P::MODULUS
    }

    #[inline]
    fn reduce(&mut self) {
        if !self.is_valid() {
            self.0.sub_noborrow(&P::MODULUS);
        }
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn mont_reduce(
        &mut self,
        r0: u64,
        mut r1: u64,
        mut r2: u64,
        mut r3: u64,
        mut r4: u64,
        mut r5: u64,
        mut r6: u64,
        mut r7: u64,
        mut r8: u64,
        mut r9: u64,
        mut r10: u64,
        mut r11: u64,
    ) {
        // The Montgomery reduction here is based on Algorithm 14.32 in
        // Handbook of Applied Cryptography
        // <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.

        let k = r0.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r0, k, P::MODULUS.0[0], &mut carry);
        r1 = fa::mac_with_carry(r1, k, P::MODULUS.0[1], &mut carry);
        r2 = fa::mac_with_carry(r2, k, P::MODULUS.0[2], &mut carry);
        r3 = fa::mac_with_carry(r3, k, P::MODULUS.0[3], &mut carry);
        r4 = fa::mac_with_carry(r4, k, P::MODULUS.0[4], &mut carry);
        r5 = fa::mac_with_carry(r5, k, P::MODULUS.0[5], &mut carry);
        carry = fa::adc(&mut r6, 0, carry);
        let carry2 = carry;
        let k = r1.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r1, k, P::MODULUS.0[0], &mut carry);
        r2 = fa::mac_with_carry(r2, k, P::MODULUS.0[1], &mut carry);
        r3 = fa::mac_with_carry(r3, k, P::MODULUS.0[2], &mut carry);
        r4 = fa::mac_with_carry(r4, k, P::MODULUS.0[3], &mut carry);
        r5 = fa::mac_with_carry(r5, k, P::MODULUS.0[4], &mut carry);
        r6 = fa::mac_with_carry(r6, k, P::MODULUS.0[5], &mut carry);
        carry = fa::adc(&mut r7, carry2, carry);
        let carry2 = carry;
        let k = r2.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r2, k, P::MODULUS.0[0], &mut carry);
        r3 = fa::mac_with_carry(r3, k, P::MODULUS.0[1], &mut carry);
        r4 = fa::mac_with_carry(r4, k, P::MODULUS.0[2], &mut carry);
        r5 = fa::mac_with_carry(r5, k, P::MODULUS.0[3], &mut carry);
        r6 = fa::mac_with_carry(r6, k, P::MODULUS.0[4], &mut carry);
        r7 = fa::mac_with_carry(r7, k, P::MODULUS.0[5], &mut carry);
        carry = fa::adc(&mut r8, carry2, carry);
        let carry2 = carry;
        let k = r3.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r3, k, P::MODULUS.0[0], &mut carry);
        r4 = fa::mac_with_carry(r4, k, P::MODULUS.0[1], &mut carry);
        r5 = fa::mac_with_carry(r5, k, P::MODULUS.0[2], &mut carry);
        r6 = fa::mac_with_carry(r6, k, P::MODULUS.0[3], &mut carry);
        r7 = fa::mac_with_carry(r7, k, P::MODULUS.0[4], &mut carry);
        r8 = fa::mac_with_carry(r8, k, P::MODULUS.0[5], &mut carry);
        carry = fa::adc(&mut r9, carry2, carry);
        let carry2 = carry;
        let k = r4.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r4, k, P::MODULUS.0[0], &mut carry);
        r5 = fa::mac_with_carry(r5, k, P::MODULUS.0[1], &mut carry);
        r6 = fa::mac_with_carry(r6, k, P::MODULUS.0[2], &mut carry);
        r7 = fa::mac_with_carry(r7, k, P::MODULUS.0[3], &mut carry);
        r8 = fa::mac_with_carry(r8, k, P::MODULUS.0[4], &mut carry);
        r9 = fa::mac_with_carry(r9, k, P::MODULUS.0[5], &mut carry);
        carry = fa::adc(&mut r10, carry2, carry);
        let carry2 = carry;
        let k = r5.wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r5, k, P::MODULUS.0[0], &mut carry);
        r6 = fa::mac_with_carry(r6, k, P::MODULUS.0[1], &mut carry);
        r7 = fa::mac_with_carry(r7, k, P::MODULUS.0[2], &mut carry);
        r8 = fa::mac_with_carry(r8, k, P::MODULUS.0[3], &mut carry);
        r9 = fa::mac_with_carry(r9, k, P::MODULUS.0[4], &mut carry);
        r10 = fa::mac_with_carry(r10, k, P::MODULUS.0[5], &mut carry);
        fa::adc(&mut r11, carry2, carry);
        (self.0).0[0] = r6;
        (self.0).0[1] = r7;
        (self.0).0[2] = r8;
        (self.0).0[3] = r9;
        (self.0).0[4] = r10;
        (self.0).0[5] = r11;
        self.reduce();
    }
}

impl<P: Fp384Parameters> Zero for Fp384<P> {
    #[inline]
    fn zero() -> Self {
        Self(BigInteger::from(0), PhantomData)
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<P: Fp384Parameters> One for Fp384<P> {
    #[inline]
    fn one() -> Self {
        Self(P::R, PhantomData)
    }

    #[inline]
    fn is_one(&self) -> bool {
        self.0 == P::R
    }
}

impl<P: Fp384Parameters> Field for Fp384<P> {
    type BasePrimeField = Self;

    // 384/64 = 6 limbs.
    impl_field_from_random_bytes_with_flags!(6);

    fn from_base_prime_field(other: Self::BasePrimeField) -> Self {
        other
    }

    fn half() -> Self {
        // Compute 1/2 `(p+1)/2` as `1/2`.
        // This is cheaper than `Self::one().double().inverse()`
        let mut two_inv = P::MODULUS;
        two_inv.add_nocarry(&1u64.into());
        two_inv.div2();
        Self::from_bigint(two_inv).unwrap() // Guaranteed to be valid.
    }

    fn sum_of_products<'a>(a: &'a [Self], b: &'a [Self]) -> Self {
        // For a single `a x b` multiplication, operand scanning (schoolbook) takes each
        // limb of `a` in turn, and multiplies it by all of the limbs of `b` to compute
        // the result as a double-width intermediate representation, which is then fully
        // reduced at the end. Here however we have pairs of multiplications (a_i, b_i),
        // the results of which are summed.
        //
        // The intuition for this algorithm is two-fold:
        // - We can interleave the operand scanning for each pair, by processing the jth
        //   limb of each `a_i` together. As these have the same offset within the overall
        //   operand scanning flow, their results can be summed directly.
        // - We can interleave the multiplication and reduction steps, resulting in a
        //   single bitshift by the limb size after each iteration. This means we only
        //   need to store a single extra limb overall, instead of keeping around all the
        //   intermediate results and eventually having twice as many limbs.

        // Algorithm 2, line 2
        let (u0, u1, u2, u3, u4, u5) = (0..6).fold((0, 0, 0, 0, 0, 0), |(u0, u1, u2, u3, u4, u5), j| {
            // Algorithm 2, line 3
            // For each pair in the overall sum of products:
            let (t0, t1, t2, t3, t4, t5, mut t6) =
                a.iter().zip(b).fold((u0, u1, u2, u3, u4, u5, 0), |(t0, t1, t2, t3, t4, t5, mut t6), (a, b)| {
                    // Compute digit_j x row and accumulate into `u`.
                    let mut carry = 0;
                    let t0 = fa::mac_with_carry(t0, a.0.0[j], b.0.0[0], &mut carry);
                    let t1 = fa::mac_with_carry(t1, a.0.0[j], b.0.0[1], &mut carry);
                    let t2 = fa::mac_with_carry(t2, a.0.0[j], b.0.0[2], &mut carry);
                    let t3 = fa::mac_with_carry(t3, a.0.0[j], b.0.0[3], &mut carry);
                    let t4 = fa::mac_with_carry(t4, a.0.0[j], b.0.0[4], &mut carry);
                    let t5 = fa::mac_with_carry(t5, a.0.0[j], b.0.0[5], &mut carry);
                    let _ = fa::adc(&mut t6, 0, carry);

                    (t0, t1, t2, t3, t4, t5, t6)
                });

            // Algorithm 2, lines 4-5
            // This is a single step of the usual Montgomery reduction process.
            let k = t0.wrapping_mul(P::INV);
            let mut carry = 0;
            let _ = fa::mac_with_carry(t0, k, P::MODULUS.0[0], &mut carry);
            let r1 = fa::mac_with_carry(t1, k, P::MODULUS.0[1], &mut carry);
            let r2 = fa::mac_with_carry(t2, k, P::MODULUS.0[2], &mut carry);
            let r3 = fa::mac_with_carry(t3, k, P::MODULUS.0[3], &mut carry);
            let r4 = fa::mac_with_carry(t4, k, P::MODULUS.0[4], &mut carry);
            let r5 = fa::mac_with_carry(t5, k, P::MODULUS.0[5], &mut carry);
            let _ = fa::adc(&mut t6, 0, carry);
            let r6 = t6;

            (r1, r2, r3, r4, r5, r6)
        });

        // Because we represent F_p elements in non-redundant form, we need a final
        // conditional subtraction to ensure the output is in range.
        let mut result = Self(BigInteger([u0, u1, u2, u3, u4, u5]), PhantomData);
        result.reduce();
        result
    }

    #[inline]
    fn double(&self) -> Self {
        let mut temp = *self;
        temp.double_in_place();
        temp
    }

    #[inline]
    fn double_in_place(&mut self) {
        // This cannot exceed the backing capacity.
        self.0.mul2();
        // However, it may need to be reduced. If subtracting the modulus borrows, the double is already reduced.
        // About half of all doubles need the reduction, so this selects without a branch, unlike `reduce`.
        let mut reduced = self.0;
        let borrow = reduced.sub_noborrow(&P::MODULUS);
        let limbs = &mut (self.0).0;
        limbs[0] = select_unpredictable(borrow, limbs[0], reduced.0[0]);
        limbs[1] = select_unpredictable(borrow, limbs[1], reduced.0[1]);
        limbs[2] = select_unpredictable(borrow, limbs[2], reduced.0[2]);
        limbs[3] = select_unpredictable(borrow, limbs[3], reduced.0[3]);
        limbs[4] = select_unpredictable(borrow, limbs[4], reduced.0[4]);
        limbs[5] = select_unpredictable(borrow, limbs[5], reduced.0[5]);
    }

    #[inline]
    fn characteristic<'a>() -> &'a [u64] {
        P::MODULUS.as_ref()
    }

    #[inline]
    fn square(&self) -> Self {
        let mut temp = *self;
        temp.square_in_place();
        temp
    }

    #[inline]
    fn square_in_place(&mut self) -> &mut Self {
        let mut carry = 0;
        let r1 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[1], &mut carry);
        let r2 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[2], &mut carry);
        let r3 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[3], &mut carry);
        let r4 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[4], &mut carry);
        let r5 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[5], &mut carry);
        let r6 = carry;
        let mut carry = 0;
        let r3 = fa::mac_with_carry(r3, (self.0).0[1], (self.0).0[2], &mut carry);
        let r4 = fa::mac_with_carry(r4, (self.0).0[1], (self.0).0[3], &mut carry);
        let r5 = fa::mac_with_carry(r5, (self.0).0[1], (self.0).0[4], &mut carry);
        let r6 = fa::mac_with_carry(r6, (self.0).0[1], (self.0).0[5], &mut carry);
        let r7 = carry;
        let mut carry = 0;
        let r5 = fa::mac_with_carry(r5, (self.0).0[2], (self.0).0[3], &mut carry);
        let r6 = fa::mac_with_carry(r6, (self.0).0[2], (self.0).0[4], &mut carry);
        let r7 = fa::mac_with_carry(r7, (self.0).0[2], (self.0).0[5], &mut carry);
        let r8 = carry;
        let mut carry = 0;
        let r7 = fa::mac_with_carry(r7, (self.0).0[3], (self.0).0[4], &mut carry);
        let r8 = fa::mac_with_carry(r8, (self.0).0[3], (self.0).0[5], &mut carry);
        let r9 = carry;
        let mut carry = 0;
        let r9 = fa::mac_with_carry(r9, (self.0).0[4], (self.0).0[5], &mut carry);
        let r10 = carry;

        let mut r11 = r10 >> 63;
        let r10 = (r10 << 1) | (r9 >> 63);
        let mut r9 = (r9 << 1) | (r8 >> 63);
        let r8 = (r8 << 1) | (r7 >> 63);
        let mut r7 = (r7 << 1) | (r6 >> 63);
        let r6 = (r6 << 1) | (r5 >> 63);
        let mut r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let mut r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let mut r1 = r1 << 1;

        let mut carry = 0;
        let r0 = fa::mac_with_carry(0, (self.0).0[0], (self.0).0[0], &mut carry);
        carry = fa::adc(&mut r1, 0, carry);
        let r2 = fa::mac_with_carry(r2, (self.0).0[1], (self.0).0[1], &mut carry);
        carry = fa::adc(&mut r3, 0, carry);
        let r4 = fa::mac_with_carry(r4, (self.0).0[2], (self.0).0[2], &mut carry);
        carry = fa::adc(&mut r5, 0, carry);
        let r6 = fa::mac_with_carry(r6, (self.0).0[3], (self.0).0[3], &mut carry);
        carry = fa::adc(&mut r7, 0, carry);
        let r8 = fa::mac_with_carry(r8, (self.0).0[4], (self.0).0[4], &mut carry);
        carry = fa::adc(&mut r9, 0, carry);
        let r10 = fa::mac_with_carry(r10, (self.0).0[5], (self.0).0[5], &mut carry);
        fa::adc(&mut r11, 0, carry);
        self.mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11);
        self
    }

    #[inline]
    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            // Guajardo Kumar Paar Pelzl
            // Efficient Software-Implementation of Finite Fields with Applications to
            // Cryptography
            // Algorithm 16 (BEA for Inversion in Fp)

            let one = BigInteger::from(1);

            let mut u = self.0;
            let mut v = P::MODULUS;
            let mut b = Self(P::R2, PhantomData); // Avoids unnecessary reduction step.
            let mut c = Self::zero();

            while u != one && v != one {
                while u.is_even() {
                    u.div2();

                    if b.0.is_even() {
                        b.0.div2();
                    } else {
                        b.0.add_nocarry(&P::MODULUS);
                        b.0.div2();
                    }
                }

                while v.is_even() {
                    v.div2();

                    if c.0.is_even() {
                        c.0.div2();
                    } else {
                        c.0.add_nocarry(&P::MODULUS);
                        c.0.div2();
                    }
                }

                if v < u {
                    u.sub_noborrow(&v);
                    b.sub_assign(&c);
                } else {
                    v.sub_noborrow(&u);
                    c.sub_assign(&b);
                }
            }

            if u == one { Some(b) } else { Some(c) }
        }
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        if let Some(inverse) = self.inverse() {
            *self = inverse;
            Some(self)
        } else {
            None
        }
    }

    #[inline]
    fn frobenius_map(&mut self, _: usize) {
        // No-op: No effect in a prime field.
    }
}

impl<P: Fp384Parameters> PrimeField for Fp384<P> {
    type BigInteger = BigInteger;
    type Parameters = P;

    #[inline]
    fn from_bigint(r: BigInteger) -> Option<Self> {
        let mut r = Fp384(r, PhantomData);
        if r.is_zero() {
            Some(r)
        } else if r.is_valid() {
            r *= &Fp384(P::R2, PhantomData);
            Some(r)
        } else {
            None
        }
    }

    #[inline]
    fn to_bigint(&self) -> BigInteger {
        let mut tmp = self.0;
        let mut r = tmp.0;
        // Montgomery Reduction
        let k = r[0].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[0], k, P::MODULUS.0[0], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry);
        r[4] = fa::mac_with_carry(r[4], k, P::MODULUS.0[4], &mut carry);
        r[5] = fa::mac_with_carry(r[5], k, P::MODULUS.0[5], &mut carry);
        r[0] = carry;

        let k = r[1].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[1], k, P::MODULUS.0[0], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[1], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[2], &mut carry);
        r[4] = fa::mac_with_carry(r[4], k, P::MODULUS.0[3], &mut carry);
        r[5] = fa::mac_with_carry(r[5], k, P::MODULUS.0[4], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[5], &mut carry);
        r[1] = carry;

        let k = r[2].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[2], k, P::MODULUS.0[0], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[1], &mut carry);
        r[4] = fa::mac_with_carry(r[4], k, P::MODULUS.0[2], &mut carry);
        r[5] = fa::mac_with_carry(r[5], k, P::MODULUS.0[3], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[4], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[5], &mut carry);
        r[2] = carry;

        let k = r[3].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[3], k, P::MODULUS.0[0], &mut carry);
        r[4] = fa::mac_with_carry(r[4], k, P::MODULUS.0[1], &mut carry);
        r[5] = fa::mac_with_carry(r[5], k, P::MODULUS.0[2], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[3], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[4], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[5], &mut carry);
        r[3] = carry;

        let k = r[4].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[4], k, P::MODULUS.0[0], &mut carry);
        r[5] = fa::mac_with_carry(r[5], k, P::MODULUS.0[1], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[2], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[3], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[4], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[5], &mut carry);
        r[4] = carry;

        let k = r[5].wrapping_mul(P::INV);
        let mut carry = 0;
        fa::mac_with_carry(r[5], k, P::MODULUS.0[0], &mut carry);
        r[0] = fa::mac_with_carry(r[0], k, P::MODULUS.0[1], &mut carry);
        r[1] = fa::mac_with_carry(r[1], k, P::MODULUS.0[2], &mut carry);
        r[2] = fa::mac_with_carry(r[2], k, P::MODULUS.0[3], &mut carry);
        r[3] = fa::mac_with_carry(r[3], k, P::MODULUS.0[4], &mut carry);
        r[4] = fa::mac_with_carry(r[4], k, P::MODULUS.0[5], &mut carry);
        r[5] = carry;

        tmp.0 = r;
        tmp
    }

    #[inline]
    fn decompose(
        &self,
        _q1: &[u64; 4],
        _q2: &[u64; 4],
        _b1: Self,
        _b2: Self,
        _r128: Self,
        _half_r: &[u64; 8],
    ) -> (Self, Self, bool, bool) {
        unimplemented!()
    }
}

impl<P: Fp384Parameters> FftField for Fp384<P> {
    type FftParameters = P;

    #[inline]
    fn two_adic_root_of_unity() -> Self {
        Self(P::TWO_ADIC_ROOT_OF_UNITY, PhantomData)
    }

    #[inline]
    fn large_subgroup_root_of_unity() -> Option<Self> {
        Some(Self(P::LARGE_SUBGROUP_ROOT_OF_UNITY?, PhantomData))
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        Self(P::GENERATOR, PhantomData)
    }
}

impl<P: Fp384Parameters> SquareRootField for Fp384<P> {
    #[inline]
    fn legendre(&self) -> LegendreSymbol {
        use crate::LegendreSymbol::*;

        // s = self^((MODULUS - 1) // 2)
        let s = self.pow(P::MODULUS_MINUS_ONE_DIV_TWO);

        if s.is_zero() {
            Zero
        } else if s.is_one() {
            QuadraticResidue
        } else {
            QuadraticNonResidue
        }
    }

    #[inline]
    fn sqrt(&self) -> Option<Self> {
        sqrt_impl!(Self, P, self)
    }

    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        (*self).sqrt().map(|sqrt| {
            *self = sqrt;
            self
        })
    }
}

/// `Fp` elements are ordered lexicographically.
impl<P: Fp384Parameters> Ord for Fp384<P> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bigint().cmp(&other.to_bigint())
    }
}

impl<P: Fp384Parameters> PartialOrd for Fp384<P> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: Fp384Parameters + PoseidonDefaultParameters> PoseidonDefaultField for Fp384<P> {}

impl_primefield_from_int!(Fp384, u128, Fp384Parameters);
impl_primefield_from_int!(Fp384, u64, Fp384Parameters);
impl_primefield_from_int!(Fp384, u32, Fp384Parameters);
impl_primefield_from_int!(Fp384, u16, Fp384Parameters);
impl_primefield_from_int!(Fp384, u8, Fp384Parameters);

impl_primefield_standard_sample!(Fp384, Fp384Parameters);

impl_add_sub_from_field_ref!(Fp384, Fp384Parameters);
impl_mul_div_from_field_ref!(Fp384, Fp384Parameters);

impl<P: Fp384Parameters> ToBits for Fp384<P> {
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        let initial_len = vec.len();
        self.to_bigint().write_bits_le(vec);
        vec.truncate(initial_len + P::MODULUS_BITS as usize);
    }

    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        let initial_len = vec.len();
        self.write_bits_le(vec);
        vec[initial_len..].reverse();
    }

    fn num_bits() -> Option<usize> {
        Some(384)
    }
}

impl<P: Fp384Parameters> ToBytes for Fp384<P> {
    #[inline]
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        self.to_bigint().write_le(writer)
    }
}

impl<P: Fp384Parameters> FromBytes for Fp384<P> {
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        BigInteger::read_le(reader).and_then(|b| match Self::from_bigint(b) {
            Some(f) => Ok(f),
            None => Err(FieldError::InvalidFieldElement.into()),
        })
    }
}

impl<P: Fp384Parameters> FromStr for Fp384<P> {
    type Err = FieldError;

    /// Interpret a string of numbers as a (congruent) prime field element.
    /// Does not accept unnecessary leading zeroes or a blank string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(FieldError::ParsingEmptyString);
        }

        if s == "0" {
            return Ok(Self::zero());
        }

        let mut res = Self::zero();

        let ten =
            Self::from_bigint(<Self as PrimeField>::BigInteger::from(10)).ok_or(FieldError::InvalidFieldElement)?;

        let mut first_digit = true;

        for c in s.chars() {
            match c.to_digit(10) {
                Some(c) => {
                    if first_digit {
                        if c == 0 {
                            return Err(FieldError::InvalidString);
                        }

                        first_digit = false;
                    }

                    res.mul_assign(&ten);
                    res.add_assign(
                        &Self::from_bigint(<Self as PrimeField>::BigInteger::from(u64::from(c)))
                            .ok_or(FieldError::InvalidFieldElement)?,
                    );
                }
                None => return Err(FieldError::ParsingNonDigitCharacter),
            }
        }

        if !res.is_valid() { Err(FieldError::InvalidFieldElement) } else { Ok(res) }
    }
}

impl<P: Fp384Parameters> Debug for Fp384<P> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.to_bigint())
    }
}

impl<P: Fp384Parameters> Display for Fp384<P> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.to_bigint())
    }
}

impl<P: Fp384Parameters> Neg for Fp384<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        if !self.is_zero() {
            let mut tmp = P::MODULUS;
            tmp.sub_noborrow(&self.0);
            Self(tmp, PhantomData)
        } else {
            self
        }
    }
}

impl<P: Fp384Parameters> Add<&'_ Fp384<P>> for Fp384<P> {
    type Output = Self;

    #[inline]
    fn add(self, other: &Self) -> Self {
        let mut result = self;
        result.add_assign(other);
        result
    }
}

impl<P: Fp384Parameters> Sub<&'_ Fp384<P>> for Fp384<P> {
    type Output = Self;

    #[inline]
    fn sub(self, other: &Self) -> Self {
        let mut result = self;
        result.sub_assign(other);
        result
    }
}

impl<P: Fp384Parameters> Mul<&'_ Fp384<P>> for Fp384<P> {
    type Output = Self;

    #[inline]
    fn mul(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(other);
        result
    }
}

impl<P: Fp384Parameters> Div<&'_ Fp384<P>> for Fp384<P> {
    type Output = Self;

    #[inline]
    fn div(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(&other.inverse().unwrap());
        result
    }
}

impl<P: Fp384Parameters> AddAssign<&'_ Self> for Fp384<P> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        // This cannot exceed the backing capacity.
        self.0.add_nocarry(&other.0);
        // However, it may need to be reduced. If subtracting the modulus borrows, the sum is already reduced.
        // About half of all sums need the reduction, so this selects without a branch, unlike `reduce`.
        // LLVM compiles a loop over the limbs, or a select through an and/or mask, to a branch here.
        let mut reduced = self.0;
        let borrow = reduced.sub_noborrow(&P::MODULUS);
        let limbs = &mut (self.0).0;
        limbs[0] = select_unpredictable(borrow, limbs[0], reduced.0[0]);
        limbs[1] = select_unpredictable(borrow, limbs[1], reduced.0[1]);
        limbs[2] = select_unpredictable(borrow, limbs[2], reduced.0[2]);
        limbs[3] = select_unpredictable(borrow, limbs[3], reduced.0[3]);
        limbs[4] = select_unpredictable(borrow, limbs[4], reduced.0[4]);
        limbs[5] = select_unpredictable(borrow, limbs[5], reduced.0[5]);
    }
}

impl<P: Fp384Parameters> SubAssign<&'_ Self> for Fp384<P> {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        // If `other` is larger than `self`, the subtraction borrows, and the result is the difference plus the modulus.
        // About half of all inputs borrow, so this selects without a branch.
        // LLVM compiles a loop over the limbs, or a select between the modulus and zero, to a branch here.
        let borrow = self.0.sub_noborrow(&other.0);
        let mut wrapped = self.0;
        wrapped.add_nocarry(&P::MODULUS);
        let limbs = &mut (self.0).0;
        limbs[0] = select_unpredictable(borrow, wrapped.0[0], limbs[0]);
        limbs[1] = select_unpredictable(borrow, wrapped.0[1], limbs[1]);
        limbs[2] = select_unpredictable(borrow, wrapped.0[2], limbs[2]);
        limbs[3] = select_unpredictable(borrow, wrapped.0[3], limbs[3]);
        limbs[4] = select_unpredictable(borrow, wrapped.0[4], limbs[4]);
        limbs[5] = select_unpredictable(borrow, wrapped.0[5], limbs[5]);
    }
}

impl<P: Fp384Parameters> MulAssign<&'_ Self> for Fp384<P> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        let mut r = [0u64; 6];
        let mut carry1 = 0u64;
        let mut carry2 = 0u64;

        // Iteration 0.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[0], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[0], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[0], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[0], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);

        r[4] = fa::mac_with_carry(r[4], (self.0).0[4], (other.0).0[0], &mut carry1);
        r[3] = fa::mac_with_carry(r[4], k, P::MODULUS.0[4], &mut carry2);

        r[5] = fa::mac_with_carry(r[5], (self.0).0[5], (other.0).0[0], &mut carry1);
        r[4] = fa::mac_with_carry(r[5], k, P::MODULUS.0[5], &mut carry2);
        r[5] = carry1 + carry2;

        // Iteration 1.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[1], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[1], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[1], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[1], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);

        r[4] = fa::mac_with_carry(r[4], (self.0).0[4], (other.0).0[1], &mut carry1);
        r[3] = fa::mac_with_carry(r[4], k, P::MODULUS.0[4], &mut carry2);

        r[5] = fa::mac_with_carry(r[5], (self.0).0[5], (other.0).0[1], &mut carry1);
        r[4] = fa::mac_with_carry(r[5], k, P::MODULUS.0[5], &mut carry2);
        r[5] = carry1 + carry2;

        // Iteration 2.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[2], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[2], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[2], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[2], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);

        r[4] = fa::mac_with_carry(r[4], (self.0).0[4], (other.0).0[2], &mut carry1);
        r[3] = fa::mac_with_carry(r[4], k, P::MODULUS.0[4], &mut carry2);

        r[5] = fa::mac_with_carry(r[5], (self.0).0[5], (other.0).0[2], &mut carry1);
        r[4] = fa::mac_with_carry(r[5], k, P::MODULUS.0[5], &mut carry2);
        r[5] = carry1 + carry2;

        // Iteration 3.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[3], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[3], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[3], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[3], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);

        r[4] = fa::mac_with_carry(r[4], (self.0).0[4], (other.0).0[3], &mut carry1);
        r[3] = fa::mac_with_carry(r[4], k, P::MODULUS.0[4], &mut carry2);

        r[5] = fa::mac_with_carry(r[5], (self.0).0[5], (other.0).0[3], &mut carry1);
        r[4] = fa::mac_with_carry(r[5], k, P::MODULUS.0[5], &mut carry2);
        r[5] = carry1 + carry2;

        // Iteration 4.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[4], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[4], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[4], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[4], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);

        r[4] = fa::mac_with_carry(r[4], (self.0).0[4], (other.0).0[4], &mut carry1);
        r[3] = fa::mac_with_carry(r[4], k, P::MODULUS.0[4], &mut carry2);

        r[5] = fa::mac_with_carry(r[5], (self.0).0[5], (other.0).0[4], &mut carry1);
        r[4] = fa::mac_with_carry(r[5], k, P::MODULUS.0[5], &mut carry2);
        r[5] = carry1 + carry2;

        // Iteration 5.
        r[0] = fa::mac(r[0], (self.0).0[0], (other.0).0[5], &mut carry1);
        let k = r[0].wrapping_mul(P::INV);
        fa::mac_discard(r[0], k, P::MODULUS.0[0], &mut carry2);
        r[1] = fa::mac_with_carry(r[1], (self.0).0[1], (other.0).0[5], &mut carry1);
        r[0] = fa::mac_with_carry(r[1], k, P::MODULUS.0[1], &mut carry2);

        r[2] = fa::mac_with_carry(r[2], (self.0).0[2], (other.0).0[5], &mut carry1);
        r[1] = fa::mac_with_carry(r[2], k, P::MODULUS.0[2], &mut carry2);

        r[3] = fa::mac_with_carry(r[3], (self.0).0[3], (other.0).0[5], &mut carry1);
        r[2] = fa::mac_with_carry(r[3], k, P::MODULUS.0[3], &mut carry2);

        r[4] = fa::mac_with_carry(r[4], (self.0).0[4], (other.0).0[5], &mut carry1);
        r[3] = fa::mac_with_carry(r[4], k, P::MODULUS.0[4], &mut carry2);

        r[5] = fa::mac_with_carry(r[5], (self.0).0[5], (other.0).0[5], &mut carry1);
        r[4] = fa::mac_with_carry(r[5], k, P::MODULUS.0[5], &mut carry2);
        r[5] = carry1 + carry2;

        (self.0).0 = r;
        self.reduce();
    }
}

impl<P: Fp384Parameters> DivAssign<&'_ Self> for Fp384<P> {
    #[inline]
    fn div_assign(&mut self, other: &Self) {
        self.mul_assign(&other.inverse().unwrap());
    }
}
