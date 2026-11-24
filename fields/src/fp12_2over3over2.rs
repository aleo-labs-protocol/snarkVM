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

use crate::{Field, Fp2, Fp2Parameters, One, Zero, fp6_3over2::*};
use snarkvm_utilities::{FromBytes, ToBits, ToBytes, bititerator::BitIteratorBE, rand::Uniform, serialize::*};

use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::Debug,
    hash::Hash,
    io::{Read, Result as IoResult, Write},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// This trait is sealed. Only snarkVM implements it.
pub trait Fp12Parameters:
    crate::sealed_parameters::Sealed + 'static + Copy + Clone + Debug + Default + PartialEq + Eq + Hash + Send + Sync
{
    type Fp6Params: Fp6Parameters;

    /// Coefficients for the Frobenius automorphism.
    const FROBENIUS_COEFF_FP12_C1: [Fp2<Fp2Params<Self>>; 12];

    /// Sets `a` to `a * b`. An override must not fall back to `Fp12::mul_assign`, which calls this
    /// hook; `Fp12::mul_assign_scalar` does not.
    #[doc(hidden)]
    #[inline]
    fn mul_assign_fp12(a: &mut Fp12<Self>, b: &Fp12<Self>) {
        a.mul_assign_scalar(b)
    }

    /// Returns `a^exp` by the chain of `Fp12::cyclotomic_exp`. `exp` lists the words of the exponent,
    /// the least significant first. An override must not fall back to `Fp12::cyclotomic_exp`, which
    /// calls this hook; `Fp12::cyclotomic_exp_scalar` does not.
    #[doc(hidden)]
    #[inline]
    fn cyclotomic_exp_fp12(a: &Fp12<Self>, exp: &[u64]) -> Fp12<Self> {
        a.cyclotomic_exp_scalar(exp)
    }
}

pub(crate) type Fp2Params<P> = <<P as Fp12Parameters>::Fp6Params as Fp6Parameters>::Fp2Params;

/// An element of Fp12, represented by c0 + c1 * v
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fp12<P: Fp12Parameters> {
    pub c0: Fp6<P::Fp6Params>,
    pub c1: Fp6<P::Fp6Params>,
}

impl<P: Fp12Parameters> Fp12<P> {
    /// Initializes an element of `Fp12` from two `Fp6` elements.
    pub const fn new(c0: Fp6<P::Fp6Params>, c1: Fp6<P::Fp6Params>) -> Self {
        Self { c0, c1 }
    }
}

impl<P: Fp12Parameters> Fp12<P> {
    pub fn conjugate(&mut self) {
        self.c1 = self.c1.neg();
    }

    pub fn mul_by_fp(&mut self, element: &<<P::Fp6Params as Fp6Parameters>::Fp2Params as Fp2Parameters>::Fp) {
        self.c0.mul_by_fp(element);
        self.c1.mul_by_fp(element);
    }

    /// Multiply by quadratic nonresidue v.
    #[inline(always)]
    pub(crate) fn mul_fp6_by_nonresidue(fe: &Fp6<P::Fp6Params>) -> Fp6<P::Fp6Params> {
        let new_c0 = P::Fp6Params::mul_fp2_by_nonresidue(&fe.c2);
        let new_c1 = fe.c0;
        let new_c2 = fe.c1;
        Fp6::new(new_c0, new_c1, new_c2)
    }

    /// Multiplies `self` by `1 + (c3 + c4 * v) * w`.
    #[inline]
    pub fn mul_by_34(&mut self, c3: &Fp2<Fp2Params<P>>, c4: &Fp2<Fp2Params<P>>) {
        let a = self.c0;
        let b = self.c1;
        let c34 = *c3 + c4;

        let b0 = b.c0 * c3;
        let b1 = b.c1 * c4;
        let d0 = P::Fp6Params::mul_fp2_by_nonresidue(&(b.c2 * c4)) + b0;
        let d1 = (b.c0 + b.c1) * c34 - b0 - b1;
        let d2 = b.c2 * c3 + b1;

        let a0 = a.c0 * c3;
        let a1 = a.c1 * c4;
        let e0 = P::Fp6Params::mul_fp2_by_nonresidue(&(a.c2 * c4)) + a0;
        let e1 = (a.c0 + a.c1) * c34 - a0 - a1;
        let e2 = a.c2 * c3 + a1;

        self.c0 = Fp6::new(a.c0 + P::Fp6Params::mul_fp2_by_nonresidue(&d2), a.c1 + d0, a.c2 + d1);
        self.c1 = Fp6::new(b.c0 + e0, b.c1 + e1, b.c2 + e2);
    }

    /// Multiplies `self` by `(1 + c1 * v) + (c4 * v) * w`.
    #[inline]
    pub fn mul_by_14(&mut self, c1: &Fp2<Fp2Params<P>>, c4: &Fp2<Fp2Params<P>>) {
        let mut a_v1 = self.c0;
        a_v1.mul_by_1(c1);

        let mut b_v4 = self.c1;
        b_v4.mul_by_1(c4);

        let c14 = *c1 + c4;
        let mut ab = self.c0 + self.c1;
        ab.mul_by_1(&c14);

        self.c1 += ab - a_v1 - b_v4;
        self.c0 += a_v1 + Self::mul_fp6_by_nonresidue(&b_v4);
    }

    pub fn mul_by_034(&mut self, c0: &Fp2<Fp2Params<P>>, c3: &Fp2<Fp2Params<P>>, c4: &Fp2<Fp2Params<P>>) {
        let a0 = self.c0.c0 * c0;
        let a1 = self.c0.c1 * c0;
        let a2 = self.c0.c2 * c0;
        let a = Fp6::new(a0, a1, a2);
        let mut b = self.c1;
        b.mul_by_01(c3, c4);

        let c0 = *c0 + c3;
        let c1 = c4;
        let mut e = self.c0 + self.c1;
        e.mul_by_01(&c0, c1);
        self.c1 = e - (a + b);
        self.c0 = a + Self::mul_fp6_by_nonresidue(&b);
    }

    pub fn mul_by_014(&mut self, c0: &Fp2<Fp2Params<P>>, c1: &Fp2<Fp2Params<P>>, c4: &Fp2<Fp2Params<P>>) {
        let mut aa = self.c0;
        aa.mul_by_01(c0, c1);
        let mut bb = self.c1;
        bb.mul_by_1(c4);
        let mut o = *c1;
        o.add_assign(c4);
        self.c1.add_assign(self.c0);
        self.c1.mul_by_01(c0, &o);
        self.c1.sub_assign(&aa);
        self.c1.sub_assign(&bb);
        self.c0 = bb;
        self.c0 = Self::mul_fp6_by_nonresidue(&self.c0);
        self.c0.add_assign(aa);
    }

    /// Sets `self` to `self * other` by the scalar path, without `Fp12Parameters::mul_assign_fp12`.
    #[doc(hidden)]
    #[inline]
    pub fn mul_assign_scalar(&mut self, other: &Self) {
        let v0 = self.c0 * other.c0;
        let v1 = self.c1 * other.c1;
        self.c1 = (self.c0 + self.c1) * (other.c0 + other.c1) - v0 - v1;
        self.c0 = v0 + Self::mul_fp6_by_nonresidue(&v1);
    }

    pub fn cyclotomic_square(&self) -> Self {
        let mut result = Self::zero();
        let fp2_nr = <P::Fp6Params as Fp6Parameters>::mul_fp2_by_nonresidue;

        let mut z0 = self.c0.c0;
        let mut z4 = self.c0.c1;
        let mut z3 = self.c0.c2;
        let mut z2 = self.c1.c0;
        let mut z1 = self.c1.c1;
        let mut z5 = self.c1.c2;

        // t0 + t1*y = (z0 + z1*y)^2 = a^2
        let mut tmp = z0 * z1;
        let t0 = (z0 + z1) * (z0 + fp2_nr(&z1)) - tmp - fp2_nr(&tmp);
        let t1 = tmp.double();

        // t2 + t3*y = (z2 + z3*y)^2 = b^2
        tmp = z2 * z3;
        let t2 = (z2 + z3) * (z2 + fp2_nr(&z3)) - tmp - fp2_nr(&tmp);
        let t3 = tmp.double();

        // t4 + t5*y = (z4 + z5*y)^2 = c^2
        tmp = z4 * z5;
        let t4 = (z4 + z5) * (z4 + fp2_nr(&z5)) - tmp - fp2_nr(&tmp);
        let t5 = tmp.double();

        // for A

        // z0 = 3 * t0 - 2 * z0
        z0 = t0 - z0;
        z0 = z0 + z0;
        result.c0.c0 = z0 + t0;

        // z1 = 3 * t1 + 2 * z1
        z1 = t1 + z1;
        z1 = z1 + z1;
        result.c1.c1 = z1 + t1;

        // for B

        // z2 = 3 * (xi * t5) + 2 * z2
        tmp = fp2_nr(&t5);
        z2 = tmp + z2;
        z2 = z2 + z2;
        result.c1.c0 = z2 + tmp;

        // z3 = 3 * t4 - 2 * z3
        z3 = t4 - z3;
        z3 = z3 + z3;
        result.c0.c2 = z3 + t4;

        // for C

        // z4 = 3 * t2 - 2 * z4
        z4 = t2 - z4;
        z4 = z4 + z4;
        result.c0.c1 = z4 + t2;

        // z5 = 3 * t3 + 2 * z5
        z5 = t3 + z5;
        z5 = z5 + z5;
        result.c1.c2 = z5 + t3;

        result
    }

    /// Exponentiates `self` by `exp` (least-significant word first), assuming `self` lies in the
    /// cyclotomic subgroup `G_{Phi_6(p^2)}` (or is zero).
    pub fn cyclotomic_exp<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        P::cyclotomic_exp_fp12(self, exp.as_ref())
    }

    fn cyclotomic_exp_uncompressed(&self, exp: &[u64]) -> Self {
        let mut res = Self::one();
        let mut found_one = false;

        for i in BitIteratorBE::new(exp) {
            if !found_one {
                if i {
                    found_one = true;
                } else {
                    continue;
                }
            }

            res = res.cyclotomic_square();

            if i {
                res *= self;
            }
        }
        res
    }

    /// Batch-decompresses `batch` (`1 <= batch.len() <= 16`) via a single stack-allocated `Fp2`
    /// Montgomery inversion and multiplies each recovered element into `res_opt`.
    ///
    /// Every caller ensures `z2 != 0` or `z3 != 0` for each entry, so every denominator (`4 * z2`
    /// or `z3`) and their product `acc` are nonzero in `Fp2`.
    fn decompress_and_mul_batch(batch: &[KarabinaCompressed<P>], res_opt: &mut Option<Self>) -> bool {
        let n = batch.len();
        debug_assert!((1..=16).contains(&n));

        let mut denoms = [Fp2::zero(); 16];
        let mut prods = [Fp2::zero(); 16];
        let mut is_case1 = [false; 16];
        let mut acc = Fp2::one();

        for i in 0..n {
            let c = &batch[i];
            if !c.z2.is_zero() {
                denoms[i] = c.z2.double().double();
                is_case1[i] = true;
            } else {
                denoms[i] = c.z3;
                is_case1[i] = false;
            }
            acc *= &denoms[i];
            prods[i] = acc;
        }

        // Defensive check: `acc` is a product of nonzero `Fp2` elements (`4 * z2` or `z3`), so `inverse` returns `Some`.
        let Some(mut inv_acc) = acc.inverse() else {
            return false;
        };

        let mut d_invs = [Fp2::zero(); 16];
        for i in (0..n).rev() {
            let prev = if i > 0 { prods[i - 1] } else { Fp2::one() };
            d_invs[i] = inv_acc * prev;
            inv_acc *= &denoms[i];
        }

        let fp2_nr = <P::Fp6Params as Fp6Parameters>::mul_fp2_by_nonresidue;
        for i in 0..n {
            let c = &batch[i];
            let z1 = if is_case1[i] {
                let z4s = c.z4.square();
                let uz5s = fp2_nr(&c.z5.square());
                let num = uz5s + z4s.double() + z4s - c.z3.double();
                num * d_invs[i]
            } else {
                (c.z4 * c.z5).double() * d_invs[i]
            };
            let z34 = c.z3 * c.z4;
            let inner = z1.square().double() + c.z2 * c.z5 - (z34.double() + z34);
            let z0 = fp2_nr(&inner) + Fp2::one();
            let elem = Self::new(Fp6::new(z0, c.z4, c.z3), Fp6::new(c.z2, z1, c.z5));
            match res_opt {
                Some(res) => *res *= &elem,
                None => *res_opt = Some(elem),
            }
        }

        true
    }

    /// Returns `self^exp` by the scalar Karabina compressed chain, without
    /// `Fp12Parameters::cyclotomic_exp_fp12`. Assumes `self` lies in `G_{Phi_6(p^2)}` (or is zero).
    #[doc(hidden)]
    pub fn cyclotomic_exp_scalar(&self, exp: &[u64]) -> Self {
        let Some(top_idx) = exp.iter().rposition(|&w| w != 0) else {
            return Self::one();
        };
        let total_bits = top_idx * 64 + (64 - exp[top_idx].leading_zeros() as usize);
        if total_bits == 1 {
            return *self;
        }
        // Inputs with `z2 == 0` and `z3 == 0` (such as `0` and `1`) fall back to the uncompressed chain.
        if self.c1.c0.is_zero() && self.c0.c2.is_zero() {
            return self.cyclotomic_exp_uncompressed(exp);
        }

        // Square in Karabina (2013) compressed coordinates and flush the 16-slot stack buffer via
        // Montgomery batch inversion whenever it fills.
        let mut res_opt = if (exp[0] & 1) != 0 { Some(*self) } else { None };
        let mut comp = KarabinaCompressed::<P> { z2: self.c1.c0, z3: self.c0.c2, z4: self.c0.c1, z5: self.c1.c2 };
        let mut needed = [KarabinaCompressed::<P>::default(); 16];
        let mut n = 0usize;

        for bit_idx in 1..total_bits {
            comp = comp.square();
            if ((exp[bit_idx / 64] >> (bit_idx % 64)) & 1) != 0 {
                if comp.z2.is_zero() && comp.z3.is_zero() {
                    return self.cyclotomic_exp_uncompressed(exp);
                }
                needed[n] = comp;
                n += 1;
                if n == 16 {
                    if !Self::decompress_and_mul_batch(&needed, &mut res_opt) {
                        return self.cyclotomic_exp_uncompressed(exp);
                    }
                    n = 0;
                }
            }
        }

        if n > 0 && !Self::decompress_and_mul_batch(&needed[..n], &mut res_opt) {
            return self.cyclotomic_exp_uncompressed(exp);
        }

        res_opt.unwrap_or_else(Self::one)
    }
}

#[derive(Copy, Clone, Default)]
struct KarabinaCompressed<P: Fp12Parameters> {
    z2: Fp2<Fp2Params<P>>,
    z3: Fp2<Fp2Params<P>>,
    z4: Fp2<Fp2Params<P>>,
    z5: Fp2<Fp2Params<P>>,
}

impl<P: Fp12Parameters> KarabinaCompressed<P> {
    #[inline(always)]
    fn fp4_square(z0: &Fp2<Fp2Params<P>>, z1: &Fp2<Fp2Params<P>>) -> (Fp2<Fp2Params<P>>, Fp2<Fp2Params<P>>) {
        let fp2_nr = <P::Fp6Params as Fp6Parameters>::mul_fp2_by_nonresidue;
        let tmp = *z0 * z1;
        let t0 = (*z0 + z1) * (*z0 + fp2_nr(z1)) - tmp - fp2_nr(&tmp);
        let t1 = tmp.double();
        (t0, t1)
    }

    #[inline(always)]
    fn square(self) -> Self {
        let (t2, t3) = Self::fp4_square(&self.z2, &self.z3);
        let (t4, t5) = Self::fp4_square(&self.z4, &self.z5);
        let nr_t5 = <P::Fp6Params as Fp6Parameters>::mul_fp2_by_nonresidue(&t5);
        KarabinaCompressed {
            z2: (nr_t5 + self.z2).double() + nr_t5,
            z3: (t4 - self.z3).double() + t4,
            z4: (t2 - self.z4).double() + t2,
            z5: (t3 + self.z5).double() + t3,
        }
    }
}

impl<P: Fp12Parameters> std::fmt::Display for Fp12<P> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "Fp12({} + {} * w)", self.c0, self.c1)
    }
}

impl<P: Fp12Parameters> Distribution<Fp12<P>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Fp12<P> {
        Fp12::new(Uniform::rand(rng), Uniform::rand(rng))
    }
}

impl<P: Fp12Parameters> Zero for Fp12<P> {
    fn zero() -> Self {
        Self::new(Fp6::zero(), Fp6::zero())
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }
}

impl<P: Fp12Parameters> One for Fp12<P> {
    fn one() -> Self {
        Self::new(Fp6::one(), Fp6::zero())
    }

    fn is_one(&self) -> bool {
        self.c0.is_one() && self.c1.is_zero()
    }
}

impl<P: Fp12Parameters> crate::sealed::Sealed for Fp12<P> {}

impl<P: Fp12Parameters> Field for Fp12<P> {
    type BasePrimeField = <Fp6<P::Fp6Params> as Field>::BasePrimeField;

    fn from_base_prime_field(other: Self::BasePrimeField) -> Self {
        Self::new(Fp6::from_base_prime_field(other), Fp6::zero())
    }

    #[inline]
    fn characteristic<'a>() -> &'a [u64] {
        Fp6::<P::Fp6Params>::characteristic()
    }

    fn double(&self) -> Self {
        let mut copy = *self;
        copy.double_in_place();
        copy
    }

    #[inline]
    fn from_random_bytes_with_flags<F: Flags>(bytes: &[u8]) -> Option<(Self, F)> {
        let split_at = bytes.len() / 2;
        if let Some(c0) = Fp6::<P::Fp6Params>::from_random_bytes(&bytes[..split_at])
            && let Some((c1, flags)) = Fp6::<P::Fp6Params>::from_random_bytes_with_flags::<F>(&bytes[split_at..])
        {
            return Some((Fp12::new(c0, c1), flags));
        }
        None
    }

    #[inline]
    fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
        Self::from_random_bytes_with_flags::<EmptyFlags>(bytes).map(|f| f.0)
    }

    fn double_in_place(&mut self) {
        self.c0.double_in_place();
        self.c1.double_in_place();
    }

    fn frobenius_map(&mut self, power: usize) {
        self.c0.frobenius_map(power);
        self.c1.frobenius_map(power);

        self.c1.c0.mul_assign(&P::FROBENIUS_COEFF_FP12_C1[power % 12]);
        self.c1.c1.mul_assign(&P::FROBENIUS_COEFF_FP12_C1[power % 12]);
        self.c1.c2.mul_assign(&P::FROBENIUS_COEFF_FP12_C1[power % 12]);
    }

    fn square(&self) -> Self {
        let mut copy = *self;
        copy.square_in_place();
        copy
    }

    fn square_in_place(&mut self) -> &mut Self {
        let mut ab = self.c0;
        ab.mul_assign(&self.c1);
        let mut c0c1 = self.c0;
        c0c1.add_assign(self.c1);
        let mut c0 = self.c1;
        c0 = Self::mul_fp6_by_nonresidue(&c0);
        c0.add_assign(self.c0);
        c0.mul_assign(&c0c1);
        c0.sub_assign(&ab);
        self.c1 = ab;
        self.c1.add_assign(ab);
        ab = Self::mul_fp6_by_nonresidue(&ab);
        c0.sub_assign(&ab);
        self.c0 = c0;
        self
    }

    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            let mut c0s = self.c0;
            c0s.square_in_place();
            let mut c1s = self.c1;
            c1s.square_in_place();
            c1s = Self::mul_fp6_by_nonresidue(&c1s);
            c0s.sub_assign(&c1s);

            c0s.inverse().map(|t| {
                let mut tmp = Fp12::new(t, t);
                tmp.c0.mul_assign(&self.c0);
                tmp.c1.mul_assign(&self.c1);
                tmp.c1 = -tmp.c1;

                tmp
            })
        }
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        match self.inverse() {
            Some(inv) => {
                *self = inv;
                Some(self)
            }
            None => None,
        }
    }
}

impl<P: Fp12Parameters> Neg for Fp12<P> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        let mut copy = Self::zero();
        copy.c0 = self.c0.neg();
        copy.c1 = self.c1.neg();
        copy
    }
}

impl_add_sub_from_field_ref!(Fp12, Fp12Parameters);
impl_mul_div_from_field_ref!(Fp12, Fp12Parameters);

impl<P: Fp12Parameters> Add<&'_ Self> for Fp12<P> {
    type Output = Self;

    #[inline]
    fn add(self, other: &Self) -> Self {
        let mut result = self;
        result.add_assign(other);
        result
    }
}

impl<P: Fp12Parameters> Sub<&'_ Self> for Fp12<P> {
    type Output = Self;

    #[inline]
    fn sub(self, other: &Self) -> Self {
        let mut result = self;
        result.sub_assign(&other);
        result
    }
}

impl<P: Fp12Parameters> Mul<&'_ Self> for Fp12<P> {
    type Output = Self;

    #[inline]
    fn mul(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(&other);
        result
    }
}

impl<P: Fp12Parameters> Div<&'_ Self> for Fp12<P> {
    type Output = Self;

    #[inline]
    fn div(self, other: &Self) -> Self {
        let mut result = self;
        result.mul_assign(&other.inverse().unwrap());
        result
    }
}

impl<P: Fp12Parameters> AddAssign<&'_ Self> for Fp12<P> {
    #[inline]
    fn add_assign(&mut self, other: &Self) {
        self.c0.add_assign(other.c0);
        self.c1.add_assign(other.c1);
    }
}

impl<P: Fp12Parameters> SubAssign<&'_ Self> for Fp12<P> {
    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        self.c0.sub_assign(&other.c0);
        self.c1.sub_assign(&other.c1);
    }
}

impl<P: Fp12Parameters> MulAssign<&'_ Self> for Fp12<P> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        P::mul_assign_fp12(self, other);
    }
}

impl<P: Fp12Parameters> DivAssign<&'_ Self> for Fp12<P> {
    #[inline]
    fn div_assign(&mut self, other: &Self) {
        self.mul_assign(&other.inverse().unwrap());
    }
}

impl<P: Fp12Parameters> Ord for Fp12<P> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        let c1_cmp = self.c1.cmp(&other.c1);
        if c1_cmp == Ordering::Equal { self.c0.cmp(&other.c0) } else { c1_cmp }
    }
}

impl<P: Fp12Parameters> PartialOrd for Fp12<P> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: Fp12Parameters> From<u128> for Fp12<P> {
    fn from(other: u128) -> Self {
        Self::new(other.into(), Fp6::zero())
    }
}

impl<P: Fp12Parameters> From<u64> for Fp12<P> {
    fn from(other: u64) -> Self {
        Self::new(other.into(), Fp6::zero())
    }
}

impl<P: Fp12Parameters> From<u32> for Fp12<P> {
    fn from(other: u32) -> Self {
        Self::new(other.into(), Fp6::zero())
    }
}

impl<P: Fp12Parameters> From<u16> for Fp12<P> {
    fn from(other: u16) -> Self {
        Self::new(other.into(), Fp6::zero())
    }
}

impl<P: Fp12Parameters> From<u8> for Fp12<P> {
    fn from(other: u8) -> Self {
        Self::new(other.into(), Fp6::zero())
    }
}

impl<P: Fp12Parameters> ToBits for Fp12<P> {
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        self.c0.write_bits_le(vec);
        self.c1.write_bits_le(vec);
    }

    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        self.c0.write_bits_be(vec);
        self.c1.write_bits_be(vec);
    }
}

impl<P: Fp12Parameters> ToBytes for Fp12<P> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.c0.write_le(&mut writer)?;
        self.c1.write_le(&mut writer)
    }
}

impl<P: Fp12Parameters> FromBytes for Fp12<P> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let c0 = Fp6::read_le(&mut reader)?;
        let c1 = Fp6::read_le(&mut reader)?;
        Ok(Fp12::new(c0, c1))
    }
}

impl<P: Fp12Parameters> CanonicalSerializeWithFlags for Fp12<P> {
    #[inline]
    fn serialize_with_flags<W: Write, F: Flags>(&self, mut writer: W, flags: F) -> Result<(), SerializationError> {
        self.c0.serialize_uncompressed(&mut writer)?;
        self.c1.serialize_with_flags(&mut writer, flags)?;
        Ok(())
    }

    fn serialized_size_with_flags<F: Flags>(&self) -> usize {
        self.c0.uncompressed_size() + self.c1.serialized_size_with_flags::<F>()
    }
}

impl<P: Fp12Parameters> CanonicalSerialize for Fp12<P> {
    #[inline]
    fn serialize_with_mode<W: Write>(&self, writer: W, _compress: Compress) -> Result<(), SerializationError> {
        self.serialize_with_flags(writer, EmptyFlags)
    }

    #[inline]
    fn serialized_size(&self, compress: Compress) -> usize {
        self.c0.serialized_size(compress) + self.c1.serialized_size(compress)
    }
}

impl<P: Fp12Parameters> CanonicalDeserializeWithFlags for Fp12<P> {
    #[inline]
    fn deserialize_with_flags<R: Read, F: Flags>(mut reader: R) -> Result<(Self, F), SerializationError> {
        let c0 = CanonicalDeserialize::deserialize_uncompressed(&mut reader)?;
        let (c1, flags) = Fp6::deserialize_with_flags(&mut reader)?;
        Ok((Self::new(c0, c1), flags))
    }
}

impl<P: Fp12Parameters> Valid for Fp12<P> {
    fn check(&self) -> Result<(), snarkvm_utilities::SerializationError> {
        Ok(())
    }

    fn batch_check<'a>(_batch: impl Iterator<Item = &'a Self>) -> Result<(), snarkvm_utilities::SerializationError>
    where
        Self: 'a,
    {
        Ok(())
    }
}

impl<P: Fp12Parameters> CanonicalDeserialize for Fp12<P> {
    #[inline]
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let c0 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Fp12::new(c0, c1))
    }
}
