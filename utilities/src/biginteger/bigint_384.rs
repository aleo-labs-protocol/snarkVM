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

use std::{
    cmp,
    fmt::{Debug, Display},
    io::{Read, Result as IoResult, Write},
};

use crate::{
    FromBits,
    FromBytes,
    ToBits,
    ToBytes,
    biginteger::BigInteger,
    bititerator::{BitIteratorBE, BitIteratorLE},
};

use anyhow::Result;
use num_bigint::BigUint;
use rand::{
    Rng,
    RngExt,
    distr::{Distribution, StandardUniform},
};
use zeroize::Zeroize;

// The CUDA FFI reads this by bytes.
#[derive(Copy, Clone, PartialEq, Eq, Default, Hash, Zeroize)]
#[repr(transparent)]
pub struct BigInteger384(pub [u64; 6]);

impl BigInteger384 {
    pub const fn new(value: [u64; 6]) -> Self {
        BigInteger384(value)
    }
}
impl BigInteger for BigInteger384 {
    const NUM_LIMBS: usize = 6;

    #[inline]
    fn add_nocarry(&mut self, other: &Self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::_addcarry_u64;
            let mut carry = 0;
            carry = _addcarry_u64(carry, self.0[0], other.0[0], &mut self.0[0]);
            carry = _addcarry_u64(carry, self.0[1], other.0[1], &mut self.0[1]);
            carry = _addcarry_u64(carry, self.0[2], other.0[2], &mut self.0[2]);
            carry = _addcarry_u64(carry, self.0[3], other.0[3], &mut self.0[3]);
            carry = _addcarry_u64(carry, self.0[4], other.0[4], &mut self.0[4]);
            carry = _addcarry_u64(carry, self.0[5], other.0[5], &mut self.0[5]);
            carry != 0
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let mut carry = 0;
            carry = super::arithmetic::adc(&mut self.0[0], other.0[0], carry);
            carry = super::arithmetic::adc(&mut self.0[1], other.0[1], carry);
            carry = super::arithmetic::adc(&mut self.0[2], other.0[2], carry);
            carry = super::arithmetic::adc(&mut self.0[3], other.0[3], carry);
            carry = super::arithmetic::adc(&mut self.0[4], other.0[4], carry);
            carry = super::arithmetic::adc(&mut self.0[5], other.0[5], carry);
            carry != 0
        }
    }

    #[inline]
    fn sub_noborrow(&mut self, other: &Self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            use core::arch::x86_64::_subborrow_u64;
            let mut borrow = 0;
            borrow = _subborrow_u64(borrow, self.0[0], other.0[0], &mut self.0[0]);
            borrow = _subborrow_u64(borrow, self.0[1], other.0[1], &mut self.0[1]);
            borrow = _subborrow_u64(borrow, self.0[2], other.0[2], &mut self.0[2]);
            borrow = _subborrow_u64(borrow, self.0[3], other.0[3], &mut self.0[3]);
            borrow = _subborrow_u64(borrow, self.0[4], other.0[4], &mut self.0[4]);
            borrow = _subborrow_u64(borrow, self.0[5], other.0[5], &mut self.0[5]);
            borrow != 0
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let mut borrow = 0;
            borrow = super::arithmetic::sbb(&mut self.0[0], other.0[0], borrow);
            borrow = super::arithmetic::sbb(&mut self.0[1], other.0[1], borrow);
            borrow = super::arithmetic::sbb(&mut self.0[2], other.0[2], borrow);
            borrow = super::arithmetic::sbb(&mut self.0[3], other.0[3], borrow);
            borrow = super::arithmetic::sbb(&mut self.0[4], other.0[4], borrow);
            borrow = super::arithmetic::sbb(&mut self.0[5], other.0[5], borrow);
            borrow != 0
        }
    }

    #[inline]
    fn mul2(&mut self) {
        let mut last = 0;
        for i in &mut self.0 {
            let tmp = *i >> 63;
            *i <<= 1;
            *i |= last;
            last = tmp;
        }
    }

    #[inline]
    fn muln(&mut self, mut n: u32) {
        if n >= 64 * 6 {
            *self = Self::from(0);
            return;
        }
        while n >= 64 {
            let mut t = 0;
            for i in &mut self.0 {
                std::mem::swap(&mut t, i);
            }
            n -= 64;
        }
        if n > 0 {
            let mut t = 0;
            for i in &mut self.0 {
                let t2 = *i >> (64 - n);
                *i <<= n;
                *i |= t;
                t = t2;
            }
        }
    }

    #[inline]
    fn div2(&mut self) {
        let mut t = 0;
        for i in self.0.iter_mut().rev() {
            let t2 = *i << 63;
            *i >>= 1;
            *i |= t;
            t = t2;
        }
    }

    #[inline]
    fn divn(&mut self, mut n: u32) {
        if n >= 64 * 6 {
            *self = Self::from(0);
            return;
        }
        while n >= 64 {
            let mut t = 0;
            for i in self.0.iter_mut().rev() {
                std::mem::swap(&mut t, i);
            }
            n -= 64;
        }
        if n > 0 {
            let mut t = 0;
            for i in self.0.iter_mut().rev() {
                let t2 = *i << (64 - n);
                *i >>= n;
                *i |= t;
                t = t2;
            }
        }
    }

    #[inline]
    fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    #[inline]
    fn is_even(&self) -> bool {
        !self.is_odd()
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.iter().all(|&e| e == 0)
    }

    #[inline]
    fn num_bits(&self) -> u32 {
        let mut ret = 6 * 64;
        for i in self.0.iter().rev() {
            let leading = i.leading_zeros();
            ret -= leading;
            if leading != 64 {
                break;
            }
        }
        ret
    }

    #[inline]
    fn get_bit(&self, i: usize) -> bool {
        if i >= 64 * 6 {
            false
        } else {
            let limb = i / 64;
            let bit = i - (64 * limb);
            (self.0[limb] & (1 << bit)) != 0
        }
    }

    #[inline]
    fn to_biguint(&self) -> num_bigint::BigUint {
        BigUint::from_bytes_le(&self.to_bytes_le().unwrap())
    }

    #[inline]
    fn find_wnaf(&self) -> Vec<i64> {
        let mut res = Vec::new();
        let mut e = *self;
        while !e.is_zero() {
            let z: i64;
            if e.is_odd() {
                z = 2 - (e.0[0] % 4) as i64;
                if z >= 0 {
                    e.sub_noborrow(&Self::from(z as u64));
                } else {
                    e.add_nocarry(&Self::from((-z) as u64));
                }
            } else {
                z = 0;
            }
            res.push(z);
            e.div2();
        }
        res
    }
}
impl ToBits for BigInteger384 {
    #[doc = " Returns `self` as a boolean array in little-endian order, with trailing zeros."]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        vec.extend(BitIteratorLE::new(self));
    }

    #[doc = " Returns `self` as a boolean array in big-endian order, with leading zeros."]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        vec.extend(BitIteratorBE::new(self));
    }
}
impl FromBits for BigInteger384 {
    #[doc = " Returns a `BigInteger` by parsing a slice of bits in little-endian format"]
    #[doc = " and transforms it into a slice of little-endian u64 elements."]
    fn from_bits_le(bits: &[bool]) -> Result<Self> {
        let mut res = Self::default();
        for (i, bits64) in bits.chunks(64).enumerate() {
            let mut acc: u64 = 0;
            for bit in bits64.iter().rev() {
                acc <<= 1;
                acc += *bit as u64;
            }
            res.0[i] = acc;
        }
        Ok(res)
    }

    #[doc = " Returns a `BigInteger` by parsing a slice of bits in big-endian format"]
    #[doc = " and transforms it into a slice of little-endian u64 elements."]
    fn from_bits_be(bits: &[bool]) -> Result<Self> {
        let mut res = Self::default();
        for (i, bits64) in bits.rchunks(64).enumerate() {
            let mut acc: u64 = 0;
            for bit in bits64.iter() {
                acc <<= 1;
                acc += *bit as u64;
            }
            res.0[i] = acc;
        }
        Ok(res)
    }
}
impl ToBytes for BigInteger384 {
    #[inline]
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        let mut arr = [0u8; 8 * 6];
        for (i, num) in self.0.iter().enumerate() {
            arr[i * 8..(i + 1) * 8].copy_from_slice(&num.to_le_bytes());
        }
        arr.write_le(writer)
    }
}
impl FromBytes for BigInteger384 {
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        <[u64; 6]>::read_le(reader).map(Self::new)
    }
}
impl Debug for BigInteger384 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for i in self.0.iter().rev() {
            write!(f, "{:016X}", *i)?;
        }
        Ok(())
    }
}
impl Display for BigInteger384 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_biguint())
    }
}
impl Ord for BigInteger384 {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        for (a, b) in self.0.iter().rev().zip(other.0.iter().rev()) {
            match a.cmp(b) {
                cmp::Ordering::Less => return cmp::Ordering::Less,
                cmp::Ordering::Greater => return cmp::Ordering::Greater,
                _ => continue,
            }
        }
        cmp::Ordering::Equal
    }
}
impl PartialOrd for BigInteger384 {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Distribution<BigInteger384> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BigInteger384 {
        BigInteger384(rng.random())
    }
}
impl AsMut<[u64]> for BigInteger384 {
    #[inline]
    fn as_mut(&mut self) -> &mut [u64] {
        &mut self.0
    }
}
impl AsRef<[u64]> for BigInteger384 {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        &self.0
    }
}
impl From<u64> for BigInteger384 {
    #[inline]
    fn from(val: u64) -> BigInteger384 {
        let mut repr = Self::default();
        repr.0[0] = val;
        repr
    }
}
