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

use anyhow::{Result, ensure};

/// Takes as input a sequence of objects, and converts them to a series of little-endian bits.
/// All traits that implement `ToBits` can be automatically converted to bits in this manner.
#[macro_export]
macro_rules! to_bits_le {
    ($($x:expr),*) => ({
        let mut buffer = vec![];
        $($x.write_bits_le(&mut buffer);)*
        buffer
    });
    ($($x:expr),*; $size:expr) => ({
        let mut buffer = Vec::with_capacity($size);
        $($x.write_bits_le(&mut buffer);)*
        buffer
    });
}

/// Takes as input a sequence of objects, and converts them to a series of little-endian bits.
/// All traits that implement `ToBitsRaw` can be automatically converted to bits in this manner.
#[macro_export]
macro_rules! to_bits_raw_le {
    ($($x:expr),*) => ({
        let mut buffer = vec![];
        $($x.write_bits_raw_le(&mut buffer);)*
        buffer
    });
    ($($x:expr),*; $size:expr) => ({
        let mut buffer = Vec::with_capacity($size);
        $($x.write_bits_raw_le(&mut buffer);)*
        buffer
    });
}

pub trait ToBits: Sized {
    /// Writes `self` into the given vector as a boolean array in little-endian order.
    fn write_bits_le(&self, vec: &mut Vec<bool>);

    /// Writes `self` into the given vector as a boolean array in big-endian order.
    fn write_bits_be(&self, vec: &mut Vec<bool>);

    /// Returns `self` as a boolean array in little-endian order.
    fn to_bits_le(&self) -> Vec<bool> {
        let mut bits = Vec::new();
        self.write_bits_le(&mut bits);
        bits
    }

    /// Returns `self` as a boolean array in big-endian order.
    fn to_bits_be(&self) -> Vec<bool> {
        let mut bits = Vec::new();
        self.write_bits_be(&mut bits);
        bits
    }

    /// An optional indication of how many bits an object can be represented with.
    fn num_bits() -> Option<usize> {
        None
    }
}

pub trait ToBitsRaw: ToBits + Sized {
    /// Writes `self` into the given vector as a raw boolean array in little-endian order.
    fn write_bits_raw_le(&self, vec: &mut Vec<bool>);

    /// Writes `self` into the given vector as a boolean array in big-endian order.
    fn write_bits_raw_be(&self, vec: &mut Vec<bool>);

    /// Returns `self` as a boolean array in little-endian order.
    fn to_bits_raw_le(&self) -> Vec<bool> {
        let mut bits = Vec::new();
        self.write_bits_raw_le(&mut bits);
        bits
    }

    /// Returns `self` as a boolean array in big-endian order.
    fn to_bits_raw_be(&self) -> Vec<bool> {
        let mut bits = Vec::new();
        self.write_bits_raw_be(&mut bits);
        bits
    }
}

pub trait FromBits: Sized {
    /// Reads `Self` from a boolean array in little-endian order.
    fn from_bits_le(bits: &[bool]) -> Result<Self>;

    /// Reads `Self` from a boolean array in big-endian order.
    fn from_bits_be(bits: &[bool]) -> Result<Self>;
}

/********************/
/****** Tuples ******/
/********************/

/// A helper macro to implement `ToBits` for a tuple of `ToBits` circuits.
macro_rules! to_bits_tuple {
    (($t0:ident, $i0:tt), $(($ty:ident, $idx:tt)),+) => {
        impl<$t0: ToBits, $($ty: ToBits),+> ToBits for ($t0, $($ty),+) {
            /// A helper method to return a concatenated list of little-endian bits from the circuits.
            #[inline]
            fn write_bits_le(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                (&self).write_bits_le(vec);
            }

            /// A helper method to return a concatenated list of big-endian bits from the circuits.
            #[inline]
            fn write_bits_be(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                (&self).write_bits_be(vec);
            }
        }

        impl<'a, $t0: ToBits, $($ty: ToBits),+> ToBits for &'a ($t0, $($ty),+) {
            /// A helper method to return a concatenated list of little-endian bits from the circuits.
            #[inline]
            fn write_bits_le(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                self.$i0.write_bits_le(vec);
                $(self.$idx.write_bits_le(vec);)+
            }

            /// A helper method to return a concatenated list of big-endian bits from the circuits.
            #[inline]
            fn write_bits_be(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                self.$i0.write_bits_be(vec);
                $(self.$idx.write_bits_be(vec);)+
            }
        }

        impl<$t0: ToBitsRaw, $($ty: ToBitsRaw),+> ToBitsRaw for ($t0, $($ty),+) {
            /// A helper method to return a concatenated list of little-endian bits without variant or identifier bits from the circuits.
            #[inline]
            fn write_bits_raw_le(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                (&self).write_bits_raw_le(vec);
            }

            /// A helper method to return a concatenated list of bits-endian bits without variant or identifier bits from the circuits.
            #[inline]
            fn write_bits_raw_be(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                (&self).write_bits_raw_be(vec);
            }
        }

        impl<'a, $t0: ToBitsRaw, $($ty: ToBitsRaw),+> ToBitsRaw for &'a ($t0, $($ty),+) {
            /// A helper method to return a concatenated list of little-endian bits without variant or identifier bits from the circuits.
            #[inline]
            fn write_bits_raw_le(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                self.$i0.write_bits_raw_le(vec);
                $(self.$idx.write_bits_raw_le(vec);)+
            }

            /// A helper method to return a concatenated list of bits-endian bits without variant or identifier bits from the circuits.
            #[inline]
            fn write_bits_raw_be(&self, vec: &mut Vec<bool>) {
                // The tuple is order-preserving, meaning the first circuit in is the first circuit bits out.
                self.$i0.write_bits_raw_be(vec);
                $(self.$idx.write_bits_raw_be(vec);)+
            }
        }
    }
}

to_bits_tuple!((C0, 0), (C1, 1));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3), (C4, 4));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3), (C4, 4), (C5, 5));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3), (C4, 4), (C5, 5), (C6, 6));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3), (C4, 4), (C5, 5), (C6, 6), (C7, 7));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3), (C4, 4), (C5, 5), (C6, 6), (C7, 7), (C8, 8));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3), (C4, 4), (C5, 5), (C6, 6), (C7, 7), (C8, 8), (C9, 9));
to_bits_tuple!((C0, 0), (C1, 1), (C2, 2), (C3, 3), (C4, 4), (C5, 5), (C6, 6), (C7, 7), (C8, 8), (C9, 9), (C10, 10));

/********************/
/****** Boolean *****/
/********************/

impl ToBits for bool {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        vec.push(*self);
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        vec.push(*self);
    }
}

/********************/
/***** Integers *****/
/********************/

macro_rules! impl_bits_for_integer {
    ($int:ty) => {
        impl ToBits for $int {
            /// Returns `self` as a boolean array in little-endian order.
            #[inline]
            fn write_bits_le(&self, vec: &mut Vec<bool>) {
                let mut value = *self;
                for _ in 0..<$int>::BITS {
                    vec.push(value & 1 == 1);
                    value = value.wrapping_shr(1u32);
                }
            }

            /// Returns `self` as a boolean array in big-endian order.
            #[inline]
            fn write_bits_be(&self, vec: &mut Vec<bool>) {
                let reversed = self.reverse_bits();
                reversed.write_bits_le(vec);
            }

            fn num_bits() -> Option<usize> {
                Some(<$int>::BITS as usize)
            }
        }

        impl FromBits for $int {
            /// Reads `Self` from a boolean array in little-endian order.
            #[inline]
            fn from_bits_le(bits: &[bool]) -> Result<Self> {
                // If the number of bits exceeds the size of the integer, ensure that the upper bits are all zero.
                // Note that because the input bits are little-endian, these are the bits at the end of slice.
                for bit in bits.iter().skip(<$int>::BITS as usize) {
                    ensure!(!bit, "upper bits are not zero");
                }
                // Construct the integer from the bits.
                Ok(bits.iter().take(<$int>::BITS as usize).rev().fold(0, |value, bit| match bit {
                    true => (value.wrapping_shl(1)) ^ 1,
                    false => (value.wrapping_shl(1)) ^ 0,
                }))
            }

            /// Reads `Self` from a boolean array in big-endian order.
            #[inline]
            fn from_bits_be(bits: &[bool]) -> Result<Self> {
                // If the number of bits exceeds the size of the integer, ensure that the upper bits are all zero.
                // Note that because the input bits are big-endian, these are the bits at the beginning of slice.
                for bit in bits.iter().take(bits.len().saturating_sub(<$int>::BITS as usize)) {
                    ensure!(!bit, "upper bits are not zero");
                }
                // Construct the integer from the bits.
                Ok(bits.iter().skip(bits.len().saturating_sub(<$int>::BITS as usize)).fold(0, |value, bit| match bit {
                    true => (value.wrapping_shl(1)) ^ 1,
                    false => (value.wrapping_shl(1)) ^ 0,
                }))
            }
        }
    };
}

impl_bits_for_integer!(u8);
impl_bits_for_integer!(u16);
impl_bits_for_integer!(u32);
impl_bits_for_integer!(u64);
impl_bits_for_integer!(u128);

impl_bits_for_integer!(i8);
impl_bits_for_integer!(i16);
impl_bits_for_integer!(i32);
impl_bits_for_integer!(i64);
impl_bits_for_integer!(i128);

/********************/
/****** String ******/
/********************/

impl ToBits for String {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        // The vector is order-preserving, meaning the first byte in is the first byte bits out.
        self.as_bytes().write_bits_le(vec);
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        // The vector is order-preserving, meaning the first byte in is the first byte bits out.
        self.as_bytes().write_bits_be(vec);
    }
}

/********************/
/****** Arrays ******/
/********************/

impl<C: ToBits> ToBits for Vec<C> {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        // The vector is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_le(vec);
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        // The vector is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_be(vec);
    }
}

impl<C: ToBits, const N: usize> ToBits for [C; N] {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        // The slice is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_le(vec)
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        // The slice is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_be(vec)
    }
}

impl<C: ToBits> ToBits for &[C] {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        if let Some(num_bits) = C::num_bits() {
            vec.reserve(num_bits * self.len());
        }

        for elem in self.iter() {
            elem.write_bits_le(vec);
        }
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        if let Some(num_bits) = C::num_bits() {
            vec.reserve(num_bits * self.len());
        }

        for elem in self.iter() {
            elem.write_bits_be(vec);
        }
    }
}

impl<C: ToBitsRaw> ToBitsRaw for Vec<C> {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_raw_le(&self, vec: &mut Vec<bool>) {
        // The vector is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_raw_le(vec);
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_raw_be(&self, vec: &mut Vec<bool>) {
        // The vector is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_raw_be(vec);
    }
}

impl<C: ToBitsRaw, const N: usize> ToBitsRaw for [C; N] {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_raw_le(&self, vec: &mut Vec<bool>) {
        // The slice is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_raw_le(vec)
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_raw_be(&self, vec: &mut Vec<bool>) {
        // The slice is order-preserving, meaning the first variable in is the first variable bits out.
        self.as_slice().write_bits_raw_be(vec)
    }
}

impl<C: ToBitsRaw> ToBitsRaw for &[C] {
    /// A helper method to return a concatenated list of little-endian bits.
    #[inline]
    fn write_bits_raw_le(&self, vec: &mut Vec<bool>) {
        if let Some(num_bits) = C::num_bits() {
            vec.reserve(num_bits * self.len());
        }

        for elem in self.iter() {
            elem.write_bits_raw_le(vec);
        }
    }

    /// A helper method to return a concatenated list of big-endian bits.
    #[inline]
    fn write_bits_raw_be(&self, vec: &mut Vec<bool>) {
        if let Some(num_bits) = C::num_bits() {
            vec.reserve(num_bits * self.len());
        }

        for elem in self.iter() {
            elem.write_bits_raw_be(vec);
        }
    }
}

impl FromBits for Vec<u8> {
    /// A helper method to return `Self` from a concatenated list of little-endian bits.
    #[inline]
    fn from_bits_le(bits: &[bool]) -> Result<Self> {
        // The vector is order-preserving, meaning the first variable in is the first variable bits out.
        bits.chunks(8).map(u8::from_bits_le).collect::<Result<Vec<_>>>()
    }

    /// A helper method to return `Self` from a concatenated list of big-endian bits.
    #[inline]
    fn from_bits_be(bits: &[bool]) -> Result<Self> {
        // The vector is order-preserving, meaning the first variable in is the first variable bits out.
        bits.chunks(8).map(u8::from_bits_be).collect::<Result<Vec<_>>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TestRng, Uniform};

    use anyhow::Result;
    use rand::{RngExt, distr::Alphanumeric};

    const ITERATIONS: u64 = 10000;

    fn random_string(len: u16, rng: &mut TestRng) -> String {
        rng.sample_iter(&Alphanumeric).take(len as usize).map(char::from).collect()
    }

    #[test]
    fn test_to_bits_le_macro() {
        let rng = &mut TestRng::default();

        // The checker.
        macro_rules! check {
            ($given:expr) => {{
                let given = $given;

                let mut expected = Vec::new();
                given.iter().for_each(|elem| elem.write_bits_le(&mut expected));

                let candidate = to_bits_le!(given);
                assert_eq!(candidate, expected);
            }};
        }

        // U8
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<u8>>());
        // U16
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<u16>>());
        // U32
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<u32>>());
        // U64
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<u64>>());
        // U128
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<u128>>());
        // I8
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<i8>>());
        // I16
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<i16>>());
        // I32
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<i32>>());
        // I64
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<i64>>());
        // I128
        check!((0..100).map(|_| Uniform::rand(rng)).collect::<Vec<i128>>());
        // String
        check!((0..100).map(|_| random_string(rng.random(), rng)).collect::<Vec<String>>());
        // Vec<Vec<u8>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<u8>>()).collect::<Vec<_>>());
        // Vec<Vec<u16>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<u16>>()).collect::<Vec<_>>());
        // Vec<Vec<u32>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<u32>>()).collect::<Vec<_>>());
        // Vec<Vec<u64>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<u64>>()).collect::<Vec<_>>());
        // Vec<Vec<u128>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<u128>>()).collect::<Vec<_>>());
        // Vec<Vec<i8>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<i8>>()).collect::<Vec<_>>());
        // Vec<Vec<i16>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<i16>>()).collect::<Vec<_>>());
        // Vec<Vec<i32>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<i32>>()).collect::<Vec<_>>());
        // Vec<Vec<i64>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<i64>>()).collect::<Vec<_>>());
        // Vec<Vec<i128>>
        check!((0..100).map(|_| (0..128).map(|_| Uniform::rand(rng)).collect::<Vec<i128>>()).collect::<Vec<_>>());
        // Vec<Vec<String>>
        check!(
            (0..100)
                .map(|_| (0..128).map(|_| random_string(rng.random(), rng)).collect::<Vec<String>>())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_to_bits_le_macro_with_capacity() {
        let mut expected = Vec::new();
        1u8.write_bits_le(&mut expected);
        2u16.write_bits_le(&mut expected);
        3u32.write_bits_le(&mut expected);
        4u64.write_bits_le(&mut expected);
        5u128.write_bits_le(&mut expected);
        6i8.write_bits_le(&mut expected);
        7i16.write_bits_le(&mut expected);
        8i32.write_bits_le(&mut expected);
        9i64.write_bits_le(&mut expected);
        10i128.write_bits_le(&mut expected);

        let capacity = expected.len();

        let candidate = to_bits_le![1u8, 2u16, 3u32, 4u64, 5u128, 6i8, 7i16, 8i32, 9i64, 10i128; capacity];
        assert_eq!(candidate, expected);
    }

    #[test]
    fn test_integers() -> Result<()> {
        macro_rules! check_integer {
            ($integer:tt, $rng:expr) => {{
                for _ in 0..ITERATIONS {
                    let expected: $integer = Uniform::rand($rng);

                    let bits_le = expected.to_bits_le();
                    assert_eq!(expected, $integer::from_bits_le(&bits_le)?);

                    let bits_be = expected.to_bits_be();
                    assert_eq!(expected, $integer::from_bits_be(&bits_be)?);
                }
            }};
        }

        let mut rng = TestRng::default();

        check_integer!(u8, &mut rng);
        check_integer!(u16, &mut rng);
        check_integer!(u32, &mut rng);
        check_integer!(u64, &mut rng);
        check_integer!(u128, &mut rng);

        check_integer!(i8, &mut rng);
        check_integer!(i16, &mut rng);
        check_integer!(i32, &mut rng);
        check_integer!(i64, &mut rng);
        check_integer!(i128, &mut rng);

        Ok(())
    }
}
