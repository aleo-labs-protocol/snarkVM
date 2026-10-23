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

#[macro_export]
macro_rules! field {
    ($name:ident, $c0:expr) => {
        $name { 0: $c0, 1: std::marker::PhantomData }
    };
    ($name:ident, $c0:expr, $c1:expr $(,)?) => {
        $name { c0: $c0, c1: $c1 }
    };
    ($name:ident, $c0:expr, $c1:expr, $c2:expr $(,)?) => {
        $name { c0: $c0, c1: $c1, c2: $c2 }
    };
}

macro_rules! impl_field_to_biginteger {
    ($field: ident, $biginteger: ident, $parameters: ident) => {
        #[allow(clippy::from_over_into)]
        impl<P: $parameters> Into<$biginteger> for $field<P> {
            fn into(self) -> $biginteger {
                self.to_bigint()
            }
        }
    };
}

macro_rules! impl_primefield_standard_sample {
    ($field: ident, $params: ident) => {
        impl<P: $params> rand::distr::Distribution<$field<P>> for rand::distr::StandardUniform {
            #[inline]
            fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> $field<P> {
                use rand::RngExt;

                loop {
                    let mut tmp = $field(rng.sample(rand::distr::StandardUniform), PhantomData);
                    // Mask away the unused bits at the beginning.
                    tmp.0.as_mut().last_mut().map(|val| *val &= u64::MAX >> P::REPR_SHAVE_BITS);

                    if tmp.is_valid() {
                        return tmp;
                    }
                }
            }
        }
    };
}

macro_rules! impl_primefield_from_int {
    ($field: ident, u128, $params: ident) => {
        impl<P: $params> From<u128> for $field<P> {
            /// Attempts to convert an integer into a field element.
            /// Panics if the provided integer is invalid (e.g. larger than the field modulus).
            fn from(other: u128) -> Self {
                let upper = (other >> 64) as u64;
                let lower = ((other << 64) >> 64) as u64;
                let mut default_int = P::BigInteger::default();
                default_int.0[0] = lower;
                default_int.0[1] = upper;
                Self::from_bigint(default_int).unwrap()
            }
        }
    };
    ($field: ident, $int: ident, $params: ident) => {
        impl<P: $params> From<$int> for $field<P> {
            /// Attempts to convert an integer into a field element.
            /// Panics if the provided integer is invalid (e.g. larger than the field modulus).
            fn from(other: $int) -> Self {
                Self::from_bigint(P::BigInteger::from(u64::from(other))).unwrap()
            }
        }
    };
}

macro_rules! sqrt_impl {
    ($Self:ident, $P:tt, $self:expr) => {{
        use crate::LegendreSymbol::*;
        if let Some(tables) = $P::sqrt_tables() {
            return tables.sqrt($self);
        }

        // https://eprint.iacr.org/2020/1407.pdf (page 4, algorithm 1)
        match $self.legendre() {
            Zero => Some(*$self),
            QuadraticNonResidue => None,
            QuadraticResidue => {
                let n = $P::TWO_ADICITY as u64;
                // `T` is equivalent to `m` in the paper.
                let v = $self.pow($P::T_MINUS_ONE_DIV_TWO);
                let x = *$self * v.square();

                let k = (n - 1).isqrt();
                // It's important that k_2 results in a number which makes `l_minus_one_times_k`
                // divisible by `k`, because the native arithmetic will not match the field
                // arithmetic otherwise (native numbers will divide and round down, but field
                // elements will end up nowhere near the native number).
                let k_2 = if n % 2 == 0 { k / 2 } else { (n - 1) % k };
                let k_1 = k - k_2;
                let l_minus_one_times_k = n - 1 - k_2;
                let l_minus_one = l_minus_one_times_k / k;
                let l = l_minus_one + 1;

                let l_s =
                    || std::iter::repeat(l_minus_one).take(k_1 as usize).chain(std::iter::repeat(l).take(k_2 as usize));

                let mut l_sum = 0;
                let x_s = l_s().take((k as usize) - 1).map(|l| {
                    l_sum += l;
                    x.pow(BigInteger::from(2u64.pow((n - 1 - l_sum) as u32)))
                });
                let x_s = x_s.chain(Some(x));

                let find = |delta: $Self| -> u64 {
                    let mut mu = delta;
                    let mut i = 0;
                    while mu != -$Self::one() {
                        mu.square_in_place();
                        i += 1;
                    }
                    i
                };

                let eval = |mut delta: $Self| -> u64 {
                    let mut s = 0u64;
                    while delta != $Self::one() {
                        let i = find(delta);
                        let n_minus_one_minus_i = n - 1 - i;
                        s += 2u64.pow(n_minus_one_minus_i as u32);
                        if i > 0 {
                            delta *= $Self($P::POWERS_OF_ROOTS_OF_UNITY[n_minus_one_minus_i as usize], PhantomData);
                        } else {
                            delta = -delta;
                        }
                    }
                    s
                };

                let calculate_gamma = |i: usize, q_s: &[u64], last: bool| -> $Self {
                    let mut gamma = $Self::one();
                    if i != 0 {
                        q_s.iter().zip(l_s()).enumerate().for_each(|(j, (q, l))| {
                            let mut kappa = l_s().take(j).sum::<u64>() + 1 + l_s().skip(i + 1).sum::<u64>();
                            if last {
                                kappa -= 1;
                            }
                            let mut value = *q;
                            (0..l as usize).for_each(|k| {
                                let bit = value & 1 == 1;
                                if bit {
                                    gamma *= $Self($P::POWERS_OF_ROOTS_OF_UNITY[(kappa as usize) + k], PhantomData);
                                }
                                value = value.wrapping_shr(1u32);
                            });
                        });
                    }
                    gamma
                };

                let mut q_s = Vec::<u64>::with_capacity(k as usize);
                let two_to_n_minus_l = 2u64.pow((n - l) as u32);
                let two_to_n_minus_l_minus_one = 2u64.pow((n - l_minus_one) as u32);
                x_s.enumerate().for_each(|(i, x)| {
                    // Calculate g^t.
                    // This algorithm deviates from the standard description in the paper, and is
                    // explained in detail in page 6, in section 2.1.
                    let gamma = calculate_gamma(i, &q_s, false);
                    let alpha = x * gamma;
                    q_s.push(
                        eval(alpha) / if i < k_1 as usize { two_to_n_minus_l_minus_one } else { two_to_n_minus_l },
                    );
                });

                // Calculate g^{t/2}.
                let gamma = calculate_gamma(k as usize, &q_s, true);
                Some(*$self * v * gamma)
            }
        }
    }};
}

macro_rules! impl_primefield_serializer {
    ($field: ident, $params: ident, $byte_size: expr) => {
        impl<P: $params> CanonicalSerializeWithFlags for $field<P> {
            #[allow(unused_qualifications)]
            fn serialize_with_flags<W: std::io::Write, F: snarkvm_utilities::Flags>(
                &self,
                mut writer: W,
                flags: F,
            ) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                use snarkvm_utilities::serialize::{SerializationError, number_of_bits_and_bytes};
                // All reasonable `Flags` should be less than 8 bits in size
                // (256 values are enough for anyone!)
                if F::BIT_SIZE > 8 {
                    return Err(SerializationError::NotEnoughSpace);
                }

                // Calculate the number of bytes required to represent a field element
                // serialized with `flags`. If `F::BIT_SIZE < 8`,
                // this is at most `$byte_size + 1`
                let output_byte_size = number_of_bits_and_bytes(P::MODULUS_BITS as usize + F::BIT_SIZE).1;

                // Write out `self` to a temporary buffer.
                // The size of the buffer is $byte_size + 1 because `F::BIT_SIZE`
                // is at most 8 bits.
                let mut bytes = [0u8; $byte_size + 1];
                self.write_le(&mut bytes[..$byte_size])?;

                // Mask out the bits of the last byte that correspond to the flag.
                bytes[output_byte_size - 1] |= flags.u8_bitmask();

                writer.write_all(&bytes[..output_byte_size])?;
                Ok(())
            }

            // Let `m = 8 * n` for some `n` be the smallest multiple of 8 greater
            // than `P::MODULUS_BITS`.
            // If `(m - P::MODULUS_BITS) >= F::BIT_SIZE` , then this method returns `n`;
            // otherwise, it returns `n + 1`.
            fn serialized_size_with_flags<F: snarkvm_utilities::Flags>(&self) -> usize {
                snarkvm_utilities::serialize::number_of_bits_and_bytes(P::MODULUS_BITS as usize + F::BIT_SIZE).1
            }
        }

        impl<P: $params> CanonicalSerialize for $field<P> {
            #[allow(unused_qualifications)]
            #[inline]
            fn serialize_with_mode<W: std::io::Write>(
                &self,
                writer: W,
                _compress: snarkvm_utilities::serialize::Compress,
            ) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                self.serialize_with_flags(writer, snarkvm_utilities::serialize::EmptyFlags)
            }

            #[inline]
            fn serialized_size(&self, _compress: snarkvm_utilities::serialize::Compress) -> usize {
                use snarkvm_utilities::EmptyFlags;
                self.serialized_size_with_flags::<EmptyFlags>()
            }
        }

        impl<P: $params> $field<P> {
            const SERIALIZED_SIZE: usize =
                snarkvm_utilities::serialize::number_of_bits_to_number_of_bytes(P::MODULUS_BITS as usize);
        }

        impl<P: $params> CanonicalDeserializeWithFlags for $field<P> {
            #[allow(unused_qualifications)]
            fn deserialize_with_flags<R: std::io::Read, F: snarkvm_utilities::Flags>(
                mut reader: R,
            ) -> Result<(Self, F), snarkvm_utilities::serialize::SerializationError> {
                use snarkvm_utilities::serialize::SerializationError;
                // All reasonable `Flags` should be less than 8 bits in size
                // (256 values are enough for anyone!)
                if F::BIT_SIZE > 8 {
                    return Err(SerializationError::NotEnoughSpace);
                }
                // Calculate the number of bytes required to represent a field element
                // serialized with `flags`. If `F::BIT_SIZE < 8`,
                // this is at most `$byte_size + 1`
                let output_byte_size = Self::SERIALIZED_SIZE;

                let mut masked_bytes = [0; $byte_size + 1];
                reader.read_exact(&mut masked_bytes[..output_byte_size])?;

                let flags = F::from_u8_remove_flags(&mut masked_bytes[output_byte_size - 1])
                    .ok_or(SerializationError::UnexpectedFlags)?;

                Ok((Self::read_le(&masked_bytes[..])?, flags))
            }
        }

        impl<P: $params> snarkvm_utilities::Valid for $field<P> {
            fn check(&self) -> Result<(), snarkvm_utilities::SerializationError> {
                Ok(())
            }

            fn batch_check<'a>(
                _batch: impl Iterator<Item = &'a Self> + Send,
            ) -> Result<(), snarkvm_utilities::SerializationError>
            where
                Self: 'a,
            {
                Ok(())
            }
        }

        impl<P: $params> CanonicalDeserialize for $field<P> {
            #[allow(unused_qualifications)]
            fn deserialize_with_mode<R: std::io::Read>(
                reader: R,
                _compress: snarkvm_utilities::serialize::Compress,
                _validate: snarkvm_utilities::serialize::Validate,
            ) -> Result<Self, snarkvm_utilities::SerializationError> {
                use snarkvm_utilities::serialize::EmptyFlags;
                Self::deserialize_with_flags::<R, EmptyFlags>(reader).map(|(r, _)| r)
            }
        }

        impl<P: $params> serde::Serialize for $field<P> {
            fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut bytes = Vec::with_capacity(Self::SERIALIZED_SIZE);
                self.serialize_uncompressed(&mut bytes).map_err(serde::ser::Error::custom)?;

                if serializer.is_human_readable() {
                    serializer.collect_str(self)
                } else {
                    snarkvm_utilities::ToBytesSerializer::serialize(&bytes, serializer)
                }
            }
        }

        impl<'de, P: $params> serde::Deserialize<'de> for $field<P> {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                match deserializer.is_human_readable() {
                    true => {
                        let s: String = serde::Deserialize::deserialize(deserializer)?;
                        core::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)
                    }
                    false => {
                        struct SerVisitor<P>(std::marker::PhantomData<P>);

                        impl<'de, P: $params> serde::de::Visitor<'de> for SerVisitor<P> {
                            type Value = $field<P>;

                            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                                formatter.write_str("a valid field element")
                            }

                            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
                            where
                                S: serde::de::SeqAccess<'de>,
                            {
                                let len = $field::<P>::SERIALIZED_SIZE;
                                let bytes = (0..len)
                                    .map(|_| {
                                        seq.next_element()?
                                            .ok_or_else(|| serde::de::Error::custom("could not read bytes"))
                                    })
                                    .collect::<Result<Vec<_>, _>>()?;

                                CanonicalDeserialize::deserialize_compressed(&*bytes).map_err(serde::de::Error::custom)
                            }
                        }

                        let visitor = SerVisitor(std::marker::PhantomData);
                        deserializer.deserialize_tuple(Self::SERIALIZED_SIZE, visitor)
                    }
                }
            }
        }
    };
}

macro_rules! impl_field_from_random_bytes_with_flags {
    ($u64_limbs: expr) => {
        #[inline]
        fn from_random_bytes_with_flags<F: snarkvm_utilities::Flags>(bytes: &[u8]) -> Option<(Self, F)> {
            (F::BIT_SIZE <= 8)
                .then(|| {
                    let mut result_bytes = [0u8; $u64_limbs * 8 + 1];
                    // Copy the input into a temporary buffer.
                    result_bytes.iter_mut().zip(bytes).for_each(|(result, input)| {
                        *result = *input;
                    });
                    // This mask retains everything in the last limb
                    // that is below `P::MODULUS_BITS`.
                    let last_limb_mask = (u64::MAX >> P::REPR_SHAVE_BITS).to_le_bytes();
                    let mut last_bytes_mask = [0u8; 9];
                    last_bytes_mask[..8].copy_from_slice(&last_limb_mask);

                    // Length of the buffer containing the field element and the flag.
                    let output_byte_size = Self::SERIALIZED_SIZE;
                    // Location of the flag is the last byte of the serialized
                    // form of the field element.
                    let flag_location = output_byte_size - 1;

                    // At which byte is the flag located in the last limb?
                    let flag_location_in_last_limb = flag_location - (8 * ($u64_limbs - 1));

                    // Take all but the last 9 bytes.
                    let last_bytes = &mut result_bytes[8 * ($u64_limbs - 1)..];

                    // The mask only has the last `F::BIT_SIZE` bits set
                    let flags_mask = u8::MAX.checked_shl(8 - (F::BIT_SIZE as u32)).unwrap_or(0);

                    // Mask away the remaining bytes, and try to reconstruct the
                    // flag
                    let mut flags: u8 = 0;
                    for (i, (b, m)) in last_bytes.iter_mut().zip(&last_bytes_mask).enumerate() {
                        if i == flag_location_in_last_limb {
                            flags = *b & flags_mask
                        }
                        *b &= m;
                    }
                    Self::deserialize_uncompressed(&result_bytes[..($u64_limbs * 8)])
                        .ok()
                        .and_then(|f| F::from_u8(flags).map(|flag| (f, flag)))
                })
                .flatten()
        }
    };
}

/// Implements Add, Sub, AddAssign, and SubAssign on Self by deferring to an implementation on &Self
#[macro_export]
macro_rules! impl_add_sub_from_field_ref {
    ($type: ident, $params: ident) => {
        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Add<Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn add(self, other: Self) -> Self {
                let mut result = self;
                result.add_assign(&other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Sub<Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn sub(self, other: Self) -> Self {
                let mut result = self;
                result.sub_assign(&other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Add<&&Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn add(self, other: &&Self) -> Self {
                let mut result = self;
                result.add_assign(*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Sub<&&Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn sub(self, other: &&Self) -> Self {
                let mut result = self;
                result.sub_assign(*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::Add<&'a mut Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn add(self, other: &'a mut Self) -> Self {
                let mut result = self;
                result.add_assign(&*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::Sub<&'a mut Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn sub(self, other: &'a mut Self) -> Self {
                let mut result = self;
                result.sub_assign(&*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::AddAssign<Self> for $type<P> {
            fn add_assign(&mut self, other: Self) {
                self.add_assign(&other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::SubAssign<Self> for $type<P> {
            fn sub_assign(&mut self, other: Self) {
                self.sub_assign(&other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::AddAssign<&&Self> for $type<P> {
            fn add_assign(&mut self, other: &&Self) {
                self.add_assign(*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::SubAssign<&&Self> for $type<P> {
            fn sub_assign(&mut self, other: &&Self) {
                self.sub_assign(*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::AddAssign<&'a mut Self> for $type<P> {
            fn add_assign(&mut self, other: &'a mut Self) {
                self.add_assign(&*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::SubAssign<&'a mut Self> for $type<P> {
            fn sub_assign(&mut self, other: &'a mut Self) {
                self.sub_assign(&*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::iter::Sum<Self> for $type<P> {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), core::ops::Add::add)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::iter::Sum<&'a Self> for $type<P> {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), core::ops::Add::add)
            }
        }
    };
}

/// Implements Mul, Div, MulAssign, and DivAssign on Self by deferring to an implementation on &Self
#[macro_export]
macro_rules! impl_mul_div_from_field_ref {
    ($type: ident, $params: ident) => {
        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Mul<Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn mul(self, other: Self) -> Self {
                let mut result = self;
                result.mul_assign(&other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Div<Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn div(self, other: Self) -> Self {
                let mut result = self;
                result.div_assign(&other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Mul<&&Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn mul(self, other: &&Self) -> Self {
                let mut result = self;
                result.mul_assign(*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::Div<&&Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn div(self, other: &&Self) -> Self {
                let mut result = self;
                result.div_assign(*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::Mul<&'a mut Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn mul(self, other: &'a mut Self) -> Self {
                let mut result = self;
                result.mul_assign(&*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::Div<&'a mut Self> for $type<P> {
            type Output = Self;

            #[inline]
            fn div(self, other: &'a mut Self) -> Self {
                let mut result = self;
                result.div_assign(&*other);
                result
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::MulAssign<Self> for $type<P> {
            fn mul_assign(&mut self, other: Self) {
                self.mul_assign(&other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::DivAssign<Self> for $type<P> {
            fn div_assign(&mut self, other: Self) {
                self.div_assign(&other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::MulAssign<&&Self> for $type<P> {
            fn mul_assign(&mut self, other: &&Self) {
                self.mul_assign(*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::ops::DivAssign<&&Self> for $type<P> {
            fn div_assign(&mut self, other: &&Self) {
                self.div_assign(*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::MulAssign<&'a mut Self> for $type<P> {
            fn mul_assign(&mut self, other: &'a mut Self) {
                self.mul_assign(&*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::ops::DivAssign<&'a mut Self> for $type<P> {
            fn div_assign(&mut self, other: &'a mut Self) {
                self.div_assign(&*other)
            }
        }

        #[allow(unused_qualifications)]
        impl<P: $params> core::iter::Product<Self> for $type<P> {
            fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::one(), core::ops::Mul::mul)
            }
        }

        #[allow(unused_qualifications)]
        impl<'a, P: $params> core::iter::Product<&'a Self> for $type<P> {
            fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::one(), Mul::mul)
            }
        }
    };
}
