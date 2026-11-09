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

use std::{cmp::min, str::FromStr};

use crate::{FftField, FieldError, FieldParameters, PoseidonDefaultField};
use snarkvm_utilities::biginteger::BigInteger;

/// The interface for a prime field.
///
/// Implementing this trait outside snarkVM is not supported. The next major release seals it,
/// which breaks such implementations. Bounds on it and calls through it are unaffected.
pub trait PrimeField:
    FftField<FftParameters = <Self as PrimeField>::Parameters> + PoseidonDefaultField + FromStr<Err = FieldError>
{
    /// Returns the field size in bits.
    const SIZE_IN_BITS: usize = Self::Parameters::MODULUS_BITS as usize;
    /// Returns the field capacity for data bits.
    const SIZE_IN_DATA_BITS: usize = Self::Parameters::CAPACITY as usize;

    type Parameters: FieldParameters<BigInteger = Self::BigInteger>;
    type BigInteger: BigInteger;

    /// Constructs a `PrimeField` element given a human-readable `Self::BigInteger`.
    fn from_bigint(repr: Self::BigInteger) -> Option<Self>;

    /// Returns a human-readable `Self::BigInteger` in the range `0..(Self::MODULUS - 1)`.
    fn to_bigint(&self) -> Self::BigInteger;

    /// Returns the decomposition of the scalar.
    fn decompose(
        &self,
        q1: &[u64; 4],
        q2: &[u64; 4],
        b1: Self,
        b2: Self,
        r128: Self,
        half_r: &[u64; 8],
    ) -> (Self, Self, bool, bool);

    /// Returns the field size in bits.
    fn size_in_bits() -> usize {
        Self::Parameters::MODULUS_BITS as usize
    }

    /// Returns the capacity size for data bits.
    fn size_in_data_bits() -> usize {
        Self::Parameters::CAPACITY as usize
    }

    /// Returns the modulus.
    fn modulus() -> Self::BigInteger {
        Self::Parameters::MODULUS
    }

    /// Returns the modulus minus one divided by two.
    fn modulus_minus_one_div_two() -> Self::BigInteger {
        Self::Parameters::MODULUS_MINUS_ONE_DIV_TWO
    }

    /// Returns the trace.
    fn trace() -> Self::BigInteger {
        Self::Parameters::T
    }

    /// Returns the trace minus one divided by two.
    fn trace_minus_one_div_two() -> Self::BigInteger {
        Self::Parameters::T_MINUS_ONE_DIV_TWO
    }

    /// Reads bytes in big-endian, and converts them to a field element.
    /// If the bytes are larger than the modulus, it will reduce them.
    fn from_bytes_be_mod_order(bytes: &[u8]) -> Self {
        let num_modulus_bytes = Self::Parameters::MODULUS_BITS.div_ceil(8) as usize;
        let num_bytes_to_directly_convert = min(num_modulus_bytes - 1, bytes.len());
        let (leading_bytes, remaining_bytes) = bytes.split_at(num_bytes_to_directly_convert);
        // Copy the leading big-endian bytes directly into a field element.
        // The number of bytes directly converted must be less than the
        // number of bytes needed to represent the modulus, as we must begin
        // modular reduction once the data is of the same number of bytes as the modulus.
        let mut bytes_to_directly_convert = leading_bytes.to_vec();
        bytes_to_directly_convert.reverse();
        // Guaranteed to not be None, as the input is less than the modulus size.
        let mut res = Self::from_random_bytes(&bytes_to_directly_convert).unwrap();

        // Update the result, byte by byte.
        // We go through existing field arithmetic, which handles the reduction.
        let window_size = Self::from(256u64);
        for byte in remaining_bytes {
            res *= window_size;
            res += Self::from(*byte);
        }
        res
    }

    /// Reads bytes in little-endian, and converts them to a field element.
    /// If the bytes are larger than the modulus, it will reduce them.
    fn from_bytes_le_mod_order(bytes: &[u8]) -> Self {
        let mut bytes_copy = bytes.to_vec();
        bytes_copy.reverse();
        Self::from_bytes_be_mod_order(&bytes_copy)
    }
}
