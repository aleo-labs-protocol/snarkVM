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

use crate::traits::{FftParameters, PoseidonDefaultParameters};

use core::{fmt::Debug, hash::Hash};

/// A trait that defines parameters for a prime field.
pub trait FieldParameters:
    'static + FftParameters + PoseidonDefaultParameters + Copy + Clone + Debug + Default + PartialEq + Eq + Hash
{
    /// The modulus of the field.
    const MODULUS: Self::BigInteger;

    /// The number of bits needed to represent the `Self::MODULUS`.
    const MODULUS_BITS: u32;

    /// The number of bits that must be shaved from the beginning of
    /// the representation when randomly sampling.
    const REPR_SHAVE_BITS: u32;

    /// R = 2^256 % Self::MODULUS
    const R: Self::BigInteger;

    /// R2 = R^2 % Self::MODULUS
    const R2: Self::BigInteger;

    /// INV = -MODULUS^{-1} mod 2^64
    const INV: u64;

    /// A multiplicative generator that is also a quadratic nonresidue.
    /// `Self::GENERATOR` is an element having multiplicative order
    /// `Self::MODULUS - 1`.
    /// There also does not exist `x` such that `Self::GENERATOR = x^2 %
    /// Self::MODULUS`
    const GENERATOR: Self::BigInteger;

    /// The number of bits that can be reliably stored.
    /// (Should equal `SELF::MODULUS_BITS - 1`)
    const CAPACITY: u32;

    /// t for 2^s * t = MODULUS - 1
    const T: Self::BigInteger;

    /// (t - 1) / 2
    const T_MINUS_ONE_DIV_TWO: Self::BigInteger;

    /// (Self::MODULUS - 1) / 2
    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInteger;
}
