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

use super::*;

impl<N: Network> Entry<N, Plaintext<N>> {
    /// Writes this entry as little-endian bits, or returns an error when a length prefix does not fit.
    pub fn try_write_bits_le(&self, vec: &mut Vec<bool>) -> Result<()> {
        match self {
            Self::Constant(..) => vec.extend_from_slice(&[false, false]),
            Self::Public(..) => vec.extend_from_slice(&[false, true]),
            Self::Private(..) => vec.extend_from_slice(&[true, false]),
        };
        match self {
            Self::Constant(plaintext) | Self::Public(plaintext) | Self::Private(plaintext) => {
                plaintext.try_write_bits_le(vec)
            }
        }
    }

    /// Returns this entry as little-endian bits, or an error when a length prefix does not fit.
    pub fn try_to_bits_le(&self) -> Result<Vec<bool>> {
        let mut bits = Vec::new();
        self.try_write_bits_le(&mut bits)?;
        Ok(bits)
    }
}

impl<N: Network> ToBits for Entry<N, Plaintext<N>> {
    /// Returns this entry as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        self.try_write_bits_le(vec).unwrap_or_else(|error| N::halt(error.to_string()));
    }

    /// Returns this entry as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Constant(..) => vec.extend_from_slice(&[false, false]),
            Self::Public(..) => vec.extend_from_slice(&[false, true]),
            Self::Private(..) => vec.extend_from_slice(&[true, false]),
        };
        match self {
            Self::Constant(plaintext) => plaintext.write_bits_be(vec),
            Self::Public(plaintext) => plaintext.write_bits_be(vec),
            Self::Private(plaintext) => plaintext.write_bits_be(vec),
        };
    }
}

impl<N: Network> ToBits for Entry<N, Ciphertext<N>> {
    /// Returns this entry as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Constant(..) => vec.extend_from_slice(&[false, false]),
            Self::Public(..) => vec.extend_from_slice(&[false, true]),
            Self::Private(..) => vec.extend_from_slice(&[true, false]),
        };
        match self {
            Self::Constant(plaintext) => plaintext.write_bits_le(vec),
            Self::Public(plaintext) => plaintext.write_bits_le(vec),
            Self::Private(plaintext) => plaintext.write_bits_le(vec),
        };
    }

    /// Returns this entry as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Constant(..) => vec.extend_from_slice(&[false, false]),
            Self::Public(..) => vec.extend_from_slice(&[false, true]),
            Self::Private(..) => vec.extend_from_slice(&[true, false]),
        };
        match self {
            Self::Constant(plaintext) => plaintext.write_bits_be(vec),
            Self::Public(plaintext) => plaintext.write_bits_be(vec),
            Self::Private(plaintext) => plaintext.write_bits_be(vec),
        };
    }
}
