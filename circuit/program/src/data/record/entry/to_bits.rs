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

/// Visibility prefix bits for (de)serializing the `Constant` variant.
const VISIBILITY_CONSTANT: [bool; 2] = [false, false];
/// Visibility prefix bits for (de)serializing the `Public` variant.
const VISIBILITY_PUBLIC: [bool; 2] = [false, true];
/// Visibility prefix bits for (de)serializing the `Private` variant.
const VISIBILITY_PRIVATE: [bool; 2] = [true, false];

impl<A: Aleo> Entry<A, Plaintext<A>> {
    /// Returns this entry as a list of **little-endian** bits, with the specified mode.
    ///
    /// # Hazards
    /// In `Public` and `Private` mode, the two visibility bits are allocated as witness variables.
    /// `Boolean::new` constrains each bit to be 0 or 1, but does not tie the bits to this entry's
    /// actual visibility, so a malicious prover can assign any of the four 2-bit patterns,
    /// including the unused `11` tag. These bits are sound only when the caller cryptographically
    /// binds this serialization to committed state. The sole caller, `get.record.dynamic`, relies
    /// on its in-circuit Merkle path check to force the bits to the committed leaf's true tag.
    /// A new caller that does not hash-bind this output to a committed value must not treat the
    /// visibility bits as trustworthy.
    pub(super) fn write_bits_le_with_visibility_as_mode(&self, vec: &mut Vec<Boolean<A>>, mode: Mode) {
        // A helper function to construct a `Boolean` with the specified mode.
        // This is needed to avoid introducing new variables for constant booleans.
        let boolean_new = |mode: Mode, value: bool| match mode {
            Mode::Constant => Boolean::constant(value),
            Mode::Public => Boolean::new(Mode::Public, value),
            Mode::Private => Boolean::new(Mode::Private, value),
        };
        // Write the variant bits.
        let visibility_bits = match self {
            Self::Constant(..) => VISIBILITY_CONSTANT,
            Self::Public(..) => VISIBILITY_PUBLIC,
            Self::Private(..) => VISIBILITY_PRIVATE,
        };
        vec.extend(visibility_bits.iter().map(|&bit| boolean_new(mode, bit)));
        // Write the data bits.
        match self {
            Self::Constant(plaintext) => plaintext.write_bits_le(vec),
            Self::Public(plaintext) => plaintext.write_bits_le(vec),
            Self::Private(plaintext) => plaintext.write_bits_le(vec),
        };
    }
}

impl<A: Aleo> ToBits for Entry<A, Plaintext<A>> {
    type Boolean = Boolean<A>;

    /// Returns this entry as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<Boolean<A>>) {
        self.write_bits_le_with_visibility_as_mode(vec, Mode::Constant);
    }

    /// Returns this entry as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<Boolean<A>>) {
        let visibility_bits = match self {
            Self::Constant(..) => VISIBILITY_CONSTANT,
            Self::Public(..) => VISIBILITY_PUBLIC,
            Self::Private(..) => VISIBILITY_PRIVATE,
        };
        vec.extend(visibility_bits.iter().map(|&bit| Boolean::constant(bit)));
        match self {
            Self::Constant(plaintext) => plaintext.write_bits_be(vec),
            Self::Public(plaintext) => plaintext.write_bits_be(vec),
            Self::Private(plaintext) => plaintext.write_bits_be(vec),
        };
    }
}

impl<A: Aleo> ToBits for Entry<A, Ciphertext<A>> {
    type Boolean = Boolean<A>;

    /// Returns this entry as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<Boolean<A>>) {
        let visibility_bits = match self {
            Self::Constant(..) => VISIBILITY_CONSTANT,
            Self::Public(..) => VISIBILITY_PUBLIC,
            Self::Private(..) => VISIBILITY_PRIVATE,
        };
        vec.extend(visibility_bits.iter().map(|&bit| Boolean::constant(bit)));
        match self {
            Self::Constant(plaintext) => plaintext.write_bits_le(vec),
            Self::Public(plaintext) => plaintext.write_bits_le(vec),
            Self::Private(plaintext) => plaintext.write_bits_le(vec),
        };
    }

    /// Returns this entry as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<Boolean<A>>) {
        let visibility_bits = match self {
            Self::Constant(..) => VISIBILITY_CONSTANT,
            Self::Public(..) => VISIBILITY_PUBLIC,
            Self::Private(..) => VISIBILITY_PRIVATE,
        };
        vec.extend(visibility_bits.iter().map(|&bit| Boolean::constant(bit)));
        match self {
            Self::Constant(plaintext) => plaintext.write_bits_be(vec),
            Self::Public(plaintext) => plaintext.write_bits_be(vec),
            Self::Private(plaintext) => plaintext.write_bits_be(vec),
        };
    }
}
