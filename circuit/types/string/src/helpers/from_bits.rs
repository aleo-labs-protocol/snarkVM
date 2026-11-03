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

impl<E: Environment> FromBits for StringType<E> {
    type Boolean = Boolean<E>;

    /// Initializes a new string from a list of little-endian bits *with* trailing zeros (to byte-alignment).
    fn from_bits_le(bits_le: &[Self::Boolean]) -> Self {
        // Determine the mode.
        let mode = bits_le.eject_mode();
        // Inject the string size in bytes.
        let size_in_bytes = Self::inject_size_in_bytes(mode, bits_le);
        // Return the string.
        StringType { mode, bytes: bits_le.chunks(8).map(U8::from_bits_le).collect(), size_in_bytes }
    }

    /// Initializes a new scalar field element from a list of big-endian bits *with* leading zeros (to byte-alignment).
    fn from_bits_be(bits_be: &[Self::Boolean]) -> Self {
        // Determine the mode.
        let mode = bits_be.eject_mode();
        // Inject the string size in bytes.
        let size_in_bytes = Self::inject_size_in_bytes(mode, bits_be);
        // Return the string.
        StringType { mode, bytes: bits_be.chunks(8).map(U8::from_bits_be).collect(), size_in_bytes }
    }
}

impl<E: Environment> StringType<E> {
    /// Checks the size of the given bits for the given mode, and returns the size (of the string) in bytes.
    /// "Load-bearing witness allocation - Please do not optimize me." - Pratyush :)
    fn inject_size_in_bytes(mode: Mode, bits: &[Boolean<E>]) -> Field<E> {
        // Ensure the bits are byte-aligned.
        let num_bits = bits.len();
        if !num_bits.is_multiple_of(8) {
            E::halt(format!("Attempted to instantiate a {num_bits}-bit string, which is not byte-aligned"))
        }

        // Cast the number of bytes in the 'string' as a field element.
        let num_bytes =
            console::Field::from_u32(u32::try_from(num_bits / 8).unwrap_or_else(|error| E::halt(error.to_string())));

        // Inject the number of bytes as a constant.
        let expected_size_in_bytes = Field::constant(num_bytes);
        // Inject the number of bytes as a witness.
        let size_in_bytes = match mode.is_constant() {
            true => expected_size_in_bytes.clone(),
            false => Field::new(Mode::Private, num_bytes),
        };
        // Ensure the witness matches the constant.
        E::assert_eq(&expected_size_in_bytes, &size_in_bytes)
            .expect("String size witness does not match expected size");

        // Return the size in bytes.
        size_in_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u32 = 10;

    fn check_from_bits_le(mode: Mode, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random string. Take 1/4th to ensure we fit for all code points.
            let expected = rng.next_string(Circuit::MAX_STRING_BYTES / 4, true);
            let expected_num_bytes = expected.len();
            assert!(expected_num_bytes <= Circuit::MAX_STRING_BYTES as usize);

            let candidate = StringType::<Circuit>::new(mode, console::StringType::new(&expected)).to_bits_le();

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = StringType::<Circuit>::from_bits_le(&candidate);
                assert_eq!(expected, *candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    fn check_from_bits_be(mode: Mode, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random string. Take 1/4th to ensure we fit for all code points.
            let expected = rng.next_string(Circuit::MAX_STRING_BYTES / 4, true);
            let expected_num_bytes = expected.len();
            assert!(expected_num_bytes <= Circuit::MAX_STRING_BYTES as usize);

            let candidate = StringType::<Circuit>::new(mode, console::StringType::new(&expected)).to_bits_be();

            Circuit::scope(format!("{mode} {i}"), || {
                let candidate = StringType::<Circuit>::from_bits_be(&candidate);
                assert_eq!(expected, *candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    #[test]
    fn test_from_bits_le_constant() {
        check_from_bits_le(Mode::Constant, 1, 0, 0, 0);
    }

    #[test]
    fn test_from_bits_le_public() {
        check_from_bits_le(Mode::Public, 1, 0, 1, 1);
    }

    #[test]
    fn test_from_bits_le_private() {
        check_from_bits_le(Mode::Private, 1, 0, 1, 1);
    }

    #[test]
    fn test_from_bits_be_constant() {
        check_from_bits_be(Mode::Constant, 1, 0, 0, 0);
    }

    #[test]
    fn test_from_bits_be_public() {
        check_from_bits_be(Mode::Public, 1, 0, 1, 1);
    }

    #[test]
    fn test_from_bits_be_private() {
        check_from_bits_be(Mode::Private, 1, 0, 1, 1);
    }
}
