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

mod bytes;
mod from_bits;
mod from_field;
mod parse;
mod random;
mod serialize;
mod to_bits;
mod to_field;
mod to_fields;

use crate::{Boolean, Field};
use snarkvm_console_network_environment::prelude::*;

/// The number of bytes in an identifier literal, derived from the field's data capacity.
/// For BLS12-377, this is 254 / 8 = 31 bytes.
pub const SIZE_IN_BYTES: usize = Field::<Console>::SIZE_IN_DATA_BITS / 8;
/// The number of bits in an identifier literal.
pub const SIZE_IN_BITS: usize = SIZE_IN_BYTES * 8;

/// An identifier literal is an ASCII string (up to SIZE_IN_BYTES bytes) stored as a byte array.
///
/// The string content is stored as null-padded bytes in little-endian order.
///
/// Syntax: `'hello_world'` (single-quoted, no type suffix).
/// The allowed characters are: `[a-zA-Z][a-zA-Z0-9_]*`.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct IdentifierLiteral<E: Environment> {
    /// The bytes of the identifier (null-padded).
    bytes: [u8; SIZE_IN_BYTES],
    _phantom: core::marker::PhantomData<E>,
}

impl<E: Environment> IdentifierLiteral<E> {
    /// Creates a new identifier literal from a string.
    /// Allowed characters: `[a-zA-Z][a-zA-Z0-9_]*`.
    pub fn new(string: &str) -> Result<Self> {
        // Ensure the string is not empty.
        ensure!(!string.is_empty(), "Identifier literal cannot be empty");
        // Ensure the string does not exceed the maximum length.
        ensure!(string.len() <= SIZE_IN_BYTES, "Identifier literal exceeds {SIZE_IN_BYTES} bytes");
        // Copy the string bytes into the byte array.
        let mut bytes = [0u8; SIZE_IN_BYTES];
        bytes[..string.len()].copy_from_slice(string.as_bytes());
        // Validate the identifier bytes (enforces ASCII character set).
        validate_identifier_bytes(&bytes)?;
        // Return the identifier literal.
        Ok(Self { bytes, _phantom: core::marker::PhantomData })
    }

    /// Creates an identifier literal from a byte array, validating the contents.
    pub fn from_bytes_array(bytes: [u8; SIZE_IN_BYTES]) -> Result<Self> {
        validate_identifier_bytes(&bytes)?;
        Ok(Self { bytes, _phantom: core::marker::PhantomData })
    }

    /// Returns the bytes of the identifier literal.
    pub fn bytes(&self) -> &[u8; SIZE_IN_BYTES] {
        &self.bytes
    }

    /// Returns the length of the identifier (number of non-null bytes).
    pub fn length(&self) -> u8 {
        // Find the first null byte, or return SIZE_IN_BYTES if no null is found.
        // Note that `SIZE_IN_BYTES` is 31, which always fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        let length = self.bytes.iter().position(|&b| b == 0).unwrap_or(SIZE_IN_BYTES) as u8;
        length
    }
}

impl<E: Environment> TypeName for IdentifierLiteral<E> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "identifier"
    }
}

impl<E: Environment> Equal for IdentifierLiteral<E> {
    type Output = Boolean<E>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        Boolean::new(self == other)
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        Boolean::new(self != other)
    }
}

impl<E: Environment> SizeInBits for IdentifierLiteral<E> {
    /// Returns the size in bits of the identifier literal.
    fn size_in_bits() -> usize {
        SIZE_IN_BITS
    }
}

impl<E: Environment> SizeInBytes for IdentifierLiteral<E> {
    /// Returns the size in bytes of the identifier literal.
    fn size_in_bytes() -> usize {
        SIZE_IN_BYTES
    }
}

/// Validates that the byte array is a valid identifier.
/// Returns the number of string bytes (before first null).
fn validate_identifier_bytes(bytes: &[u8; SIZE_IN_BYTES]) -> Result<u8> {
    // Find the number of content bytes (before the first null).
    let num_bytes = bytes.iter().position(|&b| b == 0).unwrap_or(SIZE_IN_BYTES);
    // Ensure the identifier is not empty.
    ensure!(num_bytes > 0, "Identifier literal cannot be empty");
    // Ensure all bytes after the content are zero (canonical null-padding).
    ensure!(bytes[num_bytes..].iter().all(|&b| b == 0), "Non-zero byte after null terminator");
    // Ensure the first byte is a letter.
    ensure!(bytes[0].is_ascii_alphabetic(), "Identifier literal must start with a letter");
    // Ensure all content bytes are valid identifier characters.
    ensure!(
        bytes[..num_bytes].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_'),
        "Identifier literal must contain only letters, digits, and underscores"
    );
    // Safety: num_bytes is at most 31, which always fits in u8.
    #[allow(clippy::cast_possible_truncation)]
    Ok(num_bytes as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    #[test]
    fn test_new_valid() {
        // Single character.
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("a").is_ok());
        // Multi-character.
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("hello").is_ok());
        // With underscores and digits.
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("hello_world_42").is_ok());
        // Maximum length (31 bytes).
        let max_str = "a".repeat(SIZE_IN_BYTES);
        assert!(IdentifierLiteral::<CurrentEnvironment>::new(&max_str).is_ok());
    }

    #[test]
    fn test_new_empty_fails() {
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("").is_err());
    }

    #[test]
    fn test_new_too_long_fails() {
        let long_str = "a".repeat(SIZE_IN_BYTES + 1);
        assert!(IdentifierLiteral::<CurrentEnvironment>::new(&long_str).is_err());
    }

    #[test]
    fn test_new_must_start_with_letter() {
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("1abc").is_err());
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("_abc").is_err());
    }

    #[test]
    fn test_new_invalid_chars_fails() {
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("hello world").is_err());
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("foo@bar").is_err());
        assert!(IdentifierLiteral::<CurrentEnvironment>::new("foo-bar").is_err());
    }

    #[test]
    fn test_equality() {
        let a = IdentifierLiteral::<CurrentEnvironment>::new("hello").unwrap();
        let b = IdentifierLiteral::<CurrentEnvironment>::new("hello").unwrap();
        let c = IdentifierLiteral::<CurrentEnvironment>::new("world").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_size_in_bits() {
        assert_eq!(IdentifierLiteral::<CurrentEnvironment>::size_in_bits(), 248);
    }

    #[test]
    fn test_size_in_bytes() {
        assert_eq!(IdentifierLiteral::<CurrentEnvironment>::size_in_bytes(), 31);
    }

    #[test]
    fn test_validate_identifier_bytes_all_ascii() {
        // Test first byte: only a-z and A-Z should be valid.
        for byte in 0u8..=255 {
            let mut bytes = [0u8; SIZE_IN_BYTES];
            bytes[0] = byte;
            let result = IdentifierLiteral::<CurrentEnvironment>::from_bytes_array(bytes);
            let expected_valid = byte.is_ascii_alphabetic();
            // Check positive case: valid bytes should succeed.
            if expected_valid {
                assert!(
                    result.is_ok(),
                    "First byte {byte} ('{}'): expected valid but got error",
                    if byte.is_ascii_graphic() { byte as char } else { '?' }
                );
            } else {
                // Check negative case: invalid bytes should fail.
                assert!(
                    result.is_err(),
                    "First byte {byte} ('{}'): expected error but got success",
                    if byte.is_ascii_graphic() { byte as char } else { '?' }
                );
            }
        }

        // Test subsequent bytes: a-z, A-Z, 0-9, _ should be valid (plus null for padding).
        for byte in 0u8..=255 {
            let mut bytes = [0u8; SIZE_IN_BYTES];
            bytes[0] = b'a'; // Valid first byte.
            bytes[1] = byte;
            let result = IdentifierLiteral::<CurrentEnvironment>::from_bytes_array(bytes);
            let expected_valid = byte.is_ascii_alphanumeric() || byte == b'_' || byte == 0;
            // Check positive case: valid bytes should succeed.
            if expected_valid {
                assert!(
                    result.is_ok(),
                    "Subsequent byte {byte} ('{}'): expected valid but got error",
                    if byte.is_ascii_graphic() { byte as char } else { '?' }
                );
            } else {
                // Check negative case: invalid bytes should fail.
                assert!(
                    result.is_err(),
                    "Subsequent byte {byte} ('{}'): expected error but got success",
                    if byte.is_ascii_graphic() { byte as char } else { '?' }
                );
            }
        }
    }
}
