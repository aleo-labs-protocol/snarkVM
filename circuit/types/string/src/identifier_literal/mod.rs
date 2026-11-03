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

mod equal;
mod helpers;

use snarkvm_circuit_environment::prelude::*;
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_circuit_types_field::Field;
use snarkvm_circuit_types_integers::U8;

#[cfg(test)]
use snarkvm_circuit_environment::{assert_scope, assert_scope_fails};

// Re-export size constants from console layer.
use console::{SIZE_IN_BITS, SIZE_IN_BYTES};

/// A circuit identifier literal storing an ASCII string (up to SIZE_IN_BYTES) as a byte array.
///
/// The circuit validates that every byte is a valid identifier character
/// (`[a-zA-Z0-9_\0]`), that the first byte is a letter, and that null bytes
/// appear only as trailing padding.
#[derive(Clone)]
pub struct IdentifierLiteral<E: Environment> {
    /// The bytes of the identifier literal.
    bytes: [U8<E>; SIZE_IN_BYTES],
}

impl<E: Environment> IdentifierLiteral<E> {
    /// Returns the number of bits in an identifier literal.
    pub const fn size_in_bits() -> usize {
        SIZE_IN_BITS
    }

    /// Constructs an identifier literal from circuit bytes, validating the contents.
    fn from_bytes(bytes: [U8<E>; SIZE_IN_BYTES]) -> Self {
        // Validate the bytes.
        validate_identifier_bytes::<E>(&bytes);

        Self { bytes }
    }
}

impl<E: Environment> Inject for IdentifierLiteral<E> {
    type Primitive = console::IdentifierLiteral<E::Network>;

    /// Initializes a new circuit identifier literal from a primitive.
    fn new(mode: Mode, value: Self::Primitive) -> Self {
        // Access the raw bytes from the console identifier literal.
        let raw_bytes = value.bytes();
        // Inject each byte into the circuit.
        let bytes: [U8<E>; SIZE_IN_BYTES] = std::array::from_fn(|i| U8::new(mode, console::Integer::new(raw_bytes[i])));
        // Validate and construct.
        Self::from_bytes(bytes)
    }
}

impl<E: Environment> Eject for IdentifierLiteral<E> {
    type Primitive = console::IdentifierLiteral<E::Network>;

    /// Ejects the mode of the identifier literal.
    fn eject_mode(&self) -> Mode {
        self.bytes.eject_mode()
    }

    /// Ejects the identifier literal as a primitive.
    fn eject_value(&self) -> Self::Primitive {
        // Eject each byte and collect into the byte array.
        let mut raw_bytes = [0u8; SIZE_IN_BYTES];
        for (i, byte) in self.bytes.iter().enumerate() {
            raw_bytes[i] = *byte.eject_value();
        }
        // Recover the identifier literal from the byte array.
        console::IdentifierLiteral::from_bytes_array(raw_bytes).expect("Failed to eject identifier literal")
    }
}

impl<E: Environment> Parser for IdentifierLiteral<E> {
    /// Parses a string into an identifier literal circuit.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the content from the string.
        let (string, content) = console::IdentifierLiteral::parse(string)?;
        // Parse the mode from the string.
        let (string, mode) = opt(pair(tag("."), Mode::parse))(string)?;

        match mode {
            Some((_, mode)) => Ok((string, IdentifierLiteral::new(mode, content))),
            None => Ok((string, IdentifierLiteral::new(Mode::Constant, content))),
        }
    }
}

impl<E: Environment> FromStr for IdentifierLiteral<E> {
    type Err = Error;

    /// Parses a string into an identifier literal circuit.
    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<E: Environment> TypeName for IdentifierLiteral<E> {
    /// Returns the type name of the circuit as a string.
    #[inline]
    fn type_name() -> &'static str {
        console::IdentifierLiteral::<E::Network>::type_name()
    }
}

impl<E: Environment> Debug for IdentifierLiteral<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment> Display for IdentifierLiteral<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.eject_value(), self.eject_mode())
    }
}

/// Validates that the bytes of a field element represent a valid identifier literal.
///
/// Each of the 31 bytes must be in `[a-zA-Z0-9_\0]` (null bytes must be trailing-only).
/// The first byte must be a letter (not digit, underscore, or null).
/// This function converts bytes to bits and delegates to `validate_identifier_bits`.
fn validate_identifier_bytes<E: Environment>(bytes: &[U8<E>; SIZE_IN_BYTES]) {
    // Collect all SIZE_IN_BITS bits from the SIZE_IN_BYTES bytes.
    let mut bits = Vec::with_capacity(SIZE_IN_BITS);
    for byte in bytes.iter() {
        byte.write_bits_le(&mut bits);
    }
    // Validate the bits.
    validate_identifier_bits::<E>(&bits);
}

/// Validates that the bits represent a valid identifier literal.
///
/// Expects exactly SIZE_IN_BITS bits.
/// Each byte must be in `[a-zA-Z0-9_\0]`.
/// The first byte must be a letter.
/// Null bytes must be trailing-only.
fn validate_identifier_bits<E: Environment>(bits: &[Boolean<E>]) {
    // Sanity check: requires exactly SIZE_IN_BITS bits.
    assert_eq!(
        bits.len(),
        SIZE_IN_BITS,
        "validate_identifier_bits requires exactly {SIZE_IN_BITS} bits, got {}",
        bits.len()
    );

    // Validate each byte and collect null flags.
    let mut null_flags: Vec<Boolean<E>> = Vec::with_capacity(SIZE_IN_BYTES);
    for byte_idx in 0..SIZE_IN_BYTES {
        let offset = byte_idx * 8;
        // Convert the slice to a fixed-size array reference.
        // Safety: always succeeds since we iterate in 8-bit chunks within bounds.
        let byte_bits = <&[Boolean<E>; 8]>::try_from(&bits[offset..offset + 8]).expect("slice length is exactly 8");
        let null_flag = validate_byte::<E>(byte_bits, byte_idx == 0);
        null_flags.push(null_flag);
    }

    // Enforce trailing nulls.
    validate_trailing_nulls::<E>(&null_flags);
}

/// Precomputed intermediate values for byte validation.
/// Sharing intermediates saves constraints compared to recomputing per-predicate.
///
/// # Field Descriptions
///
/// - `b4b3`: b4 & b3 - True when offset >= 24 (high bits of 5-bit offset set).
/// - `b1b0`: b1 & b0 - True when both low bits set (used in upper/lower validation).
/// - `all_zero_5`: sum(b0..b4) == 0 - True when offset is 0.
struct ByteValidationData<E: Environment> {
    /// b4 & b3: True when offset >= 24.
    b4b3: Boolean<E>,
    /// b1 & b0: Both low bits set.
    b1b0: Boolean<E>,
    /// Low 5 bits all zero (offset = 0).
    all_zero_5: Boolean<E>,
}

impl<E: Environment> ByteValidationData<E> {
    /// Computes intermediate values from raw bits.
    fn new(b0: &Boolean<E>, b1: &Boolean<E>, b2: &Boolean<E>, b3: &Boolean<E>, b4: &Boolean<E>) -> Self {
        // b4b3 = b4 & b3 (offset >= 24).
        let b4b3 = b4 & b3;

        // b1b0 = b1 & b0 (both low bits set).
        let b1b0 = b1 & b0;

        // Compute all_zero_5 = (b0 + b1 + b2 + b3 + b4 == 0).
        // Since all inputs are boolean, their sum is zero iff all are zero.
        let sum = Field::from_boolean(b0)
            + Field::from_boolean(b1)
            + Field::from_boolean(b2)
            + Field::from_boolean(b3)
            + Field::from_boolean(b4);
        let all_zero_5 = sum.is_equal(&Field::zero());

        Self { b4b3, b1b0, all_zero_5 }
    }
}

/// Returns true if the 4-bit offset represents an invalid digit character.
/// Valid offsets: 0-9 ('0'-'9'). Invalid: 10-15.
///
/// # Truth Table (b0 not needed since it doesn't affect whether offset > 9)
///
/// | Offset | b3 | b2 | b1 | b3&(b2|b1) | Valid (≤9)? |
/// |--------|----|----|----| -----------|-------------|
/// |  0-7   | 0  | *  | *  |     0      |    Yes      |
/// |   8    | 1  | 0  | 0  |     0      |    Yes      |
/// |   9    | 1  | 0  | 0  |     0      |    Yes      |
/// |  10-11 | 1  | 0  | 1  |     1      |    No       |
/// |  12-15 | 1  | 1  | *  |     1      |    No       |
///
/// Note: 8=0b1000 and 9=0b1001 both have b3=1,b2=0,b1=0; they differ only in b0.
fn is_invalid_digit_offset<E: Environment>(b1: &Boolean<E>, b2: &Boolean<E>, b3: &Boolean<E>) -> Boolean<E> {
    // b3 & (b2 | b1): factored form saves 1 gate vs (b3&b2) | (b3&b1).
    let b2_or_b1 = b2 | b1;
    b3 & &b2_or_b1
}

/// Returns true if the 5-bit offset is in the invalid uppercase range (27-30).
///
/// # ASCII Mapping
/// Offset 0 = 64 (0x40) '@' (invalid; enforced separately in validate_byte)
/// Offset 1-26 = 65-90 (0x41-0x5A) 'A'-'Z' (valid)
/// Offset 27-30 = 91-94 (0x5B-0x5E) '[', '\', ']', '^' (invalid)
/// Offset 31 = 95 (0x5F) '_' (valid)
///
/// # Truth Table for Offsets 24-31 (where b4=1, b3=1)
///
/// | Offset | Binary | Decimal | Hex  | b2 | b1&b0 | XOR(b2,b1&b0) | Char | Valid? |
/// |--------|--------|---------|------|----|-------|---------------|------|--------|
/// |   24   | 11000  |   88    | 0x58 | 0  |   0   |      0        |  X   |  Yes   |
/// |   25   | 11001  |   89    | 0x59 | 0  |   0   |      0        |  Y   |  Yes   |
/// |   26   | 11010  |   90    | 0x5A | 0  |   0   |      0        |  Z   |  Yes   |
/// |   27   | 11011  |   91    | 0x5B | 0  |   1   |      1        |  [   |  No    |
/// |   28   | 11100  |   92    | 0x5C | 1  |   0   |      1        |  \   |  No    |
/// |   29   | 11101  |   93    | 0x5D | 1  |   0   |      1        |  ]   |  No    |
/// |   30   | 11110  |   94    | 0x5E | 1  |   0   |      1        |  ^   |  No    |
/// |   31   | 11111  |   95    | 0x5F | 1  |   1   |      0        |  _   |  Yes   |
///
/// Key insight: `(b4 & b3) & XOR(b2, b1&b0)` is true exactly for offsets 27-30.
fn is_invalid_uppercase_offset<E: Environment>(data: &ByteValidationData<E>, b2: &Boolean<E>) -> Boolean<E> {
    // XOR(b2, b1b0) via ^ uses the algebraic identity (2a)*b = a+b-c: 1 gate vs 3.
    let xor_b2_b1b0 = b2 ^ &data.b1b0;
    // bad_upper catches exactly offsets 27-30.
    &data.b4b3 & &xor_b2_b1b0
}

/// Returns true if the 5-bit offset is in the invalid lowercase range (27-31).
///
/// # ASCII Mapping
/// Offset 0 = 96 (0x60) '`' (invalid; enforced separately in validate_byte)
/// Offset 1-26 = 97-122 (0x61-0x7A) 'a'-'z' (valid)
/// Offset 27-31 = 123-127 (0x7B-0x7F) '{', '|', '}', '~', DEL (invalid)
///
/// # Truth Table for Offsets 24-31 (where b4=1, b3=1)
///
/// | Offset | Binary | Decimal | Hex  | b2 | b1&b0 | b2|(b1&b0) | Char | Valid? |
/// |--------|--------|---------|------|----|-------|------------|------|--------|
/// |   24   | 11000  |  120    | 0x78 | 0  |   0   |     0      |  x   |  Yes   |
/// |   25   | 11001  |  121    | 0x79 | 0  |   0   |     0      |  y   |  Yes   |
/// |   26   | 11010  |  122    | 0x7A | 0  |   0   |     0      |  z   |  Yes   |
/// |   27   | 11011  |  123    | 0x7B | 0  |   1   |     1      |  {   |  No    |
/// |   28   | 11100  |  124    | 0x7C | 1  |   0   |     1      |  |   |  No    |
/// |   29   | 11101  |  125    | 0x7D | 1  |   0   |     1      |  }   |  No    |
/// |   30   | 11110  |  126    | 0x7E | 1  |   0   |     1      |  ~   |  No    |
/// |   31   | 11111  |  127    | 0x7F | 1  |   1   |     1      | DEL  |  No    |
///
/// Key insight: `(b4 & b3) & (b2 | (b1&b0))` is true exactly for offsets 27-31.
fn is_invalid_lowercase_offset<E: Environment>(data: &ByteValidationData<E>, b2: &Boolean<E>) -> Boolean<E> {
    // bad_lower catches offsets 27-31.
    // The zero-offset check (all_zero_5) is enforced separately in validate_byte.
    let b2_or_b1b0 = b2 | &data.b1b0;
    &data.b4b3 & &b2_or_b1b0
}

/// Validates a single byte of an identifier literal.
/// Returns the null flag (true if this byte is 0x00) for trailing-null enforcement.
///
/// # Validation Rules
/// - b7 must be 0 (ASCII).
/// - Byte must be in [a-zA-Z0-9_\0].
/// - If `is_first_byte`, must be a letter (not digit, underscore, or null).
fn validate_byte<E: Environment>(bits: &[Boolean<E>; 8], is_first_byte: bool) -> Boolean<E> {
    let [b0, b1, b2, b3, b4, b5, b6, b7] = bits;

    // Assert b7 = 0 (ASCII high bit must be zero).
    E::assert_eq(b7, Boolean::<E>::constant(false)).expect("Identifier literal high bit must be zero");

    // Compute shared intermediates for offset validation.
    let data = ByteValidationData::new(b0, b1, b2, b3, b4);

    // Bits b6 and b5 partition the byte into four 32-byte ASCII ranges:
    //
    // | b6 | b5 | ASCII Hex Range | Category          | Valid Characters                    |
    // |----|----|-----------------|-------------------|-------------------------------------|
    // | 0  | 0  | 0x00-0x1F       | Null/control      | 0x00 (null)                         |
    // | 0  | 1  | 0x20-0x3F       | Symbols/Digits    | 0x30-0x39 ('0'-'9')                 |
    // | 1  | 0  | 0x40-0x5F       | Uppercase/Symbols | 0x41-0x5A ('A'-'Z'), 0x5F ('_')     |
    // | 1  | 1  | 0x60-0x7F       | Lowercase/Symbols | 0x61-0x7A ('a'-'z')                 |
    //
    // Only two AND gates are needed: `null = !b6 & !b5` (Boolean, returned as the null flag)
    // and `lower = b6 & b5` (Boolean, used in the lowercase enforce). The other two categories
    // are free linear combinations derived from `lower`:
    // - `upper = b6 - lower = b6*(1-b5)` (free LC, no new witness)
    // - `digit = b5 - lower = b5*(1-b6)` (free LC, no new witness)
    // This saves 2 AND gates (2 private witnesses + 2 constraints) per byte vs computing all four.
    let null = &b6.not() & &b5.not();
    let lower = b6 & b5;
    let upper_lc = E::zero() + &**b6 - &*lower; // b6*(1-b5), no new witness.
    let digit_lc = E::zero() + &**b5 - &*lower; // b5*(1-b6), no new witness.

    // Validate null category: byte must be exactly 0x00.
    // Enforces null * (1 - all_zero_5) = 0.
    let any_low5 = data.all_zero_5.clone().not();
    E::enforce(|| (&null, &any_low5, E::zero())).expect("Identifier literal null byte violation");

    // Validate digit category: must have b4=1 and low nibble <= 9.
    // Enforces digit * ((1-b4) + invalid_digit) = 0.
    // Both terms are non-negative, so their sum is zero iff b4=1 AND invalid_digit=0.
    let invalid_digit = is_invalid_digit_offset::<E>(b1, b2, b3);
    E::enforce(|| (digit_lc, E::one() - &**b4 + &*invalid_digit, E::zero()))
        .expect("Identifier literal digit validation");

    // Validate uppercase category: offsets 1-26 (A-Z) and 31 (_) valid.
    // all_zero_5 (offset 0 = '@') and bad_upper (offsets 27-30) are boolean and target disjoint
    // offsets, so their sum is zero iff both are zero. Merges two constraints into one.
    let bad_upper = is_invalid_uppercase_offset::<E>(&data, b2);
    E::enforce(|| (upper_lc, &*data.all_zero_5 + &*bad_upper, E::zero()))
        .expect("Identifier literal uppercase validation");

    // Validate lowercase category: offsets 1-26 (a-z) valid.
    // all_zero_5 (offset 0 = '`') and bad_lower (offsets 27-31) are boolean and target disjoint
    // offsets, so their sum is zero iff both are zero. Merges two constraints into one.
    let bad_lower = is_invalid_lowercase_offset::<E>(&data, b2);
    E::enforce(|| (&lower, &*data.all_zero_5 + &*bad_lower, E::zero()))
        .expect("Identifier literal lowercase validation");

    // First byte must be a letter (not digit, underscore, or null).
    // is_letter = b6 & !is_underscore_offset: b6=1 selects upper/lower range; the only non-letter
    // in a valid-offset upper/lower byte is '_' (offset 31), caught by is_underscore_offset.
    // Other invalid bytes (offset 0, bad_upper, bad_lower) are already rejected by the enforces.
    if is_first_byte {
        let partial = &data.b4b3 & &data.b1b0;
        let is_underscore_offset = &partial & b2;
        let is_letter = b6 & &is_underscore_offset.not();
        E::assert(is_letter).expect("Identifier literal must start with a letter");
    }

    // Return the null flag for trailing-null enforcement.
    null
}

/// Enforces that once a null byte appears, all subsequent bytes must be null.
fn validate_trailing_nulls<E: Environment>(null_flags: &[Boolean<E>]) {
    // For each consecutive pair: null_flags[i-1] * (1 - null_flags[i]) = 0.
    for i in 1..null_flags.len() {
        let not_null = null_flags[i].clone().not();
        E::enforce(|| (&null_flags[i - 1], &not_null, E::zero())).expect("Identifier literal trailing null violation");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentEnvironment = Circuit;

    const ITERATIONS: usize = 10;

    fn check_new(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Construct a random console identifier literal.
            let expected = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            Circuit::scope(format!("new {mode}"), || {
                // Inject the identifier literal into the circuit.
                let candidate = IdentifierLiteral::<CurrentEnvironment>::new(mode, expected);
                // Check that the ejected value matches the expected value.
                assert_eq!(expected, candidate.eject_value());
                // Check that the ejected mode matches.
                assert_eq!(mode, candidate.eject_mode());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_new_constant() -> Result<()> {
        check_new(Mode::Constant, 279, 0, 0, 0)
    }

    #[test]
    fn test_new_public() -> Result<()> {
        check_new(Mode::Public, 0, 248, 375, 809)
    }

    #[test]
    fn test_new_private() -> Result<()> {
        check_new(Mode::Private, 0, 0, 623, 809)
    }

    #[test]
    fn test_new_max_length_identifier() -> Result<()> {
        // Test the maximally large identifier (31 characters, no null padding).
        let max_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde";
        assert_eq!(max_str.len(), SIZE_IN_BYTES);

        let expected =
            console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::new(max_str).unwrap();

        Circuit::scope("new max length", || {
            let candidate = IdentifierLiteral::<CurrentEnvironment>::new(Mode::Private, expected);
            assert_eq!(expected, candidate.eject_value());
            assert_scope!(0, 0, 623, 809);
        });
        Circuit::reset();
        Ok(())
    }

    #[test]
    fn test_non_trailing_null_unsatisfied() {
        use console::FromBytes;

        // Construct a field with bytes [0x61, 0x00, 0x62, 0x00, ...] — non-null after null.
        let mut bad_bytes = vec![0u8; 32];
        bad_bytes[0] = b'a';
        bad_bytes[2] = b'b';
        let field_value = console::Field::<<CurrentEnvironment as Environment>::Network>::from_bytes_le(&bad_bytes)
            .expect("Failed to construct field from bytes");

        // Inject the field and validate in a scope.
        Circuit::scope("test_non_trailing_null", || {
            let field = Field::<CurrentEnvironment>::new(Mode::Private, field_value);
            let _candidate = IdentifierLiteral::<CurrentEnvironment>::from_field(field);
            // Constraint counts are deterministic regardless of satisfaction.
            assert_scope_fails!(0, 0, 881, 1069);
        });
        // The circuit must be unsatisfied due to the trailing-null violation.
        assert!(!Circuit::is_satisfied());
        Circuit::reset();
    }

    #[test]
    fn test_first_char_must_be_letter() {
        use console::FromBytes;

        // Construct a field with bytes [0x31, ...] — starts with '1' (digit).
        let mut digit_start_bytes = vec![0u8; 32];
        digit_start_bytes[0] = b'1';
        let field_value =
            console::Field::<<CurrentEnvironment as Environment>::Network>::from_bytes_le(&digit_start_bytes)
                .expect("Failed to construct field from bytes");

        // Inject the field and validate in a scope.
        Circuit::scope("test_first_char_digit", || {
            let field = Field::<CurrentEnvironment>::new(Mode::Private, field_value);
            let _candidate = IdentifierLiteral::<CurrentEnvironment>::from_field(field);
            // Constraint counts are deterministic regardless of satisfaction.
            assert_scope_fails!(0, 0, 881, 1069);
        });
        // The circuit must be unsatisfied due to first character not being a letter.
        assert!(!Circuit::is_satisfied());
        Circuit::reset();

        // Construct a field with bytes [0x5F, ...] — starts with '_' (underscore).
        let mut underscore_start_bytes = vec![0u8; 32];
        underscore_start_bytes[0] = b'_';
        let field_value =
            console::Field::<<CurrentEnvironment as Environment>::Network>::from_bytes_le(&underscore_start_bytes)
                .expect("Failed to construct field from bytes");

        // Inject the field and validate in a scope.
        Circuit::scope("test_first_char_underscore", || {
            let field = Field::<CurrentEnvironment>::new(Mode::Private, field_value);
            let _candidate = IdentifierLiteral::<CurrentEnvironment>::from_field(field);
            // Constraint counts are deterministic regardless of satisfaction.
            assert_scope_fails!(0, 0, 881, 1069);
        });
        // The circuit must be unsatisfied due to first character not being a letter.
        assert!(!Circuit::is_satisfied());
        Circuit::reset();
    }

    #[test]
    fn test_size_constants() {
        // Verify concrete values.
        assert_eq!(SIZE_IN_BITS, 248);
        assert_eq!(SIZE_IN_BYTES, 31);

        // Verify the relationship between bits and bytes.
        assert_eq!(SIZE_IN_BITS, SIZE_IN_BYTES * 8);

        // Verify the circuit accessor matches the module constant.
        assert_eq!(IdentifierLiteral::<CurrentEnvironment>::size_in_bits(), SIZE_IN_BITS);

        // Verify the circuit layer matches the console layer.
        assert_eq!(SIZE_IN_BYTES, console::SIZE_IN_BYTES);
        assert_eq!(SIZE_IN_BITS, console::SIZE_IN_BITS);

        // Verify that SIZE_IN_BITS fits within a single field element.
        assert!(SIZE_IN_BITS < <CurrentEnvironment as Environment>::BaseField::size_in_bits());
    }

    #[test]
    fn test_ascii_character_validation() {
        use console::FromBytes;

        // Test all 256 possible first byte values.
        // Valid first bytes: a-z (26) + A-Z (26) = 52 valid, 204 invalid.
        let mut first_valid = 0u32;
        let mut first_invalid = 0u32;
        for byte in 0u8..=255 {
            let mut raw_bytes = vec![0u8; 32];
            raw_bytes[0] = byte;
            let field_value = console::Field::<<CurrentEnvironment as Environment>::Network>::from_bytes_le(&raw_bytes)
                .expect("Failed to construct field");

            // Only a-z and A-Z should satisfy the circuit.
            let expected_valid = byte.is_ascii_alphabetic();
            if expected_valid {
                first_valid += 1
            } else {
                first_invalid += 1
            }

            Circuit::scope(format!("first_byte_{byte}"), || {
                let field = Field::<CurrentEnvironment>::new(Mode::Private, field_value);
                let _candidate = IdentifierLiteral::<CurrentEnvironment>::from_field(field);
                if expected_valid { assert_scope!(0, 0, 881, 1069) } else { assert_scope_fails!(0, 0, 881, 1069) }
            });
            Circuit::reset();
        }
        assert_eq!(first_valid, 52, "Expected 52 valid first-byte values (a-z, A-Z)");
        assert_eq!(first_invalid, 204, "Expected 204 invalid first-byte values");

        // Test all 256 possible second byte values (with valid first byte).
        // Valid second bytes: a-z (26) + A-Z (26) + 0-9 (10) + _ (1) + null (1) = 64 valid, 192 invalid.
        let mut second_valid = 0u32;
        let mut second_invalid = 0u32;
        for byte in 0u8..=255 {
            let mut raw_bytes = vec![0u8; 32];
            raw_bytes[0] = b'a'; // Valid first byte.
            raw_bytes[1] = byte;
            let field_value = console::Field::<<CurrentEnvironment as Environment>::Network>::from_bytes_le(&raw_bytes)
                .expect("Failed to construct field");

            // a-z, A-Z, 0-9, _, and null should satisfy the circuit.
            let expected_valid = byte.is_ascii_alphanumeric() || byte == b'_' || byte == 0;
            if expected_valid {
                second_valid += 1
            } else {
                second_invalid += 1
            }

            Circuit::scope(format!("second_byte_{byte}"), || {
                let field = Field::<CurrentEnvironment>::new(Mode::Private, field_value);
                let _candidate = IdentifierLiteral::<CurrentEnvironment>::from_field(field);
                if expected_valid { assert_scope!(0, 0, 881, 1069) } else { assert_scope_fails!(0, 0, 881, 1069) }
            });
            Circuit::reset();
        }
        assert_eq!(second_valid, 64, "Expected 64 valid second-byte values (a-z, A-Z, 0-9, _, null)");
        assert_eq!(second_invalid, 192, "Expected 192 invalid second-byte values");
    }

    /// Helper to convert a byte to 8 Boolean circuit values (LSB first).
    fn byte_to_bits(byte: u8, mode: Mode) -> [Boolean<CurrentEnvironment>; 8] {
        std::array::from_fn(|i| Boolean::new(mode, (byte >> i) & 1 == 1))
    }

    /// Asserts that padding bits beyond the identifier data are zero.
    fn validate_padding_bits(bits: &[Boolean<CurrentEnvironment>], data_bits: usize) {
        for bit in bits.iter().skip(data_bits) {
            CurrentEnvironment::assert_eq(bit, Boolean::<CurrentEnvironment>::constant(false))
                .expect("Identifier literal padding bit must be zero");
        }
    }

    /// Validates a single byte using validate_byte and returns whether the circuit is satisfied.
    fn check_validate_byte(byte: u8, is_first_byte: bool) -> bool {
        Circuit::scope(format!("validate_byte_{byte}"), || {
            let bits = byte_to_bits(byte, Mode::Private);
            let _null_flag = validate_byte::<CurrentEnvironment>(&bits, is_first_byte);
        });
        let satisfied = Circuit::is_satisfied();
        Circuit::reset();
        satisfied
    }

    #[test]
    fn test_validate_byte_constraint_counts() {
        Circuit::scope("validate_byte_first", || {
            let bits = byte_to_bits(b'a', Mode::Private);
            let _null_flag = validate_byte::<CurrentEnvironment>(&bits, true);
            assert_scope!(0, 0, 23, 29);
        });
        Circuit::reset();

        Circuit::scope("validate_byte_non_first", || {
            let bits = byte_to_bits(b'a', Mode::Private);
            let _null_flag = validate_byte::<CurrentEnvironment>(&bits, false);
            assert_scope!(0, 0, 20, 25);
        });
        Circuit::reset();
    }

    #[test]
    fn test_validate_trailing_nulls_constraint_counts() {
        Circuit::scope("trailing_nulls_3", || {
            let null_flags: Vec<Boolean<CurrentEnvironment>> =
                [false, false, true].iter().map(|&b| Boolean::new(Mode::Private, b)).collect();
            validate_trailing_nulls::<CurrentEnvironment>(&null_flags);
            assert_scope!(0, 0, 3, 5);
        });
        Circuit::reset();

        Circuit::scope("trailing_nulls_31", || {
            let null_flags: Vec<Boolean<CurrentEnvironment>> =
                (0..31).map(|_| Boolean::new(Mode::Private, false)).collect();
            validate_trailing_nulls::<CurrentEnvironment>(&null_flags);
            assert_scope!(0, 0, 31, 61);
        });
        Circuit::reset();
    }

    #[test]
    fn test_validate_padding_bits_constraint_counts() {
        Circuit::scope("padding_2_bits", || {
            let bits: Vec<Boolean<CurrentEnvironment>> = (0..10).map(|_| Boolean::new(Mode::Private, false)).collect();
            validate_padding_bits(&bits, 8);
            assert_scope!(0, 0, 10, 12);
        });
        Circuit::reset();
    }

    #[test]
    fn test_validate_identifier_bits_constraint_counts() {
        Circuit::scope("validate_identifier_bits", || {
            let mut bits: Vec<Boolean<CurrentEnvironment>> = Vec::with_capacity(SIZE_IN_BITS);
            bits.extend(byte_to_bits(b'a', Mode::Private));
            for _ in 1..SIZE_IN_BYTES {
                bits.extend(byte_to_bits(0x00, Mode::Private));
            }
            validate_identifier_bits::<CurrentEnvironment>(&bits);
            assert_scope!(0, 0, 623, 809);
        });
        assert!(Circuit::is_satisfied());
        Circuit::reset();
    }

    #[test]
    fn test_validate_byte_lowercase_a_to_z() {
        // All lowercase letters should be valid as first or non-first byte.
        for ch in b'a'..=b'z' {
            assert!(check_validate_byte(ch, true), "Lowercase {ch} should be valid as first byte");
            assert!(check_validate_byte(ch, false), "Lowercase {ch} should be valid as non-first byte");
        }
    }

    #[test]
    fn test_validate_byte_uppercase_a_to_z() {
        // All uppercase letters should be valid as first or non-first byte.
        for ch in b'A'..=b'Z' {
            assert!(check_validate_byte(ch, true), "Uppercase {ch} should be valid as first byte");
            assert!(check_validate_byte(ch, false), "Uppercase {ch} should be valid as non-first byte");
        }
    }

    #[test]
    fn test_validate_byte_digits_0_to_9() {
        // Digits should be invalid as first byte, valid as non-first byte.
        for ch in b'0'..=b'9' {
            assert!(!check_validate_byte(ch, true), "Digit {ch} should be invalid as first byte");
            assert!(check_validate_byte(ch, false), "Digit {ch} should be valid as non-first byte");
        }
    }

    #[test]
    fn test_validate_byte_underscore() {
        // Underscore should be invalid as first byte, valid as non-first byte.
        assert!(!check_validate_byte(b'_', true), "Underscore should be invalid as first byte");
        assert!(check_validate_byte(b'_', false), "Underscore should be valid as non-first byte");
    }

    #[test]
    fn test_validate_byte_null() {
        // Null should be invalid as first byte, valid as non-first byte (as trailing padding).
        assert!(!check_validate_byte(0x00, true), "Null should be invalid as first byte");
        assert!(check_validate_byte(0x00, false), "Null should be valid as non-first byte");
    }

    #[test]
    fn test_validate_byte_invalid_chars() {
        // Test a selection of invalid characters.
        let invalid_chars = [b' ', b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'-', b'+', b'='];
        for ch in invalid_chars {
            assert!(!check_validate_byte(ch, true), "Char {ch} should be invalid as first byte");
            assert!(!check_validate_byte(ch, false), "Char {ch} should be invalid as non-first byte");
        }
    }

    #[test]
    fn test_validate_byte_non_ascii() {
        // Non-ASCII bytes (high bit set) should be invalid.
        for ch in 128u8..=255 {
            assert!(!check_validate_byte(ch, true), "Non-ASCII {ch} should be invalid as first byte");
            assert!(!check_validate_byte(ch, false), "Non-ASCII {ch} should be invalid as non-first byte");
        }
    }

    #[test]
    fn test_validate_trailing_nulls_valid() {
        // Valid: no nulls, or nulls only at the end.
        let patterns: &[&[bool]] = &[
            &[false, false, false], // No nulls.
            &[false, false, true],  // One trailing null.
            &[false, true, true],   // Two trailing nulls.
            &[true, true, true],    // All nulls (valid for trailing check, first-byte check is separate).
        ];

        for pattern in patterns {
            Circuit::scope("trailing_nulls_valid", || {
                let null_flags: Vec<Boolean<CurrentEnvironment>> =
                    pattern.iter().map(|&b| Boolean::new(Mode::Private, b)).collect();
                validate_trailing_nulls::<CurrentEnvironment>(&null_flags);
                assert_scope!(0, 0, 3, 5);
            });
            assert!(Circuit::is_satisfied(), "Pattern {pattern:?} should be valid");
            Circuit::reset();
        }
    }

    #[test]
    fn test_validate_trailing_nulls_invalid() {
        // Invalid: non-null after null.
        let patterns: &[&[bool]] = &[
            &[true, false, false], // Non-null after null.
            &[false, true, false], // Non-null after null.
            &[true, false, true],  // Non-null sandwiched.
            &[true, true, false],  // Non-null at end after nulls.
        ];

        for pattern in patterns {
            Circuit::scope("trailing_nulls_invalid", || {
                let null_flags: Vec<Boolean<CurrentEnvironment>> =
                    pattern.iter().map(|&b| Boolean::new(Mode::Private, b)).collect();
                validate_trailing_nulls::<CurrentEnvironment>(&null_flags);
                assert_scope_fails!(0, 0, 3, 5);
            });
            assert!(!Circuit::is_satisfied(), "Pattern {pattern:?} should be invalid");
            Circuit::reset();
        }
    }

    #[test]
    fn test_validate_padding_bits_valid() {
        // Valid: padding bits are all zero.
        Circuit::scope("padding_valid", || {
            // Create bits where first 8 are data (can be any value), rest are padding (must be zero).
            let mut bits: Vec<Boolean<CurrentEnvironment>> =
                (0..10).map(|_| Boolean::new(Mode::Private, false)).collect();
            bits[0] = Boolean::new(Mode::Private, true); // Data bits can be anything.
            validate_padding_bits(&bits, 8);
            assert_scope!(0, 0, 11, 13);
        });
        assert!(Circuit::is_satisfied());
        Circuit::reset();
    }

    #[test]
    fn test_validate_padding_bits_invalid() {
        // Invalid: padding bit is one.
        Circuit::scope("padding_invalid", || {
            let mut bits: Vec<Boolean<CurrentEnvironment>> =
                (0..10).map(|_| Boolean::new(Mode::Private, false)).collect();
            bits[9] = Boolean::new(Mode::Private, true); // Padding bit is 1.
            validate_padding_bits(&bits, 8);
            // Constraint counts are deterministic regardless of satisfaction.
            assert_scope_fails!(0, 0, 11, 13);
        });
        assert!(!Circuit::is_satisfied());
        Circuit::reset();
    }

    #[test]
    fn test_validate_byte_exhaustive() {
        // Test ALL 256 byte values × 2 is_first_byte values = 512 combinations.
        for byte_value in 0u8..=255 {
            for is_first in [true, false] {
                let expected_valid = match (is_first, byte_value) {
                    // First byte: only letters valid.
                    (true, b'A'..=b'Z') | (true, b'a'..=b'z') => true,
                    (true, _) => false,
                    // Non-first byte: letters, digits, underscore, null valid.
                    (false, b'A'..=b'Z') | (false, b'a'..=b'z') => true,
                    (false, b'0'..=b'9') | (false, b'_') | (false, 0x00) => true,
                    (false, _) => false,
                };

                Circuit::scope(format!("byte_{byte_value}_first_{is_first}"), || {
                    let bits = byte_to_bits(byte_value, Mode::Private);
                    let _null_flag = validate_byte::<CurrentEnvironment>(&bits, is_first);
                    if expected_valid {
                        if is_first {
                            assert_scope!(0, 0, 23, 29);
                        } else {
                            assert_scope!(0, 0, 20, 25);
                        }
                    } else if is_first {
                        assert_scope_fails!(0, 0, 23, 29);
                    } else {
                        assert_scope_fails!(0, 0, 20, 25);
                    }
                });

                assert_eq!(
                    Circuit::is_satisfied(),
                    expected_valid,
                    "byte={byte_value} (0x{byte_value:02x}, '{}'), is_first={is_first}: expected {}",
                    if byte_value.is_ascii_graphic() { byte_value as char } else { '?' },
                    if expected_valid { "satisfied" } else { "unsatisfied" }
                );
                Circuit::reset();
            }
        }
    }

    #[test]
    fn test_validate_trailing_nulls_exhaustive() {
        // Test all 2^n combinations for n = 1 to 6 (64 combinations for n=6).
        for n in 1..=6usize {
            for pattern in 0..(1 << n) {
                // Convert pattern to bool array (bit i = whether byte i is null).
                let null_flags: Vec<bool> = (0..n).map(|i| (pattern >> i) & 1 == 1).collect();

                // Valid iff nulls are trailing-only: once a null appears, all subsequent must be null.
                // Equivalently: no 0 appears after a 1 in the null_flags array.
                let expected_valid = {
                    let mut seen_null = false;
                    let mut valid = true;
                    for &is_null in &null_flags {
                        if seen_null && !is_null {
                            valid = false;
                            break;
                        }
                        seen_null |= is_null;
                    }
                    valid
                };

                Circuit::scope(format!("trailing_n{n}_p{pattern}"), || {
                    let flags: Vec<Boolean<CurrentEnvironment>> =
                        null_flags.iter().map(|&b| Boolean::new(Mode::Private, b)).collect();
                    validate_trailing_nulls::<CurrentEnvironment>(&flags);
                    if expected_valid {
                        assert_scope!(0, 0, n as u64, (2 * n - 1) as u64);
                    } else {
                        assert_scope_fails!(0, 0, n as u64, (2 * n - 1) as u64);
                    }
                });

                assert_eq!(
                    Circuit::is_satisfied(),
                    expected_valid,
                    "n={n}, pattern={pattern:0width$b}: expected {}",
                    if expected_valid { "satisfied" } else { "unsatisfied" },
                    width = n
                );
                Circuit::reset();
            }
        }
    }

    #[test]
    fn test_is_invalid_digit_offset_exhaustive() {
        // Test all 16 nibble values (0-15).
        // The function uses only b1, b2, b3 (not b0), but we test all nibbles for clarity.
        for nibble in 0u8..16 {
            let b1 = (nibble >> 1) & 1 == 1;
            let b2 = (nibble >> 2) & 1 == 1;
            let b3 = (nibble >> 3) & 1 == 1;

            // Invalid if nibble > 9 (i.e., 10-15).
            let expected_invalid = nibble > 9;

            Circuit::scope(format!("digit_nibble_{nibble}"), || {
                let b1_circuit = Boolean::new(Mode::Private, b1);
                let b2_circuit = Boolean::new(Mode::Private, b2);
                let b3_circuit = Boolean::new(Mode::Private, b3);
                let result = is_invalid_digit_offset::<CurrentEnvironment>(&b1_circuit, &b2_circuit, &b3_circuit);
                assert_eq!(
                    result.eject_value(),
                    expected_invalid,
                    "nibble={nibble}: expected is_invalid={expected_invalid}"
                );
                assert_scope!(0, 0, 5, 5);
            });
            assert!(Circuit::is_satisfied(), "Circuit should be satisfied for nibble={nibble}");
            Circuit::reset();
        }
    }

    #[test]
    fn test_is_invalid_uppercase_offset_exhaustive() {
        // Test all 32 offset values.
        // Valid offsets: 1-26 (A-Z), 31 (_). Invalid: 0, 27-30.
        // Note: this function detects only 27-30; offset 0 ('@') is enforced separately in validate_byte.
        for offset in 0u8..32 {
            let b0 = offset & 1 == 1;
            let b1 = (offset >> 1) & 1 == 1;
            let b2 = (offset >> 2) & 1 == 1;
            let b3 = (offset >> 3) & 1 == 1;
            let b4 = (offset >> 4) & 1 == 1;

            // Invalid offsets: 27, 28, 29, 30. (Offset 0 is checked separately in validate_byte.)
            let expected_invalid = (27..=30).contains(&offset);

            Circuit::scope(format!("upper_offset_{offset}"), || {
                let b0_c = Boolean::new(Mode::Private, b0);
                let b1_c = Boolean::new(Mode::Private, b1);
                let b2_c = Boolean::new(Mode::Private, b2);
                let b3_c = Boolean::new(Mode::Private, b3);
                let b4_c = Boolean::new(Mode::Private, b4);
                let data = ByteValidationData::new(&b0_c, &b1_c, &b2_c, &b3_c, &b4_c);
                let result = is_invalid_uppercase_offset::<CurrentEnvironment>(&data, &b2_c);
                assert_eq!(
                    result.eject_value(),
                    expected_invalid,
                    "offset={offset}: expected is_invalid={expected_invalid}"
                );
                assert_scope!(0, 0, 11, 11);
            });
            assert!(Circuit::is_satisfied(), "Circuit should be satisfied for offset={offset}");
            Circuit::reset();
        }
    }

    #[test]
    fn test_is_invalid_lowercase_offset_exhaustive() {
        // Test all 32 offset values.
        // Valid offsets: 1-26 (a-z). Invalid: 0, 27-31.
        // Note: this function detects only 27-31; offset 0 ('`') is enforced separately in validate_byte.
        for offset in 0u8..32 {
            let b0 = offset & 1 == 1;
            let b1 = (offset >> 1) & 1 == 1;
            let b2 = (offset >> 2) & 1 == 1;
            let b3 = (offset >> 3) & 1 == 1;
            let b4 = (offset >> 4) & 1 == 1;

            // Invalid offsets: 27, 28, 29, 30, 31. (Offset 0 is checked separately in validate_byte.)
            let expected_invalid = offset >= 27;

            Circuit::scope(format!("lower_offset_{offset}"), || {
                let b0_c = Boolean::new(Mode::Private, b0);
                let b1_c = Boolean::new(Mode::Private, b1);
                let b2_c = Boolean::new(Mode::Private, b2);
                let b3_c = Boolean::new(Mode::Private, b3);
                let b4_c = Boolean::new(Mode::Private, b4);
                let data = ByteValidationData::new(&b0_c, &b1_c, &b2_c, &b3_c, &b4_c);
                let result = is_invalid_lowercase_offset::<CurrentEnvironment>(&data, &b2_c);
                assert_eq!(
                    result.eject_value(),
                    expected_invalid,
                    "offset={offset}: expected is_invalid={expected_invalid}"
                );
                assert_scope!(0, 0, 11, 11);
            });
            assert!(Circuit::is_satisfied(), "Circuit should be satisfied for offset={offset}");
            Circuit::reset();
        }
    }
}
