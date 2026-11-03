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

/// An argument passed into a future.
#[derive(Clone, Debug)]
pub enum Argument<N: Network> {
    /// A plaintext value.
    Plaintext(Plaintext<N>),
    /// A future.
    Future(Future<N>),
    /// A dynamic future.
    DynamicFuture(DynamicFuture<N>),
}

impl<N: Network> Equal<Self> for Argument<N> {
    type Output = Boolean<N>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Plaintext(a), Self::Plaintext(b)) => a.is_equal(b),
            (Self::Future(a), Self::Future(b)) => a.is_equal(b),
            (Self::DynamicFuture(a), Self::DynamicFuture(b)) => a.is_equal(b),
            (Self::Plaintext(..), _) | (Self::Future(..), _) | (Self::DynamicFuture(..), _) => Boolean::new(false),
        }
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Plaintext(a), Self::Plaintext(b)) => a.is_not_equal(b),
            (Self::Future(a), Self::Future(b)) => a.is_not_equal(b),
            (Self::DynamicFuture(a), Self::DynamicFuture(b)) => a.is_not_equal(b),
            (Self::Plaintext(..), _) | (Self::Future(..), _) | (Self::DynamicFuture(..), _) => Boolean::new(true),
        }
    }
}

impl<N: Network> ToBits for Argument<N> {
    /// Returns the argument as a list of **little-endian** bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Plaintext(plaintext) => {
                vec.push(false);
                plaintext.write_bits_le(vec);
            }
            Self::Future(future) => {
                vec.push(true);
                future.write_bits_le(vec);
            }
            Self::DynamicFuture(dynamic_future) => {
                vec.push(true);
                // Note. This encoding is needed to uniquely disambiguate dynamic futures from static futures.
                // This is sound because:
                //  - a static future expects the program ID bits after the initial tag bit
                //  - a program ID contains two `Identifier`s
                //  - an `Identifier` cannot lead with a zero byte, since a leading zero byte implies an empty string.
                // The 12 bits consist of: 8 bits for disambiguation (zero byte) + 4 bits reserved for future variants.
                vec.extend(std::iter::repeat_n(false, 12));
                dynamic_future.write_bits_le(vec);
            }
        }
    }

    /// Returns the argument as a list of **big-endian** bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Plaintext(plaintext) => {
                vec.push(false);
                plaintext.write_bits_be(vec);
            }
            Self::Future(future) => {
                vec.push(true);
                future.write_bits_be(vec);
            }
            Self::DynamicFuture(dynamic_future) => {
                vec.push(true);
                // Note. This encoding is needed to uniquely disambiguate dynamic futures from static futures.
                // This is sound because:
                //  - a static future expects the program ID bits after the initial tag bit
                //  - a program ID contains two `Identifier`s
                //  - an `Identifier` cannot lead with a zero byte, since a leading zero byte implies an empty string.
                // The 12 bits consist of: 8 bits for disambiguation (zero byte) + 4 bits reserved for future variants.
                vec.extend(std::iter::repeat_n(false, 12));
                dynamic_future.write_bits_be(vec);
            }
        }
    }
}

impl<N: Network> ToFields for Argument<N> {
    type Field = Field<N>;

    /// Returns this plaintext as a list of field elements.
    fn to_fields(&self) -> Result<Vec<Self::Field>> {
        // Encode the data as little-endian bits.
        let mut bits_le = self.to_bits_le();
        // Adds one final bit to the data, to serve as a terminus indicator.
        // During decryption, this final bit ensures we've reached the end.
        bits_le.push(true);
        // Pack the bits into field elements.
        let fields = bits_le
            .chunks(Field::<N>::size_in_data_bits())
            .map(Field::<N>::from_bits_le)
            .collect::<Result<Vec<_>>>()?;
        // Ensure the number of field elements does not exceed the maximum allowed size.
        match fields.len() <= N::MAX_DATA_SIZE_IN_FIELDS as usize {
            true => Ok(fields),
            false => bail!("Argument exceeds maximum allowed size"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_plaintext_argument_bit_encoding() {
        // Create a plaintext argument.
        let plaintext = Plaintext::<CurrentNetwork>::from_str("42u64").unwrap();
        let argument = Argument::Plaintext(plaintext);

        // Get the bits.
        let bits = argument.to_bits_le();

        // The first bit should be false (plaintext tag).
        assert!(!bits[0], "Plaintext argument should start with false tag bit");
    }

    #[test]
    fn test_future_argument_bit_encoding() {
        // Create a future argument.
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![],
        );
        let argument = Argument::Future(future);

        // Get the bits.
        let bits = argument.to_bits_le();

        // The first bit should be true (future tag).
        assert!(bits[0], "Future argument should start with true tag bit");

        // The next bits should be the program ID, which cannot start with a zero byte.
        // Check that at least one of the first 8 bits after the tag is true.
        let first_byte_bits = &bits[1..9];
        assert!(first_byte_bits.iter().any(|&b| b), "Static future's program ID should not start with a zero byte");
    }

    #[test]
    fn test_dynamic_future_argument_bit_encoding() {
        // Create a future and convert to dynamic.
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
        );
        let dynamic_future = DynamicFuture::from_future(&future).unwrap();
        let argument = Argument::DynamicFuture(dynamic_future);

        // Get the bits.
        let bits = argument.to_bits_le();

        // The first bit should be true (future tag).
        assert!(bits[0], "DynamicFuture argument should start with true tag bit");

        // The next 12 bits should all be false (8 for disambiguation + 4 reserved for future variants).
        for (i, &bit) in bits[1..13].iter().enumerate() {
            assert!(!bit, "DynamicFuture should have false bit at position {} (1-indexed: {})", i, i + 1);
        }
    }

    #[test]
    fn test_dynamic_future_distinguishable_from_static_future() {
        // Create a static future.
        let static_future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![],
        );
        let static_argument = Argument::Future(static_future.clone());

        // Create a dynamic future from the same future.
        let dynamic_future = DynamicFuture::from_future(&static_future).unwrap();
        let dynamic_argument = Argument::DynamicFuture(dynamic_future);

        // Get the bits for both.
        let static_bits = static_argument.to_bits_le();
        let dynamic_bits = dynamic_argument.to_bits_le();

        // Both should start with true (future tag).
        assert!(static_bits[0], "Static future should start with true tag bit");
        assert!(dynamic_bits[0], "Dynamic future should start with true tag bit");

        // The disambiguation should occur in the next 12 bits.
        // Static future: program ID bits (cannot be all zeros in first byte).
        // Dynamic future: 12 zero bits.
        let static_first_12 = &static_bits[1..13];
        let dynamic_first_12 = &dynamic_bits[1..13];

        // Static future should have at least one true bit in first 8 bits (first byte of program ID).
        assert!(
            static_first_12[..8].iter().any(|&b| b),
            "Static future should have non-zero first byte (program ID identifier)"
        );

        // Dynamic future should have all false bits in first 12 bits.
        assert!(dynamic_first_12.iter().all(|&b| !b), "Dynamic future should have all-zero disambiguation prefix");
    }

    /// Verifies equality semantics: same values are equal, different values are not.
    fn check_equality(
        same1: &Argument<CurrentNetwork>,
        same2: &Argument<CurrentNetwork>,
        different: &Argument<CurrentNetwork>,
    ) {
        // Same values should be equal.
        assert!(*same1.is_equal(same2));
        assert!(!*same1.is_not_equal(same2));
        // Different values should not be equal.
        assert!(!*same1.is_equal(different));
        assert!(*same1.is_not_equal(different));
    }

    #[test]
    fn test_argument_equality() {
        // Test plaintext equality.
        let p1 = Argument::Plaintext(Plaintext::from_str("42u64").unwrap());
        let p2 = Argument::Plaintext(Plaintext::from_str("42u64").unwrap());
        let p3 = Argument::Plaintext(Plaintext::from_str("100u64").unwrap());
        check_equality(&p1, &p2, &p3);

        // Test future equality.
        let make_future = |name: &str| {
            Future::<CurrentNetwork>::new(
                ProgramID::from_str("test.aleo").unwrap(),
                Identifier::from_str(name).unwrap(),
                vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
            )
        };
        let f1 = Argument::Future(make_future("foo"));
        let f2 = Argument::Future(make_future("foo"));
        let f3 = Argument::Future(make_future("bar"));
        check_equality(&f1, &f2, &f3);

        // Test dynamic future equality.
        let make_dynamic = |program: &str| {
            let future = Future::<CurrentNetwork>::new(
                ProgramID::from_str(program).unwrap(),
                Identifier::from_str("foo").unwrap(),
                vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
            );
            DynamicFuture::from_future(&future).unwrap()
        };
        let d1 = Argument::DynamicFuture(make_dynamic("test.aleo"));
        let d2 = Argument::DynamicFuture(make_dynamic("test.aleo"));
        let d3 = Argument::DynamicFuture(make_dynamic("other.aleo"));
        check_equality(&d1, &d2, &d3);
    }

    #[test]
    fn test_argument_equality_cross_variant() {
        // Create arguments of different variants with comparable content.
        let plaintext = Plaintext::<CurrentNetwork>::from_str("42u64").unwrap();
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![],
        );
        let dynamic_future = DynamicFuture::from_future(&future).unwrap();

        let arg_plaintext = Argument::Plaintext(plaintext);
        let arg_future = Argument::Future(future);
        let arg_dynamic = Argument::DynamicFuture(dynamic_future);

        // Cross-variant comparisons should always return false for is_equal.
        assert!(!*arg_plaintext.is_equal(&arg_future));
        assert!(!*arg_plaintext.is_equal(&arg_dynamic));
        assert!(!*arg_future.is_equal(&arg_plaintext));
        assert!(!*arg_future.is_equal(&arg_dynamic));
        assert!(!*arg_dynamic.is_equal(&arg_plaintext));
        assert!(!*arg_dynamic.is_equal(&arg_future));

        // Cross-variant comparisons should always return true for is_not_equal.
        assert!(*arg_plaintext.is_not_equal(&arg_future));
        assert!(*arg_plaintext.is_not_equal(&arg_dynamic));
        assert!(*arg_future.is_not_equal(&arg_plaintext));
        assert!(*arg_future.is_not_equal(&arg_dynamic));
        assert!(*arg_dynamic.is_not_equal(&arg_plaintext));
        assert!(*arg_dynamic.is_not_equal(&arg_future));
    }
}
