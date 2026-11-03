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
mod parse;
pub(crate) mod serialize;

use crate::{LiteralType, PlaintextType, U32};
use snarkvm_console_network::prelude::*;

use core::fmt::{Debug, Display};

/// An `ArrayType` defines the type and size of an array.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ArrayType<N: Network> {
    /// The element type.
    element_type: Box<PlaintextType<N>>,
    /// The length of the array.
    length: U32<N>,
}

impl<N: Network> ArrayType<N> {
    /// Returns `true` if the `ArrayType` is a bit array.
    pub const fn is_bit_array(&self) -> bool {
        matches!(self.next_element_type(), PlaintextType::Literal(LiteralType::Boolean))
    }

    /// Returns `true` if the `ArrayType` contains a string type.
    pub fn contains_string_type(&self) -> bool {
        // Initialize depth counter and current array type.
        let mut array_type = self;

        // Check nested array types up to the maximum data depth.
        for _ in 0..=N::MAX_DATA_DEPTH {
            // Check if the current element type is a string type.
            if array_type.next_element_type().contains_string_type() {
                return true;
            }
            // If the next element is an array, continue to the next depth. Otherwise, we can stop checking.
            if let PlaintextType::Array(next) = array_type.next_element_type() {
                array_type = next;
            } else {
                return false;
            }
        }
        // If we reach here, it means we've exceeded the maximum depth without finding a non-array type.
        true
    }

    /// Returns `true` if the `ArrayType` contains an identifier type.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        // Initialize current array type.
        let mut array_type = self;

        // Check nested array types up to the maximum data depth.
        for _ in 0..N::MAX_DATA_DEPTH {
            match array_type.next_element_type() {
                PlaintextType::Literal(LiteralType::Identifier) => return Ok(true),
                PlaintextType::Literal(_) => return Ok(false),
                PlaintextType::Array(next) => array_type = next,
                // Structs are checked in their definition.
                PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_) => return Ok(false),
            }
        }
        // An identifier type was not detected, and the maximum data depth has been exceeded.
        bail!("Array type exceeds the maximum data depth of {}", N::MAX_DATA_DEPTH)
    }

    /// Returns `true` if the `ArrayType` contains an array type with a size that exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        // Initialize depth counter and current array type.
        let mut array_type = self;

        // Check nested array types up to the maximum data depth.
        for _ in 0..=N::MAX_DATA_DEPTH {
            // Check if the current array's length exceeds the maximum allowed size.
            if **array_type.length() > max_array_size {
                return true;
            }
            // If the next element is an array, continue to the next depth. Otherwise, we can stop checking.
            if let PlaintextType::Array(next) = array_type.next_element_type() {
                array_type = next;
            } else {
                return false;
            }
        }
        // If we reach here, it means we've exceeded the maximum depth without finding a non-array type.
        true
    }
}

impl<N: Network> ArrayType<N> {
    /// Initializes a new multi-dimensional array type.
    /// Note that the dimensions must be specified from the outermost to the innermost.
    pub fn new(plaintext_type: PlaintextType<N>, mut dimensions: Vec<U32<N>>) -> Result<Self> {
        // Check that the number of dimensions are valid.
        ensure!(!dimensions.is_empty(), "An array must have at least one dimension");
        ensure!(dimensions.len() <= N::MAX_DATA_DEPTH, "An array can have at most {} dimensions", N::MAX_DATA_DEPTH);
        // Check that each dimension is valid.
        for length in &dimensions {
            ensure!(**length as usize >= N::MIN_ARRAY_ELEMENTS, "An array must have {} element", N::MIN_ARRAY_ELEMENTS);
            ensure!(
                **length as usize <= N::LATEST_MAX_ARRAY_ELEMENTS(),
                "An array can contain {} elements",
                N::LATEST_MAX_ARRAY_ELEMENTS()
            );
        }
        // Construct the array type.
        // Note that this `unwrap` is safe because we have already checked that the number of dimensions is greater than zero.
        let array_type = Self { element_type: Box::new(plaintext_type), length: dimensions.pop().unwrap() };
        Ok(dimensions.into_iter().rev().fold(array_type, |array_type, dimension| Self {
            element_type: Box::new(PlaintextType::Array(array_type)),
            length: dimension,
        }))
    }
}

impl<N: Network> ArrayType<N> {
    /// Returns the next element type.
    /// In the case of a one-dimensional array, this will return the element type of the array.
    /// In the case of a multi-dimensional array, this will return the element type of the **outermost** array.
    pub const fn next_element_type(&self) -> &PlaintextType<N> {
        &self.element_type
    }

    /// Returns the base element type.
    /// In the case of a one-dimensional array, this will return the element type of the array.
    /// In the case of a multi-dimensional array, this will return the element type of the **innermost** array.
    pub fn base_element_type(&self) -> &PlaintextType<N> {
        let mut element_type = self.next_element_type();
        // Note that this `while` loop must terminate because the number of dimensions of `ArrayType` is checked to be less then N::MAX_DATA_DEPTH.
        while let PlaintextType::Array(array_type) = element_type {
            element_type = array_type.next_element_type();
        }
        element_type
    }

    /// Returns `true` if the array is empty.
    pub fn is_empty(&self) -> bool {
        self.length.is_zero()
    }

    /// Returns the length of the array.
    pub const fn length(&self) -> &U32<N> {
        &self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identifier, LiteralType};
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_array_type() -> Result<()> {
        // Test literal array types.
        let array = ArrayType::<CurrentNetwork>::from_str("[field; 4u32]")?;
        assert_eq!(array, ArrayType::<CurrentNetwork>::new(PlaintextType::from_str("field")?, vec![U32::new(4)])?);
        assert_eq!(
            array.to_bytes_le()?,
            ArrayType::<CurrentNetwork>::from_bytes_le(&array.to_bytes_le()?)?.to_bytes_le()?
        );
        assert_eq!(array.next_element_type(), &PlaintextType::Literal(LiteralType::Field));
        assert_eq!(array.length(), &U32::new(4));
        assert!(!array.is_empty());

        // Test struct array types.
        let array = ArrayType::<CurrentNetwork>::from_str("[foo; 1u32]")?;
        assert_eq!(array, ArrayType::<CurrentNetwork>::new(PlaintextType::from_str("foo")?, vec![U32::new(1)])?);
        assert_eq!(
            array.to_bytes_le()?,
            ArrayType::<CurrentNetwork>::from_bytes_le(&array.to_bytes_le()?)?.to_bytes_le()?
        );
        assert_eq!(array.next_element_type(), &PlaintextType::Struct(Identifier::from_str("foo")?));
        assert_eq!(array.length(), &U32::new(1));
        assert!(!array.is_empty());

        // Test array type with maximum length.
        let array = ArrayType::<CurrentNetwork>::from_str("[scalar; 32u32]")?;
        assert_eq!(array, ArrayType::<CurrentNetwork>::new(PlaintextType::from_str("scalar")?, vec![U32::new(32)])?);
        assert_eq!(
            array.to_bytes_le()?,
            ArrayType::<CurrentNetwork>::from_bytes_le(&array.to_bytes_le()?)?.to_bytes_le()?
        );
        assert_eq!(array.next_element_type(), &PlaintextType::Literal(LiteralType::Scalar));
        assert_eq!(array.length(), &U32::new(32));
        assert!(!array.is_empty());

        // Test multi-dimensional array types.
        let array = ArrayType::<CurrentNetwork>::from_str("[[field; 2u32]; 3u32]")?;
        assert_eq!(
            array,
            ArrayType::<CurrentNetwork>::new(
                PlaintextType::Array(ArrayType::<CurrentNetwork>::new(PlaintextType::from_str("field")?, vec![
                    U32::new(2)
                ])?),
                vec![U32::new(3)]
            )?
        );
        assert_eq!(
            array.to_bytes_le()?,
            ArrayType::<CurrentNetwork>::from_bytes_le(&array.to_bytes_le()?)?.to_bytes_le()?
        );
        assert_eq!(array.to_string(), "[[field; 2u32]; 3u32]");
        assert_eq!(
            array.next_element_type(),
            &PlaintextType::Array(ArrayType::<CurrentNetwork>::new(PlaintextType::Literal(LiteralType::Field), vec![
                U32::new(2)
            ])?)
        );
        assert_eq!(array.length(), &U32::new(3));
        assert!(!array.is_empty());

        Ok(())
    }

    #[test]
    fn test_contains_identifier_type_increasing_depth() -> Result<()> {
        // Test a flat identifier array returns true.
        let array =
            ArrayType::<CurrentNetwork>::new(PlaintextType::Literal(LiteralType::Identifier), vec![U32::new(1)])?;
        assert!(array.contains_identifier_type()?);

        // Test a flat non-identifier array returns false.
        let array = ArrayType::<CurrentNetwork>::new(PlaintextType::Literal(LiteralType::Field), vec![U32::new(1)])?;
        assert!(!array.contains_identifier_type()?);

        // Test nested arrays of increasing depth up to MAX_DATA_DEPTH - 1.
        // Each valid depth should correctly detect (or not detect) the identifier type.
        for depth in 2..CurrentNetwork::MAX_DATA_DEPTH {
            // Build dimensions for an identifier array at the given depth.
            let dimensions = vec![U32::new(1); depth];
            let with_identifier =
                ArrayType::<CurrentNetwork>::new(PlaintextType::Literal(LiteralType::Identifier), dimensions.clone())?;
            assert!(with_identifier.contains_identifier_type()?, "depth {depth}: should contain identifier");

            // Build dimensions for a non-identifier array at the given depth.
            let without_identifier =
                ArrayType::<CurrentNetwork>::new(PlaintextType::Literal(LiteralType::Field), dimensions)?;
            assert!(!without_identifier.contains_identifier_type()?, "depth {depth}: should not contain identifier");
        }

        // Test an array at exactly MAX_DATA_DEPTH should still work.
        let dimensions = vec![U32::new(1); CurrentNetwork::MAX_DATA_DEPTH];
        let at_max = ArrayType::<CurrentNetwork>::new(PlaintextType::Literal(LiteralType::Identifier), dimensions)?;
        assert!(at_max.contains_identifier_type()?);

        // Test an array exceeding MAX_DATA_DEPTH returns an error.
        // Manually construct an array deeper than MAX_DATA_DEPTH (since `new` prevents it).
        let mut array = ArrayType::<CurrentNetwork> {
            element_type: Box::new(PlaintextType::Literal(LiteralType::Field)),
            length: U32::new(1),
        };
        for _ in 0..CurrentNetwork::MAX_DATA_DEPTH {
            array = ArrayType::<CurrentNetwork> {
                element_type: Box::new(PlaintextType::Array(array)),
                length: U32::new(1),
            };
        }
        assert!(array.contains_identifier_type().is_err());

        Ok(())
    }

    #[test]
    fn test_array_type_fails() {
        let type_ = ArrayType::<CurrentNetwork>::from_str("[field; 0u32]");
        assert!(type_.is_err());

        let type_ = ArrayType::<CurrentNetwork>::from_str("[field; 4294967296u32]");
        assert!(type_.is_err());

        let type_ = ArrayType::<CurrentNetwork>::from_str("[foo; -1i32]");
        assert!(type_.is_err());

        let type_ = ArrayType::<CurrentNetwork>::from_str("[foo; 1u8]");
        assert!(type_.is_err());
    }
}
