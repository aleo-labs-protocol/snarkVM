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
mod serialize;
mod size_in_bits;

use crate::{ArrayType, Identifier, LiteralType, Locator, ProgramID, StructType};
use snarkvm_console_network::prelude::*;

/// A `PlaintextType` defines the type parameter for a literal, struct, array, or external struct.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum PlaintextType<N: Network> {
    /// A literal type contains its type name.
    /// The format of the type is `<type_name>`.
    Literal(LiteralType),
    /// A struct type contains its identifier.
    /// The format of the type is `<identifier>`.
    Struct(Identifier<N>),
    /// An array type contains its element type and length.
    /// The format of the type is `[<element_type>; <length>]`.
    Array(ArrayType<N>),
    /// An external struct type contains its locator.
    /// The format of the type is `<program_id>/<identifier>`.
    ExternalStruct(Locator<N>),
}

impl<N: Network> PlaintextType<N> {
    /// Returns whether this type refers to an external struct.
    pub fn contains_external_struct(&self) -> bool {
        use PlaintextType::*;

        match self {
            Literal(..) | Struct(..) => false,
            ExternalStruct(..) => true,
            Array(array_type) => array_type.base_element_type().contains_external_struct(),
        }
    }

    // Make unqualified structs into external ones with the given `id`.
    pub fn qualify(self, id: ProgramID<N>) -> Self {
        match self {
            PlaintextType::ExternalStruct(..) | PlaintextType::Literal(..) => self,
            PlaintextType::Struct(name) => PlaintextType::ExternalStruct(Locator::new(id, name)),
            PlaintextType::Array(array_type) => {
                let element_type = array_type.next_element_type().clone().qualify(id);
                // Safe: the length is preserved from the original array type.
                PlaintextType::Array(ArrayType::new(element_type, vec![*array_type.length()]).unwrap())
            }
        }
    }

    /// Removes all program qualification from struct types.
    pub fn unqualify(self) -> Self {
        match self {
            // Already-unqualified or unaffected
            PlaintextType::Literal(..) | PlaintextType::Struct(..) => self,

            // Drop the program qualification unconditionally
            PlaintextType::ExternalStruct(locator) => PlaintextType::Struct(*locator.resource()),

            // Recurse into arrays
            PlaintextType::Array(array_type) => {
                let element_type = array_type.next_element_type().clone().unqualify();

                PlaintextType::Array(ArrayType::new(element_type, vec![*array_type.length()]).unwrap())
            }
        }
    }
}

impl<N: Network> From<LiteralType> for PlaintextType<N> {
    /// Initializes a plaintext type from a literal type.
    fn from(literal: LiteralType) -> Self {
        PlaintextType::Literal(literal)
    }
}

impl<N: Network> From<Identifier<N>> for PlaintextType<N> {
    /// Initializes a plaintext type from a struct type.
    fn from(struct_: Identifier<N>) -> Self {
        PlaintextType::Struct(struct_)
    }
}

impl<N: Network> From<Locator<N>> for PlaintextType<N> {
    /// Initializes a plaintext type from an external struct type.
    fn from(locator: Locator<N>) -> Self {
        PlaintextType::ExternalStruct(locator)
    }
}

impl<N: Network> From<ArrayType<N>> for PlaintextType<N> {
    /// Initializes a plaintext type from an array type.
    fn from(array: ArrayType<N>) -> Self {
        PlaintextType::Array(array)
    }
}

impl<N: Network> PlaintextType<N> {
    // Prefix bits for (de)serializing the `Array` variant.
    pub const ARRAY_PREFIX_BITS: [bool; 2] = [true, false];
    /// Prefix bits for (de)serializing the `Literal` variant.
    pub const LITERAL_PREFIX_BITS: [bool; 2] = [false, false];
    /// Prefix bits for (de)serializing the `Struct` variant.
    pub const STRUCT_PREFIX_BITS: [bool; 2] = [false, true];

    /// Returns `true` if the `PlaintextType` contains a string type.
    pub fn contains_string_type(&self) -> bool {
        match self {
            Self::Literal(LiteralType::String) => true,
            Self::Array(array_type) => array_type.contains_string_type(),
            _ => false, // Structs are checked in their definition.
        }
    }

    /// Returns `true` if the `PlaintextType` contains an identifier type.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        match self {
            Self::Literal(LiteralType::Identifier) => Ok(true),
            Self::Literal(_) => Ok(false),
            Self::Array(array_type) => array_type.contains_identifier_type(),
            // Structs are checked in their definition.
            Self::Struct(_) | Self::ExternalStruct(_) => Ok(false),
        }
    }

    /// Returns `true` if the `PlaintextType` is an array and the size exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        match self {
            Self::Literal(_) | Self::Struct(_) | Self::ExternalStruct(_) => false,
            Self::Array(array_type) => array_type.exceeds_max_array_size(max_array_size),
        }
    }
}

#[test]
fn unqualify_behavior() {
    use crate::U32;
    type N = TestnetV0;

    let program = ProgramID::<N>::from_str("foo.aleo").unwrap();
    let foo = Identifier::<N>::from_str("Foo").unwrap();
    let bar = Identifier::<N>::from_str("Bar").unwrap();

    //
    // 1. Literal is unchanged
    //
    let lit = PlaintextType::<N>::Literal(LiteralType::U32);
    assert_eq!(lit.clone().unqualify(), lit);

    //
    // 2. Struct is unchanged
    //
    let s = PlaintextType::<N>::Struct(foo);
    assert_eq!(s.clone().unqualify(), s);

    //
    // 3. ExternalStruct becomes Struct
    //
    let ext = PlaintextType::<N>::ExternalStruct(Locator::new(program, bar));
    assert_eq!(ext.unqualify(), PlaintextType::Struct(bar));

    //
    // 4. Array of ExternalStruct is unqualified recursively
    //
    let ext = PlaintextType::<N>::ExternalStruct(Locator::new(program, bar));
    let arr = PlaintextType::Array(ArrayType::new(ext, vec![U32::new(3)]).unwrap());

    let expected = PlaintextType::Array(ArrayType::new(PlaintextType::Struct(bar), vec![U32::new(3)]).unwrap());

    assert_eq!(arr.unqualify(), expected);

    //
    // 5. Nested arrays recurse fully
    //
    let ext = PlaintextType::<N>::ExternalStruct(Locator::new(program, bar));
    let inner = PlaintextType::Array(ArrayType::new(ext, vec![U32::new(2)]).unwrap());
    let outer = PlaintextType::Array(ArrayType::new(inner, vec![U32::new(4)]).unwrap());

    let expected_inner = PlaintextType::Array(ArrayType::new(PlaintextType::Struct(bar), vec![U32::new(2)]).unwrap());
    let expected_outer = PlaintextType::Array(ArrayType::new(expected_inner, vec![U32::new(4)]).unwrap());

    assert_eq!(outer.unqualify(), expected_outer);

    //
    // 6. Idempotency
    //
    let once = expected_outer.clone().unqualify();
    let twice = once.clone().unqualify();
    assert_eq!(once, twice);
}
