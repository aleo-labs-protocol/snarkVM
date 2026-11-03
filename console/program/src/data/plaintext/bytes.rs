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

impl<N: Network> FromBytes for Plaintext<N> {
    /// Reads the plaintext from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Self::read_le_internal(&mut reader, 0)
    }
}

impl<N: Network> Plaintext<N> {
    /// Reads the plaintext from a buffer, while tracking the depth of the data.
    fn read_le_internal<R: Read>(mut reader: R, depth: usize) -> IoResult<Self> {
        // Ensure that the depth is within the maximum limit.
        if depth > N::MAX_DATA_DEPTH {
            return Err(error(format!(
                "Failed to deserialize plaintext: Depth exceeds maximum limit: {}",
                N::MAX_DATA_DEPTH
            )));
        }
        // Read the index.
        let index = u8::read_le(&mut reader)?;
        // Read the plaintext.
        let plaintext = match index {
            0 => Self::Literal(Literal::read_le(&mut reader)?, Default::default()),
            1 => {
                // Read the number of members in the struct.
                let num_members = u8::read_le(&mut reader)?;
                // Read the members.
                let mut members = IndexMap::with_capacity(num_members as usize);
                for _ in 0..num_members {
                    // Read the identifier.
                    let identifier = Identifier::<N>::read_le(&mut reader)?;
                    // Read the plaintext value (in 2 steps to prevent infinite recursion).
                    let num_bytes = u16::read_le(&mut reader)?;
                    // Read the plaintext bytes.
                    let mut bytes = Vec::new();
                    (&mut reader).take(num_bytes as u64).read_to_end(&mut bytes)?;
                    // Ensure the declared region is entirely present.
                    if bytes.len() != num_bytes as usize {
                        return Err(error("Failed to deserialize plaintext: struct member is truncated"));
                    }
                    // Recover the plaintext value.
                    let mut slice = bytes.as_slice();
                    let plaintext = Self::read_le_internal(&mut slice, depth + 1)?;
                    // Ensure the member fills its region. Bytes left unread would be
                    // dropped on re-serialization, giving one value a second encoding.
                    if !slice.is_empty() {
                        return Err(error("Failed to deserialize plaintext: struct member has trailing bytes"));
                    }
                    // Add the member.
                    members.insert(identifier, plaintext);
                }
                // Return the struct.
                Self::Struct(members, Default::default())
            }
            2 => {
                // Read the length of the array.
                let num_elements = u32::read_le(&mut reader)?;
                if num_elements as usize > N::LATEST_MAX_ARRAY_ELEMENTS() {
                    return Err(error("Failed to deserialize plaintext: Array exceeds maximum length"));
                }
                // Read the elements.
                let mut elements = Vec::with_capacity(num_elements as usize);
                for _ in 0..num_elements {
                    // Read the plaintext value (in 2 steps to prevent infinite recursion).
                    let num_bytes = u16::read_le(&mut reader)?;
                    // Read the plaintext bytes.
                    let mut bytes = Vec::new();
                    (&mut reader).take(num_bytes as u64).read_to_end(&mut bytes)?;
                    // Ensure the declared region is entirely present.
                    if bytes.len() != num_bytes as usize {
                        return Err(error("Failed to deserialize plaintext: array element is truncated"));
                    }
                    // Recover the plaintext value.
                    let mut slice = bytes.as_slice();
                    let plaintext = Self::read_le_internal(&mut slice, depth + 1)?;
                    // Ensure the element fills its region. Bytes left unread would be
                    // dropped on re-serialization, giving one value a second encoding.
                    if !slice.is_empty() {
                        return Err(error("Failed to deserialize plaintext: array element has trailing bytes"));
                    }
                    // Add the element.
                    elements.push(plaintext);
                }
                // Return the array.
                Self::Array(elements, Default::default())
            }
            3.. => return Err(error(format!("Failed to decode plaintext variant {index}"))),
        };
        Ok(plaintext)
    }
}

impl<N: Network> ToBytes for Plaintext<N> {
    /// Writes the plaintext to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Literal(literal, ..) => {
                0u8.write_le(&mut writer)?;
                literal.write_le(&mut writer)
            }
            Self::Struct(struct_, ..) => {
                1u8.write_le(&mut writer)?;

                // Write the number of members in the struct.
                u8::try_from(struct_.len()).map_err(error)?.write_le(&mut writer)?;

                // Write each member.
                for (member_name, member_value) in struct_ {
                    // Write the member name.
                    member_name.write_le(&mut writer)?;

                    // Write the member value (performed in 2 steps to prevent infinite recursion).
                    let bytes = member_value.to_bytes_le().map_err(|e| error(e.to_string()))?;
                    // Write the number of bytes.
                    u16::try_from(bytes.len()).map_err(error)?.write_le(&mut writer)?;
                    // Write the bytes.
                    bytes.write_le(&mut writer)?;
                }
                Ok(())
            }
            Self::Array(array, ..) => {
                2u8.write_le(&mut writer)?;

                // Write the length of the array.
                u32::try_from(array.len()).map_err(error)?.write_le(&mut writer)?;

                // Write each element.
                for element in array {
                    // Write the element (performed in 2 steps to prevent infinite recursion).
                    let bytes = element.to_bytes_le().map_err(error)?;
                    // Write the number of bytes.
                    u16::try_from(bytes.len()).map_err(error)?.write_le(&mut writer)?;
                    // Write the bytes.
                    bytes.write_le(&mut writer)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u32 = 1000;

    fn check_bytes(expected: Plaintext<CurrentNetwork>) -> Result<()> {
        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le()?;
        assert_eq!(expected, Plaintext::read_le(&expected_bytes[..])?);
        Ok(())
    }

    #[test]
    fn test_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let private_key = snarkvm_console_account::PrivateKey::<CurrentNetwork>::new(rng)?;

            // Address
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::Address(Address::try_from(private_key)?),
                Default::default(),
            ))?;
            // Boolean
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::Boolean(Boolean::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // Field
            check_bytes(Plaintext::Literal(Literal::<CurrentNetwork>::Field(Uniform::rand(rng)), Default::default()))?;
            // Group
            check_bytes(Plaintext::Literal(Literal::<CurrentNetwork>::Group(Uniform::rand(rng)), Default::default()))?;
            // I8
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::I8(I8::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // I16
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::I16(I16::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // I32
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::I32(I32::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // I64
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::I64(I64::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // I128
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::I128(I128::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // U8
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::U8(U8::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // U16
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::U16(U16::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // U32
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::U32(U32::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // U64
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::U64(U64::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // U128
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::U128(U128::new(Uniform::rand(rng))),
                Default::default(),
            ))?;
            // Scalar
            check_bytes(Plaintext::Literal(Literal::<CurrentNetwork>::Scalar(Uniform::rand(rng)), Default::default()))?;
            // String
            check_bytes(Plaintext::Literal(
                Literal::<CurrentNetwork>::String(StringType::rand(rng)),
                Default::default(),
            ))?;
        }

        // Check the struct manually.
        let expected = Plaintext::<CurrentNetwork>::from_str(
            "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah, token_amount: 100u64 }",
        )?;

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le()?;
        assert_eq!(expected, Plaintext::read_le(&expected_bytes[..])?);

        // Check the array manually.
        let expected = Plaintext::<CurrentNetwork>::from_str("[ 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8 ]")?;

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le()?;
        assert_eq!(expected, Plaintext::read_le(&expected_bytes[..])?);

        Ok(())
    }

    // A helper function to get the depth of the plaintext.
    fn get_depth(plaintext: &Plaintext<CurrentNetwork>) -> usize {
        match plaintext {
            Plaintext::Literal(_, _) => 0,
            Plaintext::Struct(members, _) => members.values().map(get_depth).max().unwrap_or(0) + 1,
            Plaintext::Array(elements, _) => elements.iter().map(get_depth).max().unwrap_or(0) + 1,
        }
    }

    #[test]
    fn test_deeply_nested_plaintext() {
        // Creates a nested array-like `Plaintext` structure by wrapping a root value `depth` times.
        fn create_nested_array(depth: usize, root: impl Display) -> Vec<u8> {
            // Start from the innermost value.
            let mut result = Plaintext::<CurrentNetwork>::from_str(&root.to_string()).unwrap().to_bytes_le().unwrap();
            // Reverse the bytes.
            result.reverse();
            // Build up the structure in reverse.
            for _ in 0..depth {
                // Write the size of the object in bytes in reverse.
                let mut length = (u16::try_from(result.len()).unwrap()).to_bytes_le().unwrap();
                length.reverse();
                result.extend(length);
                // Write the number of elements in the array in reverse.
                let mut num_elements = 1u32.to_bytes_le().unwrap();
                num_elements.reverse();
                result.extend(num_elements);
                // Write the plaintext variant in reverse.
                let mut variant = 2u8.to_bytes_le().unwrap();
                variant.reverse();
                result.extend(variant);
            }
            // Reverse the result to get the correct order.
            result.reverse();
            result
        }

        // Creates a nested struct-like `Plaintext` structure by wrapping a root value `depth` times.
        fn create_nested_struct(depth: usize, root: impl Display) -> Vec<u8> {
            // Start from the innermost value.
            let mut result = Plaintext::<CurrentNetwork>::from_str(&root.to_string()).unwrap().to_bytes_le().unwrap();
            // Reverse the bytes.
            result.reverse();
            // Build up the structure in reverse.
            for _ in 0..depth {
                // Write the size of the object in bytes in reverse.
                let mut length = (u16::try_from(result.len()).unwrap()).to_bytes_le().unwrap();
                length.reverse();
                result.extend(length);
                // Write the member name in reverse.
                let mut member_name = Identifier::<CurrentNetwork>::from_str("inner").unwrap().to_bytes_le().unwrap();
                member_name.reverse();
                result.extend(member_name);
                // Write the number of members in the struct in reverse.
                let mut num_members = 1u8.to_bytes_le().unwrap();
                num_members.reverse();
                result.extend(num_members);
                // Write the plaintext variant in reverse.
                let mut variant = 1u8.to_bytes_le().unwrap();
                variant.reverse();
                result.extend(variant);
            }
            // Reverse the result to get the correct order.
            result.reverse();
            result
        }

        // Creates a nested `Plaintext` structure with alternating array and struct wrappers.
        fn create_alternated_nested(depth: usize, root: impl Display) -> Vec<u8> {
            // Start from the innermost value.
            let mut result = Plaintext::<CurrentNetwork>::from_str(&root.to_string()).unwrap().to_bytes_le().unwrap();
            // Reverse the bytes.
            result.reverse();
            // Build up the structure in reverse.
            for i in 0..depth {
                // Write the size of the object in bytes in reverse.
                let mut length = (u16::try_from(result.len()).unwrap()).to_bytes_le().unwrap();
                length.reverse();
                result.extend(length);
                // Determine the type of the wrapper (array or struct) and handle accordingly.
                if i % 2 == 0 {
                    // Write the number of elements in the array in reverse.
                    let mut num_elements = 1u32.to_bytes_le().unwrap();
                    num_elements.reverse();
                    result.extend(num_elements);
                    // Write the plaintext variant for array in reverse.
                    let mut variant = 2u8.to_bytes_le().unwrap();
                    variant.reverse();
                    result.extend(variant);
                } else {
                    // Write the member name in reverse.
                    let mut member_name =
                        Identifier::<CurrentNetwork>::from_str("inner").unwrap().to_bytes_le().unwrap();
                    member_name.reverse();
                    result.extend(member_name);
                    // Write the number of members in the struct in reverse.
                    let mut num_members = 1u8.to_bytes_le().unwrap();
                    num_members.reverse();
                    result.extend(num_members);
                    // Write the plaintext variant for struct in reverse.
                    let mut variant = 1u8.to_bytes_le().unwrap();
                    variant.reverse();
                    result.extend(variant);
                }
            }
            // Reverse the result to get the correct order.
            result.reverse();
            result
        }

        // A helper function to run the test.
        fn run_test(expected_depth: usize, input: Vec<u8>, expected_error: bool) {
            // Parse the input string.
            let result = Plaintext::<CurrentNetwork>::read_le(&*input);
            // Check if the result is an error.
            match expected_error {
                true => {
                    assert!(result.is_err());
                    return;
                }
                false => assert!(result.is_ok()),
            };
            // Unwrap the result.
            let candidate = result.unwrap();
            // Check if the candidate is equal to the input.
            assert_eq!(input, candidate.to_bytes_le().unwrap());
            // Check if the candidate is equal to the expected depth.
            assert_eq!(get_depth(&candidate), expected_depth);
        }

        // Initialize a sequence of depths to check.
        // Note that 6500 is approximate maximum depth that can be constructed in this test.
        let mut depths = (0usize..100).collect_vec();
        depths.extend((100..6500).step_by(100));

        // Test deeply nested arrays with different literal types.
        for i in depths.iter().copied() {
            run_test(i, create_nested_array(i, "false"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_array(i, "1u8"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_array(i, "0u128"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_array(i, "10field"), i > CurrentNetwork::MAX_DATA_DEPTH);
        }

        // Test deeply nested structs with different literal types.
        for i in depths.iter().copied() {
            run_test(i, create_nested_struct(i, "false"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_struct(i, "1u8"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_struct(i, "0u128"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_struct(i, "10field"), i > CurrentNetwork::MAX_DATA_DEPTH);
        }

        // Test alternating nested arrays and structs.
        for i in depths.iter().copied() {
            run_test(i, create_alternated_nested(i, "false"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_alternated_nested(i, "1u8"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_alternated_nested(i, "0u128"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_alternated_nested(i, "10field"), i > CurrentNetwork::MAX_DATA_DEPTH);
        }
    }

    /// Builds the encoding of a one-member struct, declaring `padding` more bytes
    /// for the member than the member actually occupies.
    fn struct_with_padded_member(padding: usize) -> Result<Vec<u8>> {
        let member = Plaintext::<CurrentNetwork>::Literal(Literal::U8(U8::new(7)), Default::default());
        let member_bytes = member.to_bytes_le()?;

        let mut bytes = Vec::new();
        1u8.write_le(&mut bytes)?;
        1u8.write_le(&mut bytes)?;
        Identifier::<CurrentNetwork>::from_str("a")?.write_le(&mut bytes)?;
        u16::try_from(member_bytes.len() + padding)?.write_le(&mut bytes)?;
        bytes.extend_from_slice(&member_bytes);
        bytes.extend(std::iter::repeat_n(0u8, padding));
        Ok(bytes)
    }

    /// Builds the encoding of a one-element array, declaring `padding` more bytes
    /// for the element than the element actually occupies.
    fn array_with_padded_element(padding: usize) -> Result<Vec<u8>> {
        let element = Plaintext::<CurrentNetwork>::Literal(Literal::U8(U8::new(7)), Default::default());
        let element_bytes = element.to_bytes_le()?;

        let mut bytes = Vec::new();
        2u8.write_le(&mut bytes)?;
        1u32.write_le(&mut bytes)?;
        u16::try_from(element_bytes.len() + padding)?.write_le(&mut bytes)?;
        bytes.extend_from_slice(&element_bytes);
        bytes.extend(std::iter::repeat_n(0u8, padding));
        Ok(bytes)
    }

    #[test]
    fn test_struct_member_rejects_trailing_bytes() -> Result<()> {
        // Unpadded, this is the encoding `to_bytes_le` produces, and it must keep working.
        let exact = struct_with_padded_member(0)?;
        let plaintext = Plaintext::<CurrentNetwork>::read_le(&exact[..])?;
        assert_eq!(exact, plaintext.to_bytes_le()?, "the unpadded encoding must round trip");

        // A member region larger than the member fills leaves bytes unread. Accepting
        // it gives one value a second encoding, since re-serializing emits the exact
        // length -- and two encodings of one transaction are two TransmissionIDs.
        for padding in [1, 8, 32] {
            let padded = struct_with_padded_member(padding)?;
            assert_ne!(padded, exact);
            assert!(
                Plaintext::<CurrentNetwork>::read_le(&padded[..]).is_err(),
                "a struct member declaring {padding} bytes more than it uses must be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn test_array_element_rejects_trailing_bytes() -> Result<()> {
        let exact = array_with_padded_element(0)?;
        let plaintext = Plaintext::<CurrentNetwork>::read_le(&exact[..])?;
        assert_eq!(exact, plaintext.to_bytes_le()?, "the unpadded encoding must round trip");

        for padding in [1, 8, 32] {
            let padded = array_with_padded_element(padding)?;
            assert_ne!(padded, exact);
            assert!(
                Plaintext::<CurrentNetwork>::read_le(&padded[..]).is_err(),
                "an array element declaring {padding} bytes more than it uses must be rejected"
            );
        }
        Ok(())
    }
}
