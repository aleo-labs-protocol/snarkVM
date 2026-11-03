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

impl<N: Network> FromBytes for Future<N> {
    /// Reads in a future from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the future.
        Self::read_le_internal(&mut reader, 0)
    }
}

impl<N: Network> Future<N> {
    /// Reads in a future from a buffer, while tracking the depth of the data.
    fn read_le_internal<R: Read>(mut reader: R, depth: usize) -> IoResult<Self> {
        // Ensure that the depth is within the maximum limit.
        // Note: `N::MAX_DATA_DEPTH` is an upper bound on the number of nested futures.
        //  The true maximum is defined by `Transaction::<N>::MAX_TRANSITIONS`, however, that object is not accessible in this crate.
        //  In practice, `MAX_DATA_DEPTH` is 32, while `MAX_TRANSITIONS` is 31.
        if depth > N::MAX_DATA_DEPTH {
            return Err(error(format!(
                "Failed to deserialize plaintext: Depth exceeds maximum limit: {}",
                N::MAX_DATA_DEPTH
            )));
        }
        // Read the program ID.
        let program_id = ProgramID::read_le(&mut reader)?;
        // Read the function name.
        let function_name = Identifier::<N>::read_le(&mut reader)?;
        // Read the number of arguments to the future.
        let num_arguments = u8::read_le(&mut reader)? as usize;
        if num_arguments > N::MAX_INPUTS {
            return Err(error("Failed to read future: too many arguments"));
        };
        // Read the arguments.
        let mut arguments = Vec::with_capacity(num_arguments);
        for _ in 0..num_arguments {
            // Read the argument (in 2 steps to prevent infinite recursion).
            let num_bytes = u16::read_le(&mut reader)?;
            // Read the argument bytes.
            let mut bytes = Vec::new();
            (&mut reader).take(num_bytes as u64).read_to_end(&mut bytes)?;
            // Ensure the declared region is entirely present.
            if bytes.len() != num_bytes as usize {
                return Err(error("Failed to read future: argument is truncated"));
            }
            // Recover the argument.
            let mut slice = bytes.as_slice();
            let entry = Argument::read_le_internal(&mut slice, depth)?;
            // Ensure the argument fills its region. Bytes left unread would be dropped
            // on re-serialization, giving one value a second encoding.
            if !slice.is_empty() {
                return Err(error("Failed to read future: argument has trailing bytes"));
            }
            // Add the argument.
            arguments.push(entry);
        }
        // Return the future.
        Ok(Self::new(program_id, function_name, arguments))
    }
}

impl<N: Network> ToBytes for Future<N> {
    /// Writes a future to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the program ID.
        self.program_id.write_le(&mut writer)?;
        // Write the function name.
        self.function_name.write_le(&mut writer)?;
        // Write the number of arguments.
        if self.arguments.len() > N::MAX_INPUTS {
            return Err(error("Failed to write future: too many arguments"));
        };
        u8::try_from(self.arguments.len()).map_err(error)?.write_le(&mut writer)?;
        // Write each argument.
        for argument in &self.arguments {
            // Write the argument (performed in 2 steps to prevent infinite recursion).
            let bytes = argument.to_bytes_le().map_err(error)?;
            // Write the number of bytes.
            u16::try_from(bytes.len()).map_err(error)?.write_le(&mut writer)?;
            // Write the bytes.
            bytes.write_le(&mut writer)?;
        }
        Ok(())
    }
}

impl<N: Network> Argument<N> {
    fn read_le_internal<R: Read>(mut reader: R, depth: usize) -> IoResult<Self>
    where
        Self: Sized,
    {
        // Read the index.
        let index = u8::read_le(&mut reader)?;
        // Read the argument.
        let argument = match index {
            0 => Self::Plaintext(Plaintext::read_le(&mut reader)?),
            1 => Self::Future(Future::read_le_internal(&mut reader, depth + 1)?),
            2 => Self::DynamicFuture(DynamicFuture::read_le(&mut reader)?),
            3.. => return Err(error(format!("Failed to decode future argument {index}"))),
        };
        Ok(argument)
    }
}

impl<N: Network> ToBytes for Argument<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Plaintext(plaintext) => {
                0u8.write_le(&mut writer)?;
                plaintext.write_le(&mut writer)
            }
            Self::Future(future) => {
                1u8.write_le(&mut writer)?;
                future.write_le(&mut writer)
            }
            Self::DynamicFuture(dynamic_future) => {
                2u8.write_le(&mut writer)?;
                dynamic_future.write_le(&mut writer)
            }
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
    fn test_bytes() {
        // Check the future manually.
        let expected =
            Future::<CurrentNetwork>::from_str("{ program_id: credits.aleo, function_name: transfer, arguments: [] }")
                .unwrap();

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        assert_eq!(expected, Future::read_le(&expected_bytes[..]).unwrap());
    }

    #[test]
    fn test_bytes_with_plaintext_arguments() {
        // Create a future with plaintext arguments.
        let expected = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![
                Argument::Plaintext(Plaintext::from_str("100u64").unwrap()),
                Argument::Plaintext(Plaintext::from_str("true").unwrap()),
            ],
        );

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = Future::read_le(&expected_bytes[..]).unwrap();
        assert_eq!(expected, candidate);
    }

    #[test]
    fn test_bytes_with_dynamic_future_argument() {
        // Create an inner future.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("42u64").unwrap())],
        );

        // Convert to dynamic future.
        let dynamic_inner = DynamicFuture::from_future(&inner).unwrap();

        // Create a future with a dynamic future argument.
        let expected = Future::<CurrentNetwork>::new(
            ProgramID::from_str("outer.aleo").unwrap(),
            Identifier::from_str("baz").unwrap(),
            vec![Argument::DynamicFuture(dynamic_inner)],
        );

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = Future::read_le(&expected_bytes[..]).unwrap();

        // Verify the structure matches.
        assert_eq!(expected.program_id(), candidate.program_id());
        assert_eq!(expected.function_name(), candidate.function_name());
        assert_eq!(expected.arguments().len(), candidate.arguments().len());

        // Verify the dynamic future argument.
        match (&expected.arguments()[0], &candidate.arguments()[0]) {
            (Argument::DynamicFuture(e), Argument::DynamicFuture(c)) => {
                assert_eq!(e.program_name(), c.program_name());
                assert_eq!(e.program_network(), c.program_network());
                assert_eq!(e.function_name(), c.function_name());
                assert_eq!(e.checksum(), c.checksum());
            }
            _ => panic!("Expected DynamicFuture argument"),
        }
    }

    #[test]
    fn test_bytes_with_nested_future_argument() {
        // Create an inner future.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("42u64").unwrap())],
        );

        // Create a future with a nested future argument.
        let expected = Future::<CurrentNetwork>::new(
            ProgramID::from_str("outer.aleo").unwrap(),
            Identifier::from_str("baz").unwrap(),
            vec![Argument::Future(inner)],
        );

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = Future::read_le(&expected_bytes[..]).unwrap();
        assert_eq!(expected, candidate);
    }

    #[test]
    fn test_bytes_with_mixed_arguments() {
        // Create an inner future.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![],
        );

        // Convert to dynamic future.
        let dynamic_inner = DynamicFuture::from_future(&inner).unwrap();

        // Create a future with mixed arguments.
        let expected = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("mixed").unwrap(),
            vec![
                Argument::Plaintext(Plaintext::from_str("100u64").unwrap()),
                Argument::Future(inner),
                Argument::DynamicFuture(dynamic_inner),
            ],
        );

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = Future::read_le(&expected_bytes[..]).unwrap();

        // Verify structure.
        assert_eq!(expected.program_id(), candidate.program_id());
        assert_eq!(expected.function_name(), candidate.function_name());
        assert_eq!(expected.arguments().len(), candidate.arguments().len());
    }

    // A helper function to get the depth of a future.
    fn get_depth<N: Network>(future: &Future<N>) -> usize {
        // Count the number of nested futures.
        future
            .arguments
            .iter()
            .map(|arg| match arg {
                Argument::Plaintext(_) => 0,
                Argument::Future(future) => 1 + get_depth(future),
                Argument::DynamicFuture(_) => panic!("Dynamic futures are not used in this test"),
            })
            .sum()
    }

    #[test]
    fn test_deeply_nested_future() {
        // Creates a nested `Future`.
        // This method is iterative to avoid stack overflows.
        fn create_nested_future(depth: usize) -> Vec<u8> {
            // Start from the innermost value.
            let mut result = Future::<CurrentNetwork>::from_str(
                r"{
                program_id: foo.aleo,
                function_name: bar,
                arguments: []
            }",
            )
            .unwrap()
            .to_bytes_le()
            .unwrap();
            // Reverse the bytes.
            result.reverse();
            // Build up the structure in reverse.
            for _ in 0..depth {
                // Write the variant of the argument in reverse.
                let mut variant = 1u8.to_bytes_le().unwrap();
                variant.reverse();
                result.extend(variant);
                // Write the size of the object in bytes in reverse.
                let mut length = (u16::try_from(result.len()).unwrap()).to_bytes_le().unwrap();
                length.reverse();
                result.extend(length);
                // Write the number of arguments in reverse.
                let mut num_elements = 1u8.to_bytes_le().unwrap();
                num_elements.reverse();
                result.extend(num_elements);
                // Write the function name in reverse.
                let mut function_name = Identifier::<CurrentNetwork>::from_str("bar").unwrap().to_bytes_le().unwrap();
                function_name.reverse();
                result.extend(function_name);
                // Write the program ID in reverse.
                let mut program_id = ProgramID::<CurrentNetwork>::from_str("foo.aleo").unwrap().to_bytes_le().unwrap();
                program_id.reverse();
                result.extend(program_id);
            }
            // Reverse the result to get the correct order.
            result.reverse();
            result
        }

        // A helper function to run the test.
        fn run_test(expected_depth: usize, input: Vec<u8>, expected_error: bool) {
            // Parse the input string.
            let result = Future::<CurrentNetwork>::read_le(&*input);
            // // Check if the result is an error.
            match expected_error {
                true => {
                    assert!(result.is_err());
                    return;
                }
                false => assert!(result.is_ok()),
            };
            // Unwrap the result.
            let candidate = result.unwrap();
            // Check if the candidate is equal to the input, with whitespace removed.
            assert_eq!(input, candidate.to_bytes_le().unwrap());
            // Check if the candidate is equal to the expected depth.
            assert_eq!(get_depth(&candidate), expected_depth);
        }

        // Initialize a sequence of depths to check.
        // Note: It is not possible to create a `Future` of depth 4000 in this test as it's size would exceed `u16::MAX`.
        let mut depths = (0usize..100).collect_vec();
        depths.extend((100..3900).step_by(100));

        // Test deeply nested arrays with different literal types.
        for i in depths.iter().copied() {
            run_test(i, create_nested_future(i), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_future(i), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_future(i), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_future(i), i > CurrentNetwork::MAX_DATA_DEPTH);
        }
    }

    /// Builds the encoding of a one-argument future, declaring `padding` more bytes
    /// for the argument than the argument actually occupies.
    fn future_with_padded_argument(padding: usize) -> Result<Vec<u8>> {
        let argument = Argument::<CurrentNetwork>::Plaintext(Plaintext::from_str("7u8")?);
        let argument_bytes = argument.to_bytes_le()?;

        let mut bytes = Vec::new();
        ProgramID::<CurrentNetwork>::from_str("credits.aleo")?.write_le(&mut bytes)?;
        Identifier::<CurrentNetwork>::from_str("transfer")?.write_le(&mut bytes)?;
        1u8.write_le(&mut bytes)?;
        u16::try_from(argument_bytes.len() + padding)?.write_le(&mut bytes)?;
        bytes.extend_from_slice(&argument_bytes);
        bytes.extend(std::iter::repeat_n(0u8, padding));
        Ok(bytes)
    }

    #[test]
    fn test_future_argument_rejects_trailing_bytes() -> Result<()> {
        // Unpadded, this is the encoding `to_bytes_le` produces, and it must keep working.
        let exact = future_with_padded_argument(0)?;
        let future = Future::<CurrentNetwork>::read_le(&exact[..])?;
        assert_eq!(exact, future.to_bytes_le()?, "the unpadded encoding must round trip");

        // An argument region larger than the argument fills leaves bytes unread.
        // Accepting it gives one future -- and so one transaction -- a second
        // encoding, since re-serializing emits the exact length.
        for padding in [1, 8, 32] {
            let padded = future_with_padded_argument(padding)?;
            assert_ne!(padded, exact);
            assert!(
                Future::<CurrentNetwork>::read_le(&padded[..]).is_err(),
                "a future argument declaring {padding} bytes more than it uses must be rejected"
            );
        }
        Ok(())
    }
}
