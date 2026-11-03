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

impl<N: Network> Future<N> {
    /// Returns a value from the given path.
    pub fn find<A: Into<Access<N>> + Copy + Debug>(&self, path: &[A]) -> Result<Value<N>> {
        // Ensure the path is not empty.
        ensure!(!path.is_empty(), "Attempted to find an argument with an empty path.");

        // A helper enum to track the argument.
        enum ArgumentRefType<'a, N: Network> {
            /// A plaintext type.
            Plaintext(&'a Plaintext<N>),
            /// A future.
            Future(&'a Future<N>),
            /// A dynamic future.
            DynamicFuture(&'a DynamicFuture<N>),
        }

        // Initialize a value starting from the top-level.
        let mut value = ArgumentRefType::Future(self);

        // Iterate through the path to retrieve the value.
        for access in path.iter() {
            let access = (*access).into();
            match (value, access) {
                (ArgumentRefType::Plaintext(Plaintext::Struct(members, ..)), Access::Member(identifier)) => {
                    match members.get(&identifier) {
                        // Retrieve the member and update `value` for the next iteration.
                        Some(member) => value = ArgumentRefType::Plaintext(member),
                        // Halts if the member does not exist.
                        None => bail!("Failed to locate member '{identifier}'"),
                    }
                }
                (ArgumentRefType::Plaintext(Plaintext::Array(array, ..)), Access::Index(index)) => {
                    match array.get(*index as usize) {
                        // Retrieve the element and update `value` for the next iteration.
                        Some(element) => value = ArgumentRefType::Plaintext(element),
                        // Halts if the index is out of bounds.
                        None => bail!("Index '{index}' is out of bounds"),
                    }
                }
                (ArgumentRefType::Future(future), Access::Index(index)) => {
                    match future.arguments.get(*index as usize) {
                        // If the argument is a future, update `value` for the next iteration.
                        Some(Argument::Future(future)) => value = ArgumentRefType::Future(future),
                        // If the argument is a plaintext, update `value` for the next iteration.
                        Some(Argument::Plaintext(plaintext)) => value = ArgumentRefType::Plaintext(plaintext),
                        // If the argument is a dynamic future, update `value` for the next iteration.
                        Some(Argument::DynamicFuture(dynamic_future)) => {
                            value = ArgumentRefType::DynamicFuture(dynamic_future)
                        }
                        // Halts if the index is out of bounds.
                        None => bail!("Index '{index}' is out of bounds"),
                    }
                }
                _ => bail!("Invalid access `{access}`"),
            }
        }

        match value {
            ArgumentRefType::Plaintext(plaintext) => Ok(Value::Plaintext(plaintext.clone())),
            ArgumentRefType::Future(future) => Ok(Value::Future(future.clone())),
            ArgumentRefType::DynamicFuture(dynamic_future) => Ok(Value::DynamicFuture(dynamic_future.clone())),
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
    fn test_find_plaintext_argument() {
        // Create a future with plaintext arguments.
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![
                Argument::Plaintext(Plaintext::from_str("100u64").unwrap()),
                Argument::Plaintext(Plaintext::from_str("200u64").unwrap()),
            ],
        );

        // Access the first argument.
        let value = future.find(&[Access::Index(U32::new(0))]).unwrap();
        assert_eq!(value, Value::Plaintext(Plaintext::from_str("100u64").unwrap()));

        // Access the second argument.
        let value = future.find(&[Access::Index(U32::new(1))]).unwrap();
        assert_eq!(value, Value::Plaintext(Plaintext::from_str("200u64").unwrap()));
    }

    #[test]
    fn test_find_nested_future_argument() {
        // Create an inner future.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("42u64").unwrap())],
        );

        // Create an outer future with the inner future as an argument.
        let outer = Future::<CurrentNetwork>::new(
            ProgramID::from_str("outer.aleo").unwrap(),
            Identifier::from_str("baz").unwrap(),
            vec![Argument::Future(inner.clone())],
        );

        // Access the nested future.
        let value = outer.find(&[Access::Index(U32::new(0))]).unwrap();
        assert_eq!(value, Value::Future(inner));
    }

    #[test]
    fn test_find_dynamic_future_argument() {
        // Create an inner future and convert to dynamic.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("42u64").unwrap())],
        );
        let dynamic_inner = DynamicFuture::from_future(&inner).unwrap();

        // Create an outer future with the dynamic future as an argument.
        let outer = Future::<CurrentNetwork>::new(
            ProgramID::from_str("outer.aleo").unwrap(),
            Identifier::from_str("baz").unwrap(),
            vec![Argument::DynamicFuture(dynamic_inner.clone())],
        );

        // Access the dynamic future argument.
        let value = outer.find(&[Access::Index(U32::new(0))]).unwrap();

        // Verify the result is a dynamic future with matching fields.
        match value {
            Value::DynamicFuture(result) => {
                assert_eq!(result.program_name(), dynamic_inner.program_name());
                assert_eq!(result.program_network(), dynamic_inner.program_network());
                assert_eq!(result.function_name(), dynamic_inner.function_name());
                assert_eq!(result.checksum(), dynamic_inner.checksum());
            }
            _ => panic!("Expected DynamicFuture value"),
        }
    }

    #[test]
    fn test_find_mixed_arguments() {
        // Create an inner future and dynamic future.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![],
        );
        let dynamic_inner = DynamicFuture::from_future(&inner).unwrap();

        // Create a future with mixed argument types.
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("mixed").unwrap(),
            vec![
                Argument::Plaintext(Plaintext::from_str("100u64").unwrap()),
                Argument::Future(inner.clone()),
                Argument::DynamicFuture(dynamic_inner.clone()),
            ],
        );

        // Access plaintext argument.
        let value = future.find(&[Access::Index(U32::new(0))]).unwrap();
        assert!(matches!(value, Value::Plaintext(_)));

        // Access future argument.
        let value = future.find(&[Access::Index(U32::new(1))]).unwrap();
        assert!(matches!(value, Value::Future(_)));

        // Access dynamic future argument.
        let value = future.find(&[Access::Index(U32::new(2))]).unwrap();
        assert!(matches!(value, Value::DynamicFuture(_)));
    }

    #[test]
    fn test_find_out_of_bounds() {
        // Create a future with one argument.
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
        );

        // Try to access an out-of-bounds index.
        let result = future.find(&[Access::Index(U32::new(5))]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dynamic_future_fields_cannot_be_accessed() {
        // Create a future with a plaintext argument and convert to dynamic.
        let inner = Future::<CurrentNetwork>::new(
            ProgramID::from_str("inner.aleo").unwrap(),
            Identifier::from_str("bar").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("42u64").unwrap())],
        );
        let dynamic_inner = DynamicFuture::from_future(&inner).unwrap();

        // Create an outer future with the dynamic future as an argument.
        let outer = Future::<CurrentNetwork>::new(
            ProgramID::from_str("outer.aleo").unwrap(),
            Identifier::from_str("baz").unwrap(),
            vec![Argument::DynamicFuture(dynamic_inner)],
        );

        // Accessing the dynamic future itself should succeed.
        let value = outer.find(&[Access::Index(U32::new(0))]).unwrap();
        assert!(matches!(value, Value::DynamicFuture(_)));

        // Attempting to access fields within the dynamic future should fail.
        // Dynamic futures are opaque and do not expose their internal structure.
        let result = outer.find(&[Access::Index(U32::new(0)), Access::Index(U32::new(0))]);
        assert!(result.is_err());
    }
}
