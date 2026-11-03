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

impl<A: Aleo> Future<A> {
    /// Returns the value from the given path.
    pub fn find<A0: Into<Access<A>> + Clone + Debug>(&self, path: &[A0]) -> Result<Value<A>> {
        // Ensure the path is not empty.
        ensure!(!path.is_empty(), "Attempted to find an argument with an empty path.");

        // A helper enum to track the the argument.
        enum ArgumentRefType<'a, A: Aleo> {
            /// A plaintext type.
            Plaintext(&'a Plaintext<A>),
            /// A future.
            Future(&'a Future<A>),
            /// A dynamic future.
            DynamicFuture(&'a DynamicFuture<A>),
        }

        // Initialize a value starting from the top-level.
        let mut value = ArgumentRefType::Future(self);

        // Iterate through the path to retrieve the value.
        for access in path.iter() {
            let access = access.clone().into();
            match (value, &access) {
                (ArgumentRefType::Plaintext(Plaintext::Struct(members, ..)), Access::Member(identifier)) => {
                    match members.get(identifier) {
                        // Retrieve the member and update `value` for the next iteration.
                        Some(member) => value = ArgumentRefType::Plaintext(member),
                        // Halts if the member does not exist.
                        None => bail!("Failed to locate member '{identifier}''"),
                    }
                }
                (ArgumentRefType::Plaintext(Plaintext::Array(array, ..)), Access::Index(index)) => {
                    let index = match index.eject_mode() {
                        Mode::Constant => index.eject_value(),
                        _ => bail!("'{index}' must be a constant"),
                    };
                    match array.get(*index as usize) {
                        // Retrieve the element and update `value` for the next iteration.
                        Some(element) => value = ArgumentRefType::Plaintext(element),
                        // Halts if the index is out of bounds.
                        None => bail!("Index '{index}' is out of bounds"),
                    }
                }
                (ArgumentRefType::Future(future), Access::Index(index)) => {
                    let index = match index.eject_mode() {
                        Mode::Constant => index.eject_value(),
                        _ => bail!("'{index}' must be a constant"),
                    };
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
