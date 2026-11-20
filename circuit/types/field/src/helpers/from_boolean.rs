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

impl<E: Environment> FromBoolean for Field<E> {
    type Boolean = Boolean<E>;

    /// Initializes a base field from a boolean.
    fn from_boolean(boolean: &Self::Boolean) -> Self {
        Self::from((**boolean).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    fn check_from_boolean(mode: Mode) {
        for expected in &[true, false] {
            // Inject the boolean.
            let given = Boolean::<Circuit>::new(mode, *expected);

            Circuit::scope(format!("{mode} {expected}"), || {
                let candidate = Field::from_boolean(&given);
                match expected {
                    true => {
                        assert_eq!(console::Field::<<Circuit as Environment>::Network>::one(), candidate.eject_value())
                    }
                    false => {
                        assert_eq!(console::Field::<<Circuit as Environment>::Network>::zero(), candidate.eject_value())
                    }
                }
                assert_scope!();
            });
        }
    }

    #[test]
    fn test_from_boolean_constant() {
        check_from_boolean(Mode::Constant);
    }

    #[test]
    fn test_from_boolean_public() {
        check_from_boolean(Mode::Public);
    }

    #[test]
    fn test_from_boolean_private() {
        check_from_boolean(Mode::Private);
    }
}
