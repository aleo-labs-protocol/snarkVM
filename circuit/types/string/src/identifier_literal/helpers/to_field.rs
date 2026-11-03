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

impl<E: Environment> ToField for IdentifierLiteral<E> {
    type Field = Field<E>;

    /// Returns the identifier literal as a field element.
    fn to_field(&self) -> Field<E> {
        // Note: We are reconstituting the identifier as a base field.
        // This is safe as the number of bits in the identifier is less than the base field modulus,
        // and thus will always fit within a single base field element.
        debug_assert!(SIZE_IN_BITS < E::BaseField::size_in_bits());

        // Collect all SIZE_IN_BITS bits in little-endian order.
        let mut bits = Vec::with_capacity(SIZE_IN_BITS);
        for byte in self.bytes.iter() {
            byte.write_bits_le(&mut bits);
        }
        // Convert the bits to a field element.
        Field::from_bits_le(&bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::ToField as _;
    use snarkvm_circuit_environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentEnvironment = Circuit;

    const ITERATIONS: usize = 10;

    fn check_to_field(mode: Mode, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Construct a random console identifier literal.
            let console_value =
                console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            // Inject the identifier literal.
            let candidate = IdentifierLiteral::<CurrentEnvironment>::new(mode, console_value);

            Circuit::scope(format!("to_field {mode}"), || {
                // Perform the conversion.
                let result = candidate.to_field();

                // Verify the field value matches the console implementation (equivalence test).
                let expected_field = console_value.to_field().unwrap();
                assert_eq!(expected_field, result.eject_value());

                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            Circuit::reset();
        }
    }

    #[test]
    fn test_to_field_constant() {
        check_to_field(Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_to_field_public() {
        check_to_field(Mode::Public, 0, 0, 0, 0);
    }

    #[test]
    fn test_to_field_private() {
        check_to_field(Mode::Private, 0, 0, 0, 0);
    }
}
