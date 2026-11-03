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

impl<A: Aleo> ToBits for Identifier<A> {
    type Boolean = Boolean<A>;

    /// Returns the little-endian bits of the identifier.
    fn write_bits_le(&self, vec: &mut Vec<Self::Boolean>) {
        (&self).write_bits_le(vec);
    }

    /// Returns the big-endian bits of the identifier.
    fn write_bits_be(&self, vec: &mut Vec<Self::Boolean>) {
        (&self).write_bits_be(vec);
    }
}

impl<A: Aleo> ToBits for &Identifier<A> {
    type Boolean = Boolean<A>;

    /// Returns the little-endian bits of the identifier.
    fn write_bits_le(&self, vec: &mut Vec<Self::Boolean>) {
        let initial_len = vec.len();
        self.0.write_bits_le(vec);
        vec.truncate(initial_len + 8 * self.1 as usize);
    }

    /// Returns the big-endian bits of the identifier.
    fn write_bits_be(&self, vec: &mut Vec<Self::Boolean>) {
        let initial_len = vec.len();
        self.write_bits_le(vec);
        vec[initial_len..].reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Circuit, data::identifier::tests::sample_console_identifier};

    use anyhow::Result;

    const ITERATIONS: u64 = 10;

    fn check_to_bits_le(num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) -> Result<()> {
        for _ in 0..ITERATIONS {
            // Initialize the console identifier.
            let console_identifier = sample_console_identifier::<Circuit>()?;
            // Initialize the circuit identifier.
            let circuit_identifier = Identifier::<Circuit>::constant(console_identifier);

            Circuit::scope("Identifier ToBits", || {
                let candidate = circuit_identifier.to_bits_le();
                assert_eq!(Mode::Constant, candidate.eject_mode());
                assert_eq!(console_identifier.to_bits_le(), candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
        Ok(())
    }

    fn check_to_bits_be(num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) -> Result<()> {
        for _ in 0..ITERATIONS {
            // Initialize the console identifier.
            let console_identifier = sample_console_identifier::<Circuit>()?;
            // Initialize the circuit identifier.
            let circuit_identifier = Identifier::<Circuit>::constant(console_identifier);

            Circuit::scope("Identifier ToBits", || {
                let candidate = circuit_identifier.to_bits_be();
                assert_eq!(Mode::Constant, candidate.eject_mode());
                assert_eq!(console_identifier.to_bits_be(), candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_to_bits_le() -> Result<()> {
        check_to_bits_le(0, 0, 0, 0)
    }

    #[test]
    fn test_to_bits_be() -> Result<()> {
        check_to_bits_be(0, 0, 0, 0)
    }
}
