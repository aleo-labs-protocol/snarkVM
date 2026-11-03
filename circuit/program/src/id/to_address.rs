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

impl<A: Aleo> ProgramID<A> {
    /// Returns the program address for this program ID.
    pub fn to_address(&self) -> Address<A> {
        // Compute the program address as `HashToGroup(program_id)`.
        let group = A::hash_to_group_psd4(&[self.name().to_field(), self.network().to_field()]);
        // Return the program address.
        Address::from_group(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Circuit, data::identifier::tests::sample_lowercase_console_identifier_as_string};

    use anyhow::Result;

    const ITERATIONS: usize = 10;

    fn check_to_address(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        for i in 0..ITERATIONS {
            // Sample a random fixed-length alphanumeric string, that always starts with an alphabetic character.
            let expected_name_string = sample_lowercase_console_identifier_as_string::<Circuit>()?;
            let expected_program_id = console::ProgramID::<<Circuit as Environment>::Network>::from_str(&format!(
                "{expected_name_string}.aleo"
            ))?;
            let expected = expected_program_id.to_address()?;

            let program_id = match mode {
                Mode::Constant => ProgramID::<Circuit>::constant(expected_program_id),
                Mode::Public => ProgramID::<Circuit>::public(expected_program_id),
                Mode::Private => panic!("ProgramID cannot be private"),
            };

            Circuit::scope(format!("{mode}"), || {
                let candidate = program_id.to_address();
                assert_eq!(expected, candidate.eject_value());
                if i > 0 {
                    assert_scope!(num_constants, num_public, num_private, num_constraints);
                }
            });
            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_to_address_constant() -> Result<()> {
        check_to_address(Mode::Constant, 1059, 0, 0, 0)
    }

    #[test]
    fn test_to_address_public() -> Result<()> {
        check_to_address(Mode::Public, 529, 0, 2096, 2106)
    }
}
