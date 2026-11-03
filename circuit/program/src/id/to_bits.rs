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

impl<A: Aleo> ToBits for ProgramID<A> {
    type Boolean = Boolean<A>;

    /// Returns the little-endian bits of the program ID.
    fn write_bits_le(&self, vec: &mut Vec<Self::Boolean>) {
        (&self).write_bits_le(vec);
    }

    /// Returns the big-endian bits of the program ID.
    fn write_bits_be(&self, vec: &mut Vec<Self::Boolean>) {
        (&self).write_bits_be(vec);
    }
}

impl<A: Aleo> ToBits for &ProgramID<A> {
    type Boolean = Boolean<A>;

    /// Returns the little-endian bits of the program ID.
    fn write_bits_le(&self, vec: &mut Vec<Self::Boolean>) {
        self.name().write_bits_le(vec);
        self.network().write_bits_le(vec);
    }

    /// Returns the big-endian bits of the program ID.
    fn write_bits_be(&self, vec: &mut Vec<Self::Boolean>) {
        self.name().write_bits_be(vec);
        self.network().write_bits_be(vec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Circuit, data::identifier::tests::sample_lowercase_console_identifier_as_string};

    use anyhow::Result;

    const ITERATIONS: usize = 10;

    fn check_to_bits_le(mode: Mode) -> Result<()> {
        for _ in 0..ITERATIONS {
            // Sample a random fixed-length alphanumeric string, that always starts with an alphabetic character.
            let expected_name_string = sample_lowercase_console_identifier_as_string::<Circuit>()?;
            let expected = console::ProgramID::<<Circuit as Environment>::Network>::from_str(&format!(
                "{expected_name_string}.aleo"
            ))?;

            let candidate = match mode {
                Mode::Constant => ProgramID::<Circuit>::constant(expected),
                Mode::Public => ProgramID::<Circuit>::public(expected),
                Mode::Private => panic!("ProgramID cannot be private"),
            };
            assert_eq!(expected.to_bits_le(), candidate.to_bits_le().eject_value());
        }
        Ok(())
    }

    fn check_to_bits_be(mode: Mode) -> Result<()> {
        for _ in 0..ITERATIONS {
            // Sample a random fixed-length alphanumeric string, that always starts with an alphabetic character.
            let expected_name_string = sample_lowercase_console_identifier_as_string::<Circuit>()?;
            let expected = console::ProgramID::<<Circuit as Environment>::Network>::from_str(&format!(
                "{expected_name_string}.aleo"
            ))?;

            let candidate = match mode {
                Mode::Constant => ProgramID::<Circuit>::constant(expected),
                Mode::Public => ProgramID::<Circuit>::public(expected),
                Mode::Private => panic!("ProgramID cannot be private"),
            };
            assert_eq!(expected.to_bits_be(), candidate.to_bits_be().eject_value());
        }
        Ok(())
    }

    #[test]
    fn test_to_bits_le() -> Result<()> {
        check_to_bits_le(Mode::Constant)?;
        check_to_bits_le(Mode::Public)?;
        Ok(())
    }

    #[test]
    fn test_to_bits_be() -> Result<()> {
        check_to_bits_be(Mode::Constant)?;
        check_to_bits_be(Mode::Public)?;
        Ok(())
    }
}
