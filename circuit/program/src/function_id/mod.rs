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

use crate::{Identifier, ProgramID};
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Field, U16, environment::prelude::*};

/// Compute the function ID as `Hash(network_id, program_id.len(), program_id, function_name.len(), function_name)`.
pub fn compute_function_id<A: Aleo>(
    network_id: &U16<A>,
    program_id: &ProgramID<A>,
    function_name: &Identifier<A>,
) -> Field<A> {
    A::hash_bhp1024(
        &(
            network_id,
            program_id.name().size_in_bits(),
            program_id.name(),
            program_id.network().size_in_bits(),
            program_id.network(),
            function_name.size_in_bits(),
            function_name,
        )
            .to_bits_le(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use snarkvm_circuit_types::environment::UpdatableCount;

    use snarkvm_console::types::U16 as ConsoleU16;
    use snarkvm_console_program::{Identifier as ConsoleIdentifier, ProgramID as ConsoleProgramID};

    use anyhow::Result;

    fn check(
        mode: Mode,
        network_id: u16,
        program_id: &str,
        function_name: &str,
        expected_count: UpdatableCount,
    ) -> Result<()> {
        Circuit::initialize_global_constants();
        Circuit::reset();

        // Initialize the console values.
        let console_network_id = ConsoleU16::new(network_id);
        let console_program_id = ConsoleProgramID::from_str(program_id)?;
        let console_function_name = ConsoleIdentifier::from_str(function_name)?;

        // Compute the expected function ID.
        let expected = snarkvm_console_program::compute_function_id(
            &console_network_id,
            &console_program_id,
            &console_function_name,
        )?;

        // Initialize the network ID as a constant.
        let network_id = U16::<Circuit>::constant(console_network_id);

        // Initialize the program ID.
        let program_id = match mode {
            Mode::Constant => ProgramID::<Circuit>::constant(console_program_id),
            Mode::Public => ProgramID::<Circuit>::public(console_program_id),
            _ => panic!("Unsupported mode for ProgramID"),
        };

        // Initialize the function name.
        let function_name = match mode {
            Mode::Constant => Identifier::<Circuit>::constant(console_function_name),
            Mode::Public => Identifier::<Circuit>::public(console_function_name),
            _ => panic!("Unsupported mode for Identifier"),
        };

        Circuit::scope("compute_function_id", || {
            let candidate = compute_function_id(&network_id, &program_id, &function_name);
            assert_eq!(expected, candidate.eject_value());
            expected_count.assert_matches(
                Circuit::num_constants_in_scope(),
                Circuit::num_public_in_scope(),
                Circuit::num_private_in_scope(),
                Circuit::num_constraints_in_scope(),
            );
        });

        Circuit::reset();
        Ok(())
    }

    #[test]
    fn test_compute_function_id_constant() -> Result<()> {
        check(Mode::Constant, 0, "credits.aleo", "transfer_public", count_is!(767, 0, 0, 0))?;
        check(Mode::Constant, 0, "credits.aleo", "transfer_private", count_is!(779, 0, 0, 0))?;
        check(Mode::Constant, 0, "credits.aleo", "transfer_public_to_private", count_is!(883, 0, 0, 0))?;
        check(Mode::Constant, 0, "token_registry.aleo", "transfer_public_to_private", count_is!(959, 0, 0, 0))?;
        check(Mode::Constant, 0, "my.aleo", "foo", count_is!(584, 0, 0, 0))?;

        Ok(())
    }

    #[test]
    fn test_compute_function_id_public() -> Result<()> {
        check(Mode::Public, 0, "credits.aleo", "transfer_public", count_is!(465, 0, 1895, 1901))?;
        check(Mode::Public, 0, "credits.aleo", "transfer_private", count_is!(465, 0, 1909, 1915))?;
        check(Mode::Public, 0, "credits.aleo", "transfer_public_to_private", count_is!(465, 0, 2040, 2046))?;
        check(Mode::Public, 0, "token_registry.aleo", "transfer_public_to_private", count_is!(465, 0, 2135, 2141))?;
        check(Mode::Public, 0, "my.aleo", "foo", count_is!(463, 0, 1664, 1670))?;

        Ok(())
    }
}
