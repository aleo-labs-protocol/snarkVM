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

use circuit::Eject;
use console::program::{EntryType, FinalizeType, Identifier, Locator, PlaintextType, RecordType, RegisterType};
use snarkvm_synthesizer_program::Program;

use crate::matches_type;

use super::*;

impl<N: Network, A: circuit::Aleo<Network = N>> RegistersCircuit<N, A> for Registers<N, A> {
    /// Returns the transition signer, as a circuit.
    #[inline]
    fn signer_circuit(&self) -> Result<circuit::Address<A>> {
        self.signer_circuit.clone().ok_or_else(|| anyhow!("Signer address (circuit) is not set in the registers."))
    }

    /// Sets the transition signer, as a circuit.
    #[inline]
    fn set_signer_circuit(&mut self, signer_circuit: circuit::Address<A>) {
        self.signer_circuit = Some(signer_circuit);
    }

    /// Returns the root transition view key, as a circuit.
    #[inline]
    fn root_tvk_circuit(&self) -> Result<circuit::Field<A>> {
        self.root_tvk_circuit.clone().ok_or_else(|| anyhow!("Root tvk (circuit) is not set in the registers."))
    }

    /// Sets the root transition view key, as a circuit.
    #[inline]
    fn set_root_tvk_circuit(&mut self, root_tvk_circuit: circuit::Field<A>) {
        self.root_tvk_circuit = Some(root_tvk_circuit);
    }

    /// Returns the transition caller, as a circuit.
    #[inline]
    fn caller_circuit(&self) -> Result<circuit::Address<A>> {
        self.caller_circuit.clone().ok_or_else(|| anyhow!("Caller address (circuit) is not set in the registers."))
    }

    /// Sets the transition caller, as a circuit.
    #[inline]
    fn set_caller_circuit(&mut self, caller_circuit: circuit::Address<A>) {
        self.caller_circuit = Some(caller_circuit);
    }

    /// Returns the transition view key, as a circuit.
    #[inline]
    fn tvk_circuit(&self) -> Result<circuit::Field<A>> {
        self.tvk_circuit.clone().ok_or_else(|| anyhow!("Transition view key (circuit) is not set in the registers."))
    }

    /// Sets the transition view key, as a circuit.
    #[inline]
    fn set_tvk_circuit(&mut self, tvk_circuit: circuit::Field<A>) {
        self.tvk_circuit = Some(tvk_circuit);
    }

    /// Loads the value of a given operand from the registers.
    ///
    /// # Errors
    /// This method will halt if the register locator is not found.
    /// In the case of register accesses, this method will halt if the access is not found.
    fn load_circuit(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<circuit::Value<A>> {
        use circuit::Inject;

        // Retrieve the register.
        let register = match operand {
            // If the operand is a literal, return the literal.
            Operand::Literal(literal) => {
                return Ok(circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::constant(
                    literal.clone(),
                ))));
            }
            // If the operand is a register, load the value from the register.
            Operand::Register(register) => register,
            // If the operand is the program ID, load the program address.
            Operand::ProgramID(program_id) => {
                return Ok(circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::constant(
                    Literal::Address(program_id.to_address()?),
                ))));
            }
            // If the operand is the signer, load the value of the signer.
            Operand::Signer => {
                return Ok(circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Address(
                    self.signer_circuit()?,
                ))));
            }
            // If the operand is the caller, load the value of the caller.
            Operand::Caller => {
                return Ok(circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Address(
                    self.caller_circuit()?,
                ))));
            }
            // If the operand is the generator, retrieve the Aleo generator.
            Operand::AleoGenerator => {
                return A::g_powers()
                    .first()
                    .map(|element| {
                        circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Group(element.clone())))
                    })
                    .ok_or_else(|| anyhow!("Failed to retrieve the Aleo generator"));
            }
            // If the operand is the generator powers, retrieve the generator powers or the indexed group.
            Operand::AleoGeneratorPowers(index) => match index {
                None => {
                    return Ok(circuit::Value::Plaintext(circuit::Plaintext::Array(
                        A::g_powers()
                            .into_iter()
                            .map(|element| circuit::Plaintext::from(circuit::Literal::Group(element)))
                            .collect(),
                        OnceCell::new(),
                    )));
                }
                Some(index) => {
                    return A::g_powers()
                        .get(**index as usize)
                        .map(|element| {
                            circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Group(
                                element.clone(),
                            )))
                        })
                        .ok_or_else(|| anyhow!("Index {index} out of bounds for Aleo generator"));
                }
            },
            // If the operand is the block height, throw an error.
            Operand::BlockHeight => bail!("Cannot load the block height in a non-finalize context"),
            // If the operand is the block timestamp, throw an error.
            Operand::BlockTimestamp => bail!("Cannot load the block timestamp in a non-finalize context"),
            // If the operand is the network ID, throw an error.
            Operand::NetworkID => bail!("Cannot load the network ID in a non-finalize context"),
            // If the operand is the checksum, throw an error.
            Operand::Checksum(_) => bail!("Cannot load the checksum in a non-finalize context."),
            // If the operand is the edition, throw an error.
            Operand::Edition(_) => bail!("Cannot load the edition in a non-finalize context"),
            // If the operand is the program owner, throw an error.
            Operand::ProgramOwner(_) => bail!("Cannot load the program owner in a non-finalize context"),
            // If the operand is the component checksum, throw an error.
            Operand::ComponentChecksum(..) => bail!("Cannot load the component checksum in a non-finalize context"),
        };

        // Retrieve the circuit value.
        let circuit_value =
            self.circuit_registers.get(&register.locator()).ok_or_else(|| anyhow!("'{register}' does not exist"))?;

        // Return the value for the given register or register access.
        let circuit_value = match register {
            // If the register is a locator, then return the stack value.
            Register::Locator(..) => circuit_value.clone(),
            // If the register is a register access, then load the specific stack value.
            Register::Access(_, path) => {
                // Inject the path.
                let path = path.iter().map(|access| circuit::Access::constant(*access)).collect::<Vec<_>>();

                match circuit_value {
                    // Retrieve the plaintext member from the path.
                    circuit::Value::Plaintext(plaintext) => circuit::Value::Plaintext(plaintext.find(&path)?),
                    // Retrieve the record entry from the path.
                    circuit::Value::Record(record) => match record.find(&path)? {
                        circuit::Entry::Constant(plaintext)
                        | circuit::Entry::Public(plaintext)
                        | circuit::Entry::Private(plaintext) => circuit::Value::Plaintext(plaintext),
                    },
                    // Retrieve the argument from the future.
                    circuit::Value::Future(future) => future.find(&path)?,
                    // A dynamic record cannot be accessed directly.
                    circuit::Value::DynamicRecord(dynamic_record) => dynamic_record.find(&path)?,
                    // A dynamic future cannot be accessed directly.
                    circuit::Value::DynamicFuture(_) => {
                        bail!("Cannot invoke `find` on a dynamic future value")
                    }
                }
            }
        };

        // Retrieve the register type.
        match self.register_types.get_type(stack, register) {
            // Ensure the stack value matches the register type.
            Ok(register_type) => Self::circuit_matches_register_type(stack, &circuit_value, &register_type)?,
            // Ensure the register is defined.
            Err(error) => bail!("Register '{register}' is not a member of the function: {error}"),
        };

        Ok(circuit_value)
    }

    /// Assigns the given value to the given register, assuming the register is not already assigned.
    ///
    /// # Errors
    /// This method will halt if the given register is a register access.
    /// This method will halt if the given register is an input register.
    /// This method will halt if the register is already used.
    fn store_circuit(
        &mut self,
        stack: &impl StackTrait<N>,
        register: &Register<N>,
        circuit_value: circuit::Value<A>,
    ) -> Result<()> {
        match register {
            Register::Locator(locator) => {
                // Ensure the register assignments are monotonically increasing.
                let expected_locator = self.circuit_registers.len() as u64;
                ensure!(expected_locator == *locator, "Out-of-order write operation at '{register}'");
                // Ensure the register does not already exist.
                ensure!(
                    !self.circuit_registers.contains_key(locator),
                    "Cannot write to occupied register '{register}'"
                );

                // Ensure the register type is valid.
                match self.register_types.get_type(stack, register) {
                    // Ensure the stack value matches the register type.
                    Ok(register_type) => Self::circuit_matches_register_type(stack, &circuit_value, &register_type)?,
                    // Ensure the register is defined.
                    Err(error) => bail!("Register '{register}' is missing a type definition: {error}"),
                };

                // Store the stack value.
                match self.circuit_registers.insert(*locator, circuit_value) {
                    // Ensure the register has not been previously stored.
                    Some(..) => bail!("Attempted to write to register '{register}' again"),
                    // Return on success.
                    None => Ok(()),
                }
            }
            // Ensure the register is not a register access.
            Register::Access(..) => bail!("Cannot store to a register access: '{register}'"),
        }
    }

    // This method falls back to the private function generated by the matches_type! macro later in
    // this file and shares the same functionality as its console (StackTrait) counterpart generated
    // with the same macro.

    /// Checks that the given circuit value matches the layout of the register type.
    fn circuit_matches_register_type(
        stack: &impl StackTrait<N>,
        circuit_value: &circuit::Value<A>,
        register_type: &RegisterType<N>,
    ) -> Result<()> {
        circuit_matches_register_type(stack, circuit_value, register_type)
    }
}

// This macro invocation generates the private function which the public method
// `circuit_matches_register_type` exposed by the RegistersCircuit macro wraps around.
matches_type!(
    // Path to value types
    circuit,
    // Generics
    { <N: Network, A: circuit::Aleo<Network = N>> },
    A,
    // Used in some (limited) places to obtain console values.
    eject_value,
    // Names of the private functions to be generated. Only the first one is used, with the rest
    // being auxiliary functions.
    circuit_matches_register_type,
    circuit_matches_external_record,
    circuit_matches_record,
    circuit_matches_plaintext,
    circuit_matches_future,
    circuit_matches_record_internal,
    circuit_matches_entry_internal,
    circuit_matches_plaintext_internal,
    circuit_matches_future_internal,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Process;
    use console::network::MainnetV0;

    use circuit::{AleoV0, Inject};

    type CurrentNetwork = MainnetV0;
    type CurrentAleo = AleoV0;

    // This test verifies that `circuit_matches_register_type` accepts every injected circuit value
    // whose layout matches its register type and rejects every mismatched combination.
    #[test]
    fn test_circuit_matches_register_type() {
        let program_id = "test_matcher.aleo";

        // A program that defines the internal record, self-referential future, and external import
        // needed to exercise every `RegisterType` variant. This is necessary as ExternalRecords and
        // Records have different RegisterType but the same Value variant (if they refer to the same
        // static-record type).
        let program_str = r"
            import credits.aleo;

            program test_matcher.aleo;

            record token:
                owner as address.private;
                amount as u64.private;

            function make_future:
                input r0 as u64.public;
                async make_future r0 into r1;
                output r1 as test_matcher.aleo/make_future.future;

            finalize make_future:
                input r0 as u64.public;
                add r0 r0 into r1;
            ";

        let owner: &str = "aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah";

        // `(register type, value)` pairs covering every `RegisterType` variant. Each value matches its
        // own register type and no other register type in the list.
        let cases = vec![
            ("boolean", "true".to_string()),
            ("field", "1field".to_string()),
            ("group", "0group".to_string()),
            ("scalar", "1scalar".to_string()),
            ("u8", "1u8".to_string()),
            ("u16", "1u16".to_string()),
            ("u32", "1u32".to_string()),
            ("u64", "1u64".to_string()),
            ("u128", "1u128".to_string()),
            ("i8", "1i8".to_string()),
            ("i16", "1i16".to_string()),
            ("i32", "1i32".to_string()),
            ("i64", "1i64".to_string()),
            ("i128", "1i128".to_string()),
            ("[u8; 3u32]", "[1u8, 2u8, 3u8]".to_string()),
            // A static Record. `amount` distinguishes its layout from the `credits` record, used for
            // the ExternalRecord case.
            (
                "token.record",
                format!(
                    "{{ owner: {owner}.private, amount: 5u64.private, _nonce: 0group.public, _version: 0u8.public }}"
                ),
            ),
            // An ExternalRecord. `microcredits` distinguishes its layout from that of the `token` record.
            (
                "credits.aleo/credits.record",
                format!(
                    "{{ owner: {owner}.private, microcredits: 5u64.private, _nonce: 0group.public, _version: 0u8.public }}"
                ),
            ),
            // A future whose program ID, function name, and argument match `make_future`.
            (
                "test_matcher.aleo/make_future.future",
                "{ program_id: test_matcher.aleo, function_name: make_future, arguments: [ 5u64 ] }".to_string(),
            ),
            ("dynamic.record", format!("{{ owner: {owner}, _root: 0field, _nonce: 0group, _version: 0u8 }}")),
            (
                "dynamic.future",
                "{ _program_id: credits.aleo, _function_name: transfer_public, _checksum: 0field }".to_string(),
            ),
        ];

        // Build a stack for a program that exercises every register type variant.
        let program = Program::<CurrentNetwork>::from_str(program_str).unwrap();
        let process = Process::<CurrentNetwork>::load().unwrap();
        process.lock().add_program(&program).unwrap();
        let stack = process.get_stack(program_id).unwrap();

        let types: Vec<_> = cases.iter().map(|(t, _)| RegisterType::<CurrentNetwork>::from_str(t).unwrap()).collect();

        // Inject each console value as a private circuit value.
        let values: Vec<_> = cases
            .iter()
            .map(|(_, v)| {
                let value = Value::<CurrentNetwork>::from_str(v).unwrap();
                circuit::Value::<CurrentAleo>::new(circuit::Mode::Private, value)
            })
            .collect();

        // Every value matches its own register type (all correct combinations) and fails against
        // every other register type in the matrix (many incorrect combinations per type).
        for (i, value) in values.iter().enumerate() {
            for (j, register_type) in types.iter().enumerate() {
                let result = circuit_matches_register_type(&*stack, value, register_type);
                if i == j {
                    assert!(result.is_ok(), "expected '{}' to match '{}': {result:?}", cases[i].1, cases[j].0);
                } else {
                    assert!(result.is_err(), "expected '{}' to not match '{}'", cases[i].1, cases[j].0);
                }
            }
        }
    }
}
