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
use console::program::FinalizeType;

use std::sync::OnceLock;

impl<N: Network> RegistersTrait<N> for FinalizeRegisters<N> {
    /// Loads the value of a given operand from the registers.
    ///
    /// # Errors
    /// This method will halt if the register locator is not found.
    /// In the case of register accesses, this method will halt if the access is not found.
    fn load(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<Value<N>> {
        // Retrieve the register.
        let register = match operand {
            // If the operand is a literal, return the literal.
            Operand::Literal(literal) => return Ok(Value::Plaintext(Plaintext::from(literal))),
            // If the operand is a register, load the value from the register.
            Operand::Register(register) => register,
            // If the operand is the program ID, load the program address.
            Operand::ProgramID(program_id) => {
                return Ok(Value::Plaintext(Plaintext::from(Literal::Address(program_id.to_address()?))));
            }
            // If the operand is the signer, throw an error.
            Operand::Signer => bail!("Forbidden operation: Cannot use 'self.signer' in 'finalize'"),
            // If the operand is the caller, throw an error.
            Operand::Caller => bail!("Forbidden operation: Cannot use 'self.caller' in 'finalize'"),
            // If the operand is the block height, load the block height.
            Operand::BlockHeight => {
                return Ok(Value::Plaintext(Plaintext::from(Literal::U32(U32::new(self.state.block_height())))));
            }
            // If the operand is the block timestamp, load the block timestamp.
            Operand::BlockTimestamp => match self.state.block_timestamp() {
                Some(timestamp) => {
                    return Ok(Value::Plaintext(Plaintext::from(Literal::I64(I64::new(timestamp)))));
                }
                None => bail!("The block timestamp is not available until ConsensusVersion::V12"),
            },
            // If the operand is the network ID, load the network ID.
            Operand::NetworkID => {
                return Ok(Value::Plaintext(Plaintext::from(Literal::U16(U16::new(N::ID)))));
            }
            // If the operand is the Aleo generator, retrieve the Aleo generator.
            Operand::AleoGenerator => {
                return N::g_powers()
                    .first()
                    .map(|element| Value::Plaintext(Plaintext::from(Literal::Group(*element))))
                    .ok_or_else(|| anyhow!("Failed to retrieve the Aleo generator."));
            }
            // If the operand is the generator powers, retrieve the generator powers or the indexed group.
            Operand::AleoGeneratorPowers(index) => match index {
                None => {
                    return Ok(Value::Plaintext(Plaintext::Array(
                        N::g_powers().iter().map(|element| Plaintext::from(Literal::Group(*element))).collect(),
                        OnceLock::new(),
                    )));
                }
                Some(index) => {
                    return N::g_powers()
                        .get(**index as usize)
                        .map(|element| Value::Plaintext(Plaintext::from(Literal::Group(*element))))
                        .ok_or_else(|| anyhow!("Index {index} out of bounds for Aleo generator"));
                }
            },
            // If the operand is the checksum, load the checksum.
            Operand::Checksum(program_id) => {
                let checksum = match program_id {
                    Some(program_id) => *stack.get_external_stack(program_id)?.program_checksum(),
                    None => *stack.program_checksum(),
                };
                return Ok(Value::Plaintext(Plaintext::from(checksum)));
            }
            // If the operand is the edition, load the edition.
            Operand::Edition(program_id) => {
                let edition = match program_id {
                    Some(program_id) => stack.get_external_stack(program_id)?.program_edition(),
                    None => stack.program_edition(),
                };
                return Ok(Value::Plaintext(Plaintext::from(Literal::U16(edition))));
            }
            // If the operand is the program owner, load the program address.
            Operand::ProgramOwner(program_id) => {
                // Get the program owner from the stack.
                let program_owner = match program_id {
                    Some(program_id) => *stack.get_external_stack(program_id)?.program_owner(),
                    None => *stack.program_owner(),
                };
                // Get the address, if it exists.
                let address = match program_owner {
                    Some(address) => address,
                    None => bail!("The program owner does not exist for the program '{}'.", stack.program_id()),
                };
                return Ok(Value::Plaintext(Plaintext::from(Literal::Address(address))));
            }
            // If the operand is a component checksum, load the checksum of the named component.
            Operand::ComponentChecksum(program_id, name) => {
                let checksum = match program_id {
                    Some(program_id) => *stack.get_external_stack(program_id)?.component_checksum(name)?,
                    None => *stack.component_checksum(name)?,
                };
                return Ok(Value::Plaintext(Plaintext::from(checksum)));
            }
        };

        // Retrieve the value.
        let value = self.registers.get(&register.locator()).ok_or_else(|| anyhow!("'{register}' does not exist"))?;

        // Return the value for the given register or register access.
        let value = match register {
            // If the register is a locator, then return the plaintext value.
            Register::Locator(..) => value.clone(),
            // If the register is a register access, then load the specific plaintext value.
            Register::Access(_, path) => value.find(path)?,
        };

        // Retrieve the type of the register.
        match (self.finalize_types.get_type(stack, register), &value) {
            // Ensure the plaintext value matches the register type.
            (Ok(FinalizeType::Plaintext(plaintext_type)), Value::Plaintext(plaintext_value)) => {
                stack.matches_plaintext(plaintext_value, &plaintext_type)?
            }
            // Ensure the future value matches the register type.
            (Ok(FinalizeType::Future(locator)), Value::Future(future)) => stack.matches_future(future, &locator)?,
            (Ok(FinalizeType::DynamicFuture), Value::DynamicFuture(_)) => {}
            // Ensure the load is valid in a finalize context.
            (Ok(finalize_type), stack_value) => bail!(
                "Attempted to load a '{stack_value}' value from a register '{register}' of type '{finalize_type}' in a finalize scope",
            ),
            // Ensure the register is defined.
            (Err(error), _) => bail!("Register '{register}' is not a member of the function: {error}"),
        };

        Ok(value)
    }

    /// Assigns the given value to the given register, assuming the register is not already assigned.
    ///
    /// # Errors
    /// This method will halt if the given register is a register access.
    /// This method will halt if the given register is an input register.
    /// This method will halt if the register is already used.
    fn store(&mut self, stack: &impl StackTrait<N>, register: &Register<N>, stack_value: Value<N>) -> Result<()> {
        // Store the value to the register.
        match (register, stack_value) {
            (Register::Locator(locator), stack_value) => {
                // Ensure the register assignments are monotonically increasing.
                match self.last_register {
                    None => ensure!(*locator == 0, "Out-of-order write operation at '{register}'"),
                    Some(last) => ensure!(*locator > last, "Out-of-order write operation at '{register}'"),
                };
                // Ensure the register does not already exist.
                ensure!(!self.registers.contains_key(locator), "Cannot write to occupied register '{register}'");

                // Ensure the type of the register is valid.
                match (self.finalize_types.get_type(stack, register), &stack_value) {
                    // Ensure the plaintext value matches the plaintext type.
                    (Ok(FinalizeType::Plaintext(mut plaintext_type)), Value::Plaintext(plaintext_value)) => {
                        if N::CONSENSUS_VERSION(self.state().block_height())? < ConsensusVersion::V13 {
                            // Pre-V13, the `ExternalStruct` type did not exist. If the type happens to be qualified in
                            // `get_type` above, we need to unqualify it (i.e. `ExternalStruct` becomes `Struct`) in order
                            // to obtain the same behavior we had pre-V13.
                            //
                            // Note: we don't need to rescursively check `Struct` definitions since external structs
                            // were not allowed before V13.
                            plaintext_type = plaintext_type.unqualify();
                        }
                        stack.matches_plaintext(plaintext_value, &plaintext_type)?
                    }
                    // Ensure the future value matches the future type.
                    (Ok(FinalizeType::Future(locator)), Value::Future(future)) => {
                        stack.matches_future(future, &locator)?
                    }
                    (Ok(FinalizeType::DynamicFuture), Value::DynamicFuture(_)) => {}
                    // Ensure the store is valid in a finalize context.
                    (Ok(finalize_type), stack_value) => bail!(
                        "Attempted to store a '{stack_value}' value in a register '{register}' of type '{finalize_type}' in a finalize scope",
                    ),
                    // Ensure the register is defined.
                    (Err(error), _) => bail!("Register '{register}' is missing a type definition: {error}"),
                };

                // Store the plaintext value.
                match self.registers.insert(*locator, stack_value) {
                    // Ensure the register has not been previously stored.
                    Some(..) => bail!("Attempted to write to register '{register}' again"),
                    // Update the last register locator, and return on success.
                    None => {
                        // Update the last register locator.
                        self.last_register = Some(*locator);
                        // Return on success.
                        Ok(())
                    }
                }
            }
            // Ensure the register is not a register access.
            (Register::Access(..), _) => bail!("Cannot store to a register access: '{register}'"),
        }
    }
}
