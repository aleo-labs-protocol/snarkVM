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

impl<N: Network, A: circuit::Aleo<Network = N>> RegistersSigner<N> for Registers<N, A> {
    /// Returns the transition signer.
    #[inline]
    fn signer(&self) -> Result<Address<N>> {
        self.signer.ok_or_else(|| anyhow!("Signer address (console) is not set in the registers."))
    }

    /// Sets the transition signer.
    #[inline]
    fn set_signer(&mut self, signer: Address<N>) {
        self.signer = Some(signer);
    }

    /// Returns the root transition view key.
    #[inline]
    fn root_tvk(&self) -> Result<Field<N>> {
        self.root_tvk.ok_or_else(|| anyhow!("Root tvk (console) is not set in the registers."))
    }

    /// Sets the root transition view key.
    #[inline]
    fn set_root_tvk(&mut self, root_tvk: Field<N>) {
        self.root_tvk = Some(root_tvk);
    }

    /// Returns the transition caller.
    #[inline]
    fn caller(&self) -> Result<Address<N>> {
        self.caller.ok_or_else(|| anyhow!("Caller address (console) is not set in the registers."))
    }

    /// Sets the transition caller.
    #[inline]
    fn set_caller(&mut self, caller: Address<N>) {
        self.caller = Some(caller);
    }

    /// Returns the transition view key.
    #[inline]
    fn tvk(&self) -> Result<Field<N>> {
        self.tvk.ok_or_else(|| anyhow!("Transition view key (console) is not set in the registers."))
    }

    /// Sets the transition view key.
    #[inline]
    fn set_tvk(&mut self, tvk: Field<N>) {
        self.tvk = Some(tvk);
    }

    /// Returns the request.
    #[inline]
    fn request(&self) -> Result<&crate::Request<N>> {
        self.request.as_ref().ok_or_else(|| anyhow!("Caller request is not set in the registers."))
    }

    /// Sets the caller request.
    #[inline]
    fn set_request(&mut self, request: crate::Request<N>) {
        self.request = Some(request);
    }
}

impl<N: Network, A: circuit::Aleo<Network = N>> RegistersTrait<N> for Registers<N, A> {
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
            // If the operand is the signer, load the value of the signer.
            Operand::Signer => return Ok(Value::Plaintext(Plaintext::from(Literal::Address(self.signer()?)))),
            // If the operand is the caller, load the value of the caller.
            Operand::Caller => return Ok(Value::Plaintext(Plaintext::from(Literal::Address(self.caller()?)))),
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

        // Retrieve the stack value.
        let stack_value =
            self.console_registers.get(&register.locator()).ok_or_else(|| anyhow!("'{register}' does not exist"))?;

        // Return the value for the given register or register access.
        let stack_value = match register {
            // If the register is a locator, then return the stack value.
            Register::Locator(..) => stack_value.clone(),
            // If the register is a register access, then load the specific stack value.
            Register::Access(_, path) => {
                match stack_value {
                    // Retrieve the plaintext member from the path.
                    Value::Plaintext(plaintext) => Value::Plaintext(plaintext.find(path)?),
                    // Retrieve the record entry from the path.
                    Value::Record(record) => match record.find(path)? {
                        Entry::Constant(plaintext) | Entry::Public(plaintext) | Entry::Private(plaintext) => {
                            Value::Plaintext(plaintext)
                        }
                    },
                    // Retrieve the argument from the future.
                    Value::Future(future) => future.find(path)?,
                    // A dynamic record cannot be accessed directly.
                    Value::DynamicRecord(dynamic_record) => dynamic_record.find(path)?,
                    // A dynamic future cannot be accessed directly.
                    Value::DynamicFuture(_) => bail!("Cannot invoke `find` on a dynamic future value"),
                }
            }
        };

        // Retrieve the register type.
        match self.register_types.get_type(stack, register) {
            // Ensure the stack value matches the register type.
            Ok(register_type) => stack.matches_register_type(&stack_value, &register_type)?,
            // Ensure the register is defined.
            Err(error) => bail!("Register '{register}' is not a member of the function: {error}"),
        };

        Ok(stack_value)
    }

    /// Assigns the given value to the given register, assuming the register is not already assigned.
    ///
    /// # Errors
    /// This method will halt if the given register is a register access.
    /// This method will halt if the given register is an input register.
    /// This method will halt if the register is already used.
    fn store(&mut self, stack: &impl StackTrait<N>, register: &Register<N>, stack_value: Value<N>) -> Result<()> {
        match register {
            Register::Locator(locator) => {
                // Ensure the register assignments are monotonically increasing.
                let expected_locator = self.console_registers.len() as u64;
                ensure!(expected_locator == *locator, "Out-of-order write operation at '{register}'");
                // Ensure the register does not already exist.
                ensure!(
                    !self.console_registers.contains_key(locator),
                    "Cannot write to occupied register '{register}'"
                );

                // Ensure the register type is valid.
                match self.register_types.get_type(stack, register) {
                    // Ensure the stack value matches the register type.
                    Ok(register_type) => stack.matches_register_type(&stack_value, &register_type)?,
                    // Ensure the register is defined.
                    Err(error) => bail!("Register '{register}' is missing a type definition: {error}"),
                };

                // Store the stack value.
                match self.console_registers.insert(*locator, stack_value) {
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
}
