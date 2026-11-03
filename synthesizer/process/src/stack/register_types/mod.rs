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

mod initialize;
mod matches;

use crate::Stack;

use console::{
    network::prelude::*,
    program::{
        Access,
        ArrayType,
        EntryType,
        FinalizeType,
        Identifier,
        LiteralType,
        Locator,
        PlaintextType,
        ProgramID,
        RecordType,
        Register,
        RegisterType,
        StructType,
        ValueType,
    },
    types::U32,
};
use snarkvm_synthesizer_program::{
    CallOperator,
    CastType,
    Closure,
    Function,
    Instruction,
    Opcode,
    Operand,
    Program,
    StackTrait,
    register_types_equivalent,
    types_equivalent,
};
use snarkvm_utilities::dev_eprintln;

use indexmap::{IndexMap, IndexSet};

use std::collections::HashSet;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegisterTypes<N: Network> {
    /// The mapping of all input registers to their defined types.
    inputs: IndexMap<u64, RegisterType<N>>,
    /// The mapping of all destination registers to their defined types.
    destinations: IndexMap<u64, RegisterType<N>>,
}

impl<N: Network> RegisterTypes<N> {
    /// Initializes a new instance of `RegisterTypes` for the given closure.
    /// Checks that the given closure is well-formed for the given stack.
    #[inline]
    pub fn from_closure(stack: &Stack<N>, closure: &Closure<N>) -> Result<Self> {
        Self::initialize_closure_types(stack, closure)
    }

    /// Initializes a new instance of `RegisterTypes` for the given function.
    /// Checks that the given function is well-formed for the given stack.
    #[inline]
    pub fn from_function(stack: &Stack<N>, function: &Function<N>) -> Result<Self> {
        Self::initialize_function_types(stack, function)
    }

    /// Returns `true` if the given register exists.
    pub fn contains(&self, register: &Register<N>) -> bool {
        // Retrieve the register locator.
        let locator = &register.locator();
        // The input and destination registers represent the full set of registers.
        // The output registers represent a subset of registers that are returned by the function.
        self.inputs.contains_key(locator) || self.destinations.contains_key(locator)
    }

    /// Returns `true` if the given register corresponds to an input register.
    pub fn is_input(&self, register: &Register<N>) -> bool {
        self.inputs.contains_key(&register.locator())
    }

    /// Returns the register type of the given operand.
    pub fn get_type_from_operand(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<RegisterType<N>> {
        Ok(match operand {
            Operand::Literal(literal) => RegisterType::Plaintext(PlaintextType::from(literal.to_type())),
            Operand::Register(register) => self.get_type(stack, register)?,
            Operand::ProgramID(_) | Operand::Signer | Operand::Caller => {
                RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Address))
            }
            Operand::AleoGenerator => RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Group)),
            Operand::AleoGeneratorPowers(index) => match index {
                None => RegisterType::Plaintext(PlaintextType::Array(ArrayType::new(
                    PlaintextType::Literal(LiteralType::Group),
                    vec![U32::new(N::Scalar::SIZE_IN_BITS as u32)],
                )?)),
                Some(_) => RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Group)),
            },
            Operand::BlockHeight => bail!("'block.height' is not a valid operand in a non-finalize context."),
            Operand::BlockTimestamp => {
                bail!("'block.timestamp' is not a valid operand in a non-finalize context.")
            }
            Operand::NetworkID => bail!("'network.id' is not a valid operand in a non-finalize context."),
            Operand::Checksum(_) => bail!("'checksum' is not a valid operand in a non-finalize context."),
            Operand::Edition(_) => bail!("'edition' is not a valid operand in a non-finalize context."),
            Operand::ProgramOwner(_) => bail!("'program_owner' is not a valid operand in a non-finalize context."),
            Operand::ComponentChecksum(..) => {
                bail!("a component checksum is not a valid operand in a non-finalize context.")
            }
        })
    }

    /// Returns the register type of the given register.
    pub fn get_type(&self, stack: &impl StackTrait<N>, register: &Register<N>) -> Result<RegisterType<N>> {
        // Initialize a tracker for the register type.
        let register_type = if self.is_input(register) {
            // Retrieve the input value type as a register type.
            self.inputs.get(&register.locator()).ok_or_else(|| anyhow!("Register '{register}' does not exist"))?
        } else {
            // Retrieve the destination register type.
            self.destinations.get(&register.locator()).ok_or_else(|| anyhow!("Register '{register}' does not exist"))?
        };

        // Retrieve the path if the register is an access. Otherwise, return the register type.
        let mut path_iter = match &register {
            // If the register is a locator, then output the register type.
            Register::Locator(..) => return Ok(register_type.clone()),
            // If the register is an access, then traverse the path to output the register type.
            Register::Access(_, path) => {
                // Ensure the path is valid.
                ensure!(!path.is_empty(), "Register '{register}' references no accesses.");
                // Output the path.
                path
            }
        }
        .iter();

        // A helper enum to track the type of the register.
        enum RegisterAccessType<N: Network> {
            /// A plaintext type.
            Plaintext(PlaintextType<N>),
            /// A future.
            Future(Locator<N>),
            // A dynamic future.
            DynamicFuture,
        }

        // A literal address type.
        let literal_address_type = PlaintextType::Literal(LiteralType::Address);

        // Because the register is an access, the accessed type must be a plaintext type.
        // We perform a single access, if the register type is a record.
        // This is done to minimize the number of `clone` operations and simplify the code.
        let mut register_type = match register_type {
            RegisterType::Plaintext(plaintext_type) => RegisterAccessType::Plaintext(plaintext_type.clone()),
            RegisterType::Record(record_name) => {
                // Ensure the record type exists.
                ensure!(stack.program().contains_record(record_name), "Record '{record_name}' does not exist");
                // Retrieve the first access.
                // Note: this unwrap is safe since the path is checked to be non-empty above.
                let access = path_iter.next().unwrap();
                // Retrieve the member type from the record.
                if access == &Access::Member(Identifier::from_str("owner")?) {
                    // If the member is the owner, then output the address type.
                    RegisterAccessType::Plaintext(literal_address_type)
                } else {
                    // Retrieve the path name.
                    let path_name = match access {
                        Access::Member(path_name) => path_name,
                        Access::Index(_) => bail!("Attempted to index into a record"),
                    };
                    // Retrieve the entry type from the record.
                    match stack.program().get_record(record_name)?.entries().get(path_name) {
                        // Retrieve the plaintext type.
                        Some(entry_type) => RegisterAccessType::Plaintext(entry_type.plaintext_type().clone()),
                        None => bail!("'{path_name}' does not exist in record '{record_name}'"),
                    }
                }
            }
            RegisterType::ExternalRecord(locator) => {
                // Get the external stack.
                let external_stack = stack.get_external_stack(locator.program_id())?;
                // Get the external record.
                let external_record = external_stack
                    .program()
                    .get_record(locator.resource())
                    .or_else(|_| bail!("External record '{locator}' does not exist"))?;
                // Retrieve the first access.
                // Note: this unwrap is safe since the path is checked to be non-empty above.
                let access = path_iter.next().unwrap();
                // Retrieve the member type from the external record.
                if access == &Access::Member(Identifier::from_str("owner")?) {
                    // If the member is the owner, then output the address type.
                    RegisterAccessType::Plaintext(literal_address_type)
                } else {
                    // Retrieve the path name.
                    let path_name = match access {
                        Access::Member(path_name) => path_name,
                        Access::Index(_) => bail!("Attempted to index into an external record"),
                    };
                    // Retrieve the entry type from the external record.
                    match external_record.entries().get(path_name) {
                        // Qualify local struct references so subsequent accesses use the correct stack.
                        Some(entry_type) => {
                            let qualified = entry_type.plaintext_type().clone().qualify(*locator.program_id());
                            RegisterAccessType::Plaintext(qualified)
                        }
                        None => bail!("'{path_name}' does not exist in external record '{locator}'"),
                    }
                }
            }
            RegisterType::Future(locator) => RegisterAccessType::Future(*locator),
            // A dynamic record cannot be accessed directly.
            RegisterType::DynamicRecord => {
                // Retrieve the first access.
                // Note: this unwrap is safe since the path is checked to be non-empty above.
                let access = path_iter.next().unwrap();
                // Retrieve the member type from the external record.
                if access == &Access::Member(Identifier::from_str("owner")?) {
                    // If the member is the owner, then output the address type.
                    RegisterAccessType::Plaintext(literal_address_type)
                } else {
                    bail!(
                        "Only the 'owner' of a dynamic record can be accessed directly, use 'get.record.dynamic' instead."
                    )
                }
            }
            // A dynamic future cannot be accessed directly.
            RegisterType::DynamicFuture => bail!("Cannot access a dynamic future value directly"),
        };

        // Traverse the path to find the register type.
        for access in path_iter {
            // Update the plaintext type at each step.
            match (&register_type, access) {
                // Ensure the plaintext type is not a literal, as the register references an access.
                (RegisterAccessType::Plaintext(PlaintextType::Literal(..)), _) => {
                    bail!("'{register}' references a literal.")
                }
                // Traverse the path to output the register type.
                (RegisterAccessType::Plaintext(PlaintextType::Struct(struct_name)), Access::Member(identifier)) => {
                    // Retrieve the member type from the struct.
                    match stack.program().get_struct(struct_name)?.members().get(identifier) {
                        // Update the member type.
                        Some(member_type) => register_type = RegisterAccessType::Plaintext(member_type.clone()),
                        None => bail!("'{identifier}' does not exist in struct '{struct_name}'"),
                    }
                }
                (RegisterAccessType::Plaintext(PlaintextType::ExternalStruct(locator)), Access::Member(identifier)) => {
                    let external_stack = stack.get_external_stack(locator.program_id())?;
                    // Retrieve the member type from the external struct.
                    match external_stack.program().get_struct(locator.resource())?.members().get(identifier) {
                        // Qualify local struct references so subsequent accesses use the correct stack.
                        Some(member_type) => {
                            let qualified = member_type.clone().qualify(*locator.program_id());
                            register_type = RegisterAccessType::Plaintext(qualified);
                        }
                        None => bail!("'{identifier}' does not exist in struct '{locator}'"),
                    }
                }
                // Traverse the path to output the register type.
                (RegisterAccessType::Plaintext(PlaintextType::Array(array_type)), Access::Index(index)) => {
                    match index < array_type.length() {
                        true => register_type = RegisterAccessType::Plaintext(array_type.next_element_type().clone()),
                        false => bail!("'{index}' is out of bounds for '{register}'"),
                    }
                }
                // Access the input to the future to output the register type and check that it is in bounds.
                (RegisterAccessType::Future(locator), Access::Index(index)) => {
                    // Retrieve the external stack, if needed.
                    let external_stack = match locator.program_id() == stack.program_id() {
                        true => None,
                        // Attention - This method must fail here and early return if the external program is missing.
                        // Otherwise, this method will proceed to look for the requested function in its own program.
                        false => Some(stack.get_external_stack(locator.program_id())?),
                    };
                    // Retrieve the associated function.
                    let function = match &external_stack {
                        Some(external_stack) => external_stack.get_function_ref(locator.resource())?,
                        None => stack.get_function_ref(locator.resource())?,
                    };
                    // Retrieve the finalize inputs.
                    let finalize_inputs = match function.finalize_logic() {
                        Some(finalize_logic) => finalize_logic.inputs(),
                        None => bail!("Function '{locator}' does not have a finalize block"),
                    };
                    // Check that the index is in bounds.
                    match finalize_inputs.get_index(**index as usize) {
                        // Retrieve the input type and update `finalize_type` for the next iteration.
                        Some(input) => {
                            register_type = match input.finalize_type() {
                                FinalizeType::Plaintext(plaintext_type) => {
                                    let plaintext = match external_stack {
                                        Some(ref external_stack) => {
                                            // Qualify the finalize input type with the external program ID so that any
                                            // subsequent accesses are resolved against the correct program context.
                                            // Without this, the type would appear "local" and later lookups could
                                            // incorrectly search the current program instead of the external one the
                                            // struct originated from.
                                            //
                                            // Note: this was added in ConsensusVersion::V13 and a check was added to make
                                            // sure this doesn't affect older consensus versions.
                                            plaintext_type.clone().qualify(*external_stack.program_id())
                                        }
                                        None => plaintext_type.clone(),
                                    };

                                    RegisterAccessType::Plaintext(plaintext)
                                }
                                FinalizeType::Future(locator) => RegisterAccessType::Future(*locator),
                                FinalizeType::DynamicFuture => RegisterAccessType::DynamicFuture,
                            }
                        }
                        // Halts if the index is out of bounds.
                        None => bail!("Index out of bounds"),
                    }
                }
                (
                    RegisterAccessType::Plaintext(PlaintextType::Struct(..) | PlaintextType::ExternalStruct(..)),
                    Access::Index(..),
                )
                | (RegisterAccessType::Plaintext(PlaintextType::Array(..)), Access::Member(..))
                | (RegisterAccessType::Future(..), Access::Member(..))
                | (RegisterAccessType::DynamicFuture, _) => {
                    bail!("Invalid access `{access}`")
                }
            }
        }

        // Output the register type.
        Ok(match register_type {
            RegisterAccessType::Plaintext(plaintext_type) => RegisterType::Plaintext(plaintext_type.clone()),
            RegisterAccessType::Future(locator) => RegisterType::Future(locator),
            RegisterAccessType::DynamicFuture => RegisterType::DynamicFuture,
        })
    }
}
