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

impl<N: Network> RegisterTypes<N> {
    /// Checks that the given operands matches the layout of the struct. The ordering of the operands matters.
    pub fn matches_struct(
        &self,
        operands_stack: &Stack<N>,
        stack: &Stack<N>,
        operands: &[Operand<N>],
        struct_: &StructType<N>,
    ) -> Result<()> {
        // Retrieve the struct name.
        let struct_name = struct_.name();
        // Ensure the struct name is valid.
        ensure!(!Program::is_reserved_keyword(struct_name), "Struct name '{struct_name}' is reserved");

        // Ensure the operands length is at least the minimum required.
        if operands.len() < N::MIN_STRUCT_ENTRIES {
            bail!("'{struct_name}' must have at least {} operand(s)", N::MIN_STRUCT_ENTRIES)
        }
        // Ensure the number of struct members does not exceed the maximum.
        if operands.len() > N::MAX_STRUCT_ENTRIES {
            bail!("'{struct_name}' cannot exceed {} entries", N::MAX_STRUCT_ENTRIES)
        }

        // Ensure the number of struct members match.
        let num_members = operands.len();
        let expected_num_members = struct_.members().len();
        if expected_num_members != num_members {
            bail!("'{struct_name}' expected {expected_num_members} members, found {num_members} members")
        }

        // Ensure the operand types match the struct.
        for (operand, (member_name, member_type)) in operands.iter().zip_eq(struct_.members()) {
            match operand {
                // Ensure the literal type matches the member type.
                Operand::Literal(literal) => {
                    ensure!(
                        &PlaintextType::Literal(literal.to_type()) == member_type,
                        "Struct member '{struct_name}.{member_name}' expects a {member_type}, but found '{operand}' in the operand.",
                    )
                }
                // Ensure the register type matches the member type.
                Operand::Register(register) => {
                    // Retrieve the register type.
                    match self.get_type(operands_stack, register)? {
                        // Ensure the register type is not a record.
                        RegisterType::ExternalRecord(..) | RegisterType::Record(..) => {
                            bail!("Casting a record into a struct entry is illegal")
                        }
                        // Ensure the register type is not a future.
                        RegisterType::Future(..) => {
                            bail!("Casting a future into a struct entry is illegal")
                        }
                        // Ensure the register type is not a dynamic record.
                        RegisterType::DynamicRecord => {
                            bail!("Casting a dynamic record into a struct entry is illegal")
                        }
                        // Ensure the register type is not a dynamic future.
                        RegisterType::DynamicFuture => {
                            bail!("Casting a dynamic future into a struct entry is illegal")
                        }
                        // Ensure the register type matches the member type.
                        RegisterType::Plaintext(type_) => {
                            ensure!(
                                types_equivalent(operands_stack, &type_, stack, member_type)?,
                                "Struct entry '{struct_name}.{member_name}' expects a '{member_type}', but found '{type_}' in the operand '{operand}'.",
                            )
                        }
                    }
                }
                // Ensure the program ID, signer, and caller types match the member type.
                Operand::ProgramID(..) | Operand::Signer | Operand::Caller => {
                    // Retrieve the operand type.
                    let RegisterType::Plaintext(operand_type) = self.get_type_from_operand(stack, operand)? else {
                        bail!(
                            "Expected a plaintext type for the operand '{operand}' in struct member '{struct_name}.{member_name}'"
                        )
                    };
                    // Ensure the operand type matches the member type.
                    ensure!(
                        types_equivalent(stack, &operand_type, stack, member_type)?,
                        "Struct member '{struct_name}.{member_name}' expects {member_type}, but found '{operand_type}' in the operand '{operand}'.",
                    )
                }
                // If the operand is a block height type, throw an error.
                Operand::BlockHeight => bail!(
                    "Struct member '{struct_name}.{member_name}' cannot be from a block height in a non-finalize scope"
                ),
                // If the operand is a block timestamp type, throw an error.
                Operand::BlockTimestamp => bail!(
                    "Struct member '{struct_name}.{member_name}' cannot be from a block timestamp in a non-finalize scope"
                ),
                // If the operand is a network ID type, throw an error.
                Operand::NetworkID => bail!(
                    "Struct member '{struct_name}.{member_name}' cannot be from a network ID in a non-finalize scope"
                ),
                // If the operand is a generator, throw an error.
                Operand::AleoGenerator => {
                    bail!(
                        "Struct member '{struct_name}.{member_name}' cannot be from a generator in a non-finalize scope"
                    )
                }
                // If the operand is the generator pwers, throw an error.
                Operand::AleoGeneratorPowers(_) => {
                    bail!(
                        "Struct member '{struct_name}.{member_name}' cannot be from generator powers in a non-finalize scope"
                    )
                }
                // If the operand is a checksum type, throw an error.
                Operand::Checksum(_) => {
                    bail!(
                        "Struct member '{struct_name}.{member_name}' cannot be from a checksum in a non-finalize scope"
                    )
                }
                // If the operand is an edition type, throw an error.
                Operand::Edition(_) => {
                    bail!(
                        "Struct member '{struct_name}.{member_name}' cannot be from an edition in a non-finalize scope"
                    )
                }
                // If the operand is a program owner type, throw an error.
                Operand::ProgramOwner(_) => {
                    bail!(
                        "Struct member '{struct_name}.{member_name}' cannot be from a program owner in a non-finalize scope"
                    )
                }
                // If the operand is a component checksum type, throw an error.
                Operand::ComponentChecksum(..) => {
                    bail!(
                        "Struct member '{struct_name}.{member_name}' cannot be from a component checksum in a non-finalize scope"
                    )
                }
            }
        }
        Ok(())
    }

    /// Checks that the given operands matches the layout of the array.
    pub fn matches_array(&self, stack: &Stack<N>, operands: &[Operand<N>], array_type: &ArrayType<N>) -> Result<()> {
        // Ensure the operands length is at least the minimum required.
        if operands.len() < N::MIN_ARRAY_ELEMENTS {
            bail!("'{array_type}' must have at least {} operand(s)", N::MIN_ARRAY_ELEMENTS)
        }
        // Ensure the number of elements not exceed the maximum.
        if operands.len() > N::LATEST_MAX_ARRAY_ELEMENTS() {
            bail!("'{array_type}' cannot exceed {} elements", N::LATEST_MAX_ARRAY_ELEMENTS())
        }

        // Ensure the number of operands matches the length of the array.
        let num_elements = operands.len();
        let expected_num_elements = **array_type.length() as usize;
        if expected_num_elements != num_elements {
            bail!("'{array_type}' expected {expected_num_elements} elements, found {num_elements} elements")
        }

        // Ensure the operand types match the element type.
        for operand in operands.iter() {
            match operand {
                // Ensure the literal type matches the element type.
                Operand::Literal(literal) => {
                    ensure!(
                        &PlaintextType::Literal(literal.to_type()) == array_type.next_element_type(),
                        "Array element expects a {}, but found '{operand}' in the operand.",
                        array_type.next_element_type(),
                    )
                }
                // Ensure the register type matches the element type.
                Operand::Register(register) => {
                    // Retrieve the register type.
                    match self.get_type(stack, register)? {
                        // Ensure the register type is not a record.
                        RegisterType::ExternalRecord(..) | RegisterType::Record(..) => {
                            bail!("Casting a record into an array element is illegal")
                        }
                        // Ensure the register type is not a future.
                        RegisterType::Future(..) => {
                            bail!("Casting a future into an array element is illegal")
                        }
                        // Ensure the register type is not a dynamic record.
                        RegisterType::DynamicRecord => {
                            bail!("Casting a dynamic record into an array element is illegal")
                        }
                        // Ensure the register type is not a dynamic future.
                        RegisterType::DynamicFuture => {
                            bail!("Casting a dynamic future into an array element is illegal")
                        }
                        // Ensure the register type matches the element type.
                        RegisterType::Plaintext(type_) => {
                            ensure!(
                                types_equivalent(stack, &type_, stack, array_type.next_element_type())?,
                                "Array element expects a '{}', but found '{type_}' in the operand '{operand}'.",
                                array_type.next_element_type()
                            )
                        }
                    }
                }
                // Ensure the program ID, signer, and caller types match the element type.
                Operand::ProgramID(..) | Operand::Signer | Operand::Caller => {
                    // Retrieve the operand type.
                    let RegisterType::Plaintext(operand_type) = self.get_type_from_operand(stack, operand)? else {
                        bail!("Expected a plaintext type for the operand '{operand}' in array element '{array_type}'")
                    };
                    // Ensure the operand type matches the element type.
                    ensure!(
                        types_equivalent(stack, &operand_type, stack, array_type.next_element_type())?,
                        "Array element expects {}, but found '{operand_type}' in the operand '{operand}'.",
                        array_type.next_element_type()
                    )
                }
                // If the operand is a block height type, throw an error.
                Operand::BlockHeight => bail!("Array element cannot be from a block height in a non-finalize scope"),
                // If the operand is a block timestamp type, throw an error.
                Operand::BlockTimestamp => {
                    bail!("Array element cannot be from a block timestamp in a non-finalize scope")
                }
                // If the operand is a network ID type, throw an error.
                Operand::NetworkID => bail!("Array element cannot be from a network ID in a non-finalize scope"),
                // If the operand is a generator, throw an error.
                Operand::AleoGenerator => {
                    bail!("Array element cannot be from a generator in a non-finalize scope")
                }
                // If the operand is the generator powers, throw an error.
                Operand::AleoGeneratorPowers(_) => {
                    bail!("Array element cannot be from generator powers in a non-finalize scope")
                }
                // If the operand is a checksum type, throw an error.
                Operand::Checksum(_) => {
                    bail!("Array element cannot be from a checksum in a non-finalize scope")
                }
                // If the operand is an edition type, throw an error.
                Operand::Edition(_) => {
                    bail!("Array element cannot be from an edition in a non-finalize scope")
                }
                // If the operand is a program owner type, throw an error.
                Operand::ProgramOwner(_) => {
                    bail!("Array element cannot be from a program owner in a non-finalize scope")
                }
                // If the operand is a component checksum type, throw an error.
                Operand::ComponentChecksum(..) => {
                    bail!("Array element cannot be from a component checksum in a non-finalize scope")
                }
            }
        }
        Ok(())
    }

    /// Checks that the given record matches the layout of the record type.
    pub fn matches_record(&self, stack: &Stack<N>, operands: &[Operand<N>], record_type: &RecordType<N>) -> Result<()> {
        // Retrieve the record name.
        let record_name = record_type.name();
        // Ensure the record name is valid.
        ensure!(!Program::is_reserved_keyword(record_name), "Record name '{record_name}' is reserved");

        // Ensure the operands length is at least the minimum required.
        if operands.len() < N::MIN_RECORD_ENTRIES {
            bail!("'{record_name}' must have at least {} operand(s)", N::MIN_RECORD_ENTRIES)
        }
        // Ensure the operands length is within the maximum limit.
        if operands.len() > N::MAX_RECORD_ENTRIES {
            bail!("'{record_name}' cannot exceed {} entries", N::MAX_RECORD_ENTRIES)
        }

        // Ensure the number of record entries match.
        let num_entries = operands.len().saturating_sub(N::MIN_RECORD_ENTRIES);
        let expected_num_entries = record_type.entries().len();
        if expected_num_entries != num_entries {
            bail!("'{record_name}' expected {expected_num_entries} entries, found {num_entries} entries")
        }

        // Ensure the first input type is an address.
        match &operands[0] {
            Operand::Literal(literal) => {
                ensure!(
                    literal.to_type() == LiteralType::Address,
                    "Casting to a record requires the first operand to be an address"
                )
            }
            Operand::Register(register) => {
                // Retrieve the register type.
                let register_type = self.get_type(stack, register)?;
                // Ensure the register type is an address.
                ensure!(
                    register_type == RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Address)),
                    "Casting to a record requires the first operand to be an address"
                );
            }
            Operand::ProgramID(program_id) => {
                // Note: While the ProgramID is rendered as an address, this address is not recoverable
                // from a private key. Furthermore, programs are not allowed to own any records.
                // They must hold all necessary state in storage instead.
                bail!("Forbidden operation: Cannot cast a program ID ('{program_id}') as a record owner")
            }
            Operand::Signer | Operand::Caller => {
                // No-op.
            }
            Operand::BlockHeight => {
                bail!("Forbidden operation: Cannot cast a block height as a record owner")
            }
            Operand::BlockTimestamp => {
                bail!("Forbidden operation: Cannot cast a block timestamp as a record owner")
            }
            Operand::NetworkID => {
                bail!("Forbidden operation: Cannot cast a network ID as a record owner")
            }
            Operand::AleoGenerator => {
                bail!("Forbidden operation: Cannot cast a generator as a record owner")
            }
            Operand::AleoGeneratorPowers(_) => {
                bail!("Forbidden operation: Cannot cast generator powers as a record owner")
            }
            Operand::Checksum(_) => {
                bail!("Forbidden operation: Cannot cast a checksum as a record owner")
            }
            Operand::Edition(_) => {
                bail!("Forbidden operation: Cannot cast an edition as a record owner")
            }
            Operand::ProgramOwner(_) => {
                bail!("Forbidden operation: Cannot cast a program owner as a record owner")
            }
            Operand::ComponentChecksum(..) => {
                bail!("Forbidden operation: Cannot cast a component checksum as a record owner")
            }
        }

        // Ensure the operand types match the record entry types.
        for (operand, (entry_name, entry_type)) in
            operands.iter().skip(N::MIN_RECORD_ENTRIES).zip_eq(record_type.entries())
        {
            match entry_type {
                EntryType::Constant(plaintext_type)
                | EntryType::Public(plaintext_type)
                | EntryType::Private(plaintext_type) => {
                    match operand {
                        // Ensure the literal type matches the entry type.
                        Operand::Literal(literal) => {
                            ensure!(
                                &PlaintextType::Literal(literal.to_type()) == plaintext_type,
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found '{literal}' in the operand.",
                            )
                        }
                        // Ensure the register type matches the entry type.
                        Operand::Register(register) => {
                            // Retrieve the register type.
                            match self.get_type(stack, register)? {
                                // Ensure the register type is not a record.
                                RegisterType::ExternalRecord(..) | RegisterType::Record(..) => {
                                    bail!("Casting a record into a record entry is illegal")
                                }
                                // Ensure the register type is not a future.
                                RegisterType::Future(..) => {
                                    bail!("Casting a future into a record entry is illegal")
                                }
                                // Ensure the register type is not a dynamic record.
                                RegisterType::DynamicRecord => {
                                    bail!("Casting a dynamic record into a record entry is illegal")
                                }
                                // Ensure the register type is not a dynamic future.
                                RegisterType::DynamicFuture => {
                                    bail!("Casting a dynamic future into a record entry is illegal")
                                }
                                // Ensure the register type matches the entry type.
                                RegisterType::Plaintext(type_) => {
                                    ensure!(
                                        types_equivalent(stack, &type_, stack, plaintext_type)?,
                                        "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found '{type_}' in the operand '{operand}'.",
                                    )
                                }
                            }
                        }
                        // Ensure the program ID, signer, and caller types match the entry type.
                        Operand::ProgramID(..) | Operand::Signer | Operand::Caller => {
                            // Retrieve the operand type.
                            let RegisterType::Plaintext(operand_type) = self.get_type_from_operand(stack, operand)?
                            else {
                                bail!(
                                    "Expected a plaintext type for the operand '{operand}' in record entry '{record_name}.{entry_name}'"
                                )
                            };
                            // Ensure the operand type matches the entry type.
                            ensure!(
                                types_equivalent(stack, &operand_type, stack, plaintext_type)?,
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found '{operand_type}' in the operand '{operand}'.",
                            )
                        }
                        // Fail if the operand is a block height.
                        Operand::BlockHeight => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found a block height in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is a block timestamp.
                        Operand::BlockTimestamp => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found a block timestamp in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is a network ID.
                        Operand::NetworkID => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found a network ID in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is a generator
                        Operand::AleoGenerator => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found a generator in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is generator powers
                        Operand::AleoGeneratorPowers(_) => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found generator powers in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is a checksum.
                        Operand::Checksum(_) => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found a checksum in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is an edition.
                        Operand::Edition(_) => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found an edition in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is a program owner.
                        Operand::ProgramOwner(_) => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found a program owner in the operand '{operand}'."
                            )
                        }
                        // Fail if the operand is a component checksum.
                        Operand::ComponentChecksum(..) => {
                            bail!(
                                "Record entry '{record_name}.{entry_name}' expects a '{plaintext_type}', but found a component checksum in the operand '{operand}'."
                            )
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
