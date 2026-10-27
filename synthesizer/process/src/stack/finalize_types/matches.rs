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

impl<N: Network> FinalizeTypes<N> {
    /// Checks that the given operands matches the layout of the struct. The ordering of the operands matters.
    pub fn matches_struct(&self, stack: &Stack<N>, operands: &[Operand<N>], struct_: &StructType<N>) -> Result<()> {
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
                        // No need to call `types_equivalent`, since it can't be a struct.
                        &PlaintextType::Literal(literal.to_type()) == member_type,
                        "Struct member '{struct_name}.{member_name}' expects a {member_type}, but found '{operand}' in the operand.",
                    )
                }
                // Ensure the type of the register matches the member type.
                Operand::Register(register) => {
                    // Retrieve the type.
                    let plaintext_type = match self.get_type(stack, register)? {
                        // If the register is a plaintext type, return it.
                        FinalizeType::Plaintext(plaintext_type) => plaintext_type,
                        // If the register is a future, throw an error.
                        FinalizeType::Future(..) => bail!("Struct member cannot be a future"),
                        // If the register is a dynamic future, throw an error.
                        FinalizeType::DynamicFuture => bail!("Struct member cannot be a dynamic future"),
                    };
                    // Ensure the register type matches the member type.
                    ensure!(
                        types_equivalent(stack, &plaintext_type, stack, member_type)?,
                        "Struct member '{struct_name}.{member_name}' expects {member_type}, but found '{plaintext_type}' in the operand '{operand}'.",
                    )
                }
                // Ensure the program ID, block height, block timestamp, network ID, generator, checksum, edition, program owner, and component checksum types matches the member type.
                Operand::ProgramID(..)
                | Operand::BlockHeight
                | Operand::BlockTimestamp
                | Operand::NetworkID
                | Operand::AleoGenerator
                | Operand::AleoGeneratorPowers(_)
                | Operand::Checksum(_)
                | Operand::Edition(_)
                | Operand::ProgramOwner(_)
                | Operand::ComponentChecksum(..) => {
                    // Retrieve the operand type.
                    let FinalizeType::Plaintext(program_ref_type) = self.get_type_from_operand(stack, operand)? else {
                        bail!(
                            "Expected a plaintext type for the operand '{operand}' in struct member '{struct_name}.{member_name}'"
                        )
                    };
                    // Ensure the operand type matches the member type.
                    ensure!(
                        // No need to call `types_equivalent`, since `program_ref_type` cannot be a struct.
                        &program_ref_type == member_type,
                        "Struct member '{struct_name}.{member_name}' expects {member_type}, but found '{program_ref_type}' in the operand '{operand}'.",
                    )
                }
                // If the operand is a signer, throw an error.
                Operand::Signer => bail!(
                    "Struct member '{struct_name}.{member_name}' cannot be cast from a signer in a finalize scope."
                ),
                // If the operand is a caller, throw an error.
                Operand::Caller => bail!(
                    "Struct member '{struct_name}.{member_name}' cannot be cast from a caller in a finalize scope."
                ),
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
                        // No need to call `types_equivalent`, since it can't be a struct.
                        &PlaintextType::Literal(literal.to_type()) == array_type.next_element_type(),
                        "Array element expects {}, but found '{operand}' in the operand.",
                        array_type.next_element_type()
                    )
                }
                // Ensure the type of the register matches the element type.
                Operand::Register(register) => {
                    // Retrieve the type.
                    let plaintext_type = match self.get_type(stack, register)? {
                        // If the register is a plaintext type, return it.
                        FinalizeType::Plaintext(plaintext_type) => plaintext_type,
                        // If the register is a future, throw an error.
                        FinalizeType::Future(..) => bail!("Array element cannot be a future"),
                        // If the register is a dynamic future, throw an error.
                        FinalizeType::DynamicFuture => bail!("Array element cannot be a dynamic future"),
                    };
                    // Ensure the register type matches the element type.
                    ensure!(
                        types_equivalent(stack, &plaintext_type, stack, array_type.next_element_type())?,
                        "Array element expects {}, but found '{plaintext_type}' in the operand '{operand}'.",
                        array_type.next_element_type()
                    )
                }
                // Ensure the program ID, block height, network ID, generator, checksum, edition, and program owner types matches the element type.
                Operand::ProgramID(..)
                | Operand::BlockHeight
                | Operand::BlockTimestamp
                | Operand::NetworkID
                | Operand::AleoGenerator
                | Operand::AleoGeneratorPowers(_)
                | Operand::Checksum(_)
                | Operand::Edition(_)
                | Operand::ProgramOwner(_)
                | Operand::ComponentChecksum(..) => {
                    // Retrieve the operand type.
                    let FinalizeType::Plaintext(program_ref_type) = self.get_type_from_operand(stack, operand)? else {
                        bail!("Expected a plaintext type for the operand '{operand}' in array element '{array_type}'")
                    };
                    // Ensure the operand type matches the element type.
                    ensure!(
                        // No need to call `types_equivalent`, since `program_ref_type` cannot be a struct.
                        &program_ref_type == array_type.next_element_type(),
                        "Array element expects {}, but found '{program_ref_type}' in the operand '{operand}'.",
                        array_type.next_element_type()
                    )
                }
                // If the operand is a signer, throw an error.
                Operand::Signer => bail!("Array element cannot be cast from a signer in a finalize scope."),
                // If the operand is a caller, throw an error.
                Operand::Caller => bail!("Array element cannot be cast from a caller in a finalize scope."),
            }
        }
        Ok(())
    }
}
