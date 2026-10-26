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

use crate::Stack;
use console::{
    prelude::{Network, cfg_iter},
    program::{EntryType, FinalizeType, Identifier, Locator, PlaintextType, ProgramID, RegisterType, ValueType},
};
use snarkvm_synthesizer_program::{Program, StackTrait};

use anyhow::{Result, anyhow, bail, ensure};

use std::collections::HashMap;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// Verifies that the existing output register indices are not changed in a new version of the program.
// Note. This function is public so that depednent crates can cleanly surface this error to users.
pub fn check_output_register_indices_unchanged<N: Network>(
    old_program: &Program<N>,
    new_program: &Program<N>,
) -> Result<()> {
    for (id, function) in old_program.functions() {
        // Get the corresponding function in the new program.
        let Ok(new_function) = new_program.get_function(id) else { bail!("Missing function '{id}'") };
        // Ensure the record output registers match.
        let existing_output_registers =
            function.outputs().iter().filter(|output| matches!(output.value_type(), ValueType::Record(_)));
        let new_output_registers =
            new_function.outputs().iter().filter(|output| matches!(output.value_type(), ValueType::Record(_)));
        ensure!(
            existing_output_registers.eq(new_output_registers),
            "Function '{id}' has mismatched record output registers"
        );
    }
    Ok(())
}

// TODO (raychu86): Unify this logic with other usages of `size_in_bits`.
/// Checks that all future argument bit sizes in the program do not exceed the specified maximum.
pub fn check_future_argument_bit_size<N: Network>(
    program: &Program<N>,
    stack: &Stack<N>,
    max_future_argument_bit_size: usize,
) -> Result<()> {
    // Helper to get a struct declaration.
    let get_struct = |id: &Identifier<N>| program.get_struct(id).cloned();

    // Helper to get an external struct declaration.
    let get_external_struct = |locator: &Locator<N>| {
        stack.get_external_stack(locator.program_id())?.program().get_struct(locator.resource()).cloned()
    };

    // A helper to get the argument types of a future.
    let get_future = |locator: &Locator<N>| {
        Ok(match stack.program_id() == locator.program_id() {
            true => stack
                .program()
                .get_function_ref(locator.resource())?
                .finalize_logic()
                .ok_or_else(|| anyhow!("'{locator}' does not have a finalize scope"))?
                .input_types(),
            false => stack
                .get_external_stack(locator.program_id())?
                .program()
                .get_function_ref(locator.resource())?
                .finalize_logic()
                .ok_or_else(|| anyhow!("Failed to find function '{locator}'"))?
                .input_types(),
        })
    };

    // Check each function's finalize inputs in parallel.
    cfg_iter!(program.functions()).try_for_each(|(_, function)| {
        // If there is no finalize logic, skip.
        let Some(finalize) = function.finalize_logic() else { return Ok(()) };

        // Check each input type.
        let input_types = finalize.input_types();
        let program_id = program.id();
        let function_name = *function.name();
        cfg_iter!(input_types).enumerate().try_for_each(|(i, input_type)| {
            // If the finalize type is a future, check the argument sizes.
            let argument_num_bits =
                input_type.size_in_bits_internal(&get_struct, &get_external_struct, &get_future, 0)?;
            ensure!(
                        argument_num_bits <= max_future_argument_bit_size,
                        "Future argument {i} in {program_id}/{function_name} exceeds the maximum allowed size in bits ({argument_num_bits} > {max_future_argument_bit_size})."
                    );
            Ok(())
        })
    })
}

/// Checks that every `PlaintextType` declared in the program does not exceed the specified maximum size in bits.
pub fn check_program_plaintext_sizes<N: Network>(
    program: &Program<N>,
    stack: &Stack<N>,
    max_bits: usize,
) -> Result<()> {
    // Track the `(size, height)` of the `(program, struct)` pairs that have already been sized. This is shared by
    // every `check` below, since the declarations walked here overlap heavily; see `plaintext_size_in_bits_raw`.
    let mut memoized = HashMap::new();

    // Check a single plaintext type against the budget.
    let mut check = |pt: &PlaintextType<N>| -> Result<()> {
        let bits = plaintext_size_in_bits_raw(stack, pt, 0, &mut memoized)?.0;
        ensure!(
            bits <= max_bits,
            "Plaintext type '{pt}' exceeds the maximum allowed size in bits ({bits} > {max_bits})"
        );
        Ok(())
    };

    // Check function inputs, outputs, and finalize arguments.
    for (_, function) in program.functions() {
        for input in function.inputs() {
            if let ValueType::Constant(pt) | ValueType::Public(pt) | ValueType::Private(pt) = input.value_type() {
                check(pt)?;
            }
        }
        for output in function.outputs() {
            if let ValueType::Constant(pt) | ValueType::Public(pt) | ValueType::Private(pt) = output.value_type() {
                check(pt)?;
            }
        }
        if let Some(finalize) = function.finalize_logic() {
            for input in finalize.inputs() {
                if let FinalizeType::Plaintext(pt) = input.finalize_type() {
                    check(pt)?;
                }
            }
        }
    }

    // Check view inputs and outputs.
    for (_, view) in program.views() {
        for input in view.inputs() {
            if let FinalizeType::Plaintext(pt) = input.finalize_type() {
                check(pt)?;
            }
        }
        for output in view.outputs() {
            if let FinalizeType::Plaintext(pt) = output.finalize_type() {
                check(pt)?;
            }
        }
    }

    // Check each struct member.
    for (_, struct_) in program.structs() {
        for (_, pt) in struct_.members() {
            check(pt)?;
        }
    }

    // Check each record entry.
    for (_, record) in program.records() {
        for (_, entry) in record.entries() {
            match entry {
                EntryType::Constant(pt) | EntryType::Public(pt) | EntryType::Private(pt) => check(pt)?,
            }
        }
    }

    // Check each mapping key and value.
    for (_, mapping) in program.mappings() {
        check(mapping.key().plaintext_type())?;
        check(mapping.value().plaintext_type())?;
    }

    // Check closure inputs and outputs.
    for (_, closure) in program.closures() {
        for input in closure.inputs() {
            if let RegisterType::Plaintext(pt) = input.register_type() {
                check(pt)?;
            }
        }
        for output in closure.outputs() {
            if let RegisterType::Plaintext(pt) = output.register_type() {
                check(pt)?;
            }
        }
    }

    Ok(())
}

/// Returns the `(size, height)` in bits of the given plaintext type, excluding any type metadata.
///
/// Each struct reference is resolved against the program that declares it, since a struct declared
/// in an external program may refer to structs local to that program, or to structs in programs
/// that the current program does not import.
///
/// `memoized` records the result for each `(program, struct)` pair already sized, so that a struct shared by many
/// members is expanded at most once. Without this, a program in which every member of each struct refers to the
/// same earlier struct forms an acyclic graph with exponentially many paths, and this walk would make up to
/// `MAX_STRUCT_ENTRIES ^ MAX_STRUCTS` recursive calls.
///
/// `height` is the number of levels below a type at which its deepest node sits (a literal is `0`). It lets a
/// memoized hit at a deeper position re-apply the depth check the skipped recursion would have performed on that
/// node, so the memoization changes only the running time and never the result.
fn plaintext_size_in_bits_raw<N: Network>(
    stack: &Stack<N>,
    plaintext_type: &PlaintextType<N>,
    depth: usize,
    memoized: &mut HashMap<(ProgramID<N>, Identifier<N>), (usize, usize)>,
) -> Result<(usize, usize)> {
    // Ensure that the depth is within the maximum limit.
    ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext depth exceeds maximum limit: {}", N::MAX_DATA_DEPTH);

    match plaintext_type {
        PlaintextType::Literal(literal_type) => Ok((literal_type.size_in_bits::<N>() as usize, 0)),
        PlaintextType::Struct(struct_name) => {
            // If this struct has already been sized in the current traversal, reuse that result.
            let key = (*stack.program_id(), *struct_name);
            if let Some(&(size, height)) = memoized.get(&key) {
                ensure!(
                    depth.saturating_add(height) <= N::MAX_DATA_DEPTH,
                    "Plaintext depth exceeds maximum limit: {}",
                    N::MAX_DATA_DEPTH
                );
                return Ok((size, height));
            }

            // Add up the sizes of the members, which are declared in the same program.
            let members = stack.program().get_struct(struct_name)?.members();
            let mut total = 0usize;
            // Track the maximum height of any member's subtree.
            let mut member_height = 0usize;
            for member_type in members.values() {
                let (member_size, subtree_height) =
                    plaintext_size_in_bits_raw(stack, member_type, depth + 1, memoized)?;
                total =
                    total.checked_add(member_size).ok_or_else(|| anyhow!("`plaintext_size_in_bits_raw` overflowed"))?;
                member_height = member_height.max(subtree_height);
            }

            // The struct sits one level above its deepest member; a memberless struct recurses nowhere.
            let height = match members.is_empty() {
                true => 0,
                false => member_height + 1,
            };
            memoized.insert(key, (total, height));
            Ok((total, height))
        }
        PlaintextType::ExternalStruct(locator) => {
            // Resolve the struct, and therefore its members, against the external program.
            let external_stack = stack.get_external_stack(locator.program_id())?;
            plaintext_size_in_bits_raw(&external_stack, &PlaintextType::Struct(*locator.resource()), depth, memoized)
        }
        PlaintextType::Array(array_type) => {
            // Multiply the size of an element by the length of the array.
            let (element_size, element_height) =
                plaintext_size_in_bits_raw(stack, array_type.next_element_type(), depth + 1, memoized)?;
            let total = element_size
                .checked_mul(**array_type.length() as usize)
                .ok_or_else(|| anyhow!("`plaintext_size_in_bits_raw` overflowed"))?;
            // The array sits one level above its element.
            Ok((total, element_height + 1))
        }
    }
}
