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

impl<N: Network> Stack<N> {
    /// Initializes a new stack, given the process and program.
    #[inline]
    pub(crate) fn initialize(process: &Process<N>, program: &Program<N>) -> Result<Self> {
        // Compute the appropriate edition for the stack.
        let edition = match process.contains_program(program.id()) {
            // If the program does not exist in the process, use edition zero.
            false => 0u16,
            // If the new program matches the existing program, use the existing edition.
            // Otherwise, increment the edition.
            true => {
                // Retrieve the stack for the program.
                let stack = process.get_stack(program.id())?;
                // Retrieve the program edition.
                let edition = *stack.program_edition();
                // Increment the edition.
                edition.checked_add(1).ok_or_else(|| anyhow!("Overflow while incrementing the program edition"))?
            }
        };
        // Construct a new stack.
        let stack = Self::create_raw(process, program, edition)?;
        // Initialize and check the stack's validity.
        stack.initialize_and_check(process)?;
        // Return the stack.
        Ok(stack)
    }

    /// Create a new stack, given the process and program, without completely initializing or checking for validity.
    #[inline]
    pub(crate) fn create_raw(process: &Process<N>, program: &Program<N>, edition: u16) -> Result<Self> {
        // Construct the stack for the program.
        let stack = Self {
            program: program.clone(),
            stacks: Arc::downgrade(&process.stacks),
            constructor_types: Default::default(),
            register_types: Default::default(),
            finalize_types: Default::default(),
            view_types: Default::default(),
            universal_srs: process.universal_srs().clone(),
            proving_keys: Default::default(),
            verifying_keys: Default::default(),
            program_address: program.id().to_address()?,
            program_checksum: program.to_checksum(),
            // Component names are unique within a program, so functions, closures, and views never collide here.
            component_checksums: program
                .functions()
                .iter()
                .map(|(name, function)| (*name, function.to_checksum()))
                .chain(program.closures().iter().map(|(name, closure)| (*name, closure.to_checksum())))
                .chain(program.views().iter().map(|(name, view)| (*name, view.to_checksum())))
                .collect(),
            program_edition: U16::new(edition),
            program_amendment_count: 0,
            program_owner: None,
        };
        // Return the stack.
        Ok(stack)
    }
}
