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

use snarkvm_synthesizer_program::types_equivalent;

use super::*;

impl<N: Network> FinalizeTypes<N> {
    /// Initializes a new instance of `FinalizeTypes` for the given constructor.
    /// Checks that the given constructor is well-formed for the given stack.
    #[inline]
    pub(super) fn initialize_finalize_types_from_constructor(
        stack: &Stack<N>,
        constructor: &Constructor<N>,
    ) -> Result<Self> {
        // Initialize a map of registers to their types.
        let mut finalize_types = Self { inputs: IndexMap::new(), destinations: IndexMap::new() };

        // Check the commands are well-formed.
        for command in constructor.commands() {
            // Ensure the command is not a call instruction.
            ensure!(!command.is_call(), "`call` commands are not allowed in constructors.");
            // Ensure the command does not operate on a record (cast-to-record or `get.record.dynamic`).
            ensure!(!command.is_instruction_for_record(), "Record operations are not allowed in constructors.");
            // Ensure the command is not an await command.
            ensure!(!command.is_await(), "`await` commands are not allowed in constructors.");
            // Check the command opcode, operands, and destinations.
            finalize_types.check_command(stack, constructor.positions(), command)?;
        }

        Ok(finalize_types)
    }

    /// Initializes a new instance of `FinalizeTypes` for the given view function.
    /// Checks that the given view is well-formed for the given stack.
    ///
    /// Views share the finalize register/command shape, but cannot await futures and cannot
    /// produce side effects. The forbidden-command list (writes, async, await, call, rand.chacha)
    /// is enforced at `ViewCore` construction; this function only needs to type-check the body.
    #[inline]
    pub(super) fn initialize_finalize_types_from_view(
        stack: &Stack<N>,
        view: &snarkvm_synthesizer_program::ViewCore<N>,
    ) -> Result<Self> {
        let mut finalize_types = Self { inputs: IndexMap::new(), destinations: IndexMap::new() };

        // Type-check the inputs. View inputs are guaranteed to be plaintext at construction time.
        for input in view.inputs() {
            finalize_types.check_input(stack, input.register(), input.finalize_type())?;
        }

        // Type-check the commands.
        for command in view.commands() {
            finalize_types.check_command(stack, view.positions(), command)?;
        }

        // Type-check the outputs: each output operand must resolve and match the declared type.
        // Output operands do not flow through `check_command`, so the component checksum check is repeated here.
        // Only views have outputs; finalize and constructor scopes have none.
        for output in view.outputs() {
            // If the operand is `Operand::ComponentChecksum`, ensure the referenced component exists.
            if let Operand::ComponentChecksum(program_id, name) = output.operand() {
                Self::check_component_checksum(stack, program_id, name)?;
            }
            let actual = finalize_types.get_type_from_operand(stack, output.operand())?;
            if &actual != output.finalize_type() {
                bail!(
                    "View output type mismatch: declared '{}' but operand '{}' has type '{}'",
                    output.finalize_type(),
                    output.operand(),
                    actual,
                );
            }
        }

        Ok(finalize_types)
    }

    /// Initializes a new instance of `FinalizeTypes` for the given finalize.
    /// Checks that the given finalize is well-formed for the given stack.
    ///
    /// Attention: To support user-defined ordering for awaiting on futures, this method does **not** check
    /// that all input futures are awaited **exactly** once. It does however check that all input
    /// futures are awaited at least once. This means that it is possible to deploy a program
    /// whose finalize is not well-formed, but it is not possible to execute a program whose finalize
    /// is not well-formed.
    #[inline]
    pub(super) fn initialize_finalize_types_from_finalize(stack: &Stack<N>, finalize: &Finalize<N>) -> Result<Self> {
        // Initialize a map of registers to their types.
        let mut finalize_types = Self { inputs: IndexMap::new(), destinations: IndexMap::new() };

        // Initialize a list of input futures.
        let mut input_futures = Vec::new();

        // Step 1. Check the inputs are well-formed. Store the input futures.
        for input in finalize.inputs() {
            // Check the input register type.
            finalize_types.check_input(stack, input.register(), input.finalize_type())?;

            // If the input is a future, add it to the list of input futures.
            if matches!(input.finalize_type(), FinalizeType::Future(_) | FinalizeType::DynamicFuture) {
                input_futures.push(input.register());
            }
        }

        // Initialize the set of consumed futures.
        let mut consumed_futures = HashSet::new();

        // Step 2. Check the commands are well-formed. Make sure all the input futures are awaited.
        for command in finalize.commands() {
            // Check the command opcode, operands, and destinations.
            finalize_types.check_command(stack, finalize.positions(), command)?;

            // If the command is an `await`, add the future to the set of consumed futures.
            if let Command::Await(await_) = command {
                // Note: `check_command` ensures that the register is a future. This is an additional check.
                match finalize_types.get_type(stack, await_.register())? {
                    FinalizeType::Future(_) | FinalizeType::DynamicFuture => {}
                    FinalizeType::Plaintext(..) => bail!("Expected a future in '{await_}'"),
                };
                consumed_futures.insert(await_.register());
            }
        }

        // Check that all input futures are consumed.
        for input_future in &input_futures {
            ensure!(
                consumed_futures.contains(input_future),
                "Futures in finalize '{}' are not all awaited.",
                finalize.name()
            )
        }

        Ok(finalize_types)
    }
}

impl<N: Network> FinalizeTypes<N> {
    /// Inserts the given input register and type into the registers.
    /// Note: The given input register must be a `Register::Locator`.
    fn add_input(&mut self, register: Register<N>, finalize_type: FinalizeType<N>) -> Result<()> {
        // Ensure there are no destination registers set yet.
        ensure!(self.destinations.is_empty(), "Cannot add input registers after destination registers.");

        // Check the input register.
        match register {
            Register::Locator(locator) => {
                // Ensure the registers are monotonically increasing.
                ensure!(self.inputs.len() as u64 == locator, "Register '{register}' is out of order");

                // Insert the input register and type.
                match self.inputs.insert(locator, finalize_type) {
                    // If the register already exists, throw an error.
                    Some(..) => bail!("Input '{register}' already exists"),
                    // If the register does not exist, return success.
                    None => Ok(()),
                }
            }
            // Ensure the register is a locator, and not an access.
            Register::Access(..) => bail!("Register '{register}' must be a locator."),
        }
    }

    /// Inserts the given destination register and type into the registers.
    /// Note: The given destination register must be a `Register::Locator`.
    fn add_destination(&mut self, register: Register<N>, finalize_type: FinalizeType<N>) -> Result<()> {
        // Check the destination register.
        match register {
            Register::Locator(locator) => {
                // Ensure the registers are monotonically increasing.
                let expected_locator = (self.inputs.len() as u64) + self.destinations.len() as u64;
                ensure!(expected_locator == locator, "Register '{register}' is out of order");

                // Insert the destination register and type.
                match self.destinations.insert(locator, finalize_type) {
                    // If the register already exists, throw an error.
                    Some(..) => bail!("Destination '{register}' already exists"),
                    // If the register does not exist, return success.
                    None => Ok(()),
                }
            }
            // Ensure the register is a locator, and not an access.
            Register::Access(..) => bail!("Register '{register}' must be a locator."),
        }
    }
}

impl<N: Network> FinalizeTypes<N> {
    /// Ensure the given input register is well-formed.
    fn check_input(&mut self, stack: &Stack<N>, register: &Register<N>, finalize_type: &FinalizeType<N>) -> Result<()> {
        // Ensure the register type is defined in the program.
        match finalize_type {
            FinalizeType::Plaintext(plaintext_type) => RegisterTypes::check_plaintext_type(stack, plaintext_type)?,
            FinalizeType::Future(locator) => {
                ensure!(
                    stack.program().contains_import(locator.program_id()),
                    "Program '{locator}' is not imported by '{}'.",
                    stack.program().id()
                )
            }
            FinalizeType::DynamicFuture => {} // Do nothing.
        };

        // Insert the input register.
        self.add_input(register.clone(), finalize_type.clone())?;

        // Ensure the register type and the input type are equivalent.
        if !finalize_types_equivalent(stack, finalize_type, stack, &self.get_type(stack, register)?)? {
            bail!("Input '{register}' does not match the expected input register type.")
        }

        Ok(())
    }

    /// Ensures the given command is well-formed.
    #[inline]
    fn check_command(
        &mut self,
        stack: &Stack<N>,
        positions: &HashMap<Identifier<N>, usize>,
        command: &Command<N>,
    ) -> Result<()> {
        // Check the operands.
        for operand in command.operands() {
            // If the operand is `Operand::Checksum`, `Operand::Edition`, or `Operand::ProgramOwner` and it contains a
            // program ID, ensure that the program ID is imported by the current program.
            match operand {
                Operand::Checksum(program_id) | Operand::Edition(program_id) | Operand::ProgramOwner(program_id) => {
                    if let Some(program_id) = program_id
                        && stack.get_external_stack(program_id).is_err()
                    {
                        bail!("External program '{program_id}' is not imported by '{}'.", stack.program_id());
                    }
                }
                // If the operand is `Operand::ComponentChecksum`, ensure the referenced component exists.
                Operand::ComponentChecksum(program_id, name) => {
                    Self::check_component_checksum(stack, program_id, name)?
                }
                _ => {}
            }
        }
        match command {
            Command::Instruction(instruction) => self.check_instruction(stack, instruction)?,
            Command::Await(await_) => self.check_await(stack, await_)?,
            Command::Contains(contains) => self.check_contains(stack, contains)?,
            Command::ContainsDynamic(contains_dynamic) => self.check_contains_dynamic(stack, contains_dynamic)?,
            Command::Get(get) => self.check_get(stack, get)?,
            Command::GetDynamic(get_dynamic) => self.check_get_dynamic(stack, get_dynamic)?,
            Command::GetOrUse(get_or_use) => self.check_get_or_use(stack, get_or_use)?,
            Command::GetOrUseDynamic(get_or_use_dynamic) => self.check_get_or_use_dynamic(stack, get_or_use_dynamic)?,
            Command::RandChaCha(rand_chacha) => self.check_rand_chacha(stack, rand_chacha)?,
            Command::Remove(remove) => self.check_remove(stack, remove)?,
            Command::Set(set) => self.check_set(stack, set)?,
            Command::BranchEq(branch_eq) => self.check_branch(stack, positions, branch_eq)?,
            Command::BranchNeq(branch_neq) => self.check_branch(stack, positions, branch_neq)?,
            // Note that the `Position`s are checked for uniqueness when constructing `Finalize` or `Constructor`.
            Command::Position(_) => (),
        }
        Ok(())
    }

    /// Ensures the program referenced by a component checksum operand is imported (if external) and that the
    /// named component exists as a function, closure, or view in the target program, so a dangling reference
    /// is rejected at deployment instead of failing on every execution.
    fn check_component_checksum(
        stack: &Stack<N>,
        program_id: &Option<ProgramID<N>>,
        name: &Identifier<N>,
    ) -> Result<()> {
        // Returns `true` if `name` is a function, closure, or view in the given program.
        let is_component = |program: &Program<N>| {
            program.contains_function(name) || program.contains_closure(name) || program.contains_view(name)
        };
        let exists = match program_id {
            Some(program_id) => match stack.get_external_stack(program_id) {
                Ok(external_stack) => is_component(external_stack.program()),
                Err(_) => bail!("External program '{program_id}' is not imported by '{}'.", stack.program_id()),
            },
            None => is_component(stack.program()),
        };
        if !exists {
            let program_id = (*program_id).unwrap_or(*stack.program_id());
            bail!("'{name}' in a component checksum operand is not a function, closure, or view in '{program_id}'.");
        }
        Ok(())
    }

    /// Checks that the given `await` command is well-formed.
    #[inline]
    fn check_await(&mut self, stack: &Stack<N>, await_: &Await<N>) -> Result<()> {
        // Ensure that the register is a locator.
        ensure!(
            matches!(await_.register(), Register::Locator(..)),
            "The await register '{}' must be a locator.",
            await_.register()
        );
        // Ensure that the register is a future.
        match self.get_type(stack, await_.register())? {
            // If the register is a plaintext type, throw an error.
            FinalizeType::Plaintext(..) => bail!("Expected a future"),
            // If the register is a future, return success.
            // Note that there are not restrictions on the exact type of future.
            FinalizeType::Future(..) | FinalizeType::DynamicFuture => Ok(()),
        }
    }

    /// Checks that the given variant of the `branch` command is well-formed.
    #[inline]
    fn check_branch<const VARIANT: u8>(
        &mut self,
        stack: &Stack<N>,
        positions: &HashMap<Identifier<N>, usize>,
        branch: &Branch<N, VARIANT>,
    ) -> Result<()> {
        // Get the type of the first operand.
        let first_type = match self.get_type_from_operand(stack, branch.first())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used in a `branch` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used in a `branch` command"),
        };
        // Get the type of the second operand.
        let second_type = match self.get_type_from_operand(stack, branch.second())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used in a `branch` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used in a `branch` command"),
        };
        // Check that the operands have equivalent types.
        ensure!(
            types_equivalent(stack, &first_type, stack, &second_type)?,
            "Command '{}' expects operands of the same type. Found operands of type '{}' and '{}'",
            Branch::<N, VARIANT>::opcode(),
            first_type,
            second_type
        );
        // Check that the `Position` has been defined.
        ensure!(
            positions.get(branch.position()).is_some(),
            "Command '{}' expects a defined position to jump to. Found undefined position '{}'",
            Branch::<N, VARIANT>::opcode(),
            branch.position()
        );
        Ok(())
    }

    /// Ensures the given `contains` command is well-formed.
    #[inline]
    fn check_contains(&mut self, stack: &Stack<N>, contains: &Contains<N>) -> Result<()> {
        // Retrieve the mapping.
        let (mapping, external_program) = match contains.mapping() {
            CallOperator::Locator(locator) => {
                // Retrieve the program ID.
                let program_id = locator.program_id();
                // Retrieve the mapping_name.
                let mapping_name = locator.resource();

                // Ensure the locator does not reference the current program.
                if stack.program_id() == program_id {
                    bail!("Locator '{locator}' does not reference an external mapping.");
                }
                // Ensure the current program contains an import for this external program.
                if !stack.program().imports().keys().contains(program_id) {
                    bail!("External program '{program_id}' is not imported by '{}'.", stack.program_id());
                }
                // Retrieve the program.
                let external_stack = stack.get_external_stack(program_id)?;
                let external = external_stack.program();
                // Ensure the mapping exists in the program.
                if !external.contains_mapping(mapping_name) {
                    bail!("Mapping '{mapping_name}' in '{program_id}' is not defined.")
                }
                // Retrieve the mapping from the program.
                (external.get_mapping(mapping_name)?, Some(program_id))
            }
            CallOperator::Resource(mapping_name) => {
                // Ensure the declared mapping in `contains` is defined in the current program.
                if !stack.program().contains_mapping(mapping_name) {
                    bail!("Mapping '{mapping_name}' in '{}' is not defined.", stack.program_id())
                }
                // Retrieve the mapping from the program.
                (stack.program().get_mapping(mapping_name)?, None)
            }
        };

        // Get the mapping key type. Qualify if necessary.
        let mapping_key_type = if let Some(external_program) = external_program {
            mapping.key().plaintext_type().clone().qualify(*external_program)
        } else {
            mapping.key().plaintext_type().clone()
        };

        // Retrieve the register type of the key.
        let key_type = match self.get_type_from_operand(stack, contains.key())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `contains` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used as a key in a `contains` command"),
        };
        // Check that the key type in the mapping is equivalent to the key type in the instruction.
        if !types_equivalent(stack, &mapping_key_type, stack, &key_type)? {
            bail!(
                "Key type in `contains` '{key_type}' does not match the key type in the mapping '{mapping_key_type}'."
            )
        }
        // Get the destination register.
        let destination = contains.destination().clone();
        // Ensure the destination register is a locator (and does not reference an access).
        ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
        // Insert the destination register.
        self.add_destination(destination, FinalizeType::Plaintext(PlaintextType::Literal(LiteralType::Boolean)))?;
        Ok(())
    }

    /// Ensures the given `contains.dynamic` command is well-formed.
    #[inline]
    fn check_contains_dynamic(&mut self, stack: &Stack<N>, contains: &ContainsDynamic<N>) -> Result<()> {
        // Check that the program name, network, and mapping are all field or identifier types.
        for operand in
            [contains.program_name_operand(), contains.program_network_operand(), contains.mapping_name_operand()]
        {
            match self.get_type_from_operand(stack, operand)? {
                // If the register is a plaintext type, ensure it is a field or identifier.
                FinalizeType::Plaintext(plaintext_type) => {
                    ensure!(
                        plaintext_type == PlaintextType::Literal(LiteralType::Field)
                            || plaintext_type == PlaintextType::Literal(LiteralType::Identifier),
                        "Operand '{operand}' must be of type 'field' or 'identifier'."
                    )
                }
                // If the register is a future, throw an error.
                FinalizeType::Future(..) => {
                    bail!("A future cannot be used in a `contains.dynamic` command")
                }
                // If the register is a dynamic future, throw an error.
                FinalizeType::DynamicFuture => {
                    bail!("A dynamic future cannot be used in a `contains.dynamic` command")
                }
            }
        }
        // Check the key type.
        match self.get_type_from_operand(stack, contains.key_operand())? {
            // If the register is a plaintext type, do nothing.
            FinalizeType::Plaintext(_) => {}
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `contains.dynamic` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => {
                bail!("A dynamic future cannot be used as a key in a `contains.dynamic` command")
            }
        };
        // Get the destination register.
        let destination = contains.destination().clone();
        // Ensure the destination register is a locator (and does not reference an access).
        ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
        // Insert the destination register.
        self.add_destination(destination, FinalizeType::Plaintext(PlaintextType::Literal(LiteralType::Boolean)))?;
        Ok(())
    }

    /// Ensures the given `get` command is well-formed.
    #[inline]
    fn check_get(&mut self, stack: &Stack<N>, get: &Get<N>) -> Result<()> {
        // Retrieve the mapping.
        let (mapping, external_program) = match get.mapping() {
            CallOperator::Locator(locator) => {
                // Retrieve the program ID.
                let program_id = locator.program_id();
                // Retrieve the mapping_name.
                let mapping_name = locator.resource();

                // Ensure the locator does not reference the current program.
                if stack.program_id() == program_id {
                    bail!("Locator '{locator}' does not reference an external mapping.");
                }
                // Ensure the current program contains an import for this external program.
                if !stack.program().imports().keys().contains(program_id) {
                    bail!("External program '{program_id}' is not imported by '{}'.", stack.program_id());
                }
                // Retrieve the program.
                let external_stack = stack.get_external_stack(program_id)?;
                let external = external_stack.program();
                // Ensure the mapping exists in the program.
                if !external.contains_mapping(mapping_name) {
                    bail!("Mapping '{mapping_name}' in '{program_id}' is not defined.")
                }
                // Retrieve the mapping from the program.
                (external.get_mapping(mapping_name)?, Some(program_id))
            }
            CallOperator::Resource(mapping_name) => {
                // Ensure the declared mapping in `get` is defined in the current program.
                if !stack.program().contains_mapping(mapping_name) {
                    bail!("Mapping '{mapping_name}' in '{}' is not defined.", stack.program_id())
                }
                // Retrieve the mapping from the program.
                (stack.program().get_mapping(mapping_name)?, None)
            }
        };

        // Get the mapping key type. Qualify if necessary.
        let mapping_key_type = if let Some(external_program) = external_program {
            mapping.key().plaintext_type().clone().qualify(*external_program)
        } else {
            mapping.key().plaintext_type().clone()
        };
        // Get the mapping value type. Qualify if necessary.
        let mapping_value_type = if let Some(external_program) = external_program {
            mapping.value().plaintext_type().clone().qualify(*external_program)
        } else {
            mapping.value().plaintext_type().clone()
        };

        // Retrieve the register type of the key.
        let key_type = match self.get_type_from_operand(stack, get.key())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `get` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used as a key in a `get` command"),
        };
        // Check that the key type in the mapping is equivalent to the key type in the instruction.
        if !types_equivalent(stack, &mapping_key_type, stack, &key_type)? {
            bail!("Key type in `get` '{key_type}' does not match the key type in the mapping '{mapping_key_type}'.")
        }
        // Get the destination register.
        let destination = get.destination().clone();
        // Ensure the destination register is a locator (and does not reference an access).
        ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
        // Insert the destination register.
        self.add_destination(destination, FinalizeType::Plaintext(mapping_value_type.clone()))?;
        Ok(())
    }

    /// Ensures the given `get.dynamic` command is well-formed.
    #[inline]
    fn check_get_dynamic(&mut self, stack: &Stack<N>, get: &GetDynamic<N>) -> Result<()> {
        // Check that the program name, network, and mapping are all field or identifier types.
        for operand in [get.program_name_operand(), get.program_network_operand(), get.mapping_name_operand()] {
            match self.get_type_from_operand(stack, operand)? {
                // If the register is a plaintext type, ensure it is a field or identifier.
                FinalizeType::Plaintext(plaintext_type) => {
                    ensure!(
                        plaintext_type == PlaintextType::Literal(LiteralType::Field)
                            || plaintext_type == PlaintextType::Literal(LiteralType::Identifier),
                        "Operand '{operand}' must be of type 'field' or 'identifier'."
                    )
                }
                // If the register is a future, throw an error.
                FinalizeType::Future(..) => {
                    bail!("A future cannot be used in a `get.dynamic` command")
                }
                // If the register is a dynamic future, throw an error.
                FinalizeType::DynamicFuture => {
                    bail!("A dynamic future cannot be used in a `get.dynamic` command")
                }
            }
        }
        // Check the register type of the key.
        match self.get_type_from_operand(stack, get.key_operand())? {
            // If the register is a plaintext type, do nothing.
            FinalizeType::Plaintext(_) => {}
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `get.dynamic` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used as a key in a `get.dynamic` command"),
        };
        // Get the destination register.
        let destination = get.destination().clone();
        // Ensure the destination register is a locator (and does not reference an access).
        ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
        // Insert the destination register.
        self.add_destination(destination, FinalizeType::Plaintext(get.destination_type().clone()))?;
        Ok(())
    }

    /// Ensures the given `get.or_use` command is well-formed.
    #[inline]
    fn check_get_or_use(&mut self, stack: &Stack<N>, get_or_use: &GetOrUse<N>) -> Result<()> {
        // Retrieve the mapping.
        let (mapping, external_program) = match get_or_use.mapping() {
            CallOperator::Locator(locator) => {
                // Retrieve the program ID.
                let program_id = locator.program_id();
                // Retrieve the mapping_name.
                let mapping_name = locator.resource();

                // Ensure the locator does not reference the current program.
                if stack.program_id() == program_id {
                    bail!("Locator '{locator}' does not reference an external mapping.");
                }
                // Ensure the current program contains an import for this external program.
                if !stack.program().imports().keys().contains(program_id) {
                    bail!("External program '{program_id}' is not imported by '{}'.", stack.program_id());
                }
                // Retrieve the program.
                let external_stack = stack.get_external_stack(program_id)?;
                let external = external_stack.program();
                // Ensure the mapping exists in the program.
                if !external.contains_mapping(mapping_name) {
                    bail!("Mapping '{mapping_name}' in '{program_id}' is not defined.")
                }
                // Retrieve the mapping from the program.
                (external.get_mapping(mapping_name)?, Some(program_id))
            }
            CallOperator::Resource(mapping_name) => {
                // Ensure the declared mapping in `get.or_use` is defined in the current program.
                if !stack.program().contains_mapping(mapping_name) {
                    bail!("Mapping '{mapping_name}' in '{}' is not defined.", stack.program_id())
                }
                // Retrieve the mapping from the program.
                (stack.program().get_mapping(mapping_name)?, None)
            }
        };

        // Get the mapping key type. Qualify if necessary.
        let mapping_key_type = if let Some(external_program) = external_program {
            mapping.key().plaintext_type().clone().qualify(*external_program)
        } else {
            mapping.key().plaintext_type().clone()
        };
        // Get the mapping value type. Qualify if necessary.
        let mapping_value_type = if let Some(external_program) = external_program {
            mapping.value().plaintext_type().clone().qualify(*external_program)
        } else {
            mapping.value().plaintext_type().clone()
        };

        // Retrieve the register type of the key.
        let key_type = match self.get_type_from_operand(stack, get_or_use.key())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `get.or_use` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used as a key in a `get.or_use` command"),
        };
        // Check that the key type in the mapping is equivalent to the key type.
        if !types_equivalent(stack, &mapping_key_type, stack, &key_type)? {
            bail!(
                "Key type in `get.or_use` '{key_type}' does not match the key type in the mapping '{mapping_key_type}'."
            )
        }
        // Retrieve the register type of the default value.
        let default_value_type = match self.get_type_from_operand(stack, get_or_use.default())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A default value cannot be a future"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A default value cannot be a dynamic future"),
        };
        // Check that the value type in the mapping is equivalent to the default value type.
        if !types_equivalent(stack, &mapping_value_type, stack, &default_value_type)? {
            bail!(
                "Default value type in `get.or_use` '{default_value_type}' does not match the value type in the mapping '{mapping_value_type}'."
            )
        }
        // Get the destination register.
        let destination = get_or_use.destination().clone();
        // Ensure the destination register is a locator (and does not reference an access).
        ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
        // Insert the destination register.
        self.add_destination(destination, FinalizeType::Plaintext(default_value_type))?;
        Ok(())
    }

    /// Ensures the given `get.or_use.dynamic` command is well-formed.
    #[inline]
    fn check_get_or_use_dynamic(&mut self, stack: &Stack<N>, get_or_use: &GetOrUseDynamic<N>) -> Result<()> {
        // Check that the program name, network, and mapping are all field or identifier types.
        for operand in
            [get_or_use.program_name_operand(), get_or_use.program_network_operand(), get_or_use.mapping_name_operand()]
        {
            match self.get_type_from_operand(stack, operand)? {
                // If the register is a plaintext type, ensure it is a field or identifier.
                FinalizeType::Plaintext(plaintext_type) => {
                    ensure!(
                        plaintext_type == PlaintextType::Literal(LiteralType::Field)
                            || plaintext_type == PlaintextType::Literal(LiteralType::Identifier),
                        "Operand '{operand}' must be of type 'field' or 'identifier'."
                    )
                }
                // If the register is a future, throw an error.
                FinalizeType::Future(..) => {
                    bail!("A future cannot be used in a `get.or_use.dynamic` command")
                }
                // If the register is a dynamic future, throw an error.
                FinalizeType::DynamicFuture => {
                    bail!("A dynamic future cannot be used in a `get.or_use.dynamic` command")
                }
            }
        }
        // Check the register type of the key.
        match self.get_type_from_operand(stack, get_or_use.key_operand())? {
            // If the register is a plaintext type, do nothing.
            FinalizeType::Plaintext(_) => {}
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `get.or_use.dynamic` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => {
                bail!("A dynamic future cannot be used as a key in a `get.or_use.dynamic` command")
            }
        };
        // Check the register type of the default value.
        match self.get_type_from_operand(stack, get_or_use.default_operand())? {
            // If the register is a plaintext type, check that it matches the destination type.
            FinalizeType::Plaintext(plaintext_type) => {
                ensure!(
                    &plaintext_type == get_or_use.destination_type(),
                    "Default value type in `get.or_use.dynamic` '{plaintext_type}' does not match the destination type '{}'.",
                    get_or_use.destination_type()
                )
            }
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A default value cannot be a future"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A default value cannot be a dynamic future"),
        };
        // Get the destination register.
        let destination = get_or_use.destination().clone();
        // Ensure the destination register is a locator (and does not reference an access).
        ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
        // Insert the destination register.
        self.add_destination(destination, FinalizeType::Plaintext(get_or_use.destination_type().clone()))?;
        Ok(())
    }

    /// Ensure the given `rand.chacha` command is well-formed.
    #[inline]
    fn check_rand_chacha(&mut self, _stack: &Stack<N>, rand_chacha: &RandChaCha<N>) -> Result<()> {
        // Ensure the number of operands is within bounds.
        if rand_chacha.operands().len() > MAX_ADDITIONAL_SEEDS {
            bail!("The number of operands must be <= {MAX_ADDITIONAL_SEEDS}")
        }

        // Get the destination register.
        let destination = rand_chacha.destination().clone();
        // Ensure the destination register is a locator (and does not reference an access).
        ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");

        // Get the destination type.
        let destination_type = rand_chacha.destination_type();
        // Ensure the destination type is allowed.
        ensure!(
            !matches!(destination_type, LiteralType::String | LiteralType::Identifier),
            "Destination type '{destination_type}' is not allowed."
        );

        // Insert the destination register.
        self.add_destination(destination, FinalizeType::Plaintext(PlaintextType::from(destination_type)))?;
        Ok(())
    }

    /// Ensures the given `set` command is well-formed.
    #[inline]
    fn check_set(&self, stack: &Stack<N>, set: &Set<N>) -> Result<()> {
        // Ensure the declared mapping in `set` is defined in the program.
        if !stack.program().contains_mapping(set.mapping_name()) {
            bail!("Mapping '{}' in '{}' is not defined.", set.mapping_name(), stack.program_id())
        }
        // Retrieve the mapping from the program.
        // Note that the unwrap is safe, as we have already checked the mapping exists.
        let mapping = stack.program().get_mapping(set.mapping_name()).unwrap();
        // Get the mapping key type.
        let mapping_key_type = mapping.key().plaintext_type();
        // Get the mapping value type.
        let mapping_value_type = mapping.value().plaintext_type();
        // Retrieve the register type of the key.
        let key_type = match self.get_type_from_operand(stack, set.key())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `set` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used as a key in a `set` command"),
        };
        // Check that the key type in the mapping is equivalent the key type.
        if !types_equivalent(stack, mapping_key_type, stack, &key_type)? {
            bail!("Key type in `set` '{key_type}' does not match the key type in the mapping '{mapping_key_type}'.")
        }
        // Retrieve the type of the value.
        let value_type = match self.get_type_from_operand(stack, set.value())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a value in a `set` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used as a value in a `set` command"),
        };
        // Check that the value type in the mapping is equivalent the type of the value.
        if !types_equivalent(stack, mapping_value_type, stack, &value_type)? {
            bail!(
                "Value type in `set` '{value_type}' does not match the value type in the mapping '{mapping_value_type}'."
            )
        }
        Ok(())
    }

    /// Ensures the given `remove` command is well-formed.
    #[inline]
    fn check_remove(&self, stack: &Stack<N>, remove: &Remove<N>) -> Result<()> {
        // Ensure the declared mapping in `remove` is defined in the program.
        if !stack.program().contains_mapping(remove.mapping_name()) {
            bail!("Mapping '{}' in '{}' is not defined.", remove.mapping_name(), stack.program_id())
        }
        // Retrieve the mapping from the program.
        // Note that the unwrap is safe, as we have already checked the mapping exists.
        let mapping = stack.program().get_mapping(remove.mapping_name()).unwrap();
        // Get the mapping key type.
        let mapping_key_type = mapping.key().plaintext_type();
        // Retrieve the register type of the key.
        let key_type = match self.get_type_from_operand(stack, remove.key())? {
            // If the register is a plaintext type, return it.
            FinalizeType::Plaintext(plaintext_type) => plaintext_type,
            // If the register is a future, throw an error.
            FinalizeType::Future(..) => bail!("A future cannot be used as a key in a `remove` command"),
            // If the register is a dynamic future, throw an error.
            FinalizeType::DynamicFuture => bail!("A dynamic future cannot be used as a key in a `remove` command"),
        };
        // Check that the key type in the mapping is equivalent the key type.
        if !types_equivalent(stack, mapping_key_type, stack, &key_type)? {
            bail!("Key type in `remove` '{key_type}' does not match the key type in the mapping '{mapping_key_type}'.")
        }
        Ok(())
    }

    /// Ensures the given instruction is well-formed.
    #[inline]
    fn check_instruction(&mut self, stack: &Stack<N>, instruction: &Instruction<N>) -> Result<()> {
        // Ensure the opcode is well-formed.
        self.check_instruction_opcode(stack, instruction)?;

        // Initialize a vector to store the register types of the operands.
        let mut operand_types = Vec::with_capacity(instruction.operands().len());
        // Iterate over the operands, and retrieve the register type of each operand.
        for operand in instruction.operands() {
            // Retrieve and append the register type.
            operand_types.push(RegisterType::from(self.get_type_from_operand(stack, operand)?));
        }

        // Compute the destination register types. `CallDynamic` is rejected by
        // `Finalize::add_command` and so is unreachable here; we bail explicitly to keep the
        // assumption checked in code rather than relying solely on the upstream guard.
        let destination_types = match instruction {
            Instruction::CallDynamic(_) => bail!("'call.dynamic' is not allowed in finalize"),
            _ => instruction.output_types(stack, &operand_types)?,
        };

        // Insert the destination register.
        for (destination, destination_type) in instruction.destinations().into_iter().zip_eq(destination_types) {
            // Ensure the destination register is a locator (and does not reference an access).
            ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
            // Ensure that the destination type is a plaintext type.
            let destination_type = match destination_type {
                RegisterType::Plaintext(destination_type) => FinalizeType::Plaintext(destination_type),
                RegisterType::Future(locator) => FinalizeType::Future(locator),
                _ => bail!("Destination type '{destination_type}' must be a plaintext or future type."),
            };
            // Insert the destination register.
            self.add_destination(destination, destination_type)?;
        }
        Ok(())
    }

    /// Ensures the opcode is a valid opcode and corresponds to the correct instruction.
    /// This method is called when adding a new closure or function to the program.
    #[inline]
    fn check_instruction_opcode(&mut self, stack: &Stack<N>, instruction: &Instruction<N>) -> Result<()> {
        match instruction.opcode() {
            Opcode::Literal(opcode) => {
                // Ensure the opcode **is** a reserved opcode.
                ensure!(Program::<N>::is_reserved_opcode(opcode), "'{opcode}' is not an opcode.");
                // Ensure the instruction is not the cast operation.
                ensure!(!matches!(instruction, Instruction::Cast(..)), "Instruction '{instruction}' is a 'cast'.");
                // Ensure the instruction has one destination register.
                ensure!(
                    instruction.destinations().len() == 1,
                    "Instruction '{instruction}' has multiple destinations."
                );
            }
            Opcode::Assert(opcode) => match opcode {
                "assert.eq" => ensure!(
                    matches!(instruction, Instruction::AssertEq(..)),
                    "Instruction '{instruction}' is not for opcode '{opcode}'."
                ),
                "assert.neq" => ensure!(
                    matches!(instruction, Instruction::AssertNeq(..)),
                    "Instruction '{instruction}' is not for opcode '{opcode}'."
                ),
                _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
            },
            Opcode::Async => {
                bail!("Instruction 'async' is not allowed in 'finalize' or 'constructor'.");
            }
            Opcode::Call(_) => {
                // `call` is permitted in finalize only when the target resolves to a view
                // function. (Constructors and views themselves reject `call` at construction
                // time via their `add_command` guards, so the only commands reaching here are
                // from finalize bodies. `Instruction::CallDynamic` is rejected at construction
                // by `Finalize::add_command`, so the `_` arm below is unreachable in practice.)
                let call = match instruction {
                    Instruction::Call(call) => call,
                    _ => bail!("Instruction '{instruction}' is not a 'call' operation."),
                };
                // The self-locator and import-existence checks here intentionally mirror the
                // transition-context `Opcode::Call` arm in
                // `register_types/initialize.rs::check_instruction_opcode`. The two arms
                // diverge on what they allow as a target (views here vs. functions/closures
                // there), but the locator-resolution preamble must remain in sync — keep
                // both sites updated together when changing imports/locator semantics.
                //
                // Hold the external stack (if any) in this binding so the borrowed
                // `target_program` reference stays valid for the view check below.
                let external_stack;
                let (target_program, target_name) = match call.operator() {
                    snarkvm_synthesizer_program::CallOperator::Locator(locator) => {
                        // Cross-program: resolve the external stack and use its program.
                        if stack.program_id() == locator.program_id() {
                            bail!("Locator '{locator}' does not reference an external view.");
                        }
                        if !stack.program().imports().keys().contains(locator.program_id()) {
                            bail!(
                                "External program '{}' is not imported by '{}'.",
                                locator.program_id(),
                                stack.program_id()
                            );
                        }
                        external_stack = stack.get_external_stack(locator.program_id())?;
                        (external_stack.program(), *locator.resource())
                    }
                    snarkvm_synthesizer_program::CallOperator::Resource(name) => (stack.program(), *name),
                };
                if target_program.get_view_ref(&target_name).is_err() {
                    bail!(
                        "Instruction 'call' in finalize must target a view; '{}/{}' is not a view.",
                        target_program.id(),
                        target_name
                    );
                }
            }
            Opcode::Cast(opcode) => match opcode {
                "cast" => {
                    // Retrieve the cast operation.
                    let operation = match instruction {
                        Instruction::Cast(operation) => operation,
                        _ => bail!("Instruction '{instruction}' is not a cast operation."),
                    };

                    // Ensure the instruction has one destination register.
                    ensure!(
                        instruction.destinations().len() == 1,
                        "Instruction '{instruction}' has multiple destinations."
                    );

                    // Ensure the casted register type is defined.
                    match operation.cast_type() {
                        CastType::GroupXCoordinate
                        | CastType::GroupYCoordinate
                        | CastType::Plaintext(PlaintextType::Literal(..)) => {
                            ensure!(instruction.operands().len() == 1, "Expected 1 operand.");
                        }
                        CastType::Plaintext(plaintext @ PlaintextType::Struct(struct_name)) => {
                            // Ensure that the type is valid.
                            RegisterTypes::check_plaintext_type(stack, plaintext)?;
                            // Retrieve the struct.
                            let struct_ = stack.program().get_struct(struct_name)?;
                            // Ensure the operand types match the struct.
                            self.matches_struct(stack, instruction.operands(), struct_)?;
                        }
                        CastType::Plaintext(plaintext @ PlaintextType::ExternalStruct(locator)) => {
                            // Ensure that the type is valid.
                            RegisterTypes::check_plaintext_type(stack, plaintext)?;
                            let external_stack = stack.get_external_stack(locator.program_id())?;
                            let struct_name = locator.resource();
                            // Retrieve the struct.
                            let struct_ = external_stack.program().get_struct(struct_name)?;
                            // Ensure the operand types match the struct.
                            self.matches_struct(&*external_stack, instruction.operands(), struct_)?;
                        }
                        CastType::Plaintext(plaintext @ PlaintextType::Array(array_type)) => {
                            // Ensure that the type is valid.
                            RegisterTypes::check_plaintext_type(stack, plaintext)?;
                            // Ensure the operand types match the element type.
                            self.matches_array(stack, instruction.operands(), array_type)?;
                        }
                        CastType::Record(..) => {
                            bail!("Illegal operation: Cannot cast to a record in a finalize scope.")
                        }
                        CastType::ExternalRecord(_locator) => {
                            bail!("Illegal operation: Cannot cast to an external record in a finalize scope.")
                        }
                        CastType::DynamicRecord => {
                            bail!("Illegal operation: Cannot cast to a dynamic record in a finalize scope.")
                        }
                    }
                }
                "cast.lossy" => {
                    // Retrieve the cast operation.
                    let operation = match instruction {
                        Instruction::CastLossy(operation) => operation,
                        _ => bail!("Instruction '{instruction}' is not a cast.lossy operation."),
                    };

                    // Ensure the instruction has one destination register.
                    ensure!(
                        instruction.destinations().len() == 1,
                        "Instruction '{instruction}' has multiple destinations."
                    );

                    // Ensure the casted register type is valid and defined.
                    match operation.cast_type() {
                        CastType::Plaintext(PlaintextType::Literal(_)) => {
                            ensure!(instruction.operands().len() == 1, "Expected 1 operand.");
                        }
                        _ => bail!("`cast.lossy` is only supported for casting to a literal type."),
                    }
                }
                _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
            },
            Opcode::Command(opcode) => {
                bail!("Fatal error: Cannot check command '{opcode}' as an instruction.")
            }
            Opcode::Commit(opcode) => RegisterTypes::check_commit_opcode(opcode, instruction)?,
            Opcode::Deserialize(opcode) => RegisterTypes::check_deserialize_opcode(opcode, instruction)?,
            Opcode::ECDSA(opcode) => RegisterTypes::check_ecdsa_opcode(opcode, instruction)?,
            Opcode::GetRecordDynamic(_) => {
                bail!("Illegal operation: Cannot read from a dynamic record in a finalize scope.")
            }
            Opcode::Hash(opcode) => RegisterTypes::check_hash_opcode(opcode, instruction)?,
            Opcode::Is(opcode) => match opcode {
                "is.eq" => ensure!(
                    matches!(instruction, Instruction::IsEq(..)),
                    "Instruction '{instruction}' is not for opcode '{opcode}'."
                ),
                "is.neq" => ensure!(
                    matches!(instruction, Instruction::IsNeq(..)),
                    "Instruction '{instruction}' is not for opcode '{opcode}'."
                ),
                _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
            },
            Opcode::Serialize(opcode) => RegisterTypes::check_serialize_opcode(opcode, instruction)?,
            Opcode::Sign(_) => {
                // Ensure the instruction has one destination register.
                ensure!(
                    instruction.destinations().len() == 1,
                    "Instruction '{instruction}' has multiple destinations."
                );
            }
            Opcode::Snark(_) => {
                // Ensure the instruction has one destination register.
                ensure!(
                    instruction.destinations().len() == 1,
                    "Instruction '{instruction}' has multiple destinations."
                );
            }
        }
        Ok(())
    }
}
