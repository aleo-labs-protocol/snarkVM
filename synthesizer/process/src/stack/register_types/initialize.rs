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
    /// Initializes a new instance of `RegisterTypes` for the given closure.
    /// Checks that the given closure is well-formed for the given stack.
    #[inline]
    pub(super) fn initialize_closure_types(stack: &Stack<N>, closure: &Closure<N>) -> Result<Self> {
        // Initialize a map of registers to their types.
        let mut register_types = Self { inputs: IndexMap::new(), destinations: IndexMap::new() };

        // Step 1. Check the inputs are well-formed.
        for input in closure.inputs() {
            // Check the input register type.
            register_types.check_input(stack, input.register(), input.register_type())?;
        }

        // Step 2. Check the instructions are well-formed.
        for instruction in closure.instructions() {
            // Ensure the closure contains no async instructions.
            ensure!(instruction.opcode() != Opcode::Async, "An 'async' instruction is not allowed in closures");
            // Ensure the closure contains no call instructions.
            ensure!(
                !matches!(instruction.opcode(), Opcode::Call(_)),
                "A 'call' instruction is not allowed in closures"
            );
            // Check the instruction opcode, operands, and destinations.
            register_types.check_instruction(stack, closure.name(), instruction)?;
        }

        // Step 3. Check the outputs are well-formed.
        for output in closure.outputs() {
            // Ensure the closure output register is not a static record.
            // ExternalRecord and DynamicRecord are disallowed at V15+ deployment time (see `VM::check_transaction`).
            ensure!(
                !matches!(output.register_type(), RegisterType::Record(..)),
                "Closure outputs do not support records"
            );

            // Check the output operand type.
            register_types.check_output(stack, output.operand(), output.register_type())?;
        }

        Ok(register_types)
    }

    /// Initializes a new instance of `RegisterTypes` for the given function.
    /// Checks that the given function is well-formed for the given stack.
    #[inline]
    pub(super) fn initialize_function_types(stack: &Stack<N>, function: &Function<N>) -> Result<Self> {
        // Initialize a map of registers to their types.
        let mut register_types = Self { inputs: IndexMap::new(), destinations: IndexMap::new() };

        /* Step 1. Check the inputs are well-formed. */

        for input in function.inputs() {
            // TODO (howardwu): In order to support constant inputs, update `Self::deploy()` to allow
            //  the caller to provide optional constant inputs (instead of sampling random constants).
            //  Then, this check can be removed to enable support for constant inputs in functions.
            ensure!(!matches!(input.value_type(), ValueType::Constant(..)), "Constant inputs are not supported");
            ensure!(!matches!(input.value_type(), ValueType::Future(..)), "Future inputs are not supported");

            // Check the input register type.
            register_types.check_input(stack, input.register(), &RegisterType::from(input.value_type().clone()))?;
        }

        /* Step 2. Check the instructions are well-formed. */
        // - If the function has a finalize block, then it must contain exactly one `async` instruction.
        // - If the function has no finalize block, then it must **not** have `async` instructions.
        // - All `call` instructions must precede any `async` instruction.

        let mut async_ = None;
        for instruction in function.instructions() {
            // Check the instruction opcode, operands, and destinations.
            register_types.check_instruction(stack, function.name(), instruction)?;
            // Additional validation.
            match instruction.opcode() {
                Opcode::Async => {
                    // Ensure the function does not contain more than one `async` instruction.
                    ensure!(
                        async_.is_none(),
                        "Function '{}' can contain at most one 'async' instruction",
                        function.name()
                    );
                    // Save the `async` instruction.
                    async_ = match &instruction {
                        Instruction::Async(async_) => Some(async_),
                        _ => bail!("Expected 'async' instruction"),
                    };
                }
                Opcode::Call(_) => {
                    // Ensure the `call` instruction precedes any `async` instruction.
                    ensure!(async_.is_none(), "The 'call' can only be invoked before an 'async' instruction")
                }
                _ => {}
            }
        }

        // Ensure the number of `async` instructions is valid.
        if function.finalize_logic().is_some() {
            ensure!(async_.is_some(), "Function '{}' must contain exactly one 'async' instruction.", function.name());
        } else {
            ensure!(async_.is_none(), "Function '{}' must not contain any 'async' instructions.", function.name());
        }

        /* Step 3. Check the outputs are well-formed. */
        // - If the function has a finalize block, then its last output must be a future associated with itself.
        // - If the function has no finalize block, then it must **not** have `future` outputs.

        let mut num_futures = 0;
        for output in function.outputs() {
            // Check the output operand type.
            register_types.check_output(stack, output.operand(), &RegisterType::from(output.value_type().clone()))?;
            // Additional validation.
            if matches!(output.value_type(), ValueType::Future(..)) {
                num_futures += 1;
            }
        }

        // Ensure the `future` outputs are valid.
        if function.finalize_logic().is_some() {
            ensure!(
                num_futures == 1,
                "Function '{}' must contain exactly one 'future' output, found {num_futures}",
                function.name()
            );
            ensure!(
                match function.outputs().last().map(|output| output.value_type()) {
                    Some(ValueType::Future(locator)) =>
                        locator.program_id() == stack.program_id() && locator.resource() == function.name(),
                    _ => false,
                },
                "The last output of function '{}' must be a future associated with itself",
                function.name()
            );
        } else {
            ensure!(
                num_futures == 0,
                "Function '{}' must not contain any 'future' outputs, found {num_futures}",
                function.name()
            );
        }

        /* Additional checks. */
        // - All futures produced before the `async` call must be consumed by the `async` call.

        // Get all registers containing futures.
        let mut future_registers: IndexSet<Register<N>> = register_types
            .destinations
            .iter()
            .filter_map(|(index, register_type)| match register_type {
                RegisterType::Future(_) => Some(Register::<N>::Locator(*index)),
                RegisterType::DynamicFuture => Some(Register::<N>::Locator(*index)),
                _ => None,
            })
            .collect();

        match async_ {
            // If no `async` instruction exists, then there should not be any future registers.
            None => {
                ensure!(
                    future_registers.is_empty(),
                    "Function '{}' contains futures, but does not contain an 'async' instruction",
                    function.name()
                )
            }
            // Otherwise, check that all the registers were consumed by the `async` call.
            Some(async_) => {
                // Remove the last future, since this is the future created by the `async` call.
                future_registers.pop();
                // Check only the register operands that are `future` types.
                for operand in async_.operands() {
                    if let Operand::Register(register) = operand
                        && matches!(
                            register_types.get_type(stack, register)?,
                            RegisterType::Future(_) | RegisterType::DynamicFuture
                        )
                    {
                        ensure!(
                            future_registers.swap_remove(&register.clone()),
                            "Could not find future register '{register}' produced before the 'async' instruction.",
                        );
                    }
                }
                // Ensure that all the futures created are consumed in the async call.
                ensure!(
                    future_registers.is_empty(),
                    "Function '{}' contains futures, but the 'async' instruction does not consume all of the ones produced.",
                    function.name()
                );
            }
        }

        Ok(register_types)
    }
}

impl<N: Network> RegisterTypes<N> {
    /// Inserts the given input register and type into the registers.
    /// Note: The given input register must be a `Register::Locator`.
    fn add_input(&mut self, register: Register<N>, register_type: RegisterType<N>) -> Result<()> {
        // Ensure there are no destination registers set yet.
        ensure!(self.destinations.is_empty(), "Cannot add input registers after destination registers.");

        // Check the input register.
        match register {
            Register::Locator(locator) => {
                // Ensure the registers are monotonically increasing.
                ensure!(self.inputs.len() as u64 == locator, "Register '{register}' is out of order");

                // Insert the input register and type.
                match self.inputs.insert(locator, register_type) {
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
    fn add_destination(&mut self, register: Register<N>, register_type: RegisterType<N>) -> Result<()> {
        // Check the destination register.
        match register {
            Register::Locator(locator) => {
                // Ensure the registers are monotonically increasing.
                let expected_locator = (self.inputs.len() as u64) + self.destinations.len() as u64;
                ensure!(expected_locator == locator, "Register '{register}' is out of order");

                // Insert the destination register and type.
                match self.destinations.insert(locator, register_type) {
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

impl<N: Network> RegisterTypes<N> {
    /// Ensure the given input register is well-formed.
    #[inline]
    fn check_input(&mut self, stack: &Stack<N>, register: &Register<N>, register_type: &RegisterType<N>) -> Result<()> {
        // Ensure the register type is defined in the program.
        match register_type {
            RegisterType::Plaintext(plaintext_type) => Self::check_plaintext_type(stack, plaintext_type)?,
            RegisterType::Record(identifier) => {
                // Ensure the record type is defined in the program.
                if !stack.program().contains_record(identifier) {
                    bail!("Record '{identifier}' in '{}' is not defined.", stack.program_id())
                }
            }
            RegisterType::ExternalRecord(locator) => {
                // Get the external stack.
                let external_stack = stack.get_external_stack(locator.program_id())?;
                // Ensure the external record type is defined in the program.
                if !external_stack.program().contains_record(locator.resource()) {
                    bail!("External record '{locator}' in '{}' is not defined.", external_stack.program_id())
                }
            }
            RegisterType::Future(..) => bail!("Input '{register}' cannot be a future."),
            // Note. Checks for dynamic records are enforced at runtime.
            RegisterType::DynamicRecord => (),
            RegisterType::DynamicFuture => bail!("Input '{register}' cannot be a dynamic future."),
        };

        // Insert the input register.
        self.add_input(register.clone(), register_type.clone())?;

        // Ensure the register type and the input type match.
        if *register_type != self.get_type(stack, register)? {
            bail!("Input '{register}' does not match the expected input register type.")
        }
        Ok(())
    }

    /// Ensure the given output register is well-formed.
    fn check_output(&self, stack: &Stack<N>, operand: &Operand<N>, register_type: &RegisterType<N>) -> Result<()> {
        match operand {
            // Inform the user the output operand is an input register, to ensure this is intended behavior.
            Operand::Register(register) if self.is_input(register) => {
                dev_eprintln!(
                    "Output {operand} in '{}' is an input register, ensure this is intended",
                    stack.program_id()
                );
            }
            // Inform the user the output operand is a literal, to ensure this is intended behavior.
            Operand::Literal(..) => {
                dev_eprintln!("Output {operand} in '{}' is a literal, ensure this is intended", stack.program_id());
            }
            // Otherwise, do nothing.
            _ => (),
        }

        // Ensure the register type is defined in the program.
        match register_type {
            RegisterType::Plaintext(plaintext_type) => Self::check_plaintext_type(stack, plaintext_type)?,
            RegisterType::Record(identifier) => {
                // Ensure the record type is defined in the program.
                if !stack.program().contains_record(identifier) {
                    bail!("Record '{identifier}' in '{}' is not defined.", stack.program_id())
                }
            }
            RegisterType::ExternalRecord(locator) => {
                // Get the external stack.
                let external_stack = stack.get_external_stack(locator.program_id())?;
                // Ensure the external record type is defined in the program.
                if !external_stack.program().contains_record(locator.resource()) {
                    bail!("External record '{locator}' in '{}' is not defined.", external_stack.program_id())
                }
            }
            RegisterType::Future(locator) => {
                // Ensure that the locator is defined.
                match locator.program_id() == stack.program_id() {
                    true => stack.get_function(locator.resource())?,
                    false => {
                        stack.get_external_stack(locator.program_id())?.program().get_function(locator.resource())?
                    }
                };
            }
            RegisterType::DynamicRecord => {} // Dynamic records are valid outputs.
            RegisterType::DynamicFuture => bail!("Output '{operand}' cannot be a dynamic future."),
        };

        // Ensure the operand type and the output type match.
        let operand_type = self.get_type_from_operand(stack, operand)?;
        if !register_types_equivalent(stack, register_type, stack, &operand_type)? {
            bail!(
                "Output '{operand}' does not match the expected output operand type: expected '{operand_type}', found '{register_type}'",
            )
        }
        Ok(())
    }

    /// Ensures the given instruction is well-formed.
    #[inline]
    fn check_instruction(
        &mut self,
        stack: &Stack<N>,
        closure_or_function_name: &Identifier<N>,
        instruction: &Instruction<N>,
    ) -> Result<()> {
        // Ensure the opcode is well-formed.
        self.check_instruction_opcode(stack, closure_or_function_name, instruction)?;

        // Initialize a vector to store the register types of the operands.
        let mut operand_types = Vec::with_capacity(instruction.operands().len());
        // Iterate over the operands, and retrieve the register type of each operand.
        for operand in instruction.operands() {
            // Retrieve and append the register type.
            operand_types.push(self.get_type_from_operand(stack, operand)?);
        }

        // Compute the destination register types.
        let destination_types = instruction.output_types(stack, &operand_types)?;

        // Insert the destination register.
        for (destination, destination_type) in instruction.destinations().into_iter().zip_eq(destination_types) {
            // Ensure the destination register is a locator (and does not reference an access).
            ensure!(matches!(destination, Register::Locator(..)), "Destination '{destination}' must be a locator.");
            // Insert the destination register.
            self.add_destination(destination, destination_type)?;
        }
        Ok(())
    }

    /// Ensures the opcode is a valid opcode and corresponds to the correct instruction.
    /// This method is called when adding a new closure or function to the program.
    fn check_instruction_opcode(
        &self,
        stack: &Stack<N>,
        closure_or_function_name: &Identifier<N>,
        instruction: &Instruction<N>,
    ) -> Result<()> {
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
                // Retrieve the async operation.
                let async_ = match instruction {
                    Instruction::Async(async_) => async_,
                    _ => bail!("Instruction '{instruction}' is not an async operation."),
                };

                // Ensure the function name matches the one in the operation.
                ensure!(
                    async_.function_name() == closure_or_function_name,
                    "Instruction '{instruction}' does not match the function name '{closure_or_function_name}'."
                );
            }
            Opcode::Call(_) => {
                // The self-locator and import-existence checks here intentionally mirror the
                // finalize-context `Opcode::Call` arm in
                // `finalize_types/initialize.rs::check_instruction_opcode`. The two arms
                // diverge on what they allow as a target (functions/closures here vs. views
                // there), but the locator-resolution preamble must remain in sync — keep
                // both sites updated together when changing imports/locator semantics.
                //
                // Validate the call operation.
                match instruction {
                    Instruction::Call(call) => {
                        match call.operator() {
                            CallOperator::Locator(locator) => {
                                // Retrieve the program ID.
                                let program_id = locator.program_id();
                                // Retrieve the resource from the locator.
                                let resource = locator.resource();

                                // Ensure the locator does not reference the current program.
                                if stack.program_id() == program_id {
                                    bail!("Locator '{locator}' does not reference an external program.");
                                }
                                // Ensure the current program contains an import for this external program.
                                if !stack.program().imports().keys().contains(program_id) {
                                    bail!(
                                        "External program '{}' is not imported by '{program_id}'.",
                                        locator.program_id()
                                    );
                                }

                                // Retrieve the program.
                                let external_stack = stack.get_external_stack(program_id)?;
                                let external = external_stack.program();
                                // Check that function exists in the program.
                                if let Ok(child_function) = external.get_function_ref(resource) {
                                    // If the child function contains a finalize block, then the parent function must also contain a finalize block.
                                    let child_contains_finalize = child_function.finalize_logic().is_some();
                                    let parent_contains_finalize =
                                        stack.get_function_ref(closure_or_function_name)?.finalize_logic().is_some();
                                    if child_contains_finalize && !parent_contains_finalize {
                                        bail!(
                                            "Function '{}/{closure_or_function_name}' must contain a finalize block, since it calls '{}/{resource}'.",
                                            stack.program_id(),
                                            program_id
                                        )
                                    }
                                }
                                // Otherwise, ensure the closure exists in the program.
                                else if !external.contains_closure(resource) {
                                    bail!("'{resource}' is not defined in '{}'.", external.id())
                                }
                            }
                            CallOperator::Resource(resource) => {
                                // Ensure the resource does not reference this closure or function.
                                if resource == closure_or_function_name {
                                    bail!("Cannot invoke 'call' to self (in '{resource}'): self-recursive call.")
                                }

                                // TODO (howardwu): Revisit this decision to forbid calling internal functions. A record cannot be spent again.
                                //  But there are legitimate uses for passing a record through to an internal function.
                                //  We could invoke the internal function without a state transition, but need to match visibility.
                                if stack.program().contains_function(resource) {
                                    bail!(
                                        "Cannot call '{resource}' from '{closure_or_function_name}'. Use a closure ('closure {resource}:') instead."
                                    )
                                }
                                // Ensure the function or closure exists in the program.
                                // if !self.program.contains_function(resource) && !self.program.contains_closure(resource) {
                                if !stack.program().contains_closure(resource) {
                                    bail!("'{resource}' is not defined in '{}'.", stack.program_id())
                                }
                            }
                        }
                    }
                    Instruction::CallDynamic(_) => {} // We do not validate the targets of dynamic calls before hand.
                    _ => bail!("Instruction '{instruction}' is not a call operation."),
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
                            // Ensure the type is valid.
                            Self::check_plaintext_type(stack, plaintext)?;
                            // Retrieve the struct.
                            let struct_ = stack.program().get_struct(struct_name)?;
                            // Ensure the operand types match the struct.
                            self.matches_struct(stack, stack, instruction.operands(), struct_)?;
                        }
                        CastType::Plaintext(plaintext @ PlaintextType::ExternalStruct(locator)) => {
                            // Ensure the type is valid.
                            Self::check_plaintext_type(stack, plaintext)?;
                            let external_stack = stack.get_external_stack(locator.program_id())?;
                            let struct_name = locator.resource();
                            // Retrieve the struct.
                            let struct_ = external_stack.program().get_struct(struct_name)?;
                            // Ensure the operand types match the struct.
                            self.matches_struct(stack, &*external_stack, instruction.operands(), struct_)?;
                        }
                        CastType::Plaintext(plaintext @ PlaintextType::Array(array_type)) => {
                            // Ensure the type is valid.
                            Self::check_plaintext_type(stack, plaintext)?;
                            // Ensure the operand types match the element type.
                            self.matches_array(stack, instruction.operands(), array_type)?;
                        }
                        CastType::Record(record_name) => {
                            // Ensure the record type is defined in the program.
                            if !stack.program().contains_record(record_name) {
                                bail!("Record '{record_name}' is not defined.")
                            }
                            // Retrieve the record type.
                            let record_type = stack.program().get_record(record_name)?;
                            // Ensure the operand types match the record type.
                            self.matches_record(stack, instruction.operands(), record_type)?;
                        }
                        CastType::ExternalRecord(_locator) => {
                            bail!("Illegal operation: Cannot cast to an external record.")
                        }
                        CastType::DynamicRecord => {
                            ensure!(instruction.operands().len() == 1, "Cast to dynamic record expected 1 operand.");
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
                bail!("Forbidden operation: Instruction '{instruction}' cannot invoke command '{opcode}'.");
            }
            Opcode::Commit(opcode) => Self::check_commit_opcode(opcode, instruction)?,
            Opcode::Deserialize(opcode) => Self::check_deserialize_opcode(opcode, instruction)?,
            Opcode::ECDSA(opcode) => {
                bail!("Forbidden operation: Instruction '{instruction}' cannot invoke command '{opcode}'.")
            }
            Opcode::GetRecordDynamic(_) => {
                ensure!(instruction.operands().len() == 1, "Expected 1 operand.");
                ensure!(
                    instruction.destinations().len() == 1,
                    "Instruction '{instruction}' has multiple destinations."
                );
                ensure!(
                    matches!(instruction, Instruction::GetRecordDynamic(..)),
                    "Instruction '{instruction}' is not a get.record.dynamic operation."
                );
            }
            Opcode::Hash(opcode) => Self::check_hash_opcode(opcode, instruction)?,
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
            Opcode::Serialize(opcode) => Self::check_serialize_opcode(opcode, instruction)?,
            Opcode::Sign(_) => {
                // Ensure the instruction has one destination register.
                ensure!(
                    instruction.destinations().len() == 1,
                    "Instruction '{instruction}' has multiple destinations."
                );
            }
            Opcode::Snark(opcode) => {
                bail!("Forbidden operation: Instruction '{instruction}' cannot invoke command '{opcode}'.")
            }
        }
        Ok(())
    }
}

impl<N: Network> RegisterTypes<N> {
    /// Ensure any struct referenced directly or otherwise exists.
    pub fn check_plaintext_type(stack: &Stack<N>, type_: &PlaintextType<N>) -> Result<()> {
        // Track the `(program, struct)` pairs that have already been fully verified, so that a struct shared by
        // many members is expanded at most once. Without this, a program in which every member of each struct
        // refers to the same earlier struct forms an acyclic graph with exponentially many paths, and the walk
        // below would make up to `MAX_STRUCT_ENTRIES ^ MAX_STRUCTS` recursive calls.
        let mut visited = HashSet::new();
        Self::check_plaintext_type_inner(stack, type_, &mut visited)
    }

    /// The memoized inner traversal for [`Self::check_plaintext_type`].
    ///
    /// `visited` is keyed on `(program_id, struct_name)` rather than `struct_name` alone, since an external struct
    /// resolves against a different program whose struct names may collide with the current program's.
    fn check_plaintext_type_inner(
        stack: &Stack<N>,
        type_: &PlaintextType<N>,
        visited: &mut HashSet<(ProgramID<N>, Identifier<N>)>,
    ) -> Result<()> {
        match type_ {
            PlaintextType::Literal(..) => Ok(()),
            PlaintextType::Struct(struct_name) => {
                // If this struct has already been verified in the current traversal, there is nothing left to check.
                // Insert before recursing; struct references are guaranteed acyclic by `Program::add_struct`, so this
                // only short-circuits shared subgraphs and never hides an in-progress struct from itself.
                if !visited.insert((*stack.program_id(), *struct_name)) {
                    return Ok(());
                }
                // Retrieve the struct from the program.
                let Ok(struct_) = stack.program().get_struct(struct_name) else {
                    bail!("Struct '{struct_name}' in '{}' is not defined.", stack.program_id())
                };
                struct_
                    .members()
                    .values()
                    .try_for_each(|member| Self::check_plaintext_type_inner(stack, member, visited))
            }
            PlaintextType::ExternalStruct(locator) => {
                let external_stack = stack.get_external_stack(locator.program_id())?;
                let struct_type = PlaintextType::Struct(*locator.resource());
                Self::check_plaintext_type_inner(&external_stack, &struct_type, visited)
            }
            PlaintextType::Array(array_type) => {
                Self::check_plaintext_type_inner(stack, array_type.base_element_type(), visited)
            }
        }
    }

    /// Ensures the opcode is a valid opcode and corresponds to the `commit` instruction.
    #[inline]
    pub(crate) fn check_commit_opcode(opcode: &str, instruction: &Instruction<N>) -> Result<()> {
        // Ensure the instruction is the correct one.
        match opcode {
            "commit.bhp256" => ensure!(
                matches!(instruction, Instruction::CommitBHP256(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.bhp512" => ensure!(
                matches!(instruction, Instruction::CommitBHP512(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.bhp768" => ensure!(
                matches!(instruction, Instruction::CommitBHP768(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.bhp1024" => ensure!(
                matches!(instruction, Instruction::CommitBHP1024(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.ped64" => ensure!(
                matches!(instruction, Instruction::CommitPED64(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.ped128" => ensure!(
                matches!(instruction, Instruction::CommitPED128(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.bhp256.raw" => ensure!(
                matches!(instruction, Instruction::CommitBHP256Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.bhp512.raw" => ensure!(
                matches!(instruction, Instruction::CommitBHP512Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.bhp768.raw" => ensure!(
                matches!(instruction, Instruction::CommitBHP768Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.bhp1024.raw" => ensure!(
                matches!(instruction, Instruction::CommitBHP1024Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.ped64.raw" => ensure!(
                matches!(instruction, Instruction::CommitPED64Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "commit.ped128.raw" => ensure!(
                matches!(instruction, Instruction::CommitPED128Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
        }
        Ok(())
    }

    /// Ensures the opcode is a valid opcode and corresponds to the `hash` instruction.
    #[inline]
    pub(crate) fn check_hash_opcode(opcode: &str, instruction: &Instruction<N>) -> Result<()> {
        // Ensure the instruction is the correct one.
        match opcode {
            "hash.bhp256" => ensure!(
                matches!(instruction, Instruction::HashBHP256(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.bhp512" => ensure!(
                matches!(instruction, Instruction::HashBHP512(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.bhp768" => ensure!(
                matches!(instruction, Instruction::HashBHP768(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.bhp1024" => ensure!(
                matches!(instruction, Instruction::HashBHP1024(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak256" => ensure!(
                matches!(instruction, Instruction::HashKeccak256(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak384" => ensure!(
                matches!(instruction, Instruction::HashKeccak384(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak512" => ensure!(
                matches!(instruction, Instruction::HashKeccak512(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.ped64" => ensure!(
                matches!(instruction, Instruction::HashPED64(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.ped128" => ensure!(
                matches!(instruction, Instruction::HashPED128(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.psd2" => ensure!(
                matches!(instruction, Instruction::HashPSD2(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.psd4" => ensure!(
                matches!(instruction, Instruction::HashPSD4(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.psd8" => ensure!(
                matches!(instruction, Instruction::HashPSD8(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_256" => ensure!(
                matches!(instruction, Instruction::HashSha3_256(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_384" => ensure!(
                matches!(instruction, Instruction::HashSha3_384(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_512" => ensure!(
                matches!(instruction, Instruction::HashSha3_512(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash_many.psd2" => ensure!(
                matches!(instruction, Instruction::HashManyPSD2(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash_many.psd4" => ensure!(
                matches!(instruction, Instruction::HashManyPSD4(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash_many.psd8" => ensure!(
                matches!(instruction, Instruction::HashManyPSD8(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.bhp256.raw" => ensure!(
                matches!(instruction, Instruction::HashBHP256Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.bhp512.raw" => ensure!(
                matches!(instruction, Instruction::HashBHP512Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.bhp768.raw" => ensure!(
                matches!(instruction, Instruction::HashBHP768Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.bhp1024.raw" => ensure!(
                matches!(instruction, Instruction::HashBHP1024Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak256.raw" => ensure!(
                matches!(instruction, Instruction::HashKeccak256Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak384.raw" => ensure!(
                matches!(instruction, Instruction::HashKeccak384Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak512.raw" => ensure!(
                matches!(instruction, Instruction::HashKeccak512Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.ped64.raw" => ensure!(
                matches!(instruction, Instruction::HashPED64Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.ped128.raw" => ensure!(
                matches!(instruction, Instruction::HashPED128Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.psd2.raw" => ensure!(
                matches!(instruction, Instruction::HashPSD2Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.psd4.raw" => ensure!(
                matches!(instruction, Instruction::HashPSD4Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.psd8.raw" => ensure!(
                matches!(instruction, Instruction::HashPSD8Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_256.raw" => ensure!(
                matches!(instruction, Instruction::HashSha3_256Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_384.raw" => ensure!(
                matches!(instruction, Instruction::HashSha3_384Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_512.raw" => ensure!(
                matches!(instruction, Instruction::HashSha3_512Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak256.native" => ensure!(
                matches!(instruction, Instruction::HashKeccak256Native(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak256.native.raw" => ensure!(
                matches!(instruction, Instruction::HashKeccak256NativeRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak384.native" => ensure!(
                matches!(instruction, Instruction::HashKeccak384Native(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak384.native.raw" => ensure!(
                matches!(instruction, Instruction::HashKeccak384NativeRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak512.native" => ensure!(
                matches!(instruction, Instruction::HashKeccak512Native(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.keccak512.native.raw" => ensure!(
                matches!(instruction, Instruction::HashKeccak512NativeRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_256.native" => ensure!(
                matches!(instruction, Instruction::HashSha3_256Native(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_256.native.raw" => ensure!(
                matches!(instruction, Instruction::HashSha3_256NativeRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_384.native" => ensure!(
                matches!(instruction, Instruction::HashSha3_384Native(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_384.native.raw" => ensure!(
                matches!(instruction, Instruction::HashSha3_384NativeRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_512.native" => ensure!(
                matches!(instruction, Instruction::HashSha3_512Native(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "hash.sha3_512.native.raw" => ensure!(
                matches!(instruction, Instruction::HashSha3_512NativeRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
        }
        Ok(())
    }

    /// Ensures the opcode is a valid opcode and corresponds to the `ecdsa.verify` instruction.
    #[inline]
    pub(crate) fn check_ecdsa_opcode(opcode: &str, instruction: &Instruction<N>) -> Result<()> {
        // Ensure the instruction has one destination register.
        ensure!(instruction.destinations().len() == 1, "Instruction '{instruction}' has multiple destinations.");
        // Ensure the instruction is the correct one.
        match opcode {
            "ecdsa.verify.digest" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyDigest(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.digest.eth" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyDigestEth(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak256" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak256(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak256.raw" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak256Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak256.eth" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak256Eth(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak384" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak384(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak384.raw" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak384Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak384.eth" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak384Eth(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak512" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak512(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak512.raw" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak512Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.keccak512.eth" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifyKeccak512Eth(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_256" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_256(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_256.raw" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_256Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_256.eth" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_256Eth(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_384" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_384(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_384.raw" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_384Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_384.eth" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_384Eth(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_512" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_512(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_512.raw" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_512Raw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "ecdsa.verify.sha3_512.eth" => ensure!(
                matches!(instruction, Instruction::ECDSAVerifySha3_512Eth(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
        }
        Ok(())
    }

    /// Ensures the opcode is a valid opcode and corresponds to the `serialize` instruction.
    #[inline]
    pub(crate) fn check_serialize_opcode(opcode: &str, instruction: &Instruction<N>) -> Result<()> {
        // Ensure that the instruction has exactly one operand register.
        ensure!(instruction.operands().len() == 1, "Instruction '{instruction}' must have exactly one operand.");
        // Ensure the instruction has one destination register.
        ensure!(instruction.destinations().len() == 1, "Instruction '{instruction}' has multiple destinations.");
        // Ensure the instruction is the correct one.
        match opcode {
            "serialize.bits" => ensure!(
                matches!(instruction, Instruction::SerializeBits(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "serialize.bits.raw" => ensure!(
                matches!(instruction, Instruction::SerializeBitsRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
        }
        Ok(())
    }

    /// Ensures the opcode is a valid opcode and corresponds to the `deserialize` instruction.
    #[inline]
    pub(crate) fn check_deserialize_opcode(opcode: &str, instruction: &Instruction<N>) -> Result<()> {
        // Ensure that the instruction has exactly one operand register.
        ensure!(instruction.operands().len() == 1, "Instruction '{instruction}' must have exactly one operand.");
        // Ensure the instruction has one destination register.
        ensure!(instruction.destinations().len() == 1, "Instruction '{instruction}' has multiple destinations.");
        // Ensure the instruction is the correct one.
        match opcode {
            "deserialize.bits" => ensure!(
                matches!(instruction, Instruction::DeserializeBits(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            "deserialize.bits.raw" => ensure!(
                matches!(instruction, Instruction::DeserializeBitsRaw(..)),
                "Instruction '{instruction}' is not for opcode '{opcode}'."
            ),
            _ => bail!("Instruction '{instruction}' is not for opcode '{opcode}'."),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Process;

    use std::{fmt::Write as _, sync::mpsc, thread, time::Duration};

    type CurrentNetwork = MainnetV0;

    /// Builds a program named `name` whose `depth` structs each have `MAX_STRUCT_ENTRIES` members, where every
    /// member of `s{k}` refers to `s{k-1}` (and every member of `s0` is a `field`). A function input of type
    /// `s{depth - 1}` therefore references an acyclic struct graph with `MAX_STRUCT_ENTRIES ^ (depth - 1)`
    /// distinct root-to-leaf paths — the shape exploited by the type-validation DoS.
    ///
    /// `function` is passed `depth - 1` and returns the body of the `compute` function, so that each test can
    /// drive a different type-checking walker over that graph.
    fn sample_shared_struct_program(
        name: &str,
        depth: usize,
        function: impl FnOnce(usize) -> String,
    ) -> Program<CurrentNetwork> {
        assert!(depth >= 1);
        let mut source = format!("program {name}.aleo;\n\n");
        for level in 0..depth {
            writeln!(source, "struct s{level}:").unwrap();
            let member_type = if level == 0 { "field".to_string() } else { format!("s{}", level - 1) };
            for member in 0..CurrentNetwork::MAX_STRUCT_ENTRIES {
                writeln!(source, "    m{member} as {member_type};").unwrap();
            }
            source.push('\n');
        }
        writeln!(source, "function compute:\n{}", function(depth - 1)).unwrap();
        source.push_str("\nconstructor:\n    assert.eq true true;\n");
        Program::from_str(&source).unwrap()
    }

    #[test]
    fn test_check_plaintext_type_shared_struct_dag_terminates() {
        // A 12-level, 32-member-per-struct program: without memoization this induces hundreds of trillions of
        // calls in `check_plaintext_type`, so `Stack::new` would never return. With memoization each
        // `(program, struct)` pair is expanded once, so validation completes near-instantly.
        //
        // The traversal is run on a detached thread so that the missing-memoization regression surfaces as a
        // bounded timeout failure rather than hanging the test suite indefinitely.
        let program = sample_shared_struct_program("testing_dag", 12, |top| format!("    input r0 as s{top}.private;"));

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let process = Process::<CurrentNetwork>::load().expect("Failed to load process");
            // `Stack::new` runs `check_plaintext_type` over the `compute` input's struct graph.
            let is_ok = Stack::new(&process, &program).is_ok();
            let _ = sender.send(is_ok);
        });

        // 5 minutes is generous even if the CI machine is heavily loaded.
        match receiver.recv_timeout(Duration::from_secs(300)) {
            Ok(true) => {}
            Ok(false) => panic!("Stack::new rejected a well-formed shared-struct program"),
            Err(_) => panic!(
                "check_plaintext_type did not terminate within 300s: the shared-struct graph is being re-expanded \
                 exponentially (memoization is missing)"
            ),
        }
    }

    #[test]
    fn test_size_in_bits_shared_struct_dag_terminates() {
        // `hash.bhp256` computes `size_in_bits` of its operand type during `Stack::new` type-checking. Without
        // memoization this recurses over the shared-struct DAG exponentially and never returns. With memoization
        // the walk is linear and `Stack::new` returns promptly. (The deployment is then rejected for an unrelated
        // reason - the struct's bit size overflows `usize` - so only termination is asserted here.)
        let program = sample_shared_struct_program("testing_dag_hash", 12, |top| {
            format!(
                "    input r0 as s{top}.private;\n    hash.bhp256 r0 into r1 as field;\n    output r1 as field.private;"
            )
        });

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let process = Process::<CurrentNetwork>::load().expect("Failed to load process");
            // We only assert that type-checking terminates; the deployment itself may still be rejected.
            let _ = Stack::new(&process, &program);
            let _ = sender.send(());
        });

        // 5 minutes is generous even if the CI machine is heavily loaded.
        match receiver.recv_timeout(Duration::from_secs(300)) {
            Ok(()) => {}
            Err(_) => panic!(
                "size_in_bits did not terminate within 300s: the shared-struct type is being sized \
                 exponentially (memoization is missing)"
            ),
        }
    }

    #[test]
    fn test_types_equivalent_shared_struct_dag_terminates() {
        // `is.eq` on two shared-struct-DAG operands runs `register_types_equivalent` -> `types_equivalent`
        // during `Stack::new` type-checking. Without memoization this compares hundreds of trillions of member
        // pairs and never returns; with memoization each `(program, program, struct)` triple is compared once.
        let program = sample_shared_struct_program("testing_dag_eq", 12, |top| {
            format!(
                "    input r0 as s{top}.private;\n    input r1 as s{top}.private;\n    is.eq r0 r1 into r2;\n    \
                 output r2 as boolean.private;"
            )
        });

        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let process = Process::<CurrentNetwork>::load().expect("Failed to load process");
            let is_ok = Stack::new(&process, &program).is_ok();
            let _ = sender.send(is_ok);
        });

        // 5 minutes is generous even if the CI machine is heavily loaded.
        match receiver.recv_timeout(Duration::from_secs(300)) {
            Ok(true) => {}
            Ok(false) => panic!("Stack::new rejected a well-formed program using is.eq on shared structs"),
            Err(_) => panic!(
                "types_equivalent did not terminate within 300s: shared-struct comparison is being expanded \
                 exponentially (memoization is missing)"
            ),
        }
    }
}
