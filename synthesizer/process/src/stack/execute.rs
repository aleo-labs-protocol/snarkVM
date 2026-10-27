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
    /// Executes a program closure on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    pub fn execute_closure<A: circuit::Aleo<Network = N>>(
        &self,
        closure: &Closure<N>,
        inputs: &[circuit::Value<A>],
        call_stack: CallStack<N>,
        signer: circuit::Address<A>,
        caller: circuit::Address<A>,
        tvk: circuit::Field<A>,
    ) -> Result<Vec<circuit::Value<A>>, StackExecError> {
        let timer = timer!("Stack::execute_closure");

        // Ensure the call stack is not `Evaluate`.
        if matches!(call_stack, CallStack::Evaluate(..)) {
            return Err(anyhow!("Illegal operation: cannot evaluate in execute mode").into());
        }

        // Ensure the number of inputs matches the number of input statements.
        if closure.inputs().len() != inputs.len() {
            return Err(anyhow!("Expected {} inputs, found {}", closure.inputs().len(), inputs.len()).into());
        }
        lap!(timer, "Check the number of inputs");

        // Retrieve the number of public variables in the circuit.
        let num_public = A::num_public();

        // Initialize the registers.
        let mut registers = Registers::new(call_stack, self.get_register_types(closure.name())?.clone());

        use circuit::Eject;

        // Set the transaction signer.
        registers.set_signer(signer.eject_value());
        // Set the transition signer, as a circuit.
        registers.set_signer_circuit(signer);
        // Set the transaction caller.
        registers.set_caller(caller.eject_value());
        // Set the transition caller, as a circuit.
        registers.set_caller_circuit(caller);
        // Set the transition view key.
        registers.set_tvk(tvk.eject_value());
        // Set the transition view key, as a circuit.
        registers.set_tvk_circuit(tvk);
        lap!(timer, "Initialize the registers");

        // Store the inputs.
        closure.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            // If the circuit is in execute mode, then store the console input.
            if let CallStack::Execute(..) = registers.call_stack_ref() {
                // Assign the console input to the register.
                registers.store(self, register, input.eject_value())?;
            }
            // Assign the circuit input to the register.
            registers.store_circuit(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");

        // Execute the instructions.
        for (ix, instruction) in closure.instructions().iter().enumerate() {
            // If the circuit is in execute mode, then evaluate the instructions.
            if let CallStack::Execute(..) = registers.call_stack_ref() {
                // If the evaluation fails, bail and return the error.
                if let Err(error) = instruction.evaluate(self, &mut registers) {
                    let err = InstructionError::Eval(error.into());
                    return Err(IndexedInstructionError::new(ix, format!("{instruction}"), err).into());
                }
            }
            // Execute the instruction.
            if let Err(error) = instruction.execute(self, &mut registers) {
                let err = InstructionError::Exec(error.into());
                return Err(IndexedInstructionError::new(ix, format!("{instruction}"), err).into());
            }
        }
        lap!(timer, "Execute the instructions");

        // Ensure the number of public variables remains the same.
        if A::num_public() != num_public {
            return Err(anyhow!("Illegal closure operation: instructions injected public variables").into());
        }

        use circuit::Inject;

        // Load the outputs.
        let outputs = closure
            .outputs()
            .iter()
            .map(|output| -> Result<_> {
                match output.operand() {
                    // If the operand is a literal, use the literal directly.
                    Operand::Literal(literal) => Ok(circuit::Value::Plaintext(circuit::Plaintext::from(
                        circuit::Literal::new(circuit::Mode::Constant, literal.clone()),
                    ))),
                    // If the operand is a register, retrieve the stack value from the register.
                    Operand::Register(register) => registers.load_circuit(self, &Operand::Register(register.clone())),
                    // If the operand is the program ID, convert the program ID into an address.
                    Operand::ProgramID(program_id) => {
                        Ok(circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Address(
                            circuit::Address::new(circuit::Mode::Constant, program_id.to_address()?),
                        ))))
                    }
                    // If the operand is the signer, retrieve the signer from the registers.
                    Operand::Signer => Ok(circuit::Value::Plaintext(circuit::Plaintext::from(
                        circuit::Literal::Address(registers.signer_circuit()?),
                    ))),
                    // If the operand is the caller, retrieve the caller from the registers.
                    Operand::Caller => Ok(circuit::Value::Plaintext(circuit::Plaintext::from(
                        circuit::Literal::Address(registers.caller_circuit()?),
                    ))),
                    // If the operand is the generator, retrieve the Aleo generator.
                    Operand::AleoGenerator => A::g_powers()
                        .first()
                        .map(|element| {
                            circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Group(
                                element.clone(),
                            )))
                        })
                        .ok_or_else(|| anyhow!("Failed to retrieve the Aleo generator")),
                    // If the operand is the generator powers, retrieve the generator powers or the indexed group.
                    Operand::AleoGeneratorPowers(index) => match index {
                        None => Ok(circuit::Value::Plaintext(circuit::Plaintext::Array(
                            A::g_powers()
                                .into_iter()
                                .map(|element| circuit::Plaintext::from(circuit::Literal::Group(element)))
                                .collect(),
                            OnceCell::new(),
                        ))),
                        Some(index) => A::g_powers()
                            .get(**index as usize)
                            .map(|element| {
                                circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Group(
                                    element.clone(),
                                )))
                            })
                            .ok_or_else(|| anyhow!("Index {index} out of bounds for Aleo generator")),
                    },
                    // If the operand is the block height, throw an error.
                    Operand::BlockHeight => {
                        bail!("Illegal operation: cannot retrieve the block height in a closure scope")
                    }
                    // If the operand is the block timestamp, throw an error.
                    Operand::BlockTimestamp => {
                        bail!("Illegal operation: cannot retrieve the block timestamp in a closure scope")
                    }
                    // If the operand is the network id, throw an error.
                    Operand::NetworkID => {
                        bail!("Illegal operation: cannot retrieve the network id in a closure scope")
                    }
                    // If the operand is the checksum, throw an error.
                    Operand::Checksum(_) => bail!("Illegal operation: cannot retrieve the checksum in a closure scope"),
                    // If the operand is the edition, throw an error.
                    Operand::Edition(_) => bail!("Illegal operation: cannot retrieve the edition in a closure scope"),
                    // If the operand is the program owner, throw an error.
                    Operand::ProgramOwner(_) => {
                        bail!("Illegal operation: cannot retrieve the program owner in a closure scope")
                    }
                    // If the operand is the component checksum, throw an error.
                    Operand::ComponentChecksum(..) => {
                        bail!("Illegal operation: cannot retrieve the component checksum in a closure scope")
                    }
                }
            })
            .map(|res| res.map_err(StackExecError::Anyhow))
            .collect();
        lap!(timer, "Load the outputs");

        finish!(timer);
        outputs
    }

    /// Executes a program function on the given inputs. The output includes a `Response` object if
    /// not in `CheckDeployment` or `Synthesize` mode.
    ///
    /// Note: To execute a transition, do **not** call this method. Instead, call `Process::execute`.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    pub fn execute_function<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        mut call_stack: CallStack<N>,
        console_caller: Option<ProgramID<N>>,
        console_root_tvk: Option<Field<N>>,
        rng: &mut R,
    ) -> Result<Option<Response<N>>, StackExecError> {
        let timer = timer!("Stack::execute_function");

        // Ensure the global constants for the Aleo environment are initialized.
        A::initialize_global_constants();
        // Ensure the circuit environment is clean.
        A::reset();

        // If in 'CheckDeployment' mode, set the constraint limit and variable limit.
        // We do not have to reset it after function calls because `CheckDeployment` mode does not execute those.
        if let CallStack::CheckDeployment(_, _, _, constraint_limit, variable_limit, non_zero_limit) = &call_stack {
            A::set_constraint_limit(*constraint_limit);
            A::set_variable_limit(*variable_limit);
            A::set_non_zero_limit(*non_zero_limit);
        }

        // Retrieve the next request.
        let console_request = call_stack.pop()?;

        // If in Execute mode, push a new translation group for this execution level.
        // Translations from dynamic calls made at this level will be collected into this group,
        // and the group will be popped when the transition is inserted.
        if let CallStack::Execute(_, _, translations) = &call_stack {
            translations.write().push(Vec::new());
        }

        // Ensure the network ID matches.
        if **console_request.network_id() != N::ID {
            return Err(
                anyhow!("Network ID mismatch. Expected {}, but found {}", N::ID, console_request.network_id()).into()
            );
        }

        // We can only have a root_tvk if this request was called by another request
        if console_caller.is_some() != console_root_tvk.is_some() {
            return Err(anyhow!("root_tvk requires a caller").into());
        }

        // Determine if this is the top-level caller.
        let console_is_root = console_caller.is_none();

        // Determine the parent.
        //  - If this execution is the top-level caller, then the parent is the program ID.
        //  - If this execution is a child caller, then the parent is the caller.
        let console_parent = match console_caller {
            // If this execution is the top-level caller, then the parent is the program ID.
            None => console_request.program_id().to_address()?,
            // If this execution is a child caller, then the parent is the caller.
            Some(console_caller) => console_caller.to_address()?,
        };

        // Retrieve the function from the program.
        let function = self.get_function(console_request.function_name())?;
        // Retrieve the number of inputs.
        let num_inputs = function.inputs().len();
        // Ensure the number of inputs matches the number of input statements.
        if num_inputs != console_request.inputs().len() {
            return Err(anyhow!("Expected {num_inputs} inputs, found {}", console_request.inputs().len()).into());
        }
        // Retrieve the input types.
        let input_types = function.input_types();
        // Retrieve the output types.
        let output_types = function.output_types();
        lap!(timer, "Retrieve the input and output types");

        // Ensure the inputs match their expected types.
        console_request.inputs().iter().zip_eq(&input_types).try_for_each(|(input, input_type)| {
            // Ensure the input matches the input type in the function.
            self.matches_value_type(input, input_type)
        })?;
        lap!(timer, "Verify the input types");

        // Retrieve the program checksum, if the program has a constructor.
        let program_checksum = match self.program().contains_constructor() {
            true => Some(self.program_checksum_as_field()?),
            false => None,
        };

        let call_stack_type = call_stack.type_as_string();

        // Ensure the request is well-formed.
        if !console_request.verify(&input_types, console_is_root, program_checksum) {
            return Err(anyhow!("[Execute] Request is invalid").into());
        }
        lap!(timer, "Verify the console request");

        // Initialize the registers.
        let mut registers = Registers::new(call_stack, self.get_register_types(function.name())?.clone());

        // Set the root tvk, from a parent request or the current request.
        let console_root_tvk = console_root_tvk.unwrap_or(*console_request.tvk());
        // Inject the `root_tvk` as `Mode::Private`.
        let root_tvk = circuit::Field::<A>::new(circuit::Mode::Private, console_root_tvk);
        // Set the root tvk.
        registers.set_root_tvk(console_root_tvk);
        // Set the root tvk, as a circuit.
        registers.set_root_tvk_circuit(root_tvk.clone());

        // If a program checksum was passed in, Inject it as `Mode::Public`.
        let program_checksum = program_checksum.map(|c| circuit::Field::<A>::new(circuit::Mode::Public, c));

        use circuit::{Eject, Inject};

        // Inject the transition public key `tpk` as `Mode::Public`.
        let tpk = circuit::Group::<A>::new(circuit::Mode::Public, console_request.to_tpk());
        // Inject the request as `Mode::Private`.
        let request = circuit::Request::new(circuit::Mode::Private, console_request.clone());

        // Inject `is_root` as `Mode::Public`.
        let is_root = circuit::Boolean::new(circuit::Mode::Public, console_is_root);
        // Inject the parent as `Mode::Public`.
        let parent = circuit::Address::new(circuit::Mode::Public, console_parent);
        // Determine the caller.
        let caller = Ternary::ternary(&is_root, request.signer(), &parent);

        // Ensure the request has a valid signature, inputs, and transition view key.
        A::assert(request.verify(&input_types, &tpk, Some(root_tvk), is_root, program_checksum))?;
        lap!(timer, "Verify the circuit request");

        // Set the transition signer.
        registers.set_signer(*console_request.signer());
        // Set the transition signer, as a circuit.
        registers.set_signer_circuit(request.signer().clone());

        // Set the transition caller.
        registers.set_caller(caller.eject_value());
        // Set the transition caller, as a circuit.
        registers.set_caller_circuit(caller);

        // Set the transition view key.
        registers.set_tvk(*console_request.tvk());
        // Set the transition view key, as a circuit.
        registers.set_tvk_circuit(request.tvk().clone());

        lap!(timer, "Initialize the registers");

        Self::log_circuit::<A>("Request", &call_stack_type);

        // Retrieve the number of constraints for verifying the request in the circuit.
        let num_request_constraints = A::num_constraints();

        // Retrieve the number of public variables in the circuit.
        let num_public = A::num_public();

        // Store the inputs.
        function.inputs().iter().map(|i| i.register()).zip_eq(request.inputs()).try_for_each(|(register, input)| {
            // If the circuit is in execute mode, then store the console input.
            if let CallStack::Execute(..) = registers.call_stack_ref() {
                // Assign the console input to the register.
                registers.store(self, register, input.eject_value())?;
            }
            // Assign the circuit input to the register.
            registers.store_circuit(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");

        // Initialize a tracker to determine if there are any function calls.
        let mut contains_function_call = false;

        // Execute the instructions.
        for (ix, instruction) in function.instructions().iter().enumerate() {
            // If the circuit is in execute mode, then evaluate the instructions.
            if let CallStack::Execute(..) = registers.call_stack_ref() {
                // Evaluate the instruction.
                let result = match instruction {
                    // If the instruction is a `call` instruction, we need to handle it separately.
                    Instruction::Call(call) => CallTrait::evaluate(call, self, &mut registers, rng)
                        .map_err(|e| InstructionEvalError::Call(Box::new(e))),
                    // If the instruction is a `call.dynamic` instruction, we need to handle it separately.
                    Instruction::CallDynamic(call_dynamic) => {
                        // Evaluate the dynamic call.
                        CallTrait::evaluate(call_dynamic, self, &mut registers, rng)
                            .map_err(|e| InstructionEvalError::Call(Box::new(e)))
                    }
                    // Otherwise, evaluate the instruction normally.
                    _ => instruction.evaluate(self, &mut registers).map_err(Into::into),
                };
                // If the evaluation fails, bail and return the error.
                if let Err(error) = result {
                    let err = InstructionError::Eval(error);
                    return Err(IndexedInstructionError::new(ix, format!("{instruction}"), err).into());
                }
            }

            // Execute the instruction.
            let result = match instruction {
                // If the instruction is a `call` instruction, we need to handle it separately.
                Instruction::Call(call) => CallTrait::execute(call, self, &mut registers, rng)
                    .map_err(|e| InstructionExecError::Call(Box::new(e))),
                // If the instruction is a `call.dynamic` instruction, we need to handle it separately.
                Instruction::CallDynamic(call_dynamic) => {
                    // Execute the dynamic call.
                    CallTrait::execute(call_dynamic, self, &mut registers, rng)
                        .map_err(|e| InstructionExecError::Call(Box::new(e)))
                }
                // Otherwise, execute the instruction normally.
                _ => instruction.execute(self, &mut registers).map_err(InstructionExecError::Exec),
            };
            // If the execution fails, bail and return the error.
            if let Err(error) = result {
                let err = InstructionError::Exec(error);
                return Err(IndexedInstructionError::new(ix, format!("{instruction}"), err).into());
            }

            // If the instruction was a function call, then set the tracker to `true`.
            match instruction {
                Instruction::Call(call) => {
                    if call.is_function_call(self)? {
                        contains_function_call = true;
                    }
                }
                // A dynamic call is always a function call.
                Instruction::CallDynamic(_) => {
                    contains_function_call = true;
                }
                _ => {}
            }
        }
        lap!(timer, "Execute the instructions");

        // Load the outputs.
        let output_operands = &function.outputs().iter().map(|output| output.operand()).collect::<Vec<_>>();
        let outputs = output_operands
            .iter()
            .map(|operand| {
                match operand {
                    // If the operand is a literal, use the literal directly.
                    Operand::Literal(literal) => Ok(circuit::Value::Plaintext(circuit::Plaintext::from(
                        circuit::Literal::new(circuit::Mode::Constant, literal.clone()),
                    ))),
                    // If the operand is a register, retrieve the stack value from the register.
                    Operand::Register(register) => registers.load_circuit(self, &Operand::Register(register.clone())),
                    // If the operand is the program ID, convert the program ID into an address.
                    Operand::ProgramID(program_id) => {
                        Ok(circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Address(
                            circuit::Address::new(circuit::Mode::Constant, program_id.to_address()?),
                        ))))
                    }
                    // If the operand is the signer, retrieve the signer from the registers.
                    Operand::Signer => Ok(circuit::Value::Plaintext(circuit::Plaintext::from(
                        circuit::Literal::Address(registers.signer_circuit()?),
                    ))),
                    // If the operand is the caller, retrieve the caller from the registers.
                    Operand::Caller => Ok(circuit::Value::Plaintext(circuit::Plaintext::from(
                        circuit::Literal::Address(registers.caller_circuit()?),
                    ))),
                    // If the operand is the generator, retrieve the Aleo generator.
                    Operand::AleoGenerator => A::g_powers()
                        .first()
                        .map(|element| {
                            circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Group(
                                element.clone(),
                            )))
                        })
                        .ok_or_else(|| anyhow!("Failed to retrieve the Aleo generator")),
                    // If the operand is the generator powers, retrieve the generator powers or the indexed group.
                    Operand::AleoGeneratorPowers(index) => match index {
                        None => Ok(circuit::Value::Plaintext(circuit::Plaintext::Array(
                            A::g_powers()
                                .into_iter()
                                .map(|element| circuit::Plaintext::from(circuit::Literal::Group(element)))
                                .collect(),
                            OnceCell::new(),
                        ))),
                        Some(index) => A::g_powers()
                            .get(**index as usize)
                            .map(|element| {
                                circuit::Value::Plaintext(circuit::Plaintext::from(circuit::Literal::Group(
                                    element.clone(),
                                )))
                            })
                            .ok_or_else(|| anyhow!("Index {index} out of bounds for Aleo generator")),
                    },
                    // If the operand is the block height, throw an error.
                    Operand::BlockHeight => {
                        bail!("Illegal operation: cannot retrieve the block height in a function scope")
                    }
                    // If the operand is the block timestamp, throw an error.
                    Operand::BlockTimestamp => {
                        bail!("Illegal operation: cannot retrieve the block timestamp in a function scope")
                    }
                    // If the operand is the network id, throw an error.
                    Operand::NetworkID => {
                        bail!("Illegal operation: cannot retrieve the network id in a function scope")
                    }
                    // If the operand is the checksum, throw an error.
                    Operand::Checksum(_) => {
                        bail!("Illegal operation: cannot retrieve the checksum in a function scope")
                    }
                    // If the operand is the edition, throw an error.
                    Operand::Edition(_) => {
                        bail!("Illegal operation: cannot retrieve the edition in a function scope")
                    }
                    // If the operand is the program owner, throw an error.
                    Operand::ProgramOwner(_) => {
                        bail!("Illegal operation: cannot retrieve the program owner in a function scope")
                    }
                    // If the operand is the component checksum, throw an error.
                    Operand::ComponentChecksum(..) => {
                        bail!("Illegal operation: cannot retrieve the component checksum in a function scope")
                    }
                }
            })
            .collect::<Result<Vec<_>>>()?;
        lap!(timer, "Load the outputs");

        // Map the output operands into registers.
        let output_registers = output_operands
            .iter()
            .map(|operand| match operand {
                Operand::Register(register) => Some(register.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        Self::log_circuit::<A>(format!("Function '{}()'", function.name()), &call_stack_type);

        // Retrieve the number of constraints for executing the function in the circuit.
        let num_function_constraints = A::num_constraints().saturating_sub(num_request_constraints);

        // If the function does not contain function calls, ensure no new public variables were injected.
        if !contains_function_call && A::num_public() != num_public {
            // Ensure the number of public variables remains the same.
            return Err(anyhow!("Instructions in function injected public variables").into());
        }

        // Construct the response.
        let response = circuit::Response::from_outputs(
            request.signer(),
            request.network_id(),
            request.program_id(),
            request.function_name(),
            num_inputs,
            request.tvk(),
            request.tcm(),
            outputs,
            &output_types,
            &output_registers,
        );
        lap!(timer, "Construct the response");

        Self::log_circuit::<A>("Response", &call_stack_type);

        // Retrieve the number of constraints for verifying the response in the circuit.
        let num_response_constraints =
            A::num_constraints().saturating_sub(num_request_constraints).saturating_sub(num_function_constraints);

        Self::log_circuit::<A>("Complete", &call_stack_type);

        // Eject the response.
        let console_response =
            if matches!(registers.call_stack_ref(), CallStack::Synthesize(..) | CallStack::CheckDeployment(..)) {
                // When synthesizing proving/verifying keys or checking the latter, the values in
                // the Response object are not relevant, and neither is its console counterpart.
                None
            } else {
                let console_response = response.eject_value();

                if console_response.outputs().len() != output_types.len() {
                    return Err(anyhow!("Number of outputs does not match number of output types").into());
                }

                // Ensure the outputs matches the expected value types.
                console_response.outputs().iter().zip_eq(&output_types).try_for_each(|(output, output_type)| {
                    // Ensure the output matches its expected type.
                    self.matches_value_type(output, output_type)
                })?;

                Some(console_response)
            };

        // If the circuit is in `Execute` or `PackageRun` mode, then ensure the circuit is satisfied.
        if matches!(registers.call_stack_ref(), CallStack::Execute(..) | CallStack::PackageRun(..)) {
            // If the circuit is empty or not satisfied, then throw an error.
            if A::num_constraints() == 0 || !A::is_satisfied() {
                return Err(anyhow!(
                    "'{}/{}' is not satisfied on the given inputs ({} constraints).",
                    self.program.id(),
                    function.name(),
                    A::num_constraints()
                )
                .into());
            }
        }

        // Eject the circuit assignment and reset the circuit.
        let assignment = A::eject_assignment_and_reset();

        // If the circuit is in `Synthesize` or `Execute` mode, synthesize the circuit key, if it does not exist.
        if matches!(registers.call_stack_ref(), CallStack::Synthesize(..) | CallStack::Execute(..)) {
            // If the proving key does not exist, then synthesize it.
            if !self.contains_proving_key(function.name()) {
                // Add the circuit key to the mapping.
                self.synthesize_from_assignment(function.name(), &assignment)?;
                lap!(timer, "Synthesize the {} circuit key", function.name());
            }
        }
        // If the circuit is in `Authorize` mode, then save the transition.
        if let CallStack::Authorize(_, _, authorization) = registers.call_stack_ref() {
            // Construct the transition.
            let transition = Transition::from(
                &console_request,
                // Note console_response was set to Some above except in the Synthesize and
                // CheckDeployment modes.
                console_response
                    .as_ref()
                    .expect("console_response is None in execute_function in CallStack::Authorize mode"),
                &output_types,
                &output_registers,
            )?;

            // Add the transition to the authorization.
            authorization.insert_transition(transition)?;
            lap!(timer, "Save the transition");
        }
        // If the circuit is in `CheckDeployment` mode, then save the assignment.
        else if let CallStack::CheckDeployment(_, _, assignments, _, _, _) = registers.call_stack_ref() {
            // Construct the call metrics.
            let metrics = CallMetrics {
                program_id: *self.program_id(),
                function_name: *function.name(),
                num_instructions: function.instructions().len(),
                num_request_constraints,
                num_function_constraints,
                num_response_constraints,
            };
            // Add the assignment to the assignments.
            assignments.write().push((assignment, metrics));
            lap!(timer, "Save the circuit assignment");
        }
        // If the circuit is in `Execute` mode, then execute the circuit into a transition.
        else if let CallStack::Execute(_, trace, translations) = registers.call_stack_ref() {
            registers.ensure_console_and_circuit_registers_match()?;

            // Construct the transition.
            let transition = Transition::from(
                &console_request,
                // Note console_response was set to Some above except in the Synthesize and
                // CheckDeployment modes.
                console_response
                    .as_ref()
                    .expect("console_response is None in execute_function in CallStack::Execute mode"),
                &output_types,
                &output_registers,
            )?;

            // Retrieve the proving key.
            let proving_key = self.get_proving_key(function.name())?;
            // Construct the call metrics.
            let metrics = CallMetrics {
                program_id: *self.program_id(),
                function_name: *function.name(),
                num_instructions: function.instructions().len(),
                num_request_constraints,
                num_function_constraints,
                num_response_constraints,
            };

            // Pop the translation group for this execution level.
            // This group contains translations (with proving keys) from dynamic calls made at this level.
            let translations_for_transition =
                translations.write().pop().ok_or_else(|| anyhow!("Translation stack underflow: no group to pop"))?;

            // Add the transition to the trace.
            trace.write().insert_transition(
                console_request.input_ids(),
                &transition,
                (proving_key, assignment),
                translations_for_transition,
                metrics,
            )?;
        }
        // If the circuit is in `PackageRun` mode, then save the assignment.
        else if let CallStack::PackageRun(_, _, assignments) = registers.call_stack_ref() {
            // Construct the call metrics.
            let metrics = CallMetrics {
                program_id: *self.program_id(),
                function_name: *function.name(),
                num_instructions: function.instructions().len(),
                num_request_constraints,
                num_function_constraints,
                num_response_constraints,
            };
            // Add the assignment to the assignments.
            assignments.write().push((assignment, metrics));
            lap!(timer, "Save the circuit assignment");
        }

        finish!(timer);

        // Return the response.
        Ok(console_response)
    }
}

impl<N: Network> Stack<N> {
    /// Prints the current state of the circuit.
    #[allow(unused_variables)]
    pub(crate) fn log_circuit<A: circuit::Aleo<Network = N>>(
        scope: impl std::fmt::Display,
        call_stack_type: impl std::fmt::Display,
    ) {
        #[cfg(debug_assertions)]
        {
            use snarkvm_utilities::dev_println;

            use colored::Colorize as _;

            // Determine if the circuit is satisfied.
            let is_satisfied = if A::is_satisfied() { "✅" } else { "❌" };
            // Determine the count.
            let (num_constant, num_public, num_private, num_constraints, num_nonzeros) = A::count();

            let scope = scope.to_string().bold();

            // Print the log.
            dev_println!(
                "{is_satisfied} {call_stack_type:width$} {scope:width$} (Constant: {num_constant}, Public: {num_public}, Private: {num_private}, Constraints: {num_constraints}, NonZeros: {num_nonzeros:?})",
                width = 20
            );
        }
    }
}
