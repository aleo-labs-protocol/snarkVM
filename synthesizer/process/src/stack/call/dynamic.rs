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

impl<N: Network> CallTrait<N> for CallDynamic<N> {
    /// Evaluates the instruction.
    #[inline]
    fn evaluate<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        stack: &Stack<N>,
        registers: &mut Registers<N, A>,
        rng: &mut R,
    ) -> Result<(), CallEvalError> {
        let timer = timer!("CallDynamic::evaluate");

        // Load the operands values.
        let inputs: Vec<_> = self.operands().iter().map(|operand| registers.load(stack, operand)).try_collect()?;

        // Helper: extract a field from a field or identifier literal value.
        let value_to_field = |value: &Value<N>, position: &str| -> Result<Field<N>, CallEvalError> {
            match value {
                Value::Plaintext(Plaintext::Literal(Literal::Field(field), _)) => Ok(*field),
                Value::Plaintext(Plaintext::Literal(Literal::Identifier(id_lit), _)) => id_lit
                    .to_field()
                    .map_err(|e| anyhow!("Failed to convert identifier literal to field ({position}): {e}").into()),
                _ => Err(anyhow!(
                    "Expected the {position} operand of `call.dynamic` to be a field or identifier literal."
                )
                .into()),
            }
        };

        // Get the program name.
        let program_name_as_field = value_to_field(&inputs[0], "first")?;

        // Get the program network.
        let program_network_id = value_to_field(&inputs[1], "second")?;

        // Get the function name.
        let function_name_as_field = value_to_field(&inputs[2], "third")?;

        // Separate the remaining inputs as the function inputs.
        let inputs = &inputs[3..];

        // Resolve the program and function.
        let target = resolve_dynamic_target(
            registers.call_stack_ref(),
            stack,
            &program_name_as_field,
            &program_network_id,
            &function_name_as_field,
        )?;

        // Get the target (in evaluate mode, we must have a valid target).
        let Some(target) = target else {
            return Err(anyhow!("Failed to resolve the target of the dynamic call in 'evaluate' mode.").into());
        };

        // Retrieve the program ID, function name, and substack from the resolved target.
        let program_id = target.program_id();
        let function_name = target.function_name();
        let substack = target.substack();
        lap!(timer, "Retrieved the substack");

        // If the target is a closure, reject it — closures cannot be dynamically called.
        let outputs = if substack.program().get_closure(function_name).is_ok() {
            return Err(anyhow!("Cannot dynamically evaluate a closure: {function_name}").into());
        }
        // If the operator is a function, retrieve the function and compute the output.
        else if let Ok(function) = substack.program().get_function(function_name) {
            // Ensure the number of inputs matches the number of input statements.
            if function.inputs().len() != inputs.len() {
                return Err(anyhow!("Expected {} inputs, found {}", function.inputs().len(), inputs.len()).into());
            }

            // Get the 'root_tvk'.
            let root_tvk = Some(registers.root_tvk()?);

            // Get the call stack.
            let mut call_stack = registers.call_stack();

            // In Authorize mode, we need to compute the new request and add it to the authorization.
            if let CallStack::Authorize(requests, private_key, authorization) = &mut call_stack {
                // Set 'is_root'.
                let is_root = false;
                // Ensure that we have a private key to sign the new request.
                let Some(private_key) = private_key else {
                    return Err(anyhow!("Cannot authorize a new function call without a private key.").into());
                };
                // Retrieve the program checksum, if the program has a constructor.
                let program_checksum = match substack.program().contains_constructor() {
                    true => Some(substack.program_checksum_as_field()?),
                    false => None,
                };

                // Get the input types of the callee.
                let input_types = substack.program().get_function_ref(function_name)?.input_types();
                // Ensure the number of inputs matches the number of input types.
                if input_types.len() != inputs.len() {
                    return Err(anyhow!("Expected {} inputs, found {}", input_types.len(), inputs.len()).into());
                }

                // Convert the caller's inputs to the callee's context.
                let callee_inputs = convert_caller_inputs_to_callee_inputs(inputs, &input_types, substack)?;

                // Compute the request.
                let request = Request::sign(
                    private_key,
                    *substack.program_id(),
                    *function.name(),
                    callee_inputs.iter(),
                    &function.input_types(),
                    root_tvk,
                    is_root,
                    program_checksum,
                    true,
                    rng,
                )?;

                // Add the request to the requests.
                requests.push(request.clone());
                // Add the request to the authorization.
                authorization.push(request)?;
            };

            // In AuthorizeMocked mode, we operate similarly to the Authorize mode but mock the request.
            if let CallStack::AuthorizeMocked(requests, address, authorization, _, _) = &mut call_stack {
                // Get the input types of the callee.
                let input_types = substack.program().get_function_ref(function_name)?.input_types();
                // Ensure the number of inputs matches the number of input types.
                if input_types.len() != inputs.len() {
                    return Err(anyhow!("Expected {} inputs, found {}", input_types.len(), inputs.len()).into());
                }

                // Convert the caller's inputs to the callee's context.
                let callee_inputs = convert_caller_inputs_to_callee_inputs(inputs, &input_types, substack)?;

                // Mock the request.
                let request = Request::sample(
                    *address,
                    *substack.program_id(),
                    *function.name(),
                    callee_inputs.iter(),
                    &function.input_types(),
                    true,
                    rng,
                )?;

                // Add the request to the requests.
                requests.push(request.clone());
                // Add the request to the authorization.
                authorization.push(request)?;
            };

            // In AuthorizeRequests mode, we retrieve the expected request and match it against the call's target and inputs.
            if let CallStack::AuthorizeRequests(requests, current_index, authorization) = &mut call_stack {
                // Increment the index to advance the pre-order DFS traversal of the request tree.
                *current_index.write() += 1;

                let request = requests.get(*current_index.read()).ok_or_else(||
                    anyhow!("CallDynamic::evaluate attempted to retrieve request at index {}, but the AuthorizeRequests call stack only contains {} request(s)",
                    *current_index.read(),
                    requests.len())
                )?;

                // Sanity checks
                if *request.signer() != registers.signer()? {
                    return Err(anyhow!("CallDynamic::evaluate retrieved a request with a different signer than the signer in the registers").into());
                }
                if !request.is_dynamic() {
                    return Err(anyhow!("CallDynamic::evaluate retrieved a static request").into());
                }

                // Consistency checks: target program, target function and inputs. Note that as seen by the caller
                if request.program_id() != substack.program_id() {
                    return Err(anyhow!("CallDynamic::evaluate retrieved a request with a different program ID than the one in the call instruction").into());
                }
                if request.function_name() != function.name() {
                    return Err(anyhow!("CallDynamic::evaluate retrieved a request with a different function name than the one in the call instruction").into());
                }
                // Note the request contains the inputs as seen by the callee, yet `inputs` contains the caller's view.
                // In order to consistency-check the two, we convert the latter representation to the former.
                let callee_input_view = {
                    let input_types = substack.program().get_function_ref(function_name)?.input_types();
                    if input_types.len() != inputs.len() {
                        return Err(anyhow!("Expected {} inputs, found {}", input_types.len(), inputs.len()).into());
                    }
                    convert_caller_inputs_to_callee_inputs(inputs, &input_types, substack)?
                };
                if request.inputs() != callee_input_view {
                    return Err(anyhow!("CallDynamic::evaluate retrieved a request with different inputs than the ones passed to the call instruction").into());
                }

                // Add the request to the authorization.
                authorization.push(request.clone())?;
            }

            // Set the (console) caller.
            let console_caller = Some(*stack.program_id());
            // Evaluate the function.
            let response = substack.evaluate_function::<A, R>(call_stack, console_caller, root_tvk, rng)?;
            // Convert the callee's outputs to the caller's context.
            response.to_dynamic_outputs()?
        }
        // Else, throw an error.
        else {
            return Err(anyhow!("Dynamic call to '{program_id}/{function_name}' is invalid or unsupported.").into());
        };
        lap!(timer, "Computed outputs");

        // Assign the outputs to the destination registers.
        if outputs.len() != self.destinations().len() {
            return Err(anyhow!(
                "Expected {} outputs, but {} were provided.",
                self.destinations().len(),
                outputs.len()
            )
            .into());
        }
        for (output, register) in outputs.into_iter().zip_eq(&self.destinations()) {
            // Assign the output to the register.
            registers.store(stack, register, output)?;
        }
        finish!(timer);

        Ok(())
    }

    /// Executes the instruction.
    #[inline]
    fn execute<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        stack: &Stack<N>,
        registers: &mut Registers<N, A>,
        rng: &mut R,
    ) -> Result<(), CallExecError> {
        use circuit::{Eject, environment::ToField as _};

        let timer = timer!("CallDynamic::execute");

        // Load the operands values.
        let inputs: Vec<_> =
            self.operands().iter().map(|operand| registers.load_circuit(stack, operand)).try_collect()?;

        // Helper: extract a circuit field from a circuit Field or Identifier literal value.
        // Identifier literals are converted to their field representation via `to_field()`,
        // which adds zero circuit constraints.
        let circuit_value_to_circuit_field =
            |value: &circuit::Value<A>, position: &str| -> Result<circuit::Field<A>, CallExecError> {
                match value {
                    circuit::Value::Plaintext(circuit::Plaintext::Literal(circuit::Literal::Field(field), _)) => {
                        Ok(field.clone())
                    }
                    circuit::Value::Plaintext(circuit::Plaintext::Literal(circuit::Literal::Identifier(id_lit), _)) => {
                        Ok(id_lit.to_field())
                    }
                    _ => Err(anyhow!(
                        "Expected the {position} operand of `call.dynamic` to be a field or identifier literal."
                    )
                    .into()),
                }
            };

        // Get the program name as a circuit field.
        let program_name_as_field = circuit_value_to_circuit_field(&inputs[0], "first")?;
        // Get the program network as a circuit field.
        let program_network_as_field = circuit_value_to_circuit_field(&inputs[1], "second")?;
        // Get the function name as a circuit field.
        let function_name_as_field = circuit_value_to_circuit_field(&inputs[2], "third")?;

        // Separate the remaining inputs as the function inputs.
        let inputs = &inputs[3..];

        // Retrieve the root request's tvk, if available (None if this is the root call).
        let root_tvk = registers.root_tvk().ok();

        // Execute the function.
        let outputs = {
            lap!(timer, "Execute the function");

            // Retrieve the number of public variables in the circuit.
            let num_public = A::num_public();

            // Indicate that external calls are never a root request.
            let is_root = false;

            // Eject the existing circuit.
            let r1cs = A::eject_r1cs_and_reset();
            let (request, caller_response_outputs) = {
                // Resolve the program and function.
                let target = resolve_dynamic_target(
                    registers.call_stack_ref(),
                    stack,
                    &program_name_as_field.eject_value(),
                    &program_network_as_field.eject_value(),
                    &function_name_as_field.eject_value(),
                )?;

                // Eject the circuit inputs.
                let inputs = inputs.eject_value();

                // Set the (console) caller.
                let console_caller = Some(*stack.program_id());

                match registers.call_stack_ref() {
                    // In `Authorize` mode, add any external calls to the stack.
                    CallStack::Authorize(_, private_key, authorization) => {
                        // Get the target.
                        let Some(target) = target else {
                            return Err(anyhow!(
                                "Failed to resolve the target of the dynamic call in 'Authorize' mode."
                            )
                            .into());
                        };
                        // Get the function.
                        let function = target.substack().program().get_function_ref(target.function_name())?;
                        // Retrieve the number of inputs.
                        let num_inputs = function.inputs().len();
                        // Ensure the number of inputs matches the number of input statements.
                        if num_inputs != inputs.len() {
                            return Err(anyhow!("Expected {} inputs, found {}", num_inputs, inputs.len()).into());
                        }
                        // Ensure that we have a private key to sign the new request.
                        let Some(private_key) = private_key else {
                            return Err(anyhow!("Cannot authorize a new function call without a private key.").into());
                        };
                        // Retrieve the program checksum, if the program has a constructor.
                        let program_checksum = match target.substack().program().contains_constructor() {
                            true => Some(target.substack().program_checksum_as_field()?),
                            false => None,
                        };

                        // Get the input types of the callee.
                        let input_types =
                            &target.substack().program().get_function_ref(target.function_name())?.input_types();
                        // Ensure the number of inputs matches the number of input types.
                        if input_types.len() != inputs.len() {
                            return Err(anyhow!("Expected {} inputs, found {}", input_types.len(), inputs.len()).into());
                        }

                        // Convert the caller's inputs to the callee's context.
                        let callee_inputs =
                            convert_caller_inputs_to_callee_inputs(&inputs, input_types, target.substack())?;

                        // Construct the callee's version of the request.
                        let callee_request = Request::sign(
                            private_key,
                            *target.substack().program_id(),
                            *function.name(),
                            callee_inputs.iter(),
                            input_types,
                            root_tvk,
                            is_root,
                            program_checksum,
                            true,
                            rng,
                        )?;

                        // Construct the request verification inputs.
                        let request_verification_inputs = CalleeDynamicRequest::from(&callee_request)?;
                        // Retrieve the call stack.
                        let mut call_stack = registers.call_stack();
                        // Push the callee's request onto the call stack.
                        call_stack.push(callee_request.clone())?;

                        // Add the callee's request to the authorization.
                        authorization.push(callee_request.clone())?;

                        // Execute the callee's request.
                        let Some(callee_response) =
                            target.substack().execute_function::<A, R>(call_stack, console_caller, root_tvk, rng)?
                        else {
                            return Err(anyhow!("Response should be present in `Authorize` mode.").into());
                        };

                        // Convert the callee's outputs to the caller's context.
                        let caller_response_outputs = callee_response.to_dynamic_outputs()?;

                        // Return the request verification inputs and response.
                        (request_verification_inputs, caller_response_outputs)
                    }
                    // If the circuit is in AuthorizeMocked mode, throw an error.
                    CallStack::AuthorizeMocked(..) => {
                        return Err(anyhow!("Cannot 'execute' a function in 'authorize mocked' mode.").into());
                    }
                    // If the circuit is in AuthorizeRequests mode, throw an error.
                    CallStack::AuthorizeRequests(..) => {
                        return Err(anyhow!("Cannot 'execute' a function in 'authorize requests' mode.").into());
                    }
                    // In `Synthesize` or `CheckDeployment` mode, we use dummy inputs and outputs to avoid building a full sub-circuit.
                    CallStack::Synthesize(_, private_key, ..) | CallStack::CheckDeployment(_, private_key, ..) => {
                        // Note that it does not matter what program ID we use here, since we are only synthesizing dummy outputs.
                        let program_id = ProgramID::from_str("a.aleo")?;
                        // Note that it does not matter what function name we use here, since we are only synthesizing dummy outputs.
                        let function_name = Identifier::<N>::from_str("a")?;

                        // Compute the address.
                        let address = Address::try_from(private_key)?;

                        // Construct the request verification inputs.
                        let request_verification_inputs = CalleeDynamicRequest {
                            network_id: U16::new(N::ID),
                            program_id,
                            function_name,
                            signer: Address::rand(rng),
                            sk_tag: Field::rand(rng),
                            tvk: Field::rand(rng),
                            tcm: Field::rand(rng),
                            caller_input_ids: self
                                .operand_types()
                                .iter()
                                .map(|type_| match type_ {
                                    ValueType::Constant(..) => Ok(InputID::Constant(Field::rand(rng))),
                                    ValueType::Public(..) => Ok(InputID::Public(Field::rand(rng))),
                                    ValueType::Private(..) => Ok(InputID::Private(Field::rand(rng))),
                                    ValueType::Record(..) => Ok(InputID::Record(
                                        Field::rand(rng),
                                        Group::rand(rng),
                                        Field::rand(rng),
                                        Field::rand(rng),
                                        Field::rand(rng),
                                    )),
                                    ValueType::ExternalRecord(..) => Ok(InputID::ExternalRecord(Field::rand(rng))),
                                    ValueType::Future(..) => Err(anyhow!("A future cannot be input directly")),
                                    ValueType::DynamicRecord => Ok(InputID::DynamicRecord(Field::rand(rng))),
                                    ValueType::DynamicFuture => {
                                        Err(anyhow!("A dynamic future cannot be input directly"))
                                    }
                                })
                                .collect::<Result<Vec<_>>>()?,
                        };

                        // Sample the outputs.
                        let callee_response_outputs = self
                            .destination_types()
                            .iter()
                            .map(|output_type| match output_type {
                                ValueType::Record(_) => Err(anyhow!("A dynamic call cannot return a record.")),
                                ValueType::ExternalRecord(_) => {
                                    Err(anyhow!("A dynamic call cannot return an external record."))
                                }
                                ValueType::Future(_) => Err(anyhow!("A dynamic call cannot return a future.")),
                                // Sample the value.
                                _ => stack.sample_value(&address, &output_type.into(), rng),
                            })
                            .collect::<Result<Vec<_>>>()?;

                        // Return the request verification inputs and response.
                        (request_verification_inputs, callee_response_outputs)
                    }
                    // In PackageRun mode, we sign and execute the request once.
                    CallStack::PackageRun(_, private_key, ..) => {
                        // Get the target.
                        let Some(target) = target else {
                            return Err(anyhow!(
                                "Failed to resolve the target of the dynamic call in 'PackageRun' mode."
                            )
                            .into());
                        };
                        // Get the function.
                        let function = target.substack().program().get_function_ref(target.function_name())?;
                        // Retrieve the number of inputs.
                        let num_inputs = function.inputs().len();
                        // Ensure the number of inputs matches the number of input statements.
                        if num_inputs != inputs.len() {
                            return Err(anyhow!("Expected {} inputs, found {}", num_inputs, inputs.len()).into());
                        }
                        // Retrieve the program checksum, if the program has a constructor.
                        let program_checksum = match target.substack().program().contains_constructor() {
                            true => Some(target.substack().program_checksum_as_field()?),
                            false => None,
                        };

                        // Get the input types of the callee.
                        let input_types =
                            &target.substack().program().get_function_ref(target.function_name())?.input_types();
                        // Ensure that the number of inputs match.
                        if input_types.len() != inputs.len() {
                            return Err(anyhow!("Expected {} inputs, found {}", input_types.len(), inputs.len()).into());
                        }
                        // Convert the inputs to the callee's context.
                        let callee_inputs =
                            convert_caller_inputs_to_callee_inputs(&inputs, input_types, target.substack())?;
                        // Construct the callee's version of the request.
                        let callee_request = Request::sign(
                            private_key,
                            *target.substack().program_id(),
                            *function.name(),
                            callee_inputs.iter(),
                            input_types,
                            root_tvk,
                            is_root,
                            program_checksum,
                            true,
                            rng,
                        )?;

                        // Construct the request verification inputs.
                        let request_verification_inputs = CalleeDynamicRequest::from(&callee_request)?;

                        // Retrieve the call stack.
                        let mut call_stack = registers.call_stack();
                        // Push the callee's request onto the call stack.
                        call_stack.push(callee_request.clone())?;

                        // Evaluate the callee's request.
                        let Some(callee_response) =
                            target.substack().execute_function::<A, _>(call_stack, console_caller, root_tvk, rng)?
                        else {
                            return Err(anyhow!("Response should be present in `PackageRun` mode.").into());
                        };

                        // Convert the callee's outputs to the caller's context.
                        let caller_response_outputs = callee_response.to_dynamic_outputs()?;

                        // Return the request verification inputs and response.
                        (request_verification_inputs, caller_response_outputs)
                    }
                    // In `Evaluate` mode, throw an error.
                    CallStack::Evaluate(..) => {
                        return Err(anyhow!("Cannot 'execute' a function in 'Evaluate' mode.").into());
                    }
                    // In `Execute` mode, evaluate and execute the instructions.
                    CallStack::Execute(authorization, _, translations) => {
                        // Get the target.
                        let Some(target) = target else {
                            return Err(
                                anyhow!("Failed to resolve the target of the dynamic call in 'Execute' mode.").into()
                            );
                        };
                        // Get the function.
                        let callee_function = target.substack().program().get_function_ref(target.function_name())?;
                        // Retrieve the number of inputs.
                        let num_inputs = callee_function.inputs().len();
                        // Ensure the number of inputs matches the number of input statements.
                        if num_inputs != inputs.len() {
                            return Err(anyhow!("Expected {} inputs, found {}", num_inputs, inputs.len()).into());
                        }

                        // Retrieve the callee's request (without popping it).
                        let callee_request = authorization.peek_next()?;
                        // Ensure the request is for the resolved target of the dynamic call.
                        if *callee_request.signer() != registers.signer()? {
                            return Err(anyhow!("[execute CallDynamic] Retrieved a request with a different signer than the signer in the registers").into());
                        }
                        if !callee_request.is_dynamic() {
                            return Err(anyhow!("[execute CallDynamic] Retrieved a static request").into());
                        }
                        if callee_request.program_id() != target.substack().program_id() {
                            return Err(anyhow!("[execute CallDynamic] Retrieved a request with a different program ID than the target of the dynamic call").into());
                        }
                        if callee_request.function_name() != target.function_name() {
                            return Err(anyhow!("[execute CallDynamic] Retrieved a request with a different function name than the target of the dynamic call").into());
                        }
                        // Retrieve the callee's input types.
                        let callee_input_types = callee_function.input_types();
                        // The request holds the callee's view of the inputs, so convert the caller's view to compare them.
                        let callee_input_view =
                            convert_caller_inputs_to_callee_inputs(&inputs, &callee_input_types, target.substack())?;
                        if callee_request.inputs() != callee_input_view {
                            return Err(anyhow!("[execute CallDynamic] Retrieved a request with different inputs than the ones passed to the call instruction").into());
                        }

                        // Construct the request verification inputs.
                        let callee_request_verification_inputs = CalleeDynamicRequest::from(&callee_request)?;

                        // Evaluate the function, and load the outputs.
                        let console_callee_response = target.substack().evaluate_function::<A, R>(
                            registers.call_stack(),
                            console_caller,
                            root_tvk,
                            rng,
                        )?;
                        // Execute the request.
                        let Some(callee_response) = target.substack().execute_function::<A, R>(
                            registers.call_stack(),
                            console_caller,
                            root_tvk,
                            rng,
                        )?
                        else {
                            return Err(anyhow!("Response should be present in `Execute` mode.").into());
                        };

                        // Ensure the values are equal.
                        if console_callee_response.outputs() != callee_response.outputs() {
                            dev_eprintln!(
                                "\n{:#?} != {:#?}\n",
                                console_callee_response.outputs(),
                                callee_response.outputs()
                            );
                            return Err(anyhow!(
                                "Function '{}' outputs do not match in a 'call.dynamic' instruction.",
                                callee_function.name()
                            )
                            .into());
                        }

                        // Synthesizes the translation proving key for the given program and record
                        // (if not already synthesized), caches it in the stack, and returns it.
                        let get_translation_proving_key = |program_id: &ProgramID<N>,
                                                           record_name: &Identifier<N>,
                                                           rng: &mut R|
                         -> Result<ProvingKey<N>> {
                            let record_stack = match program_id == stack.program_id() {
                                true => stack,
                                false => &stack.get_stack_global(program_id)?,
                            };

                            record_stack.synthesize_translation_key::<A, R>(record_name, rng)?;
                            record_stack.get_proving_key(record_name)
                        };

                        let caller_console_input_ids = callee_request.to_dynamic_input_ids()?;
                        let callee_console_input_ids = callee_request.input_ids();
                        let callee_console_function_id = compute_function_id(
                            &U16::<N>::new(N::ID),
                            callee_request.program_id(),
                            callee_request.function_name(),
                        )?;

                        // Collect input record translations.
                        let input_translations = collect_input_translations(
                            &inputs,
                            &caller_console_input_ids,
                            self.operand_types(),
                            callee_request.inputs(),
                            callee_console_input_ids,
                            &callee_input_types,
                            callee_request.program_id(),
                            callee_console_function_id,
                            *callee_request.tvk(),
                        )?;

                        // Synthesize translation proving keys and store input translations.
                        // Push to the top group of the translation stack (the caller's level).
                        for translation in input_translations {
                            let proving_key =
                                get_translation_proving_key(&translation.program_id, &translation.record_name, rng)?;
                            translations
                                .write()
                                .last_mut()
                                .ok_or_else(|| anyhow!("Translation stack is empty"))?
                                .push((translation, proving_key));
                        }

                        // Collect output record translations.
                        let caller_console_outputs = callee_response.to_dynamic_outputs()?;
                        let caller_console_output_ids = callee_response.to_dynamic_output_ids(
                            callee_request.network_id(),
                            callee_request.program_id(),
                            callee_request.function_name(),
                            callee_request.inputs().len(),
                            callee_request.tvk(),
                            callee_request.tcm(),
                        )?;

                        // Closure to compute record view key for non-external output records.
                        let compute_record_view_key = |operand_index: usize,
                                                       record_static: &console::program::Record<N, Plaintext<N>>|
                         -> Result<Option<Field<N>>> {
                            // Get the output index.
                            let Some(Operand::Register(register)) = target
                                .substack()
                                .get_function_ref(target.function_name())?
                                .outputs()
                                .get_index(operand_index)
                                .map(|op| op.operand())
                            else {
                                return Err(anyhow!("Expected output to be a register"));
                            };
                            // Prepare the index as a field element.
                            let index = Field::from_u64(register.locator());
                            // Compute the randomizer as `HashToScalar(tvk || index)`.
                            let randomizer = N::hash_to_scalar_psd2(&[*callee_request.tvk(), index])?;
                            // Compute the record view key.
                            let rvk = (*record_static.owner().to_group() * randomizer).to_x_coordinate();
                            Ok(Some(rvk))
                        };

                        let output_translations = collect_output_translations(
                            &caller_console_outputs,
                            &caller_console_output_ids,
                            self.destination_types(),
                            callee_response.outputs(),
                            callee_response.output_ids(),
                            &callee_function.output_types(),
                            callee_request.program_id(),
                            callee_console_function_id,
                            *callee_request.tvk(),
                            num_inputs,
                            compute_record_view_key,
                        )?;

                        // Synthesize translation proving keys and store output translations.
                        // Push to the top group of the translation stack (the caller's level).
                        for translation in output_translations {
                            let proving_key =
                                get_translation_proving_key(&translation.program_id, &translation.record_name, rng)?;
                            translations
                                .write()
                                .last_mut()
                                .ok_or_else(|| anyhow!("Translation stack is empty"))?
                                .push((translation, proving_key));
                        }

                        // Return the caller's request and response.
                        (callee_request_verification_inputs, caller_console_outputs)
                    }
                }
            };
            lap!(timer, "Computed the request and response");

            // Restore the caller's circuit, which was saved before the callee was synthesized.
            A::inject_r1cs(r1cs);

            use circuit::Inject;

            // Inject the network ID as `Mode::Constant`.
            let network_id = circuit::U16::constant(request.network_id);
            // Inject the program ID name as `Mode::Public`.
            let program_id = circuit::ProgramID::public(request.program_id);
            // Inject the function name as `Mode::Public`.
            let function_name = circuit::Identifier::public(request.function_name);
            // Inject the function ID as `Mode::Public`.
            let function_id = circuit::Field::new(
                circuit::Mode::Public,
                compute_function_id(&request.network_id, &request.program_id, &request.function_name)?,
            );

            // Ensure that the program and function names in the registers match the witnessed values.
            A::assert_eq(program_id.name(), program_name_as_field)?;
            A::assert_eq(program_id.network(), program_network_as_field)?;
            A::assert_eq(&function_name, function_name_as_field)?;

            // Ensure exactly 4 public variables were added: program name, program network,
            // function name, and function ID. This guards against spurious public injections.
            if A::num_public() != num_public + 4 {
                return Err(anyhow!("Forbidden: 'call.dynamic' injected excess public variables").into());
            }

            // Inject the `signer` (from the request) as `Mode::Private`.
            let signer = circuit::Address::new(circuit::Mode::Private, request.signer);
            // Inject the `sk_tag` (from the request) as `Mode::Private`.
            let sk_tag = circuit::Field::new(circuit::Mode::Private, request.sk_tag);
            // Inject the `tvk` (from the request) as `Mode::Private`.
            let tvk = circuit::Field::new(circuit::Mode::Private, request.tvk);
            // Inject the `tcm` (from the request) as `Mode::Public`.
            let tcm = circuit::Field::new(circuit::Mode::Public, request.tcm);
            // Compute the transition commitment as `Hash(tvk)`.
            let candidate_tcm = A::hash_psd2(std::slice::from_ref(&tvk));
            // Ensure the transition commitment matches the computed transition commitment.
            A::assert_eq(&tcm, candidate_tcm)?;

            // Inject the caller input IDs as `Mode::Public`.
            let input_ids = request
                .caller_input_ids
                .iter()
                .map(|input_id| circuit::InputID::new(circuit::Mode::Public, *input_id))
                .collect::<Vec<_>>();

            // Ensure the candidate input IDs match their computed inputs.
            let (check_input_ids, _) = circuit::Request::check_input_ids::<false>(
                &network_id,
                &program_id,
                &function_name,
                &input_ids,
                inputs,
                self.operand_types(),
                &signer,
                &sk_tag,
                &tvk,
                &tcm,
                None,
                Some(function_id.clone()),
            );
            A::assert(check_input_ids)?;
            lap!(timer, "Checked the input ids");

            // Checking that none of the outputs in the caller's context are records or futures.
            for output in caller_response_outputs.iter() {
                match output {
                    Value::Record(_) => return Err(anyhow!("A dynamic call cannot return a record.").into()),
                    Value::Future(_) => return Err(anyhow!("A dynamic call cannot return a future.").into()),
                    Value::Plaintext(_) | Value::DynamicRecord(_) | Value::DynamicFuture(_) => {} // Do nothing.
                }
            }

            // Use `None` for the output registers. This is safe since an output of a dynamic call cannot be a record.
            let output_registers = vec![None; caller_response_outputs.len()];

            // Inject the outputs as `Mode::Private` (with the 'tcm' and output IDs as `Mode::Public`).
            let outputs = circuit::Response::process_outputs_from_callback(
                &network_id,
                &program_id,
                &function_name,
                inputs.len(),
                &tvk,
                &tcm,
                caller_response_outputs.clone(),
                self.destination_types(),
                &output_registers,
                Some(function_id),
            );
            lap!(timer, "Checked the outputs");

            // Return the circuit outputs.
            outputs
        };

        // Assign the outputs to the destination registers.
        if outputs.len() != self.destinations().len() {
            return Err(anyhow!(
                "[execute Dynamic] Expected {} outputs, but {} were provided.",
                self.destinations().len(),
                outputs.len()
            )
            .into());
        }
        for (output, register) in outputs.into_iter().zip_eq(&self.destinations()) {
            // Assign the output to the register.
            registers.store_circuit(stack, register, output)?;
        }
        lap!(timer, "Assigned the outputs to registers");

        finish!(timer);

        Ok(())
    }
}

// Information needed to verify the callee's request in a dynamic call.
struct CalleeDynamicRequest<N: Network> {
    // The network ID.
    network_id: U16<N>,
    // The program ID.
    program_id: ProgramID<N>,
    // The function name.
    function_name: Identifier<N>,
    // The signer.
    signer: Address<N>,
    // The sk_tag.
    sk_tag: Field<N>,
    // The tvk.
    tvk: Field<N>,
    // The tcm.
    tcm: Field<N>,
    // The caller input IDs.
    caller_input_ids: Vec<InputID<N>>,
}

impl<N: Network> CalleeDynamicRequest<N> {
    /// Constructs the request verification inputs from a request and caller input IDs.
    #[inline]
    pub fn from(request: &Request<N>) -> Result<Self> {
        Ok(Self {
            network_id: *request.network_id(),
            program_id: *request.program_id(),
            function_name: *request.function_name(),
            signer: *request.signer(),
            sk_tag: *request.sk_tag(),
            tvk: *request.tvk(),
            tcm: *request.tcm(),
            caller_input_ids: request.to_dynamic_input_ids()?,
        })
    }
}

/// Converts caller inputs to callee inputs for a dynamic call.
///
/// In a dynamic call, the caller provides inputs in its own context (e.g., `DynamicRecord`),
/// but the callee expects inputs in its context (e.g., `Record` with a specific type).
/// This function performs the necessary conversions:
///
/// - `DynamicRecord` → `Record`: When the callee expects a `Record` or `ExternalRecord`,
///   the dynamic record is converted to a concrete record by looking up the owner visibility
///   from the callee's program.
///
/// - `Future` / `DynamicFuture`: These are not allowed as inputs to dynamic calls and will
///   cause this function to return an error.
///
/// - All other types (`Plaintext`, `Record`, `DynamicRecord` not matching the above): Passed through unchanged.
///
/// # Arguments
/// * `inputs` - The caller's input values
/// * `input_types` - The callee's expected input types
/// * `stack` - The callee's stack, used to look up record type information
///
/// # Returns
/// A vector of converted values suitable for the callee's context.
///
/// # Errors
/// Returns an error if:
/// - A `Future` or `DynamicFuture` is provided as input
/// - Record type lookup fails
/// - Dynamic record conversion fails
fn convert_caller_inputs_to_callee_inputs<N: Network>(
    inputs: &[Value<N>],
    input_types: &[ValueType<N>],
    stack: &Stack<N>,
) -> Result<Vec<Value<N>>> {
    inputs
        .iter()
        .zip_eq(input_types.iter())
        .map(|(input, input_type)| {
            match (input, input_type) {
                // Convert DynamicRecord to Record when callee expects a Record.
                (Value::DynamicRecord(dynamic_record), ValueType::Record(record_name)) => {
                    // Look up the owner visibility from the callee's program.
                    let owner_is_private = stack.program().get_record(record_name)?.owner().is_private();
                    Ok(Value::Record(dynamic_record.to_record(owner_is_private)?))
                }
                // Convert DynamicRecord to Record when callee expects an ExternalRecord.
                (Value::DynamicRecord(dynamic_record), ValueType::ExternalRecord(locator)) => {
                    let record_program_id = locator.program_id();
                    let record_name = locator.resource();

                    // Obtain the program where the external record is defined.
                    let external_record_stack = stack.get_external_stack(record_program_id)?;

                    // Look up the owner visibility from the external program.
                    let owner_is_private =
                        external_record_stack.program().get_record(record_name)?.owner().is_private();

                    Ok(Value::Record(dynamic_record.to_record(owner_is_private)?))
                }
                // Futures are not allowed as inputs to dynamic calls.
                (Value::Future(_), _) => Err(anyhow!("A future cannot be an input to a dynamic call.")),
                // Dynamic futures are not allowed as inputs to dynamic calls.
                (Value::DynamicFuture(_), _) => Err(anyhow!("A dynamic future cannot be an input to a dynamic call.")),
                // Plaintext values pass through unchanged.
                (Value::Plaintext(_), _) => Ok(input.clone()),
                // Record values pass through unchanged.
                (Value::Record(_), _) => Ok(input.clone()),
                // DynamicRecord values that don't match the above patterns pass through unchanged.
                (Value::DynamicRecord(_), _) => Ok(input.clone()),
            }
        })
        .collect()
}

// A reference to a stack, either local or external.
enum StackRef<'a, N: Network> {
    Local(&'a Stack<N>),
    External(Arc<Stack<N>>),
}

impl<'a, N: Network> Deref for StackRef<'a, N> {
    type Target = Stack<N>;

    fn deref(&self) -> &Self::Target {
        match self {
            StackRef::Local(stack) => stack,
            StackRef::External(stack) => stack.as_ref(),
        }
    }
}

// A resolved target of a dynamic call.
struct ResolvedTarget<'a, N: Network> {
    // The program ID.
    program_id: ProgramID<N>,
    // The function name.
    function_name: Identifier<N>,
    // The stack.
    substack: StackRef<'a, N>,
}

impl<'a, N: Network> ResolvedTarget<'a, N> {
    /// Returns the program ID.
    #[inline]
    pub fn program_id(&self) -> &ProgramID<N> {
        &self.program_id
    }

    /// Returns the function name.
    #[inline]
    pub fn function_name(&self) -> &Identifier<N> {
        &self.function_name
    }

    /// Returns the stack.
    #[inline]
    pub fn substack(&self) -> &Stack<N> {
        &self.substack
    }
}

// A helper function that attempts to resolve the target of a dynamic call. This function returns:
// - Ok(Some(ResolvedTarget)) if the target is successfully resolved to a non-closure.
// - Ok(None) in `Synthesize` or `CheckDeployment` mode when the target cannot be resolved.
// - Err(_) in
//    - `Synthesize` or `CheckDeployment` mode when the target is resolved to a closure.
//    - other modes when the target cannot be resolved or it is resolved to a closure.
fn resolve_dynamic_target<'a, N: Network>(
    call_stack: &'a CallStack<N>,
    stack: &'a Stack<N>,
    program_name_as_field: &Field<N>,
    program_network_as_field: &Field<N>,
    function_name_as_field: &Field<N>,
) -> Result<Option<ResolvedTarget<'a, N>>> {
    // Determine whether we are in "dummy" (`Synthesize` or `CheckDeployment`) mode.
    let in_dummy_mode = matches!(call_stack, CallStack::Synthesize(..) | CallStack::CheckDeployment(..));

    // Decode the program name, exiting gracefully in dummy mode if it fails.
    let program_name = match Identifier::from_field(program_name_as_field) {
        Ok(id) => id,
        Err(_) if in_dummy_mode => {
            return Ok(None);
        }
        Err(e) => return Err(anyhow!("Failed to decode the program name in a dynamic call: {e}")),
    };

    // Decode the program network, exiting gracefully in dummy mode if it fails.
    let program_network = match Identifier::from_field(program_network_as_field) {
        Ok(id) => id,
        Err(_) if in_dummy_mode => {
            return Ok(None);
        }
        Err(e) => return Err(anyhow!("Failed to decode the program network in a dynamic call: {e}")),
    };

    // Decode the function name, exiting gracefully in dummy mode if it fails.
    let function_name = match Identifier::from_field(function_name_as_field) {
        Ok(id) => id,
        Err(_) if in_dummy_mode => {
            return Ok(None);
        }
        Err(e) => return Err(anyhow!("Failed to decode the function name in a dynamic call: {e}")),
    };

    // Construct the program ID.
    let program_id = match ProgramID::try_from((program_name, program_network)) {
        Ok(id) => id,
        Err(_) if in_dummy_mode => {
            return Ok(None);
        }
        Err(e) => return Err(anyhow!("Failed to construct the program ID in a dynamic call: {e}")),
    };

    // Verify that the call is not to `credits.aleo/fee_private` or `credits.aleo/fee_public`.
    // Safe: "fee_private" and "fee_public" are hardcoded valid identifiers.
    let fee_private = Identifier::from_str("fee_private").expect("'fee_private' is a valid identifier");
    let fee_public = Identifier::from_str("fee_public").expect("'fee_public' is a valid identifier");
    if program_id == ProgramID::credits() && (function_name == fee_private || function_name == fee_public) {
        return Err(anyhow!(
            "Cannot perform an external call to 'credits.aleo/fee_private' or 'credits.aleo/fee_public'."
        ));
    }

    // Retrieve the optional external stack.
    let external_stack = match stack.program().id() == &program_id {
        false => match stack.get_stack_global(&program_id) {
            Ok(ext_stack) => Some(ext_stack),
            Err(_) if in_dummy_mode => {
                return Ok(None);
            }
            Err(e) => return Err(anyhow!("Failed to retrieve the external stack in a dynamic call: {e}")),
        },
        true => None,
    };

    // Retrieve the substack.
    let substack = match &external_stack {
        Some(external_stack) => StackRef::External(external_stack.clone()),
        None => StackRef::Local(stack),
    };

    // Verify that the function is not a closure.
    if substack.program().get_closure(&function_name).is_ok() {
        Err(anyhow!("Cannot dynamically evaluate a closure: {function_name}"))
    } else if substack.program().contains_function(&function_name) {
        Ok(Some(ResolvedTarget { program_id, function_name, substack }))
    } else if in_dummy_mode {
        Ok(None)
    } else {
        Err(anyhow!("Dynamic call to '{program_id}/{function_name}' is invalid or unsupported."))
    }
}

// Checks that all translation arrays have the same length.
fn check_translation_array_lengths(
    context: &str,
    caller_values_len: usize,
    caller_ids_len: usize,
    caller_types_len: usize,
    callee_values_len: usize,
    callee_ids_len: usize,
    callee_types_len: usize,
) -> Result<()> {
    // Ensure caller and callee have the same number of values.
    ensure!(
        caller_values_len == callee_values_len,
        "{context}: caller and callee values should have the same length ({caller_values_len} vs. {callee_values_len})"
    );
    // Ensure caller values and IDs have the same length.
    ensure!(
        caller_values_len == caller_ids_len,
        "{context}: caller values and IDs should have the same length ({caller_values_len} vs. {caller_ids_len})"
    );
    // Ensure caller values and types have the same length.
    ensure!(
        caller_values_len == caller_types_len,
        "{context}: caller values and types should have the same length ({caller_values_len} vs. {caller_types_len})"
    );
    // Ensure callee values and IDs have the same length.
    ensure!(
        callee_values_len == callee_ids_len,
        "{context}: callee values and IDs should have the same length ({callee_values_len} vs. {callee_ids_len})"
    );
    // Ensure callee values and types have the same length.
    ensure!(
        callee_values_len == callee_types_len,
        "{context}: callee values and types should have the same length ({callee_values_len} vs. {callee_types_len})"
    );
    Ok(())
}

// Collects input record translations from dynamic to static records.
// The caller is responsible for synthesizing translation proving keys.
fn collect_input_translations<N: Network>(
    caller_values: &[Value<N>],
    caller_ids: &[InputID<N>],
    caller_types: &[ValueType<N>],
    callee_values: &[Value<N>],
    callee_ids: &[InputID<N>],
    callee_types: &[ValueType<N>],
    callee_program_id: &ProgramID<N>,
    function_id: Field<N>,
    tvk: Field<N>,
) -> Result<Vec<TranslationAssignment<N>>> {
    // Validate that all arrays have the same length.
    check_translation_array_lengths(
        "Inputs",
        caller_values.len(),
        caller_ids.len(),
        caller_types.len(),
        callee_values.len(),
        callee_ids.len(),
        callee_types.len(),
    )?;

    // Initialize the translations vector.
    let mut translations = Vec::new();

    // Iterate over all inputs, matching caller and callee data.
    for (operand_index, (caller_value, caller_id, caller_type, callee_value, callee_id, callee_type)) in
        itertools::izip!(caller_values, caller_ids, caller_types, callee_values, callee_ids, callee_types).enumerate()
    {
        match (caller_value, caller_id, caller_type, callee_value, callee_id, callee_type) {
            // Case: DynamicRecord translates to a non-external Record.
            (
                Value::DynamicRecord(record_dynamic),
                InputID::DynamicRecord(id_dynamic),
                ValueType::DynamicRecord,
                Value::Record(record_static),
                InputID::Record(_record_commitment, gamma, record_view_key, serial_number, _tag),
                ValueType::Record(record_name),
            ) => {
                // Add the translation data for this non-external record.
                translations.push(TranslationAssignment {
                    record_static: record_static.clone(),
                    record_dynamic: record_dynamic.clone(),
                    program_id: *callee_program_id,
                    function_id,
                    record_name: *record_name,
                    is_to_static: true,
                    is_external_record: false,
                    tvk,
                    record_view_key: Some(*record_view_key),
                    gamma: Some(*gamma),
                    id_static: *serial_number,
                    id_dynamic: *id_dynamic,
                    record_register_index: u16::try_from(operand_index)
                        .map_err(|_| anyhow!("Input operand index {operand_index} exceeds u16"))?,
                });
            }
            // Case: DynamicRecord translates to an ExternalRecord.
            (
                Value::DynamicRecord(record_dynamic),
                InputID::DynamicRecord(id_dynamic),
                ValueType::DynamicRecord,
                Value::Record(record_static),
                InputID::ExternalRecord(id_static),
                ValueType::ExternalRecord(record_locator),
            ) => {
                // Add the translation data for this external record.
                translations.push(TranslationAssignment {
                    record_static: record_static.clone(),
                    record_dynamic: record_dynamic.clone(),
                    program_id: *record_locator.program_id(),
                    function_id,
                    record_name: *record_locator.resource(),
                    is_to_static: true,
                    is_external_record: true,
                    tvk,
                    record_view_key: None,
                    gamma: None,
                    id_static: *id_static,
                    id_dynamic: *id_dynamic,
                    record_register_index: u16::try_from(operand_index)
                        .map_err(|_| anyhow!("Input operand index {operand_index} exceeds u16"))?,
                });
            }
            // Plaintext values do not require translation.
            (Value::Plaintext(..), ..) => {}
            // Record values that don't match the above patterns do not require translation.
            (Value::Record(..), ..) => {}
            // Future values do not require translation.
            (Value::Future(..), ..) => {}
            // DynamicFuture values do not require translation.
            (Value::DynamicFuture(..), ..) => {}
            // DynamicRecord values that don't match the above patterns do not require translation.
            (Value::DynamicRecord(..), ..) => {}
        }
    }

    Ok(translations)
}

// Collects output record translations from static to dynamic records.
// The `compute_record_view_key` closure computes the record view key for non-external records.
fn collect_output_translations<N: Network>(
    caller_values: &[Value<N>],
    caller_ids: &[OutputID<N>],
    caller_types: &[ValueType<N>],
    callee_values: &[Value<N>],
    callee_ids: &[OutputID<N>],
    callee_types: &[ValueType<N>],
    callee_program_id: &ProgramID<N>,
    function_id: Field<N>,
    tvk: Field<N>,
    num_inputs: usize,
    compute_record_view_key: impl Fn(usize, &console::program::Record<N, Plaintext<N>>) -> Result<Option<Field<N>>>,
) -> Result<Vec<TranslationAssignment<N>>> {
    // Validate that all arrays have the same length.
    check_translation_array_lengths(
        "Outputs",
        caller_values.len(),
        caller_ids.len(),
        caller_types.len(),
        callee_values.len(),
        callee_ids.len(),
        callee_types.len(),
    )?;

    // Initialize the translations vector.
    let mut translations = Vec::new();

    // Iterate over all outputs, matching caller and callee data.
    for (operand_index, (caller_value, caller_id, caller_type, callee_value, callee_id, callee_type)) in
        itertools::izip!(caller_values, caller_ids, caller_types, callee_values, callee_ids, callee_types).enumerate()
    {
        match (caller_value, caller_id, caller_type, callee_value, callee_id, callee_type) {
            // Case: DynamicRecord translates to a non-external Record.
            (
                Value::DynamicRecord(record_dynamic),
                OutputID::DynamicRecord(id_dynamic),
                ValueType::DynamicRecord,
                Value::Record(record_static),
                OutputID::Record(id_static, _checksum, _sender_ciphertext),
                ValueType::Record(record_name),
            ) => {
                // Compute the record view key for this non-external record.
                let record_view_key = compute_record_view_key(operand_index, record_static)?;

                // Add the translation data for this non-external record.
                translations.push(TranslationAssignment {
                    record_static: record_static.clone(),
                    record_dynamic: record_dynamic.clone(),
                    program_id: *callee_program_id,
                    function_id,
                    record_name: *record_name,
                    is_to_static: false,
                    is_external_record: false,
                    tvk,
                    record_view_key,
                    gamma: None,
                    id_static: *id_static,
                    id_dynamic: *id_dynamic,
                    record_register_index: u16::try_from(num_inputs + operand_index)
                        .map_err(|_| anyhow!("Output operand index {} exceeds u16", num_inputs + operand_index))?,
                });
            }
            // Case: DynamicRecord translates to an ExternalRecord.
            (
                Value::DynamicRecord(record_dynamic),
                OutputID::DynamicRecord(id_dynamic),
                ValueType::DynamicRecord,
                Value::Record(record_static),
                OutputID::ExternalRecord(id_static),
                ValueType::ExternalRecord(record_locator),
            ) => {
                // Add the translation data for this external record.
                translations.push(TranslationAssignment {
                    record_static: record_static.clone(),
                    record_dynamic: record_dynamic.clone(),
                    program_id: *record_locator.program_id(),
                    function_id,
                    record_name: *record_locator.resource(),
                    is_to_static: false,
                    is_external_record: true,
                    tvk,
                    record_view_key: None,
                    gamma: None,
                    id_static: *id_static,
                    id_dynamic: *id_dynamic,
                    record_register_index: u16::try_from(num_inputs + operand_index)
                        .map_err(|_| anyhow!("Output operand index {} exceeds u16", num_inputs + operand_index))?,
                });
            }
            // Plaintext values do not require translation.
            (Value::Plaintext(..), ..) => {}
            // Record values that don't match the above patterns do not require translation.
            (Value::Record(..), ..) => {}
            // Future values do not require translation.
            (Value::Future(..), ..) => {}
            // DynamicFuture values do not require translation.
            (Value::DynamicFuture(..), ..) => {}
            // DynamicRecord values that don't match the above patterns do not require translation.
            (Value::DynamicRecord(..), ..) => {}
        }
    }

    Ok(translations)
}
