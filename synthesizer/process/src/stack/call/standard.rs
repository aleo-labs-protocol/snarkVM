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

impl<N: Network> CallTrait<N> for Call<N> {
    /// Evaluates the instruction.
    #[inline]
    fn evaluate<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        stack: &Stack<N>,
        registers: &mut Registers<N, A>,
        rng: &mut R,
    ) -> Result<(), CallEvalError> {
        let timer = timer!("Call::evaluate");

        // Load the operands values.
        let inputs: Vec<_> = self.operands().iter().map(|operand| registers.load(stack, operand)).try_collect()?;

        // Retrieve the optional external stack and resource.
        let (external_stack, resource) = match self.operator() {
            // Retrieve the call stack and resource from the locator.
            CallOperator::Locator(locator) => {
                (Some(stack.get_external_stack(locator.program_id())?), locator.resource())
            }
            CallOperator::Resource(resource) => {
                // TODO (howardwu): Revisit this decision to forbid calling internal functions. A record cannot be spent again.
                //  But there are legitimate uses for passing a record through to an internal function.
                //  We could invoke the internal function without a state transition, but need to match visibility.
                if stack.program().contains_function(resource) {
                    return Err(
                        anyhow!("Cannot call '{resource}'. Use a closure ('closure {resource}:') instead.").into()
                    );
                }
                (None, resource)
            }
        };
        // Retrieve the substack.
        let substack = match &external_stack {
            Some(external_stack) => external_stack.as_ref(),
            None => stack,
        };
        lap!(timer, "Retrieved the substack and resource");

        // If the operator is a closure, retrieve the closure and compute the output.
        let outputs = if let Ok(closure) = substack.program().get_closure(resource) {
            // Ensure the number of inputs matches the number of input statements.
            if closure.inputs().len() != inputs.len() {
                return Err(anyhow!("Expected {} inputs, found {}", closure.inputs().len(), inputs.len()).into());
            }
            // Evaluate the closure, and load the outputs.
            substack.evaluate_closure::<A>(
                &closure,
                &inputs,
                registers.call_stack(),
                registers.signer()?,
                registers.caller()?,
                registers.tvk()?,
            )?
        }
        // If the operator is a function, retrieve the function and compute the output.
        else if let Ok(function) = substack.program().get_function(resource) {
            // Ensure the number of inputs matches the number of input statements.
            if function.inputs().len() != inputs.len() {
                return Err(anyhow!("Expected {} inputs, found {}", function.inputs().len(), inputs.len()).into());
            }

            // Get the 'root_tvk'.
            let root_tvk = Some(registers.root_tvk()?);

            // Get the call stack.
            let mut call_stack = registers.call_stack();

            // In Authorize mode, we need to compute the new request and push it onto the call stack.
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
                // Compute the request.
                let request = Request::sign(
                    private_key,
                    *substack.program_id(),
                    *function.name(),
                    inputs.iter(),
                    &function.input_types(),
                    root_tvk,
                    is_root,
                    program_checksum,
                    false,
                    rng,
                )?;
                // Add the request to the requests.
                requests.push(request.clone());
                // Add the request to the authorization.
                authorization.push(request.clone())?;
            }

            // In AuthorizeMocked mode, we need to compute the mocked request and push it onto the call stack.
            if let CallStack::AuthorizeMocked(requests, address, authorization, _, _) = &mut call_stack {
                // Compute the mocked request.
                let request = Request::sample(
                    *address,
                    *substack.program_id(),
                    *function.name(),
                    inputs.iter(),
                    &function.input_types(),
                    false,
                    rng,
                )?;
                // Add the request to the requests.
                requests.push(request.clone());
                // Add the request to the authorization.
                authorization.push(request.clone())?;
            }

            // In AuthorizeRequests mode, we retrieve the expected request and match it against the call's target and inputs.
            if let CallStack::AuthorizeRequests(requests, current_index, authorization) = &mut call_stack {
                // Increment the index to advance the pre-order DFS traversal of the request tree.
                *current_index.write() += 1;

                let request = requests.get(*current_index.read()).ok_or_else(||
                    anyhow!("Call::evaluate attempted to retrieve request at index {}, but the AuthorizeRequests call stack only contains {} request(s)",
                    *current_index.read(),
                    requests.len())
                )?;

                // Sanity checks
                if *request.signer() != registers.signer()? {
                    return Err(anyhow!(
                        "Call::evaluate retrieved a request with a different signer than the signer in the registers"
                    )
                    .into());
                }
                if request.is_dynamic() {
                    return Err(anyhow!("Call::evaluate retrieved a dynamic request").into());
                }

                // Consistency checks: target program, target function and inputs
                if request.program_id() != substack.program_id() {
                    return Err(anyhow!("Call::evaluate retrieved a request with a different program ID than the one in the call instruction").into());
                }
                if request.function_name() != function.name() {
                    return Err(anyhow!("Call::evaluate retrieved a request with a different function name than the one in the call instruction").into());
                }
                if request.inputs() != inputs {
                    return Err(anyhow!("Call::evaluate retrieved a request with different inputs than the ones passed to the call instruction").into());
                }

                // Add the request to the authorization.
                authorization.push(request.clone())?;
            }

            // Set the (console) caller.
            let console_caller = Some(*stack.program_id());
            // Evaluate the function.
            let response = substack.evaluate_function::<A, R>(call_stack, console_caller, root_tvk, rng)?;
            // Load the outputs.
            response.outputs().to_vec()
        }
        // Else, throw an error.
        else {
            return Err(anyhow!("Call operator '{}' is invalid or unsupported.", self.operator()).into());
        };
        lap!(timer, "Computed outputs");

        // Assign the outputs to the destination registers.
        if outputs.len() != self.destinations().len() {
            return Err(anyhow!(
                "[evaluate Standard] Expected {} outputs, but {} were provided.",
                self.destinations().len(),
                outputs.len()
            )
            .into());
        }
        for (output, register) in outputs.into_iter().zip(&self.destinations()) {
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
        let timer = timer!("Call::execute");

        // Load the operands values.
        let inputs: Vec<_> =
            self.operands().iter().map(|operand| registers.load_circuit(stack, operand)).try_collect()?;

        // Retrieve the optional external stack and resource.
        let (external_stack, resource) = match self.operator() {
            // Retrieve the call stack and resource from the locator.
            CallOperator::Locator(locator) => {
                // Check the external call locator.
                let function_name = locator.name().to_string();
                let is_credits_program = &locator.program_id().to_string() == "credits.aleo";
                let is_fee_private = &function_name == "fee_private";
                let is_fee_public = &function_name == "fee_public";

                // Ensure the external call is not to 'credits.aleo/fee_private' or 'credits.aleo/fee_public'.
                if is_credits_program && (is_fee_private || is_fee_public) {
                    return Err(anyhow!(
                        "Cannot perform an external call to 'credits.aleo/fee_private' or 'credits.aleo/fee_public'."
                    )
                    .into());
                } else {
                    (Some(stack.get_external_stack(locator.program_id())?), locator.resource())
                }
            }
            CallOperator::Resource(resource) => {
                // TODO (howardwu): Revisit this decision to forbid calling internal functions. A record cannot be spent again.
                //  But there are legitimate uses for passing a record through to an internal function.
                //  We could invoke the internal function without a state transition, but need to match visibility.
                if stack.program().contains_function(resource) {
                    return Err(
                        anyhow!("Cannot call '{resource}'. Use a closure ('closure {resource}:') instead.").into()
                    );
                }
                (None, resource)
            }
        };
        // Retrieve the substack.
        let substack = match &external_stack {
            Some(external_stack) => external_stack.as_ref(),
            None => stack,
        };
        lap!(timer, "Retrieve the substack and resource");

        // If we are not handling the root request, retrieve the root request's tvk
        let root_tvk = registers.root_tvk().ok();

        // Retrieve the program checksum, if the program has a constructor.
        let program_checksum = match substack.program().contains_constructor() {
            true => Some(substack.program_checksum_as_field()?),
            false => None,
        };

        // If the operator is a closure, retrieve the closure and compute the output.
        let outputs = if let Ok(closure) = substack.program().get_closure(resource) {
            lap!(timer, "Execute the closure");
            // Execute the closure, and load the outputs.
            substack.execute_closure(
                &closure,
                &inputs,
                registers.call_stack(),
                registers.signer_circuit()?,
                registers.caller_circuit()?,
                registers.tvk_circuit()?,
            )?
        }
        // If the operator is a function, retrieve the function and compute the output.
        else if let Ok(function) = substack.program().get_function(resource) {
            lap!(timer, "Execute the function");
            // Retrieve the number of inputs.
            let num_inputs = function.inputs().len();
            // Ensure the number of inputs matches the number of input statements.
            if num_inputs != inputs.len() {
                return Err(anyhow!("Expected {} inputs, found {}", num_inputs, inputs.len()).into());
            }

            // Retrieve the number of public variables in the circuit.
            let num_public = A::num_public();

            // Indicate that external calls are never a root request.
            let is_root = false;

            use circuit::Eject;
            // Eject the existing circuit.
            let r1cs = A::eject_r1cs_and_reset();
            let (request, response) = {
                // Eject the circuit inputs.
                let inputs = inputs.eject_value();

                // Set the (console) caller.
                let console_caller = Some(*stack.program_id());
                // Check if the substack has a proving key or not.
                let pk_missing = !substack.contains_proving_key(function.name());

                match registers.call_stack_ref() {
                    // If the circuit is in authorize mode, then add any external calls to the stack.
                    CallStack::Authorize(_, private_key, authorization) => {
                        // Ensure that we have a private key to sign the new request.
                        let Some(private_key) = private_key else {
                            return Err(anyhow!("Cannot authorize a new function call without a private key.").into());
                        };
                        // Compute the request.
                        let request = Request::sign(
                            private_key,
                            *substack.program_id(),
                            *function.name(),
                            inputs.iter(),
                            &function.input_types(),
                            root_tvk,
                            is_root,
                            program_checksum,
                            false,
                            rng,
                        )?;

                        // Retrieve the call stack.
                        let mut call_stack = registers.call_stack();
                        // Push the request onto the call stack.
                        call_stack.push(request.clone())?;

                        // Add the request to the authorization.
                        authorization.push(request.clone())?;

                        // Execute the request.
                        let response = substack.execute_function::<A, R>(call_stack, console_caller, root_tvk, rng)?;

                        // Return the request and response.
                        (request, response)
                    }
                    // If the circuit is in AuthorizeMocked mode, throw an error.
                    CallStack::AuthorizeMocked(..) => {
                        return Err(anyhow!("Cannot 'execute' a function in 'AuthorizeMocked' mode.").into());
                    }
                    // If the circuit is in AuthorizeRequests mode, throw an error.
                    CallStack::AuthorizeRequests(..) => {
                        return Err(anyhow!("Cannot 'execute' a function in 'authorize requests' mode.").into());
                    }
                    // If the proving key is missing, build real sub-circuit.
                    CallStack::Synthesize(_, private_key, ..) if pk_missing => {
                        // Compute the request.
                        let request = Request::sign(
                            private_key,
                            *substack.program_id(),
                            *function.name(),
                            inputs.iter(),
                            &function.input_types(),
                            root_tvk,
                            is_root,
                            program_checksum,
                            false,
                            rng,
                        )?;

                        // Retrieve the call stack.
                        let mut call_stack = registers.call_stack();

                        // Push the request onto the call stack.
                        call_stack.push(request.clone())?;

                        // Synthesize the circuit. Note the response will be empty.
                        let response = substack.execute_function::<A, R>(call_stack, console_caller, root_tvk, rng)?;

                        if response.is_some() {
                            return Err(anyhow!(
                                "execute_function should return an empty Response in 'Synthesize' mode."
                            )
                            .into());
                        }

                        // Return the request and response.
                        (request, None)
                    }
                    // In Synthesize mode (with an existing proving key) or CheckDeployment mode, we generate dummy outputs to avoid building a full sub-circuit.
                    CallStack::Synthesize(_, private_key, ..) | CallStack::CheckDeployment(_, private_key, ..) => {
                        // Compute the request.
                        let request = Request::sign(
                            private_key,
                            *substack.program_id(),
                            *function.name(),
                            inputs.iter(),
                            &function.input_types(),
                            root_tvk,
                            is_root,
                            program_checksum,
                            false,
                            rng,
                        )?;

                        // Return the request and response.
                        (request, None)
                    }
                    // In PackageRun mode, we sign and execute the request once.
                    CallStack::PackageRun(_, private_key, ..) => {
                        // Compute the request.
                        let request = Request::sign(
                            private_key,
                            *substack.program_id(),
                            *function.name(),
                            inputs.iter(),
                            &function.input_types(),
                            root_tvk,
                            is_root,
                            program_checksum,
                            false,
                            rng,
                        )?;

                        // Retrieve the call stack.
                        let mut call_stack = registers.call_stack();
                        // Push the request onto the call stack.
                        call_stack.push(request.clone())?;

                        // Evaluate the request.
                        let response = substack.execute_function::<A, _>(call_stack, console_caller, root_tvk, rng)?;

                        // Return the request and response.
                        (request, response)
                    }
                    // If the circuit is in evaluate mode, then throw an error.
                    CallStack::Evaluate(..) => {
                        return Err(anyhow!("Cannot 'execute' a function in 'Evaluate' mode.").into());
                    }
                    // If the circuit is in execute mode, then evaluate and execute the instructions.
                    CallStack::Execute(authorization, ..) => {
                        // Retrieve the next request (without popping it).
                        let request = authorization.peek_next()?;
                        // Ensure the request is for the target of the call instruction.
                        if *request.signer() != registers.signer()? {
                            return Err(anyhow!("[execute Standard] Retrieved a request with a different signer than the signer in the registers").into());
                        }
                        if request.is_dynamic() {
                            return Err(anyhow!("[execute Standard] Retrieved a dynamic request").into());
                        }
                        if request.program_id() != substack.program_id() {
                            return Err(anyhow!("[execute Standard] Retrieved a request with a different program ID than the one in the call instruction").into());
                        }
                        if request.function_name() != function.name() {
                            return Err(anyhow!("[execute Standard] Retrieved a request with a different function name than the one in the call instruction").into());
                        }
                        // Ensure the inputs match the original inputs.
                        if request.inputs().len() != inputs.len() {
                            return Err(anyhow!(
                                "[execute Standard] Expected {} inputs, but {} were provided.",
                                request.inputs().len(),
                                inputs.len()
                            )
                            .into());
                        }
                        request.inputs().iter().zip(&inputs).try_for_each(|(request_input, input)| {
                            ensure!(request_input == input, "Inputs do not match in a 'call' instruction.");
                            Ok(())
                        })?;

                        // Evaluate the function, and load the outputs.
                        let console_response = substack.evaluate_function::<A, R>(
                            registers.call_stack(),
                            console_caller,
                            root_tvk,
                            rng,
                        )?;
                        // Execute the request.
                        let Some(response) =
                            substack.execute_function::<A, R>(registers.call_stack(), console_caller, root_tvk, rng)?
                        else {
                            return Err(anyhow!("Response should be present in 'Execute' mode.").into());
                        };

                        // Ensure the values are equal.
                        if console_response.outputs() != response.outputs() {
                            dev_eprintln!("\n{:#?} != {:#?}\n", console_response.outputs(), response.outputs());
                            return Err(anyhow!(
                                "Function '{}' outputs do not match in a 'call' instruction.",
                                function.name()
                            )
                            .into());
                        }
                        // Return the request and response.
                        (request, Some(response))
                    }
                }
            };
            lap!(timer, "Computed the request and response");

            // Inject the existing circuit.
            A::inject_r1cs(r1cs);

            use circuit::Inject;

            // Inject the network ID as `Mode::Constant`.
            let network_id = circuit::U16::constant(*request.network_id());
            // Inject the program ID as `Mode::Constant`.
            let program_id = circuit::ProgramID::constant(*substack.program_id());
            // Inject the function name as `Mode::Constant`.
            let function_name = circuit::Identifier::constant(*function.name());

            // Ensure the number of public variables remains the same.
            if A::num_public() != num_public {
                return Err(anyhow!("Forbidden: 'call' injected excess public variables").into());
            }

            // Inject the `signer` (from the request) as `Mode::Private`.
            let signer = circuit::Address::new(circuit::Mode::Private, *request.signer());
            // Inject the `sk_tag` (from the request) as `Mode::Private`.
            let sk_tag = circuit::Field::new(circuit::Mode::Private, *request.sk_tag());
            // Inject the `tvk` (from the request) as `Mode::Private`.
            let tvk = circuit::Field::new(circuit::Mode::Private, *request.tvk());
            // Inject the `tcm` (from the request) as `Mode::Public`.
            let tcm = circuit::Field::new(circuit::Mode::Public, *request.tcm());
            // Compute the transition commitment as `Hash(tvk)`.
            let candidate_tcm = A::hash_psd2(std::slice::from_ref(&tvk));
            // Ensure the transition commitment matches the computed transition commitment.
            A::assert_eq(&tcm, candidate_tcm)?;
            // Inject the input IDs (from the request) as `Mode::Public`.
            let input_ids = request
                .input_ids()
                .iter()
                .map(|input_id| circuit::InputID::new(circuit::Mode::Public, *input_id))
                .collect::<Vec<_>>();

            // Ensure the candidate input IDs match their computed inputs.
            let (check_input_ids, _) = circuit::Request::check_input_ids::<false>(
                &network_id,
                &program_id,
                &function_name,
                &input_ids,
                &inputs,
                &function.input_types(),
                &signer,
                &sk_tag,
                &tvk,
                &tcm,
                None,
                None,
            );
            A::assert(check_input_ids)?;
            lap!(timer, "Checked the input ids");

            // Retrieve the output registers.
            let output_registers = function
                .outputs()
                .iter()
                .map(|output| match output.operand() {
                    Operand::Register(register) => Some(register.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();

            let outputs = match registers.call_stack_ref() {
                // In Synthesize and CheckDeployment modes, `response` is None at this point. Only its outputs
                // are used in the remainder of this function, and only their types (and not specific values)
                // are relevant, so we sample them instead.
                CallStack::Synthesize(_, private_key, ..) | CallStack::CheckDeployment(_, private_key, ..) => {
                    if response.is_some() {
                        return Err(
                            anyhow!("Response should be empty in 'Synthesize' and 'CheckDeployment' modes.").into()
                        );
                    }

                    let address = Address::try_from(private_key)?;

                    function
                        .outputs()
                        .iter()
                        .map(|output| match output.value_type() {
                            ValueType::Record(record_name) => {
                                let index = match output.operand() {
                                    Operand::Register(Register::Locator(index)) => Field::from_u64(*index),
                                    _ => {
                                        return Err(anyhow!(
                                            "Expected a `Register::Locator` operand for a record output."
                                        ));
                                    }
                                };
                                // Sample the record.
                                Ok(Value::Record(substack.sample_record_using_tvk(
                                    &address,
                                    record_name,
                                    *request.tvk(),
                                    index,
                                    rng,
                                )?))
                            }
                            // For non-record outputs, call sample_value.
                            _ => substack.sample_value(&address, &output.value_type().into(), rng),
                        })
                        .collect::<Result<Vec<_>>>()?
                }
                _ => {
                    if let Some(response) = response {
                        response.outputs().to_vec()
                    } else {
                        return Err(anyhow!(
                            "Response should be populated in all modes except 'Synthesize' and 'CheckDeployment'."
                        )
                        .into());
                    }
                }
            };

            // Inject the outputs as `Mode::Private` (with the 'tcm' and output IDs as `Mode::Public`).
            let outputs = circuit::Response::process_outputs_from_callback(
                &network_id,
                &program_id,
                &function_name,
                num_inputs,
                &tvk,
                &tcm,
                outputs,
                &function.output_types(),
                &output_registers,
                None,
            );
            lap!(timer, "Checked the outputs");
            // Return the circuit outputs.
            outputs
        }
        // Else, throw an error.
        else {
            return Err(anyhow!("Call operator '{}' is invalid or unsupported.", self.operator()).into());
        };

        // Assign the outputs to the destination registers.
        if outputs.len() != self.destinations().len() {
            return Err(anyhow!(
                "[execute Standard] Expected {} outputs, but {} were provided.",
                self.destinations().len(),
                outputs.len()
            )
            .into());
        }
        for (output, register) in outputs.into_iter().zip(&self.destinations()) {
            // Assign the output to the register.
            registers.store_circuit(stack, register, output)?;
        }
        lap!(timer, "Assigned the outputs to registers");

        finish!(timer);

        Ok(())
    }
}
