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
use snarkvm_synthesizer_error::*;

use std::sync::OnceLock;

impl<N: Network> Stack<N> {
    /// Evaluates a program closure on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    pub fn evaluate_closure<A: circuit::Aleo<Network = N>>(
        &self,
        closure: &Closure<N>,
        inputs: &[Value<N>],
        call_stack: CallStack<N>,
        signer: Address<N>,
        caller: Address<N>,
        tvk: Field<N>,
    ) -> Result<Vec<Value<N>>, StackEvalError> {
        let timer = timer!("Stack::evaluate_closure");

        // Ensure the number of inputs matches the number of input statements.
        if closure.inputs().len() != inputs.len() {
            return Err(anyhow!("Expected {} inputs, found {}", closure.inputs().len(), inputs.len()).into());
        }

        // Initialize the registers.
        let mut registers =
            Registers::<N, A>::new(call_stack.clone(), self.get_register_types(closure.name())?.clone());
        // Set the transition signer.
        registers.set_signer(signer);
        // Set the transition caller.
        registers.set_caller(caller);
        // Set the transition view key.
        registers.set_tvk(tvk);
        lap!(timer, "Initialize the registers");

        // Store the inputs.
        closure.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            // Assign the input value to the register.
            registers.store(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");

        // Evaluate the instructions.
        for (ix, instruction) in closure.instructions().iter().enumerate() {
            // If the evaluation fails, bail and return the error.
            if let Err(error) = instruction.evaluate(self, &mut registers) {
                return Err(IndexedInstructionError::new(ix, format!("{instruction}"), error.into()).into());
            }
        }
        lap!(timer, "Evaluate the instructions");

        // Load the outputs.
        let outputs = closure
            .outputs()
            .iter()
            .map(|output| -> Result<_> {
                match output.operand() {
                    // If the operand is a literal, use the literal directly.
                    Operand::Literal(literal) => Ok(Value::Plaintext(Plaintext::from(literal))),
                    // If the operand is a register, retrieve the stack value from the register.
                    Operand::Register(register) => registers.load(self, &Operand::Register(register.clone())),
                    // If the operand is the program ID, convert the program ID into an address.
                    Operand::ProgramID(program_id) => {
                        Ok(Value::Plaintext(Plaintext::from(Literal::Address(program_id.to_address()?))))
                    }
                    // If the operand is the signer, retrieve the signer from the registers.
                    Operand::Signer => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.signer()?)))),
                    // If the operand is the caller, retrieve the caller from the registers.
                    Operand::Caller => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.caller()?)))),
                    // If the operand is the generator, retrieve the Aleo generator.
                    Operand::AleoGenerator => N::g_powers()
                        .first()
                        .map(|element| Value::Plaintext(Plaintext::from(Literal::Group(*element))))
                        .ok_or_else(|| anyhow!("Failed to retrieve the Aleo generator.")),
                    // If the operand is the generator powers, retrieve the generator powers or the indexed group.
                    Operand::AleoGeneratorPowers(index) => match index {
                        None => Ok(Value::Plaintext(Plaintext::Array(
                            N::g_powers().iter().map(|element| Plaintext::from(Literal::Group(*element))).collect(),
                            OnceLock::new(),
                        ))),
                        Some(index) => N::g_powers()
                            .get(**index as usize)
                            .map(|element| Value::Plaintext(Plaintext::from(Literal::Group(*element))))
                            .ok_or_else(|| anyhow!("Index {index} out of bounds for Aleo generator")),
                    },
                    // If the operand is the block height, throw an error.
                    Operand::BlockHeight => bail!("Cannot retrieve the block height from a closure scope."),
                    // If the operand is the block timestamp, throw an error.
                    Operand::BlockTimestamp => bail!("Cannot retrieve the block timestamp from a closure scope."),
                    // If the operand is the network id, throw an error.
                    Operand::NetworkID => bail!("Cannot retrieve the network ID from a closure scope."),
                    // If the operand is the program checksum, throw an error.
                    Operand::Checksum(_) => bail!("Cannot retrieve the program checksum from a closure scope."),
                    // If the operand is the program edition, throw an error.
                    Operand::Edition(_) => bail!("Cannot retrieve the edition from a closure scope."),
                    // If the operand is the program owner, throw an error.
                    Operand::ProgramOwner(_) => bail!("Cannot retrieve the program owner from a closure scope."),
                    // If the operand is the component checksum, throw an error.
                    Operand::ComponentChecksum(..) => {
                        bail!("Cannot retrieve the component checksum from a closure scope.")
                    }
                }
            })
            .map(|res| res.map_err(StackEvalError::from))
            .collect();
        lap!(timer, "Load the outputs");

        finish!(timer);
        outputs
    }

    /// Evaluates a program function on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    pub fn evaluate_function<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        mut call_stack: CallStack<N>,
        caller: Option<ProgramID<N>>,
        root_tvk: Option<Field<N>>,
        rng: &mut R,
    ) -> Result<Response<N>, StackEvalError> {
        let timer = timer!("Stack::evaluate_function");

        // Retrieve the next request, based on the call stack mode.
        let (request, call_stack) =
            match &mut call_stack {
                CallStack::Authorize(..) => (call_stack.pop()?, call_stack),
                CallStack::AuthorizeMocked(..) => (call_stack.pop()?, call_stack),
                CallStack::AuthorizeRequests(requests, current_index, _) => {
                    let request = requests.get(*current_index.read()).ok_or_else(|| anyhow!("Attempted to recover request at index {}, but the AuthorizeRequests call stack only contains {} request(s)", *current_index.read(), requests.len()))?;
                    (request.clone(), call_stack)
                }
                CallStack::Evaluate(authorization) => (authorization.next()?, call_stack),
                // If the evaluation is performed in the `Execute` mode, create a new `Evaluate` mode.
                // This is done to ensure that evaluation during execution is performed consistently.
                CallStack::Execute(authorization, _, _) => {
                    // Note: We need to replicate the authorization, so that 'execute' can call 'authorization.next()?'.
                    // This way, the authorization remains unmodified in this 'evaluate' scope.
                    let authorization = authorization.replicate();
                    let request = authorization.next()?;
                    let call_stack = CallStack::Evaluate(authorization);
                    (request, call_stack)
                }
                _ => return Err(anyhow!(
                    "Illegal operation: call stack must be `Authorize`, `Evaluate`, `Execute` or `AuthorizeMocked` or `AuthorizeRequests` in `evaluate_function`."
                )
                .into()),
            };
        lap!(timer, "Retrieve the next request");

        // Ensure the network ID matches.
        if **request.network_id() != N::ID {
            return Err(anyhow!("Network ID mismatch. Expected {}, but found {}", N::ID, request.network_id()).into());
        }

        // Retrieve the function, inputs, and transition view key.
        let function = self.get_function(request.function_name())?;
        let inputs = request.inputs();
        let signer = *request.signer();
        let (is_root, caller) = match caller {
            // If a caller is provided, then this is an evaluation of a child function.
            Some(caller) => (false, caller.to_address()?),
            // If no caller is provided, then this is an evaluation of a top-level function.
            None => (true, signer),
        };
        let tvk = *request.tvk();
        // Retrieve the program checksum, if the program has a constructor.
        let program_checksum = match self.program().contains_constructor() {
            true => Some(self.program_checksum_as_field()?),
            false => None,
        };

        // Ensure the number of inputs matches.
        if function.inputs().len() != inputs.len() {
            return Err(anyhow!(
                "Function '{}' in the program '{}' expects {} inputs, but {} were provided.",
                function.name(),
                self.program.id(),
                function.inputs().len(),
                inputs.len()
            )
            .into());
        }
        lap!(timer, "Perform input checks");

        // Ensure the request is well-formed (unless it has been mocked).
        if !matches!(call_stack, CallStack::AuthorizeMocked(..))
            && !request.verify(&function.input_types(), is_root, program_checksum)
        {
            return Err(anyhow!("[Evaluate] Request is invalid").into());
        }
        lap!(timer, "Verify the request");

        // In AuthorizeMocked mode, capture the index of the request currently being evaluated,
        // which is necessary to populate the record-tracking machinery. Note the same value is
        // used below when processing the outputs.
        let current_request_index = match &call_stack {
            CallStack::AuthorizeMocked(_, _, authorization, _, _) => authorization.len() - 1,
            _ => 0,
        };

        // In AuthorizeMocked mode, detect whether any input static, external or dynamic records
        // have been minted by other requests in the transaction and track them.
        if let CallStack::AuthorizeMocked(_, _, _, _, input_records) = &call_stack {
            let mut input_records = input_records.write();

            for (input_index, input) in inputs.iter().enumerate() {
                match input {
                    Value::Record(record) => {
                        input_records
                            .entry(record.nonce().to_x_coordinate())
                            .or_default()
                            .push((current_request_index, input_index));
                    }
                    Value::DynamicRecord(dynamic_record) => {
                        input_records
                            .entry(dynamic_record.nonce().to_x_coordinate())
                            .or_default()
                            .push((current_request_index, input_index));
                    }
                    _ => {}
                }
            }
        }

        // Initialize the registers.
        let mut registers = Registers::<N, A>::new(call_stack, self.get_register_types(function.name())?.clone());
        // Set the transition signer.
        registers.set_signer(signer);
        // Set the transition caller.
        registers.set_caller(caller);
        // Set the transition view key.
        registers.set_tvk(tvk);
        // Set the root tvk.
        if let Some(root_tvk) = root_tvk {
            registers.set_root_tvk(root_tvk);
        } else {
            registers.set_root_tvk(tvk);
        }
        lap!(timer, "Initialize the registers");

        // Store the inputs.
        function.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            // Assign the input value to the register.
            registers.store(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");

        // Evaluate the instructions.
        // Note: We handle the `call` instruction separately, as it requires special handling.
        for (ix, instruction) in function.instructions().iter().enumerate() {
            // Evaluate the instruction.
            let result = match instruction {
                // If the instruction is a `call` instruction, we need to handle it separately.
                Instruction::Call(call) => CallTrait::evaluate(call, self, &mut registers, rng)
                    .map_err(|e| InstructionEvalError::Call(Box::new(e))),
                // If the instruction is a `call.dynamic` instruction, we need to handle it separately.
                Instruction::CallDynamic(call_dynamic) => CallTrait::evaluate(call_dynamic, self, &mut registers, rng)
                    .map_err(|e| InstructionEvalError::Call(Box::new(e))),
                // Otherwise, evaluate the instruction normally.
                _ => instruction.evaluate(self, &mut registers).map_err(Into::into),
            };
            // If the evaluation fails, bail and return the error.
            if let Err(error) = result {
                return Err(IndexedInstructionError::new(ix, format!("{instruction}"), error).into());
            }
        }
        lap!(timer, "Evaluate the instructions");

        // Retrieve the output operands.
        let output_operands = &function.outputs().iter().map(|output| output.operand()).collect::<Vec<_>>();
        lap!(timer, "Retrieve the output operands");

        // Load the outputs.
        let outputs = output_operands
            .iter()
            .map(|operand| {
                match operand {
                    // If the operand is a literal, use the literal directly.
                    Operand::Literal(literal) => Ok(Value::Plaintext(Plaintext::from(literal))),
                    // If the operand is a register, retrieve the stack value from the register.
                    Operand::Register(register) => registers.load(self, &Operand::Register(register.clone())),
                    // If the operand is the program ID, convert the program ID into an address.
                    Operand::ProgramID(program_id) => {
                        Ok(Value::Plaintext(Plaintext::from(Literal::Address(program_id.to_address()?))))
                    }
                    // If the operand is the signer, retrieve the signer from the registers.
                    Operand::Signer => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.signer()?)))),
                    // If the operand is the caller, retrieve the caller from the registers.
                    Operand::Caller => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.caller()?)))),
                    // If the operand is the generator, retrieve the Aleo generator.
                    Operand::AleoGenerator => N::g_powers()
                        .first()
                        .map(|element| Value::Plaintext(Plaintext::from(Literal::Group(*element))))
                        .ok_or_else(|| anyhow!("Failed to retrieve the Aleo generator.")),
                    // If the operand is the generator powers, retrieve the generator powers or the indexed group.
                    Operand::AleoGeneratorPowers(index) => match index {
                        None => Ok(Value::Plaintext(Plaintext::Array(
                            N::g_powers().iter().map(|element| Plaintext::from(Literal::Group(*element))).collect(),
                            OnceLock::new(),
                        ))),
                        Some(index) => N::g_powers()
                            .get(**index as usize)
                            .map(|element| Value::Plaintext(Plaintext::from(Literal::Group(*element))))
                            .ok_or_else(|| anyhow!("Index {index} out of bounds for Aleo generator")),
                    },
                    // If the operand is the block height, throw an error.
                    Operand::BlockHeight => bail!("Cannot retrieve the block height from a function scope."),
                    // If the operand is the block timestamp, throw an error.
                    Operand::BlockTimestamp => bail!("Cannot retrieve the block timestamp from a function scope."),
                    // If the operand is the network id, throw an error.
                    Operand::NetworkID => bail!("Cannot retrieve the network ID from a function scope."),
                    // If the operand is the program checksum, throw an error.
                    Operand::Checksum(_) => bail!("Cannot retrieve the program checksum from a function scope."),
                    // If the operand is the program edition, throw an error.
                    Operand::Edition(_) => bail!("Cannot retrieve the edition from a function scope."),
                    // If the operand is the program owner, throw an error.
                    Operand::ProgramOwner(_) => bail!("Cannot retrieve the program owner from a function scope."),
                    // If the operand is the component checksum, throw an error.
                    Operand::ComponentChecksum(..) => {
                        bail!("Cannot retrieve the component checksum from a function scope.")
                    }
                }
            })
            .collect::<Result<Vec<_>>>()?;
        lap!(timer, "Load the outputs");

        // In AuthorizeMocked mode, track the minting of static records.
        if let CallStack::AuthorizeMocked(_, _, _, minted_static_records, _) = &mut registers.call_stack_ref() {
            let mut minted_static_records = minted_static_records.write();

            for ((output, output_type), operand) in outputs.iter().zip(&function.output_types()).zip(output_operands) {
                // The output type is needed to distinguish static Records from ExternalRecords
                // (which also appear as Value::Record at this point)
                if let Value::Record(record) = output
                    && let ValueType::Record(_) = output_type
                    && let Operand::Register(register) = operand
                {
                    // Insert into the minted-record tracker, returning an error if the nonce is
                    // already present (two static records which the same nonce cannot be minted.)
                    if minted_static_records
                        .insert(record.nonce().to_x_coordinate(), (current_request_index, register.locator()))
                        .is_some()
                    {
                        return Err(anyhow!("Duplicate output-record nonce found in CallStack::AuthorizeMocked. Ensure the program is correct and rerun with a different RNG state.").into());
                    }
                }
            }
        }

        // Map the output operands to registers.
        let output_registers = output_operands
            .iter()
            .map(|operand| match operand {
                Operand::Register(register) => Some(register.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        lap!(timer, "Loaded the output registers");

        // Compute the response.
        let response = Response::new(
            request.signer(),
            request.network_id(),
            self.program.id(),
            function.name(),
            request.inputs().len(),
            request.tvk(),
            request.tcm(),
            outputs,
            &function.output_types(),
            &output_registers,
        )?;
        finish!(timer);

        // If the circuit is in `Authorize`, `AuthorizeMocked` or `AuthorizeRequests` mode, then save the transition.
        if let CallStack::Authorize(_, _, authorization) | CallStack::AuthorizeRequests(_, _, authorization) =
            registers.call_stack_ref()
        {
            // Construct the transition.
            let transition = Transition::from(&request, &response, &function.output_types(), &output_registers)?;
            // Add the transition to the authorization.
            authorization.insert_transition(transition)?;
            lap!(timer, "Save the transition");
        }
        if let CallStack::AuthorizeMocked(_, _, authorization, _, _) = registers.call_stack_ref() {
            // Construct the transition without checking correctness of input IDs.
            let transition =
                Transition::from_unchecked(&request, &response, &function.output_types(), &output_registers)?;
            // Add the transition to the authorization.
            authorization.insert_transition(transition)?;
            lap!(timer, "Save the mocked transition");
        }

        Ok(response)
    }
}
