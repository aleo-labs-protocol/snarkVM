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
use console::program::{FinalizeType, Future, Identifier, Register};
use snarkvm_synthesizer_error::{FinalizeError, IndexedFinalizeError, IntoIndexedFinalize, indexed_finalize_bail};
use snarkvm_synthesizer_program::{Await, FinalizeRegistersState, FinalizeStoreTrait, Operand, RegistersTrait};
use snarkvm_utilities::try_vm_runtime;

use std::collections::HashSet;

type TotalAwaits = usize;

impl<'a, N: Network> ProcessExclusiveGuard<'a, N> {
    /// Finalizes the deployment and fee.
    /// This method assumes the given deployment **is valid**.
    /// This method should **only** be called by `VM::finalize()`.
    #[inline]
    pub fn finalize_deployment<P: FinalizeStorage<N>>(
        &self,
        state: FinalizeGlobalState,
        store: &FinalizeStore<N, P>,
        deployment: &Deployment<N>,
        fee: &Fee<N>,
    ) -> Result<(Stack<N>, Vec<FinalizeOperation<N>>), IndexedFinalizeError<N, Command<N>>> {
        let timer = timer!("Process::finalize_deployment");

        // Fetch the program ID.
        let deploy_program_id = deployment.program().id();

        // Get the deployment version.
        let version = deployment.version()?;

        // Finalize the deployment based on its version.
        match version {
            DeploymentVersion::V1 | DeploymentVersion::V2 => {
                // Compute the program stack.
                let mut stack = Stack::new(self.process, deployment.program()).into_indexed(
                    Some((*deploy_program_id, deployment.edition())),
                    None,
                    None::<(usize, Command<N>)>,
                )?;
                lap!(timer, "Compute the stack");

                // Set the program owner.
                stack.set_program_owner(deployment.program_owner());

                // Insert all verifying keys (unified: functions + records).
                for (function_name, (verifying_key, _)) in deployment.verifying_keys() {
                    stack.insert_verifying_key(function_name, verifying_key.clone()).into_indexed(
                        Some((*deploy_program_id, deployment.edition())),
                        None,
                        None::<(usize, Command<N>)>,
                    )?;
                }
                lap!(timer, "Insert the verifying keys");

                // Determine which mappings must be initialized.
                let mappings = match deployment.edition().is_zero() {
                    true => deployment.program().mappings().values().collect::<Vec<_>>(),
                    false => {
                        // Get the existing stack.
                        let existing_stack = self.process.get_stack(deployment.program_id()).into_indexed(
                            Some((*deploy_program_id, deployment.edition())),
                            None,
                            None::<(usize, Command<N>)>,
                        )?;
                        // Get the existing mappings.
                        let existing_mappings = existing_stack.program().mappings();
                        // Determine and return the new mappings.
                        let mut new_mappings = Vec::new();
                        for mapping in deployment.program().mappings().values() {
                            if !existing_mappings.contains_key(mapping.name()) {
                                new_mappings.push(mapping);
                            }
                        }
                        new_mappings
                    }
                };
                lap!(timer, "Retrieve the mappings to initialize");

                // Initialize the mappings, and store their finalize operations.
                atomic_batch_scope!(store, IndexedFinalizeError::<N, Command<N>>, {
                    // Initialize a list for the finalize operations.
                    let mut finalize_operations = Vec::with_capacity(deployment.program().mappings().len());

                    /* Finalize the fee. */

                    // Retrieve the fee stack.
                    let fee_stack = self.process.get_stack(fee.program_id()).into_indexed(
                        Some((*fee.program_id(), self.get_latest_edition_for_program(fee.program_id()))),
                        Some(*fee.function_name()),
                        None::<(usize, Command<N>)>,
                    )?;
                    // Finalize the fee transition.
                    finalize_operations.extend(finalize_fee_transition(state, store, &fee_stack, fee)?);
                    lap!(timer, "Finalize transition for '{}/{}'", fee.program_id(), fee.function_name());

                    /* Finalize the deployment. */

                    // Retrieve the program ID.
                    let program_id = deployment.program_id();
                    // Iterate over the mappings that must be initialized.
                    for mapping in mappings {
                        // Initialize the mapping.
                        finalize_operations.push(store.initialize_mapping(*program_id, *mapping.name()).into_indexed(
                            Some((*program_id, deployment.edition())),
                            None,
                            None::<(usize, Command<N>)>,
                        )?);
                    }
                    lap!(timer, "Initialize the program mappings");

                    // If the program has a constructor, execute it and extend the finalize operations.
                    // This must happen after the mappings are initialized as the constructor may depend on them.
                    if deployment.program().contains_constructor() {
                        let operations = finalize_constructor(state, store, &stack, N::TransitionID::default())?;
                        finalize_operations.extend(operations);
                        lap!(timer, "Execute the constructor");
                    }

                    finish!(timer, "Finished finalizing the deployment");
                    // Return the stack and finalize operations.
                    Ok((stack, finalize_operations))
                })
            }
            DeploymentVersion::V3 => {
                // Ensure that the program is not `credits.aleo`.
                if deployment.program_id() == &ProgramID::credits() {
                    return Err(
                        anyhow!("The 'credits.aleo' program cannot be deployed with DeploymentVersion::V3").into()
                    );
                }

                // Get the existing stack.
                let existing_stack = self.process.get_stack(deployment.program_id())?;
                // Increment the amendment count while preserving the existing edition.
                let amendment_count = existing_stack
                    .program_amendment_count()
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("Overflow while incrementing the program amendment count"))?;

                // Compute a new stack with the same program and edition.
                // Note: `Stack::new` cannot be used here because it would increment the edition.
                // Amendments must preserve the existing edition. Validity is verified by `initialize_and_check`.
                let mut stack = Stack::new_raw(self.process, deployment.program(), *existing_stack.program_edition())?;
                stack.initialize_and_check(self.process)?;
                lap!(timer, "Compute the stack");

                // Set the amendment count for this edition.
                stack.set_program_amendment_count(amendment_count);
                // Set the program owner to the existing owner.
                stack.set_program_owner(*existing_stack.program_owner());

                // Insert all verifying keys (unified: functions + records).
                for (name, (verifying_key, _)) in deployment.verifying_keys() {
                    stack.insert_verifying_key(name, verifying_key.clone())?;
                }
                lap!(timer, "Insert the verifying keys");

                // Finalize the fee (amendments don't initialize mappings or run constructors).
                atomic_batch_scope!(store, IndexedFinalizeError::<N, Command<N>>, {
                    let mut finalize_operations = Vec::new();

                    // Retrieve the fee stack.
                    let fee_stack = self.process.get_stack(fee.program_id())?;
                    // Finalize the fee transition.
                    finalize_operations.extend(finalize_fee_transition(state, store, &fee_stack, fee)?);
                    lap!(timer, "Finalize transition for '{}/{}'", fee.program_id(), fee.function_name());

                    finish!(timer, "Finished finalizing the V3 deployment");
                    Ok((stack, finalize_operations))
                })
            }
        }
    }

    /// Finalizes the execution and fee.
    /// This method assumes the given execution **is valid**.
    /// This method should **only** be called by `VM::finalize()`.
    #[inline]
    pub fn finalize_execution<P: FinalizeStorage<N>>(
        &self,
        state: FinalizeGlobalState,
        store: &FinalizeStore<N, P>,
        execution: &Execution<N>,
        fee: Option<&Fee<N>>,
    ) -> Result<Vec<FinalizeOperation<N>>, IndexedFinalizeError<N, Command<N>>> {
        let timer = timer!("Program::finalize_execution");

        // Ensure the execution contains transitions.
        if execution.is_empty() {
            indexed_finalize_bail!(None, None, "There are no transitions in the execution");
        }

        // Ensure the number of transitions matches the program function.
        // Retrieve the root transition (without popping it).
        let transition = execution.peek().into_indexed(None, None, None::<(usize, Command<N>)>)?;
        // Extract the program ID and function name for error reporting.
        let transition_program_id = *transition.program_id();
        let transition_function_name = *transition.function_name();
        // Retrieve the stack.
        let stack = self.process.get_stack(transition.program_id()).into_indexed(
            Some((transition_program_id, self.get_latest_edition_for_program(&transition_program_id))),
            Some(transition_function_name),
            None::<(usize, Command<N>)>,
        )?;
        // Calculate the minimum number of calls for the root transition.
        let minimum_number_of_calls = stack.get_minimum_number_of_calls(transition.function_name()).into_indexed(
            Some((transition_program_id, *stack.program_edition())),
            Some(transition_function_name),
            None::<(usize, Command<N>)>,
        )?;
        // If the root transition contains a dynamic call,
        // - ensure that the number of calls is less than or equal to the number of transitions.
        // - otherwise, ensure that the number of calls matches the number of transitions.
        if stack.contains_dynamic_call(transition.function_name())? {
            if minimum_number_of_calls > execution.len() {
                indexed_finalize_bail!(
                    Some((transition_program_id, *stack.program_edition())),
                    Some(transition_function_name),
                    "The number of transitions in the execution is incorrect. \
                    Expected at least {minimum_number_of_calls}, but found {}",
                    execution.len()
                );
            }
        } else if minimum_number_of_calls != execution.len() {
            indexed_finalize_bail!(
                Some((transition_program_id, *stack.program_edition())),
                Some(transition_function_name),
                "The number of transitions in the execution is incorrect. \
                Expected {minimum_number_of_calls}, but found {}",
                execution.len()
            );
        }
        lap!(timer, "Verify the number of transitions");

        // Collect all of the futures in the execution's transitions and compute their corresponding dynamic future keys.
        // The key is (program_name, program_network, function_name, checksum). Futures with identical program,
        // function, and arguments produce the same key and the same checksum by design — they represent the same
        // logical future, so the map correctly de-duplicates them.
        let dynamic_future_to_future: HashMap<(Field<N>, Field<N>, Field<N>, Field<N>), &Future<N>> = execution
            .transitions()
            .filter_map(|transition| {
                transition.outputs().last().and_then(|output| output.future()).and_then(|future| {
                    let dynamic_future = DynamicFuture::from_future(future).ok()?;
                    let key = (
                        *dynamic_future.program_name(),
                        *dynamic_future.program_network(),
                        *dynamic_future.function_name(),
                        *dynamic_future.checksum(),
                    );
                    Some((key, future))
                })
            })
            .collect();

        // Construct the call graph.
        let consensus_version = N::CONSENSUS_VERSION(state.block_height()).into_indexed(
            Some((transition_program_id, *stack.program_edition())),
            Some(transition_function_name),
            None::<(usize, Command<N>)>,
        )?;
        let call_graph = match (ConsensusVersion::V1..=ConsensusVersion::V2).contains(&consensus_version) {
            true => {
                let mut execution_stacks = indexmap::IndexMap::new();
                for transition in execution.transitions() {
                    execution_stacks.insert(*transition.program_id(), self.process.get_stack(transition.program_id())?);
                }
                Process::construct_call_graph(execution.transitions(), &execution_stacks).into_indexed(
                    Some((transition_program_id, *stack.program_edition())),
                    Some(transition_function_name),
                    None::<(usize, Command<N>)>,
                )?
            }
            // If the height is greater than or equal to `ConsensusVersion::V3`, then provide an empty call graph, as it is no longer used during finalization.
            false => HashMap::new(),
        };

        atomic_batch_scope!(store, IndexedFinalizeError::<N, Command<N>>, {
            // Finalize the root transition.
            // Note that this will result in all the remaining transitions being finalized, since the number
            // of calls matches the number of transitions.
            let (mut finalize_operations, total_awaits) =
                finalize_transition(state, store, &stack, transition, call_graph, dynamic_future_to_future)?;

            if consensus_version >= ConsensusVersion::V15 {
                // Check that the total number of `Await` commands evaluated during
                // finalization matches the number of `Future`s defined in the
                // execution's transitions' outputs.
                let total_futures = execution
                    .transitions()
                    .filter(|t| t.outputs().last().and_then(|output| output.future()).is_some())
                    .count();
                let expected_total_awaits = total_futures.saturating_sub(1);
                if total_awaits != expected_total_awaits {
                    indexed_finalize_bail!(
                        Some((transition_program_id, *stack.program_edition())),
                        Some(transition_function_name),
                        "The number of 'await' calls during finalization is incorrect. \
                        Expected {expected_total_awaits}, but found {total_awaits}"
                    );
                }
            }

            /* Finalize the fee. */
            if let Some(fee) = fee {
                // Retrieve the fee stack.
                let fee_stack = self.process.get_stack(fee.program_id()).into_indexed(
                    Some((*fee.program_id(), self.get_latest_edition_for_program(fee.program_id()))),
                    Some(*fee.function_name()),
                    None::<(usize, Command<N>)>,
                )?;
                // Finalize the fee transition.
                finalize_operations.extend(finalize_fee_transition(state, store, &fee_stack, fee)?);
                lap!(timer, "Finalize transition for '{}/{}'", fee.program_id(), fee.function_name());
            }

            finish!(timer);
            // Return the finalize operations.
            Ok(finalize_operations)
        })
    }

    /// Finalizes the fee.
    /// This method assumes the given fee **is valid**.
    /// This method should **only** be called by `VM::finalize()`.
    #[inline]
    pub fn finalize_fee<P: FinalizeStorage<N>>(
        &self,
        state: FinalizeGlobalState,
        store: &FinalizeStore<N, P>,
        fee: &Fee<N>,
    ) -> Result<Vec<FinalizeOperation<N>>, IndexedFinalizeError<N, Command<N>>> {
        let timer = timer!("Program::finalize_fee");

        atomic_batch_scope!(store, IndexedFinalizeError::<N, Command<N>>, {
            // Retrieve the stack.
            let stack = self.process.get_stack(fee.program_id()).into_indexed(
                Some((*fee.program_id(), self.get_latest_edition_for_program(fee.program_id()))),
                Some(*fee.function_name()),
                None::<(usize, Command<N>)>,
            )?;
            // Finalize the fee transition.
            let result = finalize_fee_transition(state, store, &stack, fee);
            finish!(timer, "Finalize transition for '{}/{}'", fee.program_id(), fee.function_name());
            // Return the result.
            result
        })
    }
}

/// Finalizes the given fee transition.
fn finalize_fee_transition<N: Network, P: FinalizeStorage<N>>(
    state: FinalizeGlobalState,
    store: &FinalizeStore<N, P>,
    stack: &Arc<Stack<N>>,
    fee: &Fee<N>,
) -> Result<Vec<FinalizeOperation<N>>, IndexedFinalizeError<N, Command<N>>> {
    // Construct the call graph.
    let consensus_version = N::CONSENSUS_VERSION(state.block_height()).into_indexed(
        Some((*fee.program_id(), *stack.program_edition())),
        Some(*fee.function_name()),
        None::<(usize, Command<N>)>,
    )?;
    let call_graph = match (ConsensusVersion::V1..=ConsensusVersion::V2).contains(&consensus_version) {
        true => HashMap::from([(*fee.transition_id(), Vec::new())]),
        // If the height is greater than or equal to `ConsensusVersion::V3`, then provide an empty call graph, as it is no longer used during finalization.
        false => HashMap::new(),
    };

    // Finalize the transition.
    let (finalize_operations, total_awaits) =
        finalize_transition(state, store, stack, fee, call_graph, Default::default())?;
    // Create IndexedFinalizeError if the fee path has awaits.
    if consensus_version >= ConsensusVersion::V15 && total_awaits != 0 {
        indexed_finalize_bail!(
            Some((*fee.program_id(), *stack.program_edition())),
            Some(*fee.function_name()),
            "Fees must not have any awaits"
        );
    }
    Ok(finalize_operations)
}

/// Finalizes the constructor.
fn finalize_constructor<N: Network, P: FinalizeStorage<N>>(
    state: FinalizeGlobalState,
    store: &FinalizeStore<N, P>,
    stack: &Stack<N>,
    transition_id: N::TransitionID,
) -> Result<Vec<FinalizeOperation<N>>, IndexedFinalizeError<N, Command<N>>> {
    // Retrieve the program ID.
    let program_id = stack.program_id();
    let edition = stack.program_edition();
    let resource = Identifier::from_str("constructor")?;
    dev_println!("Finalizing constructor for {}...", stack.program_id());

    // Initialize a list for finalize operations.
    let mut finalize_operations = Vec::new();

    // Initialize a nonce for the constructor registers.
    // Currently, this nonce is set to zero for every constructor.
    let nonce = 0;

    // Get the constructor logic. If the program does not have a constructor, return early.
    let Some(constructor) = stack.program().constructor() else {
        return Ok(finalize_operations);
    };

    // Get the constructor types.
    let constructor_types = match stack.get_constructor_types() {
        Ok(types) => types.clone(),
        Err(error) => {
            indexed_finalize_bail!(
                Some((*program_id, *edition)),
                Some(resource),
                "Failed to get constructor types - {error}"
            )
        }
    };

    // Initialize the finalize registers.
    let mut registers =
        FinalizeRegisters::new(state, Some(transition_id), *program_id.name(), constructor_types, Some(nonce));

    // Determine the scope name.
    let scope_name = Identifier::<N>::from_str("constructor")?;

    // Initialize a counter for the commands.
    let mut counter = 0;

    // Evaluate the commands.
    while counter < constructor.commands().len() {
        // Retrieve the command.
        let command = &constructor.commands()[counter];
        // Finalize the command.
        match &command {
            Command::Await(_) => {
                indexed_finalize_bail!(
                    Some((*program_id, *edition)),
                    Some(resource),
                    counter,
                    command.clone(),
                    "Cannot `await` a Future in a constructor"
                )
            }
            _ => finalize_command_except_await(
                Some((*program_id, *edition)),
                Some(resource),
                store,
                stack,
                &mut registers,
                constructor.positions(),
                command,
                &mut counter,
                &mut finalize_operations,
                &scope_name,
            )?,
        };
    }

    // Return the finalize operations.
    Ok(finalize_operations)
}

/// Finalizes the given transition.
fn finalize_transition<N: Network, P: FinalizeStorage<N>>(
    state: FinalizeGlobalState,
    store: &FinalizeStore<N, P>,
    stack: &Arc<Stack<N>>,
    transition: &Transition<N>,
    call_graph: HashMap<N::TransitionID, Vec<N::TransitionID>>,
    dynamic_future_to_future: HashMap<(Field<N>, Field<N>, Field<N>, Field<N>), &Future<N>>,
) -> Result<(Vec<FinalizeOperation<N>>, TotalAwaits), IndexedFinalizeError<N, Command<N>>> {
    // Retrieve the program ID.
    let program_id = transition.program_id();
    // Retrieve the function name.
    let function_name = transition.function_name();

    dev_println!("Finalizing transition for {program_id}/{function_name}...");
    debug_assert_eq!(stack.program_id(), transition.program_id());

    // If the last output of the transition is a future, retrieve and finalize it. Otherwise, there are no operations to finalize.
    let future = match transition.outputs().last().and_then(|output| output.future()) {
        Some(future) => future,
        _ => return Ok((Vec::new(), 0)),
    };

    // Check that the program ID and function name of the transition match those in the future.
    if future.program_id() != program_id || future.function_name() != function_name {
        indexed_finalize_bail!(
            Some((*program_id, *stack.program_edition())),
            Some(*function_name),
            "The program ID and function name of the future do not match the transition"
        );
    }

    // Initialize a list for finalize operations.
    let mut finalize_operations = Vec::new();

    // Initialize a stack of active finalize states.
    let mut states = Vec::new();

    // Initialize a nonce for the finalize registers.
    // Note that this nonce must be unique for each sub-transition being finalized.
    let mut nonce = 0;
    // Top-level outputs are always static futures.
    let is_dynamic = false;

    // Initialize the top-level finalize state.
    states.push(initialize_finalize_state(state, future, stack, *transition.id(), nonce, is_dynamic).into_indexed(
        Some((*program_id, *stack.program_edition())),
        Some(*function_name),
        None::<(usize, Command<N>)>,
    )?);

    // Track the total number of `Await` commands evaluated across all `FinalizeState`s.
    let mut total_awaits: TotalAwaits = 0;

    // While there are active finalize states, finalize them.
    'outer: while let Some(FinalizeState { mut counter, mut registers, stack, mut call_counter, mut awaited }) =
        states.pop()
    {
        // Retrieve the current program ID, edition, and function name for error reporting.
        let finalize_program_id = *stack.program_id();
        let finalize_edition = *stack.program_edition();
        let finalize_resource = *registers.function_name();
        // Get the finalize logic.
        let Some(finalize) = stack
            .get_function_ref(registers.function_name())
            .into_indexed(
                Some((finalize_program_id, finalize_edition)),
                Some(finalize_resource),
                None::<(usize, Command<N>)>,
            )?
            .finalize_logic()
        else {
            indexed_finalize_bail!(
                Some((finalize_program_id, finalize_edition)),
                Some(finalize_resource),
                "The function '{finalize_program_id}/{finalize_resource}' does not have an associated finalize scope",
            )
        };
        // Determine the scope name.
        let scope_name = *registers.function_name();
        // Evaluate the commands.
        while counter < finalize.commands().len() {
            // Retrieve the command.
            let command = &finalize.commands()[counter];
            // Finalize the command.
            match &command {
                Command::Await(await_) => {
                    // Check that the `await` register is a locator.
                    if let Register::Access(_, _) = await_.register() {
                        indexed_finalize_bail!(
                            Some((finalize_program_id, finalize_edition)),
                            Some(finalize_resource),
                            "The 'await' register must be a locator"
                        )
                    };
                    // Check that the future has not previously been awaited.
                    if awaited.contains(await_.register()) {
                        indexed_finalize_bail!(
                            Some((finalize_program_id, finalize_edition)),
                            Some(finalize_resource),
                            counter,
                            command.clone(),
                            "The future register '{}' has already been awaited",
                            await_.register()
                        );
                    }
                    // Get the transition ID used to initialize the finalize registers.
                    // If the block height is greater than or equal to `ConsensusVersion::V3`, then use the top-level transition ID.
                    // Otherwise, view the call graph for the child transition ID corresponding to the future that is being awaited.
                    let consensus_version = N::CONSENSUS_VERSION(state.block_height()).into_indexed(
                        Some((finalize_program_id, finalize_edition)),
                        Some(finalize_resource),
                        Some((counter, command.clone())),
                    )?;
                    let transition_id = if (ConsensusVersion::V1..=ConsensusVersion::V2).contains(&consensus_version) {
                        // Get the current transition ID. The finalize path always initializes
                        // registers with `Some(transition_id)`; only the view path uses `None`,
                        // and `await` is forbidden on the view path, so this is unreachable
                        // there. Treat `None` as a logic error.
                        let transition_id = registers
                            .transition_id()
                            .ok_or_else(|| anyhow!("Cannot resolve a child transition ID without a transition ID"))?;
                        // Get the child transition ID.
                        match call_graph.get(transition_id) {
                            Some(transitions) => match transitions.get(call_counter) {
                                Some(transition_id) => *transition_id,
                                None => indexed_finalize_bail!(
                                    Some((finalize_program_id, finalize_edition)),
                                    Some(finalize_resource),
                                    counter,
                                    command.clone(),
                                    "Child transition ID not found."
                                ),
                            },
                            None => indexed_finalize_bail!(
                                Some((finalize_program_id, finalize_edition)),
                                Some(finalize_resource),
                                counter,
                                command.clone(),
                                "Transition ID '{transition_id}' not found in call graph"
                            ),
                        }
                    } else {
                        *transition.id()
                    };

                    // Increment the nonce.
                    nonce += 1;

                    // Set up the finalize state for the await.
                    let callee_state = match try_vm_runtime(|| {
                        setup_await(state, await_, &stack, &registers, transition_id, nonce, &dynamic_future_to_future)
                    }) {
                        Ok(Ok(callee_state)) => callee_state,
                        // If the evaluation fails, bail and return the error.
                        Ok(Err(error)) => indexed_finalize_bail!(
                            Some((finalize_program_id, finalize_edition)),
                            Some(finalize_resource),
                            counter,
                            command.clone(),
                            "'finalize' failed to evaluate command: {error}"
                        ),
                        // If the evaluation fails, bail and return the error.
                        Err(_) => indexed_finalize_bail!(
                            Some((finalize_program_id, finalize_edition)),
                            Some(finalize_resource),
                            counter,
                            command.clone(),
                            "'finalize' failed to evaluate command"
                        ),
                    };

                    // Increment the call counter.
                    call_counter += 1;
                    // Increment the total number of `Await` commands evaluated.
                    total_awaits += 1;
                    // Increment the counter.
                    counter += 1;
                    // Add the awaited register to the tracked set.
                    awaited.insert(await_.register().clone());

                    // Aggregate the caller state.
                    let caller_state = FinalizeState { counter, registers, stack, call_counter, awaited };

                    // Push the caller state onto the stack.
                    states.push(caller_state);
                    // Push the callee state onto the stack.
                    states.push(callee_state);

                    continue 'outer;
                }
                _ => finalize_command_except_await(
                    Some((finalize_program_id, finalize_edition)),
                    Some(finalize_resource),
                    store,
                    stack.deref(),
                    &mut registers,
                    finalize.positions(),
                    command,
                    &mut counter,
                    &mut finalize_operations,
                    &scope_name,
                )?,
            };
        }
        // Check that all future registers have been awaited.
        let mut unawaited = Vec::new();
        for input in finalize.inputs() {
            if matches!(input.finalize_type(), FinalizeType::Future(_) | FinalizeType::DynamicFuture)
                && !awaited.contains(input.register())
            {
                unawaited.push(input.register().clone());
            }
        }
        if !unawaited.is_empty() {
            indexed_finalize_bail!(
                Some((finalize_program_id, finalize_edition)),
                Some(finalize_resource),
                "The following future registers have not been awaited: {}",
                unawaited.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")
            );
        }
    }

    // Return the finalize operations and the total number of `Await` commands evaluated.
    Ok((finalize_operations, total_awaits))
}

// A helper struct to track the execution of a finalize scope.
struct FinalizeState<N: Network> {
    // A counter for the index of the commands.
    counter: usize,
    // The registers.
    registers: FinalizeRegisters<N>,
    // The stack.
    stack: Arc<Stack<N>>,
    // Call counter.
    call_counter: usize,
    // Awaited futures.
    awaited: HashSet<Register<N>>,
}

// A helper function to initialize the finalize state for transitions (not constructors).
fn initialize_finalize_state<N: Network>(
    state: FinalizeGlobalState,
    future: &Future<N>,
    stack: &Arc<Stack<N>>,
    transition_id: N::TransitionID,
    nonce: u64,
    is_dynamic: bool,
) -> Result<FinalizeState<N>> {
    // Get the stack.
    let stack = match (stack.program_id() == future.program_id(), is_dynamic) {
        (true, _) => stack.clone(),
        (false, true) => stack.get_stack_global(future.program_id())?,
        (false, false) => stack.get_external_stack(future.program_id())?,
    };
    // Get the finalize logic and check that it exists.
    let Some(finalize) = stack.get_function_ref(future.function_name())?.finalize_logic() else {
        bail!(
            "The function '{}/{}' does not have an associated finalize scope",
            future.program_id(),
            future.function_name()
        )
    };
    // Initialize the registers.
    let mut registers = FinalizeRegisters::new(
        state,
        Some(transition_id),
        *future.function_name(),
        stack.get_finalize_types(future.function_name())?.clone(),
        Some(nonce),
    );

    // Store the inputs. The argument count is guaranteed to match the finalize's declared inputs
    // because the Future was validated against the finalize type signature at execution time.
    finalize.inputs().iter().map(|i| i.register()).zip_eq(future.arguments().iter()).try_for_each(
        |(register, input)| {
            // Assign the input value to the register.
            registers.store(stack.deref(), register, Value::from(input))
        },
    )?;

    Ok(FinalizeState { counter: 0, registers, stack, call_counter: 0, awaited: Default::default() })
}

// A helper function to finalize all commands except `await`, updating the finalize operations and the counter.
//
// Generic over the store so the view evaluator (which passes either the canonical
// `FinalizeStore` or a read-only historic adapter) can reuse this dispatch. The stack must be
// the concrete `Stack<N>` so we can resolve `Call`-to-view targets and read their cached
// `FinalizeTypes` (the in-block call path needs concrete access).
#[inline]
pub(crate) fn finalize_command_except_await<N: Network>(
    program_id: Option<(ProgramID<N>, u16)>,
    resource: Option<Identifier<N>>,
    store: &dyn FinalizeStoreTrait<N>,
    stack: &Stack<N>,
    registers: &mut FinalizeRegisters<N>,
    positions: &HashMap<Identifier<N>, usize>,
    command: &Command<N>,
    counter: &mut usize,
    finalize_operations: &mut Vec<FinalizeOperation<N>>,
    scope_name: &Identifier<N>,
) -> Result<(), IndexedFinalizeError<N, Command<N>>> {
    // Finalize the command.
    match &command {
        Command::BranchEq(branch_eq) => {
            let result = try_vm_runtime(|| branch_to(*counter, branch_eq, positions, stack, registers));
            match result {
                Ok(Ok(new_counter)) => {
                    *counter = new_counter;
                }
                // If the evaluation fails, bail and return the error.
                Ok(Err(error)) => indexed_finalize_bail!(
                    program_id,
                    resource,
                    *counter,
                    command.clone(),
                    "'{scope_name}' failed to evaluate command ({command}): {error}"
                ),
                // If the evaluation fails, bail and return the error.
                Err(_) => indexed_finalize_bail!(
                    program_id,
                    resource,
                    *counter,
                    command.clone(),
                    "'{scope_name}' failed to evaluate command"
                ),
            }
        }
        Command::BranchNeq(branch_neq) => {
            let result = try_vm_runtime(|| branch_to(*counter, branch_neq, positions, stack, registers));
            match result {
                Ok(Ok(new_counter)) => {
                    *counter = new_counter;
                }
                // If the evaluation fails, bail and return the error.
                Ok(Err(error)) => indexed_finalize_bail!(
                    program_id,
                    resource,
                    *counter,
                    command.clone(),
                    "'{scope_name}' failed to evaluate command: {error}"
                ),
                // If the evaluation fails, bail and return the error.
                Err(_) => indexed_finalize_bail!(
                    program_id,
                    resource,
                    *counter,
                    command.clone(),
                    "'{scope_name}' failed to evaluate command"
                ),
            }
        }
        Command::Await(_) => {
            indexed_finalize_bail!(
                program_id,
                resource,
                *counter,
                command.clone(),
                "Cannot use `finalize_command_except_await` with an 'await' command"
            )
        }
        _ => {
            let result = try_vm_runtime(|| command.finalize(stack, store, registers));
            match result {
                // If the evaluation succeeds with an operation, add it to the list.
                Ok(Ok(Some(finalize_operation))) => finalize_operations.push(finalize_operation),
                // If the evaluation succeeds with no operation, continue.
                Ok(Ok(None)) => {}
                // If the evaluation fails, bail and return the error.
                Ok(Err(error)) => {
                    return Err(IndexedFinalizeError::new(
                        program_id,
                        resource,
                        Some((*counter, command.clone())),
                        error,
                    ));
                }
                // If the evaluation fails, bail and return the error.
                Err(_) => indexed_finalize_bail!(
                    program_id,
                    resource,
                    *counter,
                    command.clone(),
                    "'{scope_name}' failed to evaluate command"
                ),
            }
            *counter += 1;
        }
    };
    Ok(())
}

// A helper function that sets up the await operation.
#[inline]
fn setup_await<N: Network>(
    state: FinalizeGlobalState,
    await_: &Await<N>,
    stack: &Arc<Stack<N>>,
    registers: &FinalizeRegisters<N>,
    transition_id: N::TransitionID,
    nonce: u64,
    dynamic_future_to_future: &HashMap<(Field<N>, Field<N>, Field<N>, Field<N>), &Future<N>>,
) -> Result<FinalizeState<N>> {
    // Retrieve the input as a future.
    let (future, is_dynamic) = match registers.load(stack.deref(), &Operand::Register(await_.register().clone()))? {
        Value::Future(future) => (future, false),
        Value::DynamicFuture(dynamic_future) => {
            // Construct the key from the dynamic future's program name, network, function name, and checksum.
            let key = (
                *dynamic_future.program_name(),
                *dynamic_future.program_network(),
                *dynamic_future.function_name(),
                *dynamic_future.checksum(),
            );
            // Look up the corresponding future from the dynamic future key.
            match dynamic_future_to_future.get(&key) {
                Some(future) => ((*future).clone(), true),
                None => bail!("Dynamic future '{key:?}' not found in dynamic-future-to-future map"),
            }
        }
        _ => bail!("The input to 'await' is not a future or dynamic future"),
    };
    // Initialize the state.
    initialize_finalize_state(state, &future, stack, transition_id, nonce, is_dynamic)
}

// A helper function that returns the index to branch to.
fn branch_to<N: Network, const VARIANT: u8>(
    counter: usize,
    branch: &Branch<N, VARIANT>,
    positions: &HashMap<Identifier<N>, usize>,
    stack: &impl StackTrait<N>,
    registers: &impl RegistersTrait<N>,
) -> Result<usize> {
    // Retrieve the inputs.
    let first = registers.load(stack, branch.first())?;
    let second = registers.load(stack, branch.second())?;

    // A helper to get the index corresponding to a position.
    let get_position_index = |position: &Identifier<N>| match positions.get(position) {
        Some(index) if *index > counter => Ok(*index),
        Some(_) => bail!("Cannot branch to an earlier position '{position}' in the program"),
        None => bail!("The position '{position}' does not exist."),
    };

    // Compare the operands and determine the index to branch to.
    match VARIANT {
        // The `branch.eq` variant.
        0 if first == second => get_position_index(branch.position()),
        0 if first != second => Ok(counter + 1),
        // The `branch.neq` variant.
        1 if first == second => Ok(counter + 1),
        1 if first != second => get_position_index(branch.position()),
        _ => bail!("Invalid 'branch' variant: {VARIANT}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_execute::{sample_fee, sample_finalize_state};
    use console::prelude::TestRng;
    use snarkvm_ledger_store::{
        BlockStore,
        helpers::memory::{BlockMemory, FinalizeMemory},
    };

    use aleo_std::StorageMode;

    type CurrentNetwork = console::network::MainnetV0;
    type CurrentAleo = circuit::network::AleoV0;

    #[test]
    fn test_finalize_deployment() {
        let rng = &mut TestRng::default();

        // Initialize a new program.
        let program = Program::<CurrentNetwork>::from_str(
            r"
program testing.aleo;

struct message:
    amount as u128;

mapping account:
    key as address.public;
    value as u64.public;

record token:
    owner as address.private;
    amount as u64.private;

function initialize:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function compute:
    input r0 as message.private;
    input r1 as message.public;
    input r2 as message.private;
    input r3 as token.record;
    add r0.amount r1.amount into r4;
    cast r3.owner r3.amount into r5 as token.record;
    output r4 as u128.public;
    output r5 as token.record;",
        )
        .unwrap();

        // Initialize a new process.
        let process = Process::load().unwrap();
        // Deploy the program.
        let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Initialize a new finalize store.
        let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        // Ensure the program does not exist.
        assert!(!process.contains_program(program.id()));

        // Compute the fee.
        let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
        // Finalize the deployment.
        let (stack, _) =
            process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
        // Add the stack *manually* to the process.
        process.lock().add_stack(stack);

        // Ensure the program exists.
        assert!(process.contains_program(program.id()));
    }
}
