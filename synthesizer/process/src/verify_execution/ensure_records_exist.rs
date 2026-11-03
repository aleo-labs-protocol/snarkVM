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

use console::program::RegisterType;
use snarkvm_synthesizer_program::CallOperator;

// The checks in this file ensure that every Transition t in the given execution satisfies the following:
//
// Guarantee (G): Every non-static record (DynamicRecord or ExternalRecord) input to t or received by t from a
// function call is "connected" to a static Record which exists on the ledger at the end of the full execution
// (whether consumed or not).
//
// Here "connected" refers to the transitive relation between two or more record-like (Record, DynamicRecord or
// ExternalRecord) registers that arises when one of the following happens:
// - two of them coincide at the input or output boundary of a function call
// - two of them are related by a cast-to-dynamic instruction
//
// The following is required of every function in the execution:
//
// Contract (C): Every record-like register output or passed to a function call exists on the ledger at the end of the
// full execution.
//
// When ensuring (C), the function can assume its caller and callees (if any) also satisfy (C). Note that (C) does
// not refer to connected registers generally, but to the specific registers involved in the statement. In particular,
// (C) must be satisfied regardless of the specific operations happening inside the function's callees. For instance,
//  - A function f that mints a static Record at register r0 and passes it to an external function must output r0. It
//    is not sufficient for f to subsequently call an external "remapper function" which effectively returns the same
//    Record at r1, and then output r1.
//  - If a function f receives a DynamicRecord from a callee at r2, it is itself free to output r2, since the callee's
//    contract already guarantees that r2 corresponds to a static Record on the ledger.
//
// (G) and (C) can be ensured as follows:
//
//   1. Keeping track of each DynamicRecord and ExternalRecord register input to the root call as it travels across
//   function and closure input or output boundaries and cast-to-dynamic (in the external case) instructions, and
//   ensuring that one register connected to it is input to a function receiving it as a static Record (thus
//   consuming it). We refer to this as the *global check*.
//
//   This property depends on the root call of a Transaction and the flow of the execution and is therefore in the
//   hands of the party authorising the Transaction (and not in those of the developer of an Aleo program).
//
//   N.B.: It can be shown that materialization of a non-static record input to the root transition cannot occur due to
//   a connected static Record being output (by a function in the program containing the record definition) - at least,
//   not without first materializing it by consuming it as a static-Record input.
//
//   2. Ensuring that, in each transition t in the execution, if a static Record R_s is
//   minted locally and either
//    - passed to a callee.
//    - cast to a DynamicRecord R_d which is then passed to a callee or output.
//   then R_s is itself output. We refer to this as the *local check*. Note that, in case b), if the callee
//   would receive the value as a static Record, this would constitute an attempt to consume a Record which has not
//   been published yet. Since such an execution would be rejected during verification time (whether the
//   inclusion-proof check happens before or after the record-existence one), we allow the record-existence check to
//   reject such an execution even though it does not violate (C) (this slightly simplifies the implementation). This
//   Record -> Record boundary cannot occur in case a), as it would either be a local static call or a dynamic call
//   receiving a static-Record input and both are disallowed.
//
//   This property depends on the definition of the functions involved and is therefore in the hands of the developers
//   Aleo programs.
//
// The function ensure_records_exist explores the execution tree recursively starting at the root Transition and
// processing instructions (input/output boundaries, function calls, Record mintings and cast-to-dynamic instructions)
// in order of execution. It also ensures that no closure outputs ExternalRecord or DynamicRecord types, which is
// enforced at deployment time for V15+ programs and checked at runtime for pre-V15 programs. Closure calls do not
// need to be explored since they cannot output Records, DynamicRecords or ExternalRecords and therefore cannot
// influence any of the checks above (in particular, they cannot lead to connections between Record-like registers
// in the caller).
//
// When a function call is encountered, the function process_transition is called. This initialises a
// FunctionLocalCheck struct which keeps track of which locally minted static Records are passed to callees; or cast to
// dynamic and passed to callees or output.
//
// If the function corresponds to the root transition, a GlobalCheck is also initialised with one singleton family per
// non-static Record input. This object is passed across all recursive calls.
//
// process_transition processes the following situations:
//
//     - Case 1: RecordWithDynamicID and Record registers input to the function, whose families are marked as
//       existing if they are being tracked (global check)
//     - Case 2: connections between the caller registers where call inputs are passed and the callee's input
//       registers (global check).
//     - Case 3: cast instruction minting a static Record (local check)
//     - Case 4: casts of ExternalRecords to DynamicRecords (global check; note an external record cannot be
//       minted locally)
//     - Case 5: casts of locally minted static Records to DynamicRecords (local check)
//     - Function calls, at which point process_transition is called recursively. Two situations are kept track of
//       at the input boundary:
//         - Case 6a: Locally minted static Records passed as inputs, which must be output by the caller (local
//           check)
//         - Case 6b: DynamicRecords cast from locally minted static Records and passed as inputs, in which case the
//           static ones must be output by the caller (local check)
//     - Case 7: DynamicRecords cast from locally minted static Records and output (local check)
//     - Case 8: Connections between the caller registers where call outputs are received and call and the callee's
//       output registers (global check).

// Structure that keeps track of the global record-existence check of an execution, i.e. that each DynamicRecord and
// ExternalRecord input to the root transition corresponds to a static Record that exists on the ledger at the end of
// the execution.
struct GlobalCheck<N: Network> {
    // Each element of the vector corresponds to a family of registers that are connected to a DynamicRecord or
    // ExternalRecord input to the root transition. Once a family is known to exist on the ledger, it is removed from
    // the vector.
    families: Vec<IndexSet<(N::TransitionID, u64)>>,
}

impl<N: Network> GlobalCheck<N> {
    // Initialises the global check with one singleton family per register provided.
    fn new(non_static_input_registers: Vec<(N::TransitionID, u64)>) -> Self {
        let families = non_static_input_registers.into_iter().map(|register| IndexSet::from_iter([register])).collect();
        Self { families }
    }

    // Adds a register to the family containing another register, if any, thus connecting their existence status.
    fn add_to_family(&mut self, old_register: (N::TransitionID, u64), new_register: (N::TransitionID, u64)) {
        // Sanity check: at most one family contains each of the given registers.
        for record in [old_register, new_register] {
            debug_assert!(
                self.families.iter().filter(|family| family.contains(&record)).count() <= 1,
                "Multiple families contain register {} for transition ID {}",
                record.1,
                record.0
            );
        }

        let family = self.families.iter_mut().find(|family| family.contains(&old_register));

        if let Some(found_family) = family {
            found_family.insert(new_register);
        }
    }

    // Marks the family containing a given record-like register as existing on the ledger by removing it from the
    // vector of families.
    fn mark_existing(&mut self, register: (N::TransitionID, u64)) {
        // Sanity check: at most one family contains the given register.
        debug_assert!(
            self.families.iter().filter(|family| family.contains(&register)).count() <= 1,
            "Multiple families contain register {} for transition ID {}",
            register.1,
            register.0
        );

        let family = self.families.iter().position(|family| family.contains(&register));

        if let Some(family_index) = family {
            self.families.swap_remove(family_index);
        }
    }

    // Checks that all families have been found to correspond to a static Record on the ledger. Otherwise, returns the
    // original register of a family not known to correspond to one.
    fn validate(&self) -> Result<(), u64> {
        if self.families.is_empty() {
            Ok(())
        } else {
            // The unwrap is safe since all families have at least one element by construction.
            Err(self.families[0].iter().next().unwrap().1)
        }
    }
}

// Auxiliary structure for the local record-existence check of a function
struct LocalCheck<N: Network> {
    // The locator of the function being checked, used to provide more specific error messages.
    locator: Locator<N>,
    // The registers output by the function.
    output_registers: HashSet<u64>,
    // The set of locally minted static records, populated throughout the check.
    locally_minted_static: HashSet<u64>,
    // For each DynamicRecord at r_j cast from a locally minted static Record at r_i, this map contains the entry
    // r_j -> r_i. Populated throughout the check.
    locally_minted_dynamic: HashMap<u64, u64>,
}

impl<N: Network> LocalCheck<N> {
    // Initialises a function's local check given the registers it outputs.
    fn new(locator: Locator<N>, output_registers: HashSet<u64>) -> Self {
        Self {
            locator,
            output_registers,
            locally_minted_static: HashSet::new(),
            locally_minted_dynamic: HashMap::new(),
        }
    }

    // Tracks the minting of a static Record in the function.
    fn mint_static(&mut self, register: u64) {
        self.locally_minted_static.insert(register);
    }

    // Tracks the information about a static-to-dynamic cast if the operand corresponds to a locally minted static
    // Record.
    fn cast_to_dynamic(&mut self, operand_register: u64, destination_register: u64) {
        if self.locally_minted_static.contains(&operand_register) {
            self.locally_minted_dynamic.insert(destination_register, operand_register);
        }
    }

    // Validates an input register passed to a function call: if it contains a locally minted static Record or a
    // DynamicRecord cast from one, ensures the former is output, returning an error otherwise.
    fn validate_call_input(&mut self, register: u64) -> Result<()> {
        if self.locally_minted_static.contains(&register) && !self.output_registers.contains(&register) {
            // Case 6a)
            bail!(
                "In {}, locally minted Record at r{register} is passed to a function call but not output",
                self.locator
            );
        }
        if let Some(static_record) = self.locally_minted_dynamic.get(&register)
            && !self.output_registers.contains(static_record)
        {
            // Case 6b)
            bail!(
                "In {}, DynamicRecord at r{register} passed to a function call is cast from a locally minted Record at r{static_record} which is not output",
                self.locator
            );
        }
        Ok(())
    }

    // Validates an output register: if it contains a DynamicRecord cast from a locally minted static Record, ensures
    // the latter is output, returning an error otherwise.
    fn validate_output(&self, register: u64) -> Result<()> {
        if let Some(static_record) = self.locally_minted_dynamic.get(&register)
            && !self.output_registers.contains(static_record)
        {
            // Case 7)
            bail!(
                "In {}, output DynamicRecord at r{register} is cast from a locally minted Record at r{static_record} which is not output",
                self.locator
            );
        }
        Ok(())
    }
}

impl<N: Network> Process<N> {
    /// Checks that, for each non-closure function in the execution, each ExternalRecord and DynamicRecord received as
    /// an input or from a callee corresponds to a static Record that exists on the ledger at the end of the execution
    /// (whether spent or not). A function given this guarantee should itself ensure that all records it outputs or
    /// passes to non-closure callees exist on the ledger at the end of the execution.
    ///
    /// Input `transitions`: Iterator over the `Transition`s in the execution. The root transition must be last.
    ///
    /// Input `call_graph`: A copy of the call graph. It is assumed to contain all transitions in `transitions`. All
    /// children of a given Transition ID must appear in the same order as the corresponding calls happen in the
    /// function.
    pub fn ensure_records_exist<'a>(
        transitions: impl ExactSizeIterator<Item = &'a Transition<N>> + DoubleEndedIterator + Clone,
        call_graph: &HashMap<N::TransitionID, Vec<N::TransitionID>>,
        execution_stacks: &IndexMap<ProgramID<N>, Arc<Stack<N>>>,
    ) -> Result<()> {
        let root_transition = transitions.clone().last().ok_or_else(|| anyhow!("Empty transition list"))?;

        let tid_to_transition: HashMap<N::TransitionID, &Transition<N>> =
            transitions.map(|transition| (*transition.id(), transition)).collect();

        // Initialise the global check with one (singleton) family per DynamicRecord and ExternalRecord input to the
        // root transition.
        let root_transition_id = root_transition.id();

        let input_registers = {
            let stack = execution_stacks
                .get(root_transition.program_id())
                .ok_or_else(|| anyhow!("Missing stack for program '{}'", root_transition.program_id()))?;
            let root_function = stack.get_function_ref(root_transition.function_name())?;

            root_function.inputs().iter().map(|input| input.register().locator()).collect::<Vec<u64>>()
        };

        ensure!(
            root_transition.inputs().len() == input_registers.len(),
            "Mismatch in the number of inputs and registers in the root call: {}/{}: {} vs. {}",
            root_transition.program_id(),
            root_transition.function_name(),
            root_transition.inputs().len(),
            input_registers.len(),
        );

        let non_static_input_registers = root_transition
            .inputs()
            .iter()
            .zip_eq(input_registers.iter())
            .filter_map(|(input, register)| {
                // We do not need to match Input::ExternalRecordWithDynamicID here as that variant
                // can never occur at the root call.
                if matches!(input, Input::DynamicRecord(..) | Input::ExternalRecord(..)) {
                    Some((*root_transition_id, *register))
                } else {
                    None
                }
            })
            .collect::<Vec<(N::TransitionID, u64)>>();

        // Note: even if non_static_input_registers is empty, we need to process the transitions to enforce the
        // local-check restrictions.
        let mut global_check = GlobalCheck::new(non_static_input_registers);

        // Recursively explore the execution, keeping track of record connections across the relevant casts and calls.
        process_transition(
            execution_stacks,
            &mut global_check,
            root_transition.id(),
            None,
            &tid_to_transition,
            call_graph,
        )?;

        // Ensure the global check passes.
        global_check.validate().map_err(|register| anyhow!("Non-static record input at r{register} of the root function {}/{} is not known to correspond to a record on the ledger",
            root_transition.program_id(),
            root_transition.function_name(),
        ))
    }
}

// Auxiliary function for `ensure_records_exist` that connects registers in the transition to the relevant record
// families, tracking connections and marking families as existing if they are found to correspond to a record on the
// ledger (global check). Furthermore, it also performs the function's local record-existence check.
fn process_transition<N: Network>(
    // Cached stacks used to resolve function and closure definitions.
    execution_stacks: &IndexMap<ProgramID<N>, Arc<Stack<N>>>,
    // Global check keeping track of families of registers connected to DynamicRecords or ExternalRecords input to the
    // root transition.
    global_check: &mut GlobalCheck<N>,
    // TransitionID of the transition being processed.
    transition_id: &N::TransitionID,
    // `None` for the root transition. For non-root transitions, `Some` containing:
    //  - TransitionID of the caller.
    //  - indices of the caller registers where it passes inputs to this transition's call (with `None` for inputs
    //    that are not registers)
    //  - indices of the caller registers where it receives outputs from this transition's call
    caller_info: Option<(N::TransitionID, &[Option<u64>], &[u64])>,
    // Map from TransitionID to the corresponding Transition
    tid_to_transition: &HashMap<N::TransitionID, &Transition<N>>,
    // Call graph of the execution
    call_graph: &HashMap<N::TransitionID, Vec<N::TransitionID>>,
) -> Result<()> {
    let transition =
        tid_to_transition.get(transition_id).ok_or_else(|| anyhow!("Missing transition with ID {transition_id}"))?;
    let stack = execution_stacks
        .get(transition.program_id())
        .ok_or_else(|| anyhow!("Missing stack for program '{}'", transition.program_id()))?;
    let function = stack.get_function_ref(transition.function_name())?;
    let locator = Locator::new(*transition.program_id(), *transition.function_name());

    let inputs = transition.inputs();
    let input_registers = function.inputs().iter().map(|input| input.register().locator()).collect::<Vec<u64>>();

    ensure!(
        input_registers.len() == transition.inputs().len(),
        "Mismatch in the number of inputs and registers in the call to {locator}"
    );

    // Initialise the machinery which keeps track of the local check.
    let mut local_check = LocalCheck::new(
        locator,
        function
            .outputs()
            .iter()
            .filter_map(|output| {
                if let Operand::Register(register) = output.operand() { Some(register.locator()) } else { None }
            })
            .collect(),
    );

    // Number of function calls encountered in the current transition so far.
    let mut processed_function_calls = 0;

    // Processing the inputs if the transition is not the root.
    if let Some((caller_tid, caller_input_registers, _)) = &caller_info {
        ensure!(
            inputs.len() == input_registers.len() && inputs.len() == caller_input_registers.len(),
            "Mismatch in the number of callee/caller inputs and registers in call to {locator} (TransitionID {transition_id})",
        );

        for ((caller_input_register_opt, callee_input_register), callee_input) in
            caller_input_registers.iter().zip_eq(input_registers.iter()).zip_eq(inputs.iter())
        {
            if let Some(caller_input_register) = caller_input_register_opt {
                match callee_input {
                    Input::RecordWithDynamicID(..) | Input::Record(..) => {
                        // Case 1: consuming a Record translating from a DynamicRecord or passed as an ExternalRecord
                        // by the caller: the family is now known to exist on the ledger.
                        global_check.mark_existing((*caller_tid, *caller_input_register));
                    }
                    Input::ExternalRecord(..) | Input::ExternalRecordWithDynamicID(..) | Input::DynamicRecord(..) => {
                        // Case 2: connection at the input boundary
                        let old_register = (*caller_tid, *caller_input_register);
                        let new_register = (*transition_id, *callee_input_register);
                        // This call only adds the new register if the old register is being tracked, i.e. if it belongs to a family
                        global_check.add_to_family(old_register, new_register);
                    }
                    _ => {}
                }
            }
        }
    }

    for instruction in function.instructions() {
        match instruction {
            Instruction::Cast(cast) => {
                match cast.cast_type() {
                    CastType::Record(_) => {
                        // Case 3: minting a static Record locally.
                        local_check.mint_static(cast.destinations()[0].locator());
                    }
                    CastType::DynamicRecord => {
                        let operand_register = match cast.operands().first() {
                            Some(Operand::Register(register)) => register.locator(),
                            _ => bail!(
                                "Failed to retrieve operand register for cast to DynamicRecord instruction in {locator}"
                            ),
                        };

                        let destination_register = cast.destinations()[0].locator();

                        // Case 4: Global-check update. Since static Records never exist in any family and add_to_family
                        // only adds the new register if the old register exists in some family, this call only handles
                        // external-to-dynamic casts.
                        let old_register = (*transition_id, operand_register);
                        let new_register = (*transition_id, destination_register);
                        global_check.add_to_family(old_register, new_register);

                        // Case 5: Local-check update. This keeps track of the cast if the operand is a locally minted
                        // static Record.
                        local_check.cast_to_dynamic(operand_register, destination_register);
                    }
                    _ => {}
                }
            }
            Instruction::Call(call) if !call.is_function_call(stack.as_ref())? => {
                // Closure case

                // Runtime check: reject pre-V15 programs whose closures output records.
                // New programs are blocked at deployment time; this covers legacy programs.
                let has_forbidden_output = match call.operator() {
                    CallOperator::Resource(resource) => {
                        stack.program().get_closure(resource)?.outputs().iter().any(|output| {
                            matches!(
                                output.register_type(),
                                RegisterType::ExternalRecord(..) | RegisterType::DynamicRecord
                            )
                        })
                    }
                    CallOperator::Locator(locator) => execution_stacks
                        .get(locator.program_id())
                        .ok_or_else(|| anyhow!("Missing stack for program '{}'", locator.program_id()))?
                        .program()
                        .get_closure(locator.resource())?
                        .outputs()
                        .iter()
                        .any(|output| {
                            matches!(
                                output.register_type(),
                                RegisterType::ExternalRecord(..) | RegisterType::DynamicRecord
                            )
                        }),
                };
                ensure!(
                    !has_forbidden_output,
                    "Closure '{}' outputs ExternalRecord or DynamicRecord, which is disallowed at V15+",
                    call.operator()
                );
            }
            Instruction::Call(..) | Instruction::CallDynamic(..) => {
                // Function case (note: closures have been matched in the previous arm)

                let caller_input_operands = match instruction {
                    Instruction::Call(..) => instruction.operands(),
                    // The first three operands of a call.dynamic instruction are reserved for the target and always
                    // present.
                    Instruction::CallDynamic(..) => &instruction.operands()[3..],
                    _ => bail!("Unreachable"),
                };

                let caller_input_registers: Vec<Option<u64>> = caller_input_operands
                    .iter()
                    .map(
                        |operand| {
                            if let Operand::Register(register) = operand { Some(register.locator()) } else { None }
                        },
                    )
                    .collect();

                let caller_output_registers: Vec<u64> =
                    instruction.destinations().iter().map(|destination| destination.locator()).collect();

                let tid_callee = if let Some(tid) =
                    // The unwrap is safe (assuming a correct call graph) as we are processing a Transition which
                    // is part of the execution.
                    call_graph.get(transition_id).unwrap().get(processed_function_calls)
                {
                    processed_function_calls += 1;
                    tid
                } else {
                    bail!(
                        "Entry with Transition ID {transition_id} ({locator}) in the call graph has fewer elements than the number of calls in the corresponding function"
                    );
                };

                for input_register in caller_input_operands.iter() {
                    if let Operand::Register(register) = input_register {
                        // Case 6: Any locally minted static Records passed to a function call or cast to dynamic
                        // and passed to a function call must be output.
                        local_check.validate_call_input(register.locator())?;
                    }
                }

                // Recursively updating the global check and performing the local check in the callee.
                process_transition(
                    execution_stacks,
                    global_check,
                    tid_callee,
                    Some((*transition_id, &caller_input_registers, &caller_output_registers)),
                    tid_to_transition,
                    call_graph,
                )?;
            }
            _ => {}
        }
    }

    // Output processing

    // Case 7: DynamicRecords cast from locally minted static Records require the static Record to be output.
    for output in function.outputs().iter() {
        if let Operand::Register(output_register) = output.operand()
            && matches!(output.value_type(), ValueType::DynamicRecord)
        {
            local_check.validate_output(output_register.locator())?;
        }
    }

    // For non-root calls, update the global check's record families with the connections at the output boundary.
    if let Some((caller_tid, _, caller_output_registers)) = &caller_info {
        let outputs = function.outputs();

        ensure!(
            outputs.len() == caller_output_registers.len(),
            "Mismatch in the number of callee/caller outputs in call to {locator} (transition ID {transition_id})",
        );

        for (caller_output_register, callee_output) in caller_output_registers.iter().zip_eq(outputs.iter()) {
            if let Operand::Register(callee_output_register) = callee_output.operand()
                && matches!(callee_output.value_type(), ValueType::DynamicRecord | ValueType::ExternalRecord(..))
            {
                // Case 8: add the caller's output register to the family containing the callee's. Note that
                // output registers with type ValueType::Record are never tracked as part of the global check.
                let old_register = (*transition_id, callee_output_register.locator());
                let new_register = (*caller_tid, *caller_output_register);
                global_check.add_to_family(old_register, new_register);
            }
        }
    }

    // Sanity check: exploration should have processed all calls in the graph.
    ensure!(
        // The unwrap is safe (assuming a correct call graph) as we are processing a Transition which is part of the
        // execution.
        processed_function_calls == call_graph.get(transition_id).unwrap().len(),
        "In the record-existence check, entry for Transition ID {transition_id} ({locator}) in the call graph has unprocessed children",
    );

    Ok(())
}
