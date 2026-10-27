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

use crate::{FinalizeRegisters, Stack};
use console::{
    network::prelude::*,
    program::{Identifier, Value},
};

use snarkvm_synthesizer_program::{
    FinalizeGlobalState,
    FinalizeRegistersState,
    FinalizeStoreTrait,
    RegistersTrait,
    StackTrait,
};

/// Evaluates a view function against `store`.
pub(crate) fn evaluate_view_inner<N: Network>(
    state: FinalizeGlobalState,
    store: &dyn FinalizeStoreTrait<N>,
    stack: &Stack<N>,
    view_name: &Identifier<N>,
    inputs: Vec<Value<N>>,
) -> Result<Vec<Value<N>>> {
    // Resolve the view function in the stack's program.
    let view = stack.program().get_view_ref(view_name)?;

    // Use the cached view types (computed once at `Stack::new`).
    let types = stack.get_view_types(view_name)?;

    // Views are read-only and externally-callable: no transition is associated. Pass `None`
    // for `transition_id` and `nonce` — the only consumer (rand.chacha) is rejected by
    // `add_command`, so any future reader of these fields must handle the `None` case
    // explicitly (the trait surface makes this a compile-time obligation).
    let mut registers = FinalizeRegisters::new(state, None, *view.name(), types, None);

    // Validate the input arity.
    ensure!(
        view.inputs().len() == inputs.len(),
        "View '{}' expects {} inputs, got {}",
        view.name(),
        view.inputs().len(),
        inputs.len(),
    );

    // Reject non-plaintext inputs up-front. View input statements are typed
    // `FinalizeType::Plaintext` at construction, so the per-register store would reject
    // these as well — but with a generic type-mismatch error. Surfacing the kind here
    // gives a clearer UX.
    for (i, value) in inputs.iter().enumerate() {
        let kind = match value {
            Value::Plaintext(_) => continue,
            Value::Record(_) => "record",
            Value::Future(_) => "future",
            Value::DynamicRecord(_) => "dynamic record",
            Value::DynamicFuture(_) => "dynamic future",
        };
        bail!("View '{}' input #{i} must be a plaintext value, got a {kind}", view.name());
    }

    // Store the inputs.
    for (input_stmt, value) in view.inputs().iter().zip(inputs) {
        registers.store(stack, input_stmt.register(), value)?;
    }

    // Evaluate the commands. Views reject `await` at construction (`add_command`), so the
    // dispatch is identical to `Finalize` / `Constructor` — we share `finalize_command_except_await`
    // directly to avoid drift. `try_vm_runtime` inside that helper also gives views panic-catch
    // protection, which is desirable on the off-consensus / RPC-exposed path.
    //
    // Termination & cost bounds (prototype):
    //   - The loop is bounded by `view.commands().len()`, which is itself bounded by
    //     `N::MAX_COMMANDS` (= `u16::MAX`).
    //   - `branch_to` (used by the helper) permits forward jumps only, so the counter
    //     strictly advances and no command can re-execute. Termination is guaranteed.
    //   - Deploy-time, `view_cost_for_single_view` enforces that the worst-case body
    //     cost is `<= TRANSACTION_SPEND_LIMIT`, so a deployed view cannot register an
    //     unboundedly expensive body.
    //   - There is intentionally NO smaller per-call runtime budget below the deploy
    //     bound. A node serving repeated external view calls can therefore consume up
    //     to the deploy bound per call. Rate-limiting and indexing are expected to be
    //     handled at the snarkOS RPC layer, not here.
    let mut counter = 0;
    let mut finalize_operations: Vec<snarkvm_synthesizer_program::FinalizeOperation<N>> = Vec::new();
    while counter < view.commands().len() {
        let command = &view.commands()[counter];
        crate::finalize::finalize_command_except_await(
            Some((*stack.program_id(), *stack.program_edition())),
            Some(*registers.function_name()),
            store,
            stack,
            &mut registers,
            view.positions(),
            command,
            &mut counter,
            &mut finalize_operations,
            view.name(),
        )?;
    }
    // Defensive: views reject all write-producing commands at construction, so no finalize
    // operations should ever be emitted. Fail closed in release builds too — a regression that
    // allows a write through the type-check path must not silently leak side effects from the
    // view path, where some callers (e.g. RPC views) discard `finalize_operations` entirely.
    ensure!(
        finalize_operations.is_empty(),
        "view '{}' produced finalize operations: {finalize_operations:?}",
        view.name()
    );

    // Load the outputs.
    let mut outputs = Vec::with_capacity(view.outputs().len());
    for output in view.outputs() {
        outputs.push(registers.load(stack, output.operand())?);
    }
    Ok(outputs)
}
