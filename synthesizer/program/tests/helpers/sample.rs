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

use circuit::AleoV0;
use console::{
    network::MainnetV0,
    prelude::*,
    program::{Identifier, Plaintext, Register, Value},
};
use snarkvm_synthesizer_process::{Authorization, CallStack, FinalizeRegisters, Process, Registers, Stack};
use snarkvm_synthesizer_program::{FinalizeGlobalState, RegistersCircuit as _, RegistersTrait as _};
use std::sync::OnceLock;

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

/// Returns a process loaded once and shared by every later caller in the same test process.
/// Only use it where the test never mutates the process, e.g. via `add_program` or `execute`.
pub fn shared_process() -> &'static Process<CurrentNetwork> {
    static PROCESS: OnceLock<Process<CurrentNetwork>> = OnceLock::new();
    PROCESS.get_or_init(|| Process::load().unwrap())
}

/// Samples the registers. Note: Do not replicate this for real program use, it is insecure.
pub fn sample_registers(
    stack: &Stack<CurrentNetwork>,
    function_name: &Identifier<CurrentNetwork>,
    values: &[(Value<CurrentNetwork>, Option<circuit::Mode>)],
) -> Result<Registers<CurrentNetwork, CurrentAleo>> {
    // Initialize the registers.
    let mut registers = Registers::<CurrentNetwork, CurrentAleo>::new(
        CallStack::evaluate(Authorization::try_from((vec![], vec![]))?)?,
        stack.get_register_types(function_name)?.clone(),
    );

    // For each value, store the register and value.
    for (index, (value, mode)) in values.iter().enumerate() {
        // Initialize the register.
        let register = Register::Locator(index as u64);
        // Store the value in the console registers.
        registers.store(stack, &register, value.clone())?;
        // If the mode is not `None`,
        if let Some(mode) = mode {
            use circuit::Inject;

            // Initialize the circuit value.
            let circuit_value = circuit::Value::new(*mode, value.clone());
            // Store the value in the circuit registers.
            registers.store_circuit(stack, &register, circuit_value)?;
        }
    }
    Ok(registers)
}

/// Samples the finalize registers. Note: Do not replicate this for real program use, it is insecure.
pub fn sample_finalize_registers(
    stack: &Stack<CurrentNetwork>,
    function_name: &Identifier<CurrentNetwork>,
    plaintexts: &[Plaintext<CurrentNetwork>],
) -> Result<FinalizeRegisters<CurrentNetwork>> {
    // Initialize the registers.
    let mut finalize_registers = FinalizeRegisters::<CurrentNetwork>::new(
        FinalizeGlobalState::from(1, 1, None, [0; 32], None, None),
        Some(<CurrentNetwork as Network>::TransitionID::default()),
        *function_name,
        stack.get_finalize_types(function_name)?.clone(),
        Some(0u64),
    );

    // For each literal,
    for (index, plaintext) in plaintexts.iter().enumerate() {
        // Initialize the register
        let register = Register::Locator(index as u64);
        // Store the value in the console registers.
        finalize_registers.store(stack, &register, Value::Plaintext(plaintext.clone()))?;
    }

    Ok(finalize_registers)
}
