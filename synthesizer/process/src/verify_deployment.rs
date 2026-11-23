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

use snarkvm_synthesizer_program::CallOperator;

impl<N: Network> Process<N> {
    /// Verifies the given deployment is ordered.
    #[inline]
    pub fn verify_deployment<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        consensus_version: ConsensusVersion,
        deployment: &Deployment<N>,
        rng: &mut R,
    ) -> Result<()> {
        let timer = timing_span!("Process::verify_deployment").entered();

        // Retrieve the program ID.
        let program_id = deployment.program().id();
        // Retrieve the maximum number of mappings for the consensus version.
        let max_mappings = consensus_config_value_by_version!(N, MAX_MAPPINGS, consensus_version)
            .ok_or_else(|| anyhow!("Missing consensus config value: MAX_MAPPINGS"))?;
        // Ensure the program does not exceed the maximum number of mappings.
        ensure!(
            deployment.program().mappings().len() <= max_mappings,
            "Program '{program_id}' exceeds the maximum number of mappings ({max_mappings}) for {consensus_version}"
        );
        // Check if this deployment is an amendment.
        let version = deployment.version()?;
        let is_amendment = matches!(version, DeploymentVersion::V3);
        // If the deployment is an amendment, verify that the program exists.
        // If the edition is zero (and not an amendment), verify that the program does not exist.
        // Otherwise, verify that the program exists.
        if is_amendment {
            ensure!(
                self.contains_program(program_id),
                "Program '{program_id}' does not exist, but amendment requires an existing program"
            );
        } else {
            match deployment.edition().is_zero() {
                true => ensure!(
                    !self.contains_program(program_id),
                    "Program '{program_id}' already exists, but the deployment edition is zero"
                ),
                false => ensure!(
                    self.contains_program(program_id),
                    "Program '{program_id}' does not exist, but the deployment edition is non-zero"
                ),
            }
        }

        // Ensure the program is well-formed, by computing the stack.
        // Note: The program owner is intentionally not set, since `program_owner` is an operand
        //   that is only available in a finalize scope.
        let stack = if is_amendment {
            // For amendments, use the existing edition instead of incrementing.
            // Note: `Stack::new` cannot be used here because it would increment the edition.
            // Amendments must preserve the existing edition. Validity is verified by `initialize_and_check`.
            let existing_stack = self.get_stack(program_id)?;
            let stack = Stack::new_raw(self, deployment.program(), *existing_stack.program_edition())?;
            stack.initialize_and_check(self)?;
            stack
        } else {
            Stack::new(self, deployment.program())?
        };
        timing_event!("Compute the stack");

        // Ensure the program does not make a static call to a function with a constant output.
        if consensus_version >= ConsensusVersion::V23 {
            ensure_no_static_calls_to_constant_outputs(&stack)?;
        }

        // Ensure the verifying keys are well-formed and the certificates are valid.
        let verification = stack.verify_deployment::<A, R>(consensus_version, deployment, rng);
        timing_event!("Verify the deployment");

        drop(timer);
        verification
    }
}

/// Ensures that no function in the program of `stack` makes a static `call` to a function with a constant output.
///
/// Deployment synthesis samples the outputs of a static call, and a constant output enters the caller's circuit as a
/// constant.
fn ensure_no_static_calls_to_constant_outputs<N: Network>(stack: &Stack<N>) -> Result<()> {
    let program = stack.program();
    for function in program.functions().values() {
        for instruction in function.instructions() {
            let Instruction::Call(call) = instruction else { continue };
            // Retrieve the program that declares the callee.
            let external_stack;
            let (callee_program, callee_name) = match call.operator() {
                CallOperator::Locator(locator) => {
                    external_stack = stack.get_external_stack(locator.program_id())?;
                    (external_stack.program(), locator.resource())
                }
                CallOperator::Resource(resource) => (program, resource),
            };
            // Closure and view outputs have no visibility, so only a function can have a constant output.
            let Some(callee) = callee_program.functions().get(callee_name) else { continue };
            ensure!(
                !callee.outputs().iter().any(|output| matches!(output.value_type(), ValueType::Constant(_))),
                "Function '{}/{}' calls '{}', which has a constant output. A static call cannot return a constant output.",
                program.id(),
                function.name(),
                call.operator()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_utilities::{VmHalt, try_vm_runtime};
    use std::ops::Deref;

    type CurrentAleo = circuit::network::AleoV0;
    type CurrentNetwork = console::network::MainnetV0;

    /// Returns a program that casts `x` to a group with `op`, as a non-constant value, for every sampled input.
    fn cast_program(op: &str, index: usize, x: &str) -> Program<CurrentNetwork> {
        Program::from_str(&format!(
            "program off_curve_cast_{index}.aleo;\n\nfunction f:\n    input r0 as field.private;\n    is.eq r0 r0 into r1;\n    ternary r1 {x}field 1field into r2;\n    {op} r2 into r3 as group;\n    output r3 as group.private;\n\nconstructor:\n    assert.eq edition 0u16;\n"
        ))
        .unwrap()
    }

    /// Returns a deployment of `program` with the verifying keys of `keys_program`.
    fn deployment_with_keys_of(
        process: &Process<CurrentNetwork>,
        program: &Program<CurrentNetwork>,
        keys_program: &Program<CurrentNetwork>,
        rng: &mut TestRng,
    ) -> Deployment<CurrentNetwork> {
        let keys = process.deploy::<CurrentAleo, _>(keys_program, rng).unwrap();
        Deployment::new(
            0,
            program.clone(),
            keys.verifying_keys().clone(),
            Some(program.to_checksum()),
            Some(console::types::Address::zero()),
        )
        .unwrap()
    }

    /// The verdicts depend on the sequence of operations in the point arithmetic, through the off-curve witness of a
    /// rejected `x`. The tests of the circuit `Group::from_x_coordinate` pin the full lists of values.
    #[test]
    fn test_verify_deployment_off_curve_cast_verdicts() {
        let rng = &mut TestRng::default();

        // `2` has a group element, and the others do not.
        for (index, (op, x)) in [
            ("cast", "2"),
            ("cast", "1"),
            ("cast", "993836843171880604782108004137850162404213406205532410908816984011375463874"),
            ("cast.lossy", "2"),
            ("cast.lossy", "1646887550125418539688483748007992615780454861634823357515367456465219956426"),
        ]
        .into_iter()
        .enumerate()
        {
            let program = cast_program(op, index, x);
            let deployment = Process::load().unwrap().deploy::<CurrentAleo, _>(&program, rng).unwrap();
            Process::load()
                .unwrap()
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::latest(), &deployment, rng)
                .unwrap();
        }

        for (index, (op, x)) in [
            ("cast", "7647702037709885229845698841124471395615470129800647510314961670563126650261"),
            ("cast.lossy", "8118073244815719018718382245642935365868859196959840368889557166795111106598"),
        ]
        .into_iter()
        .enumerate()
        {
            let program = cast_program(op, index, x);
            let process = Process::load().unwrap();
            assert!(try_vm_runtime(|| process.deploy::<CurrentAleo, _>(&program, &mut TestRng::default())).is_err());

            let deployment = deployment_with_keys_of(&process, &program, &cast_program(op, index, "2"), rng);
            let process = Process::load().unwrap();
            let result = try_vm_runtime(|| {
                process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::latest(), &deployment, rng)
            });
            assert!(result.is_err(), "the deployment must be rejected by a panic during synthesis");
        }
    }

    /// `off_curve_cast.deployment` is the output of `deploy` for this program on snarkVM v4.12.1, with its original keys
    /// and certificate. A circuit change that breaks existing deployments fails here, even when `deploy` and
    /// `verify_deployment` still agree with each other.
    #[test]
    fn test_verify_deployment_saved_off_curve_cast() {
        let rng = &mut TestRng::default();

        let bytes = include_bytes!("./resources/off_curve_cast.deployment");
        let deployment = Deployment::<CurrentNetwork>::read_le(&bytes[..]).unwrap();
        let x = "993836843171880604782108004137850162404213406205532410908816984011375463874";
        assert_eq!(deployment.program(), &cast_program("cast", 0, x));

        Process::load()
            .unwrap()
            .verify_deployment::<CurrentAleo, _>(ConsensusVersion::latest(), &deployment, rng)
            .unwrap();
    }

    /// A halt in deployment synthesis on a rayon worker does not reach the host's panic hook.
    #[test]
    fn test_verify_deployment_halt_on_worker_skips_host_hook() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const CHILD_PROCESS_ENV: &str = "SNARKVM_DEPLOYMENT_HALT_HOOK_CHILD";
        const TEST_NAME: &str = "verify_deployment::tests::test_verify_deployment_halt_on_worker_skips_host_hook";

        if std::env::var_os(CHILD_PROCESS_ENV).is_none() {
            // Run this test in a fresh process because panic hooks are process-global.
            let output =
                std::process::Command::new(std::env::current_exe().expect("Failed to locate the test executable"))
                    .args([TEST_NAME, "--exact", "--nocapture"])
                    .env(CHILD_PROCESS_ENV, "1")
                    .output()
                    .expect("Failed to launch the child test process");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "Child test failed.\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let host_hook_calls = Arc::new(AtomicUsize::new(0));
        let host_hook_calls_ = host_hook_calls.clone();
        std::panic::set_hook(Box::new(move |_| {
            host_hook_calls_.fetch_add(1, Ordering::SeqCst);
        }));

        // Each function of `program` has more variables than the keys of `keys_program` allow, so its synthesis halts
        // at the variable limit. Rayon runs a loop over one item on the calling thread, so the program has two functions.
        let program_with = |instruction: &str| {
            let functions = ["f", "g"].map(|function| {
                format!(
                    "function {function}:\n    input r0 as field.private;\n    {instruction};\n    output r1 as field.private;\n\n"
                )
            });
            Program::<CurrentNetwork>::from_str(&format!(
                "program halt_on_worker.aleo;\n\n{}constructor:\n    assert.eq edition 0u16;\n",
                functions.concat()
            ))
            .expect("The program should parse")
        };
        let program = program_with("hash.bhp256 r0 into r1 as field");
        let keys_program = program_with("add r0 r0 into r1");
        let rng = &mut TestRng::default();
        let process = Process::load().unwrap();
        let deployment = deployment_with_keys_of(&process, &program, &keys_program, rng);

        // This thread is not a rayon worker, so the synthesis jobs run on workers of the global pool.
        assert!(rayon::current_thread_index().is_none());
        let result = try_vm_runtime(|| {
            process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::latest(), &deployment, rng)
        });
        let payload = result.expect_err("the deployment must be rejected by a halt during synthesis");
        let halt = payload.downcast_ref::<VmHalt>().expect("the panic must be a VM halt");
        assert!(halt.message().starts_with("Surpassed the"), "unexpected halt message: {halt}");
        assert_eq!(host_hook_calls.load(Ordering::SeqCst), 0, "the halt must not reach the host hook");
    }

    /// Use `cargo test profiler --features timer` to run this test.
    #[ignore]
    #[test]
    fn test_profiler() -> Result<()> {
        let rng = &mut TestRng::default();

        // Initialize the process.
        let process = Process::load()?;

        // Fetch the large program to deploy.
        let large_program = Program::from_str(include_str!("./resources/large_functions.aleo"))?;

        // Create a deployment for the program.
        let deployment = process.deploy::<CurrentAleo, _>(&large_program, rng)?;

        // Verify the deployment.
        assert!(process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V8, &deployment, rng).is_ok());

        bail!("\n\nRemember to #[ignore] this test!\n\n")
    }

    /// Inflates the claimed variable count on the first verifying key of `deployment`.
    fn with_inflated_variables<N: Network>(deployment: &Deployment<N>, num_variables: u64) -> Deployment<N> {
        let (function_id, (vk, certificate)) = &deployment.verifying_keys()[0];
        let tampered_vks =
            vec![(*function_id, (VerifyingKey::new(Arc::new(vk.deref().clone()), num_variables), certificate.clone()))];
        Deployment::new(
            deployment.edition(),
            deployment.program().clone(),
            tampered_vks,
            deployment.program_checksum(),
            deployment.program_owner(),
        )
        .unwrap()
    }

    /// Inflates the claimed constraint count on the first verifying key of `deployment`.
    fn with_inflated_constraints<N: Network>(deployment: &Deployment<N>, num_constraints: usize) -> Deployment<N> {
        let (function_id, (vk, certificate)) = &deployment.verifying_keys()[0];
        let mut circuit_vk = vk.deref().clone();
        circuit_vk.circuit_info.num_constraints = num_constraints;
        let tampered_vks =
            vec![(*function_id, (VerifyingKey::new(Arc::new(circuit_vk), vk.num_variables()), certificate.clone()))];
        Deployment::new(
            deployment.edition(),
            deployment.program().clone(),
            tampered_vks,
            deployment.program_checksum(),
            deployment.program_owner(),
        )
        .unwrap()
    }

    fn program_with_mappings(num_mappings: usize) -> Result<Program<CurrentNetwork>> {
        let mut program = String::new();
        program.push_str("program mappings.aleo;\n\n");
        for i in 0..num_mappings {
            program
                .push_str(&format!("mapping mapping_{i}:\n    key as field.public;\n    value as field.public;\n\n"));
        }
        program.push_str("function foo:\n    add 0u8 1u8 into r0;\n");
        Program::from_str(&program)
    }

    #[test]
    fn test_mapping_limits_by_consensus_version() -> Result<()> {
        let rng = &mut TestRng::default();
        let process = Process::load()?;

        let program_with_31_mappings = program_with_mappings(31)?;
        let deployment_with_31_mappings = process.deploy::<CurrentAleo, _>(&program_with_31_mappings, rng)?;
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V21, &deployment_with_31_mappings, rng)?;

        let program_with_32_mappings = program_with_mappings(32)?;
        let deployment_with_32_mappings = process.deploy::<CurrentAleo, _>(&program_with_32_mappings, rng)?;
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V21, &deployment_with_32_mappings, rng)
                .unwrap_err()
                .to_string()
                .contains("exceeds the maximum number of mappings (31) for V21")
        );
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V22, &deployment_with_32_mappings, rng)?;

        let program_with_128_mappings = program_with_mappings(128)?;
        let deployment_with_128_mappings = process.deploy::<CurrentAleo, _>(&program_with_128_mappings, rng)?;
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V22, &deployment_with_128_mappings, rng)?;

        Ok(())
    }

    /// A program whose `constant_output` function returns its input as a `.constant` output, and whose
    /// `private_output` function returns its input as a `.private` output.
    const CONSTANT_OUTPUT_CALLEE: &str = r"
program constant_callee.aleo;

function constant_output:
    input r0 as boolean.private;
    output r0 as boolean.constant;

function private_output:
    input r0 as boolean.private;
    output r0 as boolean.private;";

    /// The error that `verify_deployment` returns for a static call to `constant_callee.aleo/constant_output`.
    const CONSTANT_OUTPUT_REJECTION: &str = "calls 'constant_callee.aleo/constant_output', which has a constant output";

    /// Returns a program that calls `constant_callee.aleo/{callee}`.
    fn program_calling(name: &str, callee: &str) -> Result<Program<CurrentNetwork>> {
        Program::from_str(&format!(
            "import constant_callee.aleo;\n\nprogram {name}.aleo;\n\nfunction foo:\n    input r0 as boolean.private;\n    call constant_callee.aleo/{callee} r0 into r1;\n    ternary r1 1u8 0u8 into r2;\n    output r2 as u8.private;\n"
        ))
    }

    #[test]
    fn test_static_call_to_constant_output_by_consensus_version() -> Result<()> {
        let rng = &mut TestRng::default();
        let process = Process::load()?;
        process.lock().add_program(&Program::from_str(CONSTANT_OUTPUT_CALLEE)?)?;

        // Before V23, the caller's circuit depends on the value that synthesis samples for the constant output. The
        // verifier samples it with a seed derived from the deployment, which is fixed by the program. So only some
        // programs with such a call can be deployed, and each attempt below uses a new program name.
        let mut accepted = None;
        for attempt in 0..32 {
            let program = program_calling(&format!("calls_constant_{attempt}"), "constant_output")?;
            let deployment = process.deploy::<CurrentAleo, _>(&program, rng)?;
            match process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V22, &deployment, rng) {
                Ok(()) => {
                    accepted = Some(deployment);
                    break;
                }
                Err(error) => {
                    assert!(!error.to_string().contains(CONSTANT_OUTPUT_REJECTION), "unexpected error: {error}")
                }
            }
        }
        let deployment = accepted.expect("a deployment of the caller must be accepted before V23");

        // From V23, the same deployment is rejected.
        for consensus_version in [ConsensusVersion::V23, ConsensusVersion::latest()] {
            let error = process
                .verify_deployment::<CurrentAleo, _>(consensus_version, &deployment, rng)
                .unwrap_err()
                .to_string();
            assert!(error.contains(CONSTANT_OUTPUT_REJECTION), "unexpected error: {error}");
        }

        // A call to a function without constant outputs is accepted at every consensus version.
        let program = program_calling("calls_private", "private_output")?;
        let deployment = process.deploy::<CurrentAleo, _>(&program, rng)?;
        for consensus_version in [ConsensusVersion::V22, ConsensusVersion::V23, ConsensusVersion::latest()] {
            process.verify_deployment::<CurrentAleo, _>(consensus_version, &deployment, rng)?;
        }

        Ok(())
    }

    /// Per-transaction variable and constraint limits are enforced before V18 and from V19,
    /// using the v2 limits from V19. V18 skips these checks in favor of a block-wide synthesis limit.
    #[test]
    fn test_deployment_variable_and_constraint_limits_by_consensus_version() -> Result<()> {
        let rng = &mut TestRng::default();
        let process = Process::load()?;

        let program = Program::from_str(
            r"
program testing.aleo;
function foo:
    add 0u8 1u8 into r0;",
        )?;
        let deployment = process.deploy::<CurrentAleo, _>(&program, rng)?;

        let over_v1_variables = with_inflated_variables(&deployment, CurrentNetwork::MAX_DEPLOYMENT_VARIABLES + 1);
        let over_v2_variables = with_inflated_variables(&deployment, CurrentNetwork::MAX_DEPLOYMENT_VARIABLES_V2 + 1);
        let over_v1_constraints =
            with_inflated_constraints(&deployment, usize::try_from(CurrentNetwork::MAX_DEPLOYMENT_CONSTRAINTS + 1)?);
        let over_v2_constraints =
            with_inflated_constraints(&deployment, usize::try_from(CurrentNetwork::MAX_DEPLOYMENT_CONSTRAINTS_V2 + 1)?);

        // V16 enforces the original per-transaction limits.
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V16, &over_v1_variables, rng)
                .unwrap_err()
                .to_string()
                .contains("combined variables exceeds the deployment limit")
        );
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V16, &over_v1_constraints, rng)
                .unwrap_err()
                .to_string()
                .contains("combined constraints exceeds the deployment limit")
        );

        // V18 skips per-transaction variable/constraint limits.
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V18, &over_v1_variables, rng)?;
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V18, &over_v2_variables, rng)?;

        // V19 enforces the v2 per-transaction limits.
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V19, &over_v1_variables, rng)?;
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V19, &over_v2_variables, rng)
                .unwrap_err()
                .to_string()
                .contains("combined variables exceeds the deployment limit")
        );
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V19, &over_v2_constraints, rng)
                .unwrap_err()
                .to_string()
                .contains("combined constraints exceeds the deployment limit")
        );

        Ok(())
    }
}
