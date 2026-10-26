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

#![allow(clippy::cast_possible_truncation)]

use super::*;

// Construct `count` deployer keys and fund them so more than one deployment can fit in a single block.
fn fund_deployer_keys(
    vm: &VM<CurrentNetwork, LedgerType>,
    genesis_private_key: &PrivateKey<CurrentNetwork>,
    count: usize,
    rng: &mut TestRng,
) -> Vec<PrivateKey<CurrentNetwork>> {
    let funds_per_deployer: usize = 4_000_000_000;

    let mut deployer_keys = Vec::with_capacity(count);

    while deployer_keys.len() < count {
        let candidate = PrivateKey::new(rng).unwrap();
        if !deployer_keys.contains(&candidate) {
            deployer_keys.push(candidate);
        }
    }

    for chunk in deployer_keys.chunks(VM::<CurrentNetwork, LedgerType>::MAXIMUM_CONFIRMED_TRANSACTIONS) {
        let funding_transactions: Vec<_> = chunk
            .iter()
            .map(|deployer_key| {
                let deployer_address = Address::try_from(deployer_key).unwrap();
                let inputs = [
                    Value::<CurrentNetwork>::from_str(&format!("{deployer_address}")).unwrap(),
                    Value::from_str(&format!("{funds_per_deployer}u64")).unwrap(),
                ];
                vm.execute(genesis_private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
                    .unwrap()
            })
            .collect();

        add_and_test_with_costs(vm, genesis_private_key, None, &funding_transactions, rng);
    }

    deployer_keys
}

fn function_program_from_multiplier(multiplier: usize, name_prefix: &str, suffix: usize) -> Program<CurrentNetwork> {
    let mut program_str = format!(
        r"
    program {name_prefix}_fun_{suffix}.aleo;

    function fun:
        input r0 as [field; 2u32].public;
"
    );

    for j in 1..multiplier {
        program_str += &format!(
            r"
        hash.bhp256 r0 into r{j} as field;
    "
        );
    }

    program_str += r"
    constructor:
        assert.eq true true;
    ";

    Program::from_str(&program_str).unwrap()
}

fn record_program_from_multiplier(multiplier: usize, name_prefix: &str, suffix: usize) -> Program<CurrentNetwork> {
    let mut program_str = format!(
        r"
        program {name_prefix}_rec_{suffix}.aleo;"
    );

    for j in 0..multiplier {
        // Ending the record name in _ prevents the situation where the program contains both
        // rec_test_synthesis_0_1 and rec_test_synthesis_0_10, which is disallowed by the rule
        // that record names cannot be prefixes of one another.
        program_str += &format!(
            r"
            record rec_{name_prefix}_{j}_:
                owner as address.private;
                data as field.public;
        "
        );
    }

    program_str += r"
            function fun:
                assert.eq true true;

            constructor:
                assert.eq true true;
    ";

    Program::from_str(&program_str).unwrap()
}

/// Extracts the message from a panic payload caught by [`try_vm_runtime`].
fn vm_halt_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| format!("unexpected panic payload: {payload:?}"))
}

/// Checks that the block-wide synthesis limit is computed and enforced correctly.
#[test]
fn test_blockwide_synthesis_limit() {
    let current_max_certificates = CurrentNetwork::LATEST_MAX_CERTIFICATES() as f64;

    let rng = &mut TestRng::default();

    // Advance to the last V18 height so the next block remains in V18 (V19 is the subsequent height).
    let v18_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap();
    let v19_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V19).unwrap();

    // When V19 is the next height after V18, setup cannot stay in the window where
    // `Subdag::synthesis_limit` applies (V18 and the first V19 block).
    if v18_height.saturating_add(1) == v19_height {
        return;
    }

    let vm = sample_vm_at_height(v19_height.saturating_sub(1).max(v18_height.saturating_sub(1)), rng);
    let genesis_private_key = sample_genesis_private_key(rng);

    // Set to true to print the combined density of each individual deployment.
    let verbose = false;

    // Each entry has the form (c, ds, as) with
    // - c: number of certificates
    // - ds: (multiplier, function_program) for each deployment
    //       if the latter is set to true, the program constructed has a large function;
    //       if false, it has a large record
    // - as: for each deployment (in the same order as above), whether it is expected to be aborted
    //
    // For reference, these are the function- and record-program densities for a few selected multipliers:
    //          function     record
    // - 1:       69_418    171_395
    // - 2:       84_631    285_567
    // - 4:      115_057    513_911
    // - 8:      175_909    970_287
    // - 16:     297_613  1_882_985
    // - 32:     541_021  3_708_137
    // - 64:   1_027_837  7_358_441
    let cases = vec![
        // Synthesis limit = 1_081_730, densities: [297_613, 297_613, 297_613], total 892_839 below limit
        ((0.15 * current_max_certificates) as u64, vec![(16, true); 3], vec![false; 3]),
        // Synthesis limit = 1_081_730, densities: [297_613, 297_613, 297_613, 297_613], the last one goes over the limit
        ((0.15 * current_max_certificates) as u64, vec![(16, true); 4], vec![false, false, false, true]),
        // Synthesis limit = 1_442_307, densities: [1_027_837]
        ((0.2 * current_max_certificates) as u64, vec![(64, true)], vec![false; 1]),
        // Synthesis limit = 1_442_307, densities: [541_021, 541_021, 541_021], the third one goes over the limit
        ((0.2 * current_max_certificates) as u64, vec![(32, true); 3], vec![false, false, true]),
        // Synthesis limit = 1_442_307, densities: [513_911, 513_911, 513_911], the third one goes over the limit
        ((0.2 * current_max_certificates) as u64, vec![(4, false); 3], vec![false, false, true]),
        // Synthesis limit = 11_250_000, densities: [3_708_137, 3_708_137, 3_708_137]
        ((1.5 * current_max_certificates) as u64, vec![(32, false); 3], vec![false, false, false]),
        // Synthesis limit = 1_874_999, densities: [541_021, 541_021, 541_021], the third one now fits thanks to the increased limit
        ((0.25 * current_max_certificates) as u64, vec![(32, true); 3], vec![false, false, false]),
        // Synthesis limit = 1_081_730, densities: [297_613, 541_021, 297_613, 84_631, 297_613, 84_631],
        // the third and fifth go over the limit, fourth and sixth still fit
        (
            (0.15 * current_max_certificates) as u64,
            vec![(16, true), (32, true), (16, true), (2, true), (16, true), (2, true)],
            vec![false, false, true, false, true, false],
        ),
        // Similar to above, but we mix function- and record-heavy programs
        // Synthesis limit = 1_225_961, densities: [297_613, 513_911, 171_395, 297_613, 171_395, 285_567],
        // the fourth and sixth go over the limit, the fifth still fits
        (
            (0.17 * current_max_certificates) as u64,
            vec![(16, true), (4, false), (1, false), (16, true), (1, false), (2, false)],
            vec![false, false, false, true, false, true],
        ),
    ];

    let num_deployer_keys = cases.iter().map(|(_, ds, _)| ds.len()).sum::<usize>();

    let mut deployer_keys = fund_deployer_keys(&vm, &genesis_private_key, num_deployer_keys, rng);

    let block_hash = vm.block_store().get_block_hash(vm.block_store().max_height().unwrap()).unwrap().unwrap();
    let previous_block = vm.block_store().get_block(&block_hash).unwrap().unwrap();
    let next_block_height = previous_block.height().saturating_add(1);

    for (i, (num_certs, deployment_specs, aborted)) in cases.into_iter().enumerate() {
        println!("Sampling subdag at height {next_block_height}");
        let subdag = subdag_with_cert_count(num_certs as usize, rng);
        let num_deployments = deployment_specs.len();

        // From the second V19 block, per-transaction limits apply and `synthesis_limit` is `None`.
        let Some(synthesis_limit) = subdag.synthesis_limit(next_block_height) else {
            return;
        };

        let name_prefix = &format!("test_synthesis_{i}");

        println!("Sampling deployments with specs: {deployment_specs:?}");

        let deployments: Vec<Transaction<CurrentNetwork>> = deployment_specs
            .into_iter()
            .enumerate()
            .map(|(i, (multiplier, use_function_program))| {
                let program = if use_function_program {
                    function_program_from_multiplier(multiplier, name_prefix, i)
                } else {
                    record_program_from_multiplier(multiplier, name_prefix, i)
                };
                let private_key = &deployer_keys.pop().unwrap();

                let deployment = vm.deploy(private_key, &program, None, 0, None, rng).unwrap();

                if verbose {
                    println!(
                        "  Deployment with multiplier {multiplier}, combined density {}",
                        deployment.deployment().unwrap().combined_density()
                    );
                }

                deployment
            })
            .collect();

        let next_timestamp = previous_block.timestamp().saturating_add(CurrentNetwork::BLOCK_TIME as i64);
        let next_timestamp = (next_block_height
            >= CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default())
        .then_some(next_timestamp);

        println!("Sampling finalize state");
        let finalize_state = FinalizeGlobalState::from(
            previous_block.round().saturating_add(1),
            next_block_height,
            next_timestamp,
            [0u8; 32],
            subdag.spend_limit(next_block_height),
            Some(synthesis_limit),
        );

        println!("Speculating");
        let (ratifications, confirmed_transactions, aborted_transaction_ids, _finalize_operations) = vm
            .speculate(
                finalize_state,
                CurrentNetwork::BLOCK_TIME as i64,
                None,
                Vec::new(),
                &Solutions::from(None),
                deployments.iter(),
                rng,
            )
            .unwrap();

        // The first `num_deployments - num_aborted` deployments are expected to be accepted, the rest aborted.
        let expected_aborted_transaction_ids = deployments
            .iter()
            .zip(aborted.iter())
            .filter_map(|(deployment, should_be_aborted)| should_be_aborted.then_some(deployment.id()))
            .collect::<HashSet<_>>();

        println!("Synthesis limit: {synthesis_limit}\n");

        assert_eq!(ratifications.len(), 0);
        assert_eq!(confirmed_transactions.num_accepted(), num_deployments - expected_aborted_transaction_ids.len());
        assert_eq!(confirmed_transactions.num_rejected(), 0);
        assert_eq!(HashSet::from_iter(aborted_transaction_ids), expected_aborted_transaction_ids);
    }
}

/// Checks that, during synthesis, if the running density of one of the function- or record-circuit
/// matrices surpasses the total claimed in the verifying key, synthesis stops.
#[test]
fn test_vk_num_non_zero_detected() {
    let rng = &mut TestRng::default();

    let v18_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap();
    let vm = sample_vm_at_height(v18_height, rng);
    let genesis_private_key = sample_genesis_private_key(rng);

    let cases = vec![("function", 1), ("function", 2), ("function", 4), ("function", 8), ("record", 1)];
    for (i, (program_type, multiplier)) in cases.into_iter().enumerate() {
        let program = match program_type {
            "function" => function_program_from_multiplier(multiplier, "function_test", i),
            "record" => record_program_from_multiplier(1, "record_test", i),
            _ => panic!("Invalid circuit type: {program_type}"),
        };

        let deployment =
            vm.deploy(&genesis_private_key, &program, None, 0, None, rng).unwrap().deployment().unwrap().clone();

        let expected_num_vks = match program_type {
            "function" => 1,
            // The generated record-heavy program still has a circuit verification key for the dummy function.
            "record" => 2,
            _ => panic!("Invalid circuit type: {program_type}"),
        };
        assert!(deployment.verifying_keys().len() == expected_num_vks);

        let (function_id, (vk, certificate)) = &deployment.verifying_keys()[expected_num_vks - 1];

        for tamper_with in ["a", "b", "c"] {
            let mut circuit_vk = vk.deref().clone();
            assert!(
                circuit_vk.circuit_info.num_non_zero_a >= 1,
                "multiplier {multiplier}: num_non_zero_a must be at least 1 to under-report"
            );

            match tamper_with {
                "a" => circuit_vk.circuit_info.num_non_zero_a -= 1,
                "b" => circuit_vk.circuit_info.num_non_zero_b -= 1,
                "c" => circuit_vk.circuit_info.num_non_zero_c -= 1,
                _ => panic!("tamper_with must be a, b or c, got {tamper_with}"),
            }

            let tampered_vks = match program_type {
                "function" => vec![(
                    *function_id,
                    (VerifyingKey::new(Arc::new(circuit_vk), vk.num_variables()), certificate.clone()),
                )],
                "record" => vec![
                    deployment.verifying_keys()[0].clone(),
                    (*function_id, (VerifyingKey::new(Arc::new(circuit_vk), vk.num_variables()), certificate.clone())),
                ],
                _ => panic!("Invalid circuit type: {program_type}"),
            };

            let tampered_deployment = Deployment::new(
                deployment.edition(),
                deployment.program().clone(),
                tampered_vks,
                deployment.program_checksum(),
                deployment.program_owner(),
            )
            .unwrap();

            // check_transaction uses try_vm_runtime and replaces the halt panic with a generic message.
            // We call the latter directly to receive the finer-grained error.
            let verification_result = try_vm_runtime(|| {
                vm.process().verify_deployment::<CurrentAleo, _>(ConsensusVersion::V18, &tampered_deployment, rng)
            });

            let error_message = match verification_result {
                Ok(Ok(())) => panic!("Expected deployment verification to fail"),
                Ok(Err(error)) => error.to_string(),
                Err(payload) => vm_halt_message(payload),
            };

            assert!(error_message.contains("Surpassed the circuit density limit"));
        }
    }
}
