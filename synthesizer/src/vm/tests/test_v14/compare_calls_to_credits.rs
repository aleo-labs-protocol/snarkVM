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

//! Tests comparing static vs dynamic calls to all credits.aleo functions.
//!
//! Each test compares:
//! - Deployment costs (storage, synthesis, constructor, namespace)
//! - Verifying key sizes and content
//! - Execution costs (storage, finalize)

use super::*;

use snarkvm_ledger_block::Output;

/// Helper to get field representation of an identifier.
fn identifier_to_field(name: &str) -> Field<CurrentNetwork> {
    Identifier::<CurrentNetwork>::from_str(name).unwrap().to_field().unwrap()
}

/// Helper to extract and decrypt a record from a transaction's first output.
fn extract_record(
    tx: &Transaction<CurrentNetwork>,
    view_key: &ViewKey<CurrentNetwork>,
) -> Record<CurrentNetwork, Plaintext<CurrentNetwork>> {
    let output = tx.transitions().next().unwrap().outputs().iter().next().unwrap();
    match output {
        Output::Record(_, _, record_ciphertext, _) => record_ciphertext.as_ref().unwrap().decrypt(view_key).unwrap(),
        _ => panic!("Expected record output"),
    }
}

/// Helper to fund a program with public credits by transferring to the program name.
fn fund_program(
    vm: &VM<CurrentNetwork, LedgerType>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    program_name: &str,
    amount: u64,
    rng: &mut TestRng,
) {
    let inputs = vec![Value::from_str(program_name).unwrap(), Value::from_str(&format!("{amount}u64")).unwrap()];
    let tx =
        vm.execute(caller_private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng).unwrap();
    add_and_test_with_costs(vm, caller_private_key, Some(&[&inputs]), &[tx], rng);
}

/// Helper to mint a credits record via transfer_public_to_private.
fn mint_record(
    vm: &VM<CurrentNetwork, LedgerType>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    receiver: &Address<CurrentNetwork>,
    amount: u64,
    rng: &mut TestRng,
) -> (Transaction<CurrentNetwork>, Record<CurrentNetwork, Plaintext<CurrentNetwork>>) {
    let view_key = ViewKey::try_from(caller_private_key).unwrap();
    let inputs =
        vec![Value::from_str(&receiver.to_string()).unwrap(), Value::from_str(&format!("{amount}u64")).unwrap()];
    let tx = vm
        .execute(caller_private_key, ("credits.aleo", "transfer_public_to_private"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(vm, caller_private_key, Some(&[&inputs]), std::slice::from_ref(&tx), rng);
    let record = extract_record(&tx, &view_key);
    (tx, record)
}

/// Deployment cost breakdown: (total, storage, synthesis)
/// Note: constructor and namespace costs are fixed (2000 and 1000000 respectively for standard names).
type DeploymentCosts = (u64, u64, u64);

/// Execution cost breakdown: (total, storage, finalize)
type ExecutionCosts = (u64, u64, u64);

/// Helper to get deployment costs for static and dynamic wrappers.
/// Returns ((static_total, static_storage, static_synthesis), (dynamic_total, dynamic_storage, dynamic_synthesis))
fn get_deployment_costs(
    vm: &VM<CurrentNetwork, LedgerType>,
    static_deployment: &Deployment<CurrentNetwork>,
    dynamic_deployment: &Deployment<CurrentNetwork>,
    consensus_version: ConsensusVersion,
) -> (DeploymentCosts, DeploymentCosts) {
    let process = vm.process();

    let (static_total, (static_storage, static_synthesis, _, _)) =
        deployment_cost(process, static_deployment, consensus_version).unwrap();
    let (dynamic_total, (dynamic_storage, dynamic_synthesis, _, _)) =
        deployment_cost(process, dynamic_deployment, consensus_version).unwrap();

    ((static_total, static_storage, static_synthesis), (dynamic_total, dynamic_storage, dynamic_synthesis))
}

/// Helper to get verifying key sizes for static and dynamic wrappers.
/// Returns (static_vk_size, dynamic_vk_size).
fn get_vk_sizes(
    static_deployment: &Deployment<CurrentNetwork>,
    dynamic_deployment: &Deployment<CurrentNetwork>,
    function_name: &str,
) -> (usize, usize) {
    let fn_id = Identifier::<CurrentNetwork>::from_str(function_name).unwrap();

    let static_vk_bytes: Vec<u8> = static_deployment
        .verifying_keys()
        .iter()
        .find(|(name, _)| *name == fn_id)
        .map(|(_, (vk, _))| vk.to_bytes_le().unwrap())
        .unwrap();

    let dynamic_vk_bytes: Vec<u8> = dynamic_deployment
        .verifying_keys()
        .iter()
        .find(|(name, _)| *name == fn_id)
        .map(|(_, (vk, _))| vk.to_bytes_le().unwrap())
        .unwrap();

    // VKs are different circuits but should have equal size.
    assert_ne!(static_vk_bytes, dynamic_vk_bytes, "{function_name}: VKs should be different circuits");

    (static_vk_bytes.len(), dynamic_vk_bytes.len())
}

/// Helper to get execution costs for static and dynamic transactions.
/// Returns ((static_total, static_storage, static_finalize), (dynamic_total, dynamic_storage, dynamic_finalize))
fn get_execution_costs(
    vm: &VM<CurrentNetwork, LedgerType>,
    static_tx: &Transaction<CurrentNetwork>,
    dynamic_tx: &Transaction<CurrentNetwork>,
    consensus_version: ConsensusVersion,
) -> (ExecutionCosts, ExecutionCosts) {
    let process = vm.process();

    let static_exec = static_tx.execution().unwrap();
    let dynamic_exec = dynamic_tx.execution().unwrap();

    let (static_total, (static_storage, static_finalize)) =
        execution_cost(process, static_exec, consensus_version).unwrap();
    let (dynamic_total, (dynamic_storage, dynamic_finalize)) =
        execution_cost(process, dynamic_exec, consensus_version).unwrap();

    ((static_total, static_storage, static_finalize), (dynamic_total, dynamic_storage, dynamic_finalize))
}

// =============================================================================
// Transfer Functions
// =============================================================================

#[test]
fn test_compare_transfer_public() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let transfer_public_field = identifier_to_field("transfer_public");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_transfer_public.aleo;

        function transfer_public:
            input r0 as address.public;
            input r1 as u64.public;
            call credits.aleo/transfer_public r0 r1 into r2;
            async transfer_public r2 into r3;
            output r3 as sw_transfer_public.aleo/transfer_public.future;

        finalize transfer_public:
            input r0 as credits.aleo/transfer_public.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_transfer_public.aleo;

        function transfer_public:
            input r0 as address.public;
            input r1 as u64.public;
            call.dynamic {credits_field} {aleo_field} {transfer_public_field}
                with r0 r1 (as address.public u64.public)
                into r2 (as dynamic.future);
            async transfer_public r2 into r3;
            output r3 as dw_transfer_public.aleo/transfer_public.future;

        finalize transfer_public:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_111_760, 1_072_000, 37_760),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_151_470, 1_112_000, 37_470),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) = get_vk_sizes(&static_deployment, &dynamic_deployment, "transfer_public");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Fund both wrapper programs so self.caller has balance.
    fund_program(&vm, &caller_private_key, "sw_transfer_public.aleo", 10_000_000, rng);
    fund_program(&vm, &caller_private_key, "dw_transfer_public.aleo", 10_000_000, rng);

    // Execute both wrappers.
    let recipient = Address::try_from(&caller_private_key).unwrap();
    let amount = "1000000u64";

    let static_inputs = vec![Value::from_str(&recipient.to_string()).unwrap(), Value::from_str(amount).unwrap()];
    let static_tx = vm
        .execute(
            &caller_private_key,
            ("sw_transfer_public.aleo", "transfer_public"),
            static_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let dynamic_inputs = [Value::from_str(&recipient.to_string()).unwrap(), Value::from_str(amount).unwrap()];
    let dynamic_tx = vm
        .execute(
            &caller_private_key,
            ("dw_transfer_public.aleo", "transfer_public"),
            dynamic_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Assert execution costs.
    let (static_exec_costs, dynamic_exec_costs) = get_execution_costs(&vm, &static_tx, &dynamic_tx, consensus_version);
    assert_eq!(static_exec_costs, (3_716, 2_391, 1_325), "Static execution costs (total, storage, finalize)");
    assert_eq!(dynamic_exec_costs, (3_725, 2_400, 1_325), "Dynamic execution costs (total, storage, finalize)");

    // Verify transactions.
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&static_inputs]), &[static_tx], rng);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&dynamic_inputs]), &[dynamic_tx], rng);
}

#[test]
fn test_compare_transfer_public_as_signer() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let transfer_public_as_signer_field = identifier_to_field("transfer_public_as_signer");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_transfer_public_as_signer.aleo;

        function transfer_public_as_signer:
            input r0 as address.public;
            input r1 as u64.public;
            call credits.aleo/transfer_public_as_signer r0 r1 into r2;
            async transfer_public_as_signer r2 into r3;
            output r3 as sw_transfer_public_as_signer.aleo/transfer_public_as_signer.future;

        finalize transfer_public_as_signer:
            input r0 as credits.aleo/transfer_public_as_signer.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_transfer_public_as_signer.aleo;

        function transfer_public_as_signer:
            input r0 as address.public;
            input r1 as u64.public;
            call.dynamic {credits_field} {aleo_field} {transfer_public_as_signer_field}
                with r0 r1 (as address.public u64.public)
                into r2 (as dynamic.future);
            async transfer_public_as_signer r2 into r3;
            output r3 as dw_transfer_public_as_signer.aleo/transfer_public_as_signer.future;

        finalize transfer_public_as_signer:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_203_113, 1_162_000, 39_113),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_222_437, 1_182_000, 38_437),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) =
        get_vk_sizes(&static_deployment, &dynamic_deployment, "transfer_public_as_signer");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Execute both wrappers (uses self.signer, so caller's balance works).
    let recipient = Address::try_from(&caller_private_key).unwrap();
    let amount = "1000000u64";

    let static_inputs = vec![Value::from_str(&recipient.to_string()).unwrap(), Value::from_str(amount).unwrap()];
    let static_tx = vm
        .execute(
            &caller_private_key,
            ("sw_transfer_public_as_signer.aleo", "transfer_public_as_signer"),
            static_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let dynamic_inputs = [Value::from_str(&recipient.to_string()).unwrap(), Value::from_str(amount).unwrap()];
    let dynamic_tx = vm
        .execute(
            &caller_private_key,
            ("dw_transfer_public_as_signer.aleo", "transfer_public_as_signer"),
            dynamic_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Assert execution costs.
    let (static_exec_costs, dynamic_exec_costs) = get_execution_costs(&vm, &static_tx, &dynamic_tx, consensus_version);
    assert_eq!(static_exec_costs, (3_786, 2_461, 1_325), "Static execution costs (total, storage, finalize)");
    assert_eq!(dynamic_exec_costs, (3_785, 2_460, 1_325), "Dynamic execution costs (total, storage, finalize)");

    // Verify transactions.
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&static_inputs]), &[static_tx], rng);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&dynamic_inputs]), &[dynamic_tx], rng);
}

#[test]
fn test_compare_transfer_public_to_private() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let transfer_public_to_private_field = identifier_to_field("transfer_public_to_private");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_transfer_public_to_private.aleo;

        function transfer_public_to_private:
            input r0 as address.private;
            input r1 as u64.public;
            call credits.aleo/transfer_public_to_private r0 r1 into r2 r3;
            async transfer_public_to_private r3 into r4;
            output r2 as credits.aleo/credits.record;
            output r4 as sw_transfer_public_to_private.aleo/transfer_public_to_private.future;

        finalize transfer_public_to_private:
            input r0 as credits.aleo/transfer_public_to_private.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_transfer_public_to_private.aleo;

        function transfer_public_to_private:
            input r0 as address.private;
            input r1 as u64.public;
            call.dynamic {credits_field} {aleo_field} {transfer_public_to_private_field}
                with r0 r1 (as address.private u64.public)
                into r2 r3 (as dynamic.record dynamic.future);
            async transfer_public_to_private r3 into r4;
            output r2 as dynamic.record;
            output r4 as dw_transfer_public_to_private.aleo/transfer_public_to_private.future;

        finalize transfer_public_to_private:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_263_891, 1_198_000, 63_891),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_244_866, 1_196_000, 46_866),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) =
        get_vk_sizes(&static_deployment, &dynamic_deployment, "transfer_public_to_private");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Fund both wrapper programs so self.caller has balance.
    fund_program(&vm, &caller_private_key, "sw_transfer_public_to_private.aleo", 10_000_000, rng);
    fund_program(&vm, &caller_private_key, "dw_transfer_public_to_private.aleo", 10_000_000, rng);

    // Execute both wrappers.
    let recipient = Address::try_from(&caller_private_key).unwrap();
    let amount = "1000000u64";

    let static_inputs = vec![Value::from_str(&recipient.to_string()).unwrap(), Value::from_str(amount).unwrap()];
    let static_tx = vm
        .execute(
            &caller_private_key,
            ("sw_transfer_public_to_private.aleo", "transfer_public_to_private"),
            static_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let dynamic_inputs = [Value::from_str(&recipient.to_string()).unwrap(), Value::from_str(amount).unwrap()];
    let dynamic_tx = vm
        .execute(
            &caller_private_key,
            ("dw_transfer_public_to_private.aleo", "transfer_public_to_private"),
            dynamic_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Assert execution costs.
    let (static_exec_costs, dynamic_exec_costs) = get_execution_costs(&vm, &static_tx, &dynamic_tx, consensus_version);
    assert_eq!(static_exec_costs, (3_376, 2_704, 672), "Static execution costs (total, storage, finalize)");
    assert_eq!(dynamic_exec_costs, (3_932, 3_260, 672), "Dynamic execution costs (total, storage, finalize)");

    // Verify static transaction only (dynamic outputs dynamic.record).
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&static_inputs]), &[static_tx], rng);
}

#[test]
fn test_compare_transfer_private() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let transfer_private_field = identifier_to_field("transfer_private");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_transfer_private.aleo;

        function transfer_private:
            input r0 as credits.aleo/credits.record;
            input r1 as address.private;
            input r2 as u64.private;
            call credits.aleo/transfer_private r0 r1 r2 into r3 r4;
            output r3 as credits.aleo/credits.record;
            output r4 as credits.aleo/credits.record;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_transfer_private.aleo;

        function transfer_private:
            input r0 as dynamic.record;
            input r1 as address.private;
            input r2 as u64.private;
            call.dynamic {credits_field} {aleo_field} {transfer_private_field}
                with r0 r1 r2 (as dynamic.record address.private u64.private)
                into r3 r4 (as dynamic.record dynamic.record);
            output r3 as dynamic.record;
            output r4 as dynamic.record;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    // Calculate the difference
    let static_vars: u64 = static_deployment.verifying_keys().iter().map(|(_, (vk, _))| vk.num_variables()).sum();
    let static_constraints: u64 =
        static_deployment.verifying_keys().iter().map(|(_, (vk, _))| vk.circuit_info.num_constraints as u64).sum();
    let dynamic_vars: u64 = dynamic_deployment.verifying_keys().iter().map(|(_, (vk, _))| vk.num_variables()).sum();
    let dynamic_constraints: u64 =
        dynamic_deployment.verifying_keys().iter().map(|(_, (vk, _))| vk.circuit_info.num_constraints as u64).sum();

    println!("\nDIFFERENCE (static - dynamic):");
    println!("  Variables: {} - {} = {}", static_vars, dynamic_vars, static_vars as i64 - dynamic_vars as i64);
    println!(
        "  Constraints: {} - {} = {}",
        static_constraints,
        dynamic_constraints,
        static_constraints as i64 - dynamic_constraints as i64
    );
    println!("\nReason: Static call uses InputID::Record verification (commitment + serial_number + tag)");
    println!("        Dynamic call uses InputID::DynamicRecord verification (single hash of fixed-size struct)");
    println!();

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_139_740, 1_032_000, 105_740),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_092_903, 1_039_000, 51_903),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) = get_vk_sizes(&static_deployment, &dynamic_deployment, "transfer_private");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Mint records for execution.
    let (_, record_1) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);
    let (_, record_2) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);

    // Convert to dynamic records for dynamic wrapper.
    let dynamic_record_1 = DynamicRecord::<CurrentNetwork>::from_record(&record_1).unwrap();
    let _dynamic_record_2 = DynamicRecord::<CurrentNetwork>::from_record(&record_2).unwrap();

    // Execute static wrapper with static record.
    let static_inputs = vec![
        Value::Record(record_1),
        Value::from_str(&caller_address.to_string()).unwrap(),
        Value::from_str("1000000u64").unwrap(),
    ];
    let static_tx = vm
        .execute(
            &caller_private_key,
            ("sw_transfer_private.aleo", "transfer_private"),
            static_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Execute dynamic wrapper with dynamic record.
    let dynamic_tx = vm
        .execute(
            &caller_private_key,
            ("dw_transfer_private.aleo", "transfer_private"),
            vec![
                Value::<CurrentNetwork>::DynamicRecord(dynamic_record_1),
                Value::from_str(&caller_address.to_string()).unwrap(),
                Value::from_str("1000000u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Assert execution costs.
    let (static_exec_costs, dynamic_exec_costs) = get_execution_costs(&vm, &static_tx, &dynamic_tx, consensus_version);
    assert_eq!(static_exec_costs, (3_236, 3_236, 0), "Static execution costs (total, storage, finalize)");
    assert_eq!(dynamic_exec_costs, (4_108, 4_108, 0), "Dynamic execution costs (total, storage, finalize)");

    // Verify static transaction only (dynamic outputs dynamic.record).
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&static_inputs]), &[static_tx], rng);
}

#[test]
fn test_compare_transfer_private_to_public() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let transfer_private_to_public_field = identifier_to_field("transfer_private_to_public");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_transfer_private_to_public.aleo;

        function transfer_private_to_public:
            input r0 as credits.aleo/credits.record;
            input r1 as address.public;
            input r2 as u64.public;
            call credits.aleo/transfer_private_to_public r0 r1 r2 into r3 r4;
            async transfer_private_to_public r4 into r5;
            output r3 as credits.aleo/credits.record;
            output r5 as sw_transfer_private_to_public.aleo/transfer_private_to_public.future;

        finalize transfer_private_to_public:
            input r0 as credits.aleo/transfer_private_to_public.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_transfer_private_to_public.aleo;

        function transfer_private_to_public:
            input r0 as dynamic.record;
            input r1 as address.public;
            input r2 as u64.public;
            call.dynamic {credits_field} {aleo_field} {transfer_private_to_public_field}
                with r0 r1 r2 (as dynamic.record address.public u64.public)
                into r3 r4 (as dynamic.record dynamic.future);
            async transfer_private_to_public r4 into r5;
            output r3 as dynamic.record;
            output r5 as dw_transfer_private_to_public.aleo/transfer_private_to_public.future;

        finalize transfer_private_to_public:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_310_011, 1_225_000, 83_011),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_253_765, 1_203_000, 48_765),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) =
        get_vk_sizes(&static_deployment, &dynamic_deployment, "transfer_private_to_public");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Mint records for execution.
    let (_, record_1) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);
    let (_, record_2) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);

    // Convert to dynamic records for dynamic wrapper.
    let dynamic_record_2 = DynamicRecord::<CurrentNetwork>::from_record(&record_2).unwrap();

    // Execute static wrapper with static record.
    let static_inputs = vec![
        Value::Record(record_1),
        Value::from_str(&caller_address.to_string()).unwrap(),
        Value::from_str("1000000u64").unwrap(),
    ];
    let static_tx = vm
        .execute(
            &caller_private_key,
            ("sw_transfer_private_to_public.aleo", "transfer_private_to_public"),
            static_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Execute dynamic wrapper with dynamic record.
    let dynamic_inputs = vec![
        Value::<CurrentNetwork>::DynamicRecord(dynamic_record_2),
        Value::from_str(&caller_address.to_string()).unwrap(),
        Value::from_str("1000000u64").unwrap(),
    ];
    let dynamic_tx = vm
        .execute(
            &caller_private_key,
            ("dw_transfer_private_to_public.aleo", "transfer_private_to_public"),
            dynamic_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Assert execution costs.
    let (static_exec_costs, dynamic_exec_costs) = get_execution_costs(&vm, &static_tx, &dynamic_tx, consensus_version);
    assert_eq!(static_exec_costs, (3_900, 3_228, 672), "Static execution costs (total, storage, finalize)");
    assert_eq!(dynamic_exec_costs, (4_632, 3_960, 672), "Dynamic execution costs (total, storage, finalize)");

    // Verify static transaction.
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&static_inputs]), &[static_tx], rng);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&dynamic_inputs]), &[dynamic_tx], rng);
}

#[test]
fn test_compare_join() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let join_field = identifier_to_field("join");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_join.aleo;

        function join:
            input r0 as credits.aleo/credits.record;
            input r1 as credits.aleo/credits.record;
            call credits.aleo/join r0 r1 into r2;
            output r2 as credits.aleo/credits.record;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_join.aleo;

        function join:
            input r0 as dynamic.record;
            input r1 as dynamic.record;
            call.dynamic {credits_field} {aleo_field} {join_field}
                with r0 r1 (as dynamic.record dynamic.record)
                into r2 (as dynamic.record);
            output r2 as dynamic.record;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (1_001_062_645, 968_000, 92_645),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (1_001_022_361, 981_000, 39_361),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) = get_vk_sizes(&static_deployment, &dynamic_deployment, "join");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Mint records for execution.
    let (_, record_1) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);
    let (_, record_2) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);
    let (_, record_3) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);
    let (_, record_4) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);

    // Convert to dynamic records for dynamic wrapper.
    let dynamic_record_3 = DynamicRecord::<CurrentNetwork>::from_record(&record_3).unwrap();
    let dynamic_record_4 = DynamicRecord::<CurrentNetwork>::from_record(&record_4).unwrap();

    // Execute static wrapper with static records.
    let static_inputs = vec![Value::Record(record_1), Value::Record(record_2)];
    let static_tx =
        vm.execute(&caller_private_key, ("sw_join.aleo", "join"), static_inputs.iter(), None, 0, None, rng).unwrap();

    // Execute dynamic wrapper with dynamic records.
    let dynamic_tx = vm
        .execute(
            &caller_private_key,
            ("dw_join.aleo", "join"),
            vec![
                Value::<CurrentNetwork>::DynamicRecord(dynamic_record_3),
                Value::<CurrentNetwork>::DynamicRecord(dynamic_record_4),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Assert execution costs.
    let (static_exec_costs, dynamic_exec_costs) = get_execution_costs(&vm, &static_tx, &dynamic_tx, consensus_version);
    assert_eq!(static_exec_costs, (2_856, 2_856, 0), "Static execution costs (total, storage, finalize)");
    assert_eq!(dynamic_exec_costs, (3_728, 3_728, 0), "Dynamic execution costs (total, storage, finalize)");

    // Verify static transaction only.
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&static_inputs]), &[static_tx], rng);
}

#[test]
fn test_compare_split() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let split_field = identifier_to_field("split");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_split.aleo;

        function split:
            input r0 as credits.aleo/credits.record;
            input r1 as u64.private;
            call credits.aleo/split r0 r1 into r2 r3;
            output r2 as credits.aleo/credits.record;
            output r3 as credits.aleo/credits.record;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_split.aleo;

        function split:
            input r0 as dynamic.record;
            input r1 as u64.private;
            call.dynamic {credits_field} {aleo_field} {split_field}
                with r0 r1 (as dynamic.record u64.private)
                into r2 r3 (as dynamic.record dynamic.record);
            output r2 as dynamic.record;
            output r3 as dynamic.record;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (101_080_264, 980_000, 98_264),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (101_041_751, 995_000, 44_751),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) = get_vk_sizes(&static_deployment, &dynamic_deployment, "split");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Mint records for execution.
    let (_, record_1) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);
    let (_, record_2) = mint_record(&vm, &caller_private_key, &caller_address, 10_000_000, rng);

    // Convert to dynamic records for dynamic wrapper.
    let dynamic_record_2 = DynamicRecord::<CurrentNetwork>::from_record(&record_2).unwrap();

    // Execute static wrapper with static record.
    // Split needs: amount + 10_000 microcredits fee (record has 10_000_000)
    let static_inputs = vec![Value::Record(record_1), Value::from_str("1000000u64").unwrap()];
    let static_tx =
        vm.execute(&caller_private_key, ("sw_split.aleo", "split"), static_inputs.iter(), None, 0, None, rng).unwrap();

    // Execute dynamic wrapper with dynamic record.
    let dynamic_tx = vm
        .execute(
            &caller_private_key,
            ("dw_split.aleo", "split"),
            vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_record_2), Value::from_str("1000000u64").unwrap()]
                .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Assert execution costs.
    let (static_exec_costs, dynamic_exec_costs) = get_execution_costs(&vm, &static_tx, &dynamic_tx, consensus_version);
    assert_eq!(static_exec_costs, (3_003, 3_003, 0), "Static execution costs (total, storage, finalize)");
    assert_eq!(dynamic_exec_costs, (3_875, 3_875, 0), "Dynamic execution costs (total, storage, finalize)");

    // Verify static transaction only.
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&static_inputs]), &[static_tx], rng);
}

// Note: `credits.aleo/upgrade` is a restricted function that cannot be called
// externally, so we cannot create wrapper programs for it.

// =============================================================================
// Staking Functions
// =============================================================================

#[test]
fn test_compare_bond_validator() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let bond_validator_field = identifier_to_field("bond_validator");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_bond_validator.aleo;

        function bond_validator:
            input r0 as address.public;
            input r1 as u64.public;
            input r2 as u8.public;
            call credits.aleo/bond_validator r0 r1 r2 into r3;
            async bond_validator r3 into r4;
            output r4 as sw_bond_validator.aleo/bond_validator.future;

        finalize bond_validator:
            input r0 as credits.aleo/bond_validator.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_bond_validator.aleo;

        function bond_validator:
            input r0 as address.public;
            input r1 as u64.public;
            input r2 as u8.public;
            call.dynamic {credits_field} {aleo_field} {bond_validator_field}
                with r0 r1 r2 (as address.public u64.public u8.public)
                into r3 (as dynamic.future);
            async bond_validator r3 into r4;
            output r4 as dw_bond_validator.aleo/bond_validator.future;

        finalize bond_validator:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_112_678, 1_071_000, 39_678),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_157_366, 1_116_000, 39_366),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) = get_vk_sizes(&static_deployment, &dynamic_deployment, "bond_validator");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Note: Execution comparison for bond_validator requires complex validator state setup.
    // The signer needs 10M+ credits and various committee state conditions.
    // For now, we only compare deployment and VK - execution is tested indirectly.
}

#[test]
fn test_compare_bond_public() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let bond_public_field = identifier_to_field("bond_public");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_bond_public.aleo;

        function bond_public:
            input r0 as address.public;
            input r1 as address.public;
            input r2 as u64.public;
            call credits.aleo/bond_public r0 r1 r2 into r3;
            async bond_public r3 into r4;
            output r4 as sw_bond_public.aleo/bond_public.future;

        finalize bond_public:
            input r0 as credits.aleo/bond_public.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_bond_public.aleo;

        function bond_public:
            input r0 as address.public;
            input r1 as address.public;
            input r2 as u64.public;
            call.dynamic {credits_field} {aleo_field} {bond_public_field}
                with r0 r1 r2 (as address.public address.public u64.public)
                into r3 (as dynamic.future);
            async bond_public r3 into r4;
            output r4 as dw_bond_public.aleo/bond_public.future;

        finalize bond_public:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_087_356, 1_044_000, 41_356),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_137_125, 1_095_000, 40_125),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) = get_vk_sizes(&static_deployment, &dynamic_deployment, "bond_public");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Note: Execution comparison requires validator in committee, 10K+ credits for delegator.
}

#[test]
fn test_compare_unbond_public() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let unbond_public_field = identifier_to_field("unbond_public");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_unbond_public.aleo;

        function unbond_public:
            input r0 as address.public;
            input r1 as u64.public;
            call credits.aleo/unbond_public r0 r1 into r2;
            async unbond_public r2 into r3;
            output r3 as sw_unbond_public.aleo/unbond_public.future;

        finalize unbond_public:
            input r0 as credits.aleo/unbond_public.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_unbond_public.aleo;

        function unbond_public:
            input r0 as address.public;
            input r1 as u64.public;
            call.dynamic {credits_field} {aleo_field} {unbond_public_field}
                with r0 r1 (as address.public u64.public)
                into r2 (as dynamic.future);
            async unbond_public r2 into r3;
            output r3 as dw_unbond_public.aleo/unbond_public.future;

        finalize unbond_public:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_092_458, 1_054_000, 36_458),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_137_286, 1_098_000, 37_286),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) = get_vk_sizes(&static_deployment, &dynamic_deployment, "unbond_public");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Note: Execution comparison requires bonded state from prior bond_validator or bond_public.
}

#[test]
fn test_compare_claim_unbond_public() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let claim_unbond_public_field = identifier_to_field("claim_unbond_public");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_claim_unbond.aleo;

        function claim_unbond_public:
            input r0 as address.public;
            call credits.aleo/claim_unbond_public r0 into r1;
            async claim_unbond_public r1 into r2;
            output r2 as sw_claim_unbond.aleo/claim_unbond_public.future;

        finalize claim_unbond_public:
            input r0 as credits.aleo/claim_unbond_public.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_claim_unbond.aleo;

        function claim_unbond_public:
            input r0 as address.public;
            call.dynamic {credits_field} {aleo_field} {claim_unbond_public_field}
                with r0 (as address.public)
                into r1 (as dynamic.future);
            async claim_unbond_public r1 into r2;
            output r2 as dw_claim_unbond.aleo/claim_unbond_public.future;

        finalize claim_unbond_public:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_121_531, 1_086_000, 33_531),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_152_422, 1_115_000, 35_422),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) =
        get_vk_sizes(&static_deployment, &dynamic_deployment, "claim_unbond_public");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Note: Execution comparison requires unbonding state and block height advancement.
}

#[test]
fn test_compare_set_validator_state() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Field representations for call.dynamic.
    let credits_field = identifier_to_field("credits");
    let aleo_field = identifier_to_field("aleo");
    let set_validator_state_field = identifier_to_field("set_validator_state");

    // Static wrapper program.
    let static_wrapper = Program::<CurrentNetwork>::from_str(
        r"
        import credits.aleo;
        program sw_set_val_state.aleo;

        function set_validator_state:
            input r0 as boolean.public;
            call credits.aleo/set_validator_state r0 into r1;
            async set_validator_state r1 into r2;
            output r2 as sw_set_val_state.aleo/set_validator_state.future;

        finalize set_validator_state:
            input r0 as credits.aleo/set_validator_state.future;
            await r0;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Dynamic wrapper program.
    let dynamic_wrapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        program dw_set_val_state.aleo;

        function set_validator_state:
            input r0 as boolean.public;
            call.dynamic {credits_field} {aleo_field} {set_validator_state_field}
                with r0 (as boolean.public)
                into r1 (as dynamic.future);
            async set_validator_state r1 into r2;
            output r2 as dw_set_val_state.aleo/set_validator_state.future;

        finalize set_validator_state:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Initialize VM at V14 height.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy static wrapper.
    let static_deploy_tx = vm.deploy(&caller_private_key, &static_wrapper, None, 0, None, rng).unwrap();
    let static_deployment = match &static_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[static_deploy_tx], rng);

    // Deploy dynamic wrapper.
    let dynamic_deploy_tx = vm.deploy(&caller_private_key, &dynamic_wrapper, None, 0, None, rng).unwrap();
    let dynamic_deployment = match &dynamic_deploy_tx {
        Transaction::Deploy(_, _, _, deployment, _) => deployment.clone(),
        _ => panic!("Expected deploy transaction"),
    };
    add_and_test_with_costs(&vm, &caller_private_key, None, &[dynamic_deploy_tx], rng);

    let consensus_version = ConsensusVersion::V14;

    // Assert deployment costs.
    let (static_deploy_costs, dynamic_deploy_costs) =
        get_deployment_costs(&vm, &static_deployment, &dynamic_deployment, consensus_version);
    assert_eq!(
        static_deploy_costs,
        (2_122_580, 1_088_000, 32_580),
        "Static deployment costs (total, storage, synthesis)"
    );
    assert_eq!(
        dynamic_deploy_costs,
        (2_153_413, 1_117_000, 34_413),
        "Dynamic deployment costs (total, storage, synthesis)"
    );

    // Assert verifying key sizes.
    let (static_vk_size, dynamic_vk_size) =
        get_vk_sizes(&static_deployment, &dynamic_deployment, "set_validator_state");
    assert_eq!(static_vk_size, 673, "Static VK size");
    assert_eq!(dynamic_vk_size, 673, "Dynamic VK size");

    // Note: Execution comparison requires caller to be in committee.
}
