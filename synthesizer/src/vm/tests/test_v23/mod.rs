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

// Tests on static calls to functions with constant outputs.
mod static_call_constant_output;

use super::*;

#[test]
fn test_record_cast_in_mixed_version_calls() -> Result<()> {
    let rng = &mut TestRng::default();
    let owner = sample_genesis_private_key();
    let activation = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23)?;
    let vm = sample_vm_at_height(activation - 1, rng);
    let library = Program::from_str(
        "program cast_library.aleo;
         record token:
             owner as address.private;
             amount as u64.private;
         closure digest:
             input r0 as address;
             input r1 as u64;
             cast r0 r1 into r2 as token.record;
             hash.psd2 r2 into r3 as field;
             output r3 as field;
         function legacy_digest:
             input r0 as u64.private;
             call digest self.signer r0 into r1;
             output r1 as field.public;
         constructor:
             assert.eq true true;",
    )?;
    let caller = Program::from_str(
        "import cast_library.aleo;
         program cast_caller.aleo;
         function run:
             input r0 as u64.private;
             call cast_library.aleo/digest self.signer r0 into r1;
             call cast_library.aleo/legacy_digest r0 into r2;
             add r1 r2 into r3;
             output r3 as field.public;
         constructor:
             assert.eq true true;",
    )?;
    for (program, version) in [(&library, ConsensusVersion::V22), (&caller, ConsensusVersion::V23)] {
        let tx = vm.deploy(&owner, program, None, 0, None, rng)?;
        let block = sample_next_block(&vm, &owner, &[tx], rng)?;
        assert_eq!(block.transactions().num_accepted(), 1);
        vm.add_next_block(&block)?;
        assert_eq!(vm.process().get_stack(program.id())?.circuit_version(), version);
    }

    let reloaded = VM::from(vm.store.clone())?;
    let inputs = [Value::<CurrentNetwork>::from_str("5u64")?];
    let tx = reloaded.execute(&owner, (*caller.id(), "run"), inputs.iter(), None, 0, None, rng)?;
    let execution = tx.execution().context("Expected an execution transaction")?;
    assert!(execution.transitions().map(|transition| transition.program_id()).eq([library.id(), caller.id()]));
    vm.check_transaction(&tx, None, rng)?;
    Ok(())
}

#[test]
fn test_record_cast_keys_across_activation_and_restart() -> Result<()> {
    let rng = &mut TestRng::default();
    let activation = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23)?;
    let vm = sample_vm_at_height(activation - 1, rng);
    let owner = sample_genesis_private_key();
    let mut deployments = Vec::new();
    for (name, expected_height) in [("before", activation), ("after", activation + 1)] {
        let program = Program::from_str(&format!(
            "program {name}.aleo;
             record token:
                 owner as address.private;
                 amount as u64.private;
             function mint:
                 input r0 as u64.private;
                 cast self.signer r0 into r1 as token.record;
                 output r1 as token.record;
             constructor:
                 assert.eq true true;"
        ))?;
        let tx = vm.deploy(&owner, &program, None, 0, None, rng)?;
        vm.check_transaction(&tx, None, rng)?;
        let block = sample_next_block(&vm, &owner, &[tx], rng)?;
        assert_eq!(block.height(), expected_height);
        assert_eq!(block.transactions().num_accepted(), 1);
        vm.add_next_block(&block)?;
        deployments.push((program, block.height()));
    }

    let reloaded = VM::from(vm.store.clone())?;
    let offline = sample_vm();
    let query = Query::VM(vm.block_store().clone());
    let inputs = [Value::<CurrentNetwork>::from_str("5u64")?];
    for (program, height) in deployments {
        let program_id = *program.id();
        let tx = reloaded.execute(&owner, (program_id, "mint"), inputs.iter(), None, 0, None, rng)?;
        vm.check_transaction(&tx, None, rng)?;

        let version = CurrentNetwork::deployment_circuit_version(height)?;
        offline.process().lock().add_programs_with_editions(&[(program, 0)], |_| Ok(version))?;
        let tx = offline.execute(&owner, (program_id, "mint"), inputs.iter(), None, 0, Some(&query), rng)?;
        vm.check_transaction(&tx, None, rng)?;
    }
    Ok(())
}

const RECORD_CAST_PROGRAM: &str = "program cast_keys.aleo;
    record token:
        owner as address.private;
        amount as u64.private;
    function mint:
        input r0 as u64.private;
        cast self.signer r0 into r1 as token.record;
        output r1 as token.record;
    constructor:
        assert.eq true true;";

#[test]
fn test_record_cast_amendment_keys_after_restart() -> Result<()> {
    use snarkvm_synthesizer_program::StackTrait;

    let rng = &mut TestRng::default();
    let activation = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23)?;
    let vm = sample_vm_at_height(activation - 1, rng);
    let owner = sample_genesis_private_key();
    let program = Program::from_str(RECORD_CAST_PROGRAM)?;
    let mint = Identifier::from_str("mint")?;

    let deployment = vm.deploy(&owner, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &owner, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;
    let legacy_key = vm.process().get_stack(program.id())?.get_verifying_key(&mint)?;

    let mut amendment = vm.deploy_raw(ConsensusVersion::V23, &program, rng)?;
    amendment.set_edition_raw(0);
    amendment.set_program_owner_raw(None);
    amendment.set_program_checksum_raw(Some(program.to_checksum()));
    let [(name, (amended_key, _))] = amendment.function_verifying_keys() else { bail!("Expected one function key") };
    assert_eq!(*name, mint);
    let amended_key = amended_key.clone();
    assert_ne!(legacy_key, amended_key);

    let id = amendment.to_deployment_id()?;
    let signature = ProgramOwner::new(&owner, id, rng)?;
    let (cost, _) = deployment_cost(vm.process(), &amendment, ConsensusVersion::V23)?;
    let authorization = vm.authorize_fee_public(&owner, cost, 0, id, rng)?;
    let fee = vm.execute_fee_authorization(authorization, None, rng)?;
    let transaction = Transaction::from_deployment(signature, amendment, fee)?;
    let block = sample_next_block(&vm, &owner, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    let reloaded = VM::from(vm.store.clone())?;
    for node in [&vm, &reloaded] {
        let stack = node.process().get_stack(program.id())?;
        assert_eq!(*stack.program_edition(), 0);
        assert_eq!(stack.program_amendment_count(), 1);
        assert_eq!(stack.circuit_version(), ConsensusVersion::V23);
        assert_eq!(stack.get_verifying_key(&mint)?, amended_key);
    }
    let inputs = [Value::<CurrentNetwork>::from_str("5u64")?];
    let execution = reloaded.execute(&owner, (*program.id(), mint), inputs.iter(), None, 0, None, rng)?;
    vm.check_transaction(&execution, None, rng)?;
    Ok(())
}

#[test]
fn test_record_cast_cached_deployment_at_activation() -> Result<()> {
    let rng = &mut TestRng::default();
    let activation = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23)?;
    let vm = sample_vm_at_height(activation - 1, rng);
    let owner = sample_genesis_private_key();
    let program = Program::from_str(RECORD_CAST_PROGRAM)?;
    let deployment = vm.deploy(&owner, &program, None, 0, None, rng)?;
    vm.check_transaction(&deployment, None, rng)?;
    assert!(vm.partially_verified_transactions().read().iter().any(|((id, _), _)| *id == deployment.id()));

    let block = sample_next_block(&vm, &owner, &[], rng)?;
    assert_eq!(block.height(), activation);
    vm.add_next_block(&block)?;
    let error = vm.check_transaction(&deployment, None, rng).expect_err("V23 must recheck the legacy certificate");
    assert!(error.to_string().contains("The certificate for function 'mint' is invalid"), "{error}");
    Ok(())
}
