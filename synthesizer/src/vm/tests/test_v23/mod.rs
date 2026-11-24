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
