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
#[ignore = "slow"]
fn test_record_cast_keys_across_activation_and_restart() -> Result<()> {
    use console::program::Identifier;
    use snarkvm_synthesizer_program::StackTrait;

    let rng = &mut TestRng::default();
    let activation = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23)?;
    let vm = sample_vm_at_height(activation - 1, rng);
    let owner = sample_genesis_private_key();
    let function = Identifier::from_str("mint")?;
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
    }

    let reloaded = VM::from(vm.store.clone())?;
    for process in [vm.process(), reloaded.process()] {
        for program_id in ["before.aleo", "after.aleo"] {
            let stack = process.get_stack(program_id)?;
            let certified = stack.get_verifying_key(&function)?;
            stack.synthesize_key::<CurrentAleo, _>(&function, rng)?;
            assert_eq!(stack.get_verifying_key(&function)?, certified);
        }
    }
    Ok(())
}
