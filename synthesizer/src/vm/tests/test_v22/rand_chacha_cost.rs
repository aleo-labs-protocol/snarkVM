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

use snarkvm_synthesizer_process::{ConsensusFeeVersion, cost_per_command};

use super::*;

#[test]
fn test_rand_chacha_cost() {
    // The cost of rand.chacha changes at ConsensusVersion::V22:
    //   - Before V22, the command has a flat cost regardless of its seeds or output type.
    //   - From V22 onwards, the cost is the BHP hash cost of the seed plus a fixed cost if the
    //     destination type is group or address.

    // The flat cost applied before ConsensusVersion::V22.
    const LEGACY_COST: u64 = 25_000;
    // The surcharge for sampling a `group`/`address` output from V22 onwards.
    const GROUP_OUTPUT_SURCHARGE: u64 = 115_000;

    // These two values mirror their counterparts in cost.rs within synthesizer/process.
    const HASH_BHP_BASE_COST: u64 = 50_000;
    const HASH_BHP_PER_BYTE_COST: u64 = 300;

    // Two finalize blocks, each with a single `rand.chacha` command seeded by one `u64` operand:
    // one produces a `u64`, the other a `group`.
    let program = Program::<MainnetV0>::from_str(
        r"
program rand_chacha_cost.aleo;

mapping u64_data:
key as u64.public;
value as u64.public;

mapping group_data:
key as u64.public;
value as group.public;

function sample_u64:
input r0 as u64.public;
async sample_u64 r0 into r1;
output r1 as rand_chacha_cost.aleo/sample_u64.future;

finalize sample_u64:
input r0 as u64.public;
rand.chacha r0 into r1 as u64;
set r1 into u64_data[r0];

function sample_group:
input r0 as u64.public;
async sample_group r0 into r1;
output r1 as rand_chacha_cost.aleo/sample_group.future;

finalize sample_group:
input r0 as u64.public;
rand.chacha r0 into r1 as group;
set r1 into group_data[r0];
",
    )
    .unwrap();

    let process = Process::<CurrentNetwork>::load().unwrap();
    process.lock().add_program(&program).unwrap();
    let stack = process.get_stack(program.id()).unwrap();

    // Returns the cost of the single `rand.chacha` command in the given finalize block.
    let rand_chacha_cost = |function_name: &str, consensus_version: Option<ConsensusVersion>| -> u64 {
        let function_name = Identifier::from_str(function_name).unwrap();
        let finalize = stack.get_function_ref(&function_name).unwrap().finalize_logic().unwrap();
        let finalize_types = stack.get_finalize_types(finalize.name()).unwrap();
        let command = finalize
            .commands()
            .iter()
            .find(|command| matches!(command, Command::RandChaCha(_)))
            .expect("finalize should contain a rand.chacha command");
        // The fee version does not affect the `rand.chacha` cost, so any value is valid here.
        cost_per_command(&stack, &finalize_types, command, ConsensusFeeVersion::V3, consensus_version).unwrap()
    };

    // The V22 seed hashing cost: one `u64` seed operand (8 bytes) plus the three appended field
    // elements (32 bytes each).
    let expected_seed_cost = HASH_BHP_BASE_COST + HASH_BHP_PER_BYTE_COST * (8 + 3 * 32);
    assert_eq!(expected_seed_cost, 81_200, "seed cost derivation changed");

    // Before V22 (including when no consensus version is provided), the cost is the flat legacy
    // value regardless of the output type.
    assert_eq!(rand_chacha_cost("sample_u64", None), LEGACY_COST);
    assert_eq!(rand_chacha_cost("sample_group", None), LEGACY_COST);
    assert_eq!(rand_chacha_cost("sample_u64", Some(ConsensusVersion::V21)), LEGACY_COST);
    assert_eq!(rand_chacha_cost("sample_group", Some(ConsensusVersion::V21)), LEGACY_COST);

    // From V22 onwards, the cost is the seed hashing cost, plus the surcharge for a group output.
    assert_eq!(rand_chacha_cost("sample_u64", Some(ConsensusVersion::V22)), expected_seed_cost);
    assert_eq!(
        rand_chacha_cost("sample_group", Some(ConsensusVersion::V22)),
        expected_seed_cost + GROUP_OUTPUT_SURCHARGE
    );

    // The same behavior must hold at the latest consensus version. Change this if a future
    // consensus version alters the `rand.chacha` cost.
    let latest = ConsensusVersion::latest();
    assert_eq!(rand_chacha_cost("sample_u64", Some(latest)), expected_seed_cost);
    assert_eq!(rand_chacha_cost("sample_group", Some(latest)), expected_seed_cost + GROUP_OUTPUT_SURCHARGE);
}
