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

use console::{
    network::ConsensusVersion,
    program::Value,
    types::{Boolean, U8},
};
use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::TestRng;

use std::sync::OnceLock;

// This test verifies that:
// - programs using syntax introduced in `V11` cannot be deployed before `V11`.
// - programs using syntax introduced in `V11` can be deployed at and after `V11`.
// - a program with an array larger than 512 cannot be deployed after `V11`.
#[test]
#[ignore]
fn test_deployments_for_v11_features() {
    // Define the programs.
    let programs = vec![
        // A program with an array larger than 32 elements.
        r"
program uses_large_arrays.aleo;

mapping data:
    key as [u8; 33u32].public;
    value as u32.public;

function dummy:

constructor:
    assert.eq true true;
",
        // A program that uses the `serialize` opcode.
        r"
program uses_serialize.aleo;

function dummy:
    input r0 as u32.public;
    serialize.bits.raw r0 (u32) into r1 ([boolean; 32u32]);

constructor:
    assert.eq true true;
",
    ];

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at one less than the V11 height.
    let v11_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V11).unwrap();
    let num_programs = u32::try_from(programs.len()).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v11_height - num_programs, rng);

    // Deploy each program and ensure it fails.
    for program in &programs {
        let program = Program::from_str(program).unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 0);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 1);
        vm.add_next_block(&block).unwrap();
    }

    // Verify that we are at the expected height.
    assert_eq!(vm.block_store().current_block_height(), v11_height);

    // Deploy each program and ensure it succeeds.
    for program in &programs {
        let program = Program::from_str(program).unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    }
}

// This test verifies that a concrete set of test vectors for `ecdsa.verify.keccak256.eth` and `ecdsa.verify.digest.eth`.
#[test]
#[ignore]
fn test_ecdsa_keccak256_eth() {
    // Define the message test vectors.
    // Each test vector is a tuple of (message, message_hash).
    let message_test_vectors = [
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000002cef07dc0500002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b15015c28b2e444c5f1cdcac4e2a12b04cdf9ef9f9b8248a66443c5fbb63ab3f4000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb484257581b0ea13ec570ec66b02cb74cc865e11907560b9c2d3c91d95336dc185000000000000000000000000000000000000000000000000000000001cc1f08cd8ae75ea76f95afc8f4c22e31556d8ecae3d7092602dd2db717bd38a7c1e96d1b00000000",
            "0x64ce9fcee9bad13cbf5c68ca97a7f37a3373147a9ec1f3f1925527ffaf08dcb8",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000006bfdf48ab000002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b844c9b29f42aaf85ba19d18db0c5b48f4866078febfab67df63826fb568b6d01000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48be3b80b076f6020b61d7dbaa815b3cdc3b6d4f73b11a9650d79ba7b8b780e5a800000000000000000000000000000000000000000000000000000009b822cf0a36c23e83eb1cd52226ed037d4845534efa4710ce22187c5b6e29bbd4029717ce00000000",
            "0xba76c1acdf04e8ed5d63bcf096b060a4937cc8a714eee5bc2592f4e363eae14d",
        ),
        (
            "0x2bcc5ce700000001000000000000000000000000000000000000000000000000000000ab8b6e7d5400002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b115a56e9eb7088e68b399af81648edd3d7159c9fcb9f240a28aa32e342099758000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb485efac8c79e6740dcbb8e2a6bdc24f90841246923719534b10c45f84abf8e8d650000000000000000000000000000000000000000000000000000000a4aed078516e722f8c5f3964880628c3e52e551c59e281795c9baf4e7443b81205c6005e700000000",
            "0x290fff40607db16db1a0630d13896714c0a727ab740f498ae8394eb274720d52",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000001f1141881f00002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b4791febae93585fce4c0e763bdbfd43badf007d4876b2cb7f22880795d7b3969000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48da69b16070099fc984603e84b0c23c0daa8bdd1ba369cd0f7bb45e11cac99ba0000000000000000000000000000000000000000000000000000000031b535a69ef7b1fabfa3d6967878050b9898da8c7fc8f5c9fe512792d5d36efd652894ee800000000",
            "0x20b1b07bd4b9f30332792a3ea8f67764e83fdff3a508755e48e91b14e74c2ceb",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000008262f562e500002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b08473e6d72dd772b954f23275e353183facb02b06b0bb8e24a051c56fc92a96b000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c3cec7625ebee84c84759c0b309bdfb98a98ad9c3c8f8cbc7759962776b4b070000000000000000000000000000000000000000000000000000000092086efe102e4aa25865c8185b2d592c38bd3d8ef69ae5fac49b386ead387aa174ffd182000000000",
            "0xc3d49a959502d428d937f3365dc9126937696845aff3efb29d1b7dd604f2710a",
        ),
    ];

    // Define the valid test vectors.
    // Each test vector is a tuple of (message, signature, address).
    let valid_test_vectors = [
        (
            "0x2bcc5ce70000000100000000000000000000000000000000000000000000000000000000000f424000002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b000000000000000000000000742d35cc6e4c6e42e2a6e1b6d6e19d3bb14d3d1a000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000c350bfab0940d5a2410c007e06c8b1bb24e34391ddc5298e18840df438e8e05b9ac800000000",
            "0xab5373ec68978e102a9084d6d07aa1e328174d12337e0a028ec3b0c63abdb89e7a906d9de841006143de25cab83b380618972c4803bf978c5b02d4e863465b8a00",
            "0x1be31a94361a391bbafb2a4ccd704f57dc04d4bb",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000002cef07dc0500002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b15015c28b2e444c5f1cdcac4e2a12b04cdf9ef9f9b8248a66443c5fbb63ab3f4000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb484257581b0ea13ec570ec66b02cb74cc865e11907560b9c2d3c91d95336dc185000000000000000000000000000000000000000000000000000000001cc1f08cd8ae75ea76f95afc8f4c22e31556d8ecae3d7092602dd2db717bd38a7c1e96d1b00000000",
            "0x9d2aada38011b3543e73ac301eaa6a51b0a7bc9fa5df0dcd297b91602d7c425d5196639368a4dae405b46c3aa015c7551ae7af01bc7570069dde7d4035e54d1d00",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000006bfdf48ab000002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b844c9b29f42aaf85ba19d18db0c5b48f4866078febfab67df63826fb568b6d01000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48be3b80b076f6020b61d7dbaa815b3cdc3b6d4f73b11a9650d79ba7b8b780e5a800000000000000000000000000000000000000000000000000000009b822cf0a36c23e83eb1cd52226ed037d4845534efa4710ce22187c5b6e29bbd4029717ce00000000",
            "0xc573ff15d2febbbab9842fc55fc887f6353aef1caf28b8f77bb071c9a4f005685d4603939860d7ee00a3c3ec87daf1081e0c908e208391fbf3ed061f61a5dccf00",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce700000001000000000000000000000000000000000000000000000000000000ab8b6e7d5400002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b115a56e9eb7088e68b399af81648edd3d7159c9fcb9f240a28aa32e342099758000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb485efac8c79e6740dcbb8e2a6bdc24f90841246923719534b10c45f84abf8e8d650000000000000000000000000000000000000000000000000000000a4aed078516e722f8c5f3964880628c3e52e551c59e281795c9baf4e7443b81205c6005e700000000",
            "0x6fdc181e445ececf005310bdca2aa9e8a3b79a2f2a89ea898dd46cbb129ec59f5e051b496e3ce942f8cdb973bb9c5adc3247438022c8b0f1b593bd5f09bb90ea00",
            "0x72e1d63eb41fa94c6daf60670e6ddbdb3d41e1a6",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000001f1141881f00002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b4791febae93585fce4c0e763bdbfd43badf007d4876b2cb7f22880795d7b3969000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48da69b16070099fc984603e84b0c23c0daa8bdd1ba369cd0f7bb45e11cac99ba0000000000000000000000000000000000000000000000000000000031b535a69ef7b1fabfa3d6967878050b9898da8c7fc8f5c9fe512792d5d36efd652894ee800000000",
            "0x8fa4811e12534a6feb1c81272aa3e2b1c7fa77b179ff52ccc8982efaf8546742431d6bf26ca99ee6b3a82e6eb74b972ca4adda9b11a084fee754329999ffc67600",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000008262f562e500002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b08473e6d72dd772b954f23275e353183facb02b06b0bb8e24a051c56fc92a96b000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c3cec7625ebee84c84759c0b309bdfb98a98ad9c3c8f8cbc7759962776b4b070000000000000000000000000000000000000000000000000000000092086efe102e4aa25865c8185b2d592c38bd3d8ef69ae5fac49b386ead387aa174ffd182000000000",
            "0xc516d75d1dc1b564e0e53413dbe516eec202666473a17fe5dae9201e485896e0012d25e41a15661a9ae5127b71c4d3b6b06fd7e0c820e43805c45dbb691ec3f800",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
    ];

    // Define the invalid test vectors.
    // Each test vector is a tuple of (message, signature, address).
    let invalid_test_vectors = [
        (
            "0x2bcc5ce700000002000000000000000000000000000000000000000000000000000000790eb83f2d00002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8bf46f0cf141dc031b75decad8ad5cba53dcfee3d830cf8c927262b96b4da0d950000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4882df8456dec8ccb6cb5a8a777dcc68be72402305886ec7d66d236935c6068a200000000000000000000000000000000000000000000000000000000ae52a2ea5ead05a873fca3a4d472036c40e7281639cea430e4b8f5805b28e851c1304eca000000000",
            "0x394cedb62ec18360797c4fa46cde4ccc7838e50b9039586def69ebe2499ffcf30da0aea134b1fb20f57a6e50db3892dfef487abfbee56bc92d07852f2e99cc3300",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000006739b4d64900002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b977dc6c0308bc3b854d6c4931016616a734f1c70ebcbd55028a91e8e09ce4ab4000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb489eaede20b6f5f406a5a66c60778d7bb5a75057e0bf4fad41b06522cf20d77abb00000000000000000000000000000000000000000000000000000006318ad9a82596e0b175512a80b7d3e984d5262df1b473116432e15f3d4410490aa826591b0000001b81d514a2243f833d073c8fc195c005f9c9beeaf94b3efd6eba973d",
            "0xd18bdcf1c33c16a3e6d21ca66f7f5a238d6eb7e4750cfff36f34788db317285c00194c711d4f33812ecb72a5bc13c24c33e48b6e7c57690408eae13e5c81975100",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce700000001000000000000000000000000000000000000000000000000000000907a516e1300002718000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b388c60054481f5c8c4688931d44feda728c7928273f992e88054d2ee532d2ecf000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c26da16131b551fa8ea66b5953c41a687f018ca6ee28917aac1afe54506fdfdb0000000000000000000000000000000000000000000000000000000b8ee7cb5dbf5661be5b50377dcbb3fac0b4c7e0f6dc8fc190a734595cad1c4c466751644300000005e31780870c",
            "0xad605014dc973727fb4d15027a071d883550172a7f10b1ee637460a836190b5f46f32c2fc8b5f41d6d5c42a3ad6d6a1a1c854c5257fb74f878b2e624af03566b00",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce7000000010000000000000000000000000000000000000000000000000000003782f23f5c00002713000000000000000000000000a0b86a33e6f8ec61cc62f1b1cb2ad6dfe3c10e8bb7f507dd1d067a0d7ab39749c5d7fb83e8e12f640bbc6ff7cddab85232c407d6000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48502eca2c2bb19c32f940659f3f8ff8aa07473d5faaec8b499337449354c343580000000000000000000000000000000000000000000000000000000470e02e07ae6465004d4baaa9577a724e6b3996bce4788bc9f218ddf34818e23fd8a926eb0000003bc83346f0572e5ce723e43933ea7d1d344c011032e9a18e78438628af041f3e5ef747d694dca01bfd3e188e52150c85103bb8d22ad1a646ee62944f",
            "0x410abc6b68308d891a517813043adc80150e956212cb9a176db2e1194e133e330e89421cecce573d2aa15a90557f48b0248f055f6c1c457ce43afa8ebf0ddb5a00",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce700000001000000000000000000000000000000000000000000000000000000cfaebe513e00002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b7dacdaf901db311cbc5ef31f5817d6e635b0ae3dc819c7ee362cc245f17637c2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48ccb9806e28b5db6d37381f62808a5ffc40d7991a214eb87a164a18b25a0e11a300000000000000000000000000000000000000000000000000000012b101c4c07b4da36afa97ad32d0e07899a6d62989a915c1dd88bf9b17b27c8fe210017f6500000000",
            "0xddcf4943f37197ed5d6751673749dd4bd1e7423499ab94af5a3db420704238080248964ab48cfbff919ffec1901e04c53392c545e23718813cdb3b333af0619400",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
        (
            "0x2bcc5ce700000002000000000000000000000000000000000000000000000000000000185a02deda00002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b5c784a7a46c095470beacb2c58b050cf21b2bdde1e9a09f3cef5908f42804bda000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48b43be7eea0d1773b13a48664fb8bf85c77355901dda559e8e7d3a249ac08a0db0000000000000000000000000000000000000000000000000000000137b357f1d9481aced1f4df45daa76c4723686ae10e56a3f760ccab8b15b0fbf630a31b700000003e1216503decb06e9e9911963cec0ca1dfce9d358b53f970dc8382c1f01a07259c3b7678287e9996325558eb11dfcf64d4835cec2b3bfc9e3d5a122683bb3b",
            "0xd4d384470339372c22ec5b69666679215d0f7ceca293091dae6d8d9d3a4dd1bd617992b95336ecca97c899aef31389955d9c02722dc46de433702f567b7885a500",
            "0x589d3e40069df16c429522acab02c9dafd955833",
        ),
    ];

    // A helper function to pase a hex string into a `Plaintext`.
    let parse_hex_to_plaintext = |hex_str: &str| -> Plaintext<CurrentNetwork> {
        let bytes = hex::decode(hex_str.trim_start_matches("0x")).unwrap();
        Plaintext::Array(
            bytes.into_iter().map(|byte| Plaintext::from(Literal::U8(U8::new(byte)))).collect(),
            OnceLock::new(),
        )
    };

    // Define the verification program.
    let program = Program::from_str(
        r"
program test_ecdsa_keccak256_eth.aleo;

function verify_message:
    input r0 as [u8; 65u32].private;
    input r1 as [u8; 20u32].private;
    input r2 as [u8; 240u32].private;
    input r3 as boolean.private;
    async verify_message r0 r1 r2 r3 into r4;
    output r4 as test_ecdsa_keccak256_eth.aleo/verify_message.future;
finalize verify_message:
    input r0 as [u8; 65u32].public;
    input r1 as [u8; 20u32].public;
    input r2 as [u8; 240u32].public;
    input r3 as boolean.public;
    ecdsa.verify.keccak256.eth r0 r1 r2 into r4;
    hash.keccak256.native.raw r2 into r5 as [boolean; 256u32];
    deserialize.bits.raw r5 ([boolean; 256u32]) into r6 ([u8; 32u32]);
    ecdsa.verify.digest.eth r0 r1 r6 into r7;
    assert.eq r3 r4;
    assert.eq r3 r7;

function check_message_and_hash:
    input r0 as [u8; 240u32].private;
    input r1 as [u8; 32u32].private;
    hash.keccak256.native.raw r0 into r2 as [boolean; 256u32];
    deserialize.bits.raw r2 ([boolean; 256u32]) into r3 ([u8; 32u32]);
    assert.eq r1 r3;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V11 height.
    let v11_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V11).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v11_height, rng);

    // Deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Parse the invalid address.
    let inval_address = "0x589d3e40069df16c429522acab02c9dafd955834";
    let inval_address_plaintext = parse_hex_to_plaintext(inval_address);

    // For each message test vector, check that the message hashes to the expected hash.
    for (i, (message, hash)) in message_test_vectors.iter().enumerate() {
        println!("Testing message vector {}/{}", i + 1, message_test_vectors.len());

        // Parse the inputs.
        let message_plaintext = parse_hex_to_plaintext(message);
        let hash_plaintext = parse_hex_to_plaintext(hash);

        // Execute the `check_message_and_hash` function to ensure the message hashes correctly.
        let execution = vm
            .execute(
                &caller_private_key,
                ("test_ecdsa_keccak256_eth.aleo", "check_message_and_hash"),
                vec![Value::Plaintext(message_plaintext.clone()), Value::Plaintext(hash_plaintext)].into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    }

    // For each valid test vector check that the signature verification behaves as expected.
    for (i, (message, signature, valid_address)) in valid_test_vectors.iter().enumerate() {
        println!("Testing valid vector {}/{}", i + 1, valid_test_vectors.len());

        // Parse the inputs.
        let message_plaintext = parse_hex_to_plaintext(message);
        let signature_plaintext = parse_hex_to_plaintext(signature);
        let valid_address_plaintext = parse_hex_to_plaintext(valid_address);

        // Execute the `verify_message` function to check the signature verification.
        let execution = vm
            .execute(
                &caller_private_key,
                ("test_ecdsa_keccak256_eth.aleo", "verify_message"),
                vec![
                    Value::Plaintext(signature_plaintext.clone()),
                    Value::Plaintext(valid_address_plaintext.clone()),
                    Value::Plaintext(message_plaintext.clone()),
                    Value::Plaintext(Plaintext::from(Literal::Boolean(Boolean::new(true)))),
                ]
                .into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();

        // Execute the `verify_message` function to check the signature verification with an invalid address.
        let execution = vm
            .execute(
                &caller_private_key,
                ("test_ecdsa_keccak256_eth.aleo", "verify_message"),
                vec![
                    Value::Plaintext(signature_plaintext.clone()),
                    Value::Plaintext(inval_address_plaintext.clone()),
                    Value::Plaintext(message_plaintext),
                    Value::Plaintext(Plaintext::from(Literal::Boolean(Boolean::new(true)))),
                ]
                .into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 0);
        assert_eq!(block.transactions().num_rejected(), 1);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    }

    // For all invalid test vectors, check that signature verification fails.
    for (i, (message, signature, address)) in invalid_test_vectors.iter().enumerate() {
        println!("Testing invalid vector {}/{}", i + 1, invalid_test_vectors.len());

        // Parse the inputs.
        let message_plaintext = parse_hex_to_plaintext(message);
        let signature_plaintext = parse_hex_to_plaintext(signature);
        let valid_address_plaintext = parse_hex_to_plaintext(address);

        // Execute the `verify_message` function to check the signature verification.
        let execution = vm
            .execute(
                &caller_private_key,
                ("test_ecdsa_keccas256_eth.aleo", "verify_message"),
                vec![
                    Value::Plaintext(signature_plaintext.clone()),
                    Value::Plaintext(valid_address_plaintext.clone()),
                    Value::Plaintext(message_plaintext.clone()),
                    Value::Plaintext(Plaintext::from(Literal::Boolean(Boolean::new(false)))),
                ]
                .into_iter(),
                None,
                0,
                None,
                rng,
            )
            .and_then(|execution| {
                // Create a block and fail if the number of accepted transactions is zero.
                let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
                if block.transactions().num_accepted() == 0 {
                    Err(anyhow::anyhow!("The transaction was not accepted").into())
                } else {
                    Ok(())
                }
            });
        assert!(execution.is_err(), "The execution should fail");
    }
}
