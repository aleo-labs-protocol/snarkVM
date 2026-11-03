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

// These tests check `execution_cost_for_call` returns the correct result in
// some especially crafted scenarios. The cost-estimation function is already
// tested in many tests within test_v14 and text_vm_execute_and_finalize.

use super::*;

/// Reads the public credits balance for the given address.
fn get_public_balance(vm: &VM<CurrentNetwork, LedgerType>, address: &str) -> u64 {
    match vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::<CurrentNetwork>::from_str("credits.aleo").unwrap(),
            Identifier::from_str("account").unwrap(),
            &Plaintext::from_str(address).unwrap(),
        )
        .unwrap()
    {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
        _ => 0,
    }
}

// Tests that the function `execution_cost_for_call` returns the correct cost
// even in functions that depend on the signer. This test complements test cases
// in `synthesizer/tests/test_vm_execute_and_finalize.rs` and
// `test_v15/cost_for_call.rs` which also verify cost estimation correctness.
#[test]
fn test_cost_for_call_depending_on_signer() {
    let rng = &mut TestRng::default();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15).unwrap(), rng);

    let genesis_private_key = sample_genesis_private_key(rng);

    let zero_field = Identifier::<CurrentNetwork>::from_str("zero").unwrap().to_field().unwrap();
    let one_field = Identifier::<CurrentNetwork>::from_str("one").unwrap().to_field().unwrap();
    let two_field = Identifier::<CurrentNetwork>::from_str("two").unwrap().to_field().unwrap();
    let three_field = Identifier::<CurrentNetwork>::from_str("three").unwrap().to_field().unwrap();

    // This program has substantially different behaviours (input/output types
    // and visibility, call graph depth, etc.) depending on the residue of the
    // (x coordinate regarded as an integer) of the caller address modulo 4.
    // Furthermore, the finalize scope also depends on the signer in the form of
    // calls to `transfer_public` with an amount that also depends on the same
    // modulo-4 residue.
    let program = Program::<CurrentNetwork>::from_str(&format!(
        r"
        import credits.aleo;

        program test.aleo;

        struct foo:
            f as field;
            u as u128;

        function main:
            cast.lossy self.signer into r0 as u8;
            and r0 3u8 into r1;
            is.eq r1 0u8 into r2;
            is.eq r1 1u8 into r3;
            is.eq r1 2u8 into r4;
            
            ternary r4 {two_field} {three_field} into r5;
            ternary r3 {one_field} r5 into r6;
            ternary r2 {zero_field} r6 into r7;

            call.dynamic 'test' 'aleo' r7 into r8 (as dynamic.future);
            async main r8 into r9;
            
            output r9 as test.aleo/main.future;
        
        finalize main:
            input r0 as dynamic.future;
            await r0;

        function zero:
            call credits.aleo/transfer_public self.signer 0u64 into r0;

            async zero r0 into r1;
            output r1 as test.aleo/zero.future;

        finalize zero:
            input r0 as credits.aleo/transfer_public.future;
            await r0;

        function one:
            call credits.aleo/transfer_public self.signer 1u64 into r0;

            // Dummy call to increase request input/output and graph compleity
            cast 99field 19u128 into r1 as foo;
            call.dynamic 'test' 'aleo' 'call_depth_1' with 10u8 r1 (as u8.public foo.private) into r2 r3 r4 (as u8.public field.public field.public);
            // End of the dummy call

            async one r0 into r5;
            output r5 as test.aleo/one.future;

        finalize one:
            input r0 as credits.aleo/transfer_public.future;
            await r0;

        function two:
            call credits.aleo/transfer_public self.signer 2u64 into r0;

            // Dummy call to increase request input/output and graph compleity
            cast 111111field 222222u128 into r1 as foo;
            call.dynamic 'test' 'aleo' 'call_depth_2'
                with 11u8 22u8 r1 (as u8.public u8.private foo.public)
                into r2 r3 r4 r5 r6 (as u8.public field.private field.public foo.public field.private);
            // End of the dummy call

            async two r0 into r7;
            output r7 as test.aleo/two.future;

        finalize two:
            input r0 as credits.aleo/transfer_public.future;
            await r0;

        function three:
            call credits.aleo/transfer_public self.signer 3u64 into r0;
            async three r0 into r1;
            output r1 as test.aleo/three.future;

        finalize three:
            input r0 as credits.aleo/transfer_public.future;
            await r0;

        // The remaining functions are only meant to make the call graph slightly more complex.
        // Their inputs and call flow have no semantics.

        function call_depth_0:
            input r0 as foo.private;
            assert.eq true true;
            output r0.f as field.public;

        function call_depth_1:
            input r0 as u8.public;
            input r1 as foo.private;

            call.dynamic 'test' 'aleo' 'call_depth_0'
                with r1 (as foo.private)
                into r2 (as field.public);
            call.dynamic 'test' 'aleo' 'call_depth_0'
                with r1 (as foo.private)
                into r3 (as field.public);

            output r0 as u8.public;
            output r2 as field.public;
            output r3 as field.public;

        function call_depth_2:
            input r0 as u8.public;
            input r1 as u8.private;
            input r2 as foo.public;

            call.dynamic 'test' 'aleo' 'call_depth_1'
                with r1 r2 (as u8.public foo.private)
                into r3 r4 r5 (as u8.public field.public field.public);
            call.dynamic 'test' 'aleo' 'call_depth_1'
                with r0 r2 (as u8.public foo.private)
                into r6 r7 r8 (as u8.public field.public field.public);
            call.dynamic 'test' 'aleo' 'call_depth_0'
                with r2 (as foo.private)
                into r9 (as field.public);

            output r3 as u8.public;
            output r4 as field.private;
            output r5 as field.public;
            output r2 as foo.public;
            output r9 as field.private;

        constructor:
            assert.eq true true;
        "
    ))
    .unwrap();

    // Deploy the program.
    let deploy_tx = vm.deploy(&genesis_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &genesis_private_key, None, &[deploy_tx], rng);

    // Fund the program with 10 000 microcredits.
    let program_address = ProgramID::<CurrentNetwork>::from_str("test.aleo").unwrap().to_address().unwrap();
    let fund_inputs = [Value::from_str(&program_address.to_string()).unwrap(), Value::from_str("10000u64").unwrap()];
    let fund_tx = vm
        .execute(&genesis_private_key, ("credits.aleo", "transfer_public"), fund_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &genesis_private_key, Some(&[&fund_inputs]), &[fund_tx], rng);

    let program_addr_str = program_address.to_string();

    // Test with at least 10 random addresses, and at least one case of each modulo-4 residue (of the address).
    let mut tested_modular_residues = [false; 4];
    let mut num_tested_addresses = 0;

    while num_tested_addresses < 10 || tested_modular_residues.iter().any(|&residue| !residue) {
        let caller_pk = PrivateKey::new(rng).unwrap();
        let caller_address: Address<CurrentNetwork> = Address::try_from(&caller_pk).unwrap();

        // The modulo-4 residue of the (canonical integer representative of the) address' x-coordinate.
        let modulo_4_residue = {
            let x_coord: Field<CurrentNetwork> = caller_address.to_field().unwrap();
            let bits_le = x_coord.to_bits_le();
            (if bits_le[0] { 1 } else { 0 }) + (if bits_le[1] { 2 } else { 0 })
        };

        tested_modular_residues[usize::try_from(modulo_4_residue).unwrap()] = true;
        num_tested_addresses += 1;

        // Fund the caller with enough credits for the execution fee.
        let fund_inputs =
            [Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("1000000u64").unwrap()];
        let fund_tx = vm
            .execute(&genesis_private_key, ("credits.aleo", "transfer_public"), fund_inputs.iter(), None, 0, None, rng)
            .unwrap();

        add_and_test_with_costs(&vm, &genesis_private_key, Some(&[&fund_inputs]), &[fund_tx], rng);

        let program_balance_before = get_public_balance(&vm, &program_addr_str);

        // Execute main, signed by the random caller.
        let tx = vm
            .execute(
                &caller_pk,
                ("test.aleo", "main"),
                Vec::<Value<CurrentNetwork>>::new().into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        add_and_test_with_costs(&vm, &caller_pk, Some(&[&[]]), &[tx], rng);

        let program_balance_after = get_public_balance(&vm, &program_addr_str);
        assert_eq!(
            program_balance_after,
            program_balance_before - modulo_4_residue,
            "Expected transfer of {modulo_4_residue} for address {caller_address}"
        );
    }
}
