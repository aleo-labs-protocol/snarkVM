/*
randomness: 63249871089234
cases:
  - program: self_caller_in_closure.aleo
    function: dummy
    inputs: [1u32, 2u32]
  - program: self_caller_in_closure.aleo
    function: run_check
    inputs: []
*/

program self_caller_in_closure.aleo;

closure check_caller:
    input r0 as address;
    assert.eq self.caller r0;

closure check_signer:
    input r0 as address;
    assert.eq self.signer r0;

function run_check:
    call check_caller self.caller;
    call check_signer self.signer;

function dummy:
    input r0 as u32.public;
    input r1 as u32.private;
    add r0 r1 into r2;
    output r2 as u32.private;

constructor:
    assert.eq edition 0u16;