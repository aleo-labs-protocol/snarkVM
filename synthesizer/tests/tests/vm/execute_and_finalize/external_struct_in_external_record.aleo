/*
start_height: 19
randomness: 45791624
cases:
  - program: parent.aleo
    function: omega_wrapper 
    inputs: []
*/

program child.aleo;

struct Woo:
    a as u32;
    b as u32;

record BooHoo:
    owner as address.private;
    woo as Woo.private;

function create_another_wrapper:
    cast 1u32 2u32 into r0 as Woo;
    cast self.signer r0 into r1 as BooHoo.record;
    output r1 as BooHoo.record;

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import child.aleo;
program parent.aleo;

function omega_wrapper:
    call child.aleo/create_another_wrapper into r0;
    output r0 as child.aleo/BooHoo.record;

constructor:
    assert.eq edition 0u16;
