/*
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

struct BooHoo:
    woo as Woo;

function create_another_wrapper:
    cast 1u32 2u32 into r0 as Woo;
    cast r0 into r1 as BooHoo;
    async create_another_wrapper r1 into r2;
    output r2[0u32] as BooHoo.private;
    output r2 as child.aleo/create_another_wrapper.future;

finalize create_another_wrapper:
    input r0 as BooHoo.public;
    assert.eq true true;

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import child.aleo;
program parent.aleo;

function omega_wrapper:
    call child.aleo/create_another_wrapper into r0 r1;
    cast 1u32 2u32 into r2 as child.aleo/Woo;
    cast r2 into r3 as child.aleo/BooHoo;
    async omega_wrapper r3 r0 r1 into r4;
    output r4[0u32] as child.aleo/BooHoo.private;
    output r4[1u32] as child.aleo/BooHoo.private;
    output r4 as parent.aleo/omega_wrapper.future;

finalize omega_wrapper:
    input r0 as child.aleo/BooHoo.public;
    input r1 as child.aleo/BooHoo.public;
    input r2 as child.aleo/create_another_wrapper.future;
    await r2;

constructor:
    assert.eq edition 0u16;
