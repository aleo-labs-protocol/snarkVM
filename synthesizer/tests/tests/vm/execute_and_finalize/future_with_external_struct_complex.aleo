/*
randomness: 45791624
cases:
  - program: parent.aleo
    function: omega_wrapper
    inputs: []
*/

program grandchild.aleo;

struct Woo:
    a as u32;
    b as u32;

struct BooHoo:
    woo as Woo;

function create_wrapper:
    cast 1u32 2u32 into r0 as Woo;
    cast r0 into r1 as BooHoo;
    async create_wrapper r1 into r2;
    output r2[0u32] as BooHoo.private;
    output r2 as grandchild.aleo/create_wrapper.future;

finalize create_wrapper:
    input r0 as BooHoo.public;
    assert.eq true true;

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import grandchild.aleo;
program child.aleo;

struct Woo:
    a as u32;
    b as u32;

struct BooHoo:
    woo as Woo;

function create_another_wrapper:
    call grandchild.aleo/create_wrapper into r0 r1;
    cast 1u32 2u32 into r2 as Woo;
    cast r2 into r3 as BooHoo;
    async create_another_wrapper r3 r0 r1 into r4;
    output r4[0u32] as BooHoo.private;
    output r4[1u32] as grandchild.aleo/BooHoo.private;
    output r4 as child.aleo/create_another_wrapper.future;

finalize create_another_wrapper:
    input r0 as BooHoo.public;
    input r1 as grandchild.aleo/BooHoo.public;
    input r2 as grandchild.aleo/create_wrapper.future;
    await r2;

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import grandchild.aleo;
import child.aleo;
program parent.aleo;

function omega_wrapper:
    call child.aleo/create_another_wrapper into r0 r1 r2;
    cast 1u32 2u32 into r3 as child.aleo/Woo;
    cast r3 into r4 as child.aleo/BooHoo;
    async omega_wrapper r4 r0 r1 r2 into r5;
    output r5[0u32] as child.aleo/BooHoo.private;
    output r5[1u32] as child.aleo/BooHoo.private;
    output r5[2u32] as grandchild.aleo/BooHoo.private;
    output r2[2u32][0u32] as grandchild.aleo/BooHoo.private;
    output r5 as parent.aleo/omega_wrapper.future;

finalize omega_wrapper:
    input r0 as child.aleo/BooHoo.public;
    input r1 as child.aleo/BooHoo.public;
    input r2 as grandchild.aleo/BooHoo.public;
    input r3 as child.aleo/create_another_wrapper.future;
    await r3;

constructor:
    assert.eq edition 0u16;
