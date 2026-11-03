/*
randomness: 290532178
cases:
  - program: external_structs.aleo
    function: main
    inputs: []
*/

program child1.aleo;

struct Boo:
    a as u32;
    b as u32;

struct Foo:
    c as Boo;

function main_2:
    input r0 as Foo.private;
    output r0.c as Boo.private;

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import child1.aleo;
program external_structs.aleo;

function main:
    cast 1u32 2u32 into r0 as child1.aleo/Boo;
    cast r0 into r1 as child1.aleo/Foo;
    call child1.aleo/main_2 r1 into r2;
    output r0 as child1.aleo/Boo.public;
    output r1 as child1.aleo/Foo.public;
    output r2 as child1.aleo/Boo.public;

constructor:
    assert.eq edition 0u16;

