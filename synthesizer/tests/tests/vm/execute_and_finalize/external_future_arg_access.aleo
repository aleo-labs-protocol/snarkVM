/*
randomness: 45791624
cases:
  - program: test.aleo
    function: main 
    inputs: []
*/

program child.aleo;

struct Foo:
    x as u32;

function main:
    cast 42u32 into r0 as Foo;
    async main r0 into r1;
    output r1 as child.aleo/main.future;

finalize main:
    input r0 as Foo.public;
    assert.eq true true;

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import child.aleo;
program test.aleo;

function main:
    call child.aleo/main into r0;
    async main r0 into r1;
    is.eq r0[0u32].x r0[0u32].x into r2;
    output r0[0u32].x as u32.private;
    output r1 as test.aleo/main.future;

finalize main:
    input r0 as child.aleo/main.future;
    await r0;

constructor:
    assert.eq edition 0u16;
