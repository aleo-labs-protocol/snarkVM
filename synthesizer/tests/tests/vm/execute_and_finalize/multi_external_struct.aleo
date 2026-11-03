/*
randomness: 290532178
cases:
  - program: program1.aleo
    function: main
    inputs: []
*/

// Program3: defines the innermost struct
program program3.aleo;

struct Inner:
    x as u32;
    y as u32;

function main:

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import program3.aleo;
program program2.aleo;

// Program2: defines a struct containing Program3's struct
struct Middle:
    inner as program3.aleo/Inner;

// Function to construct a Middle from two u32 values
function create_middle:
    input r0 as u32.private;
    input r1 as u32.private;
    // Construct Inner internally
    cast r0 r1 into r2 as program3.aleo/Inner;
    cast r2 into r3 as Middle;
    output r3 as Middle.private;

// Function to extract Inner from Middle
function wrap_middle:
    input r0 as Middle.private;
    output r0.inner as program3.aleo/Inner.private;

constructor:
    assert.eq edition 0u16;

/////////////////////////////////////////////////

import program2.aleo;
program program1.aleo;

// Program1: only uses program2
function main:
    // Call program2 to create a Middle
    call program2.aleo/create_middle 10u32 20u32 into r0;

    // Outputs: return the Middle directly
    output r0 as program2.aleo/Middle.public;

constructor:
    assert.eq edition 0u16;

