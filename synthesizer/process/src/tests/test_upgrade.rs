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

/// The purpose of these tests are to ensure that an upgrade made to a program is syntactically correct.
/// These rules are defined in `check_upgrade_is_valid`.
/// These tests *DO NOT*: check the semantic correctness of the upgrades.
use crate::{Process, Stack};
use console::network::{MainnetV0, prelude::*};
use snarkvm_synthesizer_program::{Program, StackTrait};
use std::{panic, sync::mpsc, thread, time::Duration};

type CurrentNetwork = MainnetV0;

// A helper function to sample the default process.
fn sample_process() -> Result<Process<CurrentNetwork>, Error> {
    let process = Process::load()?;
    // Add the default program to the process.
    let default_program = Program::from_str(
        r"
program test.aleo;
function foo:
constructor:
    assert.eq true true;
    ",
    )?;
    process.lock().add_program(&default_program)?;
    // Return the process.
    Ok(process)
}

#[test]
fn test_add_simple_program() -> Result<()> {
    // Sample the default process.
    let process = Process::<CurrentNetwork>::load()?;
    // Add a simple program to the process.
    let initial_program = Program::from_str(
        r"
program test.aleo;
function foo:
    ",
    )?;
    // Add the new program to the process.
    process.lock().add_program(&initial_program)?;
    // Get the program from the process.
    let stack = process.get_stack("test.aleo")?;
    let program = stack.program();
    // Check that the program is the same as the initial program.
    assert_eq!(program, &initial_program);
    Ok(())
}

#[test]
fn test_nested_process_lock_fails_loudly() -> Result<()> {
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let process = Process::<CurrentNetwork>::load().expect("Failed to load process");
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let guard = process.lock();
            guard.lock();
        }));
        sender.send(result.is_err()).expect("Failed to send test result");
    });

    assert!(
        receiver.recv_timeout(Duration::from_secs(5)).expect("Failed to receive test result"),
        "Expected nested process lock to panic instead of deadlocking"
    );
    Ok(())
}

#[test]
fn test_upgrade_without_constructor() -> Result<()> {
    // Sample the default process.
    let process = Process::<CurrentNetwork>::load()?;
    // Add a program without a constructor to the process.
    let initial_program = Program::from_str(
        r"
program test.aleo;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Attempt to upgrade the program.
    let new_program = Program::from_str(
        r"
program test.aleo;
function foo:
function bar:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_upgrade_with_constructor() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program test.aleo;
constructor:
    assert.eq true true;
function foo:
function bar:
    ",
    )?;
    // Verify that the upgrade was successful.
    process.lock().add_program(&new_program)?;
    Ok(())
}

#[test]
fn test_add_import() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
import credits.aleo;
program test.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("test.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_add_struct() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program test.aleo;
constructor:
    assert.eq true true;
struct bar:
    data as u8;
function foo:
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("test.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_add_record() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program test.aleo;
constructor:
    assert.eq true true;
record bar:
    owner as address.private;
    data as u8.private;
function foo:
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("test.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_add_mapping() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program test.aleo;
constructor:
    assert.eq true true;
mapping onchain:
    key as u8.public;
    value as u16.public;
function foo:
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("test.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_add_closure() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program test.aleo;
constructor:
    assert.eq true true;
closure sum:
    input r0 as u8;
    input r1 as u8;
    add r0 r1 into r2;
    output r2 as u8;
function foo:
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("test.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_add_function() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program test.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
function foo:
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("test.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_modify_function_logic() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    sub r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("basic.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_modify_function_signature() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u16.private;
    input r1 as u16.private;
    add r0 r1 into r2;
    output r2 as u16.private;
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_modify_finalize_logic() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function assert_on_chain:
    input r0 as u8.public;
    input r1 as u8.public;
    async assert_on_chain r0 r1 into r2;
    output r2 as basic.aleo/assert_on_chain.future;
finalize assert_on_chain:
    input r0 as u8.public;
    input r1 as u8.public;
    assert.eq r0 r1;
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function assert_on_chain:
    input r0 as u8.public;
    input r1 as u8.public;
    async assert_on_chain r0 r1 into r2;
    output r2 as basic.aleo/assert_on_chain.future;
finalize assert_on_chain:
    input r0 as u8.public;
    input r1 as u8.public;
    assert.neq r0 r1;
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("basic.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_modify_finalize_signature() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function assert_on_chain:
    input r0 as u8.public;
    input r1 as u8.public;
    async assert_on_chain r0 r1 into r2;
    output r2 as basic.aleo/assert_on_chain.future;
finalize assert_on_chain:
    input r0 as u8.public;
    input r1 as u8.public;
    assert.eq r0 r1;
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function assert_on_chain:
    input r0 as u8.public;
    input r1 as u8.public;
    async assert_on_chain 0u16 1u16 into r2;
    output r2 as basic.aleo/assert_on_chain.future;
finalize assert_on_chain:
    input r0 as u16.public;
    input r1 as u16.public;
    assert.eq r0 r1;
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_modify_struct() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
struct bar:
    data as u8;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
struct bar:
    data as u16;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_modify_record() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
record bar:
    owner as address.private;
    data as u8.private;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
record bar:
    owner as address.private;
    data as u16.private;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_modify_mapping() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
mapping onchain:
    key as u8.public;
    value as u16.public;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
mapping onchain:
    key as u8.public;
    value as u8.public;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_modify_closure_logic() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
closure sum:
    input r0 as u8;
    input r1 as u8;
    add r0 r1 into r2;
    output r2 as u8;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
closure sum:
    input r0 as u8;
    input r1 as u8;
    sub r0 r1 into r2;
    output r2 as u8;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_modify_closure_signature() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
closure sum:
    input r0 as u8;
    input r1 as u8;
    add r0 r1 into r2;
    output r2 as u8;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
closure sum:
    input r0 as u16;
    input r1 as u16;
    add r0 r1 into r2;
    output r2 as u16;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_remove_import() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
import credits.aleo;
program basic.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_remove_struct() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
struct bar:
    data as u8;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_remove_record() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
record bar:
    owner as address.private;
    data as u8.private;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_remove_mapping() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
mapping onchain:
    key as u8.public;
    value as u16.public;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_remove_closure() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
closure sum:
    input r0 as u8;
    input r1 as u8;
    add r0 r1 into r2;
    output r2 as u8;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_remove_function() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
function foo:
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function foo:
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_add_call_to_non_async_transition() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add a program with a non-async transition.
    let new_program = Program::from_str(
        r"
program non_async.aleo;
constructor:
    assert.eq true true;
function foo:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;",
    )?;
    process.lock().add_program(&new_program)?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
import non_async.aleo;
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
import non_async.aleo;
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    call non_async.aleo/foo r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    process.lock().add_program(&new_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("basic.aleo")?;
    let program = stack.program();
    assert_eq!(program, &new_program);
    Ok(())
}

#[test]
fn test_add_call_to_async_transition() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add a program with an async transition.
    let new_program = Program::from_str(
        r"
program async_example.aleo;
constructor:
    assert.eq true true;
function foo:
    input r0 as u8.private;
    input r1 as u8.private;
    async foo r0 r1 into r2;
    add r0 r1 into r3;
    output r3 as u8.private;
    output r2 as async_example.aleo/foo.future;
finalize foo:
    input r0 as u8.public;
    input r1 as u8.public;
    assert.eq r0 r1;",
    )?;
    process.lock().add_program(&new_program)?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
import async_example.aleo;
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
import async_example.aleo;
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    call async_example.aleo/foo r0 r1 into r2 r3;
    async adder r3 into r4;
    output r2 as u8.private;
    output r4 as basic.aleo/adder.future;
finalize adder:
    input r0 as async_example.aleo/foo.future;
    await r0;",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_add_import_cycle() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;

    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    process.lock().add_program(&initial_program)?;

    // Verify that self-import cycles are not allowed.
    let new_program = Program::from_str(
        r"
import basic.aleo;
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    assert!(process.lock().add_program(&new_program).is_err());

    // Add a program dependent on `basic.aleo`.
    let dependent_program = Program::from_str(
        r"
import basic.aleo;
program dependent.aleo;
constructor:
    assert.eq true true;
function foo:
    input r0 as u8.private;
    input r1 as u8.private;
    call basic.aleo/adder r0 r1 into r2;
    output r2 as u8.private;",
    )?;
    process.lock().add_program(&dependent_program)?;
    // Verify that the upgrade was successful.
    let stack = process.get_stack("dependent.aleo")?;
    let program = stack.program();
    assert_eq!(program, &dependent_program);

    // Upgrade basic.aleo to import dependent.aleo.
    // This is allowed since we do not do cycle detection across programs.
    let new_program = Program::from_str(
        r"
import dependent.aleo;
program basic.aleo;
constructor:
    assert.eq true true;
function adder:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
    ",
    )?;
    // Verify that the upgrade was successful.
    process.lock().add_program(&new_program)?;
    Ok(())
}

#[test]
fn test_constructor_upgrade() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Add the initial program to the process.
    let initial_program = Program::from_str(
        r"
program basic.aleo;
function foo:
constructor:
    assert.eq 1u8 1u8;
    ",
    )?;
    process.lock().add_program(&initial_program)?;
    // Upgrade the program.
    let new_program = Program::from_str(
        r"
program basic.aleo;
function foo:
constructor:
    assert.eq 2u8 2u8;
    ",
    )?;
    // Verify that the upgrade was not successful.
    assert!(process.lock().add_program(&new_program).is_err());
    Ok(())
}

#[test]
fn test_credits_is_not_upgradable() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;
    // Define the new credits program.
    let credits_program = Program::<CurrentNetwork>::credits()?;
    let program = Program::from_str(&format!("{credits_program}\nfunction dummy:"))?;
    // Attempt to add the new credits program.
    let stack = process.get_stack("credits.aleo")?;
    let old_program = stack.program();
    let result = Stack::check_upgrade_is_valid(old_program, &program);
    // Verify that the upgrade was not successful.
    assert!(result.is_err(), "Upgrading 'credits.aleo' should not be allowed");
    Ok(())
}

#[test]
fn test_edition_and_checksum_and_program_owner_operands() -> Result<()> {
    // Sample the default process.
    let process = sample_process()?;

    // A helper to sample a test program with an operand in the function.
    let sample_program_with_operand_in_function = |operand: &str| -> Result<Program<CurrentNetwork>> {
        Program::from_str(&format!(
            r"
program test.aleo;

constructor:
    assert.eq true true;
    
function foo:
    assert.eq {operand} {operand};
            ",
        ))
    };

    // A helper to sample a test program with an operand in the closure.
    let sample_program_with_operand_in_closure = |operand: &str| -> Result<Program<CurrentNetwork>> {
        Program::from_str(&format!(
            r"
program test.aleo;

constructor:
    assert.eq true true;
    
function dummy:
    
closure foo:
    input r0 as u8;
    assert.eq {operand} {operand};
            ",
        ))
    };

    // Check that the below programs are invalid.

    let program = sample_program_with_operand_in_function("edition")?;
    assert!(process.lock().add_program(&program).is_err());

    let program = sample_program_with_operand_in_function("checksum")?;
    assert!(process.lock().add_program(&program).is_err());

    let program = sample_program_with_operand_in_function("program_owner")?;
    assert!(process.lock().add_program(&program).is_err());

    let program = sample_program_with_operand_in_closure("edition")?;
    assert!(process.lock().add_program(&program).is_err());

    let program = sample_program_with_operand_in_closure("checksum")?;
    assert!(process.lock().add_program(&program).is_err());

    let program = sample_program_with_operand_in_closure("program_owner")?;
    assert!(process.lock().add_program(&program).is_err());

    Ok(())
}
