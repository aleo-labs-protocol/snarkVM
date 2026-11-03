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

use crate::helpers::sample::shared_process;

use console::{
    network::MainnetV0,
    prelude::*,
    program::{ArrayType, LiteralType, Locator, PlaintextType, U32},
};
use snarkvm_synthesizer_process::{Process, Stack};
use snarkvm_synthesizer_program::{Program, types_equivalent};
use std::{env, process::Command};

type CurrentNetwork = MainnetV0;

const CYCLIC_STRUCT_CHILD: &str = "SNARKVM_CYCLIC_STRUCT_EQUIVALENCE_CHILD";

// ---------- Helper ----------
fn sample_stack(program_text: &str) -> Result<Stack<CurrentNetwork>> {
    let program = Program::from_str(program_text)?;
    let stack = Stack::new(shared_process(), &program)?;
    Ok(stack)
}

// ---------- Literal equivalence ----------
#[test]
fn test_literal_equivalence() -> Result<()> {
    let stack = sample_stack("program p_lit.aleo; function main:")?;

    let u32_ty = PlaintextType::Literal(LiteralType::U32);
    let u64_ty = PlaintextType::Literal(LiteralType::U64);

    assert!(types_equivalent(&stack, &u32_ty, &stack, &u32_ty)?);
    assert!(!types_equivalent(&stack, &u32_ty, &stack, &u64_ty)?);

    Ok(())
}

// ---------- Struct equivalence (same program) ----------
#[test]
fn test_struct_equivalence_same_program() -> Result<()> {
    let program_text = r"
        program p_struct.aleo;
        struct Foo: x as u32; y as u32;
        struct Bar: x as u32; y as u32; z as u32;
        function main:
    ";

    let stack = sample_stack(program_text)?;
    let foo_ty = PlaintextType::Struct("Foo".try_into()?);
    let bar_ty = PlaintextType::Struct("Bar".try_into()?);

    assert!(types_equivalent(&stack, &foo_ty, &stack, &foo_ty)?);
    assert!(!types_equivalent(&stack, &foo_ty, &stack, &bar_ty)?);

    Ok(())
}

// ---------- Array equivalence ----------
#[test]
fn test_array_equivalence() -> Result<()> {
    let stack = sample_stack("program p_array.aleo; function main:")?;

    let u32_ty = PlaintextType::Literal(LiteralType::U32);

    let array1 = PlaintextType::Array(ArrayType::new(*Box::new(u32_ty.clone()), vec![U32::new(3)])?);
    let array2 = PlaintextType::Array(ArrayType::new(*Box::new(u32_ty.clone()), vec![U32::new(3)])?);
    let array3 = PlaintextType::Array(ArrayType::new(*Box::new(u32_ty.clone()), vec![U32::new(4)])?);

    assert!(types_equivalent(&stack, &array1, &stack, &array2)?);
    assert!(!types_equivalent(&stack, &array1, &stack, &array3)?);

    Ok(())
}

// ---------- Cross-program struct equivalence ----------
#[test]
fn test_cross_program_structs_equivalence() -> Result<()> {
    // ---------- Sample stacks ----------
    let s1 = sample_stack("program p1.aleo; struct Foo: x as u32; y as u32; function main:")?;
    let s2 = sample_stack("program p2.aleo; struct Foo: x as u32; y as u32; function main:")?;
    let s3 = sample_stack("program p3.aleo; struct Foo: x as u32; y as u32; z as u32; function main:")?;
    let s4 = sample_stack("program p4.aleo; struct Bar: x as u32; y as u32; function main:")?;
    let s5 = sample_stack(
        "program p5.aleo; struct Inner: a as u32; struct Outer: inner as Inner; b as u32; function main:",
    )?;
    let s6 = sample_stack(
        "program p6.aleo; struct Inner: a as u32; struct Outer: inner as Inner; b as u32; function main:",
    )?;
    let s7 = sample_stack(
        "program p7.aleo; struct Inner: a as u32; struct Outer: inner as Inner; c as u32; function main:",
    )?;

    // ---------- Define types ----------
    let foo_ty = PlaintextType::Struct("Foo".try_into()?);
    let foo_ty_diff = PlaintextType::Struct("Foo".try_into()?); // will use s3 to test different fields
    let bar_ty = PlaintextType::Struct("Bar".try_into()?);
    let outer_ty = PlaintextType::Struct("Outer".try_into()?);
    let outer_ty_diff = PlaintextType::Struct("Outer".try_into()?);

    // ---------- Assertions ----------
    // Same name, same fields
    assert!(types_equivalent(&s1, &foo_ty, &s2, &foo_ty)?);

    // Same name, different fields
    assert!(!types_equivalent(&s1, &foo_ty, &s3, &foo_ty_diff)?);

    // Different names, same fields
    assert!(!types_equivalent(&s1, &foo_ty, &s4, &bar_ty)?);

    // Nested structs, same fields
    assert!(types_equivalent(&s5, &outer_ty, &s6, &outer_ty)?);

    // Nested structs, different fields in inner
    assert!(!types_equivalent(&s5, &outer_ty, &s7, &outer_ty_diff)?);

    Ok(())
}

// ---------- External vs Local struct ----------
#[test]
fn test_external_vs_local_struct_equivalence() -> Result<()> {
    // Create a single process to hold both programs
    let process = Process::<CurrentNetwork>::load()?;

    // External program
    let external_program = Program::from_str(
        r"program external.aleo;
        struct Foo: x as u32; y as u32;
        function main:",
    )?;
    process.lock().add_program(&external_program)?;

    // Local program that imports external
    let local_program = Program::from_str(
        r"import external.aleo;
        program local.aleo;
        struct Foo: x as u32; y as u32;
        function main:",
    )?;
    process.lock().add_program(&local_program)?;

    // Retrieve the stack for the local program
    let s_local = process.get_stack(local_program.id())?;

    let local_ty = PlaintextType::<CurrentNetwork>::Struct("Foo".try_into()?);
    let external_ty =
        PlaintextType::<CurrentNetwork>::ExternalStruct(Locator::new("external.aleo".try_into()?, "Foo".try_into()?));

    // Local vs External
    assert!(types_equivalent(&*s_local, &local_ty, &*s_local, &external_ty)?);

    // External vs Local
    assert!(types_equivalent(&*s_local, &external_ty, &*s_local, &local_ty)?);

    // External vs External
    assert!(types_equivalent(&*s_local, &external_ty, &*s_local, &external_ty)?);

    Ok(())
}

#[test]
fn test_external_and_array_struct_equivalence() -> Result<()> {
    use console::program::{ArrayType, LiteralType, Locator, PlaintextType, U32};
    use snarkvm_synthesizer_program::types_equivalent;

    // ---------- Create a single process ----------
    let process = Process::<CurrentNetwork>::load()?;

    // ---------- External program ----------
    let external_program = Program::from_str(
        r"program external.aleo;
        struct Foo: x as u32; y as u32;
        struct Bar: a as u32; b as u32;
        function main:",
    )?;
    process.lock().add_program(&external_program)?;

    // ---------- Local program importing external ----------
    let local_program = Program::from_str(
        r"import external.aleo;
        program local.aleo;
        struct Foo: x as u32; y as u32;
        struct Baz: f as Foo; g as u32;
        function main:",
    )?;
    process.lock().add_program(&local_program)?;

    // ---------- Retrieve the stack ----------
    let s_local = process.get_stack(local_program.id())?;

    // ---------- Define types ----------
    let local_foo = PlaintextType::Struct("Foo".try_into()?);
    let external_foo = PlaintextType::ExternalStruct(Locator::new("external.aleo".try_into()?, "Foo".try_into()?));

    let local_baz = PlaintextType::Struct("Baz".try_into()?);

    // Arrays of literals
    let u32_lit = PlaintextType::Literal(LiteralType::U32);
    let array_3 = PlaintextType::Array(ArrayType::new(*Box::new(u32_lit.clone()), vec![U32::new(3)])?);
    let array_4 = PlaintextType::Array(ArrayType::new(*Box::new(u32_lit.clone()), vec![U32::new(4)])?);

    // Arrays of structs
    let array_foo_2 = PlaintextType::Array(ArrayType::new(*Box::new(local_foo.clone()), vec![U32::new(2)])?);
    let array_external_foo_2 =
        PlaintextType::Array(ArrayType::new(*Box::new(external_foo.clone()), vec![U32::new(2)])?);

    // ---------- Assertions ----------

    // Local vs External struct
    assert!(types_equivalent(&*s_local, &local_foo, &*s_local, &external_foo)?);
    assert!(types_equivalent(&*s_local, &external_foo, &*s_local, &local_foo)?);

    // External vs External
    assert!(types_equivalent(&*s_local, &external_foo, &*s_local, &external_foo)?);

    // Arrays of literals
    assert!(types_equivalent(&*s_local, &array_3, &*s_local, &array_3)?);
    assert!(!types_equivalent(&*s_local, &array_3, &*s_local, &array_4)?);

    // Arrays of structs
    assert!(types_equivalent(&*s_local, &array_foo_2, &*s_local, &array_external_foo_2)?);

    // Nested struct inside local
    assert!(types_equivalent(&*s_local, &local_baz, &*s_local, &local_baz)?);

    Ok(())
}

#[test]
fn test_cyclic_external_struct_equivalence_returns_error() -> Result<()> {
    if env::var_os(CYCLIC_STRUCT_CHILD).is_some() {
        let process = Process::<CurrentNetwork>::load()?;

        let program_b = Program::from_str(
            r"
program cycle_b.aleo;
function main:
constructor:
    assert.eq true true;
",
        )?;
        process.lock().add_program(&program_b)?;

        let program_a = Program::from_str(
            r"
import cycle_b.aleo;
program cycle_a.aleo;
struct Node:
    next as cycle_b.aleo/Node;
function main:
constructor:
    assert.eq true true;
",
        )?;
        process.lock().add_program(&program_a)?;

        let upgraded_program_b = Program::from_str(
            r"
import cycle_a.aleo;
program cycle_b.aleo;
struct Node:
    next as cycle_a.aleo/Node;
function main:
constructor:
    assert.eq true true;
",
        )?;
        process.lock().add_program(&upgraded_program_b)?;

        let stack_a = process.get_stack(program_a.id())?;
        let node = PlaintextType::Struct("Node".try_into()?);
        let equivalence = types_equivalent(&*stack_a, &node, &*stack_a, &node);
        assert!(
            equivalence.as_ref().is_err_and(|error| error.to_string().contains("Cyclic struct reference")),
            "expected a cyclic struct reference error, got {equivalence:?}"
        );
        return Ok(());
    }

    // Run the recursive comparison in a child process because the regression aborts on stack overflow.
    let output = Command::new(env::current_exe()?)
        .arg("test_cyclic_external_struct_equivalence_returns_error")
        .arg("--nocapture")
        .env(CYCLIC_STRUCT_CHILD, "1")
        .output()?;

    assert!(
        output.status.success(),
        "Child test failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
