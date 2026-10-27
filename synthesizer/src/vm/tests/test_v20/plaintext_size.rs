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

use super::*;

use crate::Stack;

use console::network::prelude::*;

/// Builds a VM advanced to V20 height, adds `imports` to the process, and runs
/// `check_program_plaintext_sizes` against `program_text` using the V20 bit budget.
fn run_check_at_v20_with_imports(imports: &[&str], program_text: &str) -> Result<()> {
    let rng = &mut TestRng::default();
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V20).unwrap(), rng);

    // Add the imported programs, in topological order, so that the program under test resolves.
    for import in imports {
        vm.process().lock().add_program(&Program::<CurrentNetwork>::from_str(import).unwrap()).unwrap();
    }

    let program = Program::<CurrentNetwork>::from_str(program_text).unwrap();
    let stack = Stack::new(vm.process(), &program).unwrap();
    let max_bits = CurrentNetwork::LATEST_MAX_PLAINTEXT_TYPE_SIZE_IN_BITS();
    check_program_plaintext_sizes(&program, &stack, max_bits)
}

/// Builds a VM advanced to V20 height and runs `check_program_plaintext_sizes`
/// against `program_text` using the V20 bit budget.
fn run_check_at_v20(program_text: &str) -> Result<()> {
    run_check_at_v20_with_imports(&[], program_text)
}

/// A triply-nested 2048x2048x2048 bool array, the largest array type the element limit permits.
/// It is rejected on the type AST, without sampling any leaf.
#[test]
fn test_deeply_nested_array_input_rejected() {
    let result = run_check_at_v20(
        r"
program nested_array.aleo;

function f:
    input r0 as [[[boolean; 2048u32]; 2048u32]; 2048u32].private;
    output r0 as [[[boolean; 2048u32]; 2048u32]; 2048u32].private;

constructor:
    assert.eq true true;
",
    );
    let err = result.expect_err("over-cap nested array type must be rejected");
    assert!(err.to_string().contains("exceeds the maximum allowed size in bits"), "unexpected error: {err}");
}

/// A program whose function input fits well under the cap is accepted.
#[test]
fn test_under_cap_function_input_accepted() {
    run_check_at_v20(
        r"
program small.aleo;

function f:
    input r0 as [u64; 100u32].private;
    output r0 as [u64; 100u32].private;

constructor:
    assert.eq true true;
",
    )
    .expect("under-cap program must pass");
}

/// A struct whose member exceeds the per-type cap is rejected.
#[test]
fn test_over_cap_struct_member_rejected() {
    let err = run_check_at_v20(
        r"
program big_struct.aleo;

struct big:
    huge as [[u64; 2048u32]; 9u32];

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
",
    )
    .expect_err("over-cap struct member must be rejected");
    assert!(err.to_string().contains("exceeds the maximum allowed size in bits"), "unexpected error: {err}");
}

/// A record entry that exceeds the per-type cap is rejected.
#[test]
fn test_over_cap_record_entry_rejected() {
    let err = run_check_at_v20(
        r"
program big_record.aleo;

record big:
    owner as address.private;
    huge as [[u64; 2048u32]; 9u32].private;

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
",
    )
    .expect_err("over-cap record entry must be rejected");
    assert!(err.to_string().contains("exceeds the maximum allowed size in bits"), "unexpected error: {err}");
}

/// A mapping value that exceeds the per-type cap is rejected.
#[test]
fn test_over_cap_mapping_value_rejected() {
    let err = run_check_at_v20(
        r"
program big_mapping.aleo;

mapping m:
    key as u64.public;
    value as [[u64; 2048u32]; 9u32].public;

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
",
    )
    .expect_err("over-cap mapping value must be rejected");
    assert!(err.to_string().contains("exceeds the maximum allowed size in bits"), "unexpected error: {err}");
}

/// A closure input that exceeds the per-type cap is rejected.
#[test]
fn test_over_cap_closure_input_rejected() {
    let err = run_check_at_v20(
        r"
program big_closure.aleo;

closure c:
    input r0 as [[u64; 2048u32]; 9u32];
    is.eq r0 r0 into r1;
    output r1 as boolean;

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
",
    )
    .expect_err("over-cap closure input must be rejected");
    assert!(err.to_string().contains("exceeds the maximum allowed size in bits"), "unexpected error: {err}");
}

/// A finalize argument that exceeds the per-type cap is rejected.
/// Since async arguments and finalize inputs must agree, the over-cap type also appears as
/// a function input; the function-input check fires first, but the program is still rejected.
/// The legacy `check_future_argument_bit_size` runs only before V14 and permits up to
/// `u16::MAX` bits; this check applies from V20 with a tighter budget.
#[test]
fn test_over_cap_finalize_input_rejected() {
    let err = run_check_at_v20(
        r"
program big_finalize.aleo;

function f:
    input r0 as u64.public;
    input r1 as [[u64; 2048u32]; 9u32].public;
    async f r0 r1 into r2;
    output r2 as big_finalize.aleo/f.future;

finalize f:
    input r0 as u64.public;
    input r1 as [[u64; 2048u32]; 9u32].public;
    assert.eq r0 r0;

constructor:
    assert.eq true true;
",
    )
    .expect_err("over-cap finalize input must be rejected");
    assert!(err.to_string().contains("exceeds the maximum allowed size in bits"), "unexpected error: {err}");
}

/// An external struct whose members refer to structs local to the external program is resolved
/// against that program, and accepted when it fits under the cap.
#[test]
fn test_under_cap_external_struct_accepted() {
    run_check_at_v20_with_imports(
        &[r"
program child.aleo;

struct woo:
    a as u32;
    b as u32;

struct boohoo:
    woo as woo;

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
"],
        r"
import child.aleo;
program parent.aleo;

function f:
    input r0 as child.aleo/boohoo.private;
    output r0 as child.aleo/boohoo.private;

constructor:
    assert.eq true true;
",
    )
    .expect("under-cap external struct must pass");
}

/// An external struct whose local member type exceeds the per-type cap is rejected. The external
/// program may predate V20, so its declarations are only bounded where an importer declares them.
#[test]
fn test_over_cap_external_struct_rejected() {
    let err = run_check_at_v20_with_imports(
        &[r"
program child.aleo;

struct huge:
    huge as [[u64; 2048u32]; 9u32];

struct boohoo:
    huge as huge;

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
"],
        r"
import child.aleo;
program parent.aleo;

function f:
    input r0 as child.aleo/boohoo.private;
    output r0 as child.aleo/boohoo.private;

constructor:
    assert.eq true true;
",
    )
    .expect_err("over-cap external struct must be rejected");
    assert!(err.to_string().contains("exceeds the maximum allowed size in bits"), "unexpected error: {err}");
}

/// An external struct may refer to a struct in a program that the importer does not import, so
/// each struct reference must be resolved against the program that declares it.
#[test]
fn test_under_cap_transitive_external_struct_accepted() {
    run_check_at_v20_with_imports(
        &[
            r"
program grandchild.aleo;

struct woo:
    a as u32;
    b as u32;

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
",
            r"
import grandchild.aleo;
program child.aleo;

struct boohoo:
    woo as grandchild.aleo/woo;

function f:
    input r0 as u64.private;
    output r0 as u64.private;

constructor:
    assert.eq true true;
",
        ],
        r"
import child.aleo;
program parent.aleo;

function f:
    input r0 as child.aleo/boohoo.private;
    output r0 as child.aleo/boohoo.private;

constructor:
    assert.eq true true;
",
    )
    .expect("under-cap transitive external struct must pass");
}

/// A shared-struct graph: `MAX_STRUCT_ENTRIES` members per struct, every member of `s{k}` referring to `s{k-1}`.
/// A single input of type `s{depth - 1}` therefore spans `MAX_STRUCT_ENTRIES ^ (depth - 1)` distinct root-to-leaf
/// paths — the shape exploited by the type-validation DoS. Without memoization `check_program_plaintext_sizes`
/// re-expands every path and never returns; with it, each `(program, struct)` pair is sized once.
///
/// The check is run on a detached thread so that the regression surfaces as a bounded timeout failure rather
/// than hanging the test suite indefinitely.
#[test]
fn test_shared_struct_dag_terminates() {
    use std::{
        fmt::Write as _,
        sync::{mpsc, mpsc::RecvTimeoutError},
        thread,
        time::Duration,
    };

    const DEPTH: usize = 12;

    let mut source = String::from("program testing_dag.aleo;\n\n");
    for level in 0..DEPTH {
        writeln!(source, "struct s{level}:").unwrap();
        let member_type = if level == 0 { "field".to_string() } else { format!("s{}", level - 1) };
        for member in 0..CurrentNetwork::MAX_STRUCT_ENTRIES {
            writeln!(source, "    m{member} as {member_type};").unwrap();
        }
        source.push('\n');
    }
    writeln!(source, "function f:\n    input r0 as s{}.private;", DEPTH - 1).unwrap();
    source.push_str("\nconstructor:\n    assert.eq true true;\n");

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(run_check_at_v20(&source));
    });

    // 5 minutes is generous even if the CI machine is heavily loaded.
    match receiver.recv_timeout(Duration::from_secs(300)) {
        // The graph is astronomically over the cap, so it must be rejected — either for exceeding the cap or,
        // as here, because its bit size overflows `usize` first. The point is only that it is rejected promptly.
        Ok(result) => {
            result.expect_err("over-cap shared-struct graph must be rejected");
        }
        Err(RecvTimeoutError::Timeout) => panic!(
            "check_program_plaintext_sizes did not terminate within 300s: the shared-struct graph is being \
             re-expanded exponentially (memoization is missing)"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("the checking thread panicked; see its output above"),
    }
}
