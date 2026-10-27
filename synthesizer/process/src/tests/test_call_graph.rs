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

use crate::{Process, tests::test_utils::shared_process};
use console::{
    network::{MainnetV0, prelude::*},
    program::{Group, Identifier, ProgramID},
    types::Field,
};
use snarkvm_ledger_block::Transition;
use snarkvm_synthesizer_program::Program;
use std::collections::HashMap;

type CurrentNetwork = MainnetV0;

/// Creates a fake `Transition` containing only a program ID, function name, and transition ID.
fn fake_transition(
    program_id: ProgramID<CurrentNetwork>,
    function_name: Identifier<CurrentNetwork>,
    index: u64,
) -> Transition<CurrentNetwork> {
    Transition::new(
        program_id,
        function_name,
        vec![],
        vec![],
        Group::generator(),
        Field::from_u64(index),
        Field::zero(),
    )
    .expect("Failed to create fake transition")
}

/// Builds a `Process` pre-loaded with `credits.aleo` and the given programs.
/// Programs must be listed in dependency order (dependencies before dependents).
fn make_process(programs: &[&str]) -> Process<CurrentNetwork> {
    let process = Process::load().unwrap(); // unwrap: always succeeds in tests
    for src in programs {
        let (rest, program) = Program::<CurrentNetwork>::parse(src).unwrap(); // unwrap: valid test program
        assert!(rest.is_empty(), "Parser did not consume the full program string");
        process.lock().add_program(&program).unwrap(); // unwrap: valid program in dependency order
    }
    process
}

fn construct_call_graph(
    process: &Process<CurrentNetwork>,
    transitions: &[&Transition<CurrentNetwork>],
) -> Result<HashMap<<CurrentNetwork as Network>::TransitionID, Vec<<CurrentNetwork as Network>::TransitionID>>> {
    let mut execution_stacks = indexmap::IndexMap::new();
    for transition in transitions {
        execution_stacks.insert(*transition.program_id(), process.get_stack(transition.program_id())?);
    }
    Process::construct_call_graph(transitions.iter().copied(), &execution_stacks)
}

/// A single function that makes no calls.
/// Expected graph: `{ t0 → [] }`.
#[test]
fn test_single_leaf() {
    let process = make_process(&[r"
        program leaf.aleo;
        function f:
            input r0 as u8.private;
            output r0 as u8.private;"]);

    let pid = ProgramID::from_str("leaf.aleo").unwrap();
    let fname = Identifier::from_str("f").unwrap();

    let t0 = fake_transition(pid, fname, 0);
    let transitions = [&t0];

    let graph = construct_call_graph(&process, &transitions).unwrap();

    assert_eq!(graph.len(), 1);
    assert_eq!(graph[t0.id()], [] as [_; 0]);
}

/// A static linear chain: `parent.aleo/h` calls `child.aleo/g` once.
/// Execution post-order: `[g, h]`.
/// Expected graph: `{ h → [g], g → [] }`.
#[test]
fn test_linear_static_chain() {
    let process = make_process(&[
        r"
        program child.aleo;
        function g:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        import child.aleo;
        program parent.aleo;
        function h:
            input r0 as u8.private;
            call child.aleo/g r0 into r1;
            output r1 as u8.private;",
    ]);

    let child_pid = ProgramID::from_str("child.aleo").unwrap();
    let parent_pid = ProgramID::from_str("parent.aleo").unwrap();
    let g = Identifier::from_str("g").unwrap();
    let h = Identifier::from_str("h").unwrap();

    // Children come before parents in post-order.
    let t_g = fake_transition(child_pid, g, 0);
    let t_h = fake_transition(parent_pid, h, 1);
    let transitions = [&t_g, &t_h];

    let graph = construct_call_graph(&process, &transitions).unwrap();

    assert_eq!(graph.len(), 2);
    assert_eq!(graph[t_h.id()], [*t_g.id()]);
    assert_eq!(graph[t_g.id()], [] as [_; 0]);
}

/// A static fan-out: `root.aleo/r` calls `left.aleo/a` then `right.aleo/b`.
/// Execution post-order: `[a, b, r]`.
/// Expected graph: `{ r → [a, b], a → [], b → [] }`.
#[test]
fn test_fanout_two_children() {
    let process = make_process(&[
        r"
        program left.aleo;
        function a:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        program right.aleo;
        function b:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        import left.aleo;
        import right.aleo;
        program root.aleo;
        function r:
            input r0 as u8.private;
            call left.aleo/a r0 into r1;
            call right.aleo/b r0 into r2;
            output r1 as u8.private;",
    ]);

    let left_pid = ProgramID::from_str("left.aleo").unwrap();
    let right_pid = ProgramID::from_str("right.aleo").unwrap();
    let root_pid = ProgramID::from_str("root.aleo").unwrap();

    let t_a = fake_transition(left_pid, Identifier::from_str("a").unwrap(), 0);
    let t_b = fake_transition(right_pid, Identifier::from_str("b").unwrap(), 1);
    let t_r = fake_transition(root_pid, Identifier::from_str("r").unwrap(), 2);
    let transitions = [&t_a, &t_b, &t_r];

    let graph = construct_call_graph(&process, &transitions).unwrap();

    assert_eq!(graph.len(), 3);
    assert_eq!(graph[t_r.id()], [*t_a.id(), *t_b.id()]);
    assert_eq!(graph[t_a.id()], [] as [_; 0]);
    assert_eq!(graph[t_b.id()], [] as [_; 0]);
}

/// The same callee is called twice from one parent.
/// Each call produces an independent transition with a distinct ID.
/// Execution post-order: `[f0, f1, caller]`.
/// Expected graph: `{ caller → [f0, f1], f0 → [], f1 → [] }`.
#[test]
fn test_repeated_callee() {
    let process = make_process(&[
        r"
        program callee.aleo;
        function f:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        import callee.aleo;
        program caller.aleo;
        function twice:
            input r0 as u8.private;
            call callee.aleo/f r0 into r1;
            call callee.aleo/f r1 into r2;
            output r2 as u8.private;",
    ]);

    let callee_pid = ProgramID::from_str("callee.aleo").unwrap();
    let caller_pid = ProgramID::from_str("caller.aleo").unwrap();
    let f = Identifier::from_str("f").unwrap();
    let twice = Identifier::from_str("twice").unwrap();

    // Two distinct transitions for the same callee function.
    let t_f0 = fake_transition(callee_pid, f, 0);
    let t_f1 = fake_transition(callee_pid, f, 1);
    let t_caller = fake_transition(caller_pid, twice, 2);
    let transitions = [&t_f0, &t_f1, &t_caller];

    let graph = construct_call_graph(&process, &transitions).unwrap();

    assert_eq!(graph.len(), 3);
    assert_eq!(graph[t_caller.id()], [*t_f0.id(), *t_f1.id()]);
    assert_eq!(graph[t_f0.id()], [] as [_; 0]);
    assert_eq!(graph[t_f1.id()], [] as [_; 0]);
}

/// A two-level deep static chain: `grand.aleo/top` calls `mid.aleo/mid`, which calls `leaf.aleo/bot`.
/// Execution post-order: `[bot, mid, top]`.
/// Expected graph: `{ top → [mid], mid → [bot], bot → [] }`.
#[test]
fn test_deep_static_chain() {
    let process = make_process(&[
        r"
        program leaf.aleo;
        function bot:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        import leaf.aleo;
        program mid.aleo;
        function mid:
            input r0 as u8.private;
            call leaf.aleo/bot r0 into r1;
            output r1 as u8.private;",
        r"
        import mid.aleo;
        program grand.aleo;
        function top:
            input r0 as u8.private;
            call mid.aleo/mid r0 into r1;
            output r1 as u8.private;",
    ]);

    let leaf_pid = ProgramID::from_str("leaf.aleo").unwrap();
    let mid_pid = ProgramID::from_str("mid.aleo").unwrap();
    let grand_pid = ProgramID::from_str("grand.aleo").unwrap();

    // Post-order: deepest child first.
    let t_bot = fake_transition(leaf_pid, Identifier::from_str("bot").unwrap(), 0);
    let t_mid = fake_transition(mid_pid, Identifier::from_str("mid").unwrap(), 1);
    let t_top = fake_transition(grand_pid, Identifier::from_str("top").unwrap(), 2);
    let transitions = [&t_bot, &t_mid, &t_top];

    let graph = construct_call_graph(&process, &transitions).unwrap();

    assert_eq!(graph.len(), 3);
    assert_eq!(graph[t_top.id()], [*t_mid.id()]);
    assert_eq!(graph[t_mid.id()], [*t_bot.id()]);
    assert_eq!(graph[t_bot.id()], [] as [_; 0]);
}

/// A cross-program closure call must be skipped, since closures do not produce transitions.
/// `caller.aleo/use_closure` invokes `lib.aleo/c`, which is a closure (not a function).
/// Execution post-order: `[caller_t]` (the closure call adds nothing to the execution).
/// Expected graph: `{ caller_t → [] }`.
#[test]
fn test_cross_program_closure_call_is_skipped() {
    let process = make_process(&[
        r"
        program lib.aleo;
        closure c:
            input r0 as u8;
            add r0 r0 into r1;
            output r1 as u8;
        function f:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        import lib.aleo;
        program caller.aleo;
        function use_closure:
            input r0 as u8.private;
            call lib.aleo/c r0 into r1;
            output r1 as u8.private;",
    ]);

    let caller_pid = ProgramID::from_str("caller.aleo").unwrap();
    let use_closure = Identifier::from_str("use_closure").unwrap();
    let t_caller = fake_transition(caller_pid, use_closure, 0);
    let transitions = [&t_caller];

    let graph = construct_call_graph(&process, &transitions).expect("construct_call_graph must skip closure calls");

    assert_eq!(graph.len(), 1);
    assert_eq!(graph[t_caller.id()], [] as [_; 0]);
}

/// A single dynamic call: `caller.aleo/dyn_call` issues one `call.dynamic` instruction.
/// The callee program and function are not known at graph-build time; they are taken from the actual transition.
/// Execution post-order: `[callee_t, caller_t]`.
/// Expected graph: `{ caller_t → [callee_t], callee_t → [] }`.
#[test]
fn test_single_dynamic_call() {
    // Build the field representations used inside the call.dynamic instruction.
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let callee_prog_field = Identifier::<CurrentNetwork>::from_str("dyn").unwrap().to_field().unwrap();
    let callee_fn_field = Identifier::<CurrentNetwork>::from_str("leaf").unwrap().to_field().unwrap();

    let caller_src = format!(
        r"
        program caller.aleo;
        function dyn_call:
            input r0 as u8.private;
            call.dynamic {callee_prog_field} {network_field} {callee_fn_field} with r0 (as u8.private) into r1 (as u8.private);
            output r1 as u8.private;"
    );

    let process = make_process(&[
        r"
        program dyn.aleo;
        function leaf:
            input r0 as u8.private;
            output r0 as u8.private;",
        &caller_src,
    ]);

    let callee_pid = ProgramID::from_str("dyn.aleo").unwrap();
    let caller_pid = ProgramID::from_str("caller.aleo").unwrap();

    // Post-order: callee first, then caller.
    let t_callee = fake_transition(callee_pid, Identifier::from_str("leaf").unwrap(), 0);
    let t_caller = fake_transition(caller_pid, Identifier::from_str("dyn_call").unwrap(), 1);
    let transitions = [&t_callee, &t_caller];

    let graph = construct_call_graph(&process, &transitions).unwrap();

    assert_eq!(graph.len(), 2);
    assert_eq!(graph[t_caller.id()], [*t_callee.id()]);
    assert_eq!(graph[t_callee.id()], [] as [_; 0]);
}

/// A caller that issues one static call and one dynamic call.
/// Execution post-order: `[static_t, dyn_t, caller_t]`.
/// Expected graph: `{ caller_t → [static_t, dyn_t], static_t → [], dyn_t → [] }`.
#[test]
fn test_mixed_static_and_dynamic_calls() {
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let dyn_prog_field = Identifier::<CurrentNetwork>::from_str("dynee").unwrap().to_field().unwrap();
    let dyn_fn_field = Identifier::<CurrentNetwork>::from_str("g").unwrap().to_field().unwrap();

    let caller_src = format!(
        r"
        import staticee.aleo;
        program mixed.aleo;
        function both:
            input r0 as u8.private;
            call staticee.aleo/f r0 into r1;
            call.dynamic {dyn_prog_field} {network_field} {dyn_fn_field} with r0 (as u8.private) into r2 (as u8.private);
            output r1 as u8.private;"
    );

    let process = make_process(&[
        r"
        program staticee.aleo;
        function f:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        program dynee.aleo;
        function g:
            input r0 as u8.private;
            output r0 as u8.private;",
        &caller_src,
    ]);

    let staticee_pid = ProgramID::from_str("staticee.aleo").unwrap();
    let dynee_pid = ProgramID::from_str("dynee.aleo").unwrap();
    let mixed_pid = ProgramID::from_str("mixed.aleo").unwrap();

    // Post-order: both children before the caller.
    let t_static = fake_transition(staticee_pid, Identifier::from_str("f").unwrap(), 0);
    let t_dyn = fake_transition(dynee_pid, Identifier::from_str("g").unwrap(), 1);
    let t_caller = fake_transition(mixed_pid, Identifier::from_str("both").unwrap(), 2);
    let transitions = [&t_static, &t_dyn, &t_caller];

    let graph = construct_call_graph(&process, &transitions).unwrap();

    assert_eq!(graph.len(), 3);
    assert_eq!(graph[t_caller.id()], [*t_static.id(), *t_dyn.id()]);
    assert_eq!(graph[t_static.id()], [] as [_; 0]);
    assert_eq!(graph[t_dyn.id()], [] as [_; 0]);
}

/// Two independent root transitions in one execution (disconnected components).
/// This must be rejected because a single authorization must form one call tree.
#[test]
fn test_multiple_independent_roots() {
    let process = make_process(&[
        r"
        program alpha.aleo;
        function fa:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        program beta.aleo;
        function fb:
            input r0 as u8.private;
            output r0 as u8.private;",
    ]);

    let alpha_pid = ProgramID::from_str("alpha.aleo").unwrap();
    let beta_pid = ProgramID::from_str("beta.aleo").unwrap();

    let t_a = fake_transition(alpha_pid, Identifier::from_str("fa").unwrap(), 0);
    let t_b = fake_transition(beta_pid, Identifier::from_str("fb").unwrap(), 1);
    let transitions = [&t_a, &t_b];

    let result = construct_call_graph(&process, &transitions);
    assert!(result.is_err(), "expected disjoint transition trees to be rejected");
}

/// A static call where the actual transition has a different function name than the one declared in the call instruction.
/// This simulates a malformed or reordered execution sequence.
#[test]
fn test_error_static_locator_mismatch() {
    let process = make_process(&[
        r"
        program child.aleo;
        function g:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        import child.aleo;
        program parent.aleo;
        function h:
            input r0 as u8.private;
            call child.aleo/g r0 into r1;
            output r1 as u8.private;",
    ]);

    let parent_pid = ProgramID::from_str("parent.aleo").unwrap();
    let child_pid = ProgramID::from_str("child.aleo").unwrap();

    // The call declares `child.aleo/g`, but we supply a transition for `child.aleo/h`.
    let wrong_fn = Identifier::from_str("h").unwrap();
    let t_wrong = fake_transition(child_pid, wrong_fn, 0);
    let t_parent = fake_transition(parent_pid, Identifier::from_str("h").unwrap(), 1);
    let transitions = [&t_wrong, &t_parent];

    let result = construct_call_graph(&process, &transitions);
    assert!(result.is_err(), "Expected an error for a static locator mismatch");
}

/// A parent function that statically calls one child, but only the parent transition is provided (the child is missing).
/// The traversal stack will not be empty at the end, causing an error.
#[test]
fn test_error_missing_child_transition() {
    let process = make_process(&[
        r"
        program child.aleo;
        function g:
            input r0 as u8.private;
            output r0 as u8.private;",
        r"
        import child.aleo;
        program parent.aleo;
        function h:
            input r0 as u8.private;
            call child.aleo/g r0 into r1;
            output r1 as u8.private;",
    ]);

    let parent_pid = ProgramID::from_str("parent.aleo").unwrap();
    let t_parent = fake_transition(parent_pid, Identifier::from_str("h").unwrap(), 0);

    // Provide only the parent; the child transition is intentionally omitted.
    let transitions = [&t_parent];

    let result = construct_call_graph(&process, &transitions);
    assert!(result.is_ok());
}

/// An empty transition list produces an empty call graph without error.
#[test]
fn test_empty_transitions() {
    let transitions: Vec<&Transition<CurrentNetwork>> = vec![];
    let graph = construct_call_graph(shared_process(), &transitions).unwrap();
    assert!(graph.is_empty());
}
