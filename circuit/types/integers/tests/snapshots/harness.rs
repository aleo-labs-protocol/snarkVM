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

//! Records the synthesized shape of each case and compares it with a checked-in snapshot file.

use snarkvm_circuit_environment::{Circuit, Environment, Mode};

use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    fmt::Debug,
    fs,
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
    sync::Once,
};

/// The variable that makes `assert_snapshot` rewrite the snapshot files.
pub const UPDATE_VARIABLE: &str = "UPDATE_CIRCUIT_SNAPSHOTS";

/// A circuit output whose mode and value the harness records.
pub trait Output {
    type Value: Debug + PartialEq;

    /// Returns the mode of each output bit.
    fn bit_modes(&self) -> Vec<Mode>;

    /// Returns the value of the output.
    fn value(&self) -> Self::Value;
}

/// The synthesized result of one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The synthesis halted.
    Halt,
    /// The synthesis finished with the given counts and output mode.
    Done(String),
}

impl Outcome {
    fn render(&self) -> &str {
        match self {
            Self::Halt => "halt",
            Self::Done(shape) => shape,
        }
    }
}

/// One case of an op.
pub struct Case {
    /// The type and mode of each operand, such as `u8.constant u8.private`.
    pub block: String,
    /// The label of each constant operand value, or `_` for a variable operand, such as `MAX _`.
    pub values: String,
    pub outcome: Outcome,
}

/// Returns the label of an operand in `Case::values`.
pub fn value_label(mode: Mode, label: &str) -> &str {
    match mode {
        Mode::Constant => label,
        _ => "_",
    }
}

thread_local! {
    /// `true` while `catch_quietly` runs on this thread.
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `logic` and returns `None` if it panics. The panic message is not printed.
fn catch_quietly<T>(logic: impl FnOnce() -> T) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                previous(info)
            }
        }));
    });
    QUIET.with(|quiet| quiet.set(true));
    let result = panic::catch_unwind(AssertUnwindSafe(logic));
    QUIET.with(|quiet| quiet.set(false));
    result.ok()
}

/// Returns the mode of `output`, with a count per mode if the bits differ in mode.
fn render_mode<O: Output>(output: &O) -> String {
    let modes = output.bit_modes();
    let count = |mode| modes.iter().filter(|m| **m == mode).count();
    let combined = Mode::combine(Mode::Constant, modes.iter().copied());
    match modes.iter().all(|mode| *mode == combined) {
        true => combined.to_string(),
        false => {
            format!("{combined}[c{}/u{}/p{}]", count(Mode::Constant), count(Mode::Public), count(Mode::Private))
        }
    }
}

/// Synthesizes `operation` in a new scope, then resets the circuit.
///
/// The caller injects the operands before the call, so the counts cover the operation alone.
/// `expected` is the console result, or `None` if the operation is undefined for the operands.
/// Panics if a defined case does not produce `expected` in a satisfied circuit,
/// or if an undefined case gives a satisfied circuit.
pub fn measure<O: Output>(label: &str, expected: Option<O::Value>, operation: impl FnOnce() -> O) -> Outcome {
    let result = catch_quietly(|| {
        Circuit::scope("snapshot", || {
            let output = operation();
            let (a, b, c) = Circuit::num_nonzeros_in_scope();
            let shape = format!(
                "{} {} {} {} {a}/{b}/{c} {}",
                Circuit::num_constants_in_scope(),
                Circuit::num_public_in_scope(),
                Circuit::num_private_in_scope(),
                Circuit::num_constraints_in_scope(),
                render_mode(&output),
            );
            (shape, Circuit::is_satisfied_in_scope(), output.value())
        })
    });
    Circuit::reset();

    match (result, expected) {
        (None, None) => Outcome::Halt,
        (None, Some(expected)) => panic!("{label}: halted, expected {expected:?}"),
        (Some((shape, satisfied, value)), Some(expected)) => {
            assert!(satisfied, "{label}: unsatisfied, expected {expected:?}");
            assert_eq!(value, expected, "{label}: wrong value");
            Outcome::Done(shape)
        }
        (Some((shape, satisfied, _)), None) => {
            assert!(!satisfied, "{label}: satisfied, but the operation is undefined");
            Outcome::Done(shape)
        }
    }
}

/// Runs each closure on its own thread and concatenates the results in order.
///
/// Each thread has its own circuit, as the circuit is thread-local.
pub fn run_parallel(jobs: Vec<Box<dyn FnOnce() -> Vec<Case> + Send>>) -> Vec<Case> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs.into_iter().map(|job| scope.spawn(job)).collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_else(|error| panic::resume_unwind(error)))
            .collect()
    })
}

/// Returns the most frequent outcome of `cases` and its frequency, preferring the first one seen on a tie.
fn default_outcome(cases: &[Case]) -> (&Outcome, usize) {
    let mut tally: Vec<(&Outcome, usize)> = Vec::new();
    for case in cases {
        match tally.iter_mut().find(|(outcome, _)| **outcome == case.outcome) {
            Some((_, count)) => *count += 1,
            None => tally.push((&case.outcome, 1)),
        }
    }
    // `max_by_key` returns the last maximum, so the tally is reversed to prefer the first.
    tally.iter().rev().max_by_key(|(_, count)| *count).copied().unwrap_or((&Outcome::Halt, 0))
}

/// Splits `cases` into runs that share a block.
fn blocks(cases: &[Case]) -> Vec<&[Case]> {
    cases.chunk_by(|a, b| a.block == b.block).collect()
}

/// Renders the snapshot file of `op`.
fn render(op: &str, cases: &[Case]) -> String {
    let mut output = format!(
        "# Circuit shape of `{op}` for each integer type, operand mode and edge value.\n\
         # Line: <type.mode of each operand> <value of each constant operand, _ for a variable one, or *> : <result>\n\
         # A `_` stands for each value of a variable operand. The test checks that they give one result.\n\
         # Result: constants public private constraints nonzeros(A/B/C) output-mode, or halt.\n\
         # A mixed output mode counts the constant, public and private bits.\n\
         # The test also checks each case with the console operation. A defined case must give the console\n\
         # value in a satisfied circuit. An undefined case must halt or leave the circuit unsatisfied.\n\
         # A `*` line gives the result of each case of its block that has no line of its own.\n\
         # Regenerate: {UPDATE_VARIABLE}=1 cargo test -p snarkvm-circuit-types-integers --test snapshots\n"
    );
    for block in blocks(cases) {
        // A `*` line that stands for a single case would hide that case's values.
        let default = match default_outcome(block) {
            (outcome, count) if count > 1 => {
                output += &format!("{} * : {}\n", block[0].block, outcome.render());
                Some(outcome)
            }
            _ => None,
        };
        for case in block.iter().filter(|case| Some(&case.outcome) != default) {
            output += &format!("{} {} : {}\n", case.block, case.values, case.outcome.render());
        }
    }
    output
}

/// A parsed snapshot block: the default result and the result of each listed case.
struct StoredBlock<'a> {
    default: Option<&'a str>,
    cases: HashMap<&'a str, &'a str>,
}

/// Parses a snapshot file into its blocks, keyed by the block string.
fn parse(stored: &str, arity: usize) -> HashMap<String, StoredBlock<'_>> {
    let mut blocks: HashMap<String, StoredBlock> = HashMap::new();
    for line in stored.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let Some((key, result)) = line.split_once(" : ") else {
            panic!("malformed snapshot line: `{line}`");
        };
        // The block is the first `arity` tokens of the key; the values are the rest.
        let split = key.match_indices(' ').nth(arity - 1).map_or(key.len(), |(index, _)| index);
        let (block, values) = (&key[..split], key[split..].trim_start());
        let entry =
            blocks.entry(block.to_string()).or_insert_with(|| StoredBlock { default: None, cases: HashMap::new() });
        match values {
            "*" => entry.default = Some(result),
            _ => {
                entry.cases.insert(values, result);
            }
        }
    }
    blocks
}

/// Returns the number of merged cases whose stored result differs, and a description of the first one.
fn compare(stored: &str, arity: usize, cases: &[Case]) -> (usize, Option<String>) {
    let blocks = parse(stored, arity);
    let mut differences = Vec::new();
    let mut seen: HashSet<(&str, &str)> = HashSet::with_capacity(cases.len());
    for case in cases {
        seen.insert((case.block.as_str(), "*"));
        seen.insert((case.block.as_str(), case.values.as_str()));
        let found = case.outcome.render();
        let expected =
            blocks.get(&case.block).and_then(|block| block.cases.get(case.values.as_str()).copied().or(block.default));
        match expected {
            Some(expected) if expected == found => (),
            Some(expected) => {
                differences.push(format!("`{} {}`: stored `{expected}`, found `{found}`", case.block, case.values))
            }
            None => differences.push(format!("`{} {}`: not stored, found `{found}`", case.block, case.values)),
        }
    }
    let mut stale: Vec<String> = blocks
        .iter()
        .flat_map(|(block, stored)| {
            stored
                .default
                .map(|_| "*")
                .into_iter()
                .chain(stored.cases.keys().copied())
                .map(move |values| (block, values))
        })
        .filter(|(block, values)| !seen.contains(&(block.as_str(), *values)))
        .map(|(block, values)| format!("`{block} {values}`: stored, but not a case"))
        .collect();
    stale.sort();
    differences.extend(stale);
    (differences.len(), differences.into_iter().next())
}

/// Merges the cases that differ only in the values of variable operands.
///
/// Panics if such cases differ in outcome, as the shape of a circuit must not depend on a witness.
fn merge(op: &str, cases: Vec<Case>) -> Vec<Case> {
    let mut merged: Vec<Case> = Vec::with_capacity(cases.len());
    let mut index: HashMap<(String, String), usize> = HashMap::with_capacity(cases.len());
    for case in cases {
        match index.get(&(case.block.clone(), case.values.clone())) {
            Some(&i) => assert_eq!(
                merged[i].outcome, case.outcome,
                "`{op}`: `{} {}` depends on the value of a variable operand",
                case.block, case.values
            ),
            None => {
                index.insert((case.block.clone(), case.values.clone()), merged.len());
                merged.push(case);
            }
        }
    }
    merged
}

/// Compares the cases of `op` with `tests/snapshots/{op}.snap`, or rewrites the file if `UPDATE_VARIABLE` is `1`.
///
/// `arity` is the number of operands. `cases` must list the cases of each block together.
pub fn assert_snapshot(op: &str, arity: usize, cases: Vec<Case>) {
    let cases = &merge(op, cases);
    let rendered = render(op, cases);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots").join(format!("{op}.snap"));
    if std::env::var(UPDATE_VARIABLE).as_deref() == Ok("1") {
        fs::write(&path, rendered).unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        return;
    }

    let stored = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("cannot read {}: {error}. Run with {UPDATE_VARIABLE}=1 to create it.", path.display())
    });
    if stored == rendered {
        return;
    }
    let (differences, first) = compare(&stored, arity, cases);
    match first {
        Some(first) => panic!(
            "`{op}`: {differences} of {} merged cases differ from {}. First: {first}. \
             If the change is deliberate, run with {UPDATE_VARIABLE}=1 to rewrite the file.",
            cases.len(),
            path.display(),
        ),
        None => panic!(
            "`{op}`: {} has the same results in a different layout. Run with {UPDATE_VARIABLE}=1 to rewrite it.",
            path.display()
        ),
    }
}
