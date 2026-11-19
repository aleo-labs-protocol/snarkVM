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

//! Snapshot tests of circuit shape.
//!
//! A test synthesizes an operation for each case, records the counts, nonzeros, output mode and a
//! structural digest of the constraints, and compares them with a checked-in snapshot file.

use std::{
    cell::Cell,
    collections::{HashMap, HashSet, hash_map::Entry},
    fmt::Debug,
    fs,
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    path::Path,
    sync::{Condvar, Mutex, Once, PoisonError},
    thread,
};

use itertools::Itertools;

use crate::{Circuit, Eject, Environment, Inject, Mode, prelude::TypeName};

/// The variable that makes `assert_snapshot` rewrite the snapshot files.
const UPDATE_VARIABLE: &str = "UPDATE_CIRCUIT_SNAPSHOTS";

/// The snapshot files of a test target.
pub struct SnapshotFiles {
    /// The directory of the files, such as `concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots")`.
    pub directory: &'static str,
    /// What each file covers, such as `each integer type, operand mode and edge value`.
    pub coverage: &'static str,
    /// The command that runs the tests, such as `cargo test -p snarkvm-circuit-types-integers --test snapshots`.
    pub command: &'static str,
}

/// One case of an operation.
pub struct Case {
    /// The type and mode of each operand, such as `u8.constant u8.private`.
    pub block: String,
    /// The label of each constant operand value, or `_` for a variable operand, such as `MAX _`.
    pub values: String,
    /// The counts, output mode and digest of the synthesized circuit, or `halt`.
    pub outcome: String,
}

/// A job that returns the cases of one block.
pub struct Job {
    /// The relative cost of the job. The pool starts the costliest jobs first.
    cost: u64,
    run: Box<dyn FnOnce() -> Vec<Case> + Send>,
}

/// The values of an operand when it is a constant and when it is a variable.
pub struct Values<P> {
    pub constant: Vec<(P, String)>,
    pub variable: Vec<(P, String)>,
}

impl<P> Values<P> {
    fn for_mode(&self, mode: Mode) -> &[(P, String)] {
        match mode {
            Mode::Constant => &self.constant,
            _ => &self.variable,
        }
    }
}

/// Returns the label of an operand in `Case::values`.
fn value_label(mode: Mode, label: &str) -> &str {
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

/// Returns the mode of `output`, with a count per mode if `bit_modes` gives bits that differ in mode.
fn render_mode<O: Eject>(output: &O, bit_modes: Option<fn(&O) -> Vec<Mode>>) -> String {
    let Some(modes) = bit_modes.map(|bit_modes| bit_modes(output)) else {
        return output.eject_mode().to_string();
    };
    let count = |mode| modes.iter().filter(|m| **m == mode).count();
    let combined = Mode::combine(Mode::Constant, modes.iter().copied());
    match modes.iter().all(|mode| *mode == combined) {
        true => combined.to_string(),
        false => {
            format!("{combined}[c{}/u{}/p{}]", count(Mode::Constant), count(Mode::Public), count(Mode::Private))
        }
    }
}

/// Synthesizes `operation`, then resets the circuit.
///
/// The caller injects the operands before the call, so the counts and the digest cover the operation alone.
/// `expected` is the console result, or `None` if the operation is undefined for the operands.
/// `bit_modes`, if given, returns the mode of each bit of the output. It runs after the circuit is reset,
/// so any constraint it adds does not reach the counts or the digest.
/// Panics if a defined case does not produce `expected` in a satisfied circuit,
/// or if an undefined case gives a satisfied circuit.
pub fn measure<O: Eject>(
    label: &str,
    expected: Option<O::Primitive>,
    bit_modes: Option<fn(&O) -> Vec<Mode>>,
    operation: impl FnOnce() -> O,
) -> String
where
    O::Primitive: Debug + PartialEq,
{
    let first_constant = Circuit::num_constants();
    let first_public = Circuit::num_public();
    let first_private = Circuit::num_private();
    let first_constraint = Circuit::num_constraints();
    let first_nonzeros = Circuit::num_nonzeros();
    let result = catch_quietly(operation).map(|output| {
        let nonzeros = Circuit::num_nonzeros();
        let counts = format!(
            "{} {} {} {} {}/{}/{}",
            Circuit::num_constants() - first_constant,
            Circuit::num_public() - first_public,
            Circuit::num_private() - first_private,
            Circuit::num_constraints() - first_constraint,
            nonzeros.0 - first_nonzeros.0,
            nonzeros.1 - first_nonzeros.1,
            nonzeros.2 - first_nonzeros.2,
        );
        (counts, output)
    });
    let r1cs = Circuit::eject_r1cs_and_reset();
    let result = result.map(|(counts, output)| {
        let skip = usize::try_from(first_constraint).unwrap_or(usize::MAX);
        let satisfied = r1cs.to_constraints().iter().skip(skip).all(|constraint| constraint.is_satisfied());
        let digest = r1cs.structural_digest(first_constraint, first_public, first_private);
        // Note: `expect` is safe as the digest has 32 bytes.
        let prefix = u64::from_be_bytes(digest[..8].try_into().expect("the digest has 32 bytes"));
        let mode = render_mode(&output, bit_modes);
        (format!("{counts} {mode} {prefix:016x}"), satisfied, output.eject_value())
    });
    Circuit::reset();

    match (result, expected) {
        (None, None) => "halt".to_string(),
        (None, Some(expected)) => panic!("{label}: halted, expected {expected:?}"),
        (Some((shape, satisfied, value)), Some(expected)) => {
            assert!(satisfied, "{label}: unsatisfied, expected {expected:?}");
            assert_eq!(value, expected, "{label}: wrong value");
            shape
        }
        (Some((shape, satisfied, _)), None) => {
            assert!(!satisfied, "{label}: satisfied, but the operation is undefined");
            shape
        }
    }
}

/// Returns the cases of a unary operation on an operand of the given mode, one per value.
pub fn unary<A, O>(
    operation: impl Fn(&A) -> O,
    oracle: impl Fn(A::Primitive) -> Option<O::Primitive>,
    bit_modes: Option<fn(&O) -> Vec<Mode>>,
    values: &[(A::Primitive, String)],
    [mode]: [Mode; 1],
) -> Vec<Case>
where
    A: Inject + TypeName,
    A::Primitive: Clone,
    O: Eject,
    O::Primitive: Debug + PartialEq,
{
    let block = format!("{}.{mode}", A::type_name());
    values
        .iter()
        .map(|(x, label)| {
            Circuit::reset();
            let a = A::new(mode, x.clone());
            let outcome = measure(&format!("{block} {label}"), oracle(x.clone()), bit_modes, || operation(&a));
            Case { block: block.clone(), values: value_label(mode, label).to_string(), outcome }
        })
        .collect()
}

/// Returns the cases of a binary operation on operands of the given modes, one per pair of values.
pub fn binary<A, B, O>(
    operation: impl Fn(&A, &B) -> O,
    oracle: impl Fn(A::Primitive, B::Primitive) -> Option<O::Primitive>,
    bit_modes: Option<fn(&O) -> Vec<Mode>>,
    lhs: &Values<A::Primitive>,
    rhs: &Values<B::Primitive>,
    [mode_a, mode_b]: [Mode; 2],
) -> Vec<Case>
where
    A: Inject + TypeName,
    A::Primitive: Clone,
    B: Inject + TypeName,
    B::Primitive: Clone,
    O: Eject,
    O::Primitive: Debug + PartialEq,
{
    let block = format!("{}.{mode_a} {}.{mode_b}", A::type_name(), B::type_name());
    let (lhs, rhs) = (lhs.for_mode(mode_a), rhs.for_mode(mode_b));
    let mut cases = Vec::with_capacity(lhs.len() * rhs.len());
    for (x, label_x) in lhs {
        for (y, label_y) in rhs {
            Circuit::reset();
            let a = A::new(mode_a, x.clone());
            let b = B::new(mode_b, y.clone());
            let label = format!("{block} {label_x} {label_y}");
            let outcome = measure(&label, oracle(x.clone(), y.clone()), bit_modes, || operation(&a, &b));
            let values = format!("{} {}", value_label(mode_a, label_x), value_label(mode_b, label_y));
            cases.push(Case { block: block.clone(), values, outcome });
        }
    }
    cases
}

/// Returns the cases of a ternary operation on a condition and two operands of the given modes,
/// one per condition and pair of values.
pub fn ternary<C, A>(
    operation: impl Fn(&C, &A, &A) -> A,
    bit_modes: Option<fn(&A) -> Vec<Mode>>,
    values: &[(<A as Inject>::Primitive, String)],
    [mode_c, mode_a, mode_b]: [Mode; 3],
) -> Vec<Case>
where
    C: Inject<Primitive = bool> + TypeName,
    A: Inject + Eject<Primitive = <A as Inject>::Primitive> + TypeName,
    <A as Inject>::Primitive: Clone + Debug + PartialEq,
{
    let block = format!("{}.{mode_c} {}.{mode_a} {}.{mode_b}", C::type_name(), A::type_name(), A::type_name());
    let mut cases = Vec::with_capacity(2 * values.len() * values.len());
    for condition in [false, true] {
        for (x, label_x) in values {
            for (y, label_y) in values {
                Circuit::reset();
                let c = C::new(mode_c, condition);
                let a = A::new(mode_a, x.clone());
                let b = A::new(mode_b, y.clone());
                let label = format!("{block} {condition} {label_x} {label_y}");
                let expected = Some(if condition { x.clone() } else { y.clone() });
                let outcome = measure(&label, expected, bit_modes, || operation(&c, &a, &b));
                let values = format!(
                    "{} {} {}",
                    value_label(mode_c, &condition.to_string()),
                    value_label(mode_a, label_x),
                    value_label(mode_b, label_y)
                );
                cases.push(Case { block: block.clone(), values, outcome });
            }
        }
    }
    cases
}

/// Returns one job per combination of `N` operand modes, in lexicographic order of the modes.
///
/// Each job calls `block` with its modes. Its cost is `cost`, doubled for each variable operand.
pub fn mode_jobs<const N: usize>(cost: u64, block: fn([Mode; N]) -> Vec<Case>) -> impl Iterator<Item = Job> {
    (0..N).map(|_| [Mode::Constant, Mode::Public, Mode::Private]).multi_cartesian_product().map(move |modes| {
        // Note: `expect` is safe as each combination has one mode per operand.
        let modes: [Mode; N] = modes.try_into().expect("each combination has `N` modes");
        let variables = modes.iter().filter(|mode| !mode.is_constant()).count();
        Job { cost: cost << variables, run: Box::new(move || block(modes)) }
    })
}

/// The number of threads that run the jobs of one test.
///
/// `.config/nextest.toml` reserves as many threads for each snapshot test. Keep the two equal.
const WORKERS: usize = 8;

/// The number of jobs that run in this process, across tests.
static RUNNING: Mutex<usize> = Mutex::new(0);
/// Signals that a job finished.
static FINISHED: Condvar = Condvar::new();

/// A slot in the limit on the jobs that run in this process at once.
struct Slot;

impl Slot {
    /// Waits until fewer jobs than the available parallelism run in this process, then takes a slot.
    fn take() -> Self {
        let limit = thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let mut running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner);
        while *running >= limit {
            running = FINISHED.wait(running).unwrap_or_else(PoisonError::into_inner);
        }
        *running += 1;
        Self
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        *RUNNING.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
        FINISHED.notify_one();
    }
}

/// Runs the jobs on a pool of `WORKERS` threads, costliest first, and concatenates their results in the
/// order of the jobs.
///
/// Each thread has its own circuit, as the circuit is thread-local. `cargo test` runs tests as threads of
/// one process, so the jobs of all tests share a limit of the available parallelism.
pub fn run_parallel(jobs: impl IntoIterator<Item = Job>) -> Vec<Case> {
    let mut jobs: Vec<(usize, Job)> = jobs.into_iter().enumerate().collect();
    jobs.sort_by_key(|(_, job)| std::cmp::Reverse(job.cost));
    let workers = WORKERS.min(jobs.len()).max(1);
    let queue = Mutex::new(jobs.into_iter());
    // A failed job empties the queue, so the test reports without running the remaining jobs.
    let next = || queue.lock().unwrap_or_else(PoisonError::into_inner).next();
    let mut results: Vec<(usize, Vec<Case>)> = thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    std::iter::from_fn(next)
                        .map(|(index, job)| {
                            let _slot = Slot::take();
                            let cases = panic::catch_unwind(AssertUnwindSafe(job.run)).unwrap_or_else(|error| {
                                queue.lock().unwrap_or_else(PoisonError::into_inner).by_ref().for_each(drop);
                                panic::resume_unwind(error)
                            });
                            (index, cases)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_else(|error| panic::resume_unwind(error)))
            .collect()
    });
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().flat_map(|(_, cases)| cases).collect()
}

/// Returns the most frequent outcome of `cases` and its frequency, preferring the first one seen on a tie.
fn default_outcome(cases: &[Case]) -> Option<(&str, usize)> {
    let mut tally: Vec<(&str, usize)> = Vec::new();
    for case in cases {
        match tally.iter_mut().find(|(outcome, _)| *outcome == case.outcome) {
            Some((_, count)) => *count += 1,
            None => tally.push((&case.outcome, 1)),
        }
    }
    // `max_by_key` returns the last maximum, so the tally is reversed to prefer the first.
    tally.into_iter().rev().max_by_key(|(_, count)| *count)
}

/// Renders the snapshot file of `op`.
fn render(files: &SnapshotFiles, op: &str, cases: &[Case]) -> String {
    let mut output = format!(
        "# Circuit shape of `{op}` for {}.\n\
         # Line: <type.mode of each operand> | <value of each constant operand, _ for a variable one, or *> : <result>\n\
         # A `_` stands for each value of a variable operand. The test checks that they give one result.\n\
         # Result: constants public private constraints nonzeros(A/B/C) output-mode digest, or halt.\n\
         # The digest is the first 64 bits of a SHA-256 hash of the constraint structure: the order of the constraints, and the constant,\n\
         # coefficients and variables of each linear combination.\n\
         # A mixed output mode counts the constant, public and private bits.\n\
         # The test also checks each case with the console operation. A defined case must give the console\n\
         # value in a satisfied circuit. An undefined case must halt or leave the circuit unsatisfied.\n\
         # A `*` line gives the result of each case of its block that has no line of its own.\n\
         # Regenerate: {UPDATE_VARIABLE}=1 {}\n",
        files.coverage, files.command
    );
    for block in cases.chunk_by(|a, b| a.block == b.block) {
        // A `*` line that stands for a single case would hide that case's values.
        let default = match default_outcome(block) {
            Some((outcome, count)) if count > 1 => {
                output += &format!("{} | * : {outcome}\n", block[0].block);
                Some(outcome)
            }
            _ => None,
        };
        for case in block.iter().filter(|case| Some(case.outcome.as_str()) != default) {
            output += &format!("{} | {} : {}\n", case.block, case.values, case.outcome);
        }
    }
    output
}

/// A parsed snapshot block: the default result and the result of each listed case.
#[derive(Default)]
struct StoredBlock<'a> {
    default: Option<&'a str>,
    cases: HashMap<&'a str, &'a str>,
}

/// Parses a snapshot file into its blocks, keyed by the block string.
fn parse(stored: &str) -> HashMap<&str, StoredBlock<'_>> {
    let mut blocks: HashMap<&str, StoredBlock> = HashMap::new();
    for line in stored.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let Some(((block, values), result)) =
            line.split_once(" : ").and_then(|(key, result)| Some((key.split_once(" | ")?, result)))
        else {
            panic!("malformed snapshot line: `{line}`. Rewrite the file with {UPDATE_VARIABLE}=1.");
        };
        let entry = blocks.entry(block).or_default();
        match values {
            "*" => entry.default = Some(result),
            _ => {
                entry.cases.insert(values, result);
            }
        }
    }
    blocks
}

/// Returns a description of each merged case whose stored result differs, in the order of the cases,
/// then of each stored case that is no longer a case.
fn compare(stored: &str, cases: &[Case]) -> Vec<String> {
    let blocks = parse(stored);
    let mut differences = Vec::new();
    let mut seen: HashSet<(&str, &str)> = HashSet::with_capacity(cases.len());
    for case in cases {
        seen.insert((case.block.as_str(), "*"));
        seen.insert((case.block.as_str(), case.values.as_str()));
        let found = case.outcome.as_str();
        let expected = blocks
            .get(case.block.as_str())
            .and_then(|block| block.cases.get(case.values.as_str()).copied().or(block.default));
        match expected {
            Some(expected) if expected == found => (),
            Some(expected) => {
                differences.push(format!("`{} | {}`: stored `{expected}`, found `{found}`", case.block, case.values))
            }
            None => differences.push(format!("`{} | {}`: not stored, found `{found}`", case.block, case.values)),
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
                .map(move |values| (*block, values))
        })
        .filter(|key| !seen.contains(key))
        .map(|(block, values)| format!("`{block} | {values}`: stored, but not a case"))
        .collect();
    stale.sort();
    differences.extend(stale);
    differences
}

/// Merges the cases that differ only in the values of variable operands.
///
/// Panics if such cases differ in outcome, as the shape of a circuit must not depend on a witness.
fn merge(op: &str, cases: Vec<Case>) -> Vec<Case> {
    let mut merged: Vec<Case> = Vec::with_capacity(cases.len());
    let mut index: HashMap<(String, String), usize> = HashMap::with_capacity(cases.len());
    for case in cases {
        match index.entry((case.block.clone(), case.values.clone())) {
            Entry::Occupied(entry) => assert_eq!(
                merged[*entry.get()].outcome,
                case.outcome,
                "`{op}`: `{} | {}` depends on the value of a variable operand",
                case.block,
                case.values
            ),
            Entry::Vacant(entry) => {
                entry.insert(merged.len());
                merged.push(case);
            }
        }
    }
    merged
}

/// Compares the cases of `op` with `{op}.snap` in `files.directory`, or rewrites the file if `UPDATE_VARIABLE` is `1`.
///
/// `cases` must list the cases of each block together.
pub fn assert_snapshot(files: &SnapshotFiles, op: &str, cases: Vec<Case>) {
    let cases = &merge(op, cases);
    let rendered = render(files, op, cases);
    let path = Path::new(files.directory).join(format!("{op}.snap"));
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
    let differences = compare(&stored, cases);
    match differences.first() {
        Some(first) => panic!(
            "`{op}`: {} of {} merged cases differ from {}. First: {first}. \
             If the change is deliberate, run with {UPDATE_VARIABLE}=1 to rewrite the file.",
            differences.len(),
            cases.len(),
            path.display(),
        ),
        None => panic!(
            "`{op}`: {} has the same results in a different layout. Run with {UPDATE_VARIABLE}=1 to rewrite it.",
            path.display()
        ),
    }
}
