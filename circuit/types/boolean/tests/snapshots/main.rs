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

//! Snapshot tests of the circuit shape of each boolean operation.
//!
//! Each test synthesizes one operation for every operand mode and value, and compares the counts,
//! output mode and structural digest with `snapshots/{op}.snap`.

use snarkvm_circuit_environment::{
    Circuit,
    prelude::*,
    snapshot::{self, Case, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel},
};
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_console_types_boolean::Boolean as ConsoleBoolean;

const FILES: SnapshotFiles = SnapshotFiles {
    directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots"),
    coverage: "each operand mode and value",
    command: "cargo test -p snarkvm-circuit-types-boolean --test snapshots",
};

/// A console boolean.
type Console = ConsoleBoolean<<Circuit as Environment>::Network>;

/// Returns both boolean values with their labels.
fn values() -> Vec<(bool, String)> {
    vec![(false, "false".to_string()), (true, "true".to_string())]
}

/// Defines a snapshot test of a binary operation.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 2]) -> Vec<Case> {
                let values = Values::same(values());
                snapshot::binary(
                    |$a: &Boolean<Circuit>, $b: &Boolean<Circuit>| $circuit,
                    |$x: bool, $y: bool| {
                        let ($x, $y) = (Console::new($x), Console::new($y));
                        Some(*$console)
                    },
                    None,
                    &values,
                    &values,
                    modes,
                )
            }
            assert_snapshot(&FILES, stringify!($op), run_parallel(mode_jobs(1, cases)));
        }
    };
}

binary_snapshot!(and, |a, b| a & b, |x, y| x & y);
binary_snapshot!(or, |a, b| a | b, |x, y| x | y);
binary_snapshot!(nand, |a, b| a.nand(b), |x, y| x.nand(&y));
binary_snapshot!(nor, |a, b| a.nor(b), |x, y| x.nor(&y));
binary_snapshot!(xor, |a, b| a ^ b, |x, y| x ^ y);
binary_snapshot!(is_equal, |a, b| a.is_equal(b), |x, y| x.is_equal(&y));
binary_snapshot!(is_not_equal, |a, b| a.is_not_equal(b), |x, y| x.is_not_equal(&y));

#[test]
fn not() {
    fn cases(modes: [Mode; 1]) -> Vec<Case> {
        snapshot::unary(|a: &Boolean<Circuit>| !a, |x: bool| Some(*!Console::new(x)), None, &values(), modes)
    }
    assert_snapshot(&FILES, "not", run_parallel(mode_jobs(1, cases)));
}

#[test]
fn ternary() {
    fn cases(modes: [Mode; 3]) -> Vec<Case> {
        snapshot::ternary(
            |c: &Boolean<Circuit>, a: &Boolean<Circuit>, b: &Boolean<Circuit>| Boolean::ternary(c, a, b),
            None,
            &values(),
            modes,
        )
    }
    assert_snapshot(&FILES, "ternary", run_parallel(mode_jobs(1, cases)));
}
