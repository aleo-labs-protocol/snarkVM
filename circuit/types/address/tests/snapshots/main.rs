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

//! Snapshot tests of the circuit shape of each address operation.
//!
//! Each test synthesizes one operation for every operand mode and a fixed set of addresses, and compares
//! the counts, output mode and structural digest with `snapshots/{op}.snap`.

use snarkvm_circuit_environment::{
    Circuit,
    prelude::*,
    snapshot::{self, SnapshotFiles},
    snapshot_files,
};
use snarkvm_circuit_types_address::Address;
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_console_types_address::{Address as ConsoleAddress, Group as ConsoleGroup, TestRng, Uniform};

const FILES: SnapshotFiles = snapshot_files!("each operand mode and a fixed set of addresses");

/// A console address.
type Console = ConsoleAddress<<Circuit as Environment>::Network>;

/// Returns the zero address, the generator and two addresses sampled from a fixed seed, with their labels.
fn values() -> Vec<(Console, String)> {
    let rng = &mut TestRng::from_seed(0);
    vec![
        (Console::zero(), "zero".to_string()),
        (Console::new(ConsoleGroup::generator()), "generator".to_string()),
        (Uniform::rand(rng), "sampled-1".to_string()),
        (Uniform::rand(rng), "sampled-2".to_string()),
    ]
}

/// Defines a snapshot test of a binary operation that returns a boolean.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            let operation = |$a: &Address<Circuit>, $b: &Address<Circuit>| -> Boolean<Circuit> { $circuit };
            let oracle = |$x: Console, $y: Console| Some(*$console);
            snapshot::assert_binary(&FILES, stringify!($op), values, values, operation, oracle);
        }
    };
}

binary_snapshot!(is_equal, |a, b| a.is_equal(b), |x, y| x.is_equal(&y));
binary_snapshot!(is_not_equal, |a, b| a.is_not_equal(b), |x, y| x.is_not_equal(&y));
binary_snapshot!(is_less_than, |a, b| a.is_less_than(b), |x, y| x.is_less_than(&y));
binary_snapshot!(is_less_than_or_equal, |a, b| a.is_less_than_or_equal(b), |x, y| x.is_less_than_or_equal(&y));
binary_snapshot!(is_greater_than, |a, b| a.is_greater_than(b), |x, y| x.is_greater_than(&y));
binary_snapshot!(is_greater_than_or_equal, |a, b| a.is_greater_than_or_equal(b), |x, y| x.is_greater_than_or_equal(&y));

#[test]
fn ternary() {
    snapshot::assert_ternary(&FILES, "ternary", values, |c: &Boolean<Circuit>, a: &Address<Circuit>, b| {
        Address::ternary(c, a, b)
    });
}
