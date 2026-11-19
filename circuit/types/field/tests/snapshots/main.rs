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

//! Snapshot tests of the circuit shape of each field operation.
//!
//! Each test synthesizes one operation for every operand mode and a fixed set of field elements, and
//! compares the counts, output mode and structural digest with `snapshots/{op}.snap`.

use snarkvm_circuit_environment::{
    Circuit,
    prelude::*,
    snapshot::{self, Case, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel, value_label},
};
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_circuit_types_field::Field;
use snarkvm_console_types_field::Field as ConsoleField;

const FILES: SnapshotFiles = SnapshotFiles {
    directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots"),
    coverage: "each operand mode and a fixed set of field elements",
    command: "cargo test -p snarkvm-circuit-types-field --test snapshots",
};

/// A console field element.
type Console = ConsoleField<<Circuit as Environment>::Network>;

/// Returns `2^k`.
fn power(k: usize) -> Console {
    (0..k).fold(Console::one(), |power, _| power.double())
}

/// Removes the later duplicates of each value, sorts by value, and returns the values.
fn dedup_and_sort(mut values: Vec<(Console, String)>) -> Vec<(Console, String)> {
    values.sort_by_key(|(value, _)| *value);
    values.dedup_by_key(|(value, _)| *value);
    values
}

/// Returns 0, 1, 2, -2, -1 and the two elements around the middle of the field, with their labels.
///
/// `p` is the modulus, so `(p-1)/2` is `-1/2` and `(p+1)/2` is `1/2`.
fn values() -> Vec<(Console, String)> {
    let one = Console::one();
    let two = one.double();
    let half = Console::half();
    vec![
        (Console::zero(), "0".to_string()),
        (one, "1".to_string()),
        (two, "2".to_string()),
        (-half, "(p-1)/2".to_string()),
        (half, "(p+1)/2".to_string()),
        (-two, "-2".to_string()),
        (-one, "-1".to_string()),
    ]
}

/// Returns the values and the least quadratic non-residue, with their labels.
fn square_root_values() -> Vec<(Console, String)> {
    let non_residue = (2..)
        .map(|n| (n, Console::from_u64(n)))
        .find(|(_, value)| value.square_root().is_err())
        .map(|(n, value)| (value, n.to_string()));
    dedup_and_sort(values().into_iter().chain(non_residue).collect())
}

/// Returns 0, 1, `2^k-1`, `2^k` and -1 with their labels, without `2^k-1` and `2^k` if `k` is at least the size
/// of a field element.
fn lower_values(k: usize) -> Vec<(Console, String)> {
    let mut candidates = vec![(Console::zero(), "0".to_string()), (Console::one(), "1".to_string())];
    if k < Console::SIZE_IN_BITS {
        candidates.push((power(k) - Console::one(), format!("2^{k}-1")));
        candidates.push((power(k), format!("2^{k}")));
    }
    candidates.push((-Console::one(), "-1".to_string()));
    dedup_and_sort(candidates)
}

/// Returns 0, 1, -1, the least nonzero value with zero lower `n-k` bits, and the greatest one, with their labels.
///
/// `n` is the size of a field element. The greatest value is `p-1` with its lower `n-k` bits cleared.
fn upper_values(k: usize) -> Vec<(Console, String)> {
    let shift = Console::SIZE_IN_BITS.saturating_sub(k);
    let mut bits_le = (-Console::one()).to_bits_le();
    bits_le[..shift].fill(false);
    // Note: `expect` is safe as the bits are at most the bits of `p-1`.
    let greatest = Console::from_bits_le(&bits_le).expect("the bits are less than the modulus");
    dedup_and_sort(vec![
        (Console::zero(), "0".to_string()),
        (Console::one(), "1".to_string()),
        (-Console::one(), "-1".to_string()),
        (power(shift), format!("2^{shift}")),
        (greatest, format!("(p-1)>>{shift}<<{shift}")),
    ])
}

/// Returns the first `k` bits, or `None` if a later bit is set or there are fewer than `k` bits.
fn prefix(mut bits: Vec<bool>, k: usize) -> Option<Vec<bool>> {
    (k <= bits.len() && !bits.split_off(k).contains(&true)).then_some(bits)
}

/// Returns the lower `k` bits of `x` in little-endian order, or `None` if `x` does not fit in `k` bits.
fn lower_bits_le(x: Console, k: usize) -> Option<Vec<bool>> {
    prefix(x.to_bits_le(), k)
}

/// Returns the upper `k` bits of `x` in big-endian order, or `None` if a lower bit of `x` is set.
fn upper_bits_be(x: Console, k: usize) -> Option<Vec<bool>> {
    prefix(x.to_bits_be(), k)
}

/// Returns `bits` in reverse order.
fn reversed(mut bits: Vec<bool>) -> Vec<bool> {
    bits.reverse();
    bits
}

/// Returns `n` little-endian bits with their labels: 0, 1, and the greatest value if `n` is less than the size
/// of a field element; otherwise 0, 1, -1, `p`, and with more bits than a field element, the lowest excess bit.
fn bits_values(n: usize) -> Vec<(Vec<bool>, String)> {
    let size = Console::SIZE_IN_BITS;
    let bits_of = |value: Console| -> Vec<bool> {
        let mut bits_le = value.to_bits_le();
        bits_le.resize(n, false);
        bits_le
    };
    let mut values = vec![(bits_of(Console::zero()), "0".to_string()), (bits_of(Console::one()), "1".to_string())];
    if n < size {
        values.push((vec![true; n], format!("2^{n}-1")));
    } else {
        values.push((bits_of(-Console::one()), "-1".to_string()));
        let mut modulus = <Circuit as Environment>::BaseField::modulus().to_bits_le();
        modulus.resize(n, false);
        values.push((modulus, "p".to_string()));
        if n > size {
            let mut excess = vec![false; n];
            excess[size] = true;
            values.push((excess, format!("2^{size}")));
        }
    }
    values
}

/// Defines a snapshot test of a unary operation.
macro_rules! unary_snapshot {
    ($op:ident, $values:expr, |$a:ident| $circuit:expr, |$x:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 1]) -> Vec<Case> {
                snapshot::unary(|$a: &Field<Circuit>| $circuit, |$x: Console| $console, None, &$values, modes)
            }
            assert_snapshot(&FILES, stringify!($op), run_parallel(mode_jobs(1, cases)));
        }
    };
}

/// Defines a snapshot test of a binary operation on two field elements.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 2]) -> Vec<Case> {
                let values = Values::same(values());
                snapshot::binary(
                    |$a: &Field<Circuit>, $b: &Field<Circuit>| $circuit,
                    |$x: Console, $y: Console| $console,
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

/// Returns the cases of an operation that takes a field element and a bit count `k`, one per value.
fn bit_count_cases(
    k: usize,
    operation: impl Fn(&Field<Circuit>, usize) -> Vec<Boolean<Circuit>>,
    oracle: impl Fn(Console, usize) -> Option<Vec<bool>>,
    values: &[(Console, String)],
    [mode]: [Mode; 1],
) -> Vec<Case> {
    let block = format!("{}.{mode} k={k}", Field::<Circuit>::type_name());
    values
        .iter()
        .map(|(x, label)| {
            Circuit::reset();
            let a = Field::<Circuit>::new(mode, *x);
            let outcome = snapshot::measure(&format!("{block} {label}"), oracle(*x, k), None, || operation(&a, k));
            Case { block: block.clone(), values: value_label(mode, label).to_string(), outcome }
        })
        .collect()
}

/// Defines a snapshot test of an operation that takes a bit count, for each of the given bit counts.
///
/// `$values` returns the values for a bit count.
macro_rules! bit_count_snapshot {
    ($op:ident, [$($k:literal),+], $values:path, |$x:ident, $count:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases<const K: usize>(modes: [Mode; 1]) -> Vec<Case> {
                bit_count_cases(K, |a, k| a.$op(k), |$x, $count| $console, &$values(K), modes)
            }
            let jobs = [$(mode_jobs($k, cases::<$k>)),+];
            assert_snapshot(&FILES, stringify!($op), run_parallel(jobs.into_iter().flatten()));
        }
    };
}

/// Defines a snapshot test of an operation that recovers a field element from bits, for each of the given numbers
/// of bits.
///
/// `$order` maps little-endian bits to the order that the operation takes. Every bit has the same mode.
macro_rules! from_bits_snapshot {
    ($op:ident, [$($n:literal),+], $order:expr) => {
        #[test]
        fn $op() {
            fn cases<const N: usize>([mode]: [Mode; 1]) -> Vec<Case> {
                let block = format!("{}[{N}].{mode}", Boolean::<Circuit>::type_name());
                bits_values(N)
                    .into_iter()
                    .map(|(bits_le, label)| {
                        Circuit::reset();
                        let expected = Console::from_bits_le(&bits_le).ok();
                        let bits: Vec<Boolean<Circuit>> = Inject::new(mode, $order(bits_le));
                        let outcome =
                            snapshot::measure(&format!("{block} {label}"), expected, None, || Field::$op(&bits));
                        Case { block: block.clone(), values: value_label(mode, &label).to_string(), outcome }
                    })
                    .collect()
            }
            let jobs = [$(mode_jobs($n, cases::<$n>)),+];
            assert_snapshot(&FILES, stringify!($op), run_parallel(jobs.into_iter().flatten()));
        }
    };
}

/// Defines a snapshot test of an operation that takes no operands and returns a constant.
macro_rules! nullary_snapshot {
    ($op:ident, $expected:expr) => {
        #[test]
        fn $op() {
            Circuit::reset();
            let outcome = snapshot::measure(stringify!($op), Some($expected), None, Field::<Circuit>::$op);
            assert_snapshot(&FILES, stringify!($op), vec![Case {
                block: "()".to_string(),
                values: "()".to_string(),
                outcome,
            }]);
        }
    };
}

// Arithmetic.
binary_snapshot!(add, |a, b| a + b, |x, y| Some(x + y));
binary_snapshot!(sub, |a, b| a - b, |x, y| Some(x - y));
binary_snapshot!(mul, |a, b| a * b, |x, y| Some(x * y));
binary_snapshot!(div, |a, b| a / b, |x, y| (!y.is_zero()).then(|| x / y));
binary_snapshot!(pow, |a, b| a.pow(b), |x, y| Some(x.pow(y)));
unary_snapshot!(double, values(), |a| a.double(), |x| Some(x.double()));
unary_snapshot!(square, values(), |a| a.square(), |x| Some(x.square()));
unary_snapshot!(inverse, values(), |a| a.inverse(), |x| x.inverse().ok());
unary_snapshot!(neg, values(), |a| -a, |x| Some(-x));
unary_snapshot!(square_root, square_root_values(), |a| a.square_root(), |x| x.square_root().ok());
unary_snapshot!(even_square_root, square_root_values(), |a| a.even_square_root(), |x| x.even_square_root().ok());

/// Covers each pair of values. Division by zero is undefined, except that `0 / 0` on two variables gives a
/// satisfied circuit for any quotient, and the circuit returns 0.
#[test]
fn div_unchecked() {
    fn cases(modes: [Mode; 2]) -> Vec<Case> {
        let both_variable = modes.iter().all(|mode| !mode.is_constant());
        let values = Values::same(values());
        snapshot::binary(
            |a: &Field<Circuit>, b: &Field<Circuit>| a.div_unchecked(b),
            |x: Console, y: Console| match (x.is_zero(), y.is_zero()) {
                (_, false) => Some(x / y),
                (true, true) if both_variable => Some(Console::zero()),
                _ => None,
            },
            None,
            &values,
            &values,
            modes,
        )
    }
    assert_snapshot(&FILES, "div_unchecked", run_parallel(mode_jobs(1, cases)));
}

// Comparisons.
binary_snapshot!(is_equal, |a, b| a.is_equal(b), |x, y| Some(*x.is_equal(&y)));
binary_snapshot!(is_not_equal, |a, b| a.is_not_equal(b), |x, y| Some(*x.is_not_equal(&y)));
binary_snapshot!(is_less_than, |a, b| a.is_less_than(b), |x, y| Some(*x.is_less_than(&y)));
binary_snapshot!(is_less_than_or_equal, |a, b| a.is_less_than_or_equal(b), |x, y| Some(*x.is_less_than_or_equal(&y)));
binary_snapshot!(is_greater_than, |a, b| a.is_greater_than(b), |x, y| Some(*x.is_greater_than(&y)));
binary_snapshot!(is_greater_than_or_equal, |a, b| a.is_greater_than_or_equal(b), |x, y| Some(
    *x.is_greater_than_or_equal(&y)
));
unary_snapshot!(is_zero, values(), |a| a.is_zero(), |x| Some(x.is_zero()));
unary_snapshot!(is_one, values(), |a| a.is_one(), |x| Some(x.is_one()));

#[test]
fn ternary() {
    fn cases(modes: [Mode; 3]) -> Vec<Case> {
        snapshot::ternary(
            |c: &Boolean<Circuit>, a: &Field<Circuit>, b: &Field<Circuit>| Field::ternary(c, a, b),
            None,
            &values(),
            modes,
        )
    }
    assert_snapshot(&FILES, "ternary", run_parallel(mode_jobs(1, cases)));
}

// Bits.
unary_snapshot!(to_bits_le, values(), |a| a.to_bits_le(), |x| Some(x.to_bits_le()));
unary_snapshot!(to_bits_be, values(), |a| a.to_bits_be(), |x| Some(x.to_bits_be()));
bit_count_snapshot!(to_lower_bits_le, [8, 16, 32, 64, 128, 251, 252, 253, 254], lower_values, |x, k| lower_bits_le(
    x, k
));
bit_count_snapshot!(to_lower_bits_be, [8, 16, 32, 64, 128, 251, 252, 253, 254], lower_values, |x, k| lower_bits_le(
    x, k
)
.map(reversed));
bit_count_snapshot!(to_upper_bits_le, [1, 9, 17, 33, 65, 129, 251, 252, 253, 254], upper_values, |x, k| upper_bits_be(
    x, k
)
.map(reversed));
bit_count_snapshot!(to_upper_bits_be, [1, 9, 17, 33, 65, 129, 251, 252, 253, 254], upper_values, |x, k| upper_bits_be(
    x, k
));
from_bits_snapshot!(from_bits_le, [8, 252, 253, 254], |bits| bits);
from_bits_snapshot!(from_bits_be, [8, 252, 253, 254], reversed);

#[test]
fn from_boolean() {
    fn cases(modes: [Mode; 1]) -> Vec<Case> {
        snapshot::unary(
            |a: &Boolean<Circuit>| Field::from_boolean(a),
            |x: bool| Some(if x { Console::one() } else { Console::zero() }),
            None,
            &[(false, "false".to_string()), (true, "true".to_string())],
            modes,
        )
    }
    assert_snapshot(&FILES, "from_boolean", run_parallel(mode_jobs(1, cases)));
}

// Constants.
nullary_snapshot!(one, Console::one());
nullary_snapshot!(zero, Console::zero());
