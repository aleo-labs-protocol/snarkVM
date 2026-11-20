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

//! Snapshot tests of the circuit shape of each scalar operation.
//!
//! Each test synthesizes one operation for every operand mode and a fixed set of scalars, and compares
//! the counts, output mode and structural digest with `snapshots/{op}.snap`.

use snarkvm_circuit_environment::{
    Circuit,
    prelude::*,
    snapshot::{self, Array, Case, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel},
};
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_circuit_types_field::Field;
use snarkvm_circuit_types_scalar::Scalar;
use snarkvm_console_types_scalar::{Field as ConsoleField, FromField as _, Scalar as ConsoleScalar};

const FILES: SnapshotFiles = SnapshotFiles {
    directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots"),
    coverage: "each operand mode and a fixed set of scalars",
    command: "cargo test -p snarkvm-circuit-types-scalar --test snapshots",
};

/// A console scalar.
type Console = ConsoleScalar<<Circuit as Environment>::Network>;

/// A console base field element.
type Base = ConsoleField<<Circuit as Environment>::Network>;

/// Returns 0, 1, 2, -2, -1 and the two scalars around the middle of the scalar field, with their labels.
///
/// `r` is the modulus of the scalar field, so `(r-1)/2` is `-1/2` and `(r+1)/2` is `1/2`.
fn values() -> Vec<(Console, String)> {
    let one = Console::one();
    let two = one.double();
    let half = one / two;
    vec![
        (Console::zero(), "0".to_string()),
        (one, "1".to_string()),
        (two, "2".to_string()),
        (-half, "(r-1)/2".to_string()),
        (half, "(r+1)/2".to_string()),
        (-two, "-2".to_string()),
        (-one, "-1".to_string()),
    ]
}

/// Returns 0, 1, `r-1`, `r`, `2^251` and `p-1` as base field elements, with their labels.
///
/// `p` is the modulus of the base field.
fn field_values() -> Vec<(Base, String)> {
    let modulus_bits_le = <Circuit as Environment>::ScalarField::modulus().to_bits_le();
    // Note: `expect` is safe as the scalar field modulus is less than the base field modulus.
    let modulus = Base::from_bits_le(&modulus_bits_le).expect("the scalar field modulus is a base field element");
    vec![
        (Base::zero(), "0".to_string()),
        (Base::one(), "1".to_string()),
        (modulus - Base::one(), "r-1".to_string()),
        (modulus, "r".to_string()),
        (
            (0..Console::SIZE_IN_BITS).fold(Base::one(), |power, _| power.double()),
            format!("2^{}", Console::SIZE_IN_BITS),
        ),
        (-Base::one(), "p-1".to_string()),
    ]
}

/// Returns `n` little-endian bits with their labels: 0, 1, and the greatest value if `n` is less than the size
/// of a scalar; otherwise 0, 1, `r-1`, `r`, and with more bits than a scalar, the lowest excess bit.
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
        values.push((bits_of(-Console::one()), "r-1".to_string()));
        let mut modulus = <Circuit as Environment>::ScalarField::modulus().to_bits_le();
        modulus.resize(n, false);
        values.push((modulus, "r".to_string()));
        if n > size {
            let mut excess = vec![false; n];
            excess[size] = true;
            values.push((excess, format!("2^{size}")));
        }
    }
    values
}

/// Returns `bits` in reverse order.
fn reversed(mut bits: Vec<bool>) -> Vec<bool> {
    bits.reverse();
    bits
}

/// Defines a snapshot test of a unary operation on an operand of the given type.
macro_rules! unary_snapshot {
    ($op:ident, $input:ty, $values:expr, |$a:ident| $circuit:expr, |$x:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 1]) -> Vec<Case> {
                snapshot::unary(
                    |$a: &$input| $circuit,
                    |$x: <$input as Inject>::Primitive| $console,
                    None,
                    &$values,
                    modes,
                )
            }
            assert_snapshot(&FILES, stringify!($op), run_parallel(mode_jobs(1, cases)));
        }
    };
}

/// Defines a snapshot test of a binary operation on two scalars.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 2]) -> Vec<Case> {
                let values = Values::same(values());
                snapshot::binary(
                    |$a: &Scalar<Circuit>, $b: &Scalar<Circuit>| $circuit,
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

/// Defines a snapshot test of an operation that recovers a scalar from bits, for each of the given numbers of bits.
///
/// `$order` maps little-endian bits to the order that the operation takes. Every bit has the same mode.
macro_rules! from_bits_snapshot {
    ($op:ident, [$($n:literal),+], $order:expr) => {
        #[test]
        fn $op() {
            fn cases<const N: usize>(modes: [Mode; 1]) -> Vec<Case> {
                let values: Vec<_> =
                    bits_values(N).into_iter().map(|(bits_le, label)| ($order(bits_le), label)).collect();
                snapshot::unary(
                    |bits: &Array<Boolean<Circuit>, N>| Scalar::$op(bits),
                    |bits| Console::$op(&bits).ok(),
                    None,
                    &values,
                    modes,
                )
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
            let case = snapshot::case("()", &[], Some($expected), None, || (), |()| Scalar::<Circuit>::$op());
            assert_snapshot(&FILES, stringify!($op), vec![case]);
        }
    };
}

// Arithmetic.
binary_snapshot!(add, |a, b| a + b, |x, y| Some(x + y));

// Comparisons.
binary_snapshot!(is_equal, |a, b| a.is_equal(b), |x, y| Some(*x.is_equal(&y)));
binary_snapshot!(is_not_equal, |a, b| a.is_not_equal(b), |x, y| Some(*x.is_not_equal(&y)));
binary_snapshot!(is_less_than, |a, b| a.is_less_than(b), |x, y| Some(*x.is_less_than(&y)));
binary_snapshot!(is_less_than_or_equal, |a, b| a.is_less_than_or_equal(b), |x, y| Some(*x.is_less_than_or_equal(&y)));
binary_snapshot!(is_greater_than, |a, b| a.is_greater_than(b), |x, y| Some(*x.is_greater_than(&y)));
binary_snapshot!(is_greater_than_or_equal, |a, b| a.is_greater_than_or_equal(b), |x, y| Some(
    *x.is_greater_than_or_equal(&y)
));
unary_snapshot!(is_zero, Scalar<Circuit>, values(), |a| a.is_zero(), |x| Some(x.is_zero()));
unary_snapshot!(is_one, Scalar<Circuit>, values(), |a| a.is_one(), |x| Some(x.is_one()));

#[test]
fn ternary() {
    fn cases(modes: [Mode; 3]) -> Vec<Case> {
        snapshot::ternary(
            |c: &Boolean<Circuit>, a: &Scalar<Circuit>, b: &Scalar<Circuit>| Scalar::ternary(c, a, b),
            None,
            &values(),
            modes,
        )
    }
    assert_snapshot(&FILES, "ternary", run_parallel(mode_jobs(1, cases)));
}

// Bits.
unary_snapshot!(to_bits_le, Scalar<Circuit>, values(), |a| a.to_bits_le(), |x| Some(x.to_bits_le()));
unary_snapshot!(to_bits_be, Scalar<Circuit>, values(), |a| a.to_bits_be(), |x| Some(x.to_bits_be()));
from_bits_snapshot!(from_bits_le, [8, 250, 251, 252], |bits| bits);
from_bits_snapshot!(from_bits_be, [8, 250, 251, 252], reversed);

// Base field elements.
unary_snapshot!(from_field, Field<Circuit>, field_values(), |a| Scalar::from_field(a.clone()), |x| {
    Console::from_field(&x).ok()
});
unary_snapshot!(from_field_lossy, Field<Circuit>, field_values(), |a| Scalar::from_field_lossy(a), |x| Some(
    Console::from_field_lossy(&x)
));

// Constants.
nullary_snapshot!(one, Console::one());
nullary_snapshot!(zero, Console::zero());
