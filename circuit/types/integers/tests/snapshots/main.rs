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

//! Snapshot tests of the circuit shape of each integer operation.
//!
//! Each test synthesizes one operation for every integer type, every operand mode and a fixed set of
//! edge values, and compares the counts, output mode and structural digest with `snapshots/{op}.snap`.

use snarkvm_circuit_environment::{
    Circuit,
    prelude::*,
    snapshot::{self, Case, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel},
};
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_circuit_types_integers::Integer;
use snarkvm_console_types_integers::Integer as ConsoleInteger;

use num_traits::NumCast;

const FILES: SnapshotFiles = SnapshotFiles {
    directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots"),
    coverage: "each integer type, operand mode and edge value",
    command: "cargo test -p snarkvm-circuit-types-integers --test snapshots",
};

/// Returns the mode of each bit of `output`.
fn bit_modes<O: ToBits<Boolean = Boolean<Circuit>>>(output: &O) -> Vec<Mode> {
    output.to_bits_le().iter().map(Eject::eject_mode).collect()
}

/// A console integer of type `I`.
type Console<I> = ConsoleInteger<<Circuit as Environment>::Network, I>;

/// Converts a console result into the value that the circuit output ejects.
trait IntoEjected<P> {
    fn into_ejected(self) -> P;
}

impl<I: IntegerType> IntoEjected<Console<I>> for I {
    fn into_ejected(self) -> Console<I> {
        ConsoleInteger::new(self)
    }
}

impl IntoEjected<bool> for bool {
    fn into_ejected(self) -> bool {
        self
    }
}

/// Returns `2^k`.
fn power<I: IntegerType>(k: u64) -> Option<I> {
    I::one().checked_shl(&u32::try_from(k).ok()?)
}

/// Removes the later duplicates of each value, sorts by value, and returns the values as console integers.
fn dedup_and_sort<I: IntegerType>(candidates: Vec<(Option<I>, String)>) -> Vec<(Console<I>, String)> {
    let mut values: Vec<(I, String)> = Vec::with_capacity(candidates.len());
    for (value, label) in candidates {
        if let Some(value) = value
            && values.iter().all(|(v, _)| *v != value)
        {
            values.push((value, label));
        }
    }
    values.sort_by_key(|(value, _)| *value);
    values.into_iter().map(|(value, label)| (ConsoleInteger::new(value), label)).collect()
}

/// Returns the edge values of `I` with their labels.
///
/// The values are 0 to 3, -1, -2, `MIN`, `MAX` and their neighbours, `2^k` and its neighbours for
/// `k` below and at the half width and at the top bit, and the values with only the upper half set.
fn edge_values<I: IntegerType>() -> Vec<(Console<I>, String)> {
    let one = I::one();
    let two = one + one;
    let three = two + one;
    let half = I::BITS / 2;
    let top = if I::is_signed() { I::BITS - 2 } else { I::BITS - 1 };
    let mut candidates = vec![
        (Some(I::zero()), "0".to_string()),
        (Some(one), "1".to_string()),
        (Some(two), "2".to_string()),
        (Some(three), "3".to_string()),
        (I::zero().checked_sub(&one), "-1".to_string()),
        (I::zero().checked_sub(&two), "-2".to_string()),
        (Some(I::MIN), "MIN".to_string()),
        (I::MIN.checked_add(&one), "MIN+1".to_string()),
        (Some(I::MAX), "MAX".to_string()),
        (I::MAX.checked_sub(&one), "MAX-1".to_string()),
    ];
    for k in [half - 1, half, top] {
        let p = power::<I>(k);
        candidates.push((p.and_then(|p| p.checked_sub(&one)), format!("2^{k}-1")));
        candidates.push((p, format!("2^{k}")));
        candidates.push((p.and_then(|p| p.checked_add(&one)), format!("2^{k}+1")));
    }
    let p = power::<I>(half);
    match I::is_signed() {
        true => {
            let negative = p.and_then(|p| I::zero().checked_sub(&p));
            candidates.push((negative.and_then(|n| n.checked_sub(&one)), format!("-2^{half}-1")));
            candidates.push((negative, format!("-2^{half}")));
            candidates.push((negative.and_then(|n| n.checked_add(&one)), format!("-2^{half}+1")));
        }
        false => {
            let upper_half = p.and_then(|p| I::MAX.checked_sub(&(p - one)));
            candidates.push((upper_half, format!("2^{}-2^{half}", I::BITS)));
        }
    }
    dedup_and_sort(candidates)
}

/// Returns a few values of `I` that differ in their bit patterns.
fn small_values<I: IntegerType>() -> Vec<(Console<I>, String)> {
    let one = I::one();
    let candidates = vec![
        (Some(I::zero()), "0".to_string()),
        (Some(one), "1".to_string()),
        (I::zero().checked_sub(&one), "-1".to_string()),
        (Some(I::MIN), "MIN".to_string()),
        (Some(I::MAX), "MAX".to_string()),
        (power::<I>(I::BITS / 2), format!("2^{}", I::BITS / 2)),
    ];
    dedup_and_sort(candidates)
}

/// Returns the shift amounts for `I`: 0 to 2, and the amounts around half the width, the width and twice
/// the width of `I`.
fn shift_amounts<I: IntegerType>() -> [u64; 11] {
    let (half, bits) = (I::BITS / 2, I::BITS);
    [0, 1, 2, half - 1, half, half + 1, bits - 2, bits - 1, bits, bits + 1, 2 * bits]
}

/// Returns the shift amounts for a variable shift of `I`: 0, 1, and the width of `I` and its predecessor.
fn variable_shift_amounts<I: IntegerType>() -> [u64; 4] {
    [0, 1, I::BITS - 1, I::BITS]
}

/// Returns the exponents for `I`: 0 to 3, and the width of `I` and its predecessor.
fn exponents<I: IntegerType>() -> [u64; 6] {
    [0, 1, 2, 3, I::BITS - 1, I::BITS]
}

/// Returns `amounts` and `M::MAX` as values of `M`, with their labels.
fn magnitudes<M: Magnitude>(amounts: &[u64]) -> Vec<(Console<M>, String)> {
    let mut candidates: Vec<_> =
        amounts.iter().map(|amount| (<M as NumCast>::from(*amount), amount.to_string())).collect();
    candidates.push((Some(M::MAX), "MAX".to_string()));
    dedup_and_sort(candidates)
}

/// Returns the width of `I`, which is the cost of its jobs.
///
/// Inside `for_each!`, `I` is a primitive type, so `I::BITS` names its inherent `u32` constant instead.
fn bits<I: IntegerType>() -> u64 {
    I::BITS
}

/// Binds `$t` to each of the given types in turn and returns the values of `$body` as an array.
macro_rules! for_each {
    ($t:ident in [$($ty:ty),+] => $body:expr) => {
        [$({
            type $t = $ty;
            $body
        }),+]
    };
}

/// Binds `$t` to each integer type in turn and returns the values of `$body` as an array.
macro_rules! for_each_integer {
    ($t:ident => $body:expr) => {
        for_each!($t in [u8, u16, u32, u64, u128, i8, i16, i32, i64, i128] => $body)
    };
}

/// Binds `$t` to each magnitude type in turn and returns the values of `$body` as an array.
macro_rules! for_each_magnitude {
    ($t:ident => $body:expr) => {
        for_each!($t in [u8, u16, u32] => $body)
    };
}

/// Defines a snapshot test of a unary operation.
macro_rules! unary_snapshot {
    ($op:ident, |$a:ident| $circuit:expr, |$x:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases<I: IntegerType>(modes: [Mode; 1]) -> Vec<Case> {
                snapshot::unary(
                    |$a: &Integer<Circuit, I>| $circuit,
                    |$x: Console<I>| {
                        let $x = *$x;
                        $console.map(IntoEjected::into_ejected)
                    },
                    Some(bit_modes),
                    &edge_values::<I>(),
                    modes,
                )
            }
            let jobs = for_each_integer!(I => mode_jobs(bits::<I>(), cases::<I>));
            assert_snapshot(&FILES, stringify!($op), run_parallel(jobs.into_iter().flatten()));
        }
    };
}

/// Defines a snapshot test of a binary operation on two operands of the same type.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases<I: IntegerType>(modes: [Mode; 2]) -> Vec<Case> {
                let values = Values::same(edge_values::<I>());
                snapshot::binary(
                    |$a: &Integer<Circuit, I>, $b: &Integer<Circuit, I>| $circuit,
                    |$x: Console<I>, $y: Console<I>| {
                        let ($x, $y) = (*$x, *$y);
                        $console.map(IntoEjected::into_ejected)
                    },
                    Some(bit_modes),
                    &values,
                    &values,
                    modes,
                )
            }
            let jobs = for_each_integer!(I => mode_jobs(bits::<I>(), cases::<I>));
            assert_snapshot(&FILES, stringify!($op), run_parallel(jobs.into_iter().flatten()));
        }
    };
}

/// Defines a snapshot test of a binary operation whose right operand is a magnitude.
///
/// `$rhs` and `$variable_rhs` list the right operand values, besides `M::MAX`, when it is a constant
/// and when it is a variable. They may use `I`. A variable left operand takes the small value set.
macro_rules! magnitude_snapshot {
    ($op:ident, $rhs:expr, $variable_rhs:expr, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases<I: IntegerType, M: Magnitude>(modes: [Mode; 2]) -> Vec<Case> {
                snapshot::binary(
                    |$a: &Integer<Circuit, I>, $b: &Integer<Circuit, M>| $circuit,
                    |$x: Console<I>, $y: Console<M>| {
                        let $x = *$x;
                        // Note: `unwrap()` is safe as every `Magnitude` is at most 32 bits.
                        let $y = $y.to_u32().unwrap();
                        $console.map(IntoEjected::into_ejected)
                    },
                    Some(bit_modes),
                    &Values { constant: edge_values::<I>(), variable: small_values::<I>() },
                    &Values { constant: magnitudes::<M>(&$rhs), variable: magnitudes::<M>(&$variable_rhs) },
                    modes,
                )
            }
            let jobs = for_each_integer!(I => for_each_magnitude!(M => mode_jobs(bits::<I>() * bits::<M>(), cases::<I, M>)));
            assert_snapshot(&FILES, stringify!($op), run_parallel(jobs.into_iter().flatten().flatten()));
        }
    };
}

// Arithmetic.
binary_snapshot!(add_checked, |a, b| a.add_checked(b), |x, y| x.checked_add(&y));
binary_snapshot!(add_wrapped, |a, b| a.add_wrapped(b), |x, y| Some(x.wrapping_add(&y)));
binary_snapshot!(sub_checked, |a, b| a.sub_checked(b), |x, y| x.checked_sub(&y));
binary_snapshot!(sub_wrapped, |a, b| a.sub_wrapped(b), |x, y| Some(x.wrapping_sub(&y)));
binary_snapshot!(mul_checked, |a, b| a.mul_checked(b), |x, y| x.checked_mul(&y));
binary_snapshot!(mul_wrapped, |a, b| a.mul_wrapped(b), |x, y| Some(x.wrapping_mul(&y)));
binary_snapshot!(div_checked, |a, b| a.div_checked(b), |x, y| x.checked_div(&y));
binary_snapshot!(div_wrapped, |a, b| a.div_wrapped(b), |x, y| (!y.is_zero()).then(|| x.wrapping_div(&y)));
binary_snapshot!(rem_checked, |a, b| a.rem_checked(b), |x, y| x.checked_rem(&y));
binary_snapshot!(rem_wrapped, |a, b| a.rem_wrapped(b), |x, y| (!y.is_zero()).then(|| x.wrapping_rem(&y)));
binary_snapshot!(modulo, |a, b| a.modulo(b), |x, y| (!I::is_signed() && !y.is_zero()).then(|| x.wrapping_rem(&y)));

// Powers and shifts.
magnitude_snapshot!(pow_checked, exponents::<I>(), [0, 1, 2], |a, b| a.pow_checked(b), |x, y| x.checked_pow(&y));
magnitude_snapshot!(pow_wrapped, exponents::<I>(), [0, 1, 2], |a, b| a.pow_wrapped(b), |x, y| Some(x.wrapping_pow(&y)));
magnitude_snapshot!(
    shl_checked,
    shift_amounts::<I>(),
    variable_shift_amounts::<I>(),
    |a, b| a.shl_checked(b),
    |x, y| x.checked_shl(&y)
);
magnitude_snapshot!(
    shl_wrapped,
    shift_amounts::<I>(),
    variable_shift_amounts::<I>(),
    |a, b| a.shl_wrapped(b),
    |x, y| Some(x.wrapping_shl(y))
);
magnitude_snapshot!(
    shr_checked,
    shift_amounts::<I>(),
    variable_shift_amounts::<I>(),
    |a, b| a.shr_checked(b),
    |x, y| x.checked_shr(y)
);
magnitude_snapshot!(
    shr_wrapped,
    shift_amounts::<I>(),
    variable_shift_amounts::<I>(),
    |a, b| a.shr_wrapped(b),
    |x, y| Some(x.wrapping_shr(y))
);

// Bitwise.
binary_snapshot!(and, |a, b| a & b, |x, y| Some(x & y));
binary_snapshot!(or, |a, b| a | b, |x, y| Some(x | y));
binary_snapshot!(xor, |a, b| a ^ b, |x, y| Some(x ^ y));
unary_snapshot!(not, |a| !a, |x| Some(!x));

// Signs.
unary_snapshot!(neg, |a| -a, |x| if I::is_signed() { x.checked_neg() } else { None });
unary_snapshot!(abs_checked, |a| a.abs_checked(), |x| x.checked_abs());
unary_snapshot!(abs_wrapped, |a| a.abs_wrapped(), |x| Some(x.wrapping_abs()));

// Comparisons.
binary_snapshot!(is_equal, |a, b| a.is_equal(b), |x, y| Some(x == y));
binary_snapshot!(is_not_equal, |a, b| a.is_not_equal(b), |x, y| Some(x != y));
binary_snapshot!(is_less_than, |a, b| a.is_less_than(b), |x, y| Some(x < y));
binary_snapshot!(is_less_than_or_equal, |a, b| a.is_less_than_or_equal(b), |x, y| Some(x <= y));
binary_snapshot!(is_greater_than, |a, b| a.is_greater_than(b), |x, y| Some(x > y));
binary_snapshot!(is_greater_than_or_equal, |a, b| a.is_greater_than_or_equal(b), |x, y| Some(x >= y));

#[test]
fn ternary() {
    fn cases<I: IntegerType>(modes: [Mode; 3]) -> Vec<Case> {
        snapshot::ternary(
            |c: &Boolean<Circuit>, a: &Integer<Circuit, I>, b: &Integer<Circuit, I>| Integer::ternary(c, a, b),
            Some(bit_modes),
            &small_values::<I>(),
            modes,
        )
    }
    let jobs = for_each_integer!(I => mode_jobs(bits::<I>(), cases::<I>));
    assert_snapshot(&FILES, "ternary", run_parallel(jobs.into_iter().flatten()));
}
