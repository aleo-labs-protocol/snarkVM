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

mod harness;

use harness::{Case, Output, assert_snapshot, measure, mode_jobs, run_parallel, value_label};

use snarkvm_circuit_environment::{Circuit, prelude::*};
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_circuit_types_integers::Integer;
use snarkvm_console_types_integers::Integer as ConsoleInteger;

use num_traits::NumCast;

impl<I: IntegerType> Output for Integer<Circuit, I> {
    type Value = I;

    fn bit_modes(&self) -> Vec<Mode> {
        self.to_bits_le().iter().map(Eject::eject_mode).collect()
    }

    fn value(&self) -> I {
        *self.eject_value()
    }
}

impl Output for Boolean<Circuit> {
    type Value = bool;

    fn bit_modes(&self) -> Vec<Mode> {
        vec![self.eject_mode()]
    }

    fn value(&self) -> bool {
        self.eject_value()
    }
}

/// Returns `2^k`.
fn power<I: IntegerType>(k: u64) -> Option<I> {
    I::one().checked_shl(&u32::try_from(k).ok()?)
}

/// Removes the later duplicates of each value, then sorts by value.
fn dedup_and_sort<T: Copy + Ord>(candidates: Vec<(Option<T>, String)>) -> Vec<(T, String)> {
    let mut values: Vec<(T, String)> = Vec::with_capacity(candidates.len());
    for (value, label) in candidates {
        if let Some(value) = value
            && values.iter().all(|(v, _)| *v != value)
        {
            values.push((value, label));
        }
    }
    values.sort_by_key(|(value, _)| *value);
    values
}

/// Returns the edge values of `I` with their labels.
///
/// The values are 0 to 3, -1, -2, `MIN`, `MAX` and their neighbours, `2^k` and its neighbours for
/// `k` below and at the half width and at the top bit, and the values with only the upper half set.
fn edge_values<I: IntegerType>() -> Vec<(I, String)> {
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
fn small_values<I: IntegerType>() -> Vec<(I, String)> {
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

/// Returns `amounts` and `M::MAX` as values of `M`, with their labels.
fn magnitudes<M: Magnitude>(amounts: &[u64]) -> Vec<(M, String)> {
    let mut candidates: Vec<_> =
        amounts.iter().map(|amount| (<M as NumCast>::from(*amount), amount.to_string())).collect();
    candidates.push((Some(M::MAX), "MAX".to_string()));
    dedup_and_sort(candidates)
}

/// Returns the cases of a unary operation on `I` with an operand of the given mode.
fn unary<I: IntegerType, O: Output>(
    operation: impl Fn(&Integer<Circuit, I>) -> O,
    oracle: impl Fn(I) -> Option<O::Value>,
    mode: Mode,
) -> Vec<Case> {
    let block = format!("{}.{mode}", I::type_name());
    edge_values::<I>()
        .into_iter()
        .map(|(x, label)| {
            Circuit::reset();
            let a = Integer::<Circuit, I>::new(mode, ConsoleInteger::new(x));
            let outcome = measure(&format!("{block} {label}"), oracle(x), || operation(&a));
            Case { block: block.clone(), values: value_label(mode, &label).to_string(), outcome }
        })
        .collect()
}

/// The values of an operand when it is a constant and when it is a variable.
struct Values<T> {
    constant: Vec<(T, String)>,
    variable: Vec<(T, String)>,
}

impl<T> Values<T> {
    fn for_mode(&self, mode: Mode) -> &[(T, String)] {
        match mode {
            Mode::Constant => &self.constant,
            _ => &self.variable,
        }
    }
}

/// Returns the cases of a binary operation of `I` and `M` with operands of the given modes.
fn binary<I: IntegerType, M: IntegerType, O: Output>(
    operation: impl Fn(&Integer<Circuit, I>, &Integer<Circuit, M>) -> O,
    oracle: impl Fn(I, M) -> Option<O::Value>,
    lhs: &Values<I>,
    rhs: &Values<M>,
    modes: &[Mode],
) -> Vec<Case> {
    let (mode_a, mode_b) = (modes[0], modes[1]);
    let block = format!("{}.{mode_a} {}.{mode_b}", I::type_name(), M::type_name());
    let mut cases = Vec::new();
    for (x, label_x) in lhs.for_mode(mode_a) {
        for (y, label_y) in rhs.for_mode(mode_b) {
            Circuit::reset();
            let a = Integer::<Circuit, I>::new(mode_a, ConsoleInteger::new(*x));
            let b = Integer::<Circuit, M>::new(mode_b, ConsoleInteger::new(*y));
            let label = format!("{block} {label_x} {label_y}");
            let outcome = measure(&label, oracle(*x, *y), || operation(&a, &b));
            let values = format!("{} {}", value_label(mode_a, label_x), value_label(mode_b, label_y));
            cases.push(Case { block: block.clone(), values, outcome });
        }
    }
    cases
}

/// Returns `amount` as a `u32`.
fn to_u32<M: Magnitude>(amount: M) -> u32 {
    // Note: `unwrap()` is safe as every `Magnitude` is at most 32 bits.
    amount.to_u32().unwrap()
}

/// Runs `$cases::<I>` in parallel, once per block: each integer type `I` and each combination of
/// `$arity` operand modes.
macro_rules! for_each_type {
    ($cases:ident, $arity:expr) => {
        run_parallel(
            [
                mode_jobs($arity, $cases::<u8>),
                mode_jobs($arity, $cases::<u16>),
                mode_jobs($arity, $cases::<u32>),
                mode_jobs($arity, $cases::<u64>),
                mode_jobs($arity, $cases::<u128>),
                mode_jobs($arity, $cases::<i8>),
                mode_jobs($arity, $cases::<i16>),
                mode_jobs($arity, $cases::<i32>),
                mode_jobs($arity, $cases::<i64>),
                mode_jobs($arity, $cases::<i128>),
            ]
            .into_iter()
            .flatten()
            .collect(),
        )
    };
}

/// Runs `$cases::<I, M>` in parallel, once per block: each integer type `I`, each magnitude type `M`
/// and each combination of two operand modes.
macro_rules! for_each_type_and_magnitude {
    ($cases:ident) => {
        run_parallel(
            [
                mode_jobs(2, $cases::<u8, u8>),
                mode_jobs(2, $cases::<u8, u16>),
                mode_jobs(2, $cases::<u8, u32>),
                mode_jobs(2, $cases::<u16, u8>),
                mode_jobs(2, $cases::<u16, u16>),
                mode_jobs(2, $cases::<u16, u32>),
                mode_jobs(2, $cases::<u32, u8>),
                mode_jobs(2, $cases::<u32, u16>),
                mode_jobs(2, $cases::<u32, u32>),
                mode_jobs(2, $cases::<u64, u8>),
                mode_jobs(2, $cases::<u64, u16>),
                mode_jobs(2, $cases::<u64, u32>),
                mode_jobs(2, $cases::<u128, u8>),
                mode_jobs(2, $cases::<u128, u16>),
                mode_jobs(2, $cases::<u128, u32>),
                mode_jobs(2, $cases::<i8, u8>),
                mode_jobs(2, $cases::<i8, u16>),
                mode_jobs(2, $cases::<i8, u32>),
                mode_jobs(2, $cases::<i16, u8>),
                mode_jobs(2, $cases::<i16, u16>),
                mode_jobs(2, $cases::<i16, u32>),
                mode_jobs(2, $cases::<i32, u8>),
                mode_jobs(2, $cases::<i32, u16>),
                mode_jobs(2, $cases::<i32, u32>),
                mode_jobs(2, $cases::<i64, u8>),
                mode_jobs(2, $cases::<i64, u16>),
                mode_jobs(2, $cases::<i64, u32>),
                mode_jobs(2, $cases::<i128, u8>),
                mode_jobs(2, $cases::<i128, u16>),
                mode_jobs(2, $cases::<i128, u32>),
            ]
            .into_iter()
            .flatten()
            .collect(),
        )
    };
}

/// Defines a snapshot test of a unary operation.
macro_rules! unary_snapshot {
    ($op:ident, |$a:ident| $circuit:expr, |$x:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases<I: IntegerType>(modes: &[Mode]) -> Vec<Case> {
                unary::<I, _>(|$a: &Integer<Circuit, I>| $circuit, |$x: I| $console, modes[0])
            }
            assert_snapshot(stringify!($op), 1, for_each_type!(cases, 1));
        }
    };
}

/// Defines a snapshot test of a binary operation on two operands of the same type.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases<I: IntegerType>(modes: &[Mode]) -> Vec<Case> {
                let values = Values { constant: edge_values::<I>(), variable: edge_values::<I>() };
                binary::<I, I, _>(
                    |$a: &Integer<Circuit, I>, $b: &Integer<Circuit, I>| $circuit,
                    |$x: I, $y: I| $console,
                    &values,
                    &values,
                    modes,
                )
            }
            assert_snapshot(stringify!($op), 2, for_each_type!(cases, 2));
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
            fn cases<I: IntegerType, M: Magnitude>(modes: &[Mode]) -> Vec<Case> {
                binary::<I, M, _>(
                    |$a: &Integer<Circuit, I>, $b: &Integer<Circuit, M>| $circuit,
                    |$x: I, $y: M| {
                        let $y = to_u32($y);
                        $console
                    },
                    &Values { constant: edge_values::<I>(), variable: small_values::<I>() },
                    &Values { constant: magnitudes::<M>(&$rhs), variable: magnitudes::<M>(&$variable_rhs) },
                    modes,
                )
            }
            assert_snapshot(stringify!($op), 2, for_each_type_and_magnitude!(cases));
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
magnitude_snapshot!(pow_checked, [0, 1, 2, 3, I::BITS - 1, I::BITS], [0, 1, 2], |a, b| a.pow_checked(b), |x, y| x
    .checked_pow(&y));
magnitude_snapshot!(pow_wrapped, [0, 1, 2, 3, I::BITS - 1, I::BITS], [0, 1, 2], |a, b| a.pow_wrapped(b), |x, y| Some(
    x.wrapping_pow(&y)
));
magnitude_snapshot!(
    shl_checked,
    [
        0,
        1,
        2,
        I::BITS / 2 - 1,
        I::BITS / 2,
        I::BITS / 2 + 1,
        I::BITS - 2,
        I::BITS - 1,
        I::BITS,
        I::BITS + 1,
        2 * I::BITS
    ],
    [0, 1, I::BITS - 1, I::BITS],
    |a, b| a.shl_checked(b),
    |x, y| x.checked_shl(&y)
);
magnitude_snapshot!(
    shl_wrapped,
    [
        0,
        1,
        2,
        I::BITS / 2 - 1,
        I::BITS / 2,
        I::BITS / 2 + 1,
        I::BITS - 2,
        I::BITS - 1,
        I::BITS,
        I::BITS + 1,
        2 * I::BITS
    ],
    [0, 1, I::BITS - 1, I::BITS],
    |a, b| a.shl_wrapped(b),
    |x, y| Some(x.wrapping_shl(y))
);
magnitude_snapshot!(
    shr_checked,
    [
        0,
        1,
        2,
        I::BITS / 2 - 1,
        I::BITS / 2,
        I::BITS / 2 + 1,
        I::BITS - 2,
        I::BITS - 1,
        I::BITS,
        I::BITS + 1,
        2 * I::BITS
    ],
    [0, 1, I::BITS - 1, I::BITS],
    |a, b| a.shr_checked(b),
    |x, y| x.checked_shr(y)
);
magnitude_snapshot!(
    shr_wrapped,
    [
        0,
        1,
        2,
        I::BITS / 2 - 1,
        I::BITS / 2,
        I::BITS / 2 + 1,
        I::BITS - 2,
        I::BITS - 1,
        I::BITS,
        I::BITS + 1,
        2 * I::BITS
    ],
    [0, 1, I::BITS - 1, I::BITS],
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

/// Returns the cases of `ternary` on `I` with operands of the given modes, for each condition and a few
/// operand values.
fn ternary_cases<I: IntegerType>(modes: &[Mode]) -> Vec<Case> {
    let (mode_c, mode_a, mode_b) = (modes[0], modes[1], modes[2]);
    let block = format!("boolean.{mode_c} {}.{mode_a} {}.{mode_b}", I::type_name(), I::type_name());
    let values = small_values::<I>();
    let mut cases = Vec::with_capacity(2 * values.len().pow(2));
    for condition in [false, true] {
        for (x, label_x) in &values {
            for (y, label_y) in &values {
                Circuit::reset();
                let c = Boolean::<Circuit>::new(mode_c, condition);
                let a = Integer::<Circuit, I>::new(mode_a, ConsoleInteger::new(*x));
                let b = Integer::<Circuit, I>::new(mode_b, ConsoleInteger::new(*y));
                let label = format!("{block} {condition} {label_x} {label_y}");
                let expected = Some(if condition { *x } else { *y });
                let outcome = measure(&label, expected, || Integer::ternary(&c, &a, &b));
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

#[test]
fn ternary() {
    assert_snapshot("ternary", 3, for_each_type!(ternary_cases, 3));
}
