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

//! Snapshot tests of the circuit shape of each group operation.
//!
//! Each test synthesizes one operation for every operand mode and a fixed set of group elements, and compares
//! the counts, output mode and structural digest with `snapshots/{op}.snap`.

use snarkvm_circuit_environment::{
    Circuit,
    prelude::*,
    snapshot::{self, Array, Case, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel},
    snapshot_files,
};
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_circuit_types_field::Field;
use snarkvm_circuit_types_group::Group;
use snarkvm_circuit_types_scalar::Scalar;
use snarkvm_console_types_group::{
    AffineCurve,
    Field as ConsoleField,
    Group as ConsoleGroup,
    TestRng,
    ToField as _,
    Uniform,
};

const FILES: SnapshotFiles = snapshot_files!("each operand mode and a fixed set of group elements");

/// A console group element.
type Console = ConsoleGroup<<Circuit as Environment>::Network>;

/// A console base field element.
type Base = ConsoleField<<Circuit as Environment>::Network>;

/// An affine point of the curve, not necessarily in the subgroup.
type Affine = <Circuit as Environment>::Affine;

/// A console scalar.
type ConsoleScalar = snarkvm_console_types_group::Scalar<<Circuit as Environment>::Network>;

/// Returns the zero element, the generator `G`, `2G`, `-G` and an element sampled from a fixed seed, with their
/// labels.
fn values() -> Vec<(Console, String)> {
    let generator = Console::generator();
    vec![
        (Console::zero(), "zero".to_string()),
        (generator, "G".to_string()),
        (generator.double(), "2G".to_string()),
        (-generator, "-G".to_string()),
        (Uniform::rand(&mut TestRng::from_seed(0)), "sampled".to_string()),
    ]
}

/// Returns 0, 1, 2, -1 and a scalar sampled from a fixed seed, with their labels.
fn scalar_values() -> Vec<(ConsoleScalar, String)> {
    let one = ConsoleScalar::one();
    vec![
        (ConsoleScalar::zero(), "0".to_string()),
        (one, "1".to_string()),
        (one.double(), "2".to_string()),
        (-one, "-1".to_string()),
        (Uniform::rand(&mut TestRng::from_seed(0)), "sampled".to_string()),
    ]
}

/// Returns the x-coordinate of each value, the least positive x-coordinate of no point on the curve, and the least
/// positive x-coordinate of points on the curve outside the subgroup, with their labels.
fn x_values() -> Vec<(Base, String)> {
    let least_unrecoverable = |on_curve: bool| {
        (1..).map(|n| (Base::from_u64(n), n.to_string())).find(|(x, _)| {
            Console::from_x_coordinate(*x).is_err() && Affine::pair_from_x_coordinate(**x).is_some() == on_curve
        })
    };
    values()
        .into_iter()
        .map(|(point, label)| (point.to_x_coordinate(), format!("{label}.x")))
        .chain(least_unrecoverable(false))
        .chain(least_unrecoverable(true))
        .collect()
}

/// Returns the coordinates of each value, of the point `(0, -1)` of order 2 and of the point `G + (0, -1)` outside
/// the subgroup, with the label of each coordinate.
fn curve_points() -> Vec<(Base, Base, String, String)> {
    let generator = Console::generator();
    values()
        .into_iter()
        .map(|(point, label)| {
            (point.to_x_coordinate(), point.to_y_coordinate(), format!("{label}.x"), format!("{label}.y"))
        })
        .chain([
            (Base::zero(), -Base::one(), "0".to_string(), "-1".to_string()),
            (-generator.to_x_coordinate(), -generator.to_y_coordinate(), "-(G.x)".to_string(), "-(G.y)".to_string()),
        ])
        .collect()
}

/// Returns the curve points and the point `(1, 1)` off the curve, with the label of each coordinate.
fn points() -> Vec<(Base, Base, String, String)> {
    curve_points().into_iter().chain([(Base::one(), Base::one(), "1".to_string(), "1".to_string())]).collect()
}

/// Returns the group element with coordinates `(x, y)`, or `None` if `(x, y)` is off the curve or outside the
/// subgroup.
fn group_from_xy(x: Base, y: Base) -> Option<Console> {
    Console::try_new(Affine::from_coordinates_unchecked((*x, *y))).ok()
}

/// Returns `n` big-endian bits with their labels: 0, 1, with `n` the size of a scalar also `r-1` and `r`, and
/// `2^n-1`.
///
/// `r` is the order of the group.
fn bits_be_values(n: usize) -> Vec<(Vec<bool>, String)> {
    let bits_be = |mut bits: Vec<bool>| -> Vec<bool> {
        bits.resize(n, false);
        reversed(bits)
    };
    let mut values = vec![(vec![false; n], "0".to_string()), (bits_be(vec![true]), "1".to_string())];
    if n == ConsoleScalar::SIZE_IN_BITS {
        values.push((bits_be((-ConsoleScalar::one()).to_bits_le()), "r-1".to_string()));
        values.push((bits_be(<Circuit as Environment>::ScalarField::modulus().to_bits_le()), "r".to_string()));
    }
    values.push((vec![true; n], format!("2^{n}-1")));
    values
}

/// Returns the lower `n` little-endian bits of each x-coordinate in `x_values` that fits in `n` bits, and `n` ones,
/// with their labels.
///
/// With `n` the size of a base field element, `n` ones are `2^n-1`, which is not less than the modulus.
fn x_bits_values(n: usize) -> Vec<(Vec<bool>, String)> {
    x_values()
        .into_iter()
        .filter_map(|(x, label)| {
            let mut bits_le = x.to_bits_le();
            (!bits_le.split_off(n).contains(&true)).then_some((bits_le, label))
        })
        .chain([(vec![true; n], format!("2^{n}-1"))])
        .collect()
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
            let oracle = |$x: <$input as Inject>::Primitive| $console;
            snapshot::assert_unary(&FILES, stringify!($op), || $values, |$a: &$input| $circuit, oracle);
        }
    };
}

/// Defines a snapshot test of a binary operation on two group elements.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            let operation = |$a: &Group<Circuit>, $b: &Group<Circuit>| $circuit;
            snapshot::assert_binary(&FILES, stringify!($op), values, values, operation, |$x: Console, $y: Console| {
                $console
            });
        }
    };
}

/// Returns the cases of an operation on the coordinates of each point, one per point.
fn point_cases<O>(
    operation: impl Fn(&Field<Circuit>, &Field<Circuit>) -> O,
    oracle: impl Fn(Base, Base) -> Option<O::Primitive>,
    points: &[(Base, Base, String, String)],
    [mode_x, mode_y]: [Mode; 2],
) -> Vec<Case>
where
    O: Eject,
    O::Primitive: Debug + PartialEq,
{
    let name = Field::<Circuit>::type_name();
    points
        .iter()
        .map(|(x, y, label_x, label_y)| {
            let operands = [(name, mode_x, label_x.as_str()), (name, mode_y, label_y.as_str())];
            let inject = || (Field::<Circuit>::new(mode_x, *x), Field::<Circuit>::new(mode_y, *y));
            snapshot::case(&operands, None, oracle(*x, *y), None, inject, |(a, b)| operation(&a, &b))
        })
        .collect()
}

/// Defines a snapshot test of an operation on the coordinates of a point.
macro_rules! point_snapshot {
    ($op:ident, $points:expr, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 2]) -> Vec<Case> {
                point_cases(|$a, $b| $circuit, |$x, $y| $console, &$points, modes)
            }
            assert_snapshot(&FILES, stringify!($op), run_parallel(mode_jobs(1, cases)));
        }
    };
}

/// Defines a snapshot test of an operation that recovers a group element from the bits of its x-coordinate, for
/// each of the given numbers of bits.
///
/// `$order` maps little-endian bits to the order that the operation takes. Every bit has the same mode.
macro_rules! from_bits_snapshot {
    ($op:ident, [$($n:literal),+], $order:expr) => {
        #[test]
        fn $op() {
            fn cases<const N: usize>(modes: [Mode; 1]) -> Vec<Case> {
                let values: Vec<_> =
                    x_bits_values(N).into_iter().map(|(bits_le, label)| ($order(bits_le), label)).collect();
                snapshot::unary(
                    |bits: &Array<Boolean<Circuit>, N>| Group::$op(bits),
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

// Arithmetic.
binary_snapshot!(add, |a, b| a + b, |x, y| Some(x + y));
binary_snapshot!(sub, |a, b| a - b, |x, y| Some(x - y));
unary_snapshot!(neg, Group<Circuit>, values(), |a| -a, |x| Some(-x));
unary_snapshot!(double, Group<Circuit>, values(), |a| a.double(), |x| Some(x.double()));
unary_snapshot!(mul_by_cofactor, Group<Circuit>, values(), |a| a.mul_by_cofactor(), |x| Some(x.mul_by_cofactor()));

#[test]
fn mul() {
    let operation = |a: &Group<Circuit>, b: &Scalar<Circuit>| a * b;
    snapshot::assert_binary(&FILES, "mul", values, scalar_values, operation, |x: Console, y: ConsoleScalar| {
        Some(x * y)
    });
}

/// Covers the product of a group element and 8 or 251 big-endian bits. Every bit has the same mode.
#[test]
fn mul_bits() {
    fn cases<const N: usize>(modes: [Mode; 2]) -> Vec<Case> {
        snapshot::binary(
            |a: &Group<Circuit>, b: &Array<Boolean<Circuit>, N>| a * &b[..],
            |x: Console, bits_be: Vec<bool>| {
                let scalar = bits_be.iter().fold(ConsoleScalar::zero(), |scalar, bit| match bit {
                    true => scalar.double() + ConsoleScalar::one(),
                    false => scalar.double(),
                });
                Some(x * scalar)
            },
            None,
            &Values::same(values()),
            &Values::same(bits_be_values(N)),
            modes,
        )
    }
    let jobs = [mode_jobs(8, cases::<8>), mode_jobs(251, cases::<251>)];
    assert_snapshot(&FILES, "mul_bits", run_parallel(jobs.into_iter().flatten()));
}

// Comparisons.
binary_snapshot!(is_equal, |a, b| a.is_equal(b), |x, y| Some(x == y));
binary_snapshot!(is_not_equal, |a, b| a.is_not_equal(b), |x, y| Some(x != y));
unary_snapshot!(is_zero, Group<Circuit>, values(), |a| a.is_zero(), |x| Some(x.is_zero()));

#[test]
fn ternary() {
    snapshot::assert_ternary(&FILES, "ternary", values, |c: &Boolean<Circuit>, a: &Group<Circuit>, b| {
        Group::ternary(c, a, b)
    });
}

// Coordinates.
unary_snapshot!(to_x_coordinate, Group<Circuit>, values(), |a| a.to_x_coordinate(), |x| Some(x.to_x_coordinate()));
unary_snapshot!(to_y_coordinate, Group<Circuit>, values(), |a| a.to_y_coordinate(), |x| Some(x.to_y_coordinate()));
unary_snapshot!(to_field, Group<Circuit>, values(), |a| a.to_field(), |x| x.to_field().ok());
unary_snapshot!(from_x_coordinate, Field<Circuit>, x_values(), |a| Group::from_x_coordinate(a.clone()), |x| {
    Console::from_x_coordinate(x).ok()
});

// `from_x_coordinate_flagged` ejects the coordinates of the point and the error flag as field elements, as `Eject`
// covers no tuple of owned values. The error flag is set if no group element has the x-coordinate, and the point is
// then `(x, 0)`.
unary_snapshot!(
    from_x_coordinate_flagged,
    Field<Circuit>,
    x_values(),
    |a| {
        let (point, flag) = Group::from_x_coordinate_flagged(a.clone());
        vec![point.to_x_coordinate(), point.to_y_coordinate(), Field::from_boolean(&flag)]
    },
    |x| {
        Some(match Console::from_x_coordinate(x) {
            Ok(point) => vec![x, point.to_y_coordinate(), Base::zero()],
            Err(_) => vec![x, Base::zero(), Base::one()],
        })
    }
);

point_snapshot!(from_xy_coordinates, points(), |a, b| Group::from_xy_coordinates(a.clone(), b.clone()), |x, y| {
    group_from_xy(x, y)
});
point_snapshot!(
    from_xy_coordinates_unchecked,
    points(),
    |a, b| Group::from_xy_coordinates_unchecked(a.clone(), b.clone()),
    |x, y| Some(Console::from_xy_coordinates_unchecked(x, y))
);

// `is_in_group` covers each curve point, including `(0, -1)` and `G + (0, -1)`, which are outside the subgroup.
point_snapshot!(
    is_in_group,
    curve_points(),
    |a, b| Group::from_xy_coordinates_unchecked(a.clone(), b.clone()).is_in_group(),
    |x, y| Some(group_from_xy(x, y).is_some())
);

// Bits.
unary_snapshot!(to_bits_le, Group<Circuit>, values(), |a| a.to_bits_le(), |x| Some(x.to_bits_le()));
unary_snapshot!(to_bits_be, Group<Circuit>, values(), |a| a.to_bits_be(), |x| Some(x.to_bits_be()));
from_bits_snapshot!(from_bits_le, [8, 253], |bits| bits);
from_bits_snapshot!(from_bits_be, [8, 253], reversed);

// Constants.
#[test]
fn zero() {
    snapshot::assert_nullary(&FILES, "zero", Console::zero(), Group::<Circuit>::zero);
}

#[test]
fn generator() {
    snapshot::assert_nullary(&FILES, "generator", Console::generator(), Group::<Circuit>::generator);
}
