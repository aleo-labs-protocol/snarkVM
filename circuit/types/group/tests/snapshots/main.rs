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
    snapshot::{self, Case, SnapshotFiles, Values, assert_snapshot, mode_jobs, run_parallel, value_label},
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

const FILES: SnapshotFiles = SnapshotFiles {
    directory: concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots"),
    coverage: "each operand mode and a fixed set of group elements",
    command: "cargo test -p snarkvm-circuit-types-group --test snapshots",
};

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

/// Defines a snapshot test of a binary operation on two group elements.
macro_rules! binary_snapshot {
    ($op:ident, |$a:ident, $b:ident| $circuit:expr, |$x:ident, $y:ident| $console:expr) => {
        #[test]
        fn $op() {
            fn cases(modes: [Mode; 2]) -> Vec<Case> {
                let values = Values::same(values());
                snapshot::binary(
                    |$a: &Group<Circuit>, $b: &Group<Circuit>| $circuit,
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
    let block = format!("{}.{mode_x} {}.{mode_y}", Field::<Circuit>::type_name(), Field::<Circuit>::type_name());
    points
        .iter()
        .map(|(x, y, label_x, label_y)| {
            Circuit::reset();
            let a = Field::<Circuit>::new(mode_x, *x);
            let b = Field::<Circuit>::new(mode_y, *y);
            let label = format!("{block} {label_x} {label_y}");
            let outcome = snapshot::measure(&label, oracle(*x, *y), None, || operation(&a, &b));
            let values = format!("{} {}", value_label(mode_x, label_x), value_label(mode_y, label_y));
            Case { block: block.clone(), values, outcome }
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
            fn cases<const N: usize>([mode]: [Mode; 1]) -> Vec<Case> {
                let block = format!("{}[{N}].{mode}", Boolean::<Circuit>::type_name());
                x_bits_values(N)
                    .into_iter()
                    .map(|(bits_le, label)| {
                        Circuit::reset();
                        let expected = Console::from_bits_le(&bits_le).ok();
                        let bits: Vec<Boolean<Circuit>> = Inject::new(mode, $order(bits_le));
                        let outcome =
                            snapshot::measure(&format!("{block} {label}"), expected, None, || Group::$op(&bits));
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
            let outcome = snapshot::measure(stringify!($op), Some($expected), None, Group::<Circuit>::$op);
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
unary_snapshot!(neg, Group<Circuit>, values(), |a| -a, |x| Some(-x));
unary_snapshot!(double, Group<Circuit>, values(), |a| a.double(), |x| Some(x.double()));
unary_snapshot!(mul_by_cofactor, Group<Circuit>, values(), |a| a.mul_by_cofactor(), |x| Some(x.mul_by_cofactor()));

#[test]
fn mul() {
    fn cases(modes: [Mode; 2]) -> Vec<Case> {
        snapshot::binary(
            |a: &Group<Circuit>, b: &Scalar<Circuit>| a * b,
            |x: Console, y: ConsoleScalar| Some(x * y),
            None,
            &Values::same(values()),
            &Values::same(scalar_values()),
            modes,
        )
    }
    assert_snapshot(&FILES, "mul", run_parallel(mode_jobs(1, cases)));
}

/// Covers the product of a group element and 8 or 251 big-endian bits. Every bit has the same mode.
#[test]
fn mul_bits() {
    fn cases<const N: usize>([mode_a, mode_b]: [Mode; 2]) -> Vec<Case> {
        let block =
            format!("{}.{mode_a} {}[{N}].{mode_b}", Group::<Circuit>::type_name(), Boolean::<Circuit>::type_name());
        let (values, bits_values) = (values(), bits_be_values(N));
        let mut cases = Vec::with_capacity(values.len() * bits_values.len());
        for (x, label_x) in &values {
            for (bits_be, label_y) in &bits_values {
                Circuit::reset();
                let a = Group::<Circuit>::new(mode_a, *x);
                let b: Vec<Boolean<Circuit>> = Inject::new(mode_b, bits_be.clone());
                let scalar = bits_be.iter().fold(ConsoleScalar::zero(), |scalar, bit| match bit {
                    true => scalar.double() + ConsoleScalar::one(),
                    false => scalar.double(),
                });
                let label = format!("{block} {label_x} {label_y}");
                let outcome = snapshot::measure(&label, Some(*x * scalar), None, || &a * b.as_slice());
                let values = format!("{} {}", value_label(mode_a, label_x), value_label(mode_b, label_y));
                cases.push(Case { block: block.clone(), values, outcome });
            }
        }
        cases
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
    fn cases(modes: [Mode; 3]) -> Vec<Case> {
        snapshot::ternary(
            |c: &Boolean<Circuit>, a: &Group<Circuit>, b: &Group<Circuit>| Group::ternary(c, a, b),
            None,
            &values(),
            modes,
        )
    }
    assert_snapshot(&FILES, "ternary", run_parallel(mode_jobs(1, cases)));
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
nullary_snapshot!(zero, Console::zero());
nullary_snapshot!(generator, Console::generator());
