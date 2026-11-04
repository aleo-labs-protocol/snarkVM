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

use super::*;

impl<E: Environment, I: IntegerType> Mul<Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        self * &other
    }
}

impl<E: Environment, I: IntegerType> Mul<Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn mul(self, other: Integer<E, I>) -> Self::Output {
        self * &other
    }
}

impl<E: Environment, I: IntegerType> Mul<&Integer<E, I>> for Integer<E, I> {
    type Output = Self;

    fn mul(self, other: &Self) -> Self::Output {
        &self * other
    }
}

impl<E: Environment, I: IntegerType> Mul<&Integer<E, I>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn mul(self, other: &Integer<E, I>) -> Self::Output {
        let mut output = self.clone();
        output *= other;
        output
    }
}

impl<E: Environment, I: IntegerType> MulAssign<Integer<E, I>> for Integer<E, I> {
    fn mul_assign(&mut self, other: Integer<E, I>) {
        *self *= &other;
    }
}

impl<E: Environment, I: IntegerType> MulAssign<&Integer<E, I>> for Integer<E, I> {
    fn mul_assign(&mut self, other: &Integer<E, I>) {
        // Stores the product of `self` and `other` in `self`.
        *self = self.mul_checked(other);
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn Mul<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        <Self as Metrics<dyn DivChecked<Integer<E, I>, Output = Integer<E, I>>>>::count(case)
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn Mul<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        <Self as OutputMode<dyn DivChecked<Integer<E, I>, Output = Integer<E, I>>>>::output_mode(case)
    }
}

impl<E: Environment, I: IntegerType> MulChecked<Self> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn mul_checked(&self, other: &Integer<E, I>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the product and return the new constant.
            match self.eject_value().checked_mul(&other.eject_value()) {
                Some(value) => Integer::new(Mode::Constant, console::Integer::new(value)),
                None => E::halt("Integer overflow on multiplication of two constants"),
            }
        } else if I::is_signed() {
            // Compute the product of `abs(self)` and `abs(other)`, while checking for an overflow.
            // Note: it is safe to use `abs_wrapped` as we want `Integer::MIN` to be interpreted as an unsigned number.
            let product = Self::mul_and_check(&self.abs_wrapped(), &other.abs_wrapped());

            // If the product should be positive, then it cannot exceed the signed maximum.
            let operands_same_sign = &self.msb().is_equal(other.msb());
            let positive_product_overflows = operands_same_sign & product.msb();
            E::assert_eq(positive_product_overflows, E::zero())
                .expect("Signed multiplication positive overflow check failed");

            // If the product should be negative, then it cannot exceed the absolute value of the signed minimum.
            let negative_product_underflows = {
                let lower_product_bits_nonzero =
                    product.bits_le[..(I::BITS as usize - 1)].iter().fold(Boolean::constant(false), |a, b| a | b);
                let negative_product_lt_or_eq_signed_min =
                    !product.msb() | (product.msb() & !lower_product_bits_nonzero);
                !operands_same_sign & !negative_product_lt_or_eq_signed_min
            };
            E::assert_eq(negative_product_underflows, E::zero())
                .expect("Signed multiplication negative underflow check failed");

            // Note that the relevant overflow cases are checked independently above.
            // Return the product of `self` and `other` with the appropriate sign.
            Self::ternary(operands_same_sign, &product, &Self::zero().sub_wrapped(&product))
        } else {
            // Compute the product of `self` and `other`, while checking for an overflow.
            Self::mul_and_check(self, other)
        }
    }
}

impl<E: Environment, I: IntegerType> Integer<E, I> {
    /// Multiply the integer bits of `this` and `that`, while checking for an overflow.
    /// This function assumes that `this` and `that` are non-negative.
    #[inline]
    fn mul_and_check(this: &Integer<E, I>, that: &Integer<E, I>) -> Integer<E, I> {
        // Case 1 - 2 integers fit in 1 field element (u8, u16, u32, u64, i8, i16, i32, i64).
        if 2 * I::BITS < (E::BaseField::size_in_bits() - 1) as u64 {
            // Instead of multiplying the bits of `self` and `other`, witness the integer product.
            let product: Integer<E, I> = witness!(|this, that| this.mul_wrapped(&that));

            // Check that the computed product is equal to witnessed product, in the base field.
            // Note: The multiplication is safe as the field twice as large as the maximum integer type supported.
            E::enforce(|| (this.to_field(), that.to_field(), product.to_field()))
                .expect("Integer multiplication constraint unsatisfied");

            product
        }
        // Case 2 - 1.5 integers fit in 1 field element (u128, i128).
        else if (I::BITS + I::BITS / 2) < (E::BaseField::size_in_bits() - 1) as u64 {
            // Use Karatsuba multiplication to compute the product of `self` and `other`.
            let (product, z_1_upper_bits, z2) = Self::karatsuba_multiply(this, that);

            // Check that the upper bits of z1 are zero.
            Boolean::assert_bits_are_zero(&z_1_upper_bits);

            // Check that `z2` is zero.
            E::assert_eq(z2, E::zero()).expect("Karatsuba multiplication overflow check failed");

            // Return the product of `self` and `other`.
            product
        } else {
            E::halt(format!("Multiplication of integers of size {} is not supported", I::BITS))
        }
    }
}

impl<E: Environment, I: IntegerType> Integer<E, I> {
    /// Multiply the integer bits of `this` and `that`, using Karatsuba multiplication.
    ///
    /// See this page for reference: https://en.wikipedia.org/wiki/Karatsuba_algorithm.
    ///
    /// We follow the naming convention given in the `Basic Step` section of the cited page.
    /// The output is the product of `this` and `that`, the upper bits of `z1`, and `z2` as a field element.
    /// This function assumes that 1.5 * I::BITS fits in 1 field element.
    #[inline]
    pub(super) fn karatsuba_multiply(
        this: &Integer<E, I>,
        that: &Integer<E, I>,
    ) -> (Integer<E, I>, Vec<Boolean<E>>, Field<E>) {
        // Perform multiplication by decomposing it into operations on its upper and lower bits.
        // Here is a picture of the bits involved, placed according to the power-of-two weights, in little endian order:
        //   x0: <--I::BITS/2-->
        //   x1:                <--I::BITS/2-->
        //   y0: <--I::BITS/2-->
        //   y1:                <--I::BITS/2-->
        //   z0: <-----------I::BITS---------->
        //   z1:                <-----------I::BITS+1--------->
        //   z2:                               <-----------I::BITS---------->
        //                                     |   overlap    |
        // The carry bits include:
        //   - the overlapping bits of z1 and z2
        //   - the upper bits of z2

        let x_1 = Field::from_bits_le(&this.bits_le[(I::BITS as usize / 2)..]);
        let x_0 = Field::from_bits_le(&this.bits_le[..(I::BITS as usize / 2)]);
        let y_1 = Field::from_bits_le(&that.bits_le[(I::BITS as usize / 2)..]);
        let y_0 = Field::from_bits_le(&that.bits_le[..(I::BITS as usize / 2)]);

        let z_0 = &x_0 * &y_0;
        let z_2 = &x_1 * &y_1;
        let z_1 = (&x_1 + &x_0) * (&y_1 + &y_0) - &z_2 - &z_0;

        let mut b_m_bits = vec![Boolean::constant(false); I::BITS as usize / 2];
        b_m_bits.push(Boolean::constant(true));

        let b_m = Field::from_bits_le(&b_m_bits);
        let z_0_plus_scaled_z_1 = &z_0 + (&z_1 * &b_m);

        let bits_le = z_0_plus_scaled_z_1.to_lower_bits_le(I::BITS as usize + I::BITS as usize / 2 + 1);

        // Split the integer bits into product bits and the upper bits of `z_1`.
        let (bits_le, carry) = bits_le.split_at(I::BITS as usize);

        // Return the product of `self` and `other`, along with the carry bits.
        (Integer::from_bits_le(bits_le), carry.to_vec(), z_2)
    }
}

impl<E: Environment, I: IntegerType> Metrics<dyn MulChecked<Integer<E, I>, Output = Integer<E, I>>> for Integer<E, I> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        // Case 1 - 2 integers fit in 1 field element (u8, u16, u32, u64, i8, i16, i32, i64).
        if 2 * I::BITS < (E::BaseField::size_in_bits() - 1) as u64 {
            match I::is_signed() {
                // Signed case
                true => match (case.0, case.1) {
                    (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                    (Mode::Constant, _) | (_, Mode::Constant) => {
                        Count::is(4 * I::BITS, 0, (6 * I::BITS) + 4, (6 * I::BITS) + 9)
                    }
                    (_, _) => Count::is(3 * I::BITS, 0, (8 * I::BITS) + 6, (8 * I::BITS) + 12),
                },
                // Unsigned case
                false => match (case.0, case.1) {
                    (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                    (Mode::Constant, _) | (_, Mode::Constant) => Count::is(0, 0, I::BITS, I::BITS + 1),
                    (_, _) => Count::is(0, 0, I::BITS, I::BITS + 1),
                },
            }
        }
        // Case 2 - 1.5 integers fit in 1 field element (u128, i128).
        else if (I::BITS + I::BITS / 2) < (E::BaseField::size_in_bits() - 1) as u64 {
            match I::is_signed() {
                // Signed case
                true => match (case.0, case.1) {
                    (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                    (Mode::Constant, _) | (_, Mode::Constant) => Count::less_than(833, 0, 837, 844),
                    (_, _) => Count::is(3 * I::BITS, 0, 1098, 1106),
                },
                // Unsigned case
                false => match (case.0, case.1) {
                    (Mode::Constant, Mode::Constant) => Count::is(I::BITS, 0, 0, 0),
                    (Mode::Constant, _) | (_, Mode::Constant) => Count::less_than(193, 0, 193, 199),
                    (_, _) => Count::is(0, 0, 196, 199),
                },
            }
        } else {
            E::halt(format!("Multiplication of integers of size {} is not supported", I::BITS))
        }
    }
}

impl<E: Environment, I: IntegerType> OutputMode<dyn MulChecked<Integer<E, I>, Output = Integer<E, I>>>
    for Integer<E, I>
{
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            _ => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use test_utilities::*;

    use core::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: u64 = 10;

    fn check_mul<I: IntegerType + RefUnwindSafe>(
        name: &str,
        first: console::Integer<<Circuit as Environment>::Network, I>,
        second: console::Integer<<Circuit as Environment>::Network, I>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, I>::new(mode_b, second);
        match first.checked_mul(&second) {
            Some(expected) => Circuit::scope(name, || {
                let candidate = a.mul_checked(&b);
                assert_eq!(expected, *candidate.eject_value());
                assert_eq!(console::Integer::new(expected), candidate.eject_value());
                assert_count!(MulChecked(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
                // assert_output_mode!(MulChecked(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b), candidate);
            }),
            None => match (mode_a, mode_b) {
                (Mode::Constant, Mode::Constant) => check_operation_halts(&a, &b, Integer::mul_checked),
                _ => Circuit::scope(name, || {
                    let _candidate = a.mul_checked(&b);
                    assert_count_fails!(MulChecked(Integer<I>, Integer<I>) => Integer<I>, &(mode_a, mode_b));
                }),
            },
        }
        Circuit::reset();
    }

    fn run_test<I: IntegerType + RefUnwindSafe>(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Mul: {mode_a} * {mode_b} {i}");
            check_mul::<I>(&name, first, second, mode_a, mode_b);
            check_mul::<I>(&name, second, first, mode_a, mode_b); // Commute the operation.

            let name = format!("Double: {mode_a} * {mode_b} {i}");
            check_mul::<I>(&name, first, console::Integer::one() + console::Integer::one(), mode_a, mode_b);
            check_mul::<I>(&name, console::Integer::one() + console::Integer::one(), first, mode_a, mode_b); // Commute the operation.

            let name = format!("Square: {mode_a} * {mode_b} {i}");
            check_mul::<I>(&name, first, first, mode_a, mode_b);
        }

        // Check specific cases common to signed and unsigned integers.
        check_mul::<I>("1 * MAX", console::Integer::one(), console::Integer::MAX, mode_a, mode_b);
        check_mul::<I>("MAX * 1", console::Integer::MAX, console::Integer::one(), mode_a, mode_b);
        check_mul::<I>("1 * MIN", console::Integer::one(), console::Integer::MIN, mode_a, mode_b);
        check_mul::<I>("MIN * 1", console::Integer::MIN, console::Integer::one(), mode_a, mode_b);
        check_mul::<I>("0 * MAX", console::Integer::zero(), console::Integer::MAX, mode_a, mode_b);
        check_mul::<I>("MAX * 0", console::Integer::MAX, console::Integer::zero(), mode_a, mode_b);
        check_mul::<I>("0 * MIN", console::Integer::zero(), console::Integer::MIN, mode_a, mode_b);
        check_mul::<I>("MIN * 0", console::Integer::MIN, console::Integer::zero(), mode_a, mode_b);
        check_mul::<I>("1 * 1", console::Integer::one(), console::Integer::one(), mode_a, mode_b);

        // Check common overflow cases.
        check_mul::<I>(
            "MAX * 2",
            console::Integer::MAX,
            console::Integer::one() + console::Integer::one(),
            mode_a,
            mode_b,
        );
        check_mul::<I>(
            "2 * MAX",
            console::Integer::one() + console::Integer::one(),
            console::Integer::MAX,
            mode_a,
            mode_b,
        );

        // Check additional corner cases for signed integers.
        if I::is_signed() {
            check_mul::<I>("MAX * -1", console::Integer::MAX, -console::Integer::one(), mode_a, mode_b);
            check_mul::<I>("-1 * MAX", -console::Integer::one(), console::Integer::MAX, mode_a, mode_b);
            check_mul::<I>("MIN * -1", console::Integer::MIN, -console::Integer::one(), mode_a, mode_b);
            check_mul::<I>("-1 * MIN", -console::Integer::one(), console::Integer::MIN, mode_a, mode_b);
            check_mul::<I>(
                "MIN * -2",
                console::Integer::MIN,
                -console::Integer::one() - console::Integer::one(),
                mode_a,
                mode_b,
            );
            check_mul::<I>(
                "-2 * MIN",
                -console::Integer::one() - console::Integer::one(),
                console::Integer::MIN,
                mode_a,
                mode_b,
            );
        }
    }

    fn run_exhaustive_test<I: IntegerType + RefUnwindSafe>(mode_a: Mode, mode_b: Mode)
    where
        RangeInclusive<I>: Iterator<Item = I>,
    {
        for first in I::MIN..=I::MAX {
            for second in I::MIN..=I::MAX {
                let first = console::Integer::<_, I>::new(first);
                let second = console::Integer::<_, I>::new(second);

                let name = format!("Mul: ({first} * {second})");
                check_mul::<I>(&name, first, second, mode_a, mode_b);
            }
        }
    }

    test_integer_binary!(run_test, i8, times);
    test_integer_binary!(run_test, i16, times);
    test_integer_binary!(run_test, i32, times);
    test_integer_binary!(run_test, i64, times);
    test_integer_binary!(run_test, i128, times);

    test_integer_binary!(run_test, u8, times);
    test_integer_binary!(run_test, u16, times);
    test_integer_binary!(run_test, u32, times);
    test_integer_binary!(run_test, u64, times);
    test_integer_binary!(run_test, u128, times);

    test_integer_binary!(#[ignore], run_exhaustive_test, u8, times, exhaustive);
    test_integer_binary!(#[ignore], run_exhaustive_test, i8, times, exhaustive);
}
