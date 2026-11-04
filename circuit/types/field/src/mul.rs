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

impl<E: Environment> Mul<Field<E>> for Field<E> {
    type Output = Field<E>;

    fn mul(self, other: Field<E>) -> Self::Output {
        self * &other
    }
}

impl<E: Environment> Mul<&Field<E>> for Field<E> {
    type Output = Field<E>;

    fn mul(self, other: &Field<E>) -> Self::Output {
        match other.is_constant() {
            true => (self.linear_combination * *other.eject_value()).into(),
            false => &self * other,
        }
    }
}

impl<E: Environment> Mul<Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn mul(self, other: Field<E>) -> Self::Output {
        other * self
    }
}

impl<E: Environment> Mul<&Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn mul(self, other: &Field<E>) -> Self::Output {
        match (self.is_constant(), other.is_constant()) {
            (true, true) | (false, true) => (&self.linear_combination * *other.eject_value()).into(),
            (true, false) => (&other.linear_combination * *self.eject_value()).into(),
            (false, false) => {
                let product = witness!(|self, other| self * other);

                // Ensure self * other == product.
                E::enforce(|| (self, other, &product)).expect("Field multiplication constraint unsatisfied");

                product
            }
        }
    }
}

impl<E: Environment> MulAssign<Field<E>> for Field<E> {
    fn mul_assign(&mut self, other: Field<E>) {
        *self *= &other;
    }
}

impl<E: Environment> MulAssign<&Field<E>> for Field<E> {
    fn mul_assign(&mut self, other: &Field<E>) {
        *self = &*self * other;
    }
}

impl<E: Environment> Metrics<dyn Mul<Field<E>, Output = Field<E>>> for Field<E> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match case.0.is_constant() || case.1.is_constant() {
            true => Count::is(0, 0, 0, 0),
            false => Count::is(0, 0, 1, 1),
        }
    }
}

impl<E: Environment> OutputMode<dyn Mul<Field<E>, Output = Field<E>>> for Field<E> {
    type Case = (CircuitType<Field<E>>, CircuitType<Field<E>>);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0.mode(), case.1.mode()) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            (Mode::Constant, Mode::Public) => match &case.0 {
                CircuitType::Constant(constant) => match constant.eject_value() {
                    value if value.is_zero() => Mode::Constant,
                    value if value.is_one() => Mode::Public,
                    _ => Mode::Private,
                },
                _ => E::halt("The constant is required to determine the output mode of Constant * Public"),
            },
            (Mode::Public, Mode::Constant) => match &case.1 {
                CircuitType::Constant(constant) => match constant.eject_value() {
                    value if value.is_zero() => Mode::Constant,
                    value if value.is_one() => Mode::Public,
                    _ => Mode::Private,
                },
                _ => E::halt("The constant is required to determine the output mode of Public * Constant"),
            },
            (Mode::Private, Mode::Constant) => match &case.1 {
                CircuitType::Constant(constant) => match constant.eject_value() {
                    value if value.is_zero() => Mode::Constant,
                    _ => Mode::Private,
                },
                _ => E::halt("The constant is required to determine the output mode of Private * Constant"),
            },
            (Mode::Constant, Mode::Private) => match &case.0 {
                CircuitType::Constant(constant) => match constant.eject_value() {
                    value if value.is_zero() => Mode::Constant,
                    _ => Mode::Private,
                },
                _ => E::halt("The constant is required to determine the output mode of Constant * Private"),
            },
            (_, _) => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_mul(
        name: &str,
        expected: &console::Field<<Circuit as Environment>::Network>,
        a: &Field<Circuit>,
        b: &Field<Circuit>,
    ) {
        Circuit::scope(name, || {
            let candidate = a * b;
            assert_eq!(*expected, candidate.eject_value(), "({} * {})", a.eject_value(), b.eject_value());
            assert_count!(Mul(Field, Field) => Field, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Mul(Field, Field) => Field, &(CircuitType::from(a), CircuitType::from(b)), candidate);
        });
    }

    fn check_mul_assign(
        name: &str,
        expected: &console::Field<<Circuit as Environment>::Network>,
        a: &Field<Circuit>,
        b: &Field<Circuit>,
    ) {
        Circuit::scope(name, || {
            let mut candidate = a.clone();
            candidate *= b;
            assert_eq!(*expected, candidate.eject_value(), "({} * {})", a.eject_value(), b.eject_value());
            assert_count!(Mul(Field, Field) => Field, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Mul(Field, Field) => Field, &(CircuitType::from(a), CircuitType::from(b)), candidate);
        });
    }

    fn run_test(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first * second;
            let a = Field::<Circuit>::new(mode_a, first);
            let b = Field::<Circuit>::new(mode_b, second);

            let name = format!("Mul: a + b {i}");
            check_mul(&name, &expected, &a, &b);
            let name = format!("MulAssign: a + b {i}");
            check_mul_assign(&name, &expected, &a, &b);

            // Test identity.
            let name = format!("Mul: a * 1 {i}");
            let one = Field::<Circuit>::new(mode_b, console::Field::<<Circuit as Environment>::Network>::one());
            check_mul(&name, &first, &a, &one);
            let name = format!("MulAssign: a * 1 {i}");
            check_mul_assign(&name, &first, &a, &one);

            let name = format!("Mul: 1 * b {i}");
            let one = Field::<Circuit>::new(mode_a, console::Field::<<Circuit as Environment>::Network>::one());
            check_mul(&name, &second, &one, &b);
            let name = format!("MulAssign: 1 * b {i}");
            check_mul_assign(&name, &second, &one, &b);

            // Test zero.
            let name = format!("Mul: a * 0 {i}");
            let zero = Field::<Circuit>::new(mode_b, console::Field::<<Circuit as Environment>::Network>::zero());
            check_mul(&name, &console::Field::<<Circuit as Environment>::Network>::zero(), &a, &zero);
            let name = format!("MulAssign: a * 0 {i}");
            check_mul_assign(&name, &console::Field::<<Circuit as Environment>::Network>::zero(), &a, &zero);

            let name = format!("Mul: 0 * b {i}");
            let zero = Field::<Circuit>::new(mode_a, console::Field::<<Circuit as Environment>::Network>::zero());
            check_mul(&name, &console::Field::<<Circuit as Environment>::Network>::zero(), &zero, &b);
            let name = format!("MulAssign: 0 * b {i}");
            check_mul_assign(&name, &console::Field::<<Circuit as Environment>::Network>::zero(), &zero, &b);
        }
    }

    #[test]
    fn test_constant_times_constant() {
        run_test(Mode::Constant, Mode::Constant);
    }

    #[test]
    fn test_constant_times_public() {
        run_test(Mode::Constant, Mode::Public);
    }

    #[test]
    fn test_constant_times_private() {
        run_test(Mode::Constant, Mode::Private);
    }

    #[test]
    fn test_public_times_constant() {
        run_test(Mode::Public, Mode::Constant);
    }

    #[test]
    fn test_private_times_constant() {
        run_test(Mode::Private, Mode::Constant);
    }

    #[test]
    fn test_public_times_public() {
        run_test(Mode::Public, Mode::Public);
    }

    #[test]
    fn test_public_times_private() {
        run_test(Mode::Public, Mode::Private);
    }

    #[test]
    fn test_private_times_public() {
        run_test(Mode::Private, Mode::Public);
    }

    #[test]
    fn test_private_times_private() {
        run_test(Mode::Private, Mode::Private);
    }

    #[test]
    fn test_mul_matches() {
        let mut rng = TestRng::default();

        // Sample two random elements.
        let a = Uniform::rand(&mut rng);
        let b = Uniform::rand(&mut rng);
        let expected = a * b;

        // Constant
        let first = Field::<Circuit>::new(Mode::Constant, a);
        let second = Field::<Circuit>::new(Mode::Constant, b);
        let candidate_a = first * second;
        assert_eq!(expected, candidate_a.eject_value());

        // Private
        let first = Field::<Circuit>::new(Mode::Private, a);
        let second = Field::<Circuit>::new(Mode::Private, b);
        let candidate_b = first * second;
        assert_eq!(expected, candidate_b.eject_value());
    }

    #[test]
    fn test_0_times_0() {
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();

        let candidate = Field::<Circuit>::zero() * Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::zero() * &Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, zero) * Field::new(Mode::Public, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, zero) * Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, zero) * Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());
    }

    #[test]
    fn test_0_times_1() {
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();
        let one = console::Field::<<Circuit as Environment>::Network>::one();

        let candidate = Field::<Circuit>::zero() * Field::one();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::zero() * &Field::one();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::one() * Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::one() * &Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) * Field::new(Mode::Public, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) * Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) * Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());
    }

    #[test]
    fn test_1_times_1() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();

        let candidate = Field::<Circuit>::one() * Field::one();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::one() * &Field::one();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) * Field::new(Mode::Public, one);
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) * Field::new(Mode::Public, one);
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) * Field::new(Mode::Private, one);
        assert_eq!(one, candidate.eject_value());
    }

    #[test]
    fn test_2_times_2() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();
        let two = one + one;
        let four = two + two;

        let candidate_two = Field::<Circuit>::one() + Field::one();
        let candidate = candidate_two * (Field::<Circuit>::one() + Field::one());
        assert_eq!(four, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, two) * Field::new(Mode::Public, two);
        assert_eq!(four, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, two) * Field::new(Mode::Public, two);
        assert_eq!(four, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, two) * Field::new(Mode::Private, two);
        assert_eq!(four, candidate.eject_value());
    }
}
