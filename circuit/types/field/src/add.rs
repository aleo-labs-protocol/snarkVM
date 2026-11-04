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

use std::borrow::Cow;

impl<E: Environment> Add<Field<E>> for Field<E> {
    type Output = Field<E>;

    fn add(self, other: Field<E>) -> Self::Output {
        let mut result = self;
        result += other;
        result
    }
}

impl<E: Environment> Add<&Field<E>> for Field<E> {
    type Output = Field<E>;

    fn add(self, other: &Field<E>) -> Self::Output {
        let mut result = self;
        result += other;
        result
    }
}

impl<E: Environment> Add<Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn add(self, other: Field<E>) -> Self::Output {
        other + self
    }
}

impl<E: Environment> Add<&Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn add(self, other: &Field<E>) -> Self::Output {
        self.clone() + other
    }
}

impl<E: Environment> AddAssign<Field<E>> for Field<E> {
    fn add_assign(&mut self, other: Field<E>) {
        self.linear_combination += Cow::Owned(other.linear_combination);
        self.bits_le = Default::default();
    }
}
impl<E: Environment> AddAssign<&Field<E>> for Field<E> {
    fn add_assign(&mut self, other: &Field<E>) {
        self.linear_combination += Cow::Borrowed(&other.linear_combination);
        self.bits_le = Default::default();
    }
}

impl<E: Environment> Metrics<dyn Add<Field<E>, Output = Field<E>>> for Field<E> {
    type Case = (Mode, Mode);

    fn count(_case: &Self::Case) -> Count {
        Count::is(0, 0, 0, 0)
    }
}

impl<E: Environment> OutputMode<dyn Add<Field<E>, Output = Field<E>>> for Field<E> {
    type Case = (CircuitType<Field<E>>, CircuitType<Field<E>>);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0.mode(), case.1.mode()) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            (Mode::Constant, Mode::Public) => match &case.0 {
                CircuitType::Constant(constant) => match constant.eject_value().is_zero() {
                    true => Mode::Public,
                    false => Mode::Private,
                },
                _ => E::halt("The constant is required to determine the output mode of Public + Constant"),
            },
            (Mode::Public, Mode::Constant) => match &case.1 {
                CircuitType::Constant(constant) => match constant.eject_value().is_zero() {
                    true => Mode::Public,
                    false => Mode::Private,
                },
                _ => E::halt("The constant is required to determine the output mode of Public + Constant"),
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

    fn check_add(
        name: &str,
        expected: &console::Field<<Circuit as Environment>::Network>,
        a: &Field<Circuit>,
        b: &Field<Circuit>,
    ) {
        Circuit::scope(name, || {
            let candidate = a + b;
            assert_eq!(*expected, candidate.eject_value(), "({} + {})", a.eject_value(), b.eject_value());
            assert_count!(Add(Field, Field) => Field, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Add(Field, Field) => Field, &(CircuitType::from(a), CircuitType::from(b)), candidate);
        });
    }

    fn check_add_assign(
        name: &str,
        expected: &console::Field<<Circuit as Environment>::Network>,
        a: &Field<Circuit>,
        b: &Field<Circuit>,
    ) {
        Circuit::scope(name, || {
            let mut candidate = a.clone();
            candidate += b;
            assert_eq!(*expected, candidate.eject_value(), "({} + {})", a.eject_value(), b.eject_value());
            assert_count!(Add(Field, Field) => Field, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Add(Field, Field) => Field, &(CircuitType::from(a), CircuitType::from(b)), candidate);
        });
    }

    fn run_test(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first + second;
            let a = Field::<Circuit>::new(mode_a, first);
            let b = Field::<Circuit>::new(mode_b, second);

            let name = format!("Add: a + b {i}");
            check_add(&name, &expected, &a, &b);
            let name = format!("AddAssign: a + b {i}");
            check_add_assign(&name, &expected, &a, &b);

            // Test identity.
            let name = format!("Add: a + 0 {i}");
            let zero = Field::<Circuit>::new(mode_b, console::Field::<<Circuit as Environment>::Network>::zero());
            check_add(&name, &first, &a, &zero);
            let name = format!("AddAssign: a + 0 {i}");
            check_add_assign(&name, &first, &a, &zero);

            let name = format!("Add: 0 + b {i}");
            let zero = Field::<Circuit>::new(mode_a, console::Field::<<Circuit as Environment>::Network>::zero());
            check_add(&name, &second, &zero, &b);
            let name = format!("AddAssign: 0 + b {i}");
            check_add_assign(&name, &second, &zero, &b);
        }
    }

    #[test]
    fn test_constant_plus_constant() {
        run_test(Mode::Constant, Mode::Constant);
    }

    #[test]
    fn test_constant_plus_public() {
        run_test(Mode::Constant, Mode::Public);
    }

    #[test]
    fn test_public_plus_constant() {
        run_test(Mode::Public, Mode::Constant);
    }

    #[test]
    fn test_constant_plus_private() {
        run_test(Mode::Constant, Mode::Private);
    }

    #[test]
    fn test_private_plus_constant() {
        run_test(Mode::Private, Mode::Constant);
    }

    #[test]
    fn test_public_plus_public() {
        run_test(Mode::Public, Mode::Public);
    }

    #[test]
    fn test_public_plus_private() {
        run_test(Mode::Public, Mode::Private);
    }

    #[test]
    fn test_private_plus_public() {
        run_test(Mode::Private, Mode::Public);
    }

    #[test]
    fn test_private_plus_private() {
        run_test(Mode::Private, Mode::Private);
    }

    #[test]
    fn test_0_plus_0() {
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();

        let candidate = Field::<Circuit>::zero() + Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::zero() + &Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, zero) + Field::new(Mode::Public, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, zero) + Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, zero) + Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());
    }

    #[test]
    fn test_0_plus_1() {
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();
        let one = console::Field::<<Circuit as Environment>::Network>::one();

        let candidate = Field::<Circuit>::zero() + Field::one();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::zero() + &Field::one();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::one() + Field::zero();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::one() + &Field::zero();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Public, zero);
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Private, zero);
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Private, zero);
        assert_eq!(one, candidate.eject_value());
    }

    #[test]
    fn test_1_plus_1() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();
        let two = one + one;

        let candidate = Field::<Circuit>::one() + Field::one();
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::one() + &Field::one();
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Public, one);
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Public, one);
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Private, one);
        assert_eq!(two, candidate.eject_value());
    }

    #[test]
    fn test_1_plus_2() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();
        let two = one + one;
        let three = two + one;

        let candidate_two = Field::<Circuit>::one() + Field::one();
        let candidate = candidate_two + Field::one();
        assert_eq!(three, candidate.eject_value());

        let candidate_two = Field::<Circuit>::one() + &Field::one();
        let candidate = candidate_two + &Field::one();
        assert_eq!(three, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Public, two);
        assert_eq!(three, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Public, two);
        assert_eq!(three, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Private, two);
        assert_eq!(three, candidate.eject_value());
    }
}
