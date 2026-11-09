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

impl<E: Environment> Sub<Self> for Group<E> {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        self - &other
    }
}

impl<E: Environment> Sub<&Self> for Group<E> {
    type Output = Self;

    fn sub(self, other: &Self) -> Self::Output {
        self + -other
    }
}

impl<E: Environment> Sub<&Group<E>> for &Group<E> {
    type Output = Group<E>;

    fn sub(self, other: &Group<E>) -> Self::Output {
        self + &(-other)
    }
}

impl<E: Environment> SubAssign<Self> for Group<E> {
    fn sub_assign(&mut self, other: Self) {
        *self -= &other;
    }
}

impl<E: Environment> SubAssign<&Self> for Group<E> {
    fn sub_assign(&mut self, other: &Self) {
        *self = &*self + &(-other);
    }
}

impl<E: Environment> Metrics<dyn Sub<Group<E>, Output = Group<E>>> for Group<E> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Count::is(4, 0, 0, 0),
            (Mode::Constant, _) | (_, Mode::Constant) => Count::is(2, 0, 3, 3),
            (_, _) => Count::is(2, 0, 6, 6),
        }
    }
}

impl<E: Environment> OutputMode<dyn Sub<Group<E>, Output = Group<E>>> for Group<E> {
    type Case = (Mode, Mode);

    fn output_mode(case: &Self::Case) -> Mode {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Mode::Constant,
            (_, _) => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_sub(
        name: &str,
        expected: &console::Group<<Circuit as Environment>::Network>,
        a: &Group<Circuit>,
        b: &Group<Circuit>,
    ) {
        Circuit::scope(name, || {
            let candidate = a - b;
            assert_eq!(*expected, candidate.eject_value(), "({} - {})", a.eject_value(), b.eject_value());
            assert_count!(Sub(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Sub(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()), candidate);
        });
    }

    fn check_sub_assign(
        name: &str,
        expected: &console::Group<<Circuit as Environment>::Network>,
        a: &Group<Circuit>,
        b: &Group<Circuit>,
    ) {
        Circuit::scope(name, || {
            let mut candidate = a.clone();
            candidate -= b;
            assert_eq!(*expected, candidate.eject_value(), "({} - {})", a.eject_value(), b.eject_value());
            assert_count!(Sub(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Sub(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()), candidate);
        });
    }

    #[test]
    fn test_constant_minus_constant() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Constant, first);
            let b = Group::<Circuit>::new(Mode::Constant, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_constant_minus_public() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Constant, first);
            let b = Group::<Circuit>::new(Mode::Public, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_public_minus_constant() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Public, first);
            let b = Group::<Circuit>::new(Mode::Constant, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_constant_minus_private() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Constant, first);
            let b = Group::<Circuit>::new(Mode::Private, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_private_minus_constant() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Private, first);
            let b = Group::<Circuit>::new(Mode::Constant, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_public_minus_public() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Public, first);
            let b = Group::<Circuit>::new(Mode::Public, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_public_minus_private() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Public, first);
            let b = Group::<Circuit>::new(Mode::Private, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_private_minus_public() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Private, first);
            let b = Group::<Circuit>::new(Mode::Public, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_private_minus_private() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let expected = first - second;
            let a = Group::<Circuit>::new(Mode::Private, first);
            let b = Group::<Circuit>::new(Mode::Private, second);

            let name = format!("Sub: a - b {i}");
            check_sub(&name, &expected, &a, &b);
            let name = format!("SubAssign: a - b {i}");
            check_sub_assign(&name, &expected, &a, &b);
        }
    }

    #[test]
    fn test_sub_matches() {
        let mut rng = TestRng::default();

        // Sample two random elements.
        let a = Uniform::rand(&mut rng);
        let b = Uniform::rand(&mut rng);
        let expected = a - b;

        // Constant
        let first = Group::<Circuit>::new(Mode::Constant, a);
        let second = Group::<Circuit>::new(Mode::Constant, b);
        let candidate_a = first - second;
        assert_eq!(expected, candidate_a.eject_value());

        // Private
        let first = Group::<Circuit>::new(Mode::Private, a);
        let second = Group::<Circuit>::new(Mode::Private, b);
        let candidate_b = first - second;
        assert_eq!(expected, candidate_b.eject_value());
    }
}
