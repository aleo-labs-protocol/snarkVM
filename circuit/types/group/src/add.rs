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

impl<E: Environment> Add<Self> for Group<E> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        self + &other
    }
}

impl<E: Environment> Add<&Self> for Group<E> {
    type Output = Self;

    fn add(self, other: &Self) -> Self::Output {
        // If `self` is constant *and* `self` is zero, then return `other`.
        if self.is_constant() && self.eject_value().is_zero() {
            other.clone()
        }
        // If `other` is constant *and* `other` is zero, then return `self`.
        else if other.is_constant() && other.eject_value().is_zero() {
            self
        }
        // Otherwise, compute the sum of `self` and `other`.
        else {
            // This swap reduces the number of constants by one.
            let (this, that) = match other.is_constant() {
                true => (&self, other),
                false => (other, &self),
            };

            let a = Field::constant(console::Field::new(E::EDWARDS_A));
            let d = Field::constant(console::Field::new(E::EDWARDS_D));

            // Compute U = (-A * x1 + y1) * (x2 + y2)
            let u1 = (&this.x * &-&a) + &this.y;
            let u2 = &that.x + &that.y;
            let u = u1 * u2;

            // Compute v0 = x1 * y2
            let v0 = &this.x * &that.y;

            // Compute v1 = x2 * y1
            let v1 = &that.x * &this.y;

            // Compute v2 = d * v0 * v1
            let v2 = (&v0 * &v1) * d;

            // Montgomery's trick: one inversion for x3 = (v0 + v1) / (v2 + 1) and y3 = (U + a * v0 - v1) / (1 - v2).
            // Divide, not `inverse().unwrap_or(..)`: a zero denominator must halt, not yield a wrong witness.
            let (x3, y3) = witness!(|a, u, v0, v1, v2| {
                let one = console::Field::one();
                let (x_den, y_den) = (v2 + one, one - v2);
                let inv = one / (x_den * y_den);
                ((v0 + v1) * y_den * inv, (u + (v0 * a) - v1) * x_den * inv)
            });

            // Ensure x3 is well-formed.
            // x3 * (v2 + 1) = v0 + v1
            let v2_plus_one = &v2 + &Field::one();
            let v0_plus_v1 = &v0 + &v1;
            E::enforce(|| (&x3, v2_plus_one, v0_plus_v1)).expect("Group add x3 constraint unsatisfied");

            // Ensure y3 is well-formed.
            // y3 * (1 - v2) = u + (a * v0) - v1
            let one_minus_v2 = Field::one() - v2;
            let a_v0 = v0 * a;
            let u_plus_a_v0_minus_v1 = u + a_v0 - v1;
            E::enforce(|| (&y3, one_minus_v2, u_plus_a_v0_minus_v1)).expect("Group add y3 constraint unsatisfied");

            Self { x: x3, y: y3 }
        }
    }
}

impl<E: Environment> Add<&Group<E>> for &Group<E> {
    type Output = Group<E>;

    fn add(self, other: &Group<E>) -> Self::Output {
        (*self).clone() + other
    }
}

impl<E: Environment> AddAssign<Self> for Group<E> {
    fn add_assign(&mut self, other: Self) {
        *self += &other;
    }
}

impl<E: Environment> AddAssign<&Self> for Group<E> {
    fn add_assign(&mut self, other: &Self) {
        *self = self.clone() + other;
    }
}

impl<E: Environment> Metrics<dyn Add<Group<E>, Output = Group<E>>> for Group<E> {
    type Case = (Mode, Mode);

    fn count(case: &Self::Case) -> Count {
        match (case.0, case.1) {
            (Mode::Constant, Mode::Constant) => Count::less_than(4, 0, 0, 0),
            (Mode::Constant, _) | (_, Mode::Constant) => Count::is(2, 0, 3, 3),
            (_, _) => Count::is(2, 0, 6, 6),
        }
    }
}

impl<E: Environment> OutputMode<dyn Add<Group<E>, Output = Group<E>>> for Group<E> {
    type Case = (Mode, Mode);

    // TODO: This implementation is incorrect. In the case where one operand is a constant and is equal to zero, then the output mode
    //  is that of the other operand.
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

    fn check_add(
        name: &str,
        expected: &console::Group<<Circuit as Environment>::Network>,
        a: &Group<Circuit>,
        b: &Group<Circuit>,
    ) {
        Circuit::scope(name, || {
            let candidate = a + b;
            assert_eq!(*expected, candidate.eject_value(), "({} + {})", a.eject_value(), b.eject_value());
            assert_count!(Add(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Add(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()), candidate);
        });
    }

    fn check_add_assign(
        name: &str,
        expected: &console::Group<<Circuit as Environment>::Network>,
        a: &Group<Circuit>,
        b: &Group<Circuit>,
    ) {
        Circuit::scope(name, || {
            let mut candidate = a.clone();
            candidate += b;
            assert_eq!(*expected, candidate.eject_value(), "({} + {})", a.eject_value(), b.eject_value());
            assert_count!(Add(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()));
            assert_output_mode!(Add(Group, Group) => Group, &(a.eject_mode(), b.eject_mode()), candidate);
        });
    }

    fn run_test(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let a = Group::<Circuit>::new(mode_a, first);
            let b = Group::<Circuit>::new(mode_b, second);

            let expected = first + second;

            let name = format!("Add: a + b {i}");
            check_add(&name, &expected, &a, &b);
            let name = format!("AddAssign: a + b {i}");
            check_add_assign(&name, &expected, &a, &b);
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
    fn test_add_small_order() {
        let mut points = small_order_points::<Circuit>().to_vec();
        points.push(Uniform::rand(&mut TestRng::default()));
        for first in &points {
            for second in &points {
                let candidate = inject_unchecked::<Circuit>(first.to_x_coordinate(), first.to_y_coordinate())
                    + inject_unchecked(second.to_x_coordinate(), second.to_y_coordinate());
                assert_eq!(*first + *second, candidate.eject_value());
                assert!(Circuit::is_satisfied());
                Circuit::reset();
            }
        }
    }

    #[test]
    #[should_panic(expected = "Field division by zero")]
    fn test_add_zero_x_denominator() {
        let one = console::Field::one();
        let d = console::Field::<<Circuit as Environment>::Network>::new(<Circuit as Environment>::EDWARDS_D);
        let _ = inject_unchecked::<Circuit>(one, one) + inject_unchecked(one, -d.inverse().expect("d is nonzero"));
    }

    #[test]
    #[should_panic(expected = "Field division by zero")]
    fn test_add_zero_y_denominator() {
        let one = console::Field::one();
        let d = console::Field::<<Circuit as Environment>::Network>::new(<Circuit as Environment>::EDWARDS_D);
        let _ = inject_unchecked::<Circuit>(one, one) + inject_unchecked(one, d.inverse().expect("d is nonzero"));
    }

    #[test]
    fn test_add_matches() {
        let mut rng = TestRng::default();

        // Sample two random elements.
        let a = Uniform::rand(&mut rng);
        let b = Uniform::rand(&mut rng);
        let expected = a + b;

        // Constant
        let first = Group::<Circuit>::new(Mode::Constant, a);
        let second = Group::<Circuit>::new(Mode::Constant, b);
        let candidate_a = first + second;
        assert_eq!(expected, candidate_a.eject_value());

        // Private
        let first = Group::<Circuit>::new(Mode::Private, a);
        let second = Group::<Circuit>::new(Mode::Private, b);
        let candidate_b = first + second;
        assert_eq!(expected, candidate_b.eject_value());
    }
}
