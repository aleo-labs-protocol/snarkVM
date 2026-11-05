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

impl<E: Environment> Double for Group<E> {
    type Output = Group<E>;

    fn double(&self) -> Self::Output {
        // If `self` is constant *and* `self` is zero, then return `self`.
        if self.is_constant() && self.eject_value().is_zero() {
            self.clone()
        }
        // Otherwise, compute `self` + `self`.
        else {
            let a = Field::constant(console::Field::new(E::EDWARDS_A));
            let two = Field::one().double();

            // Compute xy, xx, yy, axx.
            let xy = &self.x * &self.y;
            let x2 = self.x.square();
            let y2 = self.y.square();
            let ax2 = &x2 * &a;

            // Montgomery's trick: one inversion for x3 = 2xy / (ax^2 + y^2) and y3 = (y^2 - ax^2) / (2 - ax^2 - y^2).
            // Divide, not `inverse().unwrap_or(..)`: a zero denominator must halt, not yield a wrong witness.
            let (x3, y3) = witness!(|two, xy, y2, ax2| {
                let (x_den, y_den) = (ax2 + y2, two - ax2 - y2);
                let inv = console::Field::one() / (x_den * y_den);
                (xy.double() * y_den * inv, (y2 - ax2) * x_den * inv)
            });

            // Ensure x3 is well-formed.
            // x3 * (ax^2 + y^2) = 2xy
            let ax2_plus_y2 = &ax2 + &y2;
            let two_xy = xy.double();
            E::enforce(|| (&x3, &ax2_plus_y2, two_xy)).expect("Group double x3 constraint unsatisfied");

            // Ensure y3 is well-formed.
            // y3 * (2 - (ax^2 + y^2)) = y^2 - ax^2
            let y2_minus_a_x2 = y2 - ax2;
            let two_minus_ax2_minus_y2 = two - ax2_plus_y2;
            E::enforce(|| (&y3, two_minus_ax2_minus_y2, y2_minus_a_x2))
                .expect("Group double y3 constraint unsatisfied");

            Group { x: x3, y: y3 }
        }
    }
}

impl<E: Environment> Group<E> {
    /// Enforce that double = 2 * self.
    pub fn enforce_double(&self, double: &Group<E>) {
        let a = Field::constant(console::Field::new(E::EDWARDS_A));
        let two = Field::one().double();

        // Compute xy, xx, yy, axx.
        let xy = &self.x * &self.y;
        let x2 = self.x.square();
        let y2 = self.y.square();
        let ax2 = &x2 * &a;

        // Ensure double.x is the abscissa of the double of self.
        // double.x * (ax^2 + y^2) = 2xy
        let ax2_plus_y2 = &ax2 + &y2;
        let two_xy = xy.double();
        E::enforce(|| (&double.x, &ax2_plus_y2, two_xy)).expect("Group enforce_double x constraint unsatisfied");

        // Ensure double.y is the ordinate of the double of self.
        // double.y * (2 - (ax^2 + y^2)) = y^2 - ax^2
        let y2_minus_a_x2 = y2 - ax2;
        let two_minus_ax2_minus_y2 = two - ax2_plus_y2;
        E::enforce(|| (&double.y, two_minus_ax2_minus_y2, y2_minus_a_x2))
            .expect("Group enforce_double y constraint unsatisfied");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    #[test]
    fn test_double() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random element.
            let point: console::Group<<Circuit as Environment>::Network> = Uniform::rand(&mut rng);
            let expected = point.double();

            // Constant variable
            let affine = Group::<Circuit>::new(Mode::Constant, point);

            Circuit::scope(format!("Constant {i}"), || {
                let candidate = affine.double();
                assert_eq!(expected, candidate.eject_value());
                assert_scope!(3, 0, 0, 0);
            });
            Circuit::reset();

            // Public variable
            let affine = Group::<Circuit>::new(Mode::Public, point);

            Circuit::scope(format!("Public {i}"), || {
                let candidate = affine.double();
                assert_eq!(expected, candidate.eject_value());
                assert_scope!(1, 0, 5, 5);
            });
            Circuit::reset();

            // Private variable
            let affine = Group::<Circuit>::new(Mode::Private, point);

            Circuit::scope(format!("Private {i}"), || {
                let candidate = affine.double();
                assert_eq!(expected, candidate.eject_value());
                assert_scope!(1, 0, 5, 5);
            });
            Circuit::reset();
        }
    }

    #[test]
    fn test_double_small_order() {
        for point in small_order_points::<Circuit>() {
            let candidate = inject_unchecked::<Circuit>(point.to_x_coordinate(), point.to_y_coordinate()).double();
            assert_eq!(point.double(), candidate.eject_value());
            assert!(Circuit::is_satisfied());
            Circuit::reset();
        }
    }

    #[test]
    #[should_panic(expected = "Field division by zero")]
    fn test_double_zero_x_denominator() {
        let zero = console::Field::zero();
        inject_unchecked::<Circuit>(zero, zero).double();
    }

    #[test]
    #[should_panic(expected = "Field division by zero")]
    fn test_double_zero_y_denominator() {
        let x = small_order_points::<Circuit>()[2].to_x_coordinate();
        inject_unchecked::<Circuit>(x, console::Field::one()).double();
    }

    #[test]
    fn test_double_matches() {
        // Sample two random elements.
        let a = Uniform::rand(&mut TestRng::default());
        let expected = a + a;

        // Constant
        let candidate_a = Group::<Circuit>::new(Mode::Constant, a).double();
        assert_eq!(expected, candidate_a.eject_value());

        // Private
        let candidate_b = Group::<Circuit>::new(Mode::Private, a).double();
        assert_eq!(expected, candidate_b.eject_value());
    }
}
