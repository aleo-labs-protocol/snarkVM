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

impl<E: Environment> Equal<Self> for Field<E> {
    type Output = Boolean<E>;

    ///
    /// Returns `true` if `self` and `other` are equal.
    ///
    /// This method costs 2 constraints.
    ///
    fn is_equal(&self, other: &Self) -> Self::Output {
        !self.is_not_equal(other)
    }

    ///
    /// Returns `true` if `self` and `other` are *not* equal.
    ///
    /// This method constructs a boolean that indicates if
    /// `self` and `other ` are *not* equal to each other.
    ///
    /// This method costs 2 constraints.
    ///
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        // Initialize a (console) boolean that is `true` if `this` and `that` are not equivalent.
        let is_neq_ejected = self.eject_value() != other.eject_value();

        match (self.is_constant(), other.is_constant()) {
            // If both operands are 'Constant', the result is also 'Constant'.
            (true, true) => Boolean::new(Mode::Constant, is_neq_ejected),
            _ => {
                // Inequality Enforcement
                // ----------------------------------------------------------------
                // Check 1:  (a - b) * multiplier = is_neq
                // Check 2:  (a - b) * (1 - is_neq) = 0
                //
                //
                // Case 1: a == b AND is_neq == 0 (honest)
                // ----------------------------------------------------------------
                // Check 1:  (a - b) * multiplier = 0
                //                 0 * multiplier = 0
                //                              0 = 0
                // => The constraint is satisfied.
                //
                // Check 2:  (a - b) * (1 - 0) = 0
                //                       0 * 1 = 0
                //                           0 = 0
                // => The constraint is satisfied.
                //
                //
                // Case 2: a == b AND is_neq != 0 (dishonest)
                // ----------------------------------------------------------------
                // Check 1:  (a - b) * multiplier = is_neq
                //                 0 * multiplier = is_neq
                //                              0 = is_neq
                // => As is_neq != 0, the constraint is not satisfied.
                //
                //
                // Case 3: a != b AND is_neq != 1 (dishonest).
                // ----------------------------------------------------------------
                // Check 2:  (a - b) * (1 - is_neq) = 0
                //                     (1 - is_neq) = 0
                // => As is_neq != 1, the constraint is not satisfied.
                //
                //
                // Case 4a: a != b AND is_neq == 1 AND multiplier = n [!= (a - b)^(-1)] (dishonest)
                // ---------------------------------------------------------------------------------
                // Check 1:  (a - b) * n = 1
                // => As n != (a - b)^(-1), the constraint is not satisfied.
                //
                //
                // Case 4b: a != b AND is_neq == 1 AND multiplier = (a - b)^(-1) (honest)
                // ---------------------------------------------------------------------------------
                // Check 1:  (a - b) * (a - b)^(-1) = 1
                //                                1 = 1
                // => The constraint is satisfied.
                //
                // Check 2:  (a - b) * (1 - 1) = 0
                //                 (a - b) * 0 = 0
                //                           0 = 0
                // => The constraint is satisfied.
                //
                //
                // Observe that in both of the honest cases, `is_neq` is always 0 or 1.

                // Witness a boolean that is `true` if `this` and `that` are not equivalent.
                let is_neq = Boolean::from_variable(E::new_variable(Mode::Private, match is_neq_ejected {
                    true => E::BaseField::one(),
                    false => E::BaseField::zero(),
                }));

                // Compute `self` - `other`.
                let delta = self - other;

                // Assign the expected multiplier as a witness.
                //
                // Note: the inverse of `delta` is not guaranteed to exist, and if it does not,
                // we pick 1 as the multiplier, as its value is irrelevant to satisfy the constraints.
                let multiplier: Field<E> = witness!(|delta| {
                    match delta.inverse() {
                        Ok(inverse) => inverse,
                        _ => console::Field::one(),
                    }
                });

                // Negate `is_neq`.
                let is_eq = !is_neq.clone();

                // Check 1: (a - b) * multiplier = is_neq
                E::enforce(|| (&delta, &multiplier, &is_neq)).expect("Field equality check 1 failed");

                // Check 2: (a - b) * not(is_neq) = 0
                E::enforce(|| (delta, is_eq, E::zero())).expect("Field equality check 2 failed");

                // Return `is_neq`.
                is_neq
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_is_equal(name: &str, expected: bool, a: &Field<Circuit>, b: &Field<Circuit>) {
        Circuit::scope(name, || {
            let candidate = a.is_equal(b);
            assert_eq!(expected, candidate.eject_value(), "({} == {})", a.eject_value(), b.eject_value());
            assert_scope!();
        });
    }

    fn check_is_not_equal(name: &str, expected: bool, a: &Field<Circuit>, b: &Field<Circuit>) {
        Circuit::scope(name, || {
            let candidate = a.is_not_equal(b);
            assert_eq!(expected, candidate.eject_value(), "({} != {})", a.eject_value(), b.eject_value());
            assert_scope!();
        });
    }

    fn run_test(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let a = Field::<Circuit>::new(mode_a, first);
            let b = Field::<Circuit>::new(mode_b, second);

            let name = format!("Equal: a == b {i}");
            check_is_equal(&name, first == second, &a, &b);

            let name = format!("Not Equal: a != b {i}");
            check_is_not_equal(&name, first != second, &a, &b);

            // Check first is equal to first.
            let a = Field::<Circuit>::new(mode_a, first);
            let b = Field::<Circuit>::new(mode_b, first);
            let name = format!("{first} == {first}");
            check_is_equal(&name, true, &a, &b);

            // Check second is equal to second.
            let a = Field::<Circuit>::new(mode_a, second);
            let b = Field::<Circuit>::new(mode_b, second);
            let name = format!("{second} == {second}");
            check_is_equal(&name, true, &a, &b);
        }
    }

    #[test]
    fn test_constant_is_equal_to_constant() {
        run_test(Mode::Constant, Mode::Constant);
    }

    #[test]
    fn test_constant_is_not_equal_to_public() {
        run_test(Mode::Constant, Mode::Public);
    }

    #[test]
    fn test_constant_is_not_equal_to_private() {
        run_test(Mode::Constant, Mode::Private);
    }

    #[test]
    fn test_public_is_equal_to_constant() {
        run_test(Mode::Public, Mode::Constant);
    }

    #[test]
    fn test_private_is_equal_to_constant() {
        run_test(Mode::Private, Mode::Constant);
    }

    #[test]
    fn test_public_is_equal_to_public() {
        run_test(Mode::Public, Mode::Public);
    }

    #[test]
    fn test_public_is_not_equal_to_private() {
        run_test(Mode::Public, Mode::Private);
    }

    #[test]
    fn test_private_is_equal_to_public() {
        run_test(Mode::Private, Mode::Public);
    }

    #[test]
    fn test_private_is_equal_to_private() {
        run_test(Mode::Private, Mode::Private);
    }

    #[test]
    fn test_is_eq_cases() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();

        // Basic `true` and `false` cases
        {
            let mut accumulator = one + one;

            for _ in 0..ITERATIONS {
                let a = Field::<Circuit>::new(Mode::Private, accumulator);
                let b = Field::<Circuit>::new(Mode::Private, accumulator);
                let is_eq = a.is_equal(&b);
                assert!(is_eq.eject_value()); // true

                let a = Field::<Circuit>::new(Mode::Private, one);
                let b = Field::<Circuit>::new(Mode::Private, accumulator);
                let is_eq = a.is_equal(&b);
                assert!(!is_eq.eject_value()); // false

                let a = Field::<Circuit>::new(Mode::Private, accumulator);
                let b = Field::<Circuit>::new(Mode::Private, accumulator - one);
                let is_eq = a.is_equal(&b);
                assert!(!is_eq.eject_value()); // false

                accumulator += one;
            }
        }
    }

    #[test]
    fn test_is_neq_cases() {
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();
        let one = console::Field::<<Circuit as Environment>::Network>::one();
        let two = one + one;
        let five = two + two + one;

        // Inequality Enforcement
        // ----------------------------------------------------------------
        // Check 1:  (a - b) * multiplier = is_neq
        // Check 2:  (a - b) * not(is_neq) = 0

        let enforce = |a: Field<Circuit>, b: Field<Circuit>, multiplier: Field<Circuit>, is_neq: Boolean<Circuit>| {
            // Compute `self` - `other`.
            let delta = &a - &b;

            // Negate `is_neq`.
            let is_eq = !is_neq.clone();

            // Check 1: (a - b) * multiplier = is_neq
            Circuit::enforce(|| (delta.clone(), multiplier, is_neq.clone())).unwrap();

            // Check 2: (a - b) * not(is_neq) = 0
            Circuit::enforce(|| (delta, is_eq, Circuit::zero())).unwrap();
        };

        //
        // Case 1: a == b AND is_neq == 0 (honest)
        // ----------------------------------------------------------------

        let a = Field::<Circuit>::new(Mode::Private, five);
        let b = Field::<Circuit>::new(Mode::Private, five);
        let multiplier = Field::<Circuit>::new(Mode::Private, one);
        let is_neq = Boolean::new(Mode::Private, false);

        assert!(Circuit::is_satisfied());
        enforce(a, b, multiplier, is_neq);
        assert!(Circuit::is_satisfied());
        Circuit::reset();

        //
        // Case 2: a == b AND is_neq == 1 (dishonest)
        // ----------------------------------------------------------------

        let a = Field::<Circuit>::new(Mode::Private, five);
        let b = Field::<Circuit>::new(Mode::Private, five);
        let multiplier = Field::<Circuit>::new(Mode::Private, one);
        let is_neq = Boolean::new(Mode::Private, true);

        assert!(Circuit::is_satisfied());
        enforce(a, b, multiplier, is_neq);
        assert!(!Circuit::is_satisfied());
        Circuit::reset();

        // Case 3a: a != b AND is_neq == 0 AND multiplier = 0 (dishonest)
        // ----------------------------------------------------------------

        let a = Field::<Circuit>::new(Mode::Private, five);
        let b = Field::<Circuit>::new(Mode::Private, two);
        let multiplier = Field::<Circuit>::new(Mode::Private, zero);
        let is_neq = Boolean::new(Mode::Private, false);

        assert!(Circuit::is_satisfied());
        enforce(a, b, multiplier, is_neq);
        assert!(!Circuit::is_satisfied());
        Circuit::reset();

        //
        // Case 3b: a != b AND is_neq == 0 AND multiplier = 1 (dishonest)
        // ----------------------------------------------------------------

        let a = Field::<Circuit>::new(Mode::Private, five);
        let b = Field::<Circuit>::new(Mode::Private, two);
        let multiplier = Field::<Circuit>::new(Mode::Private, one);
        let is_neq = Boolean::new(Mode::Private, false);

        assert!(Circuit::is_satisfied());
        enforce(a, b, multiplier, is_neq);
        assert!(!Circuit::is_satisfied());
        Circuit::reset();

        //
        // Case 4a: a != b AND is_neq == 1 AND multiplier = n [!= (a - b)^(-1)] (dishonest)
        // ---------------------------------------------------------------------------------

        let a = Field::<Circuit>::new(Mode::Private, five);
        let b = Field::<Circuit>::new(Mode::Private, two);
        let multiplier = Field::<Circuit>::new(Mode::Private, two);
        let is_neq = Boolean::new(Mode::Private, true);

        assert!(Circuit::is_satisfied());
        enforce(a, b, multiplier, is_neq);
        assert!(!Circuit::is_satisfied());
        Circuit::reset();

        //
        // Case 4b: a != b AND is_neq == 1 AND multiplier = (a - b)^(-1) (honest)
        // ---------------------------------------------------------------------------------

        let a = Field::<Circuit>::new(Mode::Private, five);
        let b = Field::<Circuit>::new(Mode::Private, two);
        let multiplier =
            Field::<Circuit>::new(Mode::Private, (five - two).inverse().expect("Failed to compute a native inverse"));
        let is_neq = Boolean::new(Mode::Private, true);

        assert!(Circuit::is_satisfied());
        enforce(a, b, multiplier, is_neq);
        assert!(Circuit::is_satisfied());
        Circuit::reset();
    }
}
