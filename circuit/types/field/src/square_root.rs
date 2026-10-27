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

impl<E: Environment> SquareRoot for Field<E> {
    type Output = Self;

    /// Returns the square root of `self`.
    /// If there are two square roots, the bitwise lesser one is returned.
    /// If there are no square roots, zero is returned.
    fn square_root(&self) -> Self::Output {
        let square_root: Field<E> = witness!(|self| match self.square_root() {
            Ok(square_root) => square_root,
            _ => console::Field::zero(),
        });

        // Ensure `square_root` * `square_root` == `self`.
        E::enforce(|| (&square_root, &square_root, self)).expect("Square root constraint unsatisfied");

        // Define the MODULUS_MINUS_ONE_DIV_TWO as a constant.
        let modulus_minus_one_div_two = match E::BaseField::from_bigint(E::BaseField::modulus_minus_one_div_two()) {
            Some(modulus_minus_one_div_two) => Field::constant(console::Field::new(modulus_minus_one_div_two)),
            None => E::halt("Failed to initialize MODULUS_MINUS_ONE_DIV_TWO as a constant"),
        };

        // Ensure that `square_root` is less than or equal to (MODULUS - 1) / 2.
        // This ensures that the resulting square root is unique.
        let is_less_than_or_equal = square_root.is_less_than_or_equal(&modulus_minus_one_div_two);
        E::assert(is_less_than_or_equal).expect("Square root uniqueness constraint unsatisfied");

        square_root
    }
}

impl<E: Environment> Field<E> {
    /// Returns the square root of `self`, where the least significant bit of the square root is zero.
    pub fn even_square_root(&self) -> Self {
        let square_root: Field<E> = witness!(|self| match self.even_square_root() {
            Ok(square_root) => square_root,
            _ => console::Field::zero(),
        });

        // Ensure `square_root` * `square_root` == `self`.
        E::enforce(|| (&square_root, &square_root, self)).expect("Even square root constraint unsatisfied");

        // Ensure that the LSB of the square root is zero.
        // Note that this unwrap is safe since the number of bits is always greater than zero.
        E::assert(!square_root.to_bits_be().last().unwrap()).expect("Even square root LSB constraint unsatisfied");

        square_root
    }
}

impl<E: Environment> Field<E> {
    /// Returns both square roots of `self` and a `Boolean` flag, which is set iff `self` is not a square.
    ///
    /// If `self` is a non-zero square,
    ///  - the first field result is one root and the second field result is its negation,
    ///    but which of the two roots is returned first is **not** enforced
    ///  - the flag is 0
    ///
    /// If `self` is 0,
    ///  - both field results are 0
    ///  - the flag is 0
    ///
    /// If `self` is not a square,
    ///  - both field results are 0
    ///  - the flag is 1
    ///
    /// The constraints do **not** impose an ordering on the two roots returned by this function;
    /// this is what the `nondeterministic` part of this function name refers to.
    /// This is safe in the only production caller, `Group::from_x_coordinate_flagged`,
    /// which constructs both candidate points and selects the one in the prime-order
    /// subgroup, so it does not depend on which root is returned first.
    pub fn square_roots_flagged_nondeterministic(&self) -> (Self, Self, Boolean<E>) {
        // Obtain (p-1)/2, as a constant field element.
        let modulus_minus_one_div_two = match E::BaseField::from_bigint(E::BaseField::modulus_minus_one_div_two()) {
            Some(modulus_minus_one_div_two) => Field::constant(console::Field::new(modulus_minus_one_div_two)),
            None => E::halt("Failed to initialize (modulus - 1) / 2"),
        };

        // Use Euler's criterion: self is a non-zero square iff self^((p-1)/2) is 1.
        let euler = self.pow(modulus_minus_one_div_two);
        let is_nonzero_square = euler.is_one();

        // Calculate the witness for the first square result.
        // Note that the **console** function `square_root` returns the square root closer to 0.
        let root_witness = match self.eject_value().square_root() {
            Ok(root) => root,
            Err(_) => console::Field::zero(),
        };

        // Initialize the square element, which is either `self` or 0, depending on whether `self` is a square.
        // This is done to ensure that the below constraint is satisfied even if `self` is not a square.
        let square = Self::ternary(&is_nonzero_square, self, &Field::zero());

        // Initialize a new variable for the first root.
        let mode = if self.eject_mode() == Mode::Constant { Mode::Constant } else { Mode::Private };
        let first_root = Field::new(mode, root_witness);

        // Enforce that the first root squared is equal to the square.
        // Note that if `self` is not a square, then `first_root` and `square` are both zero and the constraint is satisfied.
        E::enforce(|| (&first_root, &first_root, &square)).expect("Flagged square root constraint unsatisfied");

        // Initialize the second root as the negation of the first root.
        let second_root = first_root.clone().neg();

        // The error flag is set iff self is a non-square, i.e. it is neither zero nor a non-zero square.
        let is_nonzero = !self.is_zero();
        let error_flag = is_nonzero.bitand(is_nonzero_square.not());

        (first_root, second_root, error_flag)
    }
}

impl<E: Environment> Metrics<dyn SquareRoot<Output = Field<E>>> for Field<E> {
    type Case = Mode;

    fn count(case: &Self::Case) -> Count {
        match case.is_constant() {
            true => Count::is(2, 0, 0, 0),
            false => Count::is(1, 0, 758, 761),
        }
    }
}

impl<E: Environment> OutputMode<dyn SquareRoot<Output = Field<E>>> for Field<E> {
    type Case = Mode;

    fn output_mode(case: &Self::Case) -> Mode {
        match case.is_constant() {
            true => Mode::Constant,
            false => Mode::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_square_root(name: &str, mode: Mode, rng: &mut TestRng) {
        for _ in 0..ITERATIONS {
            // Sample a random element.
            let given: console::Field<<Circuit as Environment>::Network> = Uniform::rand(rng);
            // Compute its square root, or skip this iteration if it does not natively exist.
            if let Ok(expected) = given.square_root() {
                let input = Field::<Circuit>::new(mode, given);

                Circuit::scope(name, || {
                    let candidate = input.square_root();
                    assert_eq!(expected, candidate.eject_value());
                    assert_count!(SquareRoot(Field) => Field, &mode);
                    assert_output_mode!(SquareRoot(Field) => Field, &mode, candidate);
                });
                Circuit::reset();
            }
        }
    }

    fn check_even_square_root(
        name: &str,
        rng: &mut TestRng,
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        for _ in 0..ITERATIONS {
            // Sample a random element.
            let given: console::Field<<Circuit as Environment>::Network> = Uniform::rand(rng);
            // Compute its square root, or skip this iteration if it does not natively exist.
            if let Ok(expected) = given.even_square_root() {
                let input = Field::<Circuit>::new(mode, given);

                Circuit::scope(name, || {
                    let candidate = input.even_square_root();
                    assert_eq!(expected, candidate.eject_value());
                    assert_scope!(num_constants, num_public, num_private, num_constraints);
                });
                Circuit::reset();
            }
        }
    }

    fn check_square_roots_flagged_nondeterministic(
        name: &str,
        mode: Mode,
        rng: &mut TestRng,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        for _ in 0..ITERATIONS {
            // Sample a random element.
            let given: console::Field<<Circuit as Environment>::Network> = Uniform::rand(rng);
            // Compute square roots and error flag in console-land.
            let (expected_error_flag, expected_positive_root, expected_negative_root) = match given.square_root() {
                Ok(root) => (false, root, -root),
                Err(_) => (true, console::Field::zero(), console::Field::zero()),
            };
            // Compute square roots and error flag in circuit-land.
            let input = Field::<Circuit>::new(mode, given);
            Circuit::scope(name, || {
                let (candidate_first_root, candidate_second_root, candidate_error_flag) =
                    input.square_roots_flagged_nondeterministic();
                // Although the order of the roots is unspecified in the circuit,
                // the witness values are in a fixed order (first positive, then negative).
                assert_eq!(expected_error_flag, candidate_error_flag.eject_value());
                assert_eq!(expected_positive_root, candidate_first_root.eject_value());
                assert_eq!(expected_negative_root, candidate_second_root.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    #[test]
    fn test_square_root() {
        let mut rng = TestRng::default();

        check_square_root("Constant", Mode::Constant, &mut rng);
        check_square_root("Public", Mode::Public, &mut rng);
        check_square_root("Private", Mode::Private, &mut rng);
    }

    #[test]
    fn test_even_square_root() {
        let mut rng = TestRng::default();

        check_even_square_root("Constant", &mut rng, Mode::Constant, 254, 0, 0, 0);
        check_even_square_root("Public", &mut rng, Mode::Public, 0, 0, 506, 509);
        check_even_square_root("Private", &mut rng, Mode::Private, 0, 0, 506, 509);
    }

    #[test]
    fn test_square_roots_flagged_nondeterministic() {
        let mut rng = TestRng::default();

        check_square_roots_flagged_nondeterministic("Constant", Mode::Constant, &mut rng, 257, 0, 0, 0);
        check_square_roots_flagged_nondeterministic("Public", Mode::Public, &mut rng, 254, 0, 344, 344);
        check_square_roots_flagged_nondeterministic("Private", Mode::Private, &mut rng, 254, 0, 344, 344);
    }
}
