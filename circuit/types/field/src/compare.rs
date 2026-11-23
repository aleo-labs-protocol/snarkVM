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

impl<E: Environment> Compare<Field<E>> for Field<E> {
    type Output = Boolean<E>;

    /// Returns `true` if `self` is less than `other`.
    fn is_less_than(&self, other: &Self) -> Self::Output {
        // Case 1: Constant < Constant
        if self.is_constant() && other.is_constant() {
            Boolean::constant(self.eject_value() < other.eject_value())
        }
        // Case 2: Constant < Variable
        else if self.is_constant() {
            // See the `else` case below for the truth table and description of the logic.
            self.eject_value().to_bits_le().into_iter().zip_eq(other.to_bits_le()).fold(
                Boolean::constant(false),
                |is_less_than, (this, that)| match this {
                    true => that.bitand(&is_less_than),
                    false => that.bitor(&is_less_than),
                },
            )
        }
        // Case 3: Variable < Constant
        else if other.is_constant() {
            // See the `else` case below for the truth table and description of the logic.
            self.to_bits_le().into_iter().zip_eq(other.eject_value().to_bits_le()).fold(
                Boolean::constant(false),
                |is_less_than, (this, that)| match that {
                    true => (!this).bitor(is_less_than),
                    false => (!this).bitand(&is_less_than),
                },
            )
        }
        // Case 4: Variable < Variable
        else {
            // Check each bitwise pair of `(self, other)` from MSB to LSB as follows:
            //   - If `this` != `that`, and if `this` is `true`, return `false`.
            //   - If `this` != `that`, and if `this` is `false`, return `true`.
            //   - If `this` == `that`, return `is_less_than`.
            //
            // The following is the truth table:
            //
            // | this    | that    | is_less_than | result |
            // |---------+---------+--------------+--------|
            // | `true`  | `true`  | `true`       | `true` |
            // | `true`  | `true`  | `false`      | `false`|
            // | `true`  | `false` | `true`       | `true` |
            // | `true`  | `false` | `false`      | `true` |
            // | `false` | `true`  | `true`       | `false`|
            // | `false` | `true`  | `false`      | `false`|
            // | `false` | `false` | `true`       | `true` |
            // | `false` | `false` | `false`      | `false`|
            //
            self.to_bits_le()
                .iter()
                .zip_eq(other.to_bits_le())
                .fold(Boolean::constant(false), |is_less_than, (this, that)| {
                    Boolean::ternary(&this.bitxor(&that), &that, &is_less_than)
                })
        }
    }

    /// Returns `true` if `self` is greater than `other`.
    fn is_greater_than(&self, other: &Self) -> Self::Output {
        other.is_less_than(self)
    }

    /// Returns `true` if `self` is less than or equal to `other`.
    fn is_less_than_or_equal(&self, other: &Self) -> Self::Output {
        other.is_greater_than_or_equal(self)
    }

    /// Returns `true` if `self` is greater than or equal to `other`.
    fn is_greater_than_or_equal(&self, other: &Self) -> Self::Output {
        !self.is_less_than(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_is_less_than(
        name: &str,
        expected: bool,
        a: &Field<Circuit>,
        b: &Field<Circuit>,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        // Perform the less than comparison.
        Circuit::scope(name, || {
            let candidate = a.is_less_than(b);
            assert_eq!(expected, candidate.eject_value());
            match (a.eject_mode(), b.eject_mode()) {
                (Mode::Constant, Mode::Constant) => {
                    assert_scope!(num_constants, num_public, num_private, num_constraints)
                }
                (_, Mode::Constant) | (Mode::Constant, _) => {
                    assert_scope!(<=num_constants, <=num_public, <=num_private, <=num_constraints)
                }
                _ => assert_scope!(num_constants, num_public, num_private, num_constraints),
            }
        });
        Circuit::reset();
    }

    fn run_test(
        mode_a: Mode,
        mode_b: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let a = Field::<Circuit>::new(mode_a, first);
            let b = Field::<Circuit>::new(mode_b, second);
            let expected = first < second;
            let name = format!("{mode_a} {mode_b} {i}");
            check_is_less_than(&name, expected, &a, &b, num_constants, num_public, num_private, num_constraints);

            // Check `first` is not less than `first`.
            let a = Field::<Circuit>::new(mode_a, first);
            let b = Field::<Circuit>::new(mode_b, first);
            check_is_less_than(
                "first !< first",
                false,
                &a,
                &b,
                num_constants,
                num_public,
                num_private,
                num_constraints,
            );
        }
    }

    #[test]
    fn test_constant_is_less_than_constant() {
        run_test(Mode::Constant, Mode::Constant, 0, 0, 0, 0);
    }

    #[test]
    fn test_constant_is_less_than_public() {
        run_test(Mode::Constant, Mode::Public, 0, 0, 757, 759);
    }

    #[test]
    fn test_constant_is_less_than_private() {
        run_test(Mode::Constant, Mode::Private, 0, 0, 757, 759);
    }

    #[test]
    fn test_public_is_less_than_constant() {
        run_test(Mode::Public, Mode::Constant, 0, 0, 757, 759);
    }

    #[test]
    fn test_public_is_less_than_public() {
        run_test(Mode::Public, Mode::Public, 0, 0, 1516, 1520);
    }

    #[test]
    fn test_public_is_less_than_private() {
        run_test(Mode::Public, Mode::Private, 0, 0, 1516, 1520);
    }

    #[test]
    fn test_private_is_less_than_constant() {
        run_test(Mode::Private, Mode::Constant, 0, 0, 757, 759);
    }

    #[test]
    fn test_private_is_less_than_public() {
        run_test(Mode::Private, Mode::Public, 0, 0, 1516, 1520);
    }

    #[test]
    fn test_private_is_less_than_private() {
        run_test(Mode::Private, Mode::Private, 0, 0, 1516, 1520);
    }
}
