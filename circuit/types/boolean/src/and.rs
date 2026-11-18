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

impl<E: Environment> BitAnd<Boolean<E>> for Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: Boolean<E>) -> Self::Output {
        self & &other
    }
}

impl<E: Environment> BitAnd<Boolean<E>> for &Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: Boolean<E>) -> Self::Output {
        self & &other
    }
}

impl<E: Environment> BitAnd<&Boolean<E>> for Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: &Boolean<E>) -> Self::Output {
        &self & other
    }
}

impl<E: Environment> BitAnd<&Boolean<E>> for &Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self AND other)`.
    fn bitand(self, other: &Boolean<E>) -> Self::Output {
        // Constant `self`
        if self.is_constant() {
            match self.eject_value() {
                true => other.clone(),
                false => self.clone(),
            }
        }
        // Constant `other`
        else if other.is_constant() {
            match other.eject_value() {
                true => self.clone(),
                false => other.clone(),
            }
        }
        // Variable AND Variable
        else {
            // Declare a new variable with the expected output as witness.
            // Note: The constraint below will ensure `output` is either 0 or 1,
            // assuming `self` and `other` are well-formed (they are either 0 or 1).
            let output = Boolean(
                E::new_variable(Mode::Private, match self.eject_value() & other.eject_value() {
                    true => E::BaseField::one(),
                    false => E::BaseField::zero(),
                })
                .into(),
            );

            // Ensure `self` * `other` = `output`
            // `output` is `1` iff `self` AND `other` are both `1`.
            E::enforce(|| (self, other, &output)).expect("Boolean AND constraint unsatisfied");

            output
        }
    }
}

impl<E: Environment> BitAndAssign<Boolean<E>> for Boolean<E> {
    /// Sets `self` as `(self AND other)`.
    fn bitand_assign(&mut self, other: Boolean<E>) {
        *self &= &other;
    }
}

impl<E: Environment> BitAndAssign<&Boolean<E>> for Boolean<E> {
    /// Sets `self` as `(self AND other)`.
    fn bitand_assign(&mut self, other: &Boolean<E>) {
        *self = &*self & other;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    fn check_and(
        name: &str,
        expected: bool,
        a: Boolean<Circuit>,
        b: Boolean<Circuit>,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        Circuit::scope(name, || {
            let candidate = &a & &b;
            assert_eq!(expected, candidate.eject_value(), "({} AND {})", a.eject_value(), b.eject_value());
            assert_scope!(num_constants, num_public, num_private, num_constraints);
        });
    }

    #[test]
    fn test_constant_and_constant() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_and("false AND false", expected, a, b, 0, 0, 0, 0);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_and("false AND true", expected, a, b, 0, 0, 0, 0);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_and("true AND false", expected, a, b, 0, 0, 0, 0);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_and("true AND true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_constant_and_public() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_and("false AND false", expected, a, b, 0, 0, 0, 0);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_and("false AND true", expected, a, b, 0, 0, 0, 0);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_and("true AND false", expected, a, b, 0, 0, 0, 0);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_and("true AND true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_constant_and_private() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("false AND false", expected, a, b, 0, 0, 0, 0);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("false AND true", expected, a, b, 0, 0, 0, 0);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("true AND false", expected, a, b, 0, 0, 0, 0);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("true AND true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_public_and_constant() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_and("false AND false", expected, a, b, 0, 0, 0, 0);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_and("false AND true", expected, a, b, 0, 0, 0, 0);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_and("true AND false", expected, a, b, 0, 0, 0, 0);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_and("true AND true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_public_and_public() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_and("false AND false", expected, a, b, 0, 0, 1, 1);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_and("false AND true", expected, a, b, 0, 0, 1, 1);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_and("true AND false", expected, a, b, 0, 0, 1, 1);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_and("true AND true", expected, a, b, 0, 0, 1, 1);
    }

    #[test]
    fn test_public_and_private() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("false AND false", expected, a, b, 0, 0, 1, 1);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("false AND true", expected, a, b, 0, 0, 1, 1);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("true AND false", expected, a, b, 0, 0, 1, 1);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("true AND true", expected, a, b, 0, 0, 1, 1);
    }

    #[test]
    fn test_private_and_constant() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_and("false AND false", expected, a, b, 0, 0, 0, 0);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_and("false AND true", expected, a, b, 0, 0, 0, 0);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_and("true AND false", expected, a, b, 0, 0, 0, 0);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_and("true AND true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_private_and_public() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("false AND false", expected, a, b, 0, 0, 1, 1);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("false AND true", expected, a, b, 0, 0, 1, 1);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("true AND false", expected, a, b, 0, 0, 1, 1);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("true AND true", expected, a, b, 0, 0, 1, 1);
    }

    #[test]
    fn test_private_and_private() {
        // false AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("false AND false", expected, a, b, 0, 0, 1, 1);

        // false AND true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("false AND true", expected, a, b, 0, 0, 1, 1);

        // true AND false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_and("true AND false", expected, a, b, 0, 0, 1, 1);

        // true AND true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_and("true AND true", expected, a, b, 0, 0, 1, 1);
    }
}
