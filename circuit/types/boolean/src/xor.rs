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

impl<E: Environment> BitXor<Boolean<E>> for Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self != other)`.
    fn bitxor(self, other: Boolean<E>) -> Self::Output {
        self ^ &other
    }
}

impl<E: Environment> BitXor<Boolean<E>> for &Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self != other)`.
    fn bitxor(self, other: Boolean<E>) -> Self::Output {
        self ^ &other
    }
}

impl<E: Environment> BitXor<&Boolean<E>> for Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self != other)`.
    fn bitxor(self, other: &Boolean<E>) -> Self::Output {
        &self ^ other
    }
}

impl<E: Environment> BitXor<&Boolean<E>> for &Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(self != other)`.
    fn bitxor(self, other: &Boolean<E>) -> Self::Output {
        // Constant `self`
        if self.is_constant() {
            match self.eject_value() {
                true => !other.clone(),
                false => other.clone(),
            }
        }
        // Constant `other`
        else if other.is_constant() {
            match other.eject_value() {
                true => !self.clone(),
                false => self.clone(),
            }
        }
        // Variable != Variable
        else {
            // Declare a new variable with the expected output as witness.
            // Note: The constraint below will ensure `output` is either 0 or 1,
            // assuming `self` and `other` are well-formed (they are either 0 or 1).
            let output = Boolean(
                E::new_variable(Mode::Private, match self.eject_value() ^ other.eject_value() {
                    true => E::BaseField::one(),
                    false => E::BaseField::zero(),
                })
                .into(),
            );

            //
            // Ensure (`self` + `self`) * (`other`) = (`self` + `other` - `output`)
            // `output` is `1` iff `self` != `other`.
            //
            // As `self` and `other` are enforced to be `Boolean` types,
            // if they are equal, then the `output` is 0,
            // and if they are different, then `output` must be 1.
            //
            // ¬(a ∧ b) ∧ ¬(¬a ∧ ¬b) = c
            //
            // (1 - (a * b)) * (1 - ((1 - a) * (1 - b))) = c
            // (1 - ab) * (1 - (1 - a - b + ab)) = c
            // (1 - ab) * (a + b - ab) = c
            // a + b - ab - (a^2)b - (b^2)a + (a^2)(b^2) = c
            // a + b - ab - ab - ab + ab = c
            // a + b - 2ab = c
            // -2a * b = c - a - b
            // 2a * b = a + b - c
            // (a + a) * b = a + b - c
            //
            E::enforce(|| ((&self.0 + &self.0), other, (&self.0 + &other.0 - &output.0)))
                .expect("Boolean XOR constraint unsatisfied");

            output
        }
    }
}

impl<E: Environment> BitXorAssign<Boolean<E>> for Boolean<E> {
    /// Sets `self` as `(self != other)`.
    fn bitxor_assign(&mut self, other: Boolean<E>) {
        *self ^= &other;
    }
}

impl<E: Environment> BitXorAssign<&Boolean<E>> for Boolean<E> {
    /// Sets `self` as `(self != other)`.
    fn bitxor_assign(&mut self, other: &Boolean<E>) {
        *self = &*self ^ other;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    fn check_xor(
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
            let candidate = &a ^ &b;
            assert_eq!(expected, candidate.eject_value(), "({} != {})", a.eject_value(), b.eject_value());
            assert_scope!(num_constants, num_public, num_private, num_constraints);
        });
    }

    #[test]
    fn test_constant_xor_constant() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_xor("false != false", expected, a, b, 0, 0, 0, 0);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_xor("false != true", expected, a, b, 0, 0, 0, 0);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_xor("true != false", expected, a, b, 0, 0, 0, 0);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_xor("true != true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_constant_xor_public() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_xor("false != false", expected, a, b, 0, 0, 0, 0);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_xor("false != true", expected, a, b, 0, 0, 0, 0);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_xor("true != false", expected, a, b, 0, 0, 0, 0);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_xor("true != true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_constant_xor_private() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_xor("false != false", expected, a, b, 0, 0, 0, 0);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_xor("false != true", expected, a, b, 0, 0, 0, 0);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_xor("true != false", expected, a, b, 0, 0, 0, 0);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_xor("true != true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_public_xor_constant() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_xor("false != false", expected, a, b, 0, 0, 0, 0);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_xor("false != true", expected, a, b, 0, 0, 0, 0);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_xor("true != false", expected, a, b, 0, 0, 0, 0);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_xor("true != true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_public_xor_public() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_xor("false != false", expected, a, b, 0, 0, 1, 1);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_xor("false != true", expected, a, b, 0, 0, 1, 1);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_xor("true != false", expected, a, b, 0, 0, 1, 1);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_xor("true != true", expected, a, b, 0, 0, 1, 1);
    }

    #[test]
    fn test_public_xor_private() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_xor("false != false", expected, a, b, 0, 0, 1, 1);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_xor("false != true", expected, a, b, 0, 0, 1, 1);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_xor("true != false", expected, a, b, 0, 0, 1, 1);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_xor("true != true", expected, a, b, 0, 0, 1, 1);
    }

    #[test]
    fn test_private_xor_constant() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_xor("false != false", expected, a, b, 0, 0, 0, 0);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_xor("false != true", expected, a, b, 0, 0, 0, 0);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_xor("true != false", expected, a, b, 0, 0, 0, 0);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_xor("true != true", expected, a, b, 0, 0, 0, 0);
    }

    #[test]
    fn test_private_xor_public() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_xor("false != false", expected, a, b, 0, 0, 1, 1);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_xor("false != true", expected, a, b, 0, 0, 1, 1);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_xor("true != false", expected, a, b, 0, 0, 1, 1);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_xor("true != true", expected, a, b, 0, 0, 1, 1);
    }

    #[test]
    fn test_private_xor_private() {
        // false != false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_xor("false != false", expected, a, b, 0, 0, 1, 1);

        // false != true
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_xor("false != true", expected, a, b, 0, 0, 1, 1);

        // true != false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_xor("true != false", expected, a, b, 0, 0, 1, 1);

        // true != true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_xor("true != true", expected, a, b, 0, 0, 1, 1);
    }
}
