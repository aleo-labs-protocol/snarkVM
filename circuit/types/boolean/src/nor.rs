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

impl<E: Environment> Nor<Self> for Boolean<E> {
    type Output = Boolean<E>;

    /// Returns `(NOT a) AND (NOT b)`.
    fn nor(&self, other: &Self) -> Self::Output {
        // Constant `self`
        if self.is_constant() {
            match self.eject_value() {
                true => !self.clone(),
                false => !other.clone(),
            }
        }
        // Constant `other`
        else if other.is_constant() {
            match other.eject_value() {
                true => !other.clone(),
                false => !self.clone(),
            }
        }
        // Variable NOR Variable
        else {
            // Declare a new variable with the expected output as witness.
            // Note: The constraint below will ensure `output` is either 0 or 1,
            // assuming `self` and `other` are well-formed (they are either 0 or 1).
            let output = Boolean(
                E::new_variable(Mode::Private, match !self.eject_value() & !other.eject_value() {
                    true => E::BaseField::one(),
                    false => E::BaseField::zero(),
                })
                .into(),
            );

            // Ensure (1 - `self`) * (1 - `other`) = `output`
            // `output` is `1` iff `self` and `other` are both `0`, otherwise `output` is `0`.
            E::enforce(|| (E::one() - &self.0, E::one() - &other.0, &output))
                .expect("Boolean NOR constraint unsatisfied");

            output
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    fn check_nor(name: &str, expected: bool, a: Boolean<Circuit>, b: Boolean<Circuit>) {
        Circuit::scope(name, || {
            let candidate = a.nor(&b);
            assert_eq!(expected, candidate.eject_value(), "({} NOR {})", a.eject_value(), b.eject_value());
            assert_scope!();
        });
        Circuit::reset();
    }

    #[test]
    fn test_constant_nor_constant() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_constant_nor_public() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_constant_nor_private() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Constant, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_public_nor_constant() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_public_nor_public() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_public_nor_private() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Public, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_private_nor_constant() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Constant, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_private_nor_public() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Public, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Public, true);
        check_nor("true NOR true", expected, a, b);
    }

    #[test]
    fn test_private_nor_private() {
        // false NOR false
        let expected = true;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_nor("false NOR false", expected, a, b);

        // false NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, false);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_nor("false NOR true", expected, a, b);

        // true NOR false
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Private, false);
        check_nor("true NOR false", expected, a, b);

        // true NOR true
        let expected = false;
        let a = Boolean::<Circuit>::new(Mode::Private, true);
        let b = Boolean::<Circuit>::new(Mode::Private, true);
        check_nor("true NOR true", expected, a, b);
    }
}
