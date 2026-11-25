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

impl<E: Environment> Div<Field<E>> for Field<E> {
    type Output = Field<E>;

    fn div(self, other: Field<E>) -> Self::Output {
        self / &other
    }
}

impl<E: Environment> Div<&Field<E>> for Field<E> {
    type Output = Field<E>;

    fn div(self, other: &Field<E>) -> Self::Output {
        &self / other
    }
}

impl<E: Environment> Div<Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn div(self, other: Field<E>) -> Self::Output {
        self / &other
    }
}

impl<E: Environment> Div<&Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn div(self, other: &Field<E>) -> Self::Output {
        let mut output = self.clone();
        output /= other;
        output
    }
}

impl<E: Environment> DivAssign<Self> for Field<E> {
    fn div_assign(&mut self, other: Self) {
        *self /= &other;
    }
}

impl<E: Environment> DivAssign<&Self> for Field<E> {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn div_assign(&mut self, other: &Self) {
        match other.is_constant() {
            // If `other` is a constant and zero, halt since the inverse of zero is undefined.
            true if other.eject_value().is_zero() => E::halt("Attempted to divide by zero."),
            // If `other` is a constant and non-zero, we can perform multiplication and inversion for 0 constraints.
            // If `self` is a constant, we can perform multiplication and inversion for 1 constraint.
            // Otherwise, we can perform multiplication and inversion for 2 constraints.
            _ => *self *= other.inverse(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::{Circuit, assert_scope_fails};

    const ITERATIONS: u64 = 10;

    fn check_div(
        name: &str,
        first: &console::Field<<Circuit as Environment>::Network>,
        second: &console::Field<<Circuit as Environment>::Network>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = &Field::<Circuit>::new(mode_a, *first);
        let b = &Field::<Circuit>::new(mode_b, *second);

        match second.is_zero() {
            true => match mode_b.is_constant() {
                true => {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Field::div(a.clone(), b)));
                    assert!(result.is_err());
                }
                false => {
                    Circuit::scope(name, || {
                        let _ = a / b;
                        assert_scope_fails!();
                    });
                }
            },
            false => {
                let expected = *first / *second;
                Circuit::scope(name, || {
                    let candidate = a / b;
                    assert_eq!(expected, candidate.eject_value(), "({} / {})", a.eject_value(), b.eject_value());
                    assert_scope!();
                });
            }
        }
    }

    fn check_div_assign(
        name: &str,
        first: &console::Field<<Circuit as Environment>::Network>,
        second: &console::Field<<Circuit as Environment>::Network>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = &Field::<Circuit>::new(mode_a, *first);
        let b = &Field::<Circuit>::new(mode_b, *second);

        match second.is_zero() {
            true => match mode_b.is_constant() {
                true => {
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Field::div_assign(&mut a.clone(), b)));
                    assert!(result.is_err());
                }
                false => {
                    Circuit::scope(name, || {
                        let mut candidate = a.clone();
                        candidate /= b;
                        assert_scope_fails!();
                    });
                }
            },
            false => {
                let expected = *first / *second;
                Circuit::scope(name, || {
                    let mut candidate = a.clone();
                    candidate /= b;
                    assert_eq!(expected, candidate.eject_value(), "({} /= {})", a.eject_value(), b.eject_value());
                    assert_scope!();
                });
            }
        }
    }

    fn run_test(mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Div: a / b {i}");
            check_div(&name, &first, &second, mode_a, mode_b);
            let name = format!("DivAssign: a / b {i}");
            check_div_assign(&name, &first, &second, mode_a, mode_b);

            // Check division by one.
            let one = console::Field::<<Circuit as Environment>::Network>::one();
            let name = format!("Div By One {i}");
            check_div(&name, &first, &one, mode_a, mode_b);
            let name = format!("DivAssign By One {i}");
            check_div_assign(&name, &first, &one, mode_a, mode_b);

            // Check division by zero.
            let zero = console::Field::<<Circuit as Environment>::Network>::zero();
            let name = format!("Div By Zero {i}");
            check_div(&name, &first, &zero, mode_a, mode_b);
            let name = format!("DivAssign By Zero {i}");
            check_div_assign(&name, &first, &zero, mode_a, mode_b);
        }
    }

    #[test]
    fn test_constant_div_constant() {
        run_test(Mode::Constant, Mode::Constant);
    }

    #[test]
    fn test_constant_div_public() {
        run_test(Mode::Constant, Mode::Public);
    }

    #[test]
    fn test_constant_div_private() {
        run_test(Mode::Constant, Mode::Private);
    }

    #[test]
    fn test_public_div_constant() {
        run_test(Mode::Public, Mode::Constant);
    }

    #[test]
    fn test_public_div_public() {
        run_test(Mode::Public, Mode::Public);
    }

    #[test]
    fn test_public_div_private() {
        run_test(Mode::Public, Mode::Private);
    }

    #[test]
    fn test_private_div_constant() {
        run_test(Mode::Private, Mode::Constant);
    }

    #[test]
    fn test_private_div_public() {
        run_test(Mode::Private, Mode::Public);
    }

    #[test]
    fn test_private_div_private() {
        run_test(Mode::Private, Mode::Private);
    }

    #[test]
    fn test_div_by_zero_fails() {
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();
        let one = console::Field::<<Circuit as Environment>::Network>::one();

        let result = std::panic::catch_unwind(|| Field::<Circuit>::one() / Field::zero());
        assert!(result.is_err()); // Probe further for specific error type here, if desired

        let result =
            std::panic::catch_unwind(|| Field::<Circuit>::new(Mode::Constant, one) / Field::new(Mode::Constant, zero));
        assert!(result.is_err()); // Probe further for specific error type here, if desired

        Circuit::scope("Public Div by Zero", || {
            let _ = Field::<Circuit>::new(Mode::Public, one) / Field::new(Mode::Public, zero);
            assert!(!Circuit::is_satisfied_in_scope());
        });

        Circuit::scope("Private Div by Zero", || {
            let _ = Field::<Circuit>::new(Mode::Private, one) / Field::new(Mode::Private, zero);
            assert!(!Circuit::is_satisfied_in_scope());
        });
    }
}
