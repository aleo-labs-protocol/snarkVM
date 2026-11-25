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

impl<E: Environment> Add<Scalar<E>> for Scalar<E> {
    type Output = Scalar<E>;

    fn add(self, other: Scalar<E>) -> Self::Output {
        self + &other
    }
}

impl<E: Environment> Add<Scalar<E>> for &Scalar<E> {
    type Output = Scalar<E>;

    fn add(self, other: Scalar<E>) -> Self::Output {
        self + &other
    }
}

impl<E: Environment> Add<&Scalar<E>> for Scalar<E> {
    type Output = Scalar<E>;

    fn add(self, other: &Scalar<E>) -> Self::Output {
        &self + other
    }
}

impl<E: Environment> Add<&Scalar<E>> for &Scalar<E> {
    type Output = Scalar<E>;

    fn add(self, other: &Scalar<E>) -> Self::Output {
        let mut result = self.clone();
        result += other;
        result
    }
}

impl<E: Environment> AddAssign<Scalar<E>> for Scalar<E> {
    fn add_assign(&mut self, other: Scalar<E>) {
        *self += &other;
    }
}

impl<E: Environment> AddAssign<&Scalar<E>> for Scalar<E> {
    fn add_assign(&mut self, other: &Scalar<E>) {
        // Determine the variable mode.
        if self.is_constant() && other.is_constant() {
            // Compute the sum and set the new constant in `self`.
            *self = witness!(|self, other| self + other);
        } else {
            // Instead of adding the bits of `self` and `other` directly, the scalars are
            // converted into a field elements, and summed, before converting back to scalars.
            // Note: This is safe as the base field is larger than the scalar field.
            let sum = self.to_field() + other.to_field();

            // Extract the scalar field bits from the field element, with a carry bit.
            // (For advanced users) This operation saves us 2 private variables and 2 constraints.
            let bits_le = sum.to_lower_bits_le(E::ScalarField::size_in_bits() + 1);

            // Recover the sanitized (truncated) sum on the base field.
            // (For advanced users) This operation saves us 2 private variables and 2 constraints.
            let sum = Field::from_bits_le(&bits_le);

            // Initialize the scalar field modulus as a constant base field variable.
            //
            // Note: We are reconstituting the scalar field into a base field here in order to
            // compute the difference between the sum and modulus. This is safe as the scalar field modulus
            // is less that the base field modulus, and thus will always fit in a base field element.
            let modulus =
                Field::constant(match console::FromBits::from_bits_le(&E::ScalarField::modulus().to_bits_le()) {
                    Ok(modulus) => modulus,
                    Err(error) => E::halt(format!("Failed to retrieve the scalar modulus as bytes: {error}")),
                });

            // Determine the wrapping sum, by computing the difference between the sum and modulus, if `sum` < `modulus`.
            let wrapping_sum = Ternary::ternary(&sum.is_less_than(&modulus), &sum, &(&sum - &modulus));

            // Retrieve the bits of the wrapping sum.
            let bits_le = wrapping_sum.to_lower_bits_le(console::Scalar::<E::Network>::size_in_bits());

            // Set the sum of `self` and `other`, in `self`.
            let cell = OnceCell::new();
            cell.set(bits_le).unwrap();
            *self = Scalar { field: wrapping_sum, bits_le: cell };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    #[rustfmt::skip]
    fn check_add(
        name: &str,
        first: console::Scalar<<Circuit as Environment>::Network>,
        second: console::Scalar<<Circuit as Environment>::Network>,
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let a = Scalar::<Circuit>::new(mode_a, first);
        let b = Scalar::<Circuit>::new(mode_b, second);
        let case = format!("({} + {})", a.eject_value(), b.eject_value());
        let expected = first + second;

        Circuit::scope(name, || {
            let candidate = a + b;
            assert_eq!(expected, candidate.eject_value(), "{case}");
            assert_scope!();
        });
    }

    #[rustfmt::skip]
    fn run_test(
        mode_a: Mode,
        mode_b: Mode,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let name = format!("Add: {mode_a} + {mode_b} {i}");
            check_add(&name, first, second, mode_a, mode_b);

            let name = format!("Add: {mode_a} + {mode_b} {i} (commutative)");
            check_add(&name, second, first, mode_a, mode_b);
        }
    }

    #[test]
    fn test_scalar_constant_plus_constant() {
        run_test(Mode::Constant, Mode::Constant);
    }

    #[test]
    fn test_scalar_constant_plus_public() {
        run_test(Mode::Constant, Mode::Public);
    }

    #[test]
    fn test_scalar_constant_plus_private() {
        run_test(Mode::Constant, Mode::Private);
    }

    #[test]
    fn test_scalar_public_plus_constant() {
        run_test(Mode::Public, Mode::Constant);
    }

    #[test]
    fn test_scalar_private_plus_constant() {
        run_test(Mode::Private, Mode::Constant);
    }

    #[test]
    fn test_scalar_public_plus_public() {
        run_test(Mode::Public, Mode::Public);
    }

    #[test]
    fn test_scalar_public_plus_private() {
        run_test(Mode::Public, Mode::Private);
    }

    #[test]
    fn test_scalar_private_plus_public() {
        run_test(Mode::Private, Mode::Public);
    }

    #[test]
    fn test_scalar_private_plus_private() {
        run_test(Mode::Private, Mode::Private);
    }
}
