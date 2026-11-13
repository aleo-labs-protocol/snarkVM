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

impl<E: Environment> Mul<Scalar<E>> for Group<E> {
    type Output = Group<E>;

    fn mul(self, other: Scalar<E>) -> Self::Output {
        self * &other
    }
}

impl<E: Environment> Mul<Scalar<E>> for &Group<E> {
    type Output = Group<E>;

    fn mul(self, other: Scalar<E>) -> Self::Output {
        self * &other
    }
}

impl<E: Environment> Mul<&Scalar<E>> for Group<E> {
    type Output = Group<E>;

    fn mul(self, other: &Scalar<E>) -> Self::Output {
        let mut output = self;
        output *= other;
        output
    }
}

impl<E: Environment> Mul<&Scalar<E>> for &Group<E> {
    type Output = Group<E>;

    fn mul(self, other: &Scalar<E>) -> Self::Output {
        (*self).clone() * other
    }
}

impl<E: Environment> Mul<Group<E>> for Scalar<E> {
    type Output = Group<E>;

    fn mul(self, other: Group<E>) -> Self::Output {
        other * &self
    }
}

impl<E: Environment> Mul<Group<E>> for &Scalar<E> {
    type Output = Group<E>;

    fn mul(self, other: Group<E>) -> Self::Output {
        &other * self
    }
}

impl<E: Environment> Mul<&Group<E>> for Scalar<E> {
    type Output = Group<E>;

    fn mul(self, other: &Group<E>) -> Self::Output {
        other * &self
    }
}

impl<E: Environment> Mul<&Group<E>> for &Scalar<E> {
    type Output = Group<E>;

    fn mul(self, other: &Group<E>) -> Self::Output {
        other * self
    }
}

impl<E: Environment> MulAssign<Scalar<E>> for Group<E> {
    fn mul_assign(&mut self, other: Scalar<E>) {
        *self *= &other;
    }
}

impl<E: Environment> MulAssign<&Scalar<E>> for Group<E> {
    fn mul_assign(&mut self, other: &Scalar<E>) {
        *self *= other.to_bits_be().as_slice();
    }
}

impl<E: Environment, const N: usize> Mul<[Boolean<E>; N]> for Group<E> {
    type Output = Group<E>;

    fn mul(self, other: [Boolean<E>; N]) -> Self::Output {
        self * &other[..]
    }
}

impl<E: Environment, const N: usize> Mul<[Boolean<E>; N]> for &Group<E> {
    type Output = Group<E>;

    fn mul(self, other: [Boolean<E>; N]) -> Self::Output {
        self * &other[..]
    }
}

impl<E: Environment> Mul<&[Boolean<E>]> for Group<E> {
    type Output = Group<E>;

    fn mul(self, other: &[Boolean<E>]) -> Self::Output {
        let mut output = self;
        output *= other;
        output
    }
}

impl<E: Environment> Mul<&[Boolean<E>]> for &Group<E> {
    type Output = Group<E>;

    fn mul(self, other: &[Boolean<E>]) -> Self::Output {
        (*self).clone() * other
    }
}

impl<E: Environment, const N: usize> Mul<Group<E>> for [Boolean<E>; N] {
    type Output = Group<E>;

    fn mul(self, other: Group<E>) -> Self::Output {
        other * &self[..]
    }
}

impl<E: Environment> Mul<Group<E>> for &[Boolean<E>] {
    type Output = Group<E>;

    fn mul(self, other: Group<E>) -> Self::Output {
        &other * self
    }
}

impl<E: Environment, const N: usize> Mul<&Group<E>> for [Boolean<E>; N] {
    type Output = Group<E>;

    fn mul(self, other: &Group<E>) -> Self::Output {
        other * &self[..]
    }
}

impl<E: Environment> Mul<&Group<E>> for &[Boolean<E>] {
    type Output = Group<E>;

    fn mul(self, other: &Group<E>) -> Self::Output {
        other * self
    }
}

impl<E: Environment, const N: usize> MulAssign<[Boolean<E>; N]> for Group<E> {
    fn mul_assign(&mut self, other: [Boolean<E>; N]) {
        *self *= &other[..];
    }
}

impl<E: Environment> MulAssign<&[Boolean<E>]> for Group<E> {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn mul_assign(&mut self, other: &[Boolean<E>]) {
        let mut output = Group::zero();
        for bit in other.iter() {
            output = output.double();
            output = Group::ternary(bit, &(&*self + &output), &output);
        }
        *self = output;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_mul(
        name: &str,
        expected: &console::Group<<Circuit as Environment>::Network>,
        a: &Group<Circuit>,
        b: &Scalar<Circuit>,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        Circuit::scope(name, || {
            let candidate = a * b;
            assert_eq!(*expected, candidate.eject_value(), "({} * {})", a.eject_value(), b.eject_value());
            assert_scope!(<=num_constants, num_public, num_private, num_constraints);
        });
        Circuit::reset();
    }

    fn check_mul_assign(
        name: &str,
        expected: &console::Group<<Circuit as Environment>::Network>,
        a: &Group<Circuit>,
        b: &Scalar<Circuit>,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        Circuit::scope(name, || {
            let mut candidate = a.clone();
            candidate *= b;
            assert_eq!(*expected, candidate.eject_value(), "({} * {})", a.eject_value(), b.eject_value());
            // Note that these define an upper bound. Furthermore, since `check_mul_assign` is called after `check_mul`, it does not incur
            // the overhead of converting to a bitwise representation.
            assert_scope!(<=num_constants, num_public, num_private, num_constraints);
        });
        Circuit::reset();
    }

    #[allow(clippy::identity_op)]
    #[test]
    fn test_constant_times_scalar_constant() {
        use snarkvm_utilities::BigInteger;

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar: console::Scalar<<Circuit as Environment>::Network> = Uniform::rand(&mut rng);

            let num_nonzero_bits = (*scalar).to_bigint().to_biguint().bits();
            let num_constant =
                (3 /* DOUBLE private */ + 4/* public ADD private */ + 0/* TERNARY */) * (num_nonzero_bits - 1) + 251; // Typically around 760.

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Constant, base);
            let b = Scalar::<Circuit>::new(Mode::Constant, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, num_constant, 0, 0, 0);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, num_constant, 0, 0, 0);
        }
    }

    #[test]
    fn test_constant_times_scalar_public() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar = Uniform::rand(&mut rng);

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Constant, base);
            let b = Scalar::<Circuit>::new(Mode::Public, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, 750, 0, 3001, 3003);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, 750, 0, 2500, 2500);
        }
    }

    #[test]
    fn test_constant_times_scalar_private() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar = Uniform::rand(&mut rng);

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Constant, base);
            let b = Scalar::<Circuit>::new(Mode::Private, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, 750, 0, 3001, 3003);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, 750, 0, 2500, 2500);
        }
    }

    #[allow(clippy::identity_op)]
    #[test]
    fn test_public_times_scalar_constant() {
        use snarkvm_utilities::BigInteger;

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar: console::Scalar<<Circuit as Environment>::Network> = Uniform::rand(&mut rng);

            let num_nonzero_bits = (*scalar).to_bigint().to_biguint().bits();
            let num_constant =
                (1 /* DOUBLE private */ + 2/* public ADD private */ + 0/* TERNARY */) * (num_nonzero_bits - 1) + 251; // Typically around 760.
            let num_private =
                (5 /* DOUBLE private */ + 6/* public ADD private */ + 0/* TERNARY */) * (num_nonzero_bits - 1); // Typically around 2700.
            let num_constraints =
                (5 /* DOUBLE private */ + 6/* public ADD private */ + 0/* TERNARY */) * (num_nonzero_bits - 1); // Typically around 2700.

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Public, base);
            let b = Scalar::<Circuit>::new(Mode::Constant, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, num_constant, 0, num_private, num_constraints);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, num_constant, 0, num_private, num_constraints);
        }
    }

    #[allow(clippy::identity_op)]
    #[test]
    fn test_private_times_scalar_constant() {
        use snarkvm_utilities::BigInteger;

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar: console::Scalar<<Circuit as Environment>::Network> = Uniform::rand(&mut rng);

            let num_nonzero_bits = (*scalar).to_bigint().to_biguint().bits();
            let num_constant =
                (1 /* DOUBLE private */ + 2/* private ADD private */ + 0/* TERNARY */) * (num_nonzero_bits - 1) + 251; // Typically around 760.
            let num_private =
                (5 /* DOUBLE private */ + 6/* private ADD private */ + 0/* TERNARY */) * (num_nonzero_bits - 1); // Typically around 2700.
            let num_constraints =
                (5 /* DOUBLE private */ + 6/* private ADD private */ + 0/* TERNARY */) * (num_nonzero_bits - 1); // Typically around 2700.

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Private, base);
            let b = Scalar::<Circuit>::new(Mode::Constant, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, num_constant, 0, num_private, num_constraints);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, num_constant, 0, num_private, num_constraints);
        }
    }

    #[test]
    fn test_public_times_scalar_public() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar = Uniform::rand(&mut rng);

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Public, base);
            let b = Scalar::<Circuit>::new(Mode::Public, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, 750, 0, 3753, 3755);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, 750, 0, 3252, 3252);
        }
    }

    #[test]
    fn test_public_times_scalar_private() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar = Uniform::rand(&mut rng);

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Public, base);
            let b = Scalar::<Circuit>::new(Mode::Private, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, 750, 0, 3753, 3755);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, 750, 0, 3252, 3252);
        }
    }

    #[test]
    fn test_private_times_scalar_public() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar = Uniform::rand(&mut rng);

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Private, base);
            let b = Scalar::<Circuit>::new(Mode::Public, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, 750, 0, 3753, 3755);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, 750, 0, 3252, 3252);
        }
    }

    #[test]
    fn test_private_times_scalar_private() {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            let base = Uniform::rand(&mut rng);
            let scalar = Uniform::rand(&mut rng);

            let expected = base * scalar;
            let a = Group::<Circuit>::new(Mode::Private, base);
            let b = Scalar::<Circuit>::new(Mode::Private, scalar);

            let name = format!("Mul: a * b {i}");
            check_mul(&name, &expected, &a, &b, 750, 0, 3753, 3755);
            let name = format!("MulAssign: a * b {i}");
            check_mul_assign(&name, &expected, &a, &b, 750, 0, 3252, 3252);
        }
    }

    #[test]
    fn test_mul_matches() {
        let mut rng = TestRng::default();

        // Sample two random elements.
        let a = Uniform::rand(&mut rng);
        let b = Uniform::rand(&mut rng);
        let expected = a * b;

        // Constant
        let base = Group::<Circuit>::new(Mode::Constant, a);
        let scalar = Scalar::<Circuit>::new(Mode::Constant, b);
        let candidate_a = base * scalar;
        assert_eq!(expected, candidate_a.eject_value());

        // Private
        let base = Group::<Circuit>::new(Mode::Private, a);
        let scalar = Scalar::<Circuit>::new(Mode::Private, b);
        let candidate_b = base * scalar;
        assert_eq!(expected, candidate_b.eject_value());
    }
}
