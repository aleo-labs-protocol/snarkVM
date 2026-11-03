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

impl<E: Environment> Equal<Self> for IdentifierLiteral<E> {
    type Output = Boolean<E>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        self.to_field().is_equal(&other.to_field())
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        self.to_field().is_not_equal(&other.to_field())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentEnvironment = Circuit;

    const ITERATIONS: usize = 10;

    fn check_equal(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Construct two distinct random console identifier literals.
            let value_a = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);
            let value_b = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            // Inject both into the circuit.
            let circuit_a = IdentifierLiteral::<CurrentEnvironment>::new(mode, value_a);
            let circuit_a2 = IdentifierLiteral::<CurrentEnvironment>::new(mode, value_a);
            let circuit_b = IdentifierLiteral::<CurrentEnvironment>::new(mode, value_b);

            // Check is_equal: same value returns true.
            Circuit::scope(format!("is_equal {mode} (same)"), || {
                let candidate = circuit_a.is_equal(&circuit_a2);
                assert!(candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            // Check is_equal: different values match console.
            Circuit::scope(format!("is_equal {mode} (different)"), || {
                let candidate = circuit_a.is_equal(&circuit_b);
                assert_eq!(value_a == value_b, candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            // Check is_not_equal: different values match console.
            Circuit::scope(format!("is_not_equal {mode} (different)"), || {
                let candidate = circuit_a.is_not_equal(&circuit_b);
                assert_eq!(value_a != value_b, candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            // Check is_not_equal: same value returns false.
            Circuit::scope(format!("is_not_equal {mode} (same)"), || {
                let candidate = circuit_a.is_not_equal(&circuit_a2);
                assert!(!candidate.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });

            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_equal() -> Result<()> {
        check_equal(Mode::Constant, 1, 0, 0, 0)?;
        check_equal(Mode::Public, 0, 0, 2, 2)?;
        check_equal(Mode::Private, 0, 0, 2, 2)
    }
}
