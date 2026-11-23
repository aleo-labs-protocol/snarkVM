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

impl<A: Aleo> Equal<Self> for Signature<A> {
    type Output = Boolean<A>;

    ///
    /// Returns `true` if `self` and `other` are equal.
    ///
    fn is_equal(&self, other: &Self) -> Self::Output {
        // Determine if this operation is constant or variable.
        match self.is_constant() && other.is_constant() {
            true => Boolean::constant(self.eject_value() == other.eject_value()),
            false => {
                self.challenge().is_equal(other.challenge())
                    & self.response().is_equal(other.response())
                    & self.compute_key().is_equal(other.compute_key())
            }
        }
    }

    ///
    /// Returns `true` if `self` and `other` are *not* equal.
    ///
    /// This method constructs a boolean that indicates if
    /// `self` and `other ` are *not* equal to each other.
    ///
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        !self.is_equal(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use snarkvm_circuit_network::AleoV0;
    use snarkvm_utilities::TestRng;

    type CurrentAleo = AleoV0;

    const ITERATIONS: u64 = 10;

    fn check_is_equal(
        mode_a: Mode,
        mode_b: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
        rng: &mut TestRng,
    ) {
        for i in 0..ITERATIONS {
            // Sample two random signatures.
            let a = Signature::<CurrentAleo>::new(mode_a, crate::helpers::generate_signature(i, rng));
            let b = Signature::<CurrentAleo>::new(mode_b, crate::helpers::generate_signature(i, rng));

            CurrentAleo::scope(format!("{mode_a} {mode_a} {i}"), || {
                let equals = a.is_equal(&a);
                assert!(equals.eject_value());
            });

            CurrentAleo::scope(format!("{mode_a} {mode_b} {i}"), || {
                let equals = a.is_equal(&b);
                assert!(!equals.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
        }
    }

    fn check_is_not_equal(
        mode_a: Mode,
        mode_b: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
        rng: &mut TestRng,
    ) {
        for i in 0..ITERATIONS {
            // Sample two random signatures.
            let a = Signature::<CurrentAleo>::new(mode_a, crate::helpers::generate_signature(i, rng));
            let b = Signature::<CurrentAleo>::new(mode_b, crate::helpers::generate_signature(i, rng));

            CurrentAleo::scope(format!("{mode_a} {mode_a} {i}"), || {
                let equals = a.is_not_equal(&a);
                assert!(!equals.eject_value());
            });

            CurrentAleo::scope(format!("{mode_a} {mode_b} {i}"), || {
                let equals = a.is_not_equal(&b);
                assert!(equals.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
        }
    }

    #[test]
    fn test_is_equal() {
        let mut rng = TestRng::default();

        check_is_equal(Mode::Constant, Mode::Constant, 0, 0, 0, 0, &mut rng);
        check_is_equal(Mode::Constant, Mode::Public, 0, 0, 20, 20, &mut rng);
        check_is_equal(Mode::Constant, Mode::Private, 0, 0, 20, 20, &mut rng);
        check_is_equal(Mode::Public, Mode::Constant, 0, 0, 20, 20, &mut rng);
        check_is_equal(Mode::Private, Mode::Constant, 0, 0, 20, 20, &mut rng);
        check_is_equal(Mode::Public, Mode::Public, 0, 0, 20, 20, &mut rng);
        check_is_equal(Mode::Public, Mode::Private, 0, 0, 20, 20, &mut rng);
        check_is_equal(Mode::Private, Mode::Public, 0, 0, 20, 20, &mut rng);
        check_is_equal(Mode::Private, Mode::Private, 0, 0, 20, 20, &mut rng);
    }

    #[test]
    fn test_is_not_equal() {
        let mut rng = TestRng::default();

        check_is_not_equal(Mode::Constant, Mode::Constant, 0, 0, 0, 0, &mut rng);
        check_is_not_equal(Mode::Constant, Mode::Public, 0, 0, 20, 20, &mut rng);
        check_is_not_equal(Mode::Constant, Mode::Private, 0, 0, 20, 20, &mut rng);
        check_is_not_equal(Mode::Public, Mode::Constant, 0, 0, 20, 20, &mut rng);
        check_is_not_equal(Mode::Private, Mode::Constant, 0, 0, 20, 20, &mut rng);
        check_is_not_equal(Mode::Public, Mode::Public, 0, 0, 20, 20, &mut rng);
        check_is_not_equal(Mode::Public, Mode::Private, 0, 0, 20, 20, &mut rng);
        check_is_not_equal(Mode::Private, Mode::Public, 0, 0, 20, 20, &mut rng);
        check_is_not_equal(Mode::Private, Mode::Private, 0, 0, 20, 20, &mut rng);
    }
}
