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

impl<A: Aleo> Equal<Self> for DynamicRecord<A> {
    type Output = Boolean<A>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        // Check the `owner`, `root`, `nonce`, and `version`.
        self.owner.is_equal(&other.owner)
            & self.root.is_equal(&other.root)
            & self.nonce.is_equal(&other.nonce)
            & self.version.is_equal(&other.version)
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        !self.is_equal(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use snarkvm_circuit_types::environment::{Eject, Inject, Mode, assert_scope};
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentNetwork = <Circuit as Environment>::Network;

    /// Creates a sample dynamic record for testing.
    fn sample_dynamic_record(mode: Mode, rng: &mut TestRng) -> DynamicRecord<Circuit> {
        let owner = console::Address::<CurrentNetwork>::rand(rng);
        let root = console::Field::<CurrentNetwork>::rand(rng);
        let nonce = console::Group::<CurrentNetwork>::rand(rng);
        let version = console::U8::<CurrentNetwork>::rand(rng);
        let console_record = console::DynamicRecord::new_unchecked(owner, root, nonce, version, None);
        DynamicRecord::new(mode, console_record)
    }

    /// Tests equality operations for the given mode.
    /// - `equal_counts`: (constants, public, private, constraints) for self-comparison
    /// - `unequal_counts`: (constants, public, private, constraints) for different-value comparison
    fn check_equality(
        mode: Mode,
        equal_counts: (u64, u64, u64, u64),
        unequal_counts: (u64, u64, u64, u64),
    ) -> Result<()> {
        let rng = &mut TestRng::default();

        // Sample two distinct dynamic records.
        let a = sample_dynamic_record(mode, rng);
        let b = sample_dynamic_record(mode, rng);

        // Test is_equal on self (should be true).
        Circuit::scope(format!("{mode} is_equal(self)"), || {
            assert!(a.is_equal(&a).eject_value());
            assert_scope!(equal_counts.0, equal_counts.1, equal_counts.2, equal_counts.3);
        });
        Circuit::reset();

        // Test is_equal on different values (should be false).
        Circuit::scope(format!("{mode} is_equal(other)"), || {
            assert!(!a.is_equal(&b).eject_value());
            assert_scope!(unequal_counts.0, unequal_counts.1, unequal_counts.2, unequal_counts.3);
        });
        Circuit::reset();

        // Test is_not_equal on self (should be false).
        Circuit::scope(format!("{mode} is_not_equal(self)"), || {
            assert!(!a.is_not_equal(&a).eject_value());
            assert_scope!(equal_counts.0, equal_counts.1, equal_counts.2, equal_counts.3);
        });
        Circuit::reset();

        // Test is_not_equal on different values (should be true).
        Circuit::scope(format!("{mode} is_not_equal(other)"), || {
            assert!(a.is_not_equal(&b).eject_value());
            assert_scope!(unequal_counts.0, unequal_counts.1, unequal_counts.2, unequal_counts.3);
        });
        Circuit::reset();

        Ok(())
    }

    #[test]
    fn test_equality_constant() -> Result<()> {
        check_equality(Mode::Constant, (6, 0, 11, 17), (0, 0, 17, 17))
    }

    #[test]
    fn test_equality_public() -> Result<()> {
        check_equality(Mode::Public, (6, 0, 11, 17), (0, 0, 17, 17))
    }

    #[test]
    fn test_equality_private() -> Result<()> {
        check_equality(Mode::Private, (6, 0, 11, 17), (0, 0, 17, 17))
    }
}
