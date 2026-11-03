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

impl<N: Network> Eq for DynamicRecord<N> {}

impl<N: Network> PartialEq for DynamicRecord<N> {
    /// Returns `true` if `self` and `other` are equal.
    fn eq(&self, other: &Self) -> bool {
        *self.is_equal(other)
    }
}

impl<N: Network> Equal<Self> for DynamicRecord<N> {
    type Output = Boolean<N>;

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
    use snarkvm_console_network::MainnetV0;

    use std::str::FromStr;

    type CurrentNetwork = MainnetV0;

    fn sample_record() -> DynamicRecord<CurrentNetwork> {
        DynamicRecord::from_record(
            &Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
                r"{
    owner: aleo14tlamssdmg3d0p5zmljma573jghe2q9n6wz29qf36re2glcedcpqfg4add.private,
    a: true.private,
    b: 123456789field.public,
    c: 0group.private,
    d: {
        e: true.private,
        f: 123456789field.private,
        g: 0group.private
    },
    _nonce: 0group.public,
    _version: 0u8.public
}",
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn sample_mismatched_record() -> DynamicRecord<CurrentNetwork> {
        DynamicRecord::from_record(
            &Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
                r"{
    owner: aleo14tlamssdmg3d0p5zmljma573jghe2q9n6wz29qf36re2glcedcpqfg4add.private,
    a: true.public,
    b: 123456789field.public,
    c: 0group.private,
    d: {
        e: true.private,
        f: 123456789field.private,
        g: 0group.private
    },
    _nonce: 0group.public,
    _version: 0u8.public
}",
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn check_is_equal() {
        // Sample the record.
        let record = sample_record();
        let mismatched_record = sample_mismatched_record();

        let candidate = record.is_equal(&record);
        assert!(*candidate);

        let candidate = record.is_equal(&mismatched_record);
        assert!(!*candidate);
    }

    fn check_is_not_equal() {
        // Sample the record.
        let record = sample_record();
        let mismatched_record = sample_mismatched_record();

        let candidate = record.is_not_equal(&mismatched_record);
        assert!(*candidate);

        let candidate = record.is_not_equal(&record);
        assert!(!*candidate);
    }

    #[test]
    fn test_is_equal() {
        check_is_equal()
    }

    #[test]
    fn test_is_not_equal() {
        check_is_not_equal()
    }
}
