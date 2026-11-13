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

mod assignment;
pub use assignment::*;

mod constraint_system;
pub use constraint_system::{ConstraintSynthesizer, ConstraintSystem};

pub mod errors;
pub use errors::*;

mod linear_combination;
pub use linear_combination::*;

mod namespace;
pub use namespace::*;

#[cfg(feature = "test")]
mod optional_vec;
#[cfg(feature = "test")]
pub use optional_vec::*;

#[cfg(feature = "test")]
mod test_constraint_system;
#[cfg(feature = "test")]
pub use test_constraint_system::{Fr, TestConstraintSystem};

#[cfg(feature = "test")]
mod test_constraint_checker;
#[cfg(feature = "test")]
pub use test_constraint_checker::TestConstraintChecker;

use snarkvm_utilities::serialize::*;

use core::cmp::Ordering;

/// Represents a variable in a constraint system.
#[derive(PartialOrd, Ord, PartialEq, Eq, Copy, Clone, Debug, Hash)]
pub struct Variable(Index);

impl Variable {
    /// This constructs a variable with an arbitrary index.
    /// Circuit implementations are not recommended to use this.
    pub fn new_unchecked(idx: Index) -> Variable {
        Variable(idx)
    }

    /// This returns the index underlying the variable.
    /// Circuit implementations are not recommended to use this.
    pub fn get_unchecked(&self) -> Index {
        self.0
    }
}

/// Represents the index of either a public variable (input) or a private
/// variable (auxiliary).
#[derive(Copy, Clone, PartialEq, Debug, Eq, Hash)]
pub enum Index {
    /// Index of a public variable.
    Public(usize),
    /// Index of a private variable.
    Private(usize),
}

impl PartialOrd for Index {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Index {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Index::Public(idx1), Index::Public(idx2)) | (Index::Private(idx1), Index::Private(idx2)) => idx1.cmp(idx2),
            (Index::Public(_), Index::Private(_)) => Ordering::Less,
            (Index::Private(_), Index::Public(_)) => Ordering::Greater,
        }
    }
}

impl CanonicalSerialize for Index {
    #[inline]
    fn serialize_with_mode<W: Write>(&self, mut writer: W, _: Compress) -> Result<(), SerializationError> {
        let (is_public, inner) = match *self {
            Index::Public(inner) => (true, inner),
            Index::Private(inner) => (false, inner),
        };
        // we use uncompressed here because the serialization of bool and usize
        // don't change whether we use uncompressed or not.
        is_public.serialize_uncompressed(&mut writer)?;
        inner.serialize_uncompressed(&mut writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self, _: Compress) -> usize {
        // we use uncompressed here because the serialization of bool and usize
        // don't change whether we use uncompressed or not.
        0usize.uncompressed_size() + true.uncompressed_size()
    }
}

impl Valid for Index {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl CanonicalDeserialize for Index {
    #[inline]
    fn deserialize_with_mode<R: Read>(mut reader: R, _: Compress, _: Validate) -> Result<Self, SerializationError> {
        // we use uncompressed here because the serialization of bool and usize
        // don't change whether we use uncompressed or not.
        let is_input = bool::deserialize_uncompressed(&mut reader)?;
        let inner = usize::deserialize_uncompressed(&mut reader)?;
        Ok(if is_input { Index::Public(inner) } else { Index::Private(inner) })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_index() {
        serialize_index_test(true);
        serialize_index_test(false);
    }

    fn serialize_index_test(input: bool) {
        let idx = if input { Index::Public(32) } else { Index::Private(32) };

        let mut v = vec![];
        idx.serialize_compressed(&mut v).unwrap();
        let idx2 = Index::deserialize_compressed(&v[..]).unwrap();
        assert_eq!(idx, idx2);
    }
}
