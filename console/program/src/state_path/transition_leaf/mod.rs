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

mod bytes;
mod serialize;
mod string;
mod to_bits;

use snarkvm_console_network::prelude::*;
use snarkvm_console_types::Field;

/// The version of a transition leaf.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LeafVersion {
    /// Static leaf (version 1) — standard inputs/outputs.
    Static = 1,
    /// Dynamic leaf (version 2) — record inputs/outputs from dynamic transition calls.
    Dynamic = 2,
}

impl TryFrom<u8> for LeafVersion {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Static),
            2 => Ok(Self::Dynamic),
            _ => bail!("Invalid transition leaf version: {value}"),
        }
    }
}

/// The Merkle leaf for an input or output ID in the transition.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TransitionLeaf<N: Network> {
    /// The version of the Merkle leaf.
    version: u8,
    /// The index of the Merkle leaf.
    index: u8,
    /// The variant of the Merkle leaf.
    variant: u8,
    /// The ID.
    id: Field<N>,
}

impl<N: Network> TransitionLeaf<N> {
    /// Initializes a new instance of `TransitionLeaf` with static version.
    pub const fn new(index: u8, variant: u8, id: Field<N>) -> Self {
        Self { version: LeafVersion::Static as u8, index, variant, id }
    }

    /// Initializes a new instance of `TransitionLeaf` for a record input/output with a dynamic ID (variant 3).
    pub const fn new_record_with_dynamic_id(index: u8, id: Field<N>) -> Self {
        Self { version: LeafVersion::Dynamic as u8, index, variant: 3, id }
    }

    /// Initializes a new instance of `TransitionLeaf` for an external record input/output with a dynamic ID (variant 4).
    pub const fn new_external_record_with_dynamic_id(index: u8, id: Field<N>) -> Self {
        Self { version: LeafVersion::Dynamic as u8, index, variant: 4, id }
    }

    /// Initializes a new instance of `TransitionLeaf` from raw fields.
    /// Returns an error if the version/variant combination is invalid.
    pub fn from(version: u8, index: u8, variant: u8, id: Field<N>) -> Result<Self> {
        // Validate the version.
        let leaf_version = LeafVersion::try_from(version)?;
        // Dynamic version is only allowed for Record (3) and ExternalRecord (4) variants.
        if matches!(leaf_version, LeafVersion::Dynamic) && variant != 3 && variant != 4 {
            bail!("Dynamic transition leaf variant must be 3 (Record) or 4 (ExternalRecord), found {variant}");
        }
        Ok(Self { version, index, variant, id })
    }

    /// Returns the version of the Merkle leaf.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the index of the Merkle leaf.
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// Returns the variant of the Merkle leaf.
    pub const fn variant(&self) -> u8 {
        self.variant
    }

    /// Returns the ID in the Merkle leaf.
    pub const fn id(&self) -> Field<N> {
        self.id
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    /// Samples a transition leaf with version 1 (static).
    pub(super) fn sample_leaf(rng: &mut TestRng) -> TransitionLeaf<CurrentNetwork> {
        // Construct a new leaf.
        TransitionLeaf::new(rng.random(), rng.random(), Uniform::rand(rng))
    }

    /// Samples a transition leaf with version 2 (dynamic).
    pub(super) fn sample_dynamic_leaf(rng: &mut TestRng) -> TransitionLeaf<CurrentNetwork> {
        // Randomly choose between Record (variant 3) and ExternalRecord (variant 4).
        if rng.random() {
            TransitionLeaf::new_record_with_dynamic_id(rng.random(), Uniform::rand(rng))
        } else {
            TransitionLeaf::new_external_record_with_dynamic_id(rng.random(), Uniform::rand(rng))
        }
    }
}
