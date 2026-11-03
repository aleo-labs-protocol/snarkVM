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

use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Boolean, Field, U8, environment::prelude::*};

#[derive(Clone)]
pub struct TransitionLeaf<A: Aleo> {
    /// The version of the Merkle leaf.
    version: U8<A>,
    /// The index of the Merkle leaf.
    index: U8<A>,
    /// The variant of the Merkle leaf.
    variant: U8<A>,
    /// The ID.
    id: Field<A>,
}

impl<A: Aleo> TransitionLeaf<A> {
    /// Returns the version of the Merkle leaf.
    pub const fn version(&self) -> &U8<A> {
        &self.version
    }

    /// Returns the index of the Merkle leaf.
    pub const fn index(&self) -> &U8<A> {
        &self.index
    }

    /// Returns the variant of the Merkle leaf.
    pub const fn variant(&self) -> &U8<A> {
        &self.variant
    }

    /// Returns the ID in the Merkle leaf.
    pub const fn id(&self) -> &Field<A> {
        &self.id
    }
}

impl<A: Aleo> Inject for TransitionLeaf<A> {
    type Primitive = console::TransitionLeaf<A::Network>;

    /// Initializes a new transition leaf circuit from a primitive.
    fn new(mode: Mode, transition_leaf: Self::Primitive) -> Self {
        Self {
            version: U8::new(mode, console::U8::new(transition_leaf.version())),
            index: U8::new(mode, console::U8::new(transition_leaf.index())),
            variant: U8::new(mode, console::U8::new(transition_leaf.variant())),
            id: Field::new(mode, transition_leaf.id()),
        }
    }
}

impl<A: Aleo> Eject for TransitionLeaf<A> {
    type Primitive = console::TransitionLeaf<A::Network>;

    /// Ejects the mode of the transition leaf.
    fn eject_mode(&self) -> Mode {
        (&self.version, &self.index, &self.variant, &self.id).eject_mode()
    }

    /// Ejects the transition leaf.
    fn eject_value(&self) -> Self::Primitive {
        match Self::Primitive::from(
            *self.version.eject_value(),
            *self.index.eject_value(),
            *self.variant.eject_value(),
            self.id.eject_value(),
        ) {
            Ok(leaf) => leaf,
            Err(error) => A::halt(format!("Failed to eject the transition leaf: {error}")),
        }
    }
}

impl<A: Aleo> ToBits for TransitionLeaf<A> {
    type Boolean = Boolean<A>;

    /// Outputs the little-endian bit representation of `self` *without* trailing zeros.
    fn write_bits_le(&self, vec: &mut Vec<Self::Boolean>) {
        self.version.write_bits_le(vec);
        self.index.write_bits_le(vec);
        self.variant.write_bits_le(vec);
        self.id.write_bits_le(vec);
    }

    /// Outputs the big-endian bit representation of `self` *without* leading zeros.
    fn write_bits_be(&self, vec: &mut Vec<Self::Boolean>) {
        self.version.write_bits_be(vec);
        self.index.write_bits_be(vec);
        self.variant.write_bits_be(vec);
        self.id.write_bits_be(vec);
    }
}
