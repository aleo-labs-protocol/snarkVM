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

mod sponge;
pub(super) use sponge::*;

mod state;
pub(super) use state::*;

use snarkvm_console_types::{Field, prelude::*};

use smallvec::SmallVec;

/// The interface for a cryptographic sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls.
pub trait AlgebraicSponge<E: Environment, const RATE: usize, const CAPACITY: usize>: Clone + Debug {
    /// Parameters used by the sponge.
    type Parameters;

    /// Initialize a new instance of the sponge.
    fn new(params: &Self::Parameters) -> Self;

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &[Field<E>]);

    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze(&mut self, num_elements: u16) -> SmallVec<[Field<E>; 10]>;
}

/// The mode structure for duplex sponges.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum DuplexSpongeMode {
    /// The sponge is currently absorbing data.
    Absorbing {
        /// The next position of the state to be XOR-ed when absorbing.
        next_absorb_index: usize,
    },
    /// The sponge is currently squeezing data out.
    Squeezing {
        /// The next position of the state to be outputted when squeezing.
        next_squeeze_index: usize,
    },
}
