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
mod try_from;

#[cfg(feature = "signature")]
mod sign;

use snarkvm_console_network::prelude::*;
use snarkvm_console_types::{Field, Scalar};

use zeroize::Zeroize;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Zeroize)]
pub struct PrivateKey<N: Network> {
    /// The account seed that derives the full private key.
    seed: Field<N>,
    /// The derived signature secret key.
    sk_sig: Scalar<N>,
    /// The derived signature randomizer.
    r_sig: Scalar<N>,
}

impl<N: Network> PrivateKey<N> {
    /// Samples a new random private key.
    #[inline]
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self> {
        // Sample a random account seed.
        Self::try_from(Uniform::rand(rng))
    }

    /// Returns the account seed.
    pub const fn seed(&self) -> Field<N> {
        self.seed
    }

    /// Returns the signature secret key.
    pub const fn sk_sig(&self) -> Scalar<N> {
        self.sk_sig
    }

    /// Returns the signature randomizer.
    pub const fn r_sig(&self) -> Scalar<N> {
        self.r_sig
    }
}
