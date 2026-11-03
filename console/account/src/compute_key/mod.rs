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

mod bitwise;
mod bytes;
mod from_bits;
mod serialize;
mod size_in_bits;
mod size_in_bytes;
mod to_address;
mod to_bits;
mod to_fields;
mod try_from;

#[cfg(feature = "private_key")]
use crate::PrivateKey;

use snarkvm_console_network::prelude::*;
use snarkvm_console_types::{Address, Boolean, Field, Group, Scalar};

static _COMPUTE_KEY_PREFIX: [u8; 10] = [109, 249, 98, 224, 36, 15, 213, 187, 79, 190]; // AComputeKey1

#[derive(Copy, Clone, Debug)]
pub struct ComputeKey<N: Network> {
    /// The signature public key `pk_sig` := G^sk_sig.
    pk_sig: Group<N>,
    /// The signature public randomizer `pr_sig` := G^r_sig.
    pr_sig: Group<N>,
    /// The PRF secret key `sk_prf` := HashToScalar(pk_sig || pr_sig), or `None` if it is computed on each use.
    sk_prf: Option<Scalar<N>>,
}

/// `sk_prf` is excluded, as it is derived from `pk_sig` and `pr_sig`.
impl<N: Network> PartialEq for ComputeKey<N> {
    fn eq(&self, other: &Self) -> bool {
        self.pk_sig == other.pk_sig && self.pr_sig == other.pr_sig
    }
}

impl<N: Network> Eq for ComputeKey<N> {}

impl<N: Network> core::hash::Hash for ComputeKey<N> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.pk_sig.hash(state);
        self.pr_sig.hash(state);
    }
}

impl<N: Network> ComputeKey<N> {
    /// Returns the signature public key.
    pub const fn pk_sig(&self) -> Group<N> {
        self.pk_sig
    }

    /// Returns the signature public randomizer.
    pub const fn pr_sig(&self) -> Group<N> {
        self.pr_sig
    }

    /// Returns the PRF secret key.
    pub fn sk_prf(&self) -> Scalar<N> {
        self.sk_prf.unwrap_or_else(|| {
            // Poseidon `hash_to_scalar` always returns `Ok`.
            N::hash_to_scalar_psd4(&[self.pk_sig.to_x_coordinate(), self.pr_sig.to_x_coordinate()]).unwrap()
        })
    }
}
