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

#![forbid(unsafe_code)]
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_console as console;

mod bytes;
mod serialize;
mod string;

use console::{
    account::{Address, PrivateKey, Signature},
    network::Network,
    prelude::{
        Debug,
        Deserialize,
        DeserializeExt,
        Deserializer,
        Display,
        Error,
        Formatter,
        FromBytes,
        FromBytesUncheckedDeserializer,
        FromStr,
        IoResult,
        Read,
        Serialize,
        SerializeStruct,
        Serializer,
        ToBytes,
        ToBytesSerializer,
        Write,
        de,
        error,
        fmt,
        ser,
    },
    types::Field,
};
use snarkvm_ledger_narwhal_subdag::Subdag;

use anyhow::Result;
use rand::{CryptoRng, Rng};

#[derive(Clone, PartialEq, Eq)]
pub enum Authority<N: Network> {
    Beacon(Signature<N>),
    Quorum(Subdag<N>),
}

impl<N: Network> Authority<N> {
    /// Initializes a new beacon authority.
    pub fn new_beacon<R: Rng + CryptoRng>(
        private_key: &PrivateKey<N>,
        block_hash: Field<N>,
        rng: &mut R,
    ) -> Result<Self> {
        // Sign the block hash.
        let signature = private_key.sign(&[block_hash], rng)?;
        // Return the beacon authority.
        Ok(Self::Beacon(signature))
    }

    /// Initializes a new quorum authority.
    pub fn new_quorum(subdag: Subdag<N>) -> Self {
        Self::Quorum(subdag)
    }
}

impl<N: Network> Authority<N> {
    /// Initializes a new beacon authority from the given signature.
    pub const fn from_beacon(signature: Signature<N>) -> Self {
        Self::Beacon(signature)
    }

    /// Initializes a new quorum authority.
    pub const fn from_quorum(subdag: Subdag<N>) -> Self {
        Self::Quorum(subdag)
    }
}

impl<N: Network> Authority<N> {
    /// Returns `true` if the authority is a beacon.
    pub const fn is_beacon(&self) -> bool {
        matches!(self, Self::Beacon(_))
    }

    /// Returns `true` if the authority is a quorum.
    pub const fn is_quorum(&self) -> bool {
        matches!(self, Self::Quorum(_))
    }
}

impl<N: Network> Authority<N> {
    /// Returns address of the authority.
    /// If the authority is a beacon, the address of the signer is returned.
    /// If the authority is a quorum, the address of the leader is returned.
    pub fn to_address(&self) -> Address<N> {
        match self {
            Self::Beacon(signature) => signature.to_address(),
            Self::Quorum(subdag) => subdag.leader_address(),
        }
    }

    /// Returns spend and synthesis limits for a beacon block at `block_height`.
    pub fn beacon_limits(block_height: u32) -> (Option<u64>, Option<u64>) {
        (Subdag::<N>::min_spend_limit(block_height), Subdag::<N>::min_synthesis_limit(block_height))
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::prelude::{TestRng, Uniform};

    pub type CurrentNetwork = console::network::MainnetV0;

    /// Returns a sample beacon authority.
    pub fn sample_beacon_authority(rng: &mut TestRng) -> Authority<CurrentNetwork> {
        Authority::new_beacon(&PrivateKey::new(rng).unwrap(), Field::rand(rng), rng).unwrap()
    }

    /// Returns a sample quorum authority.
    pub fn sample_quorum_authority(rng: &mut TestRng) -> Authority<CurrentNetwork> {
        // Return the quorum authority.
        Authority::new_quorum(snarkvm_ledger_narwhal_subdag::test_helpers::sample_subdag(rng))
    }

    /// Returns a list of sample authorities.
    pub fn sample_authorities(rng: &mut TestRng) -> Vec<Authority<CurrentNetwork>> {
        vec![sample_beacon_authority(rng), sample_quorum_authority(rng)]
    }
}
