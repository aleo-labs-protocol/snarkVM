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
#![allow(clippy::too_many_arguments)]
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_console_account as console;

#[cfg(test)]
use snarkvm_circuit_network::AleoV0 as Circuit;

pub mod compute_key;
pub use compute_key::*;

pub mod graph_key;
pub use graph_key::*;

pub mod private_key;
pub use private_key::*;

pub mod signature;
pub use signature::*;

pub mod view_key;
pub use view_key::*;

#[cfg(test)]
pub(crate) mod helpers {
    use snarkvm_circuit_network::AleoV0;
    use snarkvm_circuit_types::environment::Environment;
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    type CurrentNetwork = <AleoV0 as Environment>::Network;

    #[allow(clippy::type_complexity)]
    pub(crate) fn generate_account() -> Result<(
        console::PrivateKey<CurrentNetwork>,
        console::ComputeKey<CurrentNetwork>,
        console::ViewKey<CurrentNetwork>,
        console::Address<CurrentNetwork>,
    )> {
        // Sample a random private key.
        let private_key = console::PrivateKey::<CurrentNetwork>::new(&mut TestRng::default())?;

        // Derive the compute key, view key, and address.
        let compute_key = console::ComputeKey::try_from(&private_key)?;
        let view_key = console::ViewKey::try_from(&private_key)?;
        let address = console::Address::try_from(&compute_key)?;

        // Return the private key and compute key components.
        Ok((private_key, compute_key, view_key, address))
    }

    pub(crate) fn generate_signature(num_fields: u64, rng: &mut TestRng) -> console::Signature<CurrentNetwork> {
        // Sample an address and a private key.
        let private_key = console::PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let address = console::Address::try_from(&private_key).unwrap();

        // Generate a signature.
        let message: Vec<_> = (0..num_fields).map(|_| Uniform::rand(rng)).collect();
        let signature = console::Signature::sign(&private_key, &message, rng).unwrap();
        assert!(signature.verify(&address, &message));
        signature
    }
}
