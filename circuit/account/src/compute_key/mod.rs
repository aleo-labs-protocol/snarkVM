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

mod equal;
mod from;
mod from_private_key;
mod helpers;
mod ternary;
mod to_address;

#[cfg(test)]
use snarkvm_circuit_types::environment::assert_scope;

use crate::PrivateKey;
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Address, Boolean, Field, Group, Scalar, environment::prelude::*};

#[derive(Clone)]
pub struct ComputeKey<A: Aleo> {
    /// The signature public key `pk_sig` := G^sk_sig.
    pk_sig: Group<A>,
    /// The signature public randomizer `pr_sig` := G^r_sig.
    pr_sig: Group<A>,
    /// The PRF secret key `sk_prf` := RO(G^sk_sig || G^r_sig).
    sk_prf: Scalar<A>,
}

impl<A: Aleo> Inject for ComputeKey<A> {
    type Primitive = console::ComputeKey<A::Network>;

    /// Initializes an account compute key from the given mode and native compute key.
    fn new(mode: Mode, compute_key: Self::Primitive) -> Self {
        // Inject `pk_sig`.
        let pk_sig = Group::new(mode, compute_key.pk_sig());
        // Inject `pr_sig`.
        let pr_sig = Group::new(mode, compute_key.pr_sig());
        // Output the compute key.
        Self::from((pk_sig, pr_sig))
    }
}

impl<A: Aleo> ComputeKey<A> {
    /// Returns the signature public key.
    pub const fn pk_sig(&self) -> &Group<A> {
        &self.pk_sig
    }

    /// Returns the signature public randomizer.
    pub const fn pr_sig(&self) -> &Group<A> {
        &self.pr_sig
    }

    /// Returns the PRF secret key.
    pub const fn sk_prf(&self) -> &Scalar<A> {
        &self.sk_prf
    }
}

impl<A: Aleo> Eject for ComputeKey<A> {
    type Primitive = console::ComputeKey<A::Network>;

    /// Ejects the mode of the compute key.
    fn eject_mode(&self) -> Mode {
        (&self.pk_sig, &self.pr_sig, &self.sk_prf).eject_mode()
    }

    /// Ejects the compute key.
    fn eject_value(&self) -> Self::Primitive {
        match Self::Primitive::try_from((&self.pk_sig, &self.pr_sig).eject_value()) {
            Ok(compute_key) => compute_key,
            Err(error) => A::halt(format!("Failed to eject the compute key: {error}")),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Circuit, helpers::generate_account};

    use anyhow::Result;

    const ITERATIONS: u64 = 10;

    fn check_new(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        for i in 0..ITERATIONS {
            // Generate a private key, compute key, view key, and address.
            let (_private_key, compute_key, _view_key, _address) = generate_account()?;

            Circuit::scope(format!("New {mode}"), || {
                let candidate = ComputeKey::<Circuit>::new(mode, compute_key);
                match mode.is_constant() {
                    true => assert_eq!(Mode::Constant, candidate.eject_mode()),
                    false => assert_eq!(Mode::Private, candidate.eject_mode()),
                };
                assert_eq!(compute_key, candidate.eject_value());
                // TODO (howardwu): Resolve skipping the cost count checks for the burn-in round.
                if i > 0 {
                    assert_scope!(num_constants, num_public, num_private, num_constraints);
                }
            });
            Circuit::reset();
        }
        Ok(())
    }

    #[test]
    fn test_compute_key_new_constant() -> Result<()> {
        check_new(Mode::Constant, 274, 0, 0, 0)
    }

    #[test]
    fn test_compute_key_new_public() -> Result<()> {
        check_new(Mode::Public, 9, 4, 869, 873)
    }

    #[test]
    fn test_compute_key_new_private() -> Result<()> {
        check_new(Mode::Private, 9, 0, 873, 873)
    }
}
