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
mod helpers;
mod ternary;
mod verify;

#[cfg(test)]
use snarkvm_circuit_types::environment::{assert_count, assert_output_mode, assert_scope};

use crate::ComputeKey;
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Address, Boolean, Field, Scalar, environment::prelude::*};

#[derive(Clone)]
pub struct Signature<A: Aleo> {
    /// The verifier challenge to check against.
    challenge: Scalar<A>,
    /// The prover response to the challenge.
    response: Scalar<A>,
    /// The compute key of the prover.
    compute_key: ComputeKey<A>,
}

impl<A: Aleo> Inject for Signature<A> {
    type Primitive = console::Signature<A::Network>;

    /// Initializes a signature from the given mode and native signature.
    fn new(mode: Mode, signature: Self::Primitive) -> Signature<A> {
        Self {
            challenge: Scalar::new(mode, signature.challenge()),
            response: Scalar::new(mode, signature.response()),
            compute_key: ComputeKey::new(mode, signature.compute_key()),
        }
    }
}

impl<A: Aleo> Signature<A> {
    /// Returns the challenge.
    pub const fn challenge(&self) -> &Scalar<A> {
        &self.challenge
    }

    /// Returns the response.
    pub const fn response(&self) -> &Scalar<A> {
        &self.response
    }

    /// Returns the account compute key.
    pub const fn compute_key(&self) -> &ComputeKey<A> {
        &self.compute_key
    }
}

impl<A: Aleo> Eject for Signature<A> {
    type Primitive = console::Signature<A::Network>;

    /// Ejects the mode of the signature.
    fn eject_mode(&self) -> Mode {
        (&self.challenge, &self.response, &self.compute_key).eject_mode()
    }

    /// Ejects the signature.
    fn eject_value(&self) -> Self::Primitive {
        Self::Primitive::from((&self.challenge, &self.response, &self.compute_key).eject_value())
    }
}

impl<A: Aleo> Parser for Signature<A> {
    /// Parses a string into a signature circuit.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the signature from the string.
        let (string, signature) = console::Signature::parse(string)?;
        // Parse the mode from the string.
        let (string, mode) = opt(pair(tag("."), Mode::parse))(string)?;

        match mode {
            Some((_, mode)) => Ok((string, Signature::new(mode, signature))),
            None => Ok((string, Signature::new(Mode::Constant, signature))),
        }
    }
}

impl<A: Aleo> FromStr for Signature<A> {
    type Err = Error;

    /// Parses a string into a signature.
    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<A: Aleo> TypeName for Signature<A> {
    /// Returns the type name of the circuit as a string.
    #[inline]
    fn type_name() -> &'static str {
        console::Signature::<A::Network>::type_name()
    }
}

impl<A: Aleo> Debug for Signature<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<A: Aleo> Display for Signature<A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.eject_value(), self.eject_mode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Circuit, helpers::generate_account};
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    const ITERATIONS: u64 = 10;

    fn check_new(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        let rng = &mut TestRng::default();

        // Generate a private key, compute key, view key, and address.
        let (private_key, _compute_key, _view_key, _address) = generate_account()?;

        for i in 0..ITERATIONS {
            // Generate a signature.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = console::Signature::sign(&private_key, &message, rng)?;

            Circuit::scope(format!("New {mode}"), || {
                let candidate = Signature::<Circuit>::new(mode, signature);
                assert_eq!(signature, candidate.eject_value());
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
    fn test_signature_new_constant() -> Result<()> {
        check_new(Mode::Constant, 276, 0, 0, 0)
    }

    #[test]
    fn test_signature_new_public() -> Result<()> {
        check_new(Mode::Public, 9, 6, 869, 873)
    }

    #[test]
    fn test_signature_new_private() -> Result<()> {
        check_new(Mode::Private, 9, 0, 875, 873)
    }
}
