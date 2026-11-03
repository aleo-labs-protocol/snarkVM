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

use super::*;

mod bytes;
mod parse;
mod serialize;

use snarkvm_algorithms::snark::varuna::VarunaVersion;
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey<N: Network> {
    /// The verifying key for the function.
    verifying_key: Arc<varuna::CircuitVerifyingKey<N::PairingCurve>>,
    /// The number of public and private variables for the circuit.
    num_variables: u64,
}

impl<N: Network> VerifyingKey<N> {
    /// Initializes a new verifying key.
    pub const fn new(verifying_key: Arc<varuna::CircuitVerifyingKey<N::PairingCurve>>, num_variables: u64) -> Self {
        Self { verifying_key, num_variables }
    }

    /// Returns the number of public and private variables for the circuit.
    pub fn num_variables(&self) -> u64 {
        self.num_variables
    }

    /// Returns `true` if the proof is valid for the given public inputs.
    pub fn verify(
        &self,
        _function_name: &str,
        varuna_version: varuna::VarunaVersion,
        inputs: &[N::Field],
        proof: &Proof<N>,
    ) -> bool {
        #[cfg(feature = "dev-print")]
        let timer = std::time::Instant::now();

        // Retrieve the verification parameters.
        let universal_verifier = N::varuna_universal_verifier();
        let fiat_shamir = N::varuna_fs_parameters();

        // Verify the proof.
        #[allow(clippy::manual_unwrap_or_default)]
        match Varuna::<N>::verify(universal_verifier, fiat_shamir, self, varuna_version, inputs, proof) {
            Ok(is_valid) => {
                #[cfg(feature = "dev-print")]
                {
                    let _elapsed = timer.elapsed().as_millis();
                    dev_println!(" • Verified '{_function_name}' (in {_elapsed} ms)");
                }
                is_valid
            }
            Err(_error) => {
                dev_println!(" • Verifier failed on network {}: {_error}", N::NAME);
                false
            }
        }
    }

    /// Returns `true` if the batch proof is valid for the given public inputs.
    #[allow(clippy::type_complexity)]
    pub fn verify_batch(
        _locator: &str,
        varuna_version: VarunaVersion,
        inputs: Vec<(VerifyingKey<N>, Vec<Vec<N::Field>>)>,
        proof: &Proof<N>,
    ) -> Result<()> {
        #[cfg(feature = "dev-print")]
        let timer = std::time::Instant::now();

        // Convert the instances.
        let num_expected_keys = inputs.len();
        let keys_to_inputs: BTreeMap<_, _> =
            inputs.iter().map(|(verifying_key, inputs)| (verifying_key.deref(), inputs.as_slice())).collect();
        ensure!(keys_to_inputs.len() == num_expected_keys, "Incorrect number of verifying keys for batch proof");

        // Retrieve the verification parameters.
        let universal_verifier = N::varuna_universal_verifier();
        let fiat_shamir = N::varuna_fs_parameters();

        // Verify the batch proof.
        match Varuna::<N>::verify_batch(universal_verifier, fiat_shamir, varuna_version, &keys_to_inputs, proof) {
            Ok(is_valid) => {
                #[cfg(feature = "dev-print")]
                {
                    let _elapsed = timer.elapsed().as_millis();
                    dev_println!(" • Verified '{_locator}': {is_valid} (in {_elapsed} ms)");
                }
                if is_valid { Ok(()) } else { bail!("'verify_batch' failed") }
            }
            Err(error) => {
                dev_println!(" • Verifier failed on network {}: {error}", N::NAME);
                bail!(error)
            }
        }
    }
}

impl<N: Network> Deref for VerifyingKey<N> {
    type Target = varuna::CircuitVerifyingKey<N::PairingCurve>;

    fn deref(&self) -> &Self::Target {
        &self.verifying_key
    }
}
