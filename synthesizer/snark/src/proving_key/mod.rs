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

use std::collections::BTreeMap;

#[derive(Clone)]
pub struct ProvingKey<N: Network> {
    /// The proving key for the function.
    proving_key: Arc<varuna::CircuitProvingKey<N::PairingCurve, varuna::VarunaHidingMode>>,
}

impl<N: Network> ProvingKey<N> {
    /// Initializes a new proving key.
    pub const fn new(proving_key: Arc<varuna::CircuitProvingKey<N::PairingCurve, varuna::VarunaHidingMode>>) -> Self {
        Self { proving_key }
    }

    /// Returns a proof for the given assignment on the circuit.
    pub fn prove<R: Rng + CryptoRng>(
        &self,
        function_name: &str,
        varuna_version: varuna::VarunaVersion,
        assignment: &circuit::Assignment<N::Field>,
        rng: &mut R,
    ) -> Result<Proof<N>> {
        let _timer = timing_span!("Prove", function_name).entered();

        // Retrieve the proving parameters.
        let universal_prover = N::varuna_universal_prover();
        let fiat_shamir = N::varuna_fs_parameters();

        // Compute the proof.
        let proof =
            Proof::new(Varuna::<N>::prove(universal_prover, fiat_shamir, self, varuna_version, assignment, rng)?);

        Ok(proof)
    }

    /// Returns a proof for the given batch of proving keys and assignments.
    #[allow(clippy::type_complexity)]
    pub fn prove_batch<R: Rng + CryptoRng>(
        locator: &str,
        varuna_version: varuna::VarunaVersion,
        assignments: &[(ProvingKey<N>, Vec<circuit::Assignment<N::Field>>)],
        rng: &mut R,
    ) -> Result<Proof<N>> {
        let _timer = timing_span!("Prove batch", locator).entered();

        // Prepare the instances.
        let num_expected_instances = assignments.len();
        let instances: BTreeMap<_, _> = assignments
            .iter()
            .map(|(proving_key, assignments)| (proving_key.deref(), assignments.as_slice()))
            .collect();
        ensure!(instances.len() == num_expected_instances, "Incorrect number of proving keys for batch proof");

        // Retrieve the proving parameters.
        let universal_prover = N::varuna_universal_prover();
        let fiat_shamir = N::varuna_fs_parameters();

        // Compute the proof.
        let batch_proof =
            Proof::new(Varuna::<N>::prove_batch(universal_prover, fiat_shamir, varuna_version, &instances, rng)?);

        Ok(batch_proof)
    }
}

impl<N: Network> Deref for ProvingKey<N> {
    type Target = varuna::CircuitProvingKey<N::PairingCurve, varuna::VarunaHidingMode>;

    fn deref(&self) -> &Self::Target {
        &self.proving_key
    }
}
