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

#[derive(Clone, PartialEq, Eq)]
pub struct Certificate<N: Network> {
    /// The certificate.
    certificate: varuna::Certificate<N::PairingCurve>,
}

impl<N: Network> Certificate<N> {
    /// Initializes a new certificate.
    pub(super) const fn new(certificate: varuna::Certificate<N::PairingCurve>) -> Self {
        Self { certificate }
    }

    /// Returns the certificate from the proving and verifying key.
    pub fn certify(
        function_name: &str,
        proving_key: &ProvingKey<N>,
        verifying_key: &VerifyingKey<N>,
    ) -> Result<Certificate<N>> {
        let _timer = timing_span!("Certify", function_name).entered();

        // Retrieve the proving parameters.
        let universal_prover = N::varuna_universal_prover();
        let fiat_shamir = N::varuna_fs_parameters();

        // Compute the certificate.
        let certificate = Varuna::<N>::prove_vk(universal_prover, fiat_shamir, verifying_key, proving_key)?;

        Ok(Self::new(certificate))
    }

    /// Returns the certificate from the proving and verifying key.
    pub fn verify(
        &self,
        function_name: &str,
        assignment: &circuit::Assignment<N::Field>,
        verifying_key: &VerifyingKey<N>,
    ) -> bool {
        let _timer = timing_span!("Verify certificate", function_name).entered();

        // Retrieve the verification parameters.
        let universal_verifier = N::varuna_universal_verifier();
        let fiat_shamir = N::varuna_fs_parameters();

        // Verify the certificate.
        #[allow(clippy::manual_unwrap_or_default)]
        match Varuna::<N>::verify_vk(universal_verifier, fiat_shamir, assignment, verifying_key, self) {
            Ok(is_valid) => is_valid,
            Err(error) => {
                debug!("Certificate verification on network {} failed: {error}", N::NAME);
                false
            }
        }
    }
}

impl<N: Network> Deref for Certificate<N> {
    type Target = varuna::Certificate<N::PairingCurve>;

    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}
