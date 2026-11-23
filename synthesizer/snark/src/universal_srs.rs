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

#[derive(Clone)]
pub struct UniversalSRS<N: Network> {
    /// The universal SRS parameter.
    srs: Arc<OnceLock<varuna::UniversalSRS<N::PairingCurve>>>,
}

impl<N: Network> UniversalSRS<N> {
    /// Initializes the universal SRS.
    pub fn load() -> Result<Self> {
        Ok(Self { srs: Arc::new(OnceLock::new()) })
    }

    /// Returns the circuit proving and verifying key.
    pub fn to_circuit_key(
        &self,
        function_name: &str,
        assignment: &circuit::Assignment<N::Field>,
    ) -> Result<(ProvingKey<N>, VerifyingKey<N>)> {
        let timer = timing_span!("Build circuit key", function_name).entered();
        let (proving_key, verifying_key) = Varuna::<N>::circuit_setup(self, assignment)?;
        drop(timer);

        Ok((
            ProvingKey::new(Arc::new(proving_key)),
            VerifyingKey::new(Arc::new(verifying_key), assignment.num_variables()),
        ))
    }
}

impl<N: Network> Deref for UniversalSRS<N> {
    type Target = varuna::UniversalSRS<N::PairingCurve>;

    fn deref(&self) -> &Self::Target {
        self.srs.get_or_init(|| {
            let _timer = timing_span!("Load universal setup").entered();
            varuna::UniversalSRS::load().expect("Failed to load the universal SRS")
        })
    }
}
