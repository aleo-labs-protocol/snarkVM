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

use snarkvm_synthesizer_error::*;

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Authorizes a call to the program function for the given inputs.
    #[inline]
    pub fn authorize<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        program_id: impl TryInto<ProgramID<N>>,
        function_name: impl TryInto<Identifier<N>>,
        inputs: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = impl TryInto<Value<N>>>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, VmAuthError> {
        let timer = timing_span!("VM::authorize").entered();

        // Prepare the program ID.
        let program_id = program_id.try_into().map_err(|_| anyhow!("Invalid program ID"))?;
        // Prepare the function name.
        let function_name = function_name.try_into().map_err(|_| anyhow!("Invalid function name"))?;
        // Prepare the inputs.
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(index, input)| {
                input
                    .try_into()
                    .map_err(|_| anyhow!("Failed to parse input #{index} for '{program_id}/{function_name}'"))
            })
            .collect::<Result<Vec<_>>>()?;
        timing_event!("Prepare inputs");

        // Authorize the call.
        let result = self.authorize_raw(private_key, program_id, function_name, inputs, rng);
        timing_event!("Authorize the call");
        drop(timer);
        result
    }

    /// Authorizes the fee given the credits record, the fee amount (in microcredits),
    /// and the deployment or execution ID.
    #[inline]
    pub fn authorize_fee_private<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        credits: Record<N, Plaintext<N>>,
        base_fee_in_microcredits: u64,
        priority_fee_in_microcredits: u64,
        deployment_or_execution_id: Field<N>,
        rng: &mut R,
    ) -> Result<Authorization<N>> {
        macro_rules! logic {
            ($process:expr, $network:path, $aleo:path) => {{
                // Compute the authorization.
                let authorization = $process.authorize_fee_private::<$aleo, _>(
                    cast_ref!(&private_key as PrivateKey<$network>),
                    cast_ref!(credits as Record<$network, Plaintext<$network>>).clone(),
                    base_fee_in_microcredits,
                    priority_fee_in_microcredits,
                    *cast_ref!(deployment_or_execution_id as Field<$network>),
                    rng,
                )?;
                // Prepare the authorization.
                Ok(cast_ref!(authorization as Authorization<N>).clone())
            }};
        }

        // Compute the authorization.
        let timer = timing_span!("VM::authorize_fee_private").entered();
        let result = process!(self, logic);
        timing_event!("Compute the authorization");
        drop(timer);
        result
    }

    /// Authorizes the fee given the the fee amount (in microcredits) and the deployment or execution ID.
    #[inline]
    pub fn authorize_fee_public<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        base_fee_in_microcredits: u64,
        priority_fee_in_microcredits: u64,
        deployment_or_execution_id: Field<N>,
        rng: &mut R,
    ) -> Result<Authorization<N>> {
        macro_rules! logic {
            ($process:expr, $network:path, $aleo:path) => {{
                // Compute the authorization.
                let authorization = $process.authorize_fee_public::<$aleo, _>(
                    cast_ref!(&private_key as PrivateKey<$network>),
                    base_fee_in_microcredits,
                    priority_fee_in_microcredits,
                    *cast_ref!(deployment_or_execution_id as Field<$network>),
                    rng,
                )?;
                // Prepare the authorization.
                Ok(cast_ref!(authorization as Authorization<N>).clone())
            }};
        }

        // Compute the authorization.
        let timer = timing_span!("VM::authorize_fee_public").entered();
        let result = process!(self, logic);
        timing_event!("Compute the authorization");
        drop(timer);
        result
    }
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Authorizes a call to the program function for the given inputs.
    #[inline]
    fn authorize_raw<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        program_id: ProgramID<N>,
        function_name: Identifier<N>,
        inputs: Vec<Value<N>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, VmAuthError> {
        macro_rules! logic {
            ($process:expr, $network:path, $aleo:path) => {{
                // Compute the authorization.
                let authorization = $process.authorize::<$aleo, _>(
                    cast_ref!(&private_key as PrivateKey<$network>),
                    cast_ref!(program_id as ProgramID<$network>),
                    cast_ref!(function_name as Identifier<$network>),
                    cast_ref!(inputs as Vec<Value<$network>>).iter(),
                    rng,
                )?;
                // Prepare the authorization.
                Ok(cast_ref!(authorization as Authorization<N>).clone())
            }};
        }

        // Compute the authorization.
        let timer = timing_span!("VM::authorize_raw").entered();
        let result = process!(self, logic);
        timing_event!("Compute the authorization");
        drop(timer);
        result
    }
}
