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

impl<N: Network> Process<N> {
    /// Authorizes a call to the program function for the given inputs.
    ///
    // This method is meant to be completely stateless. It has no notion of block height or consensus version.
    #[inline]
    pub fn authorize<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        program_id: impl TryInto<ProgramID<N>>,
        function_name: impl TryInto<Identifier<N>>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<N>>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, ProcessAuthError> {
        // Authorize the call.
        self.get_stack(program_id)?
            .authorize::<A, R>(private_key, function_name, inputs, rng)
            .map_err(ProcessAuthError::from)
    }

    /// Authorizes a call to the program function for the given inputs.
    /// Compared to `authorize`, this method does not check for circuit satisfiability of the request.
    #[inline]
    pub fn authorize_unchecked<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        program_id: impl TryInto<ProgramID<N>>,
        function_name: impl TryInto<Identifier<N>>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<N>>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, ProcessAuthError> {
        // Authorize the call.
        self.get_stack(program_id)?
            .authorize_unchecked::<A, R>(private_key, function_name, inputs, rng)
            .map_err(ProcessAuthError::from)
    }

    /// Authorizes a call to the program function for the given inputs.
    /// Compared to `authorize`, no private key is needed, but this only works for single public requests.
    #[inline]
    pub fn authorize_request<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        request: Request<N>,
        rng: &mut R,
    ) -> Result<Authorization<N>, ProcessAuthError> {
        // Initialize the program id.
        let program_id = request.program_id();
        // Authorize the call.
        self.get_stack(program_id)?.authorize_request::<A, R>(request, rng).map_err(ProcessAuthError::from)
    }

    /// Authorizes the fee given the credits record, the fee amount (in microcredits),
    /// and the deployment or execution ID.
    #[inline]
    pub fn authorize_fee_private<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        credits: Record<N, Plaintext<N>>,
        base_fee_in_microcredits: u64,
        priority_fee_in_microcredits: u64,
        deployment_or_execution_id: Field<N>,
        rng: &mut R,
    ) -> Result<Authorization<N>, ProcessAuthError> {
        let timer = timer!("Process::authorize_fee_private");

        // Ensure the fee has the correct program ID.
        let program_id = ProgramID::from_str("credits.aleo")?;
        // Ensure the fee has the correct function.
        let function_name = Identifier::from_str("fee_private")?;

        // Ensure the record contains a sufficient balance to pay the fee.
        ensure_record_microcredits_is_sufficient(
            &credits,
            base_fee_in_microcredits.saturating_add(priority_fee_in_microcredits),
        )?;

        // Construct the inputs.
        let inputs = [
            Value::Record(credits),
            Value::from(Literal::U64(U64::<N>::new(base_fee_in_microcredits))),
            Value::from(Literal::U64(U64::<N>::new(priority_fee_in_microcredits))),
            Value::from(Literal::Field(deployment_or_execution_id)),
        ]
        .into_iter();
        lap!(timer, "Construct the inputs");

        // Authorize the call.
        let authorization = self.get_stack(program_id)?.authorize::<A, R>(private_key, function_name, inputs, rng)?;
        finish!(timer, "Compute the authorization");

        // Return the authorization.
        Ok(authorization)
    }

    /// Authorizes the fee given the the fee amount (in microcredits) and the deployment or execution ID.
    #[inline]
    pub fn authorize_fee_public<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        base_fee_in_microcredits: u64,
        priority_fee_in_microcredits: u64,
        deployment_or_execution_id: Field<N>,
        rng: &mut R,
    ) -> Result<Authorization<N>, ProcessAuthError> {
        let timer = timer!("Process::authorize_fee_public");

        // Ensure the fee has the correct program ID.
        let program_id = ProgramID::from_str("credits.aleo")?;
        // Ensure the fee has the correct function.
        let function_name = Identifier::from_str("fee_public")?;

        // Construct the inputs.
        let inputs = [
            Value::from(Literal::U64(U64::<N>::new(base_fee_in_microcredits))),
            Value::from(Literal::U64(U64::<N>::new(priority_fee_in_microcredits))),
            Value::from(Literal::Field(deployment_or_execution_id)),
        ]
        .into_iter();
        lap!(timer, "Construct the inputs");

        // Authorize the call.
        let authorization = self.get_stack(program_id)?.authorize::<A, R>(private_key, function_name, inputs, rng)?;
        finish!(timer, "Compute the authorization");

        // Return the authorization.
        Ok(authorization)
    }
}

/// Ensures the record contains a sufficient balance to pay the fee.
fn ensure_record_microcredits_is_sufficient<N: Network>(
    record: &Record<N, Plaintext<N>>,
    fee_in_microcredits: u64,
) -> Result<()> {
    // Retrieve the balance from the record.
    let balance = match record.find(&[Identifier::from_str("microcredits")?]) {
        Ok(console::program::Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => *amount,
        _ => bail!("The fee record does not contain a 'microcredits' entry"),
    };
    // Ensure the balance is sufficient to pay the fee.
    ensure!(balance >= fee_in_microcredits, "Credits record balance is insufficient to pay the fee");
    Ok(())
}
