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

use std::collections::HashMap;

/// A tracker for records which are both minted by a request in a given transaction and received
/// (possibly as external or dynamic) by other requests in the same transaction. Entry `(n, m) ->
/// [(k_1, l_1), (k_2, l_2), ...]` indicates that the `n`-th transaction outputs a static record at
/// register `m` which is (possibly after conversion to an external or dynamic record) passed as the
/// `l_1`-th input to the `k_1`-th request, the `l_2`-th input to the `k_2`-th request, etc.
pub type RecordFlowTracker = HashMap<(usize, u64), Vec<(usize, usize)>>;

impl<N: Network> Stack<N> {
    /// Authorizes a call to the program function for the given inputs.
    #[inline]
    pub fn authorize<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        function_name: impl TryInto<Identifier<N>>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<N>>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, StackAuthError> {
        let timer = timer!("Stack::authorize");

        // Get the program ID.
        let program_id = *self.program.id();
        // Prepare the function name.
        let function_name = function_name.try_into().map_err(|_| anyhow!("Invalid function name"))?;
        // Retrieve the input types.
        let input_types = self.get_function(&function_name)?.input_types();
        lap!(timer, "Retrieve the input types");
        // Set is_root to true.
        let is_root = true;
        // Retrieve the program checksum, if the program has a constructor.
        let program_checksum = match self.program().contains_constructor() {
            true => Some(self.program_checksum_as_field()?),
            false => None,
        };

        // This is the root request and does not have a caller.
        let caller = None;
        // This is the root request and we do not have a root_tvk to pass on.
        let root_tvk = None;
        // Compute the request.
        let request = Request::sign(
            private_key,
            program_id,
            function_name,
            inputs,
            &input_types,
            root_tvk,
            is_root,
            program_checksum,
            false,
            rng,
        )?;
        lap!(timer, "Compute the request");
        // Initialize the authorization.
        let authorization = Authorization::new(request.clone());
        // Construct the call stack.
        let call_stack = CallStack::Authorize(vec![request], Some(*private_key), authorization.clone());
        // Construct the authorization from the function.
        let _response = self.execute_function::<A, R>(call_stack, caller, root_tvk, rng)?;
        finish!(timer, "Construct the authorization from the function");

        // Return the authorization.
        Ok(authorization)
    }

    /// Authorizes a call to the program function for the given inputs.
    /// Compared to `authorize`, this method does not check for circuit satisfiability of the request.
    #[inline]
    pub fn authorize_unchecked<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        function_name: impl TryInto<Identifier<N>>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<N>>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, StackAuthError> {
        let timer = timer!("Stack::authorize_unchecked");

        // Get the program ID.
        let program_id = *self.program.id();
        // Prepare the function name.
        let function_name = function_name.try_into().map_err(|_| anyhow!("Invalid function name"))?;
        // Retrieve the input types.
        let input_types = self.get_function(&function_name)?.input_types();
        lap!(timer, "Retrieve the input types");
        // Set is_root to true.
        let is_root = true;

        // This is the root request and does not have a caller.
        let caller = None;
        // This is the root request and we do not have a root_tvk to pass on.
        let root_tvk = None;
        // Retrieve the program checksum, if the program has a constructor.
        let program_checksum = match self.program().contains_constructor() {
            true => Some(self.program_checksum_as_field()?),
            false => None,
        };
        // Compute the request.
        let request = Request::sign(
            private_key,
            program_id,
            function_name,
            inputs,
            &input_types,
            root_tvk,
            is_root,
            program_checksum,
            false,
            rng,
        )?;
        lap!(timer, "Compute the request");
        // Initialize the authorization.
        let authorization = Authorization::new(request.clone());
        // Construct the call stack.
        let call_stack = CallStack::Authorize(vec![request], Some(*private_key), authorization.clone());
        // Construct the authorization from the function.
        let _response = self.evaluate_function::<A, R>(call_stack, caller, root_tvk, rng)?;
        finish!(timer, "Construct the authorization from the function");

        // Return the authorization.
        Ok(authorization)
    }

    /// Produces a mocked `Authorization` for a call to the given function on
    /// the supplied inputs using the provided caller address. The resulting
    /// `Authorization` has the same size as the one which would be produced
    /// (and signed) using the private key corresponding to that address and can
    /// therefore be used to compute the cost of the associated `Execution`, but
    /// many of its values (such as the input IDs in the `Request`s) may not be
    /// correct. This method does not check circuit satisfiability or `Request`
    /// validity.
    #[inline]
    pub fn sample_authorization<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        address: Address<A::Network>,
        program_id: ProgramID<A::Network>,
        function_name: Identifier<A::Network>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<A::Network>>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, StackAuthError> {
        self.sample_authorization_with_record_tracking::<A, R>(address, program_id, function_name, inputs, rng)
            .map(|(authorization, _, _, _)| authorization)
    }

    /// Produces a mocked `Authorization` with the same properties as
    /// `sample_authorization` alongside some extra information necessary to
    /// populate the mocked `Request`s. In a multi-request signing flow,
    /// sampling the `tvk` of a request requires static, external and dynamic
    /// record inputs to subsequent mocked requests to be updated with nonces
    /// derived from the fresh `tvk`.
    #[inline]
    pub fn sample_authorization_with_record_tracking<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        address: Address<A::Network>,
        program_id: ProgramID<A::Network>,
        function_name: Identifier<A::Network>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<A::Network>>>,
        rng: &mut R,
    ) -> Result<(Authorization<N>, RecordFlowTracker, RecordNameTracker<N>, ProgramChecksumTracker<N>), StackAuthError>
    {
        let timer = timer!("Stack::sample_authorization");

        if program_id != *self.program.id() {
            return Err(anyhow!("Program ID mismatch").into());
        }

        // Get the program ID.
        let program_id = *self.program.id();
        // Retrieve the input types.
        let input_types = self.get_function(&function_name)?.input_types();
        lap!(timer, "Retrieve the input types");

        // This is the root request and does not have a caller.
        let caller = None;
        // This is the root request and we do not have a root_tvk to pass on.
        let root_tvk = None;

        // Compute the mock request.
        let mocked_request = Request::sample(address, program_id, function_name, inputs, &input_types, false, rng)?;

        lap!(timer, "Compute the mocked request");
        // Initialize the authorization.
        let authorization = Authorization::new(mocked_request.clone());
        // Initialize Arc-wrapped trackers for static records minted in the transaction and static,
        // dynamic and external records received by any request in the transaction
        let minted_static_records = Arc::new(RwLock::new(HashMap::new()));
        let input_records = Arc::new(RwLock::new(HashMap::new()));
        // Construct the call stack.
        let call_stack = CallStack::AuthorizeMocked(
            vec![mocked_request],
            address,
            authorization.clone(),
            minted_static_records.clone(),
            input_records.clone(),
        );
        // Construct the authorization from the function.
        let _response = self.evaluate_function::<A, R>(call_stack, caller, root_tvk, rng)?;
        lap!(timer, "Construct the mocked authorization from the function");

        // Collate the information on minted and consumed records:
        let mut record_tracking = HashMap::new();
        let input_records = input_records.read();
        let minted_static_records = minted_static_records.read();

        for (nonce_x, minter_request_and_register) in minted_static_records.iter() {
            if let Some(consumer_requests_and_indices) = input_records.get(nonce_x) {
                record_tracking.insert(*minter_request_and_register, consumer_requests_and_indices.clone());
            }
        }

        // Collect the names of (all) static Record inputs and the program checksums.
        let record_names = authorization.collect_record_names(self)?;
        let program_checksums = authorization.collect_program_checksums(self)?;

        finish!(timer, "Gather record-tracking and other auxiliary information");

        // Return the authorization and record tracking.
        Ok((authorization, record_tracking, record_names, program_checksums))
    }

    /// Authorizes a call to a public function for the given request.
    /// Compared to `authorize`, no private key is needed, but this only works for single public requests.
    #[inline]
    pub fn authorize_request<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        request: Request<N>,
        rng: &mut R,
    ) -> Result<Authorization<N>, StackAuthError> {
        let timer = timer!("Stack::authorize_request");

        // Initialize the authorization.
        let authorization = Authorization::new(request.clone());
        // Construct the call stack.
        let call_stack = CallStack::Authorize(vec![request], None, authorization.clone());
        // This is the root request and does not have a caller.
        let caller = None;
        // This is the root request and we do not have a root_tvk to pass on.
        let root_tvk = None;
        // Construct the authorization from the function.
        let _response = self.evaluate_function::<A, R>(call_stack, caller, root_tvk, rng)?;
        finish!(timer, "Construct the authorization from the function");

        // Return the authorization.
        Ok(authorization)
    }

    /// Authorizes a number of `Request`s resulting from a root call and populated with correct data
    /// (`tvk`, input IDs, signature, etc.), checking they are correctly related. The `Request`s
    /// must be in DFS pre-order (as present, for instance, in `Authorization`s).
    #[inline]
    pub fn authorize_requests<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        requests: Vec<Request<N>>,
        rng: &mut R,
    ) -> Result<Authorization<N>, StackAuthError> {
        let timer = timer!("Stack::authorize_requests");

        if requests.is_empty() {
            return Err(anyhow!("No requests provided").into());
        }

        // A root request has no caller, so it cannot be dynamic.
        if requests[0].is_dynamic() {
            return Err(anyhow!(
                "The root request for '{}/{}' is flagged dynamic",
                requests[0].program_id(),
                requests[0].function_name()
            )
            .into());
        }

        if *requests[0].program_id() != *self.program.id() {
            return Err(anyhow!("Program ID mismatch in 'authorize_requests'").into());
        }

        // Ensure each request's signer commitment `scm` is `Hash(signer || root_tvk)`.
        let root_tvk = *requests[0].tvk();
        for (index, request) in requests.iter().enumerate() {
            if *request.scm() != N::hash_psd2(&[request.signer().to_x_coordinate(), root_tvk])? {
                return Err(anyhow!(
                    "The request at index {index} for '{}/{}' has a signer commitment that does not match its signer and root 'tvk'",
                    request.program_id(),
                    request.function_name()
                )
                .into());
            }
        }

        // This index, passed to the call stack, tracks the element in the requests array currently
        // being explored. It is shared throughout the entire evaluation of the call stack, just like
        // the authorization is handled.
        let current_index = Arc::new(RwLock::new(0));

        // Initialize the authorization with the request corresponding to the root call.
        let authorization = Authorization::new(requests[0].clone());
        let num_requests = requests.len();

        // Construct the call stack in AuthorizeRequests mode.
        let call_stack = CallStack::AuthorizeRequests(requests, current_index, authorization.clone());

        // Populate the authorization by processing the call stack.
        let _response = self.evaluate_function::<A, R>(call_stack, None, None, rng)?;

        finish!(timer, "Construct the authorization from the function");

        if authorization.transitions().len() != num_requests {
            return Err(anyhow!(
                "Not all requests supplied were explored while evaluating CallStack::AuthorizeRequests"
            )
            .into());
        }

        // Return the authorization.
        Ok(authorization)
    }
}
