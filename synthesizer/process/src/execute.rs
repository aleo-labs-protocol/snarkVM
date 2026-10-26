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
    /// Executes the given authorization.
    #[inline]
    pub fn execute<A: circuit::Aleo<Network = N>, R: CryptoRng + Rng>(
        &self,
        authorization: Authorization<N>,
        rng: &mut R,
    ) -> Result<(Response<N>, Trace<N>), ProcessExecError> {
        let timer = timer!("Process::execute");

        // Retrieve the main request (without popping it).
        let request = authorization.peek_next()?;
        // Construct the locator.
        let locator = Locator::new(*request.program_id(), *request.function_name());
        // A root request has no caller, so it cannot be dynamic.
        if request.is_dynamic() {
            return Err(anyhow!("The root request for '{locator}' is flagged dynamic").into());
        }

        dev_println!("{}", format!(" • Executing '{locator}'...",));

        // The root request does not have a caller.
        let caller = None;
        // The root request does not have to pass on another request's root_tvk.
        let root_tvk = None;
        // Initialize the trace.
        let trace = Arc::new(RwLock::new(Trace::new()));
        // Initialize the translations.
        let translations = Arc::new(RwLock::new(Vec::new()));
        // Retrieve the number of requests, which `execute_function` consumes.
        let num_requests = authorization.len();
        // Initialize the call stack.
        let call_stack = CallStack::execute(authorization, trace.clone(), translations)?;
        lap!(timer, "Initialize call stack");

        // Retrieve the stack.
        let stack = self.get_stack(request.program_id())?;
        // Execute the circuit.
        let Some(response) = stack.execute_function::<A, R>(call_stack, caller, root_tvk, rng)? else {
            return Err(anyhow!("Response should be present in `Execute` mode.").into());
        };
        lap!(timer, "Execute the function");

        // Extract the trace.
        let mut trace = Arc::try_unwrap(trace).unwrap().into_inner();
        // Ensure the trace is not empty.
        if trace.transitions().is_empty() {
            return Err(anyhow!("Execution of '{locator}' is empty").into());
        }
        // Ensure every request was used.
        if trace.transitions().len() != num_requests {
            return Err(anyhow!(
                "Execution of '{locator}' used {} of its {num_requests} requests",
                trace.transitions().len()
            )
            .into());
        }
        // Construct the call graph.
        trace.construct_call_graph(self)?;

        finish!(timer);
        Ok((response, trace))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::types::Address;

    type CurrentNetwork = console::network::MainnetV0;
    type CurrentAleo = circuit::AleoV0;

    #[test]
    fn test_execute_fee_private() {
        let rng = &mut TestRng::default();

        // Initialize the process.
        let process = Process::<CurrentNetwork>::load().unwrap();

        // Sample a private key.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let owner = Address::try_from(private_key).unwrap();

        // Sample a base fee in microcredits.
        let base_fee_in_microcredits = rng.random_range(1_000_000..u64::MAX / 2);
        // Sample a priority fee in microcredits.
        let priority_fee_in_microcredits = rng.random_range(0..u64::MAX / 2);
        // Sample a deployment or execution ID.
        let deployment_or_execution_id = Field::rand(rng);

        // Sample a credits record.
        let fee_in_microcredits = base_fee_in_microcredits.saturating_add(priority_fee_in_microcredits);
        let credits = Record::<CurrentNetwork, Plaintext<_>>::from_str(&format!(
            "{{ owner: {owner}.private, microcredits: {fee_in_microcredits}u64.private, _nonce: 0group.public, _version: 1u8.public }}"
        ))
        .unwrap();

        // Initialize the authorization.
        let authorization = process
            .authorize_fee_private::<CurrentAleo, _>(
                &private_key,
                credits,
                base_fee_in_microcredits,
                priority_fee_in_microcredits,
                deployment_or_execution_id,
                rng,
            )
            .unwrap();
        assert!(authorization.is_fee_private(), "Authorization must be for a call to 'credits.aleo/fee_private'");

        // Execute the authorization.
        let (response, trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
        // Ensure the response has 1 output.
        assert_eq!(response.outputs().len(), 1, "Execution of 'credits.aleo/fee_private' must contain 1 output");
        // Ensure the response has 1 output ID.
        assert_eq!(response.output_ids().len(), 1, "Execution of 'credits.aleo/fee_private' must contain 1 output ID");
        // Ensure the trace contains 1 transition.
        assert_eq!(trace.transitions().len(), 1, "Execution of 'credits.aleo/fee_private' must contain 1 transition");

        // Retrieve the transition.
        let transition = trace.transitions()[0].clone();
        assert!(transition.is_fee_private(), "Transition must be for 'credits.aleo/fee_private'");
    }

    #[test]
    fn test_execute_fee_public() {
        let rng = &mut TestRng::default();

        // Initialize the process.
        let process = Process::<CurrentNetwork>::load().unwrap();

        // Sample a private key.
        let private_key = PrivateKey::new(rng).unwrap();
        // Sample a base fee in microcredits.
        let base_fee_in_microcredits = rng.random_range(1_000_000..u64::MAX / 2);
        // Sample a priority fee in microcredits.
        let priority_fee_in_microcredits = rng.random_range(0..u64::MAX / 2);
        // Sample a deployment or execution ID.
        let deployment_or_execution_id = Field::rand(rng);

        // Compute the authorization.
        let authorization = process
            .authorize_fee_public::<CurrentAleo, _>(
                &private_key,
                base_fee_in_microcredits,
                priority_fee_in_microcredits,
                deployment_or_execution_id,
                rng,
            )
            .unwrap();
        assert!(authorization.is_fee_public(), "Authorization must be for a call to 'credits.aleo/fee_public'");

        // Execute the authorization.
        let (response, trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
        // Ensure the response has 1 outputs.
        assert_eq!(response.outputs().len(), 1, "Execution of 'credits.aleo/fee_public' must contain 1 output");
        // Ensure the response has 1 output IDs.
        assert_eq!(response.output_ids().len(), 1, "Execution of 'credits.aleo/fee_public' must contain 1 output ID");
        // Ensure the trace contains 1 transition.
        assert_eq!(trace.transitions().len(), 1, "Execution of 'credits.aleo/fee_public' must contain 1 transition");

        // Retrieve the transition.
        let transition = trace.transitions()[0].clone();
        assert!(transition.is_fee_public(), "Transition must be for 'credits.aleo/fee_public'");
    }
}
