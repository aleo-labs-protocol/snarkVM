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

impl<N: Network> Process<N> {
    /// Verifies the given fee is valid.
    /// Note: This does *not* check that the global state root exists in the ledger.
    #[inline]
    pub fn verify_fee(
        &self,
        consensus_version: ConsensusVersion,
        varuna_version: VarunaVersion,
        inclusion_version: InclusionVersion,
        fee: &Fee<N>,
        deployment_or_execution_id: Field<N>,
    ) -> Result<()> {
        let timer = timer!("Process::verify_fee");

        // Retrieve the stack.
        let stack = self.get_stack(fee.program_id())?;
        // Retrieve the function from the stack.
        let function = stack.get_function(fee.function_name())?;

        dev_println!("Verifying fee from {}/{}...", fee.program_id(), fee.function_name());

        #[cfg(debug_assertions)]
        {
            // Ensure that there are no dynamic calls in this function.
            if stack.contains_dynamic_call(function.name())? {
                bail!("The function '{}/{}' should not have dynamic calls", stack.program_id(), function.name())
            }
            // Ensure the minimum number of function calls in this function is 1.
            if stack.get_minimum_number_of_calls(function.name())? != 1 {
                bail!("The number of function calls in '{}/{}' should be 1", stack.program_id(), function.name())
            }
            // Debug-mode only, as the `Transition` constructor recomputes the transition ID at initialization.
            let expected_id = N::hash_bhp512(&(fee.to_root()?, *fee.tcm()).to_bits_le())?;
            debug_assert_eq!(**fee.id(), expected_id, "Transition ID of the fee is incorrect");
        }

        // Determine if the fee is private.
        let is_fee_private = fee.is_fee_private();
        // Determine if the fee is public.
        let is_fee_public = fee.is_fee_public();
        // Ensure the fee has the correct program ID and function.
        ensure!(is_fee_private || is_fee_public, "Incorrect program ID or function name for fee transition");
        // Ensure the number of inputs is within the allowed range.
        ensure!(fee.inputs().len() <= N::MAX_INPUTS, "Fee exceeded maximum number of inputs");
        // Ensure the number of outputs is within the allowed range.
        ensure!(fee.outputs().len() <= N::MAX_INPUTS, "Fee exceeded maximum number of outputs");

        // Ensure the input and output types are equivalent to the ones defined in the function.
        // We only need to check that the variant type matches because we already check the hashes in
        // the `Input::verify` and `Output::verify` functions.
        ensure!(
            function.input_types().len() == fee.inputs().len(),
            "The number of fee inputs is incorrect: expected {}, found {}",
            function.input_types().len(),
            fee.inputs().len()
        );
        for (function_input, fee_input) in function.input_types().iter().zip_eq(fee.inputs().iter()) {
            ensure!(fee_input.is_type(function_input), "The fee input variants do not match");
        }
        ensure!(
            function.output_types().len() == fee.outputs().len(),
            "The number of fee outputs is incorrect: expected {}, found {}",
            function.output_types().len(),
            fee.outputs().len()
        );
        for (function_output, fee_output) in function.output_types().iter().zip_eq(fee.outputs().iter()) {
            ensure!(fee_output.is_type(function_output), "The fee output variants do not match");
        }

        // Retrieve the candidate deployment or execution ID.
        let Ok(candidate_id) = fee.deployment_or_execution_id() else {
            bail!("Failed to get the deployment or execution ID in the fee transition")
        };
        // Ensure the candidate ID is the deployment or execution ID.
        if candidate_id != deployment_or_execution_id {
            bail!("Incorrect deployment or execution ID in the fee transition")
        }
        lap!(timer, "Verify the deployment or execution ID");

        // Verify the fee transition is well-formed.
        match is_fee_private {
            true => self.verify_fee_private(consensus_version, varuna_version, inclusion_version, &fee)?,
            false => self.verify_fee_public(varuna_version, inclusion_version, &fee)?,
        }
        finish!(timer, "Verify the fee transition");
        Ok(())
    }
}

impl<N: Network> Process<N> {
    /// Verifies the transition for `credits.aleo/fee_private` is well-formed.
    fn verify_fee_private(
        &self,
        consensus_version: ConsensusVersion,
        varuna_version: VarunaVersion,
        inclusion_version: InclusionVersion,
        fee: &&Fee<N>,
    ) -> Result<()> {
        let timer = timer!("Process::verify_fee_private");

        // Retrieve the network ID.
        let network_id = U16::new(N::ID);
        // Compute the function ID.
        let function_id = compute_function_id(&network_id, fee.program_id(), fee.function_name())?;

        // Ensure the fee contains 1 input record.
        ensure!(
            fee.inputs().iter().filter(|input| matches!(input, Input::Record(..))).count() == 1,
            "The fee transition must contain *1* input record"
        );
        // Ensure the number of inputs is correct.
        let num_inputs = fee.inputs().len();
        ensure!(num_inputs == 4, "The number of inputs in the fee transition should be 4, found {num_inputs}",);
        // Ensure each input is valid.
        if fee.inputs().iter().enumerate().any(|(index, input)| !input.verify(function_id, fee.tcm(), index)) {
            bail!("Failed to verify a fee input")
        }
        lap!(timer, "Verify the inputs");

        // Ensure the number of outputs is correct.
        ensure!(
            fee.outputs().len() == 1,
            "The number of outputs in the fee transition should be 1, found {}",
            fee.outputs().len()
        );
        // Ensure each output is valid.
        for (index, output) in fee.outputs().iter().enumerate() {
            // If the consensus version are before `ConsensusVersion::V8`, ensure the output record is on Version 0.
            // if the consensus version is on or after `ConsensusVersion::V8`, ensure the output record is on Version 1.
            if let Some((_, record)) = output.record() {
                if (ConsensusVersion::V1..=ConsensusVersion::V7).contains(&consensus_version) {
                    #[cfg(not(any(test, feature = "test")))]
                    ensure!(record.version().is_zero(), "Output record must be Version 0 before Consensus V8");
                    #[cfg(any(test, feature = "test"))]
                    ensure!(
                        record.version().is_one(),
                        "Output record must be Version 1 before Consensus V8  in tests."
                    );
                } else {
                    ensure!(record.version().is_one(), "Output record must be Version 1 on or after Consensus V8");
                }
            }
            // Ensure the output is valid.
            if !output.verify(function_id, fee.tcm(), num_inputs + index) {
                bail!("Failed to verify a fee output")
            }
        }
        lap!(timer, "Verify the outputs");

        // Compute the x- and y-coordinate of `tpk`.
        let (tpk_x, tpk_y) = fee.tpk().to_xy_coordinates();

        // Retrieve the address belonging to the program ID.
        let stack = self.get_stack(fee.program_id())?;
        let program_address = stack.program_address();

        // Compute the x- and y-coordinate of `parent`.
        let (parent_x, parent_y) = program_address.to_xy_coordinates();

        // Construct the public inputs to verify the proof.
        let mut inputs = vec![N::Field::one(), *tpk_x, *tpk_y, **fee.tcm(), **fee.scm()];
        // Extend the inputs with the input IDs.
        inputs.extend(fee.inputs().iter().flat_map(|input| input.verifier_inputs()));
        // Extend the verifier inputs with the public inputs for 'self.caller'.
        inputs.extend([*Field::<N>::one(), *parent_x, *parent_y]);
        // Extend the inputs with the output IDs.
        inputs.extend(fee.outputs().iter().flat_map(|output| output.verifier_inputs()));
        lap!(timer, "Construct the verifier inputs");

        dev_println!("Fee public inputs ({} elements): {:#?}", inputs.len(), inputs);

        // Retrieve the verifying key.
        let verifying_key = stack.get_verifying_key(fee.function_name())?;

        // Ensure the fee proof is valid.
        Trace::verify_fee_proof(varuna_version, inclusion_version, (verifying_key, vec![inputs]), fee)?;
        finish!(timer, "Verify the fee proof");
        Ok(())
    }

    /// Verifies the transition for `credits.aleo/fee_public` is well-formed.
    /// Attention: This method does *not* verify the account balance is sufficient.
    fn verify_fee_public(
        &self,
        varuna_version: VarunaVersion,
        inclusion_version: InclusionVersion,
        fee: &&Fee<N>,
    ) -> Result<()> {
        let timer = timer!("Process::verify_fee_public");

        // Retrieve the network ID.
        let network_id = U16::new(N::ID);
        // Compute the function ID.
        let function_id = compute_function_id(&network_id, fee.program_id(), fee.function_name())?;

        // Ensure the fee contains all public inputs.
        ensure!(
            fee.inputs().iter().all(|input| matches!(input, Input::Public(..))),
            "The fee transition must contain *only* public inputs"
        );
        // Ensure the number of inputs is correct.
        let num_inputs = fee.inputs().len();
        ensure!(num_inputs == 3, "The number of inputs in the fee transition should be 3, found {num_inputs}",);
        // Ensure each input is valid.
        if fee.inputs().iter().enumerate().any(|(index, input)| !input.verify(function_id, fee.tcm(), index)) {
            bail!("Failed to verify a fee input")
        }
        lap!(timer, "Verify the inputs");

        // Ensure there is one output.
        ensure!(
            fee.outputs().len() == 1,
            "The number of outputs in the fee transition should be 1, found {}",
            fee.outputs().len()
        );
        // Ensure each output is valid.
        if fee
            .outputs()
            .iter()
            .enumerate()
            .any(|(index, output)| !output.verify(function_id, fee.tcm(), num_inputs + index))
        {
            bail!("Failed to verify a fee output")
        }
        lap!(timer, "Verify the outputs");

        // Compute the x- and y-coordinate of `tpk`.
        let (tpk_x, tpk_y) = fee.tpk().to_xy_coordinates();

        // Retrieve the address belonging to the program ID.
        let stack = self.get_stack(fee.program_id())?;
        let program_address = stack.program_address();

        // Compute the x- and y-coordinate of `parent`.
        let (parent_x, parent_y) = program_address.to_xy_coordinates();

        // Construct the public inputs to verify the proof.
        let mut inputs = vec![N::Field::one(), *tpk_x, *tpk_y, **fee.tcm(), **fee.scm()];
        // Extend the inputs with the input IDs.
        inputs.extend(fee.inputs().iter().flat_map(|input| input.verifier_inputs()));
        // Extend the verifier inputs with the public inputs for 'self.caller'
        inputs.extend([*Field::<N>::one(), *parent_x, *parent_y]);
        // Extend the inputs with the output IDs.
        inputs.extend(fee.outputs().iter().flat_map(|output| output.verifier_inputs()));
        lap!(timer, "Construct the verifier inputs");

        dev_println!("Fee public inputs ({} elements): {:#?}", inputs.len(), inputs);

        // Retrieve the verifying key.
        let verifying_key = stack.get_verifying_key(fee.function_name())?;

        // Ensure the fee proof is valid.
        Trace::verify_fee_proof(varuna_version, inclusion_version, (verifying_key, vec![inputs]), fee)?;
        finish!(timer, "Verify the fee proof");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::prelude::TestRng;
    use snarkvm_ledger_block::Transaction;

    #[test]
    fn test_verify_fee() {
        let rng = &mut TestRng::default();

        // Fetch transactions.
        let transactions = [
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, false, rng),
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 0),
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(false, rng, 0),
            snarkvm_ledger_test_helpers::sample_fee_private_transaction(rng),
            snarkvm_ledger_test_helpers::sample_fee_public_transaction(rng),
        ];

        // Construct a new process.
        let process = Process::load().unwrap();

        for transaction in transactions {
            match transaction {
                Transaction::Deploy(_, _, _, deployment, fee) => {
                    // Compute the deployment ID.
                    let deployment_id = deployment.to_deployment_id().unwrap();
                    // Verify the fee.
                    process
                        .verify_fee(ConsensusVersion::V8, VarunaVersion::V1, InclusionVersion::V0, &fee, deployment_id)
                        .unwrap();
                }
                Transaction::Execute(_, _, execution, fee) => {
                    // Compute the execution ID.
                    let execution_id = execution.to_execution_id().unwrap();
                    // Verify the fee.
                    process
                        .verify_fee(
                            ConsensusVersion::V8,
                            VarunaVersion::V1,
                            InclusionVersion::V0,
                            &fee.unwrap(),
                            execution_id,
                        )
                        .unwrap();
                }
                Transaction::Fee(_, fee) => match fee.is_fee_private() {
                    true => process
                        .verify_fee_private(ConsensusVersion::V8, VarunaVersion::V1, InclusionVersion::V0, &&fee)
                        .unwrap(),
                    false => process.verify_fee_public(VarunaVersion::V1, InclusionVersion::V0, &&fee).unwrap(),
                },
            }
        }
    }
}
