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

use std::collections::HashMap;

use crate::{Authorization, FinalizeTypes, Process, Stack, StackRef, StackTrait};

use circuit::Aleo;
use console::{
    prelude::*,
    program::{FinalizeType, Identifier, Literal, LiteralType, PlaintextType, ProgramID, Value},
    types::{Address, Field},
};
use indexmap::IndexMap;
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_ledger_block::{Deployment, Execution, Transaction};
use snarkvm_synthesizer_program::{CallDynamic, CastType, Command, GetRecordDynamic, Instruction, Operand};
use snarkvm_synthesizer_snark::proof_size;

pub type MinimumCost = u64;
pub type StorageCost = u64;
pub type SynthesisCost = u64;
pub type ConstructorCost = u64;
pub type NamespaceCost = u64;
pub type FinalizeCost = u64;
pub type DeployCostDetails = (StorageCost, SynthesisCost, ConstructorCost, NamespaceCost);
pub type ExecuteCostDetails = (StorageCost, FinalizeCost);

/// Returns the deployment cost in microcredits for a given deployment.
pub fn deployment_cost<N: Network>(
    process: &Process<N>,
    deployment: &Deployment<N>,
    consensus_version: ConsensusVersion,
) -> Result<(MinimumCost, DeployCostDetails)> {
    if consensus_version >= ConsensusVersion::V22 {
        deployment_cost_v5(process, deployment, consensus_version)
    } else if consensus_version >= ConsensusVersion::V18 {
        deployment_cost_v4(process, deployment)
    } else if consensus_version >= ConsensusVersion::V16 {
        deployment_cost_v3(process, deployment)
    } else if consensus_version >= ConsensusVersion::V10 {
        deployment_cost_v2(process, deployment)
    } else {
        deployment_cost_v1(process, deployment)
    }
}

/// Returns the execution cost in microcredits for a given execution.
pub fn execution_cost<N: Network>(
    process: &Process<N>,
    execution: &Execution<N>,
    consensus_version: ConsensusVersion,
) -> Result<(MinimumCost, ExecuteCostDetails)> {
    let execution_size = execution.size_in_bytes()?;

    execution_cost_given_size(process, execution, execution_size, consensus_version)
}

// Returns the execution cost in microcredits for a given execution whose size is provided as an argument.
fn execution_cost_given_size<N: Network>(
    process: &Process<N>,
    execution: &Execution<N>,
    execution_size: u64,
    consensus_version: ConsensusVersion,
) -> Result<(MinimumCost, ExecuteCostDetails)> {
    if consensus_version >= ConsensusVersion::V10 {
        execution_cost_v3(process, execution, execution_size, Some(consensus_version))
    } else if consensus_version >= ConsensusVersion::V2 {
        execution_cost_v2(process, execution, execution_size)
    } else {
        execution_cost_v1(process, execution, execution_size)
    }
}

/// Returns the execution cost in microcredits for a given `Authorization`.
pub fn execution_cost_for_authorization<N: Network>(
    process: &Process<N>,
    authorization: &Authorization<N>,
    consensus_version: ConsensusVersion,
) -> Result<(MinimumCost, ExecuteCostDetails)> {
    ensure!(
        consensus_version >= ConsensusVersion::V4,
        "Execution-cost computation for authorization relies on proof-size estimation, which is only implemented for Varuna version >= V2 (consensus version >= V4)"
    );

    // Reconstruct an Execution from the Authorization. Note that the StateRoot
    // does not affect the fee (it has constant size).
    let reconstructed_execution =
        Execution::from(authorization.transitions().values().cloned(), N::StateRoot::default(), None)?;

    // Compute the size of the proof that will result from proving the
    // Authorization. The first step is to compute the Varuna batch sizes. The
    // Varuna circuits that must be proved as part of an Execution are:
    // - the circuit instances of each Transition
    // - one inclusion circuit instance per input record to all of those Transitions
    // - one translation circuit instance per record-translation task derived from those Transitions
    // For each of the types above, if several instances correspond to the same circuit, they are
    // grouped into a single Varuna batch.

    let mut circuit_frequencies = HashMap::new();

    // In order to compute the frequencies of function circuits, we mimic the
    // operation of Process::verify_execution:
    for transition in authorization.transitions().values() {
        let entry =
            circuit_frequencies.entry((*transition.program_id(), *transition.function_name())).or_insert(0usize);
        *entry += 1;
    }

    let mut batch_sizes: Vec<usize> = circuit_frequencies.values().cloned().collect();

    // Add the single batch of inclusion circuits for input records, if
    // any:
    let n_input_records = Authorization::number_of_input_records(authorization.transitions().values());
    if n_input_records > 0 {
        batch_sizes.push(n_input_records);
    }

    // Build the execution stacks once and reuse for translation batch sizing.
    let mut execution_stacks = IndexMap::new();
    for transition in authorization.transitions().values() {
        execution_stacks.insert(*transition.program_id(), process.get_stack(transition.program_id())?);
    }

    // Add the batches corresponding to translation tasks
    let translations_for_transaction =
        Authorization::translation_batch_sizes(authorization.transitions().values(), &execution_stacks)?;
    batch_sizes.extend(translations_for_transaction);

    // Varuna is always run in hiding (i. e. ZK) mode when proving Executions.
    let hiding_mode = true;

    // Varuna V2 and V3 use the same serialized proof layout.
    let varuna_version = VarunaVersion::V2;

    let expected_proof_size = u64::try_from(proof_size::<N>(&batch_sizes, varuna_version, hiding_mode)?)?;
    let unproved_execution_size = reconstructed_execution.size_in_bytes()?;
    let execution_size = unproved_execution_size.checked_add(expected_proof_size).ok_or(anyhow!(
        "The execution size computation overflowed for an authorization when the proof was taken into account"
    ))?;

    execution_cost_given_size(process, &reconstructed_execution, execution_size, consensus_version)
}

/// Returns the execution cost in microcredits for a call to the given function with the given inputs.
pub fn execution_cost_for_call<A: Aleo, R: Rng + CryptoRng>(
    process: &Process<A::Network>,
    address: Address<A::Network>,
    program_id: ProgramID<A::Network>,
    function_name: Identifier<A::Network>,
    inputs: impl ExactSizeIterator<Item = impl TryInto<Value<A::Network>>>,
    consensus_version: ConsensusVersion,
    rng: &mut R,
) -> Result<(MinimumCost, ExecuteCostDetails)> {
    let stack = process.get_stack(program_id)?;

    // Follow the evaluation flow for the given call, using correct input/output values and calls and mocking
    // only the fields which cannot be computed (essentially: values depending on the private key, such as
    // the signature)
    let authorization = stack.sample_authorization::<A, R>(address, program_id, function_name, inputs, rng)?;

    execution_cost_for_authorization(process, &authorization, consensus_version)
}

/// Returns the compute cost for a deployment in microcredits.
/// This is used to limit the amount of single-threaded compute in the block generation hot
/// path. This does NOT represent the full costs which a user has to pay.
pub fn deploy_compute_cost_in_microcredits(
    cost_details: DeployCostDetails,
    consensus_version: ConsensusVersion,
) -> u64 {
    let (storage_cost, synthesis_cost, constructor_cost, _) = cost_details;
    if consensus_version >= ConsensusVersion::V10 {
        // From V10, only include the constructor compute cost for
        // deployments.
        //
        // The limits of individual function's finalize compute costs are
        // checked in calls to `deployment_cost`.
        constructor_cost
    } else {
        // Include the storage, synthesis, and constructor cost for deployments.
        storage_cost.saturating_add(synthesis_cost).saturating_add(constructor_cost)
    }
}

/// Returns the compute cost for an execution in microcredits.
/// This is used to limit the amount of single-threaded compute in the block generation hot
/// path. This does NOT represent the full costs which a user has to pay.
pub fn execute_compute_cost_in_microcredits(
    cost_details: ExecuteCostDetails,
    consensus_version: ConsensusVersion,
) -> u64 {
    let (storage_cost, finalize_cost) = cost_details;
    if consensus_version >= ConsensusVersion::V10 {
        // From V10, only include the finalize compute cost for executions.
        finalize_cost
    } else {
        // Include the finalize cost and storage cost for executions.
        storage_cost.saturating_add(finalize_cost)
    }
}

/// Returns the compute spend for a transaction in microcredits.
/// This is used to limit the amount of single-threaded compute in block generation and finalization hot paths.
/// This does NOT represent the full cost which a user has to pay.
pub fn transaction_compute_spend_in_microcredits<N: Network>(
    process: &Process<N>,
    transaction: &Transaction<N>,
    consensus_version: ConsensusVersion,
) -> Result<u64> {
    match transaction {
        Transaction::Deploy(_, _, _, deployment, _) => {
            let (_, cost_details) = deployment_cost(process, deployment, consensus_version)?;
            Ok(deploy_compute_cost_in_microcredits(cost_details, consensus_version))
        }
        Transaction::Execute(_, _, execution, _) => {
            let (_, cost_details) = execution_cost(process, execution, consensus_version)?;
            Ok(execute_compute_cost_in_microcredits(cost_details, consensus_version))
        }
        Transaction::Fee(id, _) => bail!("Fee transaction '{id}' does not have deployment or execution spend"),
    }
}

/// Returns the minimum cost in microcredits to publish the given deployment (V5).
///
/// Identical to V3 except in the cost of the rand.chacha command.
//
// The only difference between deployment_cost_v3 and deployment_cost_v4 is the use of num_variables
// + num_constraints in the former and density in the latter. deployment_cost_v5 returns to the
// behaviour of the deployment_cost_v3 in this regard, in line with the return to
// variable/constraint-based deployment (and not density-based) deployment limits at consensus
// version V19.
pub fn deployment_cost_v5<N: Network>(
    process: &Process<N>,
    deployment: &Deployment<N>,
    consensus_version: ConsensusVersion,
) -> Result<(MinimumCost, DeployCostDetails)> {
    inner_deployment_cost_v3_v5(process, deployment, Some(consensus_version))
}

/// Returns the minimum cost in microcredits to publish the given deployment (V4).
///
/// Identical to V3 except in that it replaces the factor (`num_combined_variables` + `num_combined_constraints`)
/// of the synthesis cost by the deployment's combined density.
pub fn deployment_cost_v4<N: Network>(
    process: &Process<N>,
    deployment: &Deployment<N>,
) -> Result<(MinimumCost, DeployCostDetails)> {
    // Determine the number of bytes in the deployment.
    let size_in_bytes = deployment.size_in_bytes()?;
    // Retrieve the program ID.
    let program_id = deployment.program_id();
    // Determine the number of characters in the program ID.
    let num_characters = u32::try_from(program_id.name().to_string().len())?;
    // Compute the combined density of the deployment.
    let combined_density = deployment.combined_density();

    // Compute the storage cost in microcredits, with a quadratic penalty above 512 kB.
    let storage_cost = deployment_storage_cost::<N>(size_in_bytes)?;

    // Compute the synthesis cost in microcredits based on the combined density of the program.
    let synthesis_cost = combined_density.saturating_mul(N::SYNTHESIS_FEE_MULTIPLIER) / N::ARC_0005_COMPUTE_DISCOUNT;

    // Compute a Stack for the deployment.
    let stack = Stack::new(process, deployment.program())?;

    // Compute the constructor cost in microcredits.
    let constructor_cost = constructor_cost_in_microcredits_v2(&stack, None)?;

    // Check that the functions are valid.
    for function in deployment.program().functions().values() {
        // Get the finalize cost.
        let finalize_cost = minimum_cost_in_microcredits_v3(&stack, function.name(), None)?;
        // Check that the finalize cost does not exceed the maximum.
        ensure!(
            finalize_cost <= N::TRANSACTION_SPEND_LIMIT[1].1,
            "Finalize block '{}' has a cost '{finalize_cost}' which exceeds the transaction spend limit '{}'",
            function.name(),
            N::TRANSACTION_SPEND_LIMIT[1].1
        );
    }

    // Bound each view function's worst-case compute.
    for view in deployment.program().views().values() {
        let view_cost = view_cost_for_single_view(&stack, view.name(), ConsensusFeeVersion::V3, None)?;
        ensure!(
            view_cost <= N::TRANSACTION_SPEND_LIMIT[1].1,
            "View '{}' has a cost '{view_cost}' which exceeds the transaction spend limit '{}'",
            view.name(),
            N::TRANSACTION_SPEND_LIMIT[1].1
        );
    }

    // Compute the namespace cost in microcredits: 10^(10 - num_characters) * 1e6
    let namespace_cost = 10u64
        .checked_pow(10u32.saturating_sub(num_characters))
        .ok_or(anyhow!("The namespace cost computation overflowed for a deployment"))?
        .saturating_mul(1_000_000); // 1 microcredit = 1e-6 credits.

    // Compute the minimum cost in microcredits.
    let minimum_cost = storage_cost
        .checked_add(synthesis_cost)
        .and_then(|x| x.checked_add(constructor_cost))
        .and_then(|x| x.checked_add(namespace_cost))
        .ok_or(anyhow!("The total cost computation overflowed for a deployment"))?;

    Ok((minimum_cost, (storage_cost, synthesis_cost, constructor_cost, namespace_cost)))
}

// Common computation for deployment costs V3 and V5. Their only difference is that the V5 version
// needs the consensus version in order to pass it downstream until the inner cost_per_command. In
// V3 (and earlier), callees do not need it and `None` is passed throughout the entire call chain.
fn inner_deployment_cost_v3_v5<N: Network>(
    process: &Process<N>,
    deployment: &Deployment<N>,
    consensus_version: Option<ConsensusVersion>,
) -> Result<(MinimumCost, DeployCostDetails)> {
    // Determine the number of bytes in the deployment.
    let size_in_bytes = deployment.size_in_bytes()?;
    // Retrieve the program ID.
    let program_id = deployment.program_id();
    // Determine the number of characters in the program ID.
    let num_characters = u32::try_from(program_id.name().to_string().len())?;
    // Compute the number of combined variables in the program.
    let num_combined_variables = deployment.num_combined_variables()?;
    // Compute the number of combined constraints in the program.
    let num_combined_constraints = deployment.num_combined_constraints()?;

    // Compute the storage cost in microcredits, with a quadratic penalty above 512 kB.
    let storage_cost = deployment_storage_cost::<N>(size_in_bytes)?;

    // Compute the synthesis cost in microcredits.
    let synthesis_cost = num_combined_variables.saturating_add(num_combined_constraints) * N::SYNTHESIS_FEE_MULTIPLIER
        / N::ARC_0005_COMPUTE_DISCOUNT;

    // Compute a Stack for the deployment.
    let stack = Stack::new(process, deployment.program())?;

    // Compute the constructor cost in microcredits.
    let constructor_cost = constructor_cost_in_microcredits_v2(&stack, consensus_version)?;

    // Check that the functions are valid.
    for function in deployment.program().functions().values() {
        // Get the finalize cost.
        let finalize_cost = minimum_cost_in_microcredits_v3(&stack, function.name(), consensus_version)?;
        // Check that the finalize cost does not exceed the maximum.
        ensure!(
            finalize_cost <= N::TRANSACTION_SPEND_LIMIT[1].1,
            "Finalize block '{}' has a cost '{finalize_cost}' which exceeds the transaction spend limit '{}'",
            function.name(),
            N::TRANSACTION_SPEND_LIMIT[1].1
        );
    }

    // Bound each view function's worst-case compute.
    for view in deployment.program().views().values() {
        let view_cost = view_cost_for_single_view(&stack, view.name(), ConsensusFeeVersion::V3, consensus_version)?;
        ensure!(
            view_cost <= N::TRANSACTION_SPEND_LIMIT[1].1,
            "View '{}' has a cost '{view_cost}' which exceeds the transaction spend limit '{}'",
            view.name(),
            N::TRANSACTION_SPEND_LIMIT[1].1
        );
    }

    // Compute the namespace cost in microcredits: 10^(10 - num_characters) * 1e6
    let namespace_cost = 10u64
        .checked_pow(10u32.saturating_sub(num_characters))
        .ok_or(anyhow!("The namespace cost computation overflowed for a deployment"))?
        .saturating_mul(1_000_000); // 1 microcredit = 1e-6 credits.

    // Compute the minimum cost in microcredits.
    let minimum_cost = storage_cost
        .checked_add(synthesis_cost)
        .and_then(|x| x.checked_add(constructor_cost))
        .and_then(|x| x.checked_add(namespace_cost))
        .ok_or(anyhow!("The total cost computation overflowed for a deployment"))?;

    Ok((minimum_cost, (storage_cost, synthesis_cost, constructor_cost, namespace_cost)))
}

/// Returns the minimum cost in microcredits to publish the given deployment (V3).
///
/// Identical to V2 except that the storage cost scales quadratically for programs larger
/// than 512 kB (the V14 limit). Programs at or below that threshold are priced identically
/// to V2, so this function is only routed to at consensus V16+.
pub fn deployment_cost_v3<N: Network>(
    process: &Process<N>,
    deployment: &Deployment<N>,
) -> Result<(MinimumCost, DeployCostDetails)> {
    inner_deployment_cost_v3_v5(process, deployment, None)
}

/// Returns the *minimum* cost in microcredits to publish the given deployment using the ARC_0005_COMPUTE_DISCOUNT.
pub fn deployment_cost_v2<N: Network>(
    process: &Process<N>,
    deployment: &Deployment<N>,
) -> Result<(MinimumCost, DeployCostDetails)> {
    // Determine the number of bytes in the deployment.
    let size_in_bytes = deployment.size_in_bytes()?;
    // Retrieve the program ID.
    let program_id = deployment.program_id();
    // Determine the number of characters in the program ID.
    let num_characters = u32::try_from(program_id.name().to_string().len())?;
    // Compute the number of combined variables in the program.
    let num_combined_variables = deployment.num_combined_variables()?;
    // Compute the number of combined constraints in the program.
    let num_combined_constraints = deployment.num_combined_constraints()?;

    // Compute the storage cost in microcredits.
    let storage_cost = size_in_bytes
        .checked_mul(N::DEPLOYMENT_FEE_MULTIPLIER)
        .ok_or(anyhow!("The storage cost computation overflowed for a deployment"))?;

    // Compute the synthesis cost in microcredits.
    let synthesis_cost = num_combined_variables.saturating_add(num_combined_constraints) * N::SYNTHESIS_FEE_MULTIPLIER
        / N::ARC_0005_COMPUTE_DISCOUNT;

    // Compute a Stack for the deployment.
    let stack = Stack::new(process, deployment.program())?;

    // Compute the constructor cost in microcredits.
    let constructor_cost = constructor_cost_in_microcredits_v2(&stack, None)?;

    // Check that the functions are valid.
    for function in deployment.program().functions().values() {
        // Get the finalize cost.
        let finalize_cost = minimum_cost_in_microcredits_v3(&stack, function.name(), None)?;
        // Check that the finalize cost does not exceed the maximum.
        ensure!(
            finalize_cost <= N::TRANSACTION_SPEND_LIMIT[1].1,
            "Finalize block '{}' has a cost '{finalize_cost}' which exceeds the transaction spend limit '{}'",
            function.name(),
            N::TRANSACTION_SPEND_LIMIT[1].1
        );
    }

    // Bound each view function's worst-case compute. Views are off-consensus and have no
    // dedicated fee component beyond what is already counted in `storage_cost` (their bytes
    // contribute to `size_in_bytes`). The bound below is purely a deploy-time sanity check
    // to keep pathological views from being accepted.
    for view in deployment.program().views().values() {
        let view_cost = view_cost_for_single_view(&stack, view.name(), ConsensusFeeVersion::V3, None)?;
        ensure!(
            view_cost <= N::TRANSACTION_SPEND_LIMIT[1].1,
            "View '{}' has a cost '{view_cost}' which exceeds the transaction spend limit '{}'",
            view.name(),
            N::TRANSACTION_SPEND_LIMIT[1].1
        );
    }

    // Compute the namespace cost in microcredits: 10^(10 - num_characters) * 1e6
    let namespace_cost = 10u64
        .checked_pow(10u32.saturating_sub(num_characters))
        .ok_or(anyhow!("The namespace cost computation overflowed for a deployment"))?
        .saturating_mul(1_000_000); // 1 microcredit = 1e-6 credits.

    // Compute the minimum cost in microcredits.
    let minimum_cost = storage_cost
        .checked_add(synthesis_cost)
        .and_then(|x| x.checked_add(constructor_cost))
        .and_then(|x| x.checked_add(namespace_cost))
        .ok_or(anyhow!("The total cost computation overflowed for a deployment"))?;

    Ok((minimum_cost, (storage_cost, synthesis_cost, constructor_cost, namespace_cost)))
}

/// Returns the *minimum* cost in microcredits to publish the given deployment.
pub fn deployment_cost_v1<N: Network>(
    process: &Process<N>,
    deployment: &Deployment<N>,
) -> Result<(MinimumCost, DeployCostDetails)> {
    // Determine the number of bytes in the deployment.
    let size_in_bytes = deployment.size_in_bytes()?;
    // Retrieve the program ID.
    let program_id = deployment.program_id();
    // Determine the number of characters in the program ID.
    let num_characters = u32::try_from(program_id.name().to_string().len())?;
    // Compute the number of combined variables in the program.
    let num_combined_variables = deployment.num_combined_variables()?;
    // Compute the number of combined constraints in the program.
    let num_combined_constraints = deployment.num_combined_constraints()?;

    // Compute the storage cost in microcredits.
    let storage_cost = size_in_bytes
        .checked_mul(N::DEPLOYMENT_FEE_MULTIPLIER)
        .ok_or(anyhow!("The storage cost computation overflowed for a deployment"))?;

    // Compute the synthesis cost in microcredits.
    let synthesis_cost = num_combined_variables.saturating_add(num_combined_constraints) * N::SYNTHESIS_FEE_MULTIPLIER;

    // Compute a Stack for the deployment.
    let stack = Stack::new(process, deployment.program())?;

    // Compute the constructor cost in microcredits.
    let constructor_cost = constructor_cost_in_microcredits_v1(&stack)?;

    // Check that the functions are valid.
    for function in deployment.program().functions().values() {
        // Get the finalize cost.
        let finalize_cost = minimum_cost_in_microcredits_v2(&stack, function.name())?;
        // Check that the finalize cost does not exceed the maximum.
        ensure!(
            finalize_cost <= N::TRANSACTION_SPEND_LIMIT[0].1,
            "Finalize block '{}' has a cost '{finalize_cost}' which exceeds the transaction spend limit '{}'",
            function.name(),
            N::TRANSACTION_SPEND_LIMIT[0].1
        );
    }

    // Compute the namespace cost in microcredits: 10^(10 - num_characters) * 1e6
    let namespace_cost = 10u64
        .checked_pow(10u32.saturating_sub(num_characters))
        .ok_or(anyhow!("The namespace cost computation overflowed for a deployment"))?
        .saturating_mul(1_000_000); // 1 microcredit = 1e-6 credits.

    // Compute the minimum cost in microcredits.
    let minimum_cost = storage_cost
        .checked_add(synthesis_cost)
        .and_then(|x| x.checked_add(constructor_cost))
        .and_then(|x| x.checked_add(namespace_cost))
        .ok_or(anyhow!("The total cost computation overflowed for a deployment"))?;

    Ok((minimum_cost, (storage_cost, synthesis_cost, constructor_cost, namespace_cost)))
}

/// Returns the cost in microcredits to publish the given execution using the ARC_0005_COMPUTE_DISCOUNT.
/// For executions with dynamic futures, this computes the exact cost by iterating over concrete transitions.
fn execution_cost_v3<N: Network>(
    process: &Process<N>,
    execution: &Execution<N>,
    execution_size: u64,
    consensus_version: Option<ConsensusVersion>,
) -> Result<(MinimumCost, ExecuteCostDetails)> {
    // Compute the storage cost in microcredits.
    let storage_cost = execution_storage_cost::<N>(execution_size);

    // Compute the finalize cost by iterating over all concrete transitions.
    // This handles dynamic futures correctly because we know the actual functions called.
    let finalize_cost = execution_finalize_cost(process, execution, ConsensusFeeVersion::V3, consensus_version)?;

    // Compute the total cost in microcredits.
    let total_cost = storage_cost
        .checked_add(finalize_cost)
        .ok_or(anyhow!("The total cost computation overflowed for an execution"))?;

    Ok((total_cost, (storage_cost, finalize_cost)))
}

/// Returns the cost in microcredits to publish the given execution.
/// For executions with dynamic futures, this computes the exact cost by iterating over concrete transitions.
fn execution_cost_v2<N: Network>(
    process: &Process<N>,
    execution: &Execution<N>,
    execution_size: u64,
) -> Result<(MinimumCost, ExecuteCostDetails)> {
    // Compute the storage cost in microcredits.
    let storage_cost = execution_storage_cost::<N>(execution_size);

    // Compute the finalize cost by iterating over all concrete transitions.
    // This handles dynamic futures correctly because we know the actual functions called.
    let finalize_cost = execution_finalize_cost(process, execution, ConsensusFeeVersion::V2, None)?;

    // Compute the total cost in microcredits.
    let total_cost = storage_cost
        .checked_add(finalize_cost)
        .ok_or(anyhow!("The total cost computation overflowed for an execution"))?;

    Ok((total_cost, (storage_cost, finalize_cost)))
}

/// Returns the cost in microcredits to publish the given execution.
/// For executions with dynamic futures, this computes the exact cost by iterating over concrete transitions.
fn execution_cost_v1<N: Network>(
    process: &Process<N>,
    execution: &Execution<N>,
    execution_size: u64,
) -> Result<(MinimumCost, ExecuteCostDetails)> {
    // Compute the storage cost in microcredits.
    let storage_cost = execution_storage_cost::<N>(execution_size);

    // Compute the finalize cost by iterating over all concrete transitions.
    // This handles dynamic futures correctly because we know the actual functions called.
    let finalize_cost = execution_finalize_cost(process, execution, ConsensusFeeVersion::V1, None)?;

    // Compute the total cost in microcredits.
    let total_cost = storage_cost
        .checked_add(finalize_cost)
        .ok_or(anyhow!("The total cost computation overflowed for an execution"))?;

    Ok((total_cost, (storage_cost, finalize_cost)))
}

/// Returns the storage cost in microcredits for a program execution.
fn execution_storage_cost<N: Network>(size_in_bytes: u64) -> u64 {
    if size_in_bytes > N::EXECUTION_STORAGE_PENALTY_THRESHOLD {
        size_in_bytes.saturating_mul(size_in_bytes).saturating_div(N::EXECUTION_STORAGE_FEE_SCALING_FACTOR)
    } else {
        size_in_bytes
    }
}

/// The size threshold in bytes above which deployment storage costs scale quadratically.
/// Corresponds to the V14 maximum program size (512 kB).
const DEPLOYMENT_STORAGE_PENALTY_THRESHOLD: u64 = 512_000;

/// Returns the storage cost in microcredits for a program deployment.
///
/// Below 512 kB the cost is linear: `size * DEPLOYMENT_FEE_MULTIPLIER`.
/// Above 512 kB the cost scales quadratically, calibrated to be continuous at the threshold:
/// `size^2 * DEPLOYMENT_FEE_MULTIPLIER / DEPLOYMENT_STORAGE_PENALTY_THRESHOLD`.
fn deployment_storage_cost<N: Network>(size_in_bytes: u64) -> Result<u64> {
    if size_in_bytes <= DEPLOYMENT_STORAGE_PENALTY_THRESHOLD {
        size_in_bytes
            .checked_mul(N::DEPLOYMENT_FEE_MULTIPLIER)
            .ok_or_else(|| anyhow!("The storage cost computation overflowed for a deployment"))
    } else {
        size_in_bytes
            .checked_mul(size_in_bytes)
            .and_then(|x| x.checked_mul(N::DEPLOYMENT_FEE_MULTIPLIER))
            .and_then(|x| x.checked_div(DEPLOYMENT_STORAGE_PENALTY_THRESHOLD))
            .ok_or_else(|| anyhow!("The storage cost computation overflowed for a deployment"))
    }
}

// Finalize costs for compute heavy operations, derived as:
// `BASE_COST + (PER_BYTE_COST * SIZE_IN_BYTES)`.

const CAST_BASE_COST: u64 = 500;
const CAST_PER_BYTE_COST: u64 = 30;

const HASH_BASE_COST: u64 = 10_000;
const HASH_PER_BYTE_COST: u64 = 30;

const HASH_BHP_BASE_COST: u64 = 50_000;
const HASH_BHP_PER_BYTE_COST: u64 = 300;

const HASH_PSD_BASE_COST: u64 = 40_000;
const HASH_PSD_PER_BYTE_COST: u64 = 75;

const ECDSA_VERIFY_BASE_COST: u64 = 60_000;
const ECDSA_VERIFY_ETH_BASE_COST: u64 = 75_000;

const SNARK_VERIFY_BASE_COST: u64 = 100_000;
const SNARK_VERIFY_PER_BYTE_COST: u64 = 50;

#[derive(Copy, Clone)]
pub enum ConsensusFeeVersion {
    V1,
    V2,
    V3,
}

const MAPPING_BASE_COST_V1: u64 = 10_000;
const MAPPING_BASE_COST_V2: u64 = 1_500;
const MAPPING_PER_BYTE_COST: u64 = 10;

const SET_BASE_COST: u64 = 10_000;
const SET_PER_BYTE_COST: u64 = 100;

/// A helper function to determine the plaintext type in bytes.
fn plaintext_size_in_bytes<N: Network>(stack: &Stack<N>, plaintext_type: &PlaintextType<N>) -> Result<u64> {
    match plaintext_type {
        PlaintextType::Literal(literal_type) => Ok(literal_type.size_in_bytes::<N>() as u64),
        PlaintextType::Struct(struct_name) => {
            // Retrieve the struct from the stack.
            let struct_ = stack.program().get_struct(struct_name)?;
            // Retrieve the size of the struct name.
            let size_of_name = struct_.name().to_bytes_le()?.len() as u64;
            // Retrieve the size of all the members of the struct.
            let size_of_members = struct_.members().iter().try_fold(0u64, |acc, (_, member_type)| {
                acc.checked_add(plaintext_size_in_bytes(stack, member_type)?).ok_or_else(|| {
                    anyhow!(
                        "Overflowed while computing the size of the struct '{}/{struct_name}' - {member_type}",
                        stack.program_id()
                    )
                })
            })?;
            // Return the size of the struct.
            Ok(size_of_name.saturating_add(size_of_members))
        }
        PlaintextType::ExternalStruct(locator) => {
            let external_stack = stack.get_external_stack(locator.program_id())?;
            plaintext_size_in_bytes(&*external_stack, &PlaintextType::Struct(*locator.resource()))
        }
        PlaintextType::Array(array_type) => {
            // Retrieve the number of elements in the array.
            let num_elements = **array_type.length() as u64;
            // Compute the size of an array element.
            let size_of_element = plaintext_size_in_bytes(stack, array_type.next_element_type())?;
            // Return the size of the array.
            Ok(num_elements.saturating_mul(size_of_element))
        }
    }
}

/// A helper function to compute the following: base_cost + (byte_multiplier * size_of_operands).
fn cost_in_size<'a, N: Network>(
    stack: &Stack<N>,
    finalize_types: &FinalizeTypes<N>,
    operands: impl IntoIterator<Item = &'a Operand<N>>,
    byte_multiplier: u64,
    base_cost: u64,
) -> Result<u64> {
    // Compute the size of the operands.
    let size_of_operands = operands.into_iter().try_fold(0u64, |acc, operand| {
        // Determine the size of the operand.
        let operand_size = match finalize_types.get_type_from_operand(stack, operand)? {
            FinalizeType::Plaintext(plaintext_type) => plaintext_size_in_bytes(stack, &plaintext_type)?,
            FinalizeType::Future(future) => {
                bail!("Future '{future}' is not a valid operand");
            }
            FinalizeType::DynamicFuture => {
                bail!("Dynamic future is not a valid operand");
            }
        };
        // Safely add the size to the accumulator.
        acc.checked_add(operand_size).ok_or_else(|| {
            anyhow!("Overflowed while computing the size of the operand '{operand}' in '{}'", stack.program_id(),)
        })
    })?;
    // Return the cost.
    Ok(base_cost.saturating_add(byte_multiplier.saturating_mul(size_of_operands)))
}

/// Returns the the cost of a command in a finalize scope.
pub fn cost_per_command<N: Network>(
    stack: &Stack<N>,
    finalize_types: &FinalizeTypes<N>,
    command: &Command<N>,
    consensus_fee_version: ConsensusFeeVersion,
    consensus_version: Option<ConsensusVersion>,
) -> Result<u64> {
    let mapping_base_cost = match consensus_fee_version {
        ConsensusFeeVersion::V1 => MAPPING_BASE_COST_V1,
        ConsensusFeeVersion::V2 | ConsensusFeeVersion::V3 => MAPPING_BASE_COST_V2,
    };

    match command {
        Command::Instruction(Instruction::Abs(_)) => Ok(500),
        Command::Instruction(Instruction::AbsWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::Add(_)) => Ok(500),
        Command::Instruction(Instruction::AddWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::And(_)) => Ok(500),
        Command::Instruction(Instruction::AssertEq(_)) => Ok(500),
        Command::Instruction(Instruction::AssertNeq(_)) => Ok(500),
        Command::Instruction(Instruction::Async(_)) => bail!("'async' is not supported in finalize"),
        Command::Instruction(Instruction::Call(call)) => {
            // From a finalize body, `call` is permitted only when the target resolves to a
            // view function (validated at `Stack::new`). Roll up the called view's worst-case
            // body cost into the caller's finalize cost, mirroring how function-to-function
            // call costs already aggregate. Same-program targets reuse the current stack;
            // cross-program targets resolve through the external stack.
            //
            // Recursion bound: `view_cost_for_single_view` re-enters `cost_per_command` on the
            // view's body, but views reject `is_call()` at construction (`ViewCore::add_command`)
            // and again at deploy via `FinalizeTypes::from_view`. So this recursion is at most
            // one level deep — a Call in a finalize body, never a Call inside a view body.
            use snarkvm_synthesizer_program::CallOperator;
            match call.operator() {
                CallOperator::Locator(locator) => {
                    let external_stack = stack.get_external_stack(locator.program_id())?;
                    view_cost_for_single_view(
                        &*external_stack,
                        locator.resource(),
                        consensus_fee_version,
                        consensus_version,
                    )
                }
                CallOperator::Resource(name) => {
                    view_cost_for_single_view(stack, name, consensus_fee_version, consensus_version)
                }
            }
        }
        Command::Instruction(Instruction::CallDynamic(_)) => {
            bail!("'{}' is not supported in finalize", CallDynamic::<N>::opcode())
        }
        Command::Instruction(Instruction::Cast(cast)) => match cast.cast_type() {
            CastType::Plaintext(PlaintextType::Literal(_)) => Ok(500),
            CastType::Plaintext(plaintext_type) => Ok(plaintext_size_in_bytes(stack, plaintext_type)?
                .saturating_mul(CAST_PER_BYTE_COST)
                .saturating_add(CAST_BASE_COST)),
            CastType::GroupXCoordinate | CastType::GroupYCoordinate => Ok(500),
            CastType::Record(_) => bail!("'cast' to a record is not supported in finalize"),
            CastType::ExternalRecord(_) => bail!("'cast' to an external record is not supported in finalize"),
            CastType::DynamicRecord => bail!("'cast' to a dynamic record is not supported in finalize"),
        },
        Command::Instruction(Instruction::CastLossy(cast_lossy)) => match cast_lossy.cast_type() {
            CastType::Plaintext(PlaintextType::Literal(_)) => Ok(500),
            CastType::Plaintext(plaintext_type) => Ok(plaintext_size_in_bytes(stack, plaintext_type)?
                .saturating_mul(CAST_PER_BYTE_COST)
                .saturating_add(CAST_BASE_COST)),
            CastType::GroupXCoordinate | CastType::GroupYCoordinate => Ok(500),
            CastType::Record(_) => bail!("'cast.lossy' to a record is not supported in finalize"),
            CastType::ExternalRecord(_) => bail!("'cast.lossy' to an external record is not supported in finalize"),
            CastType::DynamicRecord => bail!("'cast.lossy' to a dynamic record is not supported in finalize"),
        },
        Command::Instruction(Instruction::CommitBHP256(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitBHP512(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitBHP768(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitBHP1024(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitPED64(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::CommitPED128(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::CommitBHP256Raw(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitBHP512Raw(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitBHP768Raw(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitBHP1024Raw(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::CommitPED64Raw(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::CommitPED128Raw(commit)) => {
            cost_in_size(stack, finalize_types, commit.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::DeserializeBits(deserialize)) => {
            Ok(plaintext_size_in_bytes(stack, &PlaintextType::Array(deserialize.operand_type().clone()))?
                .saturating_mul(CAST_PER_BYTE_COST)
                .saturating_add(CAST_BASE_COST))
        }
        Command::Instruction(Instruction::DeserializeBitsRaw(deserialize)) => {
            Ok(plaintext_size_in_bytes(stack, &PlaintextType::Array(deserialize.operand_type().clone()))?
                .saturating_mul(CAST_PER_BYTE_COST)
                .saturating_add(CAST_BASE_COST))
        }
        Command::Instruction(Instruction::Div(div)) => {
            // Ensure `div` has exactly two operands.
            ensure!(div.operands().len() == 2, "'div' must contain exactly 2 operands");
            // Retrieve the price by the operand type.
            match finalize_types.get_type_from_operand(stack, &div.operands()[0])? {
                FinalizeType::Plaintext(PlaintextType::Literal(LiteralType::Field)) => Ok(1_500),
                FinalizeType::Plaintext(PlaintextType::Literal(_)) => Ok(500),
                FinalizeType::Plaintext(PlaintextType::Array(_)) => bail!("'div' does not support arrays"),
                FinalizeType::Plaintext(PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_)) => {
                    bail!("'div' does not support structs")
                }
                FinalizeType::Future(_) => bail!("'div' does not support futures"),
                FinalizeType::DynamicFuture => bail!("'div' does not support dynamic futures"),
            }
        }
        Command::Instruction(Instruction::DivWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::Double(_)) => Ok(500),
        Command::Instruction(Instruction::ECDSAVerifyDigest(_)) => Ok(ECDSA_VERIFY_BASE_COST),
        Command::Instruction(Instruction::ECDSAVerifyDigestEth(_)) => Ok(ECDSA_VERIFY_ETH_BASE_COST),
        Command::Instruction(Instruction::ECDSAVerifyKeccak256(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak256Raw(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak256Eth(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_ETH_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak384(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak384Raw(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak384Eth(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_ETH_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak512(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak512Raw(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifyKeccak512Eth(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_ETH_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_256(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_256Raw(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_256Eth(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_ETH_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_384(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_384Raw(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_384Eth(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_ETH_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_512(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_512Raw(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::ECDSAVerifySha3_512Eth(ecdsa)) => {
            cost_in_size(stack, finalize_types, ecdsa.operands(), HASH_PER_BYTE_COST, ECDSA_VERIFY_ETH_BASE_COST)
        }
        Command::Instruction(Instruction::GetRecordDynamic(_)) => {
            bail!("'{}' is not supported in finalize", GetRecordDynamic::<N>::opcode())
        }
        Command::Instruction(Instruction::GreaterThan(_)) => Ok(500),
        Command::Instruction(Instruction::GreaterThanOrEqual(_)) => Ok(500),
        Command::Instruction(Instruction::HashBHP256(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashBHP256Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashBHP512(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashBHP512Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashBHP768(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashBHP768Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashBHP1024(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashBHP1024Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak256(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak256Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak256Native(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak256NativeRaw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak384(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak384Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak384Native(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak384NativeRaw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak512(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak512Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak512Native(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashKeccak512NativeRaw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashPED64(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashPED64Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashPED128(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashPED128Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashPSD2(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PSD_PER_BYTE_COST, HASH_PSD_BASE_COST)
        }
        Command::Instruction(Instruction::HashPSD2Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PSD_PER_BYTE_COST, HASH_PSD_BASE_COST)
        }
        Command::Instruction(Instruction::HashPSD4(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PSD_PER_BYTE_COST, HASH_PSD_BASE_COST)
        }
        Command::Instruction(Instruction::HashPSD4Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PSD_PER_BYTE_COST, HASH_PSD_BASE_COST)
        }
        Command::Instruction(Instruction::HashPSD8(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PSD_PER_BYTE_COST, HASH_PSD_BASE_COST)
        }
        Command::Instruction(Instruction::HashPSD8Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PSD_PER_BYTE_COST, HASH_PSD_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_256(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_256Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_256Native(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_256NativeRaw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_384(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_384Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_384Native(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_384NativeRaw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_512(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_512Raw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_512Native(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashSha3_512NativeRaw(hash)) => {
            cost_in_size(stack, finalize_types, hash.operands(), HASH_PER_BYTE_COST, HASH_BASE_COST)
        }
        Command::Instruction(Instruction::HashManyPSD2(_)) => {
            bail!("`hash_many.psd2` is not supported in finalize")
        }
        Command::Instruction(Instruction::HashManyPSD4(_)) => {
            bail!("`hash_many.psd4` is not supported in finalize")
        }
        Command::Instruction(Instruction::HashManyPSD8(_)) => {
            bail!("`hash_many.psd8` is not supported in finalize")
        }
        Command::Instruction(Instruction::Inv(_)) => Ok(2_500),
        Command::Instruction(Instruction::IsEq(_)) => Ok(500),
        Command::Instruction(Instruction::IsNeq(_)) => Ok(500),
        Command::Instruction(Instruction::LessThan(_)) => Ok(500),
        Command::Instruction(Instruction::LessThanOrEqual(_)) => Ok(500),
        Command::Instruction(Instruction::Modulo(_)) => Ok(500),
        Command::Instruction(Instruction::Mul(mul)) => {
            // Ensure `mul` has exactly two operands.
            ensure!(mul.operands().len() == 2, "'mul' must contain exactly 2 operands");
            // Retrieve the price by operand type.
            match finalize_types.get_type_from_operand(stack, &mul.operands()[0])? {
                FinalizeType::Plaintext(PlaintextType::Literal(LiteralType::Group)) => Ok(10_000),
                FinalizeType::Plaintext(PlaintextType::Literal(LiteralType::Scalar)) => Ok(10_000),
                FinalizeType::Plaintext(PlaintextType::Literal(_)) => Ok(500),
                FinalizeType::Plaintext(PlaintextType::Array(_)) => bail!("'mul' does not support arrays"),
                FinalizeType::Plaintext(PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_)) => {
                    bail!("'mul' does not support structs")
                }
                FinalizeType::Future(_) => bail!("'mul' does not support futures"),
                FinalizeType::DynamicFuture => bail!("'mul' does not support dynamic futures"),
            }
        }
        Command::Instruction(Instruction::MulWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::Nand(_)) => Ok(500),
        Command::Instruction(Instruction::Neg(_)) => Ok(500),
        Command::Instruction(Instruction::Nor(_)) => Ok(500),
        Command::Instruction(Instruction::Not(_)) => Ok(500),
        Command::Instruction(Instruction::Or(_)) => Ok(500),
        Command::Instruction(Instruction::Pow(pow)) => {
            // Ensure `pow` has at least one operand.
            ensure!(!pow.operands().is_empty(), "'pow' must contain at least 1 operand");
            // Retrieve the price by operand type.
            match finalize_types.get_type_from_operand(stack, &pow.operands()[0])? {
                FinalizeType::Plaintext(PlaintextType::Literal(LiteralType::Field)) => Ok(1_500),
                FinalizeType::Plaintext(PlaintextType::Literal(_)) => Ok(500),
                FinalizeType::Plaintext(PlaintextType::Array(_)) => bail!("'pow' does not support arrays"),
                FinalizeType::Plaintext(PlaintextType::Struct(_) | PlaintextType::ExternalStruct(_)) => {
                    bail!("'pow' does not support structs")
                }
                FinalizeType::Future(_) => bail!("'pow' does not support futures"),
                FinalizeType::DynamicFuture => bail!("'pow' does not support dynamic futures"),
            }
        }
        Command::Instruction(Instruction::PowWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::Rem(_)) => Ok(500),
        Command::Instruction(Instruction::RemWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::SerializeBits(serialize)) => {
            Ok(plaintext_size_in_bytes(stack, &PlaintextType::Array(serialize.destination_type().clone()))?
                .saturating_mul(CAST_PER_BYTE_COST)
                .saturating_add(CAST_BASE_COST))
        }
        Command::Instruction(Instruction::SerializeBitsRaw(serialize)) => {
            Ok(plaintext_size_in_bytes(stack, &PlaintextType::Array(serialize.destination_type().clone()))?
                .saturating_mul(CAST_PER_BYTE_COST)
                .saturating_add(CAST_BASE_COST))
        }
        Command::Instruction(Instruction::SignVerify(sign)) => {
            cost_in_size(stack, finalize_types, sign.operands(), HASH_PSD_PER_BYTE_COST, HASH_PSD_BASE_COST)
        }
        Command::Instruction(Instruction::Shl(_)) => Ok(500),
        Command::Instruction(Instruction::ShlWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::Shr(_)) => Ok(500),
        Command::Instruction(Instruction::ShrWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::SnarkVerify(snark)) => {
            cost_in_size(stack, finalize_types, snark.operands(), SNARK_VERIFY_PER_BYTE_COST, SNARK_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::SnarkVerifyBatch(snark)) => {
            cost_in_size(stack, finalize_types, snark.operands(), SNARK_VERIFY_PER_BYTE_COST, SNARK_VERIFY_BASE_COST)
        }
        Command::Instruction(Instruction::Square(_)) => Ok(500),
        Command::Instruction(Instruction::SquareRoot(_)) => Ok(2_500),
        Command::Instruction(Instruction::Sub(_)) => Ok(500),
        Command::Instruction(Instruction::SubWrapped(_)) => Ok(500),
        Command::Instruction(Instruction::Ternary(_)) => Ok(500),
        Command::Instruction(Instruction::Xor(_)) => Ok(500),
        Command::Await(_) => Ok(500),
        Command::Contains(command) => {
            cost_in_size(stack, finalize_types, [command.key()], MAPPING_PER_BYTE_COST, mapping_base_cost)
        }
        Command::ContainsDynamic(command) => {
            cost_in_size(stack, finalize_types, [command.key_operand()], MAPPING_PER_BYTE_COST, mapping_base_cost)
        }
        Command::Get(command) => {
            cost_in_size(stack, finalize_types, [command.key()], MAPPING_PER_BYTE_COST, mapping_base_cost)
        }
        Command::GetDynamic(command) => {
            cost_in_size(stack, finalize_types, [command.key_operand()], MAPPING_PER_BYTE_COST, mapping_base_cost)
        }
        Command::GetOrUse(command) => {
            cost_in_size(stack, finalize_types, [command.key()], MAPPING_PER_BYTE_COST, mapping_base_cost)
        }
        Command::GetOrUseDynamic(command) => {
            cost_in_size(stack, finalize_types, [command.key_operand()], MAPPING_PER_BYTE_COST, mapping_base_cost)
        }
        Command::RandChaCha(command) => {
            if consensus_version.is_some_and(|version| version >= ConsensusVersion::V22) {
                let seed_component = {
                    let mut bhp_operands = command.operands().to_vec();
                    // The always-present pre-seed is about 750 bits, which is roughly equivalent to 3 field elements.
                    for _ in 0..3 {
                        bhp_operands.push(Operand::Literal(Literal::Field(Field::one())));
                    }
                    cost_in_size(stack, finalize_types, &bhp_operands, HASH_BHP_PER_BYTE_COST, HASH_BHP_BASE_COST)
                };

                // The rand_chacha operations which produce a group element incur a non-negligible
                // cost due to finite-field and elliptic-curve arithmetic.
                let output_component =
                    if matches!(command.destination_type(), LiteralType::Group | LiteralType::Address) {
                        115_000
                    } else {
                        0
                    };

                seed_component.map(|cost| cost.saturating_add(output_component))
            } else {
                // Pre-V22 fixed cost.
                Ok(25_000)
            }
        }
        Command::Remove(_) => Ok(SET_BASE_COST),
        Command::Set(command) => {
            cost_in_size(stack, finalize_types, [command.key(), command.value()], SET_PER_BYTE_COST, SET_BASE_COST)
        }
        Command::BranchEq(_) | Command::BranchNeq(_) => Ok(500),
        Command::Position(_) => Ok(100),
    }
}

/// Returns the minimum number of microcredits required to run the constructor in the given stack.
/// If a constructor does not exist, no cost is incurred.
pub fn constructor_cost_in_microcredits_v2<N: Network>(
    stack: &Stack<N>,
    consensus_version: Option<ConsensusVersion>,
) -> Result<u64> {
    match stack.program().constructor() {
        Some(constructor) => {
            // Get the constructor types.
            let constructor_types = stack.get_constructor_types()?;
            // Get the base cost of the constructor.
            let base_cost = constructor
                .commands()
                .iter()
                .map(|command| {
                    cost_per_command(stack, &constructor_types, command, ConsensusFeeVersion::V2, consensus_version)
                })
                .try_fold(0u64, |acc, res| {
                    res.and_then(|x| acc.checked_add(x).ok_or(anyhow!("Constructor cost overflowed")))
                })?;
            // Scale by the multiplier and divide by the ARC-0005 cost reduction factor.
            base_cost
                .checked_mul(N::CONSTRUCTOR_FEE_MULTIPLIER)
                .map(|result| result / N::ARC_0005_COMPUTE_DISCOUNT)
                .ok_or(anyhow!("Constructor cost overflowed"))
        }
        None => Ok(0),
    }
}

/// Returns the minimum number of microcredits required to run the constructor in the given stack.
/// If a constructor does not exist, no cost is incurred.
pub fn constructor_cost_in_microcredits_v1<N: Network>(stack: &Stack<N>) -> Result<u64> {
    match stack.program().constructor() {
        Some(constructor) => {
            // Get the constructor types.
            let constructor_types = stack.get_constructor_types()?;
            // Get the base cost of the constructor.
            let base_cost = constructor
                .commands()
                .iter()
                .map(|command| cost_per_command(stack, &constructor_types, command, ConsensusFeeVersion::V2, None))
                .try_fold(0u64, |acc, res| {
                    res.and_then(|x| acc.checked_add(x).ok_or(anyhow!("Constructor cost overflowed")))
                })?;
            // Scale by the multiplier and divide by the ARC-0005 cost reduction factor.
            base_cost.checked_mul(N::CONSTRUCTOR_FEE_MULTIPLIER).ok_or(anyhow!("Constructor cost overflowed"))
        }
        None => Ok(0),
    }
}

/// Returns the minimum number of microcredits required to run the finalize using the ARC-0005 cost reduction factor.
/// Note: For dynamic futures, this only provides a lower bound on the cost because the target functions
/// cannot be statically determined. For exact execution cost, use `execution_finalize_cost`.
pub fn minimum_cost_in_microcredits_v3<N: Network>(
    stack: &Stack<N>,
    function_name: &Identifier<N>,
    consensus_version: Option<ConsensusVersion>,
) -> Result<u64> {
    minimum_cost_in_microcredits(stack, function_name, ConsensusFeeVersion::V3, consensus_version)
}

/// Returns the finalize cost for a single function's finalize block, without recursively following futures.
/// This is used for runtime cost calculation where we iterate over concrete transitions.
/// Note: This returns the RAW cost without applying the quotient divisor. The caller is responsible
/// for applying the quotient after summing all costs to avoid integer division truncation errors.
fn finalize_cost_for_single_function_raw<N: Network>(
    stack: &Stack<N>,
    function_name: &Identifier<N>,
    consensus_fee_version: ConsensusFeeVersion,
    consensus_version: Option<ConsensusVersion>,
) -> Result<u64> {
    // Get the finalize logic. If the function does not have a finalize scope, no cost is incurred.
    let Some(finalize) = stack.get_function_ref(function_name)?.finalize_logic() else {
        return Ok(0);
    };

    // Get the finalize types.
    let finalize_types = stack.get_finalize_types(finalize.name())?;

    // Sum the cost of all commands in the finalize block.
    // Note: We don't recursively follow futures here because each transition's
    // finalize cost is computed separately when iterating over all transitions.
    let mut finalize_cost = 0u64;
    for command in finalize.commands() {
        finalize_cost = finalize_cost
            .checked_add(cost_per_command(stack, &finalize_types, command, consensus_fee_version, consensus_version)?)
            .ok_or_else(|| anyhow!("Finalize cost overflowed"))?;
    }

    Ok(finalize_cost)
}

/// Returns the maximum compute cost (in microcredits) of a single view function's body.
///
/// This raw cost contributes to finalize commands that call the view and to deployment
/// spend-limit checks. The caller applies any compute discount after summing costs.
fn view_cost_for_single_view<N: Network>(
    stack: &Stack<N>,
    view_name: &Identifier<N>,
    consensus_fee_version: ConsensusFeeVersion,
    consensus_version: Option<ConsensusVersion>,
) -> Result<u64> {
    let view = stack.program().get_view_ref(view_name)?;
    // Use the cached view types (computed once at `Stack::new`).
    let view_types = stack.get_view_types(view_name)?;

    let mut view_cost = 0u64;
    for command in view.commands() {
        view_cost = view_cost
            .checked_add(cost_per_command(stack, &view_types, command, consensus_fee_version, consensus_version)?)
            .ok_or_else(|| anyhow!("View cost overflowed"))?;
    }
    Ok(view_cost)
}

/// Returns the total finalize cost for an execution by iterating over all concrete transitions.
/// This gives an exact cost calculation because we know which functions were actually called.
/// The complexity is O(MAX_TRANSITIONS * MAX_COMMANDS_PER_FINALIZE) which is bounded.
pub(crate) fn execution_finalize_cost<N: Network>(
    process: &Process<N>,
    execution: &Execution<N>,
    consensus_fee_version: ConsensusFeeVersion,
    consensus_version: Option<ConsensusVersion>,
) -> Result<u64> {
    // Get the quotient for the cost reduction factor.
    // We apply this at the end after summing all costs to match the behavior of
    // minimum_cost_in_microcredits and avoid integer division truncation errors.
    let quotient = match consensus_fee_version {
        ConsensusFeeVersion::V1 | ConsensusFeeVersion::V2 => 1,
        ConsensusFeeVersion::V3 => N::ARC_0005_COMPUTE_DISCOUNT,
    };

    let mut total_cost = 0u64;

    // Iterate over all transitions and sum their finalize costs.
    // This is bounded by Transaction::MAX_TRANSITIONS.
    for transition in execution.transitions() {
        // Get the stack for this transition's program.
        let stack = process.get_stack(transition.program_id())?;
        // Compute the raw finalize cost for this single transition (without quotient).
        let cost = finalize_cost_for_single_function_raw(
            &stack,
            transition.function_name(),
            consensus_fee_version,
            consensus_version,
        )?;
        // Add to the total.
        total_cost = total_cost.checked_add(cost).ok_or_else(|| anyhow!("Execution finalize cost overflowed"))?;
    }

    // Apply the quotient divisor at the end (matching behavior of minimum_cost_in_microcredits).
    Ok(total_cost / quotient)
}

/// Returns the minimum number of microcredits required to run the finalize.
/// Note: For dynamic futures, this only provides a lower bound on the cost because the target functions
/// cannot be statically determined. For exact execution cost, use `execution_finalize_cost`.
pub fn minimum_cost_in_microcredits_v2<N: Network>(stack: &Stack<N>, function_name: &Identifier<N>) -> Result<u64> {
    minimum_cost_in_microcredits(stack, function_name, ConsensusFeeVersion::V2, None)
}

/// Returns the minimum number of microcredits required to run the finalize (deprecated).
/// Note: For dynamic futures, this only provides a lower bound on the cost because the target functions
/// cannot be statically determined. For exact execution cost, use `execution_finalize_cost`.
pub fn minimum_cost_in_microcredits_v1<N: Network>(stack: &Stack<N>, function_name: &Identifier<N>) -> Result<u64> {
    minimum_cost_in_microcredits(stack, function_name, ConsensusFeeVersion::V1, None)
}

// A helper function to compute the minimum cost in microcredits for a given function.
// This performs static analysis and recursively follows static futures, but not dynamic futures.
fn minimum_cost_in_microcredits<N: Network>(
    stack: &Stack<N>,
    function_name: &Identifier<N>,
    consensus_fee_version: ConsensusFeeVersion,
    consensus_version: Option<ConsensusVersion>,
) -> Result<u64> {
    // Initialize the base cost.
    let mut finalize_cost = 0u64;
    // Initialize a queue of finalize blocks to tally.
    let mut finalizes = vec![(StackRef::Internal(stack), *function_name)];
    // Initialize a counter for the number of finalize blocks seen.
    let mut num_finalizes = 1;
    // Get the quotient for the cost reduction factor.
    let quotient = match consensus_fee_version {
        ConsensusFeeVersion::V1 | ConsensusFeeVersion::V2 => 1,
        ConsensusFeeVersion::V3 => N::ARC_0005_COMPUTE_DISCOUNT,
    };
    // Iterate over the finalize blocks.
    while let Some((stack_ref, function_name)) = finalizes.pop() {
        // Ensure that the number of finalize blocks does not exceed the maximum.
        // Note that one transition is reserved for the fee.
        ensure!(
            num_finalizes < Transaction::<N>::MAX_TRANSITIONS,
            "The number of finalize blocks must be less than '{}'",
            Transaction::<N>::MAX_TRANSITIONS
        );
        // Get the finalize logic. If the function does not have a finalize scope then no cost is incurred.
        // Note: For dynamic futures, this only creates a lower bound on the cost because we cannot
        // statically determine which functions will be called. For exact execution cost calculation,
        // use `execution_finalize_cost` which iterates over concrete transitions.
        if let Some(finalize) = stack_ref.get_function_ref(&function_name)?.finalize_logic() {
            // Queue the futures to be tallied.
            for input in finalize.inputs() {
                if let FinalizeType::Future(future) = input.finalize_type() {
                    // Increment the number of finalize blocks seen.
                    num_finalizes += 1;
                    // If the locator matches the program ID of the provided stack, use it directly.
                    // Otherwise, retrieve the external stack.
                    let stack = if future.program_id() == stack.program().id() {
                        StackRef::Internal(stack)
                    } else {
                        StackRef::External(stack_ref.get_external_stack(future.program_id())?)
                    };
                    // Queue the future.
                    finalizes.push((stack, *future.resource()));
                }
            }
            // Get the finalize types.
            let finalize_types = stack_ref.get_finalize_types(finalize.name())?;
            // Iterate over the commands in the finalize block.
            for command in finalize.commands() {
                // Sum the cost of all commands in the current future into the total running cost.
                finalize_cost = finalize_cost
                    .checked_add(cost_per_command(
                        &stack_ref,
                        &finalize_types,
                        command,
                        consensus_fee_version,
                        consensus_version,
                    )?)
                    .ok_or_else(|| anyhow!("Finalize cost overflowed"))?;
            }
        }
    }
    Ok(finalize_cost / quotient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::get_execution;
    use circuit::{Aleo, AleoCanaryV0, AleoTestnetV0, AleoV0};

    use console::{
        network::{CanaryV0, ConsensusVersion, MainnetV0, TestnetV0, prelude::consensus_config_value_by_version},
        types::Address,
    };
    use snarkvm_synthesizer_program::Program;

    // Test program with two functions just below and above the size threshold.
    const SIZE_BOUNDARY_PROGRAM: &str = r#"
program size_boundary.aleo;

function under_five_thousand:
    input r0 as group.public;
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 into r1 as [group; 9u32];
    cast r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 into r2 as [[group; 9u32]; 10u32];
    cast r0 r0 r0 r0 r0 r0 r0 into r3 as [group; 7u32];
    output r2 as [[group; 9u32]; 10u32].public;
    output r3 as [group; 7u32].public;

function over_five_thousand:
    input r0 as group.public;
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 into r1 as [group; 9u32];
    cast r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 into r2 as [[group; 9u32]; 10u32];
    cast r0 r0 r0 r0 r0 r0 r0 into r3 as [group; 7u32];
    output r2 as [[group; 9u32]; 10u32].public;
    output r3 as [group; 7u32].public;
    output 5u64 as u64.public;
    "#;
    // Cost for a program +1 byte above the threshold.
    const STORAGE_COST_ABOVE_THRESHOLD: u64 = 5002;
    // Storage cost for an execution transaction at the maximum transaction size.
    const V1_STORAGE_COST_MAX: u64 = 3_276_800;
    const V14_STORAGE_COST_MAX: u64 = 117_964_800;
    const V16_STORAGE_COST_MAX: u64 = 1_061_683_200;

    fn test_storage_cost_bounds<N: Network>() {
        // Calculate the bounds directly above and below the size threshold.
        let threshold = N::EXECUTION_STORAGE_PENALTY_THRESHOLD;
        let threshold_lower_offset = threshold.saturating_sub(1);
        let threshold_upper_offset = threshold.saturating_add(1);

        // Test the storage cost bounds.
        assert_eq!(execution_storage_cost::<N>(0), 0);
        assert_eq!(execution_storage_cost::<N>(1), 1);
        assert_eq!(execution_storage_cost::<N>(threshold_lower_offset), threshold_lower_offset);
        assert_eq!(execution_storage_cost::<N>(threshold), threshold);
        assert_eq!(execution_storage_cost::<N>(threshold_upper_offset), STORAGE_COST_ABOVE_THRESHOLD);
        // Use V1 value for backwards-compatible test.
        let v1_max_tx_size = consensus_config_value_by_version!(N, MAX_TRANSACTION_SIZE, ConsensusVersion::V1).unwrap();
        assert_eq!(execution_storage_cost::<N>(v1_max_tx_size as u64), V1_STORAGE_COST_MAX);
        let v14_max_tx_size =
            consensus_config_value_by_version!(N, MAX_TRANSACTION_SIZE, ConsensusVersion::V14).unwrap();
        assert_eq!(execution_storage_cost::<N>(v14_max_tx_size as u64), V14_STORAGE_COST_MAX);
        let v16_max_tx_size =
            consensus_config_value_by_version!(N, MAX_TRANSACTION_SIZE, ConsensusVersion::V16).unwrap();
        assert_eq!(execution_storage_cost::<N>(v16_max_tx_size as u64), V16_STORAGE_COST_MAX);
    }

    #[test]
    fn test_storage_cost_bounds_for_all_networks() {
        test_storage_cost_bounds::<CanaryV0>();
        test_storage_cost_bounds::<MainnetV0>();
        test_storage_cost_bounds::<TestnetV0>();
    }

    #[test]
    fn test_storage_costs_compute_correctly() {
        // Test the storage cost of an execution.
        let threshold = MainnetV0::EXECUTION_STORAGE_PENALTY_THRESHOLD;

        // We ensure the check pases in the latest consensus version. Change either this or the 3 in
        // execution_cost_v3 below if new execution_cost versions are introduced which break the
        // test.
        let latest_consensus_version = ConsensusVersion::latest();

        // Test the cost of an execution.
        let mut process = Process::load().unwrap();

        // Get the program.
        let program = Program::from_str(SIZE_BOUNDARY_PROGRAM).unwrap();

        // Get the program identifiers.
        let under_5000 = Identifier::from_str("under_five_thousand").unwrap();
        let over_5000 = Identifier::from_str("over_five_thousand").unwrap();

        // Get execution and cost data.
        let execution_under_5000 = get_execution(&mut process, &program, &under_5000, ["2group"].into_iter());
        let execution_size_under_5000 = execution_under_5000.size_in_bytes().unwrap();
        let (_, (storage_cost_under_5000, _)) = execution_cost_v3(
            &process,
            &execution_under_5000,
            execution_size_under_5000,
            Some(latest_consensus_version),
        )
        .unwrap();
        let execution_over_5000 = get_execution(&mut process, &program, &over_5000, ["2group"].into_iter());
        let execution_size_over_5000 = execution_over_5000.size_in_bytes().unwrap();
        let (_, (storage_cost_over_5000, _)) =
            execution_cost_v3(&process, &execution_over_5000, execution_size_over_5000, Some(latest_consensus_version))
                .unwrap();

        // Ensure the sizes are below and above the threshold respectively.
        assert!(execution_size_under_5000 < threshold);
        assert!(execution_size_over_5000 > threshold);

        // Ensure storage costs compute correctly.
        assert_eq!(storage_cost_under_5000, execution_storage_cost::<MainnetV0>(execution_size_under_5000));
        assert_eq!(storage_cost_over_5000, execution_storage_cost::<MainnetV0>(execution_size_over_5000));
    }

    #[test]
    fn test_deployment_storage_cost_bounds() {
        // Below threshold: linear at DEPLOYMENT_FEE_MULTIPLIER microcredits per byte.
        assert_eq!(deployment_storage_cost::<MainnetV0>(0).unwrap(), 0);
        assert_eq!(deployment_storage_cost::<MainnetV0>(1).unwrap(), MainnetV0::DEPLOYMENT_FEE_MULTIPLIER);
        // One byte below threshold: still linear.
        let below = DEPLOYMENT_STORAGE_PENALTY_THRESHOLD - 1;
        assert_eq!(deployment_storage_cost::<MainnetV0>(below).unwrap(), below * MainnetV0::DEPLOYMENT_FEE_MULTIPLIER);
        // At threshold: the linear and quadratic formulas agree (continuity check).
        // `deployment_storage_cost` uses the linear arm at the threshold (size <= threshold), so
        // compute the quadratic-arm value independently and confirm they match at the boundary.
        let t = DEPLOYMENT_STORAGE_PENALTY_THRESHOLD;
        let quadratic_at_threshold =
            t * t * MainnetV0::DEPLOYMENT_FEE_MULTIPLIER / DEPLOYMENT_STORAGE_PENALTY_THRESHOLD;
        assert_eq!(deployment_storage_cost::<MainnetV0>(t).unwrap(), quadratic_at_threshold);
        // One byte above threshold: quadratic formula kicks in.
        let above = DEPLOYMENT_STORAGE_PENALTY_THRESHOLD + 1;
        let expected_above =
            above * above * MainnetV0::DEPLOYMENT_FEE_MULTIPLIER / DEPLOYMENT_STORAGE_PENALTY_THRESHOLD;
        assert_eq!(deployment_storage_cost::<MainnetV0>(above).unwrap(), expected_above);
        // At the V16 max program size (2048 kB = 4x the threshold): cost is exactly 4x the linear cost.
        let max = 2_048_000u64;
        assert_eq!(deployment_storage_cost::<MainnetV0>(max).unwrap(), 4 * max * MainnetV0::DEPLOYMENT_FEE_MULTIPLIER);
    }

    #[test]
    fn test_deployment_cost_with_constructors() {
        // A helper to run the test.
        fn run_test<N: Network, A: Aleo<Network = N>>() {
            let process = Process::<N>::load().unwrap();
            let rng = &mut TestRng::default();

            // Define the programs.
            let program_0 = Program::from_str(
                r"
program program_with_constructor.aleo;

constructor:
    assert.eq true true;

mapping foo:
    key as field.public;
    value as field.public;

function dummy:",
            )
            .unwrap();

            let program_1 = Program::from_str(
                r"
program program_with_constructor.aleo;

constructor:
    assert.eq edition 0u16;

mapping foo:
    key as field.public;
    value as field.public;

function dummy:",
            )
            .unwrap();

            let program_2 = Program::from_str(
                r"
program program_with_constructor.aleo;

constructor:
    get foo[0field] into r0;

mapping foo:
    key as field.public;
    value as field.public;

function dummy:",
            )
            .unwrap();

            let program_3 = Program::from_str(
                r"
program program_with_constructor.aleo;

constructor:
    set 0field into foo[0field];

mapping foo:
    key as field.public;
    value as field.public;

function dummy:",
            )
            .unwrap();

            // Verify the deployment costs.
            let mut deployment_0 = process.deploy::<A, _>(&program_0, rng).unwrap();
            deployment_0.set_program_checksum_raw(Some(deployment_0.program().to_checksum()));
            deployment_0.set_program_owner_raw(Some(Address::rand(rng)));
            let expected_storage_cost = 879000;
            let expected_synthesis_cost = 603500;
            let expected_constructor_cost = 50000;
            let expected_namespace_cost = 1000000;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v1(&process, &deployment_0).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            let expected_synthesis_cost = expected_synthesis_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_constructor_cost = expected_constructor_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v2(&process, &deployment_0).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            // V3 uses quadratic storage above 512 kB; this program is well below that threshold,
            // so the storage cost equals the v2 linear cost and all other components are identical.
            assert_eq!(
                deployment_cost_v3(&process, &deployment_0).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );

            let mut deployment_1 = process.deploy::<A, _>(&program_1, rng).unwrap();
            deployment_1.set_program_checksum_raw(Some(deployment_1.program().to_checksum()));
            deployment_1.set_program_owner_raw(Some(Address::rand(rng)));
            let expected_storage_cost = 878000;
            let expected_synthesis_cost = 603500;
            let expected_constructor_cost = 50000;
            let expected_namespace_cost = 1000000;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v1(&process, &deployment_1).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            let expected_synthesis_cost = expected_synthesis_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_constructor_cost = expected_constructor_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v2(&process, &deployment_1).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            assert_eq!(
                deployment_cost_v3(&process, &deployment_1).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );

            let mut deployment_2 = process.deploy::<A, _>(&program_2, rng).unwrap();
            deployment_2.set_program_checksum_raw(Some(deployment_2.program().to_checksum()));
            deployment_2.set_program_owner_raw(Some(Address::rand(rng)));
            let expected_storage_cost = 911000;
            let expected_synthesis_cost = 603500;
            let expected_constructor_cost = 182000;
            let expected_namespace_cost = 1000000;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v1(&process, &deployment_2).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            let expected_synthesis_cost = expected_synthesis_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_constructor_cost = expected_constructor_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v2(&process, &deployment_2).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            assert_eq!(
                deployment_cost_v3(&process, &deployment_2).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );

            let mut deployment_3 = process.deploy::<A, _>(&program_3, rng).unwrap();
            deployment_3.set_program_checksum_raw(Some(deployment_3.program().to_checksum()));
            deployment_3.set_program_owner_raw(Some(Address::rand(rng)));
            let expected_storage_cost = 943000;
            let expected_synthesis_cost = 603500;
            let expected_constructor_cost = 1640000;
            let expected_namespace_cost = 1000000;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v1(&process, &deployment_3).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            let expected_synthesis_cost = expected_synthesis_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_constructor_cost = expected_constructor_cost / N::ARC_0005_COMPUTE_DISCOUNT;
            let expected_total_cost =
                expected_storage_cost + expected_synthesis_cost + expected_constructor_cost + expected_namespace_cost;
            assert_eq!(
                deployment_cost_v2(&process, &deployment_3).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
            assert_eq!(
                deployment_cost_v3(&process, &deployment_3).unwrap(),
                (
                    expected_total_cost,
                    (
                        expected_storage_cost,
                        expected_synthesis_cost,
                        expected_constructor_cost,
                        expected_namespace_cost
                    )
                )
            );
        }

        // Run the tests for all networks.
        run_test::<CanaryV0, AleoCanaryV0>();
        run_test::<MainnetV0, AleoV0>();
        run_test::<TestnetV0, AleoTestnetV0>();
    }

    #[test]
    fn test_deployment_cost_v3_dispatch_and_quadratic_storage() {
        // Verify that `deployment_cost` with ConsensusVersion::V16 dispatches to `deployment_cost_v3`,
        // and that v3 applies the quadratic storage penalty above DEPLOYMENT_STORAGE_PENALTY_THRESHOLD.
        let process = Process::<MainnetV0>::load().unwrap();
        let rng = &mut TestRng::default();

        let program = Program::from_str(
            r"
program dispatch_test.aleo;

function noop:",
        )
        .unwrap();

        let mut deployment = process.deploy::<AleoV0, _>(&program, rng).unwrap();
        deployment.set_program_checksum_raw(Some(deployment.program().to_checksum()));
        deployment.set_program_owner_raw(Some(Address::rand(rng)));

        // `deployment_cost` must dispatch to v3 for ConsensusVersion::V16.
        assert_eq!(
            deployment_cost(&process, &deployment, ConsensusVersion::V16).unwrap(),
            deployment_cost_v3(&process, &deployment).unwrap(),
        );

        // For programs below DEPLOYMENT_STORAGE_PENALTY_THRESHOLD, v3 and v2 produce equal costs.
        let (v2_total, (v2_storage, _, _, _)) = deployment_cost_v2(&process, &deployment).unwrap();
        let (v3_total, (v3_storage, _, _, _)) = deployment_cost_v3(&process, &deployment).unwrap();
        let size_in_bytes = deployment.size_in_bytes().unwrap();
        assert!(
            size_in_bytes < DEPLOYMENT_STORAGE_PENALTY_THRESHOLD,
            "Program must be below the storage penalty threshold for this assertion to hold"
        );
        assert_eq!(v2_storage, v3_storage);
        assert_eq!(v2_total, v3_total);

        // For sizes above the threshold, the quadratic formula makes v3 storage exceed v2 storage.
        // At 2x the threshold: quadratic gives 4x the linear base, which is 2x the v2 cost.
        let above = 2 * DEPLOYMENT_STORAGE_PENALTY_THRESHOLD;
        let v2_storage_above = above * MainnetV0::DEPLOYMENT_FEE_MULTIPLIER;
        let v3_storage_above = deployment_storage_cost::<MainnetV0>(above).unwrap();
        assert!(v3_storage_above > v2_storage_above, "v3 storage must exceed v2 storage above the penalty threshold");
        assert_eq!(v3_storage_above, 2 * v2_storage_above);
    }

    #[test]
    fn test_deployment_cost_v4_v5_dispatch_and_rand_chacha_constructor_cost() {
        // Verify that `deployment_cost` dispatches to `deployment_cost_v4` for ConsensusVersion::V18
        // through V21 and to `deployment_cost_v5` from V22 onwards. Also verify that v5 prices
        // synthesis like v3 (by variables and constraints, not by density as in v4), and that v5
        // only differs from v3 in the constructor cost of `rand.chacha`.
        let process = Process::<MainnetV0>::load().unwrap();
        let rng = &mut TestRng::default();

        // The constructor samples one non-group and one group value, so that both branches of the
        // V22 `rand.chacha` cost are exercised.
        let program = Program::from_str(
            r"
program dispatch_v5_test.aleo;

constructor:
    rand.chacha into r0 as u64;
    rand.chacha into r1 as group;

function noop:",
        )
        .unwrap();

        let mut deployment = process.deploy::<AleoV0, _>(&program, rng).unwrap();
        deployment.set_program_checksum_raw(Some(deployment.program().to_checksum()));
        deployment.set_program_owner_raw(Some(Address::rand(rng)));

        let v3_cost = deployment_cost_v3(&process, &deployment).unwrap();
        let v4_cost = deployment_cost_v4(&process, &deployment).unwrap();
        let v5_cost = deployment_cost_v5(&process, &deployment, ConsensusVersion::V22).unwrap();

        // `deployment_cost` must dispatch to v4 for ConsensusVersion::V18 to V21.
        for consensus_version in
            [ConsensusVersion::V18, ConsensusVersion::V19, ConsensusVersion::V20, ConsensusVersion::V21]
        {
            assert_eq!(deployment_cost(&process, &deployment, consensus_version).unwrap(), v4_cost);
        }
        // `deployment_cost` must dispatch to v5 for ConsensusVersion::V22 and the latest version.
        // Change this if a future consensus version introduces a new deployment cost version.
        for consensus_version in [ConsensusVersion::V22, ConsensusVersion::latest()] {
            assert_eq!(deployment_cost(&process, &deployment, consensus_version).unwrap(), v5_cost);
        }

        let (v3_total, (v3_storage, v3_synthesis, v3_constructor, v3_namespace)) = v3_cost;
        let (_, (v4_storage, v4_synthesis, v4_constructor, v4_namespace)) = v4_cost;
        let (v5_total, (v5_storage, v5_synthesis, v5_constructor, v5_namespace)) = v5_cost;

        // The storage and namespace costs are the same across v3, v4, and v5.
        assert_eq!(v3_storage, v4_storage);
        assert_eq!(v3_storage, v5_storage);
        assert_eq!(v3_namespace, v4_namespace);
        assert_eq!(v3_namespace, v5_namespace);

        // v3 and v5 price synthesis by the combined number of variables and constraints, while v4
        // prices it by the combined density.
        let scale_synthesis = |factor: u64| {
            factor * <MainnetV0 as Network>::SYNTHESIS_FEE_MULTIPLIER
                / <MainnetV0 as Network>::ARC_0005_COMPUTE_DISCOUNT
        };
        let num_variables_and_constraints =
            deployment.num_combined_variables().unwrap() + deployment.num_combined_constraints().unwrap();
        assert_eq!(v3_synthesis, scale_synthesis(num_variables_and_constraints));
        assert_eq!(v5_synthesis, scale_synthesis(num_variables_and_constraints));
        assert_eq!(v4_synthesis, scale_synthesis(deployment.combined_density()));
        assert_ne!(v4_synthesis, v5_synthesis, "the program must distinguish the two synthesis cost formulas");

        // Only the constructor cost differs between v3 and v5.
        assert_eq!(v3_total - v3_constructor, v5_total - v5_constructor);

        // In v3 and v4, each `rand.chacha` has a flat cost of 25_000.
        let legacy_base_cost = 2 * 25_000;
        // In v5, each `rand.chacha` costs the BHP hash of its seed (no operands plus three field
        // elements of 32 bytes each), and the `group` destination adds a surcharge of 115_000.
        let v5_seed_cost = HASH_BHP_BASE_COST + HASH_BHP_PER_BYTE_COST * (3 * 32);
        let v5_base_cost = 2 * v5_seed_cost + 115_000;
        assert_eq!(v5_base_cost, 272_600, "v5 rand.chacha cost derivation changed");

        let scale_constructor = |base_cost: u64| {
            base_cost * <MainnetV0 as Network>::CONSTRUCTOR_FEE_MULTIPLIER
                / <MainnetV0 as Network>::ARC_0005_COMPUTE_DISCOUNT
        };
        assert_eq!(v3_constructor, scale_constructor(legacy_base_cost));
        assert_eq!(v4_constructor, scale_constructor(legacy_base_cost));
        assert_eq!(v5_constructor, scale_constructor(v5_base_cost));
    }

    #[test]
    fn test_deployment_cost_v5_matches_v3_without_rand_chacha() {
        // Verify that, for a program which does not use `rand.chacha`, `deployment_cost_v5` returns
        // exactly the same cost breakdown as `deployment_cost_v3`.
        let process = Process::<MainnetV0>::load().unwrap();
        let rng = &mut TestRng::default();

        let program = Program::from_str(
            r"
program v5_matches_v3.aleo;

constructor:
    assert.eq edition 0u16;

mapping data:
    key as field.public;
    value as field.public;

function store:
    input r0 as field.public;
    async store r0 into r1;
    output r1 as v5_matches_v3.aleo/store.future;

finalize store:
    input r0 as field.public;
    hash.bhp256 r0 into r1 as field;
    set r1 into data[r0];",
        )
        .unwrap();

        let mut deployment = process.deploy::<AleoV0, _>(&program, rng).unwrap();
        deployment.set_program_checksum_raw(Some(deployment.program().to_checksum()));
        deployment.set_program_owner_raw(Some(Address::rand(rng)));

        let v3_cost = deployment_cost_v3(&process, &deployment).unwrap();
        for consensus_version in [ConsensusVersion::V22, ConsensusVersion::latest()] {
            assert_eq!(deployment_cost_v5(&process, &deployment, consensus_version).unwrap(), v3_cost);
        }
    }

    // Test program with finalize blocks for cost comparison test
    const FINALIZE_PROGRAM: &str = r#"
program finalize_test.aleo;

mapping counter:
    key as u64.public;
    value as u64.public;

function increment:
    input r0 as u64.public;
    async increment r0 into r1;
    output r1 as finalize_test.aleo/increment.future;

finalize increment:
    input r0 as u64.public;
    get.or_use counter[r0] 0u64 into r1;
    add r1 1u64 into r2;
    set r2 into counter[r0];
"#;

    #[test]
    fn test_execution_finalize_cost_matches_static() {
        // This test verifies that for executions WITHOUT dynamic futures,
        // the runtime cost calculation (execution_finalize_cost) matches
        // the static cost calculation (minimum_cost_in_microcredits).

        let mut process = Process::load().unwrap();
        let program = Program::from_str(FINALIZE_PROGRAM).unwrap();
        let function_name = Identifier::from_str("increment").unwrap();

        // Get execution using the test helper
        let execution = get_execution(&mut process, &program, &function_name, ["42u64"].into_iter());

        // Get the stack for static cost calculation
        let stack = process.get_stack(program.id()).unwrap();

        // Calculate costs using both methods for all fee versions
        // V1
        let static_cost_v1 = minimum_cost_in_microcredits_v1(&stack, &function_name).unwrap();
        let runtime_cost_v1 = execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V1, None).unwrap();
        assert_eq!(
            static_cost_v1, runtime_cost_v1,
            "V1: Static and runtime costs should match: static={static_cost_v1}, runtime={runtime_cost_v1}"
        );

        // V2
        let static_cost_v2 = minimum_cost_in_microcredits_v2(&stack, &function_name).unwrap();
        let runtime_cost_v2 = execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V2, None).unwrap();
        assert_eq!(
            static_cost_v2, runtime_cost_v2,
            "V2: Static and runtime costs should match: static={static_cost_v2}, runtime={runtime_cost_v2}"
        );

        // V3

        // As this is the latest ConsensusFeeVersion, we ensure the check pases in the latest
        // consensus version. Change this if future ConsensusFeeVersion or ConsensusVersion changes
        // break the test.
        let latest_consensus_version = ConsensusVersion::latest();
        let static_cost_v3 =
            minimum_cost_in_microcredits_v3(&stack, &function_name, Some(latest_consensus_version)).unwrap();
        let runtime_cost_v3 =
            execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V3, Some(latest_consensus_version))
                .unwrap();
        assert_eq!(
            static_cost_v3, runtime_cost_v3,
            "V3: Static and runtime costs should match: static={static_cost_v3}, runtime={runtime_cost_v3}"
        );

        // Verify costs are non-zero to ensure meaningful test
        assert!(static_cost_v1 > 0, "Expected non-zero cost");
        println!("Single function - Static cost V3: {static_cost_v3}");
    }

    #[test]
    fn test_execution_finalize_cost_matches_static_nested_calls() {
        // This test verifies cost calculation with NESTED static futures.
        // Program structure:
        //   caller.aleo/call_child -> child.aleo/child_fn
        // Both have finalize blocks, and caller awaits child's future.

        // Child program with a finalize block
        let (_, child_program) = Program::<MainnetV0>::parse(
            r"
program child.aleo;

mapping child_counter:
    key as u64.public;
    value as u64.public;

function child_fn:
    input r0 as u64.public;
    async child_fn r0 into r1;
    output r1 as child.aleo/child_fn.future;

finalize child_fn:
    input r0 as u64.public;
    get.or_use child_counter[r0] 0u64 into r1;
    add r1 1u64 into r2;
    set r2 into child_counter[r0];
",
        )
        .unwrap();

        // Caller program that calls child and awaits its future
        let (_, caller_program) = Program::<MainnetV0>::parse(
            r"
import child.aleo;

program caller.aleo;

mapping caller_counter:
    key as u64.public;
    value as u64.public;

function call_child:
    input r0 as u64.public;
    call child.aleo/child_fn r0 into r1;
    async call_child r1 r0 into r2;
    output r2 as caller.aleo/call_child.future;

finalize call_child:
    input r0 as child.aleo/child_fn.future;
    input r1 as u64.public;
    await r0;
    get.or_use caller_counter[r1] 0u64 into r2;
    add r2 10u64 into r3;
    set r3 into caller_counter[r1];
",
        )
        .unwrap();

        // Build the process with both programs
        let mut process = crate::test_helpers::sample_process(&child_program);
        process.lock().add_program(&caller_program).unwrap();

        let function_name = Identifier::from_str("call_child").unwrap();

        // Get execution
        let execution = get_execution(&mut process, &caller_program, &function_name, ["42u64"].into_iter());

        // Verify we have 2 transitions (child + caller)
        assert_eq!(execution.transitions().count(), 2, "Expected 2 transitions for nested call");

        // Get the stack for static cost calculation
        let stack = process.get_stack(caller_program.id()).unwrap();

        // Calculate costs using both methods. Since V3 is the latest ConsensusFeeVersion, we ensure
        // the check pases in the latest consensus version. Change this if future
        // ConsensusFeeVersion or ConsensusVersion changes break the test.
        let latest_consensus_version = ConsensusVersion::latest();
        let static_cost_v3 =
            minimum_cost_in_microcredits_v3(&stack, &function_name, Some(latest_consensus_version)).unwrap();
        let runtime_cost_v3 =
            execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V3, Some(latest_consensus_version))
                .unwrap();

        println!("Nested calls - Static cost V3: {static_cost_v3}");
        println!("Nested calls - Runtime cost V3: {runtime_cost_v3}");
        println!("Nested calls - Number of transitions: {}", execution.transitions().count());

        assert_eq!(
            static_cost_v3, runtime_cost_v3,
            "V3: Static and runtime costs should match for nested calls: static={static_cost_v3}, runtime={runtime_cost_v3}"
        );

        // Also verify V1 and V2 (where the specific ConsensusVersion is not relevant to the cost
        // function in question)
        let static_cost_v1 = minimum_cost_in_microcredits_v1(&stack, &function_name).unwrap();
        let runtime_cost_v1 = execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V1, None).unwrap();
        assert_eq!(
            static_cost_v1, runtime_cost_v1,
            "V1: Static and runtime costs should match for nested calls: static={static_cost_v1}, runtime={runtime_cost_v1}"
        );

        let static_cost_v2 = minimum_cost_in_microcredits_v2(&stack, &function_name).unwrap();
        let runtime_cost_v2 = execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V2, None).unwrap();
        assert_eq!(
            static_cost_v2, runtime_cost_v2,
            "V2: Static and runtime costs should match for nested calls: static={static_cost_v2}, runtime={runtime_cost_v2}"
        );

        // Verify costs are non-zero and nested cost > single cost
        assert!(static_cost_v3 > 0, "Expected non-zero cost for nested calls");
    }

    #[test]
    fn test_execution_finalize_cost_matches_static_complex_call_graph() {
        // This test verifies cost calculation with a COMPLEX call graph:
        //
        // root.aleo/main
        //   -> level1_a.aleo/fn_a (has finalize with await)
        //        -> leaf.aleo/leaf_fn (has finalize)
        //   -> level1_b.aleo/fn_b (has finalize with await)
        //        -> leaf.aleo/leaf_fn (has finalize)
        //
        // Execution order: leaf, fn_a, leaf, fn_b, main
        // Total: 5 transitions, 5 finalize blocks

        // Leaf program - called twice
        let (_, leaf_program) = Program::<MainnetV0>::parse(
            r"
program leaf.aleo;

mapping leaf_data:
    key as u64.public;
    value as u64.public;

function leaf_fn:
    input r0 as u64.public;
    async leaf_fn r0 into r1;
    output r1 as leaf.aleo/leaf_fn.future;

finalize leaf_fn:
    input r0 as u64.public;
    get.or_use leaf_data[r0] 0u64 into r1;
    add r1 1u64 into r2;
    set r2 into leaf_data[r0];
",
        )
        .unwrap();

        // Level 1 program A - calls leaf
        let (_, level1_a_program) = Program::<MainnetV0>::parse(
            r"
import leaf.aleo;

program level1_a.aleo;

mapping level1_a_data:
    key as u64.public;
    value as u64.public;

function fn_a:
    input r0 as u64.public;
    call leaf.aleo/leaf_fn r0 into r1;
    async fn_a r1 r0 into r2;
    output r2 as level1_a.aleo/fn_a.future;

finalize fn_a:
    input r0 as leaf.aleo/leaf_fn.future;
    input r1 as u64.public;
    await r0;
    get.or_use level1_a_data[r1] 0u64 into r2;
    add r2 100u64 into r3;
    set r3 into level1_a_data[r1];
",
        )
        .unwrap();

        // Level 1 program B - also calls leaf
        let (_, level1_b_program) = Program::<MainnetV0>::parse(
            r"
import leaf.aleo;

program level1_b.aleo;

mapping level1_b_data:
    key as u64.public;
    value as u64.public;

function fn_b:
    input r0 as u64.public;
    call leaf.aleo/leaf_fn r0 into r1;
    async fn_b r1 r0 into r2;
    output r2 as level1_b.aleo/fn_b.future;

finalize fn_b:
    input r0 as leaf.aleo/leaf_fn.future;
    input r1 as u64.public;
    await r0;
    get.or_use level1_b_data[r1] 0u64 into r2;
    add r2 200u64 into r3;
    set r3 into level1_b_data[r1];
",
        )
        .unwrap();

        // Root program - calls both level1_a and level1_b
        // Note: must import leaf.aleo for transitive dependency resolution
        let (_, root_program) = Program::<MainnetV0>::parse(
            r"
import leaf.aleo;
import level1_a.aleo;
import level1_b.aleo;

program root.aleo;

mapping root_data:
    key as u64.public;
    value as u64.public;

function main:
    input r0 as u64.public;
    call level1_a.aleo/fn_a r0 into r1;
    call level1_b.aleo/fn_b r0 into r2;
    async main r1 r2 r0 into r3;
    output r3 as root.aleo/main.future;

finalize main:
    input r0 as level1_a.aleo/fn_a.future;
    input r1 as level1_b.aleo/fn_b.future;
    input r2 as u64.public;
    await r0;
    await r1;
    get.or_use root_data[r2] 0u64 into r3;
    add r3 1000u64 into r4;
    set r4 into root_data[r2];
",
        )
        .unwrap();

        // Build the process with all programs
        let mut process = crate::test_helpers::sample_process(&leaf_program);
        process.lock().add_program(&level1_a_program).unwrap();
        process.lock().add_program(&level1_b_program).unwrap();
        process.lock().add_program(&root_program).unwrap();

        let function_name = Identifier::from_str("main").unwrap();

        // Get execution
        let execution = get_execution(&mut process, &root_program, &function_name, ["42u64"].into_iter());

        // Verify we have 5 transitions
        let num_transitions = execution.transitions().count();
        println!("Complex call graph - Number of transitions: {num_transitions}");
        assert_eq!(num_transitions, 5, "Expected 5 transitions for complex call graph");

        // Get the stack for static cost calculation
        let stack = process.get_stack(root_program.id()).unwrap();

        // Calculate costs using both methods Since V3 is the latest ConsensusFeeVersion, we ensure
        // the check pases in the latest consensus version. Change this if future
        // ConsensusFeeVersion or ConsensusVersion changes break the test.
        let latest_consensus_version = ConsensusVersion::latest();
        let static_cost_v3 =
            minimum_cost_in_microcredits_v3(&stack, &function_name, Some(latest_consensus_version)).unwrap();
        let runtime_cost_v3 =
            execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V3, Some(latest_consensus_version))
                .unwrap();

        println!("Complex call graph - Static cost V3: {static_cost_v3}");
        println!("Complex call graph - Runtime cost V3: {runtime_cost_v3}");

        assert_eq!(
            static_cost_v3, runtime_cost_v3,
            "V3: Static and runtime costs should match for complex call graph: static={static_cost_v3}, runtime={runtime_cost_v3}"
        );

        // Also verify V1 and V2 (where the specific ConsensusVersion is not relevant to the cost
        // function in question)
        let static_cost_v1 = minimum_cost_in_microcredits_v1(&stack, &function_name).unwrap();
        let runtime_cost_v1 = execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V1, None).unwrap();
        assert_eq!(static_cost_v1, runtime_cost_v1, "V1: Static and runtime costs should match for complex call graph");

        let static_cost_v2 = minimum_cost_in_microcredits_v2(&stack, &function_name).unwrap();
        let runtime_cost_v2 = execution_finalize_cost(&process, &execution, ConsensusFeeVersion::V2, None).unwrap();
        assert_eq!(static_cost_v2, runtime_cost_v2, "V2: Static and runtime costs should match for complex call graph");

        // Verify costs are meaningful
        assert!(static_cost_v3 > 0, "Expected non-zero cost");
        println!(
            "Complex call graph - V1 cost: {static_cost_v1}, V2 cost: {static_cost_v2}, V3 cost: {static_cost_v3}"
        );
    }
}
