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

use std::collections::{BTreeMap, VecDeque};

use crate::{
    fft::{DensePolynomial, EvaluationDomain, Evaluations as EvaluationsOnDomain, Polynomial},
    polycommit::sonic_pc::LabeledPolynomial,
    r1cs::{SynthesisError, SynthesisResult},
    snark::varuna::{AHPError, AHPForR1CS, Circuit, SNARKMode},
};
use anyhow::anyhow;
use snarkvm_fields::PrimeField;

/// Circuit Specific State of the Prover
pub struct CircuitSpecificState<F: PrimeField> {
    pub(super) input_domain: EvaluationDomain<F>,
    pub(super) variable_domain: EvaluationDomain<F>,
    pub(super) constraint_domain: EvaluationDomain<F>,
    pub(super) non_zero_a_domain: EvaluationDomain<F>,
    pub(super) non_zero_b_domain: EvaluationDomain<F>,
    pub(super) non_zero_c_domain: EvaluationDomain<F>,

    /// The number of instances being proved in this batch.
    pub(in crate::snark) batch_size: usize,

    /// The list of public inputs for each instance in the batch (`x_{i, j}` in
    /// the Varuna spec). The length of this list must be equal to the batch
    /// size.
    pub(super) padded_public_variables: Vec<Vec<F>>,

    /// The list of private variables for each instance in the batch (after
    /// padding: `w` in the Varuna spec). The length of this list must be equal
    /// to the batch size.
    pub(super) private_variables: Vec<Vec<F>>,

    /// The list of `A_i * z_i_j` vectors for each instance `j` in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) z_a: Option<Vec<Vec<F>>>,

    /// The list of `B_i * z_i_j` vectors for each instance `j` in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) z_b: Option<Vec<Vec<F>>>,

    /// The list of `C_i * z_i_j` vectors for each instance `j` in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) z_c: Option<Vec<Vec<F>>>,

    /// A list of polynomials (`\tilde{x}_{i, j}(X)` in the Varuna spec)
    /// corresponding to the interpolation of the public input `x_{i, j}`. The
    /// length of this list must be equal to the batch size.
    pub(super) x_polys: Vec<DensePolynomial<F>>,

    /// Intermediary polynomials of the row sumcheck.
    pub(in crate::snark) z_m_at_alpha_polys: Option<VecDeque<[DensePolynomial<F>; 3]>>,

    /// Intermediary polynomials of the matrix sumcheck.
    pub(in crate::snark) a_polys: Option<[LabeledPolynomial<F>; 3]>,

    /// Intermediary polynomials of the matrix sumcheck.
    pub(in crate::snark) b_polys: Option<[LabeledPolynomial<F>; 3]>,

    /// Intermediary polynomials of the matrix sumcheck.
    pub(super) lhs_polynomials: Option<[LabeledPolynomial<F>; 3]>,
}

/// State for the AHP prover.
pub struct State<'a, F: PrimeField, SM: SNARKMode> {
    /// The state for each circuit in the batch.
    pub(in crate::snark) circuit_specific_states: BTreeMap<&'a Circuit<F, SM>, CircuitSpecificState<F>>,
    /// The first round oracles sent by the prover.
    /// The length of this list must be equal to the batch size.
    pub(in crate::snark) first_round_oracles: Option<super::FirstOracles<F>>,
    /// The largest non_zero domain of all circuits in the batch.
    pub(in crate::snark) max_non_zero_domain: EvaluationDomain<F>,
    /// The largest constraint domain of all circuits in the batch.
    pub(in crate::snark) max_constraint_domain: EvaluationDomain<F>,
    /// The largest variable domain of all circuits in the batch.
    pub(in crate::snark) max_variable_domain: EvaluationDomain<F>,
    /// The total number of instances we're proving in the batch.
    pub(in crate::snark) total_instances: usize,
}

/// The public inputs for a single instance.
type PaddedPubInputs<F> = Vec<F>;
/// The private inputs for a single instance.
type PrivateInputs<F> = Vec<F>;
/// The vector `z_i_j * A_i` for a single instance.
type Za<F> = Vec<F>;
/// The vector `z_i_j * B_i` for a single instance.
type Zb<F> = Vec<F>;
/// The vector `z_i_j * C_i` for a single instance.
type Zc<F> = Vec<F>;

/// Assignments for a single instance.
pub(super) struct Assignments<F>(
    pub(super) PaddedPubInputs<F>,
    pub(super) PrivateInputs<F>,
    pub(super) Za<F>,
    pub(super) Zb<F>,
    pub(super) Zc<F>,
);

impl<'a, F: PrimeField, SM: SNARKMode> State<'a, F, SM> {
    pub(super) fn initialize(
        indices_and_assignments: BTreeMap<&'a Circuit<F, SM>, Vec<Assignments<F>>>,
    ) -> Result<Self, AHPError> {
        let mut max_non_zero_domain: Option<EvaluationDomain<F>> = None;
        let mut max_num_constraints = 0;
        let mut max_num_variables = 0;
        let mut total_instances = 0usize;
        let circuit_specific_states = indices_and_assignments
            .into_iter()
            .map(|(circuit, variable_assignments)| {
                let index_info = &circuit.index_info;

                let constraint_domain =
                    EvaluationDomain::new(index_info.num_constraints).ok_or(SynthesisError::PolyTooLarge)?;
                max_num_constraints = max_num_constraints.max(index_info.num_constraints);

                let variable_domain = EvaluationDomain::new(index_info.num_public_and_private_variables)
                    .ok_or(SynthesisError::PolyTooLarge)?;
                max_num_variables = max_num_variables.max(index_info.num_public_and_private_variables);

                let non_zero_domains = AHPForR1CS::<_, SM>::cmp_non_zero_domains(index_info, max_non_zero_domain)?;
                max_non_zero_domain = non_zero_domains.max_non_zero_domain;

                let first_padded_public_inputs = &variable_assignments[0].0;
                let input_domain = EvaluationDomain::new(first_padded_public_inputs.len())
                    .ok_or(anyhow!("Cannot create EvaluationDomain"))?;
                let batch_size = variable_assignments.len();
                total_instances =
                    total_instances.checked_add(batch_size).ok_or_else(|| anyhow!("Batch size too large"))?;
                let mut z_as = Vec::with_capacity(batch_size);
                let mut z_bs = Vec::with_capacity(batch_size);
                let mut z_cs = Vec::with_capacity(batch_size);
                let mut x_polys = Vec::with_capacity(batch_size);
                let mut padded_public_variables = Vec::with_capacity(batch_size);
                let mut private_variables = Vec::with_capacity(batch_size);

                for Assignments(padded_public_input, private_input, z_a, z_b, z_c) in variable_assignments {
                    z_as.push(z_a);
                    z_bs.push(z_b);
                    z_cs.push(z_c);
                    let x_poly = EvaluationsOnDomain::from_vec_and_domain(padded_public_input.clone(), input_domain)
                        .interpolate();
                    x_polys.push(x_poly);
                    padded_public_variables.push(padded_public_input);
                    private_variables.push(private_input);
                }

                let state = CircuitSpecificState {
                    input_domain,
                    variable_domain,
                    constraint_domain,
                    non_zero_a_domain: non_zero_domains.domain_a,
                    non_zero_b_domain: non_zero_domains.domain_b,
                    non_zero_c_domain: non_zero_domains.domain_c,
                    batch_size,
                    padded_public_variables,
                    x_polys,
                    private_variables,
                    z_a: Some(z_as),
                    z_b: Some(z_bs),
                    z_c: Some(z_cs),
                    z_m_at_alpha_polys: None,
                    a_polys: None,
                    b_polys: None,
                    lhs_polynomials: None,
                };
                Ok((circuit, state))
            })
            .collect::<SynthesisResult<BTreeMap<_, _>>>()?;

        let max_non_zero_domain = max_non_zero_domain.ok_or(AHPError::BatchSizeIsZero)?;
        let max_constraint_domain = EvaluationDomain::new(max_num_constraints).ok_or(SynthesisError::PolyTooLarge)?;
        let max_variable_domain = EvaluationDomain::new(max_num_variables).ok_or(SynthesisError::PolyTooLarge)?;

        Ok(Self {
            max_constraint_domain,
            max_variable_domain,
            max_non_zero_domain,
            circuit_specific_states,
            total_instances,
            first_round_oracles: None,
        })
    }

    /// Get the batch size for a given circuit.
    pub fn batch_size(&self, circuit: &Circuit<F, SM>) -> Option<usize> {
        self.circuit_specific_states.get(circuit).map(|s| s.batch_size)
    }

    /// Get the public inputs for the entire batch.
    pub fn public_inputs(&self, circuit: &Circuit<F, SM>) -> Option<Vec<Vec<F>>> {
        // We need to export inputs as they live longer than prover_state
        self.circuit_specific_states.get(circuit).map(|s| {
            s.padded_public_variables.iter().map(|v| super::ConstraintSystem::unformat_public_input(v)).collect()
        })
    }

    /// Get the padded public inputs for the entire batch.
    pub fn padded_public_inputs(&self, circuit: &Circuit<F, SM>) -> Option<&[Vec<F>]> {
        self.circuit_specific_states.get(circuit).map(|s| s.padded_public_variables.as_slice())
    }

    /// Iterate over the lhs_polynomials, in the order of `lhs_polys_into_iter`.
    pub fn lhs_polys(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        self.circuit_specific_states.values().flat_map(|s| s.lhs_polynomials.iter().flatten())
    }

    /// Iterate over the lhs_polynomials
    pub fn lhs_polys_into_iter(self) -> impl Iterator<Item = DensePolynomial<F>> + 'a {
        self.circuit_specific_states
            .into_values()
            .flat_map(|s| s.lhs_polynomials.unwrap().into_iter())
            .map(|mut p| std::mem::replace(p.polynomial_mut(), Polynomial::zero()).into())
    }
}
