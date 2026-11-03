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

use crate::{
    fft::DensePolynomial,
    snark::varuna::{
        AHPError,
        Matrix,
        SNARKMode,
        ahp::{AHPForR1CS, indexer::CircuitId, verifier},
        prover::{self, MatrixSums, ThirdMessage},
    },
};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{ExecutionPool, defer};
use std::sync::Arc;

use anyhow::Result;
use itertools::Itertools;
use rand::Rng;
use std::collections::{BTreeMap, VecDeque};

struct LinevalPrepInstance<F: PrimeField> {
    z_m_at_alpha: DensePolynomial<F>,
    sum: F,
}

impl<F: PrimeField, SM: SNARKMode> AHPForR1CS<F, SM> {
    /// Output the preparation third round message and the next state.
    pub fn prover_prepare_third_round<'a, R: Rng>(
        verifier_message: &verifier::FirstMessage<F>,
        verifier_second_message: &verifier::SecondMessage<F>,
        mut state: prover::State<'a, F, SM>,
        _r: &mut R,
    ) -> Result<(prover::ThirdMessage<F>, prover::State<'a, F, SM>), AHPError> {
        let round_time = start_timer!(|| "AHP::Prover::PrepareThirdRound");
        defer! { end_timer!(round_time); }

        let verifier::FirstMessage { first_round_batch_combiners } = verifier_message;
        let verifier::SecondMessage { alpha, eta_b, eta_c } = verifier_second_message;

        if eta_b.is_some() || eta_c.is_some() {
            return Err(AHPError::AnyhowError(anyhow::anyhow!(
                "Did not expect eta_b,c in SecondMessage in VarunaVersion::V2 or greater"
            )));
        }

        let assignments = Self::calculate_assignments(&mut state)?;
        let matrix_transposes = Self::calculate_matrix_transpose(&mut state)?;

        let msg = Self::calculate_prep_lineval_sumcheck_witness(
            &mut state,
            first_round_batch_combiners,
            assignments,
            matrix_transposes,
            alpha,
        )?;

        Ok((msg, state))
    }

    fn calculate_prep_lineval_sumcheck_witness(
        state: &mut prover::State<F, SM>,
        first_round_batch_combiners: &BTreeMap<CircuitId, verifier::BatchCombiners<F>>,
        assignments: BTreeMap<CircuitId, Vec<DensePolynomial<F>>>,
        matrix_transposes: BTreeMap<CircuitId, BTreeMap<String, Matrix<F>>>,
        alpha: &F,
    ) -> Result<ThirdMessage<F>> {
        let num_instances = first_round_batch_combiners.values().map(|c| c.instance_combiners.len()).collect_vec();
        let total_instances = num_instances.iter().sum::<usize>();
        let matrix_labels = ["a", "b", "c"];

        // Borrowed, not cloned. Each precomputation holds a root-of-unity table sized
        // by the circuit's largest multiplicative domain, so cloning copies
        // megabytes per circuit per proof to produce a byte-identical result --
        // the tables are circuit data, fixed for the life of the process.
        let fft_precomputations = state
            .circuit_specific_states
            .keys()
            .map(|circuit| (&circuit.fft_precomputation, &circuit.ifft_precomputation))
            .collect_vec();

        // Compute lineval sumcheck witnesses
        let mut job_pool = ExecutionPool::with_capacity(total_instances * 3);
        // Iterate for each circuit in the batch.
        anyhow::ensure!(
            state.circuit_specific_states.len() == fft_precomputations.len(),
            "[calculate Prep Lineval Sumcheck Witness] Expected {} circuit specific states, but {} were provided.",
            fft_precomputations.len(),
            state.circuit_specific_states.len()
        );
        anyhow::ensure!(
            state.circuit_specific_states.len() == assignments.len(),
            "[calculate Prep Lineval Sumcheck Witness] Expected {} assignments, but {} were provided.",
            assignments.len(),
            state.circuit_specific_states.len()
        );
        anyhow::ensure!(
            state.circuit_specific_states.len() == matrix_transposes.len(),
            "[calculate Prep Lineval Sumcheck Witness] Expected {} matrix transposes, but {} were provided.",
            matrix_transposes.len(),
            state.circuit_specific_states.len()
        );
        for ((((&circuit, circuit_specific_state), precomp), assignments_i), matrix_transposes_i) in state
            .circuit_specific_states
            .iter()
            .zip_eq(fft_precomputations.iter())
            .zip_eq(assignments.values())
            .zip_eq(matrix_transposes.values())
        {
            // One Lagrange vector per circuit rather than one per matrix: it depends only
            // on the constraint domain and alpha, both of which are fixed
            // across the jobs below.
            let lagrange_time = start_timer!(|| "Lagrange coefficients at alpha");
            let l_at_alpha =
                Arc::new(circuit_specific_state.constraint_domain.evaluate_all_lagrange_coefficients(*alpha));
            end_timer!(lagrange_time);

            // Iterate for each instance in the batch.
            for assignment in assignments_i {
                // Iterate for each R1CS matrix corresponding to the circuit and instance.
                for label in matrix_labels {
                    let matrix_transpose = &matrix_transposes_i[label];
                    let l_at_alpha = l_at_alpha.clone();
                    job_pool.add_job(move || {
                        let z_m_at_alpha = Self::calculate_lineval_sumcheck_instance_witness(
                            label,
                            &l_at_alpha,
                            &circuit_specific_state.variable_domain,
                            precomp.0,
                            precomp.1,
                            assignment,
                            matrix_transpose,
                        )?;
                        // sum_{h in H} f(h) = n*(c_0 + c_n) for deg(p) < 2n, where c_0 and c_n are the
                        // coeffs of f at degree 0 and n, resp. and in [0, 2n-2]
                        // only k=0 and k=n are multiples of n. Avoids an O(n log n) FFT.
                        let n = circuit_specific_state.variable_domain.size_as_field_element;
                        let c_0 = z_m_at_alpha.coeffs.first().copied().unwrap_or_default();
                        let c_n = z_m_at_alpha
                            .coeffs
                            .get(circuit_specific_state.variable_domain.size())
                            .copied()
                            .unwrap_or_default();
                        let sum = n * (c_0 + c_n);
                        Ok((circuit, LinevalPrepInstance { z_m_at_alpha, sum }))
                    });
                }
            }
        }

        let mut sums = num_instances.iter().map(|n| Vec::with_capacity(*n)).collect_vec();
        let mut circuit_index = 0;
        let mut instances_seen = 0;
        for (i, ((circuit_a, lineval_a), (circuit_b, lineval_b), (circuit_c, lineval_c))) in
            job_pool.execute_all().into_iter().collect::<Result<Vec<_>>>()?.into_iter().tuples().enumerate()
        {
            // Sanity check that we're collecting data from the same circuits.
            assert_eq!(circuit_a, circuit_b);
            assert_eq!(circuit_a, circuit_c);
            sums[circuit_index].push(MatrixSums { sum_a: lineval_a.sum, sum_b: lineval_b.sum, sum_c: lineval_c.sum });
            if 1 + i - instances_seen == num_instances[circuit_index] {
                instances_seen += num_instances[circuit_index];
                circuit_index += 1;
            }

            // Store the z_m_at_alpha polynomials for use in the next round.
            match &mut state.circuit_specific_states.get_mut(circuit_a).unwrap().z_m_at_alpha_polys {
                None => {
                    let mut z_m_at_alpha_polys = VecDeque::new();
                    z_m_at_alpha_polys.push_back([
                        lineval_a.z_m_at_alpha,
                        lineval_b.z_m_at_alpha,
                        lineval_c.z_m_at_alpha,
                    ]);
                    state.circuit_specific_states.get_mut(circuit_a).unwrap().z_m_at_alpha_polys =
                        Some(z_m_at_alpha_polys);
                }
                Some(z_m_at_alpha_polys) => {
                    z_m_at_alpha_polys.push_back([
                        lineval_a.z_m_at_alpha,
                        lineval_b.z_m_at_alpha,
                        lineval_c.z_m_at_alpha,
                    ]);
                }
            }
        }

        let msg = ThirdMessage { sums };

        Ok(msg)
    }
}
