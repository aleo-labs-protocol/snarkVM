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

use std::{borrow::Cow, collections::BTreeMap};

use crate::{
    fft::{DensePolynomial, EvaluationDomain, Evaluations as EvaluationsOnDomain},
    polycommit::sonic_pc::{LabeledPolynomial, PolynomialInfo, PolynomialLabel},
    snark::varuna::{
        Circuit,
        CircuitId,
        SNARKMode,
        ahp::{AHPForR1CS, verifier},
        prover,
        witness_label,
    },
};
use anyhow::{Result, ensure};
use rand::Rng;
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{ExecutionPool, cfg_into_iter, cfg_iter, cfg_reduce, defer};

#[cfg(feature = "serial")]
use itertools::Itertools;
#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

impl<F: PrimeField, SM: SNARKMode> AHPForR1CS<F, SM> {
    /// Output the number of oracles sent by the prover in the second round.
    pub const fn num_second_round_oracles() -> usize {
        1
    }

    /// Output the degree bounds of oracles in the second round.
    pub fn second_round_polynomial_info() -> BTreeMap<PolynomialLabel, PolynomialInfo> {
        [PolynomialInfo::new("h_0".into(), None, None)].into_iter().map(|info| (info.label().into(), info)).collect()
    }

    /// Output the second round message and the next state.
    pub fn prover_second_round<'a, R: Rng>(
        verifier_message: &verifier::FirstMessage<F>,
        mut state: prover::State<'a, F, SM>,
        _r: &mut R,
    ) -> Result<(prover::SecondOracles<F>, prover::State<'a, F, SM>)> {
        let round_time = start_timer!(|| "AHP::Prover::SecondRound");
        defer! { end_timer!(round_time); }

        let zk_bound = Self::zk_bound();

        let max_constraint_domain = state.max_constraint_domain;

        let verifier::FirstMessage { first_round_batch_combiners, .. } = verifier_message;

        let h_0 = Self::calculate_rowcheck_witness(&mut state, first_round_batch_combiners)?;

        assert!(h_0.degree() <= 2 * max_constraint_domain.size() + 2 * zk_bound.unwrap_or(0) - 2);

        let oracles = prover::SecondOracles { h_0: LabeledPolynomial::new("h_0", h_0, None, None) };
        assert!(oracles.matches_info(&Self::second_round_polynomial_info()));

        Ok((oracles, state))
    }

    fn calculate_rowcheck_witness(
        state: &mut prover::State<F, SM>,
        batch_combiners: &BTreeMap<CircuitId, verifier::BatchCombiners<F>>,
    ) -> Result<DensePolynomial<F>> {
        let mut job_pool = ExecutionPool::with_capacity(state.circuit_specific_states.len());
        let max_constraint_domain = state.max_constraint_domain;

        for (circuit, circuit_specific_state) in state.circuit_specific_states.iter_mut() {
            let z_a = circuit_specific_state.z_a.take().unwrap();
            let z_b = circuit_specific_state.z_b.take().unwrap();
            let z_c = circuit_specific_state.z_c.take().unwrap();

            let circuit_combiner = batch_combiners[&circuit.id].circuit_combiner;
            let instance_combiners = batch_combiners[&circuit.id].instance_combiners.clone();
            let constraint_domain = circuit_specific_state.constraint_domain;
            let fft_precomputation = &circuit.fft_precomputation;
            let ifft_precomputation = &circuit.ifft_precomputation;

            let _circuit_id = &circuit.id; // seems like a compiler bug marks this as unused

            for (j, (instance_combiner, z_a, z_b, z_c)) in
                itertools::izip!(instance_combiners, z_a, z_b, z_c).enumerate()
            {
                job_pool.add_job(move || {
                    // The quotient below assumes that the assignment satisfies every row.
                    let satisfied = cfg_iter!(z_a).zip_eq(&z_b).zip_eq(&z_c).all(|((a, b), c)| *a * b == *c);
                    ensure!(satisfied, "The assignment does not satisfy the circuit's constraints");

                    let za_label = witness_label(circuit.id, "z_a", j);
                    let zb_label = witness_label(circuit.id, "z_b", j);
                    let zc_label = witness_label(circuit.id, "z_c", j);
                    let z_a = Self::calculate_z_m(za_label, z_a, constraint_domain, circuit);
                    let z_b = Self::calculate_z_m(zb_label, z_b, constraint_domain, circuit);
                    let z_c = Self::calculate_z_m(zc_label, z_c, constraint_domain, circuit);
                    // Dividing `(v_H / v_H_i) * (H_i.size() / H.size())` by `v_H` leaves
                    // `H_i.size() / H.size()` on the quotient over `v_H_i`.
                    let scale = instance_combiner
                        * circuit_combiner
                        * constraint_domain.size_as_field_element
                        * max_constraint_domain.size_inv;
                    constraint_domain.divide_product_by_vanishing_poly(
                        Cow::Owned(z_a),
                        Cow::Owned(z_b),
                        &z_c,
                        scale,
                        fft_precomputation,
                        ifft_precomputation,
                    )
                });
            }
        }

        let h_sum_time = start_timer!(|| "AHP::Prover::SecondRound h_sum");
        defer! { end_timer!(h_sum_time); }
        let h_sum: DensePolynomial<F> =
            cfg_reduce!(cfg_into_iter!(job_pool.execute_all()), || Ok(DensePolynomial::zero()), |a, b| {
                a.and_then(|a| {
                    b.map(|mut b| {
                        b += &a;
                        b
                    })
                })
            })?;
        Ok(h_sum)
    }

    fn calculate_z_m(
        label: impl ToString,
        evaluations: Vec<F>,
        constraint_domain: EvaluationDomain<F>,
        circuit: &Circuit<F, SM>,
    ) -> DensePolynomial<F> {
        let label = label.to_string();
        let poly_time = start_timer!(|| format!("Computing {label}"));

        let evals = EvaluationsOnDomain::from_vec_and_domain(evaluations, constraint_domain);
        let poly = evals.interpolate_with_pc_by_ref(&circuit.ifft_precomputation);

        debug_assert!(
            poly.evaluate_over_domain_by_ref(constraint_domain)
                .evaluations
                .into_iter()
                .zip(&evals.evaluations)
                .all(|(z, e)| *e == z),
            "Label: {label}\n1: {:#?}\n2: {:#?}",
            poly.evaluate_over_domain_by_ref(constraint_domain).evaluations,
            &evals.evaluations,
        );

        end_timer!(poly_time);

        poly
    }
}
