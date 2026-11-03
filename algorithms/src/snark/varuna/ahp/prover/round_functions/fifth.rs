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

use std::collections::BTreeMap;

use crate::{
    fft::DensePolynomial,
    polycommit::sonic_pc::{LabeledPolynomial, PolynomialInfo, PolynomialLabel},
    snark::varuna::{
        SNARKMode,
        ahp::{AHPError, AHPForR1CS, verifier},
        prover,
    },
};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{cfg_par_bridge, cfg_reduce};

use itertools::Itertools;
use rand::Rng;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

impl<F: PrimeField, SM: SNARKMode> AHPForR1CS<F, SM> {
    /// Output the number of oracles sent by the prover in this round.
    pub const fn num_fifth_round_oracles() -> usize {
        1
    }

    /// Output the fifth round message and the next state.
    pub fn prover_fifth_round<R: Rng>(
        verifier_message: verifier::FourthMessage<F>,
        state: prover::State<'_, F, SM>,
        _r: &mut R,
    ) -> Result<prover::FifthOracles<F>, AHPError> {
        let round_time = start_timer!(|| "AHP::Prover::FifthRound");

        let lhs_sum: DensePolynomial<F> = cfg_reduce!(
            cfg_par_bridge!(verifier_message.into_iter().zip_eq(state.lhs_polys_into_iter())).map(
                |(delta, mut lhs)| {
                    lhs *= delta;
                    lhs
                }
            ),
            || DensePolynomial::zero(),
            |mut a, mut b| {
                if b != DensePolynomial::zero() {
                    a += &std::mem::take(&mut b);
                }
                a
            }
        );
        let h_2 = LabeledPolynomial::new("h_2", lhs_sum, None, None);
        let oracles = prover::FifthOracles { h_2 };
        assert!(oracles.matches_info(&Self::fifth_round_polynomial_info()));

        end_timer!(round_time);
        Ok(oracles)
    }

    /// Output the degree bounds of oracles in the last round.
    pub fn fifth_round_polynomial_info() -> BTreeMap<PolynomialLabel, PolynomialInfo> {
        [("h_2".into(), PolynomialInfo::new("h_2".into(), None, None))].into()
    }
}
