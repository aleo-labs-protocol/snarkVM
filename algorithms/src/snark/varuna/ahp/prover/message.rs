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

use std::{collections::BTreeMap, io};

use crate::snark::varuna::{CircuitId, verifier::BatchCombiners};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{ToBytes, Write, into_io_error, serialize::*};

/// A triple of sums `({sigma_{A, i, j}, {sigma_{B, i, j}, {sigma_{C, i, j})` as
/// sent by the prover during round 3 of the AHP.
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MatrixSums<F: PrimeField> {
    pub sum_a: F,
    pub sum_b: F,
    pub sum_c: F,
}

impl<F: PrimeField> MatrixSums<F> {
    /// Iterate over the sums
    pub fn iter(&self) -> impl ExactSizeIterator<Item = F> {
        [self.sum_a, self.sum_b, self.sum_c].into_iter()
    }
}

/// The prover message in the third round.
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ThirdMessage<F: PrimeField> {
    pub sums: Vec<Vec<MatrixSums<F>>>,
}

impl<F: PrimeField> ThirdMessage<F> {
    // Compute the batched sum `sigma` of all the `sigma_{M, i, j}` using the
    // coefficients mu_i (to batch circuits), rho_{i, j} (to batch instances of
    // the same circuit) and (eta_A, eta_B, eta_C) (to batch the three matrices
    // within the same instance).
    pub(crate) fn sum(
        &self,
        batch_combiners: &BTreeMap<CircuitId, BatchCombiners<F>>,
        eta_a: F,
        eta_b: F,
        eta_c: F,
    ) -> F {
        self.sums
            .iter()
            .zip(batch_combiners.values())
            .map(|(circuit_sums, combiners)| {
                combiners.circuit_combiner
                    * circuit_sums
                        .iter()
                        .zip(&combiners.instance_combiners)
                        .map(|(sums, combiner)| {
                            (eta_a * sums.sum_a + eta_b * sums.sum_b + eta_c * sums.sum_c) * combiner
                        })
                        .sum::<F>()
            })
            .sum()
    }
}

impl<F: PrimeField> ToBytes for ThirdMessage<F> {
    fn write_le<W: Write>(&self, mut w: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(self, &mut w)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("Could not serialize ThirdMessage")))
    }
}

/// The prover message in the fourth round.
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FourthMessage<F: PrimeField> {
    pub sums: Vec<MatrixSums<F>>,
}

impl<F: PrimeField> ToBytes for FourthMessage<F> {
    fn write_le<W: Write>(&self, mut w: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(self, &mut w)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("Could not serialize FourthMessage")))
    }
}
