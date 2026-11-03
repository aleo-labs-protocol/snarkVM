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

use crate::{PoseidonGrainLFSR, PrimeField, serial_batch_inversion_and_mul};
use aleo_std::{end_timer, start_timer};
use itertools::Itertools;
use snarkvm_utilities::defer;

use anyhow::{Result, bail};

/// Parameters and RNG used
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonParameters<F: PrimeField, const RATE: usize, const CAPACITY: usize> {
    /// number of rounds in a full-round operation
    pub full_rounds: usize,
    /// number of rounds in a partial-round operation
    pub partial_rounds: usize,
    /// Exponent used in S-boxes
    pub alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    pub ark: Vec<Vec<F>>,
    /// Maximally Distance Separating Matrix.
    pub mds: Vec<Vec<F>>,
}

/// A field with Poseidon parameters associated
pub trait PoseidonDefaultField {
    /// Obtain the default Poseidon parameters for this rate and for this prime field,
    /// with a specific optimization goal.
    fn default_poseidon_parameters<const RATE: usize>() -> Result<PoseidonParameters<Self, RATE, 1>>
    where
        Self: PrimeField,
    {
        /// Internal function that computes the ark and mds from the Poseidon Grain LFSR.
        #[allow(clippy::type_complexity)]
        fn find_poseidon_ark_and_mds<F: PrimeField, const RATE: usize>(
            full_rounds: u64,
            partial_rounds: u64,
            skip_matrices: u64,
        ) -> Result<(Vec<Vec<F>>, Vec<Vec<F>>)> {
            let lfsr_time = start_timer!(|| "LFSR Init");
            let mut lfsr =
                PoseidonGrainLFSR::new(false, F::size_in_bits() as u64, (RATE + 1) as u64, full_rounds, partial_rounds);
            end_timer!(lfsr_time);

            let ark = {
                let ark_time = start_timer!(|| "Constructing ARK");
                defer! { end_timer!(ark_time); }
                let mut ark = Vec::with_capacity((full_rounds + partial_rounds) as usize);
                for _ in 0..(full_rounds + partial_rounds) {
                    ark.push(lfsr.get_field_elements_rejection_sampling(RATE + 1)?);
                }
                ark
            };

            {
                let skip_time = start_timer!(|| "Skipping matrices");
                defer! { end_timer!(skip_time); }
                for _ in 0..skip_matrices {
                    let _ = lfsr.get_field_elements_mod_p::<F>(2 * (RATE + 1))?;
                }
            }

            // A qualifying matrix must satisfy the following requirements:
            // - There is no duplication among the elements in x or y.
            // - There is no i and j such that x[i] + y[j] = p.
            // - There resultant MDS passes all three tests.

            let xs = lfsr.get_field_elements_mod_p::<F>(RATE + 1)?;
            let ys = lfsr.get_field_elements_mod_p::<F>(RATE + 1)?;

            let mds_time = start_timer!(|| "Construct MDS");
            let mut mds_flattened = vec![F::zero(); (RATE + 1) * (RATE + 1)];
            for (x, mds_row_i) in xs.iter().take(RATE + 1).zip_eq(mds_flattened.chunks_mut(RATE + 1)) {
                for (y, e) in ys.iter().take(RATE + 1).zip_eq(mds_row_i) {
                    *e = *x + y;
                }
            }
            serial_batch_inversion_and_mul(&mut mds_flattened, &F::one());
            let mds = mds_flattened.chunks(RATE + 1).map(|row| row.to_vec()).collect();
            end_timer!(mds_time);

            Ok((ark, mds))
        }

        match Self::Parameters::PARAMS_OPT_FOR_CONSTRAINTS.iter().find(|entry| entry.rate == RATE) {
            Some(entry) => {
                let (ark, mds) = find_poseidon_ark_and_mds::<Self, RATE>(
                    entry.full_rounds as u64,
                    entry.partial_rounds as u64,
                    entry.skip_matrices as u64,
                )?;
                Ok(PoseidonParameters {
                    full_rounds: entry.full_rounds,
                    partial_rounds: entry.partial_rounds,
                    alpha: entry.alpha as u64,
                    ark,
                    mds,
                })
            }
            None => bail!("No Poseidon parameters were found for this rate"),
        }
    }
}

/// A trait for default Poseidon parameters associated with a prime field
pub trait PoseidonDefaultParameters {
    /// An array of the parameters optimized for constraints
    /// (rate, alpha, full_rounds, partial_rounds, skip_matrices)
    /// for rate = 2, 3, 4, 5, 6, 7, 8
    ///
    /// Here, `skip_matrices` denote how many matrices to skip before
    /// finding one that satisfy all the requirements.
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultParametersEntry; 7];
}

/// An entry in the default Poseidon parameters
pub struct PoseidonDefaultParametersEntry {
    /// The rate (in terms of number of field elements).
    pub rate: usize,
    /// Exponent used in S-boxes.
    pub alpha: usize,
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Number of matrices to skip when generating parameters using the Grain LFSR.
    ///
    /// The matrices being skipped are those that do not satisfy all the desired properties.
    /// See the [reference implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage) for more detail.
    pub skip_matrices: usize,
}

impl PoseidonDefaultParametersEntry {
    /// Create an entry in PoseidonDefaultParameters.
    pub const fn new(
        rate: usize,
        alpha: usize,
        full_rounds: usize,
        partial_rounds: usize,
        skip_matrices: usize,
    ) -> Self {
        Self { rate, alpha, full_rounds, partial_rounds, skip_matrices }
    }
}
