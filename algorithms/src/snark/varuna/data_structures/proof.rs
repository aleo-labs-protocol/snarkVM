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
    SNARKError,
    polycommit::{kzg10::KZGCommitment, sonic_pc},
    snark::varuna::{CircuitId, VarunaVersion, ahp},
};

use ahp::prover::{FourthMessage, ThirdMessage};
use snarkvm_curves::PairingEngine;
use snarkvm_fields::{One, PrimeField};
use snarkvm_utilities::{FromBytes, ToBytes, into_io_error, serialize::*};

use anyhow::{Result, anyhow};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
};

use std::mem::size_of;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitments<E: PairingEngine> {
    pub witness_commitments: Vec<WitnessCommitments<E>>,
    /// Commitment to the masking polynomial.
    pub mask_poly: Option<sonic_pc::Commitment<E>>,
    /// Commitment to the `h_0` polynomial.
    pub h_0: sonic_pc::Commitment<E>,
    /// Commitment to the `g_1` polynomial.
    pub g_1: sonic_pc::Commitment<E>,
    /// Commitment to the `h_1` polynomial.
    pub h_1: sonic_pc::Commitment<E>,
    /// Commitment to the `g_a` polynomials.
    pub g_a_commitments: Vec<sonic_pc::Commitment<E>>,
    /// Commitment to the `g_b` polynomials.
    pub g_b_commitments: Vec<sonic_pc::Commitment<E>>,
    /// Commitment to the `g_c` polynomials.
    pub g_c_commitments: Vec<sonic_pc::Commitment<E>>,
    /// Commitment to the `h_2` polynomial.
    pub h_2: sonic_pc::Commitment<E>,
}

impl<E: PairingEngine> Commitments<E> {
    fn serialize_with_mode<W: snarkvm_utilities::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), snarkvm_utilities::SerializationError> {
        serialize_vec_without_len(self.witness_commitments.iter(), &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.mask_poly, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.h_0, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.g_1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.h_1, &mut writer, compress)?;
        serialize_vec_without_len(self.g_a_commitments.iter(), &mut writer, compress)?;
        serialize_vec_without_len(self.g_b_commitments.iter(), &mut writer, compress)?;
        serialize_vec_without_len(self.g_c_commitments.iter(), &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.h_2, &mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        serialized_vec_size_without_len(&self.witness_commitments, compress)
            .saturating_add(CanonicalSerialize::serialized_size(&self.mask_poly, compress))
            .saturating_add(CanonicalSerialize::serialized_size(&self.h_0, compress))
            .saturating_add(CanonicalSerialize::serialized_size(&self.g_1, compress))
            .saturating_add(CanonicalSerialize::serialized_size(&self.h_1, compress))
            .saturating_add(serialized_vec_size_without_len(&self.g_a_commitments, compress))
            .saturating_add(serialized_vec_size_without_len(&self.g_b_commitments, compress))
            .saturating_add(serialized_vec_size_without_len(&self.g_c_commitments, compress))
            .saturating_add(CanonicalSerialize::serialized_size(&self.h_2, compress))
    }

    fn deserialize_with_mode<R: snarkvm_utilities::Read>(
        batch_sizes: &[usize],
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, snarkvm_utilities::SerializationError> {
        let mut w = Vec::new();
        for batch_size in batch_sizes {
            w.extend(deserialize_vec_without_len(&mut reader, compress, validate, *batch_size)?);
        }
        Ok(Commitments {
            witness_commitments: w,
            mask_poly: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            h_0: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            g_1: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            h_1: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            g_a_commitments: deserialize_vec_without_len(&mut reader, compress, validate, batch_sizes.len())?,
            g_b_commitments: deserialize_vec_without_len(&mut reader, compress, validate, batch_sizes.len())?,
            g_c_commitments: deserialize_vec_without_len(&mut reader, compress, validate, batch_sizes.len())?,
            h_2: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
        })
    }
}
/// Commitments to the `w` polynomials.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct WitnessCommitments<E: PairingEngine> {
    /// Commitment to the `w` polynomial.
    pub w: sonic_pc::Commitment<E>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluations<F: PrimeField> {
    /// Evaluation of `g_1` at `beta`.
    pub g_1_eval: F,
    /// Evaluation of `g_a_i`'s at `beta`.
    pub g_a_evals: Vec<F>,
    /// Evaluation of `g_b_i`'s at `gamma`.
    pub g_b_evals: Vec<F>,
    /// Evaluation of `g_c_i`'s at `gamma`.
    pub g_c_evals: Vec<F>,
}

impl<F: PrimeField> Evaluations<F> {
    fn serialize_with_mode<W: snarkvm_utilities::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), snarkvm_utilities::SerializationError> {
        CanonicalSerialize::serialize_with_mode(&self.g_1_eval, &mut writer, compress)?;
        serialize_vec_without_len(self.g_a_evals.iter(), &mut writer, compress)?;
        serialize_vec_without_len(self.g_b_evals.iter(), &mut writer, compress)?;
        serialize_vec_without_len(self.g_c_evals.iter(), &mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        CanonicalSerialize::serialized_size(&self.g_1_eval, compress)
            .saturating_add(serialized_vec_size_without_len(&self.g_a_evals, compress))
            .saturating_add(serialized_vec_size_without_len(&self.g_b_evals, compress))
            .saturating_add(serialized_vec_size_without_len(&self.g_c_evals, compress))
    }

    fn deserialize_with_mode<R: snarkvm_utilities::Read>(
        batch_sizes: &[usize],
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, snarkvm_utilities::SerializationError> {
        Ok(Evaluations {
            g_1_eval: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            g_a_evals: deserialize_vec_without_len(&mut reader, compress, validate, batch_sizes.len())?,
            g_b_evals: deserialize_vec_without_len(&mut reader, compress, validate, batch_sizes.len())?,
            g_c_evals: deserialize_vec_without_len(&mut reader, compress, validate, batch_sizes.len())?,
        })
    }
}

impl<F: PrimeField> Evaluations<F> {
    pub(crate) fn from_map(
        map: &std::collections::BTreeMap<String, F>,
        batch_sizes: BTreeMap<CircuitId, usize>,
    ) -> Self {
        let mut g_a_evals = Vec::with_capacity(batch_sizes.len());
        let mut g_b_evals = Vec::with_capacity(batch_sizes.len());
        let mut g_c_evals = Vec::with_capacity(batch_sizes.len());

        for (label, value) in map {
            if label == "g_1" {
                continue;
            }

            if label.contains("g_a") {
                g_a_evals.push(*value);
            } else if label.contains("g_b") {
                g_b_evals.push(*value);
            } else if label.contains("g_c") {
                g_c_evals.push(*value);
            }
        }
        Self { g_1_eval: map["g_1"], g_a_evals, g_b_evals, g_c_evals }
    }

    pub(crate) fn get(&self, circuit_index: usize, label: &str) -> Option<F> {
        if label == "g_1" {
            return Some(self.g_1_eval);
        }

        if label.contains("g_a") {
            self.g_a_evals.get(circuit_index).copied()
        } else if label.contains("g_b") {
            self.g_b_evals.get(circuit_index).copied()
        } else if label.contains("g_c") {
            self.g_c_evals.get(circuit_index).copied()
        } else {
            None
        }
    }

    pub fn to_field_elements(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(1 + self.g_a_evals.len() + self.g_b_evals.len() + self.g_c_evals.len());
        result.push(self.g_1_eval);
        result.extend_from_slice(&self.g_a_evals);
        result.extend_from_slice(&self.g_b_evals);
        result.extend_from_slice(&self.g_c_evals);
        result
    }
}

impl<F: PrimeField> Valid for Evaluations<F> {
    fn check(&self) -> Result<(), snarkvm_utilities::SerializationError> {
        self.g_1_eval.check()?;
        self.g_a_evals.check()?;
        self.g_b_evals.check()?;
        self.g_c_evals.check()
    }
}

/// A zkSNARK proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<E: PairingEngine> {
    /// The number of instances being proven in this proof.
    batch_sizes: Vec<usize>,

    /// Commitments to prover polynomials.
    pub commitments: Commitments<E>,

    /// Evaluations of some of the committed polynomials.
    pub evaluations: Evaluations<E::Fr>,

    /// Prover message: sum_a, sum_b, sum_c for each instance
    pub third_msg: ThirdMessage<E::Fr>,

    /// Prover message: sum_a, sum_b, sum_c for each circuit
    pub fourth_msg: FourthMessage<E::Fr>,

    /// An evaluation proof from the polynomial commitment.
    pub pc_proof: sonic_pc::BatchLCProof<E>,
}

impl<E: PairingEngine> Proof<E> {
    /// Construct a new proof.
    pub fn new(
        batch_sizes: BTreeMap<CircuitId, usize>,
        commitments: Commitments<E>,
        evaluations: Evaluations<E::Fr>,
        third_msg: ThirdMessage<E::Fr>,
        fourth_msg: FourthMessage<E::Fr>,
        pc_proof: sonic_pc::BatchLCProof<E>,
    ) -> Result<Self, SNARKError> {
        let batch_sizes: Vec<usize> = batch_sizes.into_values().collect();
        Ok(Self { batch_sizes, commitments, evaluations, third_msg, fourth_msg, pc_proof })
    }

    pub fn is_hiding(&self) -> bool {
        self.pc_proof.is_hiding()
    }

    pub fn batch_sizes(&self) -> &[usize] {
        &self.batch_sizes
    }

    /// Check that the number of messages is consistent with our batch size
    pub fn check_batch_sizes(&self) -> Result<(), SNARKError> {
        let total_instances = self
            .batch_sizes
            .iter()
            .try_fold(0usize, |acc, &size| acc.checked_add(size))
            .ok_or(SNARKError::BatchSizeMismatch)?;
        if self.commitments.witness_commitments.len() != total_instances {
            return Err(SNARKError::BatchSizeMismatch);
        }
        let g_comms =
            [&self.commitments.g_a_commitments, &self.commitments.g_b_commitments, &self.commitments.g_c_commitments];
        for comms in g_comms {
            if comms.len() != self.batch_sizes.len() {
                return Err(SNARKError::BatchSizeMismatch);
            }
        }
        let g_evals = [&self.evaluations.g_a_evals, &self.evaluations.g_b_evals, &self.evaluations.g_c_evals];
        for evals in g_evals {
            if evals.len() != self.batch_sizes.len() {
                return Err(SNARKError::BatchSizeMismatch);
            }
        }
        if self.third_msg.sums.len() != self.batch_sizes.len() {
            return Err(SNARKError::BatchSizeMismatch);
        }
        for (msg, &batch_size) in self.third_msg.sums.iter().zip(self.batch_sizes.iter()) {
            if msg.len() != batch_size {
                return Err(SNARKError::BatchSizeMismatch);
            }
        }
        if self.fourth_msg.sums.len() != self.batch_sizes.len() {
            return Err(SNARKError::BatchSizeMismatch);
        }
        Ok(())
    }
}

impl<E: PairingEngine> CanonicalSerialize for Proof<E> {
    fn serialize_with_mode<W: Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        let batch_sizes: Vec<u64> = self.batch_sizes.iter().map(|x| u64::try_from(*x)).collect::<Result<_, _>>()?;
        CanonicalSerialize::serialize_with_mode(&batch_sizes, &mut writer, compress)?;
        Commitments::serialize_with_mode(&self.commitments, &mut writer, compress)?;
        Evaluations::serialize_with_mode(&self.evaluations, &mut writer, compress)?;
        for third_sums in self.third_msg.sums.iter() {
            serialize_vec_without_len(third_sums.iter(), &mut writer, compress)?;
        }
        serialize_vec_without_len(self.fourth_msg.sums.iter(), &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.pc_proof, &mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, mode: Compress) -> usize {
        let mut size = 0;
        size += CanonicalSerialize::serialized_size(&self.batch_sizes, mode);
        size += Commitments::serialized_size(&self.commitments, mode);
        size += Evaluations::serialized_size(&self.evaluations, mode);
        for third_sums in self.third_msg.sums.iter() {
            size += serialized_vec_size_without_len(third_sums, mode);
        }
        size += serialized_vec_size_without_len(&self.fourth_msg.sums, mode);
        size += CanonicalSerialize::serialized_size(&self.pc_proof, mode);
        size
    }
}

impl<E: PairingEngine> Valid for Proof<E> {
    fn check(&self) -> Result<(), SerializationError> {
        self.batch_sizes.check()?;
        self.commitments.check()?;
        self.evaluations.check()?;
        self.third_msg.check()?;
        self.fourth_msg.check()?;
        self.pc_proof.check()
    }
}

impl<E: PairingEngine> CanonicalDeserialize for Proof<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let batch_sizes: Vec<u64> = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let batch_sizes: Vec<usize> = batch_sizes.into_iter().map(|x| x as usize).collect();
        let commitments = Commitments::deserialize_with_mode(&batch_sizes, &mut reader, compress, validate)?;
        let evaluations = Evaluations::deserialize_with_mode(&batch_sizes, &mut reader, compress, validate)?;
        let third_msg_sums = batch_sizes
            .iter()
            .map(|&batch_size| deserialize_vec_without_len(&mut reader, compress, validate, batch_size))
            .collect::<Result<Vec<_>, _>>()?;
        let fourth_msg_sums = deserialize_vec_without_len(&mut reader, compress, validate, batch_sizes.len())?;
        Ok(Proof {
            commitments,
            evaluations,
            third_msg: ThirdMessage { sums: third_msg_sums },
            fourth_msg: FourthMessage { sums: fourth_msg_sums },
            pc_proof: CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?,
            batch_sizes,
        })
    }
}

impl<E: PairingEngine> ToBytes for Proof<E> {
    fn write_le<W: Write>(&self, mut w: W) -> io::Result<()> {
        Self::serialize_compressed(self, &mut w)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not serialize Proof")))
    }
}

impl<E: PairingEngine> FromBytes for Proof<E> {
    fn read_le<R: Read>(mut r: R) -> io::Result<Self> {
        Self::deserialize_compressed(&mut r)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not deserialize Proof")))
    }

    fn read_le_unchecked<R: Read>(mut r: R) -> io::Result<Self> {
        Self::deserialize_compressed_unchecked(&mut r)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not deserialize Proof")))
    }
}

/// Computes the size in bytes of a Varuna proof as produced by
/// `Proof::serialize_compressed` without needing to receive the proof itself.
///
/// *Arguments*:
///  - `batch_sizes`: the batch sizes of the circuits and instances being
///    proved.
///  - `varuna_version`: the version of Varuna being used
///  - `hiding`: indicates whether the proof system is run in ZK mode
///
/// *Returns*:
///  - `Ok(size)` for `VarunaVersion::V2` and `VarunaVersion::V3`, where `size`
///    is the size of the proof in bytes.
///  - `Err` for `VarunaVersion::V1`.
pub fn proof_size<E: PairingEngine>(
    batch_sizes: &[usize],
    varuna_version: VarunaVersion,
    hiding: bool,
) -> Result<usize> {
    let n_circuits: usize = batch_sizes.len();
    let n_instances: usize = batch_sizes.iter().sum();

    match varuna_version {
        VarunaVersion::V1 => Err(anyhow!("Proof-size calculation not implemented for Varuna version V1")),
        VarunaVersion::V2 | VarunaVersion::V3 => {
            // All fields are serialised in Compressed mode The breakdown is as
            // follows:
            // - batch sizes: one `usize` (which is serialised as a `u64`) for each batch
            //   size, plus one `u64` for the number of batches. This contains the size
            //   information for the vectors in all other fields, which are therefore
            //   serialised without their length prefix.
            // - commitments:
            //   + witness_commitments: n_instances commitments
            //   + mask_poly: 1 byte to encode the enum tag (a bool) plus one commitment if
            //     the variant is Some (if and only if the proof system is run in ZK mode)
            //   + h_0, g_1, g_2, h_2: four commitments
            //   + g_a, g_b, g_c: 3 * n_circuits commitments
            // - evaluations:
            //   + g_1_eval: one field element
            //   + g_a_evals, g_b_evals, g_c_evals: 3 * n_circuits field elements
            // - third_msg:
            //   + 3 * n_instances field elements
            // - fourth_msg:
            //   + 3 * n_circuits field elements
            // - pc_proof:
            //   + one usize for the size of the vector (which is always 3)
            //   + three of [1 commitment + 1 bool (for the Option tag) + {1 field element
            //     if the variant is Some (if and only if the proof system is run in ZK
            //     mode)}]

            let n_bool = 1;
            let n_u64 = 1;
            let n_field_elements = 1 + 6 * n_circuits + 3 * n_instances;
            let n_commitments = 4 + n_instances + (if hiding { 1 } else { 0 }) + 3 * n_circuits;

            // The next three sizes are const functions
            let size_bool = size_of::<bool>();
            let size_u64 = size_of::<u64>();

            // The next two can be hard-coded if performance becomes critical
            // and they are considered fully stable. They are 32 and 48 bytes at
            // the time of writing, respectively (commitments are affine points
            // written in compressed form).
            let size_field_element = E::Fr::one().compressed_size();
            let size_commitment = KZGCommitment::<E>::empty().compressed_size();

            let size_pc_proof = size_u64 + 3 * (size_commitment + 1) + if hiding { size_field_element } else { 0 };

            Ok(n_bool * size_bool
                + (n_u64 + batch_sizes.len()) * size_u64
                + n_field_elements * size_field_element
                + n_commitments * size_commitment
                + size_pc_proof)
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(non_camel_case_types)]

    use super::*;

    use crate::{
        polycommit::{
            kzg10::{KZGCommitment, KZGProof},
            sonic_pc::BatchProof,
        },
        snark::varuna::prover::MatrixSums,
    };
    use snarkvm_curves::{
        AffineCurve,
        bls12_377::{Bls12_377, Fr, G1Affine},
    };
    use snarkvm_utilities::{TestRng, Uniform};

    const fn modes() -> [(Compress, Validate); 4] {
        [
            (Compress::No, Validate::No),
            (Compress::Yes, Validate::No),
            (Compress::No, Validate::Yes),
            (Compress::Yes, Validate::Yes),
        ]
    }

    fn sample_commit() -> KZGCommitment<Bls12_377> {
        let buf = G1Affine::prime_subgroup_generator().to_bytes_le().unwrap();
        FromBytes::read_le(buf.as_slice()).unwrap()
    }

    fn rand_commitments(j: usize, i: usize, test_with_none: bool) -> Commitments<Bls12_377> {
        assert!(i > 0);
        assert!(j > 0);
        let sample_commit = sample_commit();
        let mask_poly = if test_with_none { None } else { Some(sample_commit) };
        Commitments {
            witness_commitments: vec![WitnessCommitments { w: sample_commit }; i * j],
            mask_poly,
            h_0: sample_commit,
            g_1: sample_commit,
            h_1: sample_commit,
            g_a_commitments: vec![sample_commit; i],
            g_b_commitments: vec![sample_commit; i],
            g_c_commitments: vec![sample_commit; i],
            h_2: sample_commit,
        }
    }

    fn rand_evaluations<F: PrimeField>(rng: &mut TestRng, i: usize) -> Evaluations<F> {
        Evaluations {
            g_1_eval: F::rand(rng),
            g_a_evals: (0..i).map(|_| F::rand(rng)).collect(),
            g_b_evals: (0..i).map(|_| F::rand(rng)).collect(),
            g_c_evals: (0..i).map(|_| F::rand(rng)).collect(),
        }
    }

    fn rand_sums<F: PrimeField>(rng: &mut TestRng) -> MatrixSums<F> {
        MatrixSums::<F> { sum_a: F::rand(rng), sum_b: F::rand(rng), sum_c: F::rand(rng) }
    }

    fn rand_kzg_proof(rng: &mut TestRng, test_with_none: bool) -> KZGProof<Bls12_377> {
        let random_v = if test_with_none { None } else { Some(Fr::rand(rng)) };
        KZGProof::<Bls12_377> { w: G1Affine::prime_subgroup_generator(), random_v }
    }

    #[test]
    fn test_serializing_commitments() {
        for i in 1..11 {
            for j in 1..11 {
                let test_with_none = i * j % 2 == 0;
                let commitments = rand_commitments(j, i, test_with_none);
                let batch_sizes = vec![j; i];
                let combinations = modes();
                for (compress, validate) in combinations {
                    let size = Commitments::serialized_size(&commitments, compress);
                    let mut serialized = vec![0; size];
                    Commitments::serialize_with_mode(&commitments, &mut serialized[..], compress).unwrap();
                    let de =
                        Commitments::deserialize_with_mode(&batch_sizes, &serialized[..], compress, validate).unwrap();
                    assert_eq!(commitments, de);
                }
            }
        }
    }

    #[test]
    fn test_serializing_evaluations() {
        let rng = &mut TestRng::default();

        for i in 1..11 {
            for j in 1..11 {
                let evaluations: Evaluations<Fr> = rand_evaluations(rng, i);
                let batch_sizes = vec![j; i];
                let combinations = modes();
                for (compress, validate) in combinations {
                    let size = Evaluations::serialized_size(&evaluations, compress);
                    let mut serialized = vec![0; size];
                    Evaluations::serialize_with_mode(&evaluations, &mut serialized[..], compress).unwrap();
                    let de =
                        Evaluations::deserialize_with_mode(&batch_sizes, &serialized[..], compress, validate).unwrap();
                    assert_eq!(evaluations, de);
                }
            }
        }
    }

    #[test]
    fn test_serializing_proof() {
        let rng = &mut snarkvm_utilities::rand::TestRng::default();

        for i in 1..11 {
            for j in 1..11 {
                let test_with_none = i * j % 2 == 0;
                let batch_sizes = vec![j; i];
                let commitments = rand_commitments(j, i, test_with_none);
                let evaluations: Evaluations<Fr> = rand_evaluations(rng, i);
                let third_msg = ThirdMessage::<Fr> { sums: vec![vec![rand_sums(rng); j]; i] };
                let fourth_msg = FourthMessage::<Fr> { sums: vec![rand_sums(rng); i] };
                let pc_proof =
                    sonic_pc::BatchLCProof { proof: BatchProof(vec![rand_kzg_proof(rng, test_with_none); j]) };
                let proof = Proof { batch_sizes, commitments, evaluations, third_msg, fourth_msg, pc_proof };
                let combinations = modes();
                for (compress, validate) in combinations {
                    let size = Proof::serialized_size(&proof, compress);
                    let mut serialized = vec![0; size];
                    Proof::serialize_with_mode(&proof, &mut serialized[..], compress).unwrap();
                    let de = Proof::deserialize_with_mode(&serialized[..], compress, validate).unwrap();
                    assert_eq!(proof, de);
                }
            }
        }
    }
}
