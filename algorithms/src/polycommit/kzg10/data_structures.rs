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
    AlgebraicSponge,
    fft::{DensePolynomial, EvaluationDomain},
};
use snarkvm_curves::{AffineCurve, PairingCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, ToConstraintField, Zero};
use snarkvm_parameters::mainnet::{PowersFile, PowersOfG};
use snarkvm_utilities::{
    FromBytes,
    ToBytes,
    error,
    into_io_error,
    serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate},
};

use crate::srs::{UniversalProver, UniversalVerifier};
use anyhow::Result;
use core::ops::{Add, AddAssign};
use rand::Rng;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    io,
    io::{Read, Write},
    ops::Range,
    sync::Arc,
};

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
#[derive(Clone, Debug)]
pub struct UniversalParams<E: PairingEngine> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to
    /// `degree`, and group elements of the form `{ \beta^i \gamma G }`,
    /// where `i` ranges from 0 to `degree`. This struct provides an
    /// abstraction over the powers which are located on-disk
    /// to reduce memory usage.
    powers: Arc<PowersOfG<E>>,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: <E::G2Affine as PairingCurve>::Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: <E::G2Affine as PairingCurve>::Prepared,
}

impl<E: PairingEngine> UniversalParams<E> {
    pub fn load() -> Result<Self> {
        let powers = Arc::new(PowersOfG::<E>::load()?);
        let h = E::G2Affine::prime_subgroup_generator();
        let prepared_h = h.prepare();
        let prepared_beta_h = powers.beta_h().prepare();

        Ok(Self { powers, h, prepared_h, prepared_beta_h })
    }

    pub fn download_powers_for(&self, range: Range<usize>) -> Result<()> {
        self.powers.download_powers_for(range)
    }

    /// See `PowersOfG::download_powers_for_ends`.
    pub fn download_powers_for_ends(&self, prefix: usize, suffix: usize) -> Result<()> {
        self.powers.download_powers_for_ends(prefix, suffix)
    }

    /// The files this SRS still needs to hold `range`, in the order
    /// `add_powers_file` accepts them. An embedded file is never listed.
    pub fn missing_files_for(&self, range: Range<usize>) -> Result<Vec<PowersFile>> {
        self.powers.missing_files_for(range)
    }

    /// Reads `file` from `reader`, checks its size and checksum, and appends
    /// its powers. A file already held is not read. `reader` need not be
    /// buffered.
    pub fn add_powers_file(&self, file: &PowersFile, reader: impl Read) -> Result<()> {
        self.powers.add_powers_file(file, reader)
    }

    pub fn lagrange_basis(&self, domain: EvaluationDomain<E::Fr>) -> Result<Vec<E::G1Affine>> {
        let basis = domain
            .ifft(&self.powers_of_beta_g(0, domain.size())?.iter().map(|e| (*e).to_projective()).collect::<Vec<_>>());
        Ok(E::G1Projective::batch_normalization_into_affine(basis))
    }

    pub fn power_of_beta_g(&self, index: usize) -> Result<E::G1Affine> {
        self.powers.power_of_beta_g(index)
    }

    pub fn powers_of_beta_g(&self, lower: usize, upper: usize) -> Result<Vec<E::G1Affine>> {
        self.powers.powers_of_beta_g(lower..upper)
    }

    /// The powers in `lower..upper`, as the SRS snapshot holding them and their
    /// range within it, fetched first if needed. The snapshot never changes, so
    /// a key may share it for as long as it lives.
    pub fn shared_powers_of_beta_g(&self, lower: usize, upper: usize) -> Result<(Arc<Vec<E::G1Affine>>, Range<usize>)> {
        self.powers.shared_powers_of_beta_g(lower..upper)
    }

    /// The powers in `lower..upper`, as `shared_powers_of_beta_g` gives them,
    /// if this SRS already holds them; downloads nothing.
    pub fn held_shared_powers_of_beta_g(
        &self,
        lower: usize,
        upper: usize,
    ) -> Option<(Arc<Vec<E::G1Affine>>, Range<usize>)> {
        self.powers.held_shared_powers_of_beta_g(lower..upper)
    }

    pub fn powers_of_beta_times_gamma_g(&self) -> &BTreeMap<usize, E::G1Affine> {
        self.powers.powers_of_beta_gamma_g()
    }

    pub fn beta_h(&self) -> E::G2Affine {
        self.powers.beta_h()
    }

    pub fn max_degree(&self) -> usize {
        self.powers.max_num_powers() - 1
    }

    pub fn to_universal_prover(&self) -> Result<UniversalProver<E>> {
        Ok(UniversalProver::<E> { max_degree: self.max_degree(), _unused: None })
    }

    pub fn to_universal_verifier(&self) -> Result<UniversalVerifier<E>> {
        let g = self.power_of_beta_g(0)?;
        let h = self.h;
        let beta_h = self.beta_h();
        let gamma_g = self.powers_of_beta_times_gamma_g()[&0];
        let prepared_h = self.prepared_h.clone();
        let prepared_beta_h = self.prepared_beta_h.clone();

        Ok(UniversalVerifier {
            vk: VerifierKey::<E> { g, gamma_g, h, beta_h, prepared_h, prepared_beta_h },
            prepared_negative_powers_of_beta_h: self.powers.prepared_negative_powers_of_beta_h(),
        })
    }
}

/// `Powers` is used to commit to and create evaluation proofs for a given
/// polynomial.
#[derive(Clone, Debug, Default, Hash)]
pub struct Powers<'a, E: PairingEngine> {
    /// Group elements of the form `β^i G`, for different values of `i`.
    pub powers_of_beta_g: Cow<'a, [E::G1Affine]>,
    /// Group elements of the form `β^i γG`, for different values of `i`.
    pub powers_of_beta_times_gamma_g: Cow<'a, [E::G1Affine]>,
}

impl<E: PairingEngine> Powers<'_, E> {
    /// The number of powers in `self`.
    pub fn size(&self) -> usize {
        self.powers_of_beta_g.len()
    }
}
/// `LagrangeBasis` is used to commit to and create evaluation proofs for a
/// given polynomial.
#[derive(Clone, Debug, Hash)]
pub struct LagrangeBasis<'a, E: PairingEngine> {
    /// Group elements of the form `β^i G`, for different values of `i`.
    pub lagrange_basis_at_beta_g: Cow<'a, [E::G1Affine]>,
    /// Group elements of the form `β^i γG`, for different values of `i`.
    pub powers_of_beta_times_gamma_g: Cow<'a, [E::G1Affine]>,
    /// Domain representing the multiplicative subgroup the powers
    /// in `self.lagrange_basis_at_beta_g` are defined over.
    pub domain: EvaluationDomain<E::Fr>,
}

impl<E: PairingEngine> LagrangeBasis<'_, E> {
    /// The number of powers in `self`.
    pub fn size(&self) -> usize {
        self.lagrange_basis_at_beta_g.len()
    }
}

/// `VerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifierKey<E: PairingEngine> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G1 that is used for making a commitment hiding.
    pub gamma_g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: <E::G2Affine as PairingCurve>::Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: <E::G2Affine as PairingCurve>::Prepared,
}

impl<E: PairingEngine> CanonicalSerialize for VerifierKey<E> {
    fn serialize_with_mode<W: Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        self.g.serialize_with_mode(&mut writer, compress)?;
        self.gamma_g.serialize_with_mode(&mut writer, compress)?;
        self.h.serialize_with_mode(&mut writer, compress)?;
        self.beta_h.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.g.serialized_size(compress)
            + self.gamma_g.serialized_size(compress)
            + self.h.serialized_size(compress)
            + self.beta_h.serialized_size(compress)
    }
}

impl<E: PairingEngine> CanonicalDeserialize for VerifierKey<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let g = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let gamma_g = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let h: E::G2Affine = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let beta_h: E::G2Affine = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let prepared_h = h.prepare();
        let prepared_beta_h = beta_h.prepare();
        Ok(VerifierKey { g, gamma_g, h, beta_h, prepared_h, prepared_beta_h })
    }
}

impl<E: PairingEngine> Valid for VerifierKey<E> {
    fn check(&self) -> Result<(), SerializationError> {
        Valid::check(&self.g)?;
        Valid::check(&self.gamma_g)?;
        Valid::check(&self.h)?;
        Valid::check(&self.beta_h)?;
        Ok(())
    }

    fn batch_check<'a>(batch: impl Iterator<Item = &'a Self> + Send) -> Result<(), SerializationError>
    where
        Self: 'a,
    {
        let batch: Vec<_> = batch.collect();
        Valid::batch_check(batch.iter().map(|v| &v.g))?;
        Valid::batch_check(batch.iter().map(|v| &v.gamma_g))?;
        Valid::batch_check(batch.iter().map(|v| &v.h))?;
        Valid::batch_check(batch.iter().map(|v| &v.beta_h))?;
        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for VerifierKey<E> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize_compressed(&mut reader)
            .map_err(|_| error("could not deserialize VerifierKey"))
    }
}

impl<E: PairingEngine> ToBytes for VerifierKey<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(self, &mut writer)
            .map_err(|_| error("could not serialize VerifierKey"))
    }
}

/// `KZGCommitment` commits to a polynomial. It is output by `KZG10::commit`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGCommitment<E: PairingEngine>(
    /// The commitment is a group element.
    pub E::G1Affine,
);

impl<E: PairingEngine> FromBytes for KZGCommitment<E> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize_compressed(&mut reader)
            .map_err(|_| error("could not deserialize KZGCommitment"))
    }
}

impl<E: PairingEngine> ToBytes for KZGCommitment<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(self, &mut writer)
            .map_err(|_| error("could not serialize KZGCommitment"))
    }
}

impl<E: PairingEngine> KZGCommitment<E> {
    #[inline]
    pub fn empty() -> Self {
        KZGCommitment(E::G1Affine::zero())
    }

    pub fn has_degree_bound(&self) -> bool {
        false
    }

    pub fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
        self.0.is_in_correct_subgroup_assuming_on_curve()
    }
}

impl<E: PairingEngine> ToConstraintField<E::Fq> for KZGCommitment<E> {
    fn to_field_elements(&self) -> Result<Vec<E::Fq>, ConstraintFieldError> {
        self.0.to_field_elements()
    }
}

/// `KZGRandomness` hides the polynomial inside a commitment. It is output by
/// `KZG10::commit`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGRandomness<E: PairingEngine> {
    /// For KZG10, the commitment randomness is a random polynomial.
    pub blinding_polynomial: DensePolynomial<E::Fr>,
}
impl<E: PairingEngine> FromBytes for KZGRandomness<E> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize_compressed(&mut reader)
            .map_err(|_| error("could not deserialize KZGRandomness"))
    }
}

impl<E: PairingEngine> ToBytes for KZGRandomness<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(self, &mut writer)
            .map_err(|_| error("could not serialize KZGRandomness"))
    }
}

impl<E: PairingEngine> KZGRandomness<E> {
    /// Does `self` provide any hiding properties to the corresponding
    /// commitment? `self.is_hiding() == true` only if the underlying
    /// polynomial is non-zero.
    #[inline]
    pub fn is_hiding(&self) -> bool {
        !self.blinding_polynomial.is_zero()
    }

    /// What is the degree of the hiding polynomial for a given hiding bound?
    #[inline]
    pub fn calculate_hiding_polynomial_degree(hiding_bound: usize) -> usize {
        hiding_bound + 1
    }
}

impl<E: PairingEngine> KZGRandomness<E> {
    pub fn empty() -> Self {
        Self { blinding_polynomial: DensePolynomial::zero() }
    }

    pub fn rand<R: Rng>(hiding_bound: usize, _: bool, rng: &mut R) -> Self {
        let mut randomness = KZGRandomness::empty();
        let hiding_poly_degree = Self::calculate_hiding_polynomial_degree(hiding_bound);
        randomness.blinding_polynomial = DensePolynomial::rand(hiding_poly_degree, rng);
        randomness
    }
}

impl<'a, E: PairingEngine> Add<&'a KZGRandomness<E>> for KZGRandomness<E> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &'a Self) -> Self {
        self.blinding_polynomial += &other.blinding_polynomial;
        self
    }
}

impl<'a, E: PairingEngine> Add<(E::Fr, &'a KZGRandomness<E>)> for KZGRandomness<E> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: (E::Fr, &'a KZGRandomness<E>)) -> Self {
        self += other;
        self
    }
}

impl<'a, E: PairingEngine> AddAssign<&'a KZGRandomness<E>> for KZGRandomness<E> {
    #[inline]
    fn add_assign(&mut self, other: &'a Self) {
        self.blinding_polynomial += &other.blinding_polynomial;
    }
}

impl<'a, E: PairingEngine> AddAssign<(E::Fr, &'a KZGRandomness<E>)> for KZGRandomness<E> {
    #[inline]
    fn add_assign(&mut self, (f, other): (E::Fr, &'a KZGRandomness<E>)) {
        self.blinding_polynomial += (f, &other.blinding_polynomial);
    }
}

/// `KZGProof` is an evaluation proof that is output by `KZG10::open`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGProof<E: PairingEngine> {
    /// This is a commitment to the witness polynomial; see [\[KZG10\]][kzg] for
    /// more details.
    ///
    /// [kzg]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
    pub w: E::G1Affine,
    /// This is the evaluation of the random polynomial at the point for which
    /// the evaluation proof was produced.
    pub random_v: Option<E::Fr>,
}

impl<E: PairingEngine> KZGProof<E> {
    pub fn absorb_into_sponge(&self, sponge: &mut impl AlgebraicSponge<E::Fq, 2>) {
        sponge.absorb_native_field_elements(&self.w.to_field_elements().unwrap());
        if let Some(random_v) = self.random_v {
            sponge.absorb_nonnative_field_elements([random_v]);
        }
    }
}

impl<E: PairingEngine> FromBytes for KZGProof<E> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize_compressed(&mut reader)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not deserialize KZG proof")))
    }
}

impl<E: PairingEngine> ToBytes for KZGProof<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(self, &mut writer)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not serialize KZG proof")))
    }
}

impl<E: PairingEngine> KZGProof<E> {
    pub fn is_hiding(&self) -> bool {
        self.random_v.is_some()
    }
}
