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

use super::{LabeledPolynomial, PolynomialInfo};
use crate::{crypto_hash::sha256::Sha256Writer, fft::EvaluationDomain, polycommit::kzg10};
use snarkvm_curves::{AffineCurve, PairingEngine};
use snarkvm_fields::{ConstraintFieldError, Field, PrimeField, ToConstraintField};
use snarkvm_parameters::mainnet::MAX_NUM_POWERS;
use snarkvm_utilities::{FromBytes, ToBytes, error, into_io_error, serialize::*};

use hashbrown::HashMap;
use std::{
    borrow::{Borrow, Cow},
    collections::{BTreeMap, BTreeSet},
    fmt,
    io,
    ops::{AddAssign, Deref, MulAssign, Range, SubAssign},
    sync::Arc,
};

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
pub type UniversalParams<E> = kzg10::UniversalParams<E>;

/// `Randomness` is the randomness for the KZG10 scheme.
pub type Randomness<E> = kzg10::KZGRandomness<E>;

/// `Commitment` is the commitment for the KZG10 scheme.
pub type Commitment<E> = kzg10::KZGCommitment<E>;

/// A committer key's bases: points it owns, or a range of an SRS snapshot it
/// shares. A snapshot never changes once made, so a shared range stays valid
/// for as long as the key holds it.
#[derive(Clone)]
pub enum Bases<G> {
    Owned(Vec<G>),
    Shared { store: Arc<Vec<G>>, range: Range<usize> },
}

/// The key's own points, not the whole snapshot a shared range is cut from,
/// which can be millions of them.
impl<G: fmt::Debug> fmt::Debug for Bases<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<G> Deref for Bases<G> {
    type Target = [G];

    fn deref(&self) -> &[G] {
        match self {
            Self::Owned(points) => points,
            Self::Shared { store, range } => &store[range.clone()],
        }
    }
}

impl<G> Bases<G> {
    /// A range of `store`, checked here rather than on first use.
    pub fn shared(store: Arc<Vec<G>>, range: Range<usize>) -> Self {
        assert!(
            range.start <= range.end && range.end <= store.len(),
            "a shared range {range:?} outside a snapshot of {} points",
            store.len()
        );
        Self::Shared { store, range }
    }
}

impl<G: Clone> Bases<G> {
    /// Points this key allocated itself: none when it shares them, which is
    /// what a key cache should budget for. A shared key can still keep an
    /// older snapshot alive after the SRS grows past it; that is bounded by
    /// the SRS, not by the key, and is not counted here.
    pub fn owned_capacity(&self) -> usize {
        match self {
            Self::Owned(points) => points.capacity(),
            Self::Shared { .. } => 0,
        }
    }

    /// The points, to edit; a shared range becomes an owned copy first.
    pub fn to_mut(&mut self) -> &mut Vec<G> {
        if let Self::Shared { .. } = self {
            *self = Self::Owned(self.to_vec());
        }
        match self {
            Self::Owned(points) => points,
            Self::Shared { .. } => unreachable!("made owned above"),
        }
    }
}

/// Written as a `Vec` of the points is, so a key's bytes and hash don't depend
/// on whether it shares them.
impl<G: ToBytes> ToBytes for Bases<G> {
    fn write_le<W: Write>(&self, writer: W) -> io::Result<()> {
        (&**self).write_le(writer)
    }
}

impl<G> From<Vec<G>> for Bases<G> {
    fn from(points: Vec<G>) -> Self {
        Self::Owned(points)
    }
}

/// `CommitterKey` is used to commit to, and create evaluation proofs for, a
/// given polynomial.
#[derive(Debug)]
pub struct CommitterKey<E: PairingEngine> {
    /// The key used to commit to polynomials.
    pub powers_of_beta_g: Bases<E::G1Affine>,

    /// The key used to commit to polynomials in Lagrange basis.
    pub lagrange_bases_at_beta_g: BTreeMap<usize, Vec<E::G1Affine>>,

    /// The key used to commit to hiding polynomials.
    pub powers_of_beta_times_gamma_g: Vec<E::G1Affine>,

    /// The powers used to commit to shifted polynomials.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub shifted_powers_of_beta_g: Option<Bases<E::G1Affine>>,

    /// The powers used to commit to shifted hiding polynomials.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub shifted_powers_of_beta_times_gamma_g: Option<BTreeMap<usize, Vec<E::G1Affine>>>,

    /// The degree bounds that are supported by `self`.
    /// Sorted in ascending order from smallest bound to largest bound.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub enforced_degree_bounds: Option<Vec<usize>>,
}

impl<E: PairingEngine> FromBytes for CommitterKey<E> {
    fn read_le<R: Read>(reader: R) -> io::Result<Self> {
        Self::read_le_sharing(reader, None)
    }
}

impl<E: PairingEngine> CommitterKey<E> {
    /// Reads the bytes `read_le` reads, but shares both ends of the powers of
    /// beta G with `srs`, skipping those points in `reader`. Skipped points are
    /// never parsed or used: the key's hash checks the shared points in their
    /// place.
    ///
    /// It never grows `srs`, and fails if `srs` does not hold either end.
    /// A key shares the snapshot `srs` holds when it is read, and growing `srs`
    /// later leaves that snapshot alive beside the new one. So grow `srs` to
    /// the largest degree any key needs, then read the keys.
    pub fn read_le_with_srs<R: Read>(reader: R, srs: &UniversalParams<E>) -> io::Result<Self> {
        Self::read_le_sharing(reader, Some(srs))
    }

    pub(crate) fn read_le_sharing<R: Read>(mut reader: R, srs: Option<&UniversalParams<E>>) -> io::Result<Self> {
        // Deserialize `powers`.
        let powers_len: u32 = FromBytes::read_le(&mut reader)?;
        // Ensure the number of powers is within bounds.
        if powers_len as usize > MAX_NUM_POWERS {
            return Err(error(format!(
                "CommitterKey (from 'read_le') has too many points ({powers_len} > {MAX_NUM_POWERS})"
            )));
        }
        let held = srs
            .map(|srs| {
                srs.held_shared_powers_of_beta_g(0, powers_len as usize)
                    .ok_or_else(|| error(format!("The SRS does not hold the committer key's {powers_len} powers")))
            })
            .transpose()?;
        let powers_of_beta_g = read_bases(&mut reader, powers_len as usize, held)?;

        // Deserialize `lagrange_basis_at_beta`.
        let lagrange_bases_at_beta_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut lagrange_bases_at_beta_g = BTreeMap::new();
        for _ in 0..lagrange_bases_at_beta_len {
            let size: u32 = FromBytes::read_le(&mut reader)?;
            let basis = read_bounded(&mut reader, size as usize, "Lagrange basis points")?;
            lagrange_bases_at_beta_g.insert(size as usize, basis);
        }

        // Deserialize `powers_of_beta_times_gamma_g`.
        let powers_of_beta_times_gamma_g_len: u32 = FromBytes::read_le(&mut reader)?;
        let powers_of_beta_times_gamma_g =
            read_bounded(&mut reader, powers_of_beta_times_gamma_g_len as usize, "hiding points")?;

        // Deserialize `shifted_powers_of_beta_g`.
        let has_shifted_powers_of_beta_g: bool = FromBytes::read_le(&mut reader)?;
        let shifted_powers_of_beta_g = match has_shifted_powers_of_beta_g {
            true => {
                let shifted_powers_len: u32 = FromBytes::read_le(&mut reader)?;
                // Ensure the number of shifted powers is within bounds.
                if shifted_powers_len as usize > MAX_NUM_POWERS {
                    return Err(error(format!(
                        "CommitterKey (from 'read_le') has too many shifted points ({shifted_powers_len} > {MAX_NUM_POWERS})"
                    )));
                }
                // The shifted powers are the highest powers of the SRS.
                let held = srs
                    .map(|srs| {
                        let end = srs.max_degree() + 1;
                        end.checked_sub(shifted_powers_len as usize)
                            .and_then(|start| srs.held_shared_powers_of_beta_g(start, end))
                            .ok_or_else(|| {
                                error(format!(
                                    "The SRS does not hold the committer key's {shifted_powers_len} shifted powers"
                                ))
                            })
                    })
                    .transpose()?;
                Some(read_bases(&mut reader, shifted_powers_len as usize, held)?)
            }
            false => None,
        };

        // Deserialize `shifted_powers_of_beta_times_gamma_g`.
        let has_shifted_powers_of_beta_times_gamma_g: bool = FromBytes::read_le(&mut reader)?;
        let shifted_powers_of_beta_times_gamma_g = match has_shifted_powers_of_beta_times_gamma_g {
            true => {
                let mut shifted_powers_of_beta_times_gamma_g = BTreeMap::new();
                let shifted_powers_of_beta_times_gamma_g_num_elements: u32 = FromBytes::read_le(&mut reader)?;
                for _ in 0..shifted_powers_of_beta_times_gamma_g_num_elements {
                    let key: u32 = FromBytes::read_le(&mut reader)?;

                    let value_len: u32 = FromBytes::read_le(&mut reader)?;
                    let value = read_bounded(&mut reader, value_len as usize, "shifted hiding points")?;

                    shifted_powers_of_beta_times_gamma_g.insert(key as usize, value);
                }

                Some(shifted_powers_of_beta_times_gamma_g)
            }
            false => None,
        };

        // Deserialize `enforced_degree_bounds`.
        let has_enforced_degree_bounds: bool = FromBytes::read_le(&mut reader)?;
        let enforced_degree_bounds = match has_enforced_degree_bounds {
            true => {
                let enforced_degree_bounds_len: u32 = FromBytes::read_le(&mut reader)?;
                let enforced_degree_bounds =
                    read_bounded::<u32, _>(&mut reader, enforced_degree_bounds_len as usize, "degree bounds")?;
                let enforced_degree_bounds = enforced_degree_bounds.into_iter().map(|bound| bound as usize).collect();

                Some(enforced_degree_bounds)
            }
            false => None,
        };

        let key = Self {
            powers_of_beta_g,
            lagrange_bases_at_beta_g,
            powers_of_beta_times_gamma_g,
            shifted_powers_of_beta_g,
            shifted_powers_of_beta_times_gamma_g,
            enforced_degree_bounds,
        };

        // Deserialize `hash`.
        let expected_hash: [u8; 32] = FromBytes::read_le(&mut reader)?;

        // Enforce the group elements construct the expected hash. This also
        // checks the points shared with `srs` in place of the skipped ones.
        if key.points_hash()? != expected_hash {
            return Err(error(match srs {
                Some(_) => {
                    "Mismatching group elements: the committer key does not match the SRS, or its hiding powers are corrupt"
                }
                None => "Mismatching group elements",
            }));
        }
        Ok(key)
    }
}

impl<E: PairingEngine> ToBytes for CommitterKey<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Serialize `powers`.
        (self.powers_of_beta_g.len() as u32).write_le(&mut writer)?;
        for power in self.powers_of_beta_g.iter() {
            power.write_le(&mut writer)?;
        }

        // Serialize `powers`.
        (self.lagrange_bases_at_beta_g.len() as u32).write_le(&mut writer)?;
        for (size, powers) in &self.lagrange_bases_at_beta_g {
            (*size as u32).write_le(&mut writer)?;
            for power in powers {
                power.write_le(&mut writer)?;
            }
        }

        // Serialize `powers_of_beta_times_gamma_g`.
        (self.powers_of_beta_times_gamma_g.len() as u32).write_le(&mut writer)?;
        for power_of_gamma_g in &self.powers_of_beta_times_gamma_g {
            power_of_gamma_g.write_le(&mut writer)?;
        }

        // Serialize `shifted_powers_of_beta_g`.
        self.shifted_powers_of_beta_g.is_some().write_le(&mut writer)?;
        if let Some(shifted_powers_of_beta_g) = &self.shifted_powers_of_beta_g {
            (shifted_powers_of_beta_g.len() as u32).write_le(&mut writer)?;
            for shifted_power in shifted_powers_of_beta_g.iter() {
                shifted_power.write_le(&mut writer)?;
            }
        }

        // Serialize `shifted_powers_of_beta_times_gamma_g`.
        self.shifted_powers_of_beta_times_gamma_g.is_some().write_le(&mut writer)?;
        if let Some(shifted_powers_of_beta_times_gamma_g) = &self.shifted_powers_of_beta_times_gamma_g {
            (shifted_powers_of_beta_times_gamma_g.len() as u32).write_le(&mut writer)?;
            for (key, shifted_powers_of_beta_g) in shifted_powers_of_beta_times_gamma_g {
                (*key as u32).write_le(&mut writer)?;
                (shifted_powers_of_beta_g.len() as u32).write_le(&mut writer)?;
                for shifted_power in shifted_powers_of_beta_g {
                    shifted_power.write_le(&mut writer)?;
                }
            }
        }

        // Serialize `enforced_degree_bounds`.
        self.enforced_degree_bounds.is_some().write_le(&mut writer)?;
        if let Some(enforced_degree_bounds) = &self.enforced_degree_bounds {
            (enforced_degree_bounds.len() as u32).write_le(&mut writer)?;
            for enforced_degree_bound in enforced_degree_bounds {
                (*enforced_degree_bound as u32).write_le(&mut writer)?;
            }
        }

        // Serialize `hash`
        self.points_hash()?.write_le(&mut writer)
    }
}

/// Reads `len` points, or, given the SRS range that holds them, skips them in
/// `reader` and shares that range.
fn read_bases<G: AffineCurve, R: Read>(
    mut reader: R,
    len: usize,
    held: Option<(Arc<Vec<G>>, Range<usize>)>,
) -> io::Result<Bases<G>> {
    match held {
        Some((store, range)) => {
            let point_size = G::zero().to_bytes_le().map_err(into_io_error)?.len() as u64;
            let skip = point_size * len as u64;
            if io::copy(&mut (&mut reader).take(skip), &mut io::sink())? != skip {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(Bases::shared(store, range))
        }
        None => read_bounded(&mut reader, len, "points").map(Bases::Owned),
    }
}

/// Reads `len` values, failing before it allocates if `len` exceeds
/// `MAX_NUM_POWERS`.
fn read_bounded<T: FromBytes, R: Read>(mut reader: R, len: usize, what: &str) -> io::Result<Vec<T>> {
    if len > MAX_NUM_POWERS {
        return Err(error(format!("CommitterKey (from 'read_le') has too many {what} ({len} > {MAX_NUM_POWERS})")));
    }
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        values.push(T::read_le(&mut reader)?);
    }
    Ok(values)
}

impl<E: PairingEngine> CommitterKey<E> {
    /// The hash a key's bytes end with. It covers every point except the
    /// Lagrange bases.
    fn points_hash(&self) -> io::Result<[u8; 32]> {
        // Construct the hash of the group elements.
        let mut hash_input = Sha256Writer::default();
        self.powers_of_beta_g.write_le(&mut hash_input).map_err(|_| error("Could not serialize powers"))?;
        self.powers_of_beta_times_gamma_g
            .write_le(&mut hash_input)
            .map_err(|_| error("Could not serialize powers_of_beta_times_gamma_g"))?;

        if let Some(shifted_powers_of_beta_g) = &self.shifted_powers_of_beta_g {
            shifted_powers_of_beta_g
                .write_le(&mut hash_input)
                .map_err(|_| error("Could not serialize shifted_powers_of_beta_g"))?;
        }

        if let Some(shifted_powers_of_beta_times_gamma_g) = &self.shifted_powers_of_beta_times_gamma_g {
            for value in shifted_powers_of_beta_times_gamma_g.values() {
                value.write_le(&mut hash_input).map_err(|_| error("Could not serialize shifted_power_of_gamma_g"))?;
            }
        }

        Ok(hash_input.finalize())
    }
}

/// `CommitterUnionKey` is a union of `CommitterKey`s, useful for multi-circuit
/// batch proofs.
#[derive(Debug)]
pub struct CommitterUnionKey<'a, E: PairingEngine> {
    /// The key used to commit to polynomials.
    pub powers_of_beta_g: Option<&'a [E::G1Affine]>,

    /// The key used to commit to polynomials in Lagrange basis.
    pub lagrange_bases_at_beta_g: BTreeMap<usize, &'a Vec<E::G1Affine>>,

    /// The key used to commit to hiding polynomials.
    pub powers_of_beta_times_gamma_g: Option<&'a [E::G1Affine]>,

    /// The powers used to commit to shifted polynomials.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub shifted_powers_of_beta_g: Option<&'a [E::G1Affine]>,

    /// The powers used to commit to shifted hiding polynomials.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub shifted_powers_of_beta_times_gamma_g: Option<BTreeMap<usize, &'a [E::G1Affine]>>,

    /// The degree bounds that are supported by `self`.
    /// Sorted in ascending order from smallest bound to largest bound.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub enforced_degree_bounds: Option<Vec<usize>>,
}

impl<'a, E: PairingEngine> CommitterUnionKey<'a, E> {
    /// Obtain powers for the underlying KZG10 construction
    pub fn powers(&self) -> kzg10::Powers<'_, E> {
        kzg10::Powers {
            powers_of_beta_g: self.powers_of_beta_g.unwrap().into(),
            powers_of_beta_times_gamma_g: self.powers_of_beta_times_gamma_g.unwrap().into(),
        }
    }

    /// Obtain powers for committing to shifted polynomials.
    pub fn shifted_powers_of_beta_g(&self, degree_bound: impl Into<Option<usize>>) -> Option<kzg10::Powers<'_, E>> {
        match (&self.shifted_powers_of_beta_g, &self.shifted_powers_of_beta_times_gamma_g) {
            (Some(shifted_powers_of_beta_g), Some(shifted_powers_of_beta_times_gamma_g)) => {
                let max_bound = self.enforced_degree_bounds.as_ref().unwrap().last().unwrap();
                let (bound, powers_range) = if let Some(degree_bound) = degree_bound.into() {
                    assert!(self.enforced_degree_bounds.as_ref().unwrap().contains(&degree_bound));
                    (degree_bound, (max_bound - degree_bound)..)
                } else {
                    (*max_bound, 0..)
                };

                let ck = kzg10::Powers {
                    powers_of_beta_g: shifted_powers_of_beta_g[powers_range].into(),
                    powers_of_beta_times_gamma_g: shifted_powers_of_beta_times_gamma_g[&bound].into(),
                };

                Some(ck)
            }

            (_, _) => None,
        }
    }

    /// Obtain elements of the SRS in the lagrange basis powers, for use with
    /// the underlying KZG10 construction.
    pub fn lagrange_basis(&self, domain: EvaluationDomain<E::Fr>) -> Option<kzg10::LagrangeBasis<'_, E>> {
        self.lagrange_bases_at_beta_g.get(&domain.size()).map(|basis| kzg10::LagrangeBasis {
            lagrange_basis_at_beta_g: Cow::Borrowed(basis),
            powers_of_beta_times_gamma_g: Cow::Borrowed(self.powers_of_beta_times_gamma_g.unwrap()),
            domain,
        })
    }

    pub fn union<T: IntoIterator<Item = &'a CommitterKey<E>>>(committer_keys: T) -> Self {
        let mut ck_union = CommitterUnionKey::<E> {
            powers_of_beta_g: None,
            lagrange_bases_at_beta_g: BTreeMap::new(),
            powers_of_beta_times_gamma_g: None,
            shifted_powers_of_beta_g: None,
            shifted_powers_of_beta_times_gamma_g: None,
            enforced_degree_bounds: None,
        };
        let mut enforced_degree_bounds = vec![];
        // Every key's arrays are cut from one SRS, whose top degree is the constant
        // `MAX_NUM_POWERS - 1`: its prefix and hiding powers from the start, its
        // shifted powers from the end, and each bound's shifted hiding powers from
        // that bound's shift. So the longest of each array, across keys, contains the
        // others, and one key need not hold the longest of all of them.
        let mut shifted_powers_of_beta_times_gamma_g: BTreeMap<usize, &'a [E::G1Affine]> = BTreeMap::new();
        for ck in committer_keys {
            keep_longer(ck_union.powers_of_beta_g.get_or_insert(&ck.powers_of_beta_g), &ck.powers_of_beta_g);
            keep_longer(
                ck_union.powers_of_beta_times_gamma_g.get_or_insert(&ck.powers_of_beta_times_gamma_g),
                &ck.powers_of_beta_times_gamma_g,
            );
            if let Some(shifted_powers) = ck.shifted_powers_of_beta_g.as_ref() {
                keep_longer(ck_union.shifted_powers_of_beta_g.get_or_insert(shifted_powers), shifted_powers);
            }
            let lagrange_bases = &ck.lagrange_bases_at_beta_g;
            for (bound_base, bases) in lagrange_bases.iter() {
                ck_union.lagrange_bases_at_beta_g.entry(*bound_base).or_insert(bases);
            }
            if let Some(shifted_powers) = ck.shifted_powers_of_beta_times_gamma_g.as_ref() {
                for (bound_power, powers) in shifted_powers.iter() {
                    keep_longer(shifted_powers_of_beta_times_gamma_g.entry(*bound_power).or_insert(powers), powers);
                }
            }
            if let Some(degree_bounds) = &ck.enforced_degree_bounds {
                enforced_degree_bounds.extend_from_slice(degree_bounds);
            }
        }
        assert!(ck_union.powers_of_beta_g.is_some(), "a union needs at least one committer key");

        if !enforced_degree_bounds.is_empty() {
            enforced_degree_bounds.sort();
            enforced_degree_bounds.dedup();
            // `shifted_powers_of_beta_g(bound)` slices from `max_bound - bound`, which
            // is only right if the array starts at the largest bound's shift.
            assert_eq!(
                ck_union.shifted_powers_of_beta_g.map(<[_]>::len),
                enforced_degree_bounds.last().map(|max_bound| max_bound + 1),
                "the longest shifted powers do not start at the largest degree bound's shift"
            );
            ck_union.enforced_degree_bounds = Some(enforced_degree_bounds);
            ck_union.shifted_powers_of_beta_times_gamma_g = Some(shifted_powers_of_beta_times_gamma_g);
        }

        ck_union
    }
}

fn keep_longer<'a, T>(kept: &mut &'a [T], candidate: &'a [T]) {
    if kept.len() < candidate.len() {
        *kept = candidate;
    }
}

/// Evaluation proof at a query set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchProof<E: PairingEngine>(pub(crate) Vec<kzg10::KZGProof<E>>);

impl<E: PairingEngine> BatchProof<E> {
    pub fn is_hiding(&self) -> bool {
        self.0.iter().any(|c| c.is_hiding())
    }
}

/// Labels a `LabeledPolynomial` or a `LabeledCommitment`.
pub type PolynomialLabel = String;

/// A commitment along with information about its degree bound (if any).
#[derive(Clone, Debug, CanonicalSerialize, PartialEq, Eq)]
pub struct LabeledCommitment<C: CanonicalSerialize + 'static> {
    label: PolynomialLabel,
    commitment: C,
    degree_bound: Option<usize>,
}

impl<F: Field, C: CanonicalSerialize + ToConstraintField<F>> ToConstraintField<F> for LabeledCommitment<C> {
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        self.commitment.to_field_elements()
    }
}

// NOTE: Serializing the LabeledCommitments struct is done by serializing
// _WITHOUT_ the labels or the degree bound. Deserialization is _NOT_ supported,
// and you should construct the struct via the `LabeledCommitment::new` method
// after deserializing the Commitment.
impl<C: CanonicalSerialize + ToBytes> ToBytes for LabeledCommitment<C> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(&self.commitment, &mut writer)
            .map_err(|_| error("could not serialize struct"))
    }
}

impl<C: CanonicalSerialize> LabeledCommitment<C> {
    /// Instantiate a new polynomial_context.
    pub fn new(label: PolynomialLabel, commitment: C, degree_bound: Option<usize>) -> Self {
        Self { label, commitment, degree_bound }
    }

    pub fn new_with_info(info: &PolynomialInfo, commitment: C) -> Self {
        Self { label: info.label().to_string(), commitment, degree_bound: info.degree_bound() }
    }

    /// Return the label for `self`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Retrieve the commitment from `self`.
    pub fn commitment(&self) -> &C {
        &self.commitment
    }

    /// Retrieve the degree bound in `self`.
    pub fn degree_bound(&self) -> Option<usize> {
        self.degree_bound
    }
}

/// A term in a linear combination.
#[derive(Hash, Ord, PartialOrd, Clone, Eq, PartialEq)]
pub enum LCTerm {
    /// The constant term representing `one`.
    One,
    /// Label for a polynomial.
    PolyLabel(String),
}

impl fmt::Debug for LCTerm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LCTerm::One => write!(f, "1"),
            LCTerm::PolyLabel(label) => write!(f, "{label}"),
        }
    }
}

impl LCTerm {
    /// Returns `true` if `self == LCTerm::One`
    #[inline]
    pub fn is_one(&self) -> bool {
        matches!(self, LCTerm::One)
    }
}

impl From<PolynomialLabel> for LCTerm {
    fn from(other: PolynomialLabel) -> Self {
        Self::PolyLabel(other)
    }
}

impl From<&'_ str> for LCTerm {
    fn from(other: &str) -> Self {
        Self::PolyLabel(other.into())
    }
}

impl core::convert::TryInto<PolynomialLabel> for LCTerm {
    type Error = ();

    fn try_into(self) -> Result<PolynomialLabel, ()> {
        match self {
            Self::One => Err(()),
            Self::PolyLabel(l) => Ok(l),
        }
    }
}

impl<'a> core::convert::TryInto<&'a PolynomialLabel> for &'a LCTerm {
    type Error = ();

    fn try_into(self) -> Result<&'a PolynomialLabel, ()> {
        match self {
            LCTerm::One => Err(()),
            LCTerm::PolyLabel(l) => Ok(l),
        }
    }
}

impl<B: Borrow<String>> PartialEq<B> for LCTerm {
    fn eq(&self, other: &B) -> bool {
        match self {
            Self::One => false,
            Self::PolyLabel(l) => l == other.borrow(),
        }
    }
}

/// A labeled linear combinations of polynomials.
#[derive(Clone, Debug)]
pub struct LinearCombination<F> {
    /// The label.
    pub label: String,
    /// The linear combination of `(poly_label, coeff)` pairs.
    pub terms: BTreeMap<LCTerm, F>,
}

#[allow(clippy::or_fun_call)]
impl<F: Field> LinearCombination<F> {
    /// Construct an empty labeled linear combination.
    pub fn empty(label: impl Into<String>) -> Self {
        Self { label: label.into(), terms: BTreeMap::new() }
    }

    /// Construct a new labeled linear combination.
    /// with the terms specified in `term`.
    pub fn new(label: impl Into<String>, _terms: impl IntoIterator<Item = (F, impl Into<LCTerm>)>) -> Self {
        let mut terms = BTreeMap::new();
        for (c, l) in _terms.into_iter().map(|(c, t)| (c, t.into())) {
            *terms.entry(l).or_insert(F::zero()) += c;
        }

        Self { label: label.into(), terms }
    }

    /// Returns the label of the linear combination.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns `true` if the linear combination has no terms.
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Add a term to the linear combination.
    pub fn add(&mut self, c: F, t: impl Into<LCTerm>) -> &mut Self {
        let t = t.into();
        *self.terms.entry(t.clone()).or_insert(F::zero()) += c;
        if self.terms[&t].is_zero() {
            self.terms.remove(&t);
        }
        self
    }

    pub fn len(&self) -> usize {
        self.terms.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&F, &LCTerm)> {
        self.terms.iter().map(|(t, c)| (c, t))
    }
}

impl<'a, F: Field> AddAssign<(F, &'a LinearCombination<F>)> for LinearCombination<F> {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, (coeff, other): (F, &'a LinearCombination<F>)) {
        for (t, c) in other.terms.iter() {
            self.add(coeff * c, t.clone());
        }
    }
}

impl<'a, F: Field> SubAssign<(F, &'a LinearCombination<F>)> for LinearCombination<F> {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, (coeff, other): (F, &'a LinearCombination<F>)) {
        for (t, c) in other.terms.iter() {
            self.add(-coeff * c, t.clone());
        }
    }
}

impl<'a, F: Field> AddAssign<&'a LinearCombination<F>> for LinearCombination<F> {
    fn add_assign(&mut self, other: &'a LinearCombination<F>) {
        for (t, c) in other.terms.iter() {
            self.add(*c, t.clone());
        }
    }
}

impl<'a, F: Field> SubAssign<&'a LinearCombination<F>> for LinearCombination<F> {
    fn sub_assign(&mut self, other: &'a LinearCombination<F>) {
        for (t, &c) in other.terms.iter() {
            self.add(-c, t.clone());
        }
    }
}

impl<F: Field> AddAssign<F> for LinearCombination<F> {
    fn add_assign(&mut self, coeff: F) {
        self.add(coeff, LCTerm::One);
    }
}

impl<F: Field> SubAssign<F> for LinearCombination<F> {
    fn sub_assign(&mut self, coeff: F) {
        self.add(-coeff, LCTerm::One);
    }
}

impl<F: Field> MulAssign<F> for LinearCombination<F> {
    fn mul_assign(&mut self, coeff: F) {
        self.terms.values_mut().for_each(|c| *c *= &coeff);
    }
}

/// `QuerySet` is the set of queries that are to be made to a set of labeled
/// polynomials/equations `p` that have previously been committed to. Each
/// element of a `QuerySet` is a `(label, query)` pair, where `label` is the
/// label of a polynomial in `p`, and `query` is the field element
/// that `p[label]` is to be queried at.
///
/// Added the third field: the point name.
pub type QuerySet<T> = BTreeSet<(String, (String, T))>;

/// `Evaluations` is the result of querying a set of labeled polynomials or
/// equations `p` at a `QuerySet` `Q`. It maps each element of `Q` to the
/// resulting evaluation. That is, if `(label, query)` is an element of `Q`,
/// then `evaluation.get((label, query))` should equal
/// `p[label].evaluate(query)`.
pub type Evaluations<F> = BTreeMap<(String, F), F>;

/// Evaluate the given polynomials at `query_set`.
pub fn evaluate_query_set<'a, F: PrimeField>(
    polys: impl IntoIterator<Item = &'a LabeledPolynomial<F>>,
    query_set: &QuerySet<F>,
) -> Evaluations<F> {
    let polys: HashMap<_, _> = polys.into_iter().map(|p| (p.label(), p)).collect();
    let mut evaluations = Evaluations::new();
    for (label, (_point_name, point)) in query_set {
        let poly = polys.get(label as &str).expect("polynomial in evaluated lc is not found");
        let eval = poly.evaluate(*point);
        evaluations.insert((label.clone(), *point), eval);
    }
    evaluations
}

/// A proof of satisfaction of linear combinations.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchLCProof<E: PairingEngine> {
    /// Evaluation proof.
    pub proof: BatchProof<E>,
}

impl<E: PairingEngine> BatchLCProof<E> {
    pub fn is_hiding(&self) -> bool {
        self.proof.is_hiding()
    }
}

impl<E: PairingEngine> FromBytes for BatchLCProof<E> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize_compressed(&mut reader)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not deserialize struct")))
    }

    fn read_le_unchecked<R: Read>(mut reader: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize_compressed_unchecked(&mut reader)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not deserialize struct")))
    }
}

impl<E: PairingEngine> ToBytes for BatchLCProof<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(self, &mut writer)
            .map_err(|err| into_io_error(anyhow::Error::from(err).context("could not serialize struct")))
    }
}
