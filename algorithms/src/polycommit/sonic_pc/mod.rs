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
    fft::DensePolynomial,
    msm::variable_base::VariableBase,
    polycommit::{PCError, kzg10},
    srs::{UniversalProver, UniversalVerifier},
};
use hashbrown::HashMap;
use itertools::Itertools;
use snarkvm_curves::traits::{AffineCurve, PairingCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::{One, Zero};
use snarkvm_utilities::defer;

use anyhow::{Result, bail, ensure};
use rand::{Rng, SeedableRng};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    marker::PhantomData,
    ops::Mul,
};

mod data_structures;
pub use data_structures::*;

mod polynomial;
pub use polynomial::*;

/// What `combine_group` produced.
///
/// The host path returns the combined polynomial for `KZG10::open` to divide
/// and commit to. The device path does both itself, so what comes back is the
/// commitment to the quotient and the polynomial never reaches the host.
enum Combined<E: PairingEngine> {
    Host(DensePolynomial<E::Fr>),
    /// Constructed only with the `cuda` feature, but read by a match arm that
    /// is not cfg-gated.
    #[allow(dead_code)]
    WitnessCommitment(E::G1Projective),
}

/// A linear combination whose polynomial has not been formed.
///
/// `open_combinations` resolves each combination to the polynomials it names
/// and the scalar in front of each, and leaves the coefficient arithmetic to
/// `open_lazy_combinations`, which folds in the Fiat-Shamir challenge and
/// accumulates once. Holding the polynomial by reference is the
/// point: `LabeledPolynomial` owns a `Cow<'static, _>`, so putting one into a
/// combination is a clone of every coefficient.
struct LazyCombination<'a, E: PairingEngine> {
    label: String,
    /// `(coefficient, polynomial)` per term, with the `LCTerm::One` constants
    /// already filtered out -- the verifier uses those directly and nothing
    /// is committed to them.
    terms: Vec<(E::Fr, &'a LabeledPolynomial<E::Fr>)>,
    /// `Some` only for a single-term combination whose coefficient is one,
    /// which is what `open_combinations` enforces; `open_lazy_combinations`
    /// relies on it.
    degree_bound: Option<usize>,
    randomness: Randomness<E>,
}

/// Polynomial commitment based on [\[KZG10\]][kzg], with degree enforcement and
/// batching taken from [[MBKM19, “Sonic”]][sonic] (more precisely, their
/// counterparts in [[Gabizon19, “AuroraLight”]][al] that avoid negative G1
/// powers). The (optional) hiding property of the commitment scheme follows the
/// approach described in [[CHMMVW20, “Marlin”]][marlin].
///
/// [kzg]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
/// [sonic]: https://eprint.iacr.org/2019/099
/// [al]: https://eprint.iacr.org/2019/601
/// [marlin]: https://eprint.iacr.org/2019/1047
#[derive(Clone, Debug)]
pub struct SonicKZG10<E: PairingEngine, S: AlgebraicSponge<E::Fq, 2>> {
    _engine: PhantomData<(E, S)>,
}

impl<E: PairingEngine, S: AlgebraicSponge<E::Fq, 2>> SonicKZG10<E, S> {
    pub fn load_srs(max_degree: usize) -> Result<UniversalParams<E>, PCError> {
        kzg10::KZG10::load_srs(max_degree)
    }

    pub fn trim(
        pp: &UniversalParams<E>,
        supported_degree: usize,
        supported_lagrange_sizes: impl IntoIterator<Item = usize>,
        supported_hiding_bound: usize,
        enforced_degree_bounds: Option<&[usize]>,
    ) -> Result<(CommitterKey<E>, UniversalVerifier<E>)> {
        let trim_time = start_timer!(|| "Trimming public parameters");
        defer! { end_timer!(trim_time); }
        let max_degree = pp.max_degree();

        let enforced_degree_bounds = enforced_degree_bounds.map(|bounds| {
            let mut v = bounds.to_vec();
            v.sort_unstable();
            v.dedup();
            v
        });

        // Every argument is validated before anything is downloaded, so a
        // rejected call leaves the SRS as it was.
        let supported_lagrange_sizes: Vec<usize> = supported_lagrange_sizes.into_iter().collect();
        for &size in &supported_lagrange_sizes {
            if !size.is_power_of_two() {
                bail!("The Lagrange basis size ({size}) is not a power of two")
            }
            if size > max_degree + 1 {
                bail!("The Lagrange basis size ({size}) is larger than the supported degree ({})", max_degree + 1)
            }
        }
        if let Some([.., highest_enforced_degree_bound]) = enforced_degree_bounds.as_deref()
            && *highest_enforced_degree_bound > supported_degree
        {
            bail!(
                "The highest enforced degree bound {highest_enforced_degree_bound} is larger than the supported degree {supported_degree}"
            );
        }

        // Both ends are downloaded before anything is shared: a later download
        // would replace a snapshot this key already shared, which the key would
        // then keep alive after the SRS moved on.
        let prefix = supported_lagrange_sizes.iter().fold(supported_degree + 1, |end, &size| end.max(size));
        let suffix = enforced_degree_bounds.as_deref().and_then(|bounds| bounds.last()).map_or(0, |bound| bound + 1);
        pp.download_powers_for_ends(prefix, suffix)?;

        let (shifted_powers_of_beta_g, shifted_powers_of_beta_times_gamma_g) = match enforced_degree_bounds.as_deref() {
            // The bounds are sorted, so the last is the highest.
            Some(enforced_degree_bounds @ [.., highest_enforced_degree_bound]) => {
                let lowest_shift_degree = max_degree - highest_enforced_degree_bound;

                let shifted_ck_time = start_timer!(|| format!(
                    "Constructing `shifted_powers_of_beta_g` of size {}",
                    max_degree - lowest_shift_degree + 1
                ));
                defer! { end_timer!(shifted_ck_time); }

                let (store, range) = pp.shared_powers_of_beta_g(lowest_shift_degree, pp.max_degree() + 1)?;
                let shifted_powers_of_beta_g = Bases::shared(store, range);
                let mut shifted_powers_of_beta_times_gamma_g = BTreeMap::new();
                // Also add degree 0.
                for degree_bound in enforced_degree_bounds {
                    let shift_degree = max_degree - degree_bound;
                    // We have an additional degree in `powers_of_beta_times_gamma_g` beyond
                    // `powers_of_beta_g`.
                    let powers_for_degree_bound = pp
                        .powers_of_beta_times_gamma_g()
                        .range(shift_degree..max_degree.min(shift_degree + supported_hiding_bound) + 2)
                        .map(|(_k, v)| *v)
                        .collect();
                    shifted_powers_of_beta_times_gamma_g.insert(*degree_bound, powers_for_degree_bound);
                }

                (Some(shifted_powers_of_beta_g), Some(shifted_powers_of_beta_times_gamma_g))
            }
            _ => (None, None),
        };

        let (store, range) = pp.shared_powers_of_beta_g(0, supported_degree + 1)?;
        let powers_of_beta_g = Bases::shared(store, range);
        let powers_of_beta_times_gamma_g = pp
            .powers_of_beta_times_gamma_g()
            .range(0..=(supported_hiding_bound + 1))
            .map(|(_k, v)| *v)
            .collect::<Vec<_>>();
        if powers_of_beta_times_gamma_g.len() != supported_hiding_bound + 2 {
            return Err(
                PCError::HidingBoundToolarge { hiding_poly_degree: supported_hiding_bound, num_powers: 0 }.into()
            );
        }

        let mut lagrange_bases_at_beta_g = BTreeMap::new();
        for size in supported_lagrange_sizes {
            let lagrange_time = start_timer!(|| format!("Constructing `lagrange_bases` of size {size}"));
            defer! { end_timer!(lagrange_time); }
            // Validated above: the size is a power of two no larger than the SRS.
            let domain = crate::fft::EvaluationDomain::new(size).unwrap();
            let lagrange_basis_at_beta_g = pp.lagrange_basis(domain)?;
            assert!(lagrange_basis_at_beta_g.len().is_power_of_two());
            lagrange_bases_at_beta_g.insert(domain.size(), lagrange_basis_at_beta_g);
        }

        let ck = CommitterKey {
            powers_of_beta_g,
            lagrange_bases_at_beta_g,
            powers_of_beta_times_gamma_g,
            shifted_powers_of_beta_g,
            shifted_powers_of_beta_times_gamma_g,
            enforced_degree_bounds,
        };

        let vk = pp.to_universal_verifier()?;

        Ok((ck, vk))
    }

    /// Outputs commitments to `polynomials`.
    ///
    /// If `polynomials[i].is_hiding()`, then the `i`-th commitment is hiding
    /// up to `polynomials.hiding_bound()` queries.
    ///
    /// `rng` should not be `None` if `polynomials[i].is_hiding() == true` for
    /// any `i`.
    ///
    /// If for some `i`, `polynomials[i].is_hiding() == false`, then the
    /// corresponding randomness is `Randomness<E>::empty()`.
    ///
    /// If for some `i`, `polynomials[i].degree_bound().is_some()`, then that
    /// polynomial will have the corresponding degree bound enforced.
    #[allow(clippy::format_push_string)]
    pub fn commit<'b>(
        universal_prover: &UniversalProver<E>,
        ck: &CommitterUnionKey<E>,
        polynomials: impl IntoIterator<Item = LabeledPolynomialWithBasis<'b, E::Fr>>,
        mut rng: Option<&mut dyn Rng>,
    ) -> Result<(Vec<LabeledCommitment<Commitment<E>>>, Vec<Randomness<E>>), PCError> {
        let commit_time = start_timer!(|| "Committing to polynomials");
        defer! { end_timer!(commit_time); }

        let mut pool = snarkvm_utilities::ExecutionPool::<Result<_, _>>::new();
        for p in polynomials {
            let seed = rng.as_mut().map(|r| {
                let mut seed = [0u8; 32];
                r.fill_bytes(&mut seed);
                seed
            });

            kzg10::KZG10::<E>::check_degrees_and_bounds(
                universal_prover.max_degree,
                ck.enforced_degree_bounds.as_deref(),
                p.clone(),
            )?;
            let degree_bound = p.degree_bound();
            let hiding_bound = p.hiding_bound();
            let label = p.label().to_string();

            pool.add_job(move || {
                let mut rng = seed.map(rand::rngs::StdRng::from_seed);
                add_to_trace!(|| "PC::Commit", || format!(
                    "Polynomial {} of degree {}, degree bound {:?}, and hiding bound {:?}",
                    label,
                    p.degree(),
                    degree_bound,
                    hiding_bound,
                ));

                let (comm, rand) = {
                    let rng_ref = rng.as_mut().map(|s| s as _);
                    match p.polynomial {
                        PolynomialWithBasis::Lagrange { evaluations } => {
                            let domain = crate::fft::EvaluationDomain::new(evaluations.evaluations.len()).unwrap();
                            let lagrange_basis = ck
                                .lagrange_basis(domain)
                                .ok_or(PCError::UnsupportedLagrangeBasisSize(domain.size()))?;
                            assert!(domain.size().is_power_of_two());
                            assert!(lagrange_basis.size().is_power_of_two());
                            kzg10::KZG10::commit_lagrange(
                                &lagrange_basis,
                                &evaluations.evaluations,
                                hiding_bound,
                                rng_ref,
                            )?
                        }
                        PolynomialWithBasis::Monomial { polynomial, degree_bound } => {
                            let powers = if let Some(degree_bound) = degree_bound {
                                ck.shifted_powers_of_beta_g(degree_bound).unwrap()
                            } else {
                                ck.powers()
                            };

                            kzg10::KZG10::commit(&powers, &polynomial, hiding_bound, rng_ref)?
                        }
                    }
                };

                Ok((LabeledCommitment::new(label.to_string(), comm, degree_bound), rand))
            });
        }
        let results: Vec<Result<_, PCError>> = pool.execute_all();

        let mut labeled_comms = Vec::with_capacity(results.len());
        let mut randomness = Vec::with_capacity(results.len());
        for result in results {
            let (comm, rand) = result?;
            labeled_comms.push(comm);
            randomness.push(rand);
        }

        Ok((labeled_comms, randomness))
    }

    pub fn combine_for_open<'a>(
        universal_prover: &UniversalProver<E>,
        ck: &CommitterUnionKey<E>,
        labeled_polynomials: impl ExactSizeIterator<Item = &'a LabeledPolynomial<E::Fr>>,
        rands: impl ExactSizeIterator<Item = &'a Randomness<E>>,
        fs_rng: &mut S,
    ) -> Result<(DensePolynomial<E::Fr>, Randomness<E>)>
    where
        Randomness<E>: 'a,
        Commitment<E>: 'a,
    {
        ensure!(labeled_polynomials.len() == rands.len());
        let mut to_combine = Vec::with_capacity(labeled_polynomials.len());

        for (p, r) in labeled_polynomials.zip_eq(rands) {
            let enforced_degree_bounds: Option<&[usize]> = ck.enforced_degree_bounds.as_deref();

            kzg10::KZG10::<E>::check_degrees_and_bounds(universal_prover.max_degree, enforced_degree_bounds, p)?;
            let challenge = fs_rng.squeeze_short_nonnative_field_element::<E::Fr>();
            to_combine.push((challenge, p.polynomial().to_dense(), r));
        }

        Ok(Self::combine_polynomials(to_combine))
    }

    /// `batch_open` over combinations whose polynomials have not been formed.
    ///
    /// Both levels of the opening are linear in the coefficients. A combination
    /// is `Σ c_i · P_i`, and `combine_for_open` then scales that by a
    /// Fiat-Shamir challenge `d_j` and sums the results. So
    ///
    /// ```text
    ///     Σ_j d_j · ( Σ_i c_ji · P_i )  =  Σ_i ( Σ_j d_j · c_ji ) · P_i
    /// ```
    ///
    /// and composing the two coefficients accumulates the same polynomial in
    /// **one** pass over each term instead of two. What made the second
    /// pass easy to miss is that most of Varuna's combinations have a
    /// single term, so their first pass is a whole scaled copy of a polynomial
    /// that the second pass then walks again.
    ///
    /// This is safe to compose only because the sponge is **squeezed and never
    /// absorbed** between here and the KZG open, so every challenge is
    /// determined before any polynomial arithmetic happens. Squeeze order
    /// is preserved exactly: groups in query-set order, combinations in
    /// label order within a group, and the trailing squeeze per group.
    fn open_lazy_combinations(
        universal_prover: &UniversalProver<E>,
        ck: &CommitterUnionKey<E>,
        combinations: &[LazyCombination<'_, E>],
        query_set: &QuerySet<E::Fr>,
        fs_rng: &mut S,
    ) -> Result<BatchProof<E>> {
        let open_time = start_timer!(|| format!(
            "Opening {} combinations at query set of size {}",
            combinations.len(),
            query_set.len(),
        ));
        defer! { end_timer!(open_time); }

        let by_label: BTreeMap<&str, &LazyCombination<'_, E>> =
            combinations.iter().map(|c| (c.label.as_str(), c)).collect();

        let mut query_to_labels_map = BTreeMap::new();
        for (label, (point_name, point)) in query_set.iter() {
            let labels = query_to_labels_map.entry(point_name).or_insert((point, BTreeSet::new()));
            labels.1.insert(label);
        }

        let mut proofs = Vec::new();
        for (_point_name, (&query, labels)) in query_to_labels_map.into_iter() {
            let mut group = Vec::with_capacity(labels.len());
            for label in labels {
                let c = by_label.get(label as &str).ok_or(PCError::MissingPolynomial { label: label.to_string() })?;
                group.push(*c);
            }

            let mut challenges = Vec::with_capacity(group.len());
            for c in &group {
                // `check_degrees_and_bounds` returns immediately unless the polynomial carries
                // a degree bound, and a combination only carries one when it
                // has a single term with coefficient one -- in which case the
                // combination's polynomial *is* that term's. So checking the
                // term is the same check on the same coefficients.
                if let Some(bound) = c.degree_bound {
                    // Enforced rather than asserted. The invariant is real -- `open_combinations`
                    // bails unless `lc.len() == 1` before it can set `degree_bound` -- but it is
                    // established in another function, and `debug_assert!` is compiled out of the
                    // builds that ship. If it ever broke, nothing would panic: the bound would be
                    // checked against the first term while the opening covered the whole sum, the
                    // proof would still verify, and what would quietly be gone is a soundness
                    // property of the commitment scheme.
                    ensure!(
                        c.terms.len() == 1,
                        "combination {} carries degree bound {bound} with {} terms; \
                         a degree-bounded combination must have exactly one",
                        c.label,
                        c.terms.len(),
                    );
                    let enforced_degree_bounds: Option<&[usize]> = ck.enforced_degree_bounds.as_deref();
                    kzg10::KZG10::<E>::check_degrees_and_bounds(
                        universal_prover.max_degree,
                        enforced_degree_bounds,
                        c.terms[0].1,
                    )?;
                }
                challenges.push(fs_rng.squeeze_short_nonnative_field_element::<E::Fr>());
            }

            let combine_time = start_timer!(|| format!("Combining {} combinations for the opening", group.len()));
            let mut rand = Randomness::empty();
            for (c, challenge) in group.iter().zip_eq(challenges.iter()) {
                rand += (*challenge, &c.randomness);
            }
            let polynomial = Self::combine_group(ck, &group, &challenges, query)?;
            end_timer!(combine_time);

            let proof = {
                let proof_time = start_timer!(|| "Creating proof");
                defer! { end_timer!(proof_time); }
                match polynomial {
                    Combined::Host(polynomial) => kzg10::KZG10::open(&ck.powers(), &polynomial, query, &rand)?,
                    // The device returned the commitment to the quotient, so
                    // only the hiding term remains.
                    Combined::WitnessCommitment(w) => {
                        let hiding_witness =
                            rand.is_hiding().then(|| rand.blinding_polynomial.divide_by_monic_linear(query).0);
                        kzg10::KZG10::finish_open(&ck.powers(), query, &rand, w, hiding_witness.as_ref())
                    }
                }
            };
            proofs.push(proof);

            let _ = fs_rng.squeeze_short_nonnative_field_element::<E::Fr>();
        }

        Ok(BatchProof(proofs))
    }

    /// On input a list of labeled polynomials and a query set, `open` outputs a
    /// proof of evaluation of the polynomials at the points in the query
    /// set.
    pub fn batch_open<'a>(
        universal_prover: &UniversalProver<E>,
        ck: &CommitterUnionKey<E>,
        labeled_polynomials: impl ExactSizeIterator<Item = &'a LabeledPolynomial<E::Fr>>,
        query_set: &QuerySet<E::Fr>,
        rands: impl ExactSizeIterator<Item = &'a Randomness<E>>,
        fs_rng: &mut S,
    ) -> Result<BatchProof<E>>
    where
        Randomness<E>: 'a,
        Commitment<E>: 'a,
    {
        ensure!(labeled_polynomials.len() == rands.len());
        let poly_rand: HashMap<_, _> =
            labeled_polynomials.into_iter().zip_eq(rands).map(|(poly, r)| (poly.label(), (poly, r))).collect();

        let open_time = start_timer!(|| format!(
            "Opening {} polynomials at query set of size {}",
            poly_rand.len(),
            query_set.len(),
        ));
        defer! { end_timer!(open_time); }

        let mut query_to_labels_map = BTreeMap::new();

        for (label, (point_name, point)) in query_set.iter() {
            let labels = query_to_labels_map.entry(point_name).or_insert((point, BTreeSet::new()));
            labels.1.insert(label);
        }

        let mut proofs = Vec::new();
        for (_point_name, (&query, labels)) in query_to_labels_map.into_iter() {
            let mut query_polys = Vec::with_capacity(labels.len());
            let mut query_rands = Vec::with_capacity(labels.len());

            for label in labels {
                let (polynomial, rand) =
                    poly_rand.get(label as &str).ok_or(PCError::MissingPolynomial { label: label.to_string() })?;

                query_polys.push(*polynomial);
                query_rands.push(*rand);
            }
            let (polynomial, rand) =
                Self::combine_for_open(universal_prover, ck, query_polys.into_iter(), query_rands.into_iter(), fs_rng)?;

            let proof = {
                let proof_time = start_timer!(|| "Creating proof");
                defer! { end_timer!(proof_time); }
                kzg10::KZG10::open(&ck.powers(), &polynomial, query, &rand)?
            };
            proofs.push(proof);

            let _ = fs_rng.squeeze_short_nonnative_field_element::<E::Fr>();
        }

        Ok(BatchProof(proofs))
    }

    pub fn batch_check<'a>(
        vk: &UniversalVerifier<E>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Commitment<E>>>,
        query_set: &QuerySet<E::Fr>,
        values: &Evaluations<E::Fr>,
        proof: &BatchProof<E>,
        fs_rng: &mut S,
    ) -> Result<bool>
    where
        Commitment<E>: 'a,
    {
        let commitments: BTreeMap<_, _> = commitments.into_iter().map(|c| (c.label().to_owned(), c)).collect();
        let batch_check_time = start_timer!(|| format!(
            "Checking {} commitments at query set of size {}",
            commitments.len(),
            query_set.len(),
        ));
        defer! { end_timer!(batch_check_time); }
        let mut query_to_labels_map = BTreeMap::new();

        for (label, (point_name, point)) in query_set.iter() {
            let labels = query_to_labels_map.entry(point_name).or_insert((point, BTreeSet::new()));
            labels.1.insert(label);
        }

        ensure!(query_to_labels_map.len() == proof.0.len());

        let mut private_sponge = fs_rng.clone();
        for proof in &proof.0 {
            proof.absorb_into_sponge(&mut private_sponge);
        }

        let mut randomizer = E::Fr::one();

        let mut combined_comms = BTreeMap::new();
        let mut combined_witness = E::G1Projective::zero();
        let mut combined_adjusted_witness = E::G1Projective::zero();

        for ((_query_name, (query, labels)), p) in query_to_labels_map.into_iter().zip_eq(&proof.0) {
            let mut comms_to_combine: Vec<&'_ LabeledCommitment<_>> = Vec::new();
            let mut values_to_combine = Vec::new();
            for label in labels.into_iter() {
                let commitment =
                    commitments.get(label).ok_or(PCError::MissingPolynomial { label: label.to_string() })?;

                let v_i = values
                    .get(&(label.clone(), *query))
                    .ok_or(PCError::MissingEvaluation { label: label.to_string() })?;

                comms_to_combine.push(commitment);
                values_to_combine.push(*v_i);
            }

            Self::accumulate_elems(
                &mut combined_comms,
                &mut combined_witness,
                &mut combined_adjusted_witness,
                vk,
                comms_to_combine.into_iter(),
                *query,
                values_to_combine.into_iter(),
                p,
                Some(randomizer),
                fs_rng,
            )?;

            let _ = fs_rng.squeeze_short_nonnative_field_element::<E::Fr>();

            randomizer = private_sponge.squeeze_short_nonnative_field_element::<E::Fr>();
        }

        Self::check_elems(vk, combined_comms, combined_witness, combined_adjusted_witness)
    }

    pub fn open_combinations<'a>(
        universal_prover: &UniversalProver<E>,
        ck: &CommitterUnionKey<E>,
        linear_combinations: impl IntoIterator<Item = &'a LinearCombination<E::Fr>>,
        polynomials: impl IntoIterator<Item = LabeledPolynomial<E::Fr>>,
        rands: impl IntoIterator<Item = &'a Randomness<E>>,
        query_set: &QuerySet<E::Fr>,
        fs_rng: &mut S,
    ) -> Result<BatchLCProof<E>>
    where
        Randomness<E>: 'a,
        Commitment<E>: 'a,
    {
        let label_map =
            polynomials.into_iter().zip_eq(rands).map(|(p, r)| (p.to_label(), (p, r))).collect::<BTreeMap<_, _>>();

        // Resolve each combination to its terms without forming its polynomial.
        //
        // The arithmetic below is over scalars: `lc` is symbolic, its terms naming
        // polynomials rather than holding them. Forming the polynomial here is
        // exactly what `open_lazy_combinations` avoids.
        let combinations = {
            let resolve_time = start_timer!(|| "Resolving combination terms");
            defer! { end_timer!(resolve_time); }
            let mut combinations = Vec::new();
            for lc in linear_combinations {
                let lc_label = lc.label().to_string();
                // `lc.len()` counts terms *before* the `is_one()` filter below, so this
                // over-reserves by the number of constant terms. Left as is because
                // that pre-filter reading is what the degree-bound guard relies on.
                let mut terms = Vec::with_capacity(lc.len());
                let mut randomness = Randomness::empty();
                let mut degree_bound = None;

                let num_polys = lc.len();
                // We filter out l.is_one() entries because those constants are not committed to
                // and used directly by the verifier.
                for (coeff, label) in lc.iter().filter(|(_, l)| !l.is_one()) {
                    let label: &String = label.try_into().expect("cannot be one!");
                    let (cur_poly, cur_rand) =
                        label_map.get(label as &str).ok_or(PCError::MissingPolynomial { label: label.to_string() })?;
                    if let Some(cur_degree_bound) = cur_poly.degree_bound() {
                        if num_polys != 1 {
                            bail!(PCError::EquationHasDegreeBounds(lc_label));
                        }
                        assert!(coeff.is_one(), "Coefficient must be one for degree-bounded equations");
                        if let Some(old_degree_bound) = degree_bound {
                            assert_eq!(old_degree_bound, cur_degree_bound)
                        } else {
                            degree_bound = cur_poly.degree_bound();
                        }
                    }
                    terms.push((*coeff, cur_poly));
                    randomness += (*coeff, *cur_rand);
                }

                // The hiding bound is not carried. It was only ever handed to the
                // `LabeledPolynomial` built here, and nothing downstream of the
                // opening reads it: the hiding bound is enforced when the
                // polynomial is committed, not when it is opened.
                combinations.push(LazyCombination { label: lc_label, terms, degree_bound, randomness });
            }
            combinations
        };

        let proof = Self::open_lazy_combinations(universal_prover, ck, &combinations, query_set, fs_rng)?;

        Ok(BatchLCProof { proof })
    }

    /// The opening's per-group work: `Σ (challenge_j · coeff_ji) · P_ji` over
    /// every term of every combination. The device path also divides by
    /// `X - z` and commits to the quotient.
    fn combine_group(
        ck: &CommitterUnionKey<E>,
        group: &[&LazyCombination<'_, E>],
        challenges: &[E::Fr],
        query: E::Fr,
    ) -> Result<Combined<E>> {
        // With `cuda` and BLS12-377 the device path is unconditional. The host
        // path runs without `cuda` or for any other field.
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if core::any::TypeId::of::<E::Fr>() == core::any::TypeId::of::<snarkvm_curves::bls12_377::Fr>() {
            // `to_dense` borrows a dense polynomial and converts a sparse one,
            // such as `mask_poly`, as the host path's `AddAssign` does. The
            // `Cow`s are held for the call because `terms` borrows from them.
            let densified: Vec<(E::Fr, std::borrow::Cow<'_, DensePolynomial<E::Fr>>)> = group
                .iter()
                .zip_eq(challenges.iter())
                .flat_map(|(c, challenge)| {
                    c.terms.iter().map(move |(coeff, p)| (*challenge * coeff, p.polynomial().to_dense()))
                })
                .collect();
            let out_len = densified.iter().map(|(_, p)| p.coeffs.len()).max().unwrap_or(0);

            // A quotient needs two coefficients. Below that only the host path
            // is defined.
            if out_len >= 2 {
                let terms: Vec<(E::Fr, &[E::Fr])> = densified.iter().map(|(c, p)| (*c, p.coeffs.as_slice())).collect();

                let powers = ck.powers();
                // `KZG10::open`'s check, against the bound `out_len - 1` rather
                // than the trimmed degree, so it can only reject more.
                kzg10::KZG10::<E>::check_degree_is_too_large(out_len - 1, powers.size())?;

                let result = snarkvm_algorithms_cuda::accumulate_open(
                    out_len,
                    &terms,
                    &query,
                    &powers.powers_of_beta_g[..out_len - 1],
                );
                let w = crate::cuda_must_succeed!(result, "accumulate_open");
                return Ok(Combined::WitnessCommitment(w));
            }
        }

        let mut polynomial = DensePolynomial::zero();
        for (c, challenge) in group.iter().zip_eq(challenges.iter()) {
            for (coeff, p) in &c.terms {
                let scale = *challenge * coeff;
                if scale.is_one() {
                    polynomial += p.polynomial();
                } else {
                    polynomial += (scale, p.polynomial());
                }
            }
        }
        // Live on the device path; unused only when the `cuda` cfg is off.
        let _ = (ck, query);
        Ok(Combined::Host(polynomial))
    }

    /// Checks that `values` are the true evaluations at `query_set` of the
    /// polynomials committed in `labeled_commitments`.
    pub fn check_combinations<'a>(
        vk: &UniversalVerifier<E>,
        linear_combinations: impl IntoIterator<Item = &'a LinearCombination<E::Fr>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Commitment<E>>>,
        query_set: &QuerySet<E::Fr>,
        evaluations: &Evaluations<E::Fr>,
        proof: &BatchLCProof<E>,
        fs_rng: &mut S,
    ) -> Result<bool>
    where
        Commitment<E>: 'a,
    {
        let BatchLCProof { proof } = proof;
        let label_comm_map = commitments.into_iter().map(|c| (c.label(), c)).collect::<BTreeMap<_, _>>();

        let mut lc_commitments = Vec::new();
        let mut lc_info = Vec::new();
        let mut evaluations = evaluations.clone();

        {
            let lc_processing_time = start_timer!(|| "Combining commitments");
            defer! { end_timer!(lc_processing_time); }
            for lc in linear_combinations {
                let lc_label = lc.label().to_string();
                let num_polys = lc.len();

                let mut degree_bound = None;
                let mut coeffs_and_comms = Vec::new();

                for (coeff, label) in lc.iter() {
                    if label.is_one() {
                        for ((label, _), ref mut eval) in evaluations.iter_mut() {
                            if label == &lc_label {
                                **eval -= coeff;
                            }
                        }
                    } else {
                        let label: &String = label.try_into().unwrap();
                        let &cur_comm = label_comm_map
                            .get(label as &str)
                            .ok_or(PCError::MissingPolynomial { label: label.to_string() })?;

                        if cur_comm.degree_bound().is_some() {
                            if num_polys != 1 || !coeff.is_one() {
                                bail!(PCError::EquationHasDegreeBounds(lc_label));
                            }
                            degree_bound = cur_comm.degree_bound();
                        }
                        coeffs_and_comms.push((*coeff, cur_comm.commitment()));
                    }
                }
                let lc_time = start_timer!(|| format!("Combining {num_polys} commitments for {lc_label}"));
                lc_commitments.push(Self::combine_commitments(coeffs_and_comms));
                end_timer!(lc_time);
                lc_info.push((lc_label, degree_bound));
            }
        }

        let lc_commitments = {
            let combined_comms_norm_time = start_timer!(|| "Normalizing commitments");
            defer! { end_timer!(combined_comms_norm_time); }
            let comms = Self::normalize_commitments(lc_commitments);
            ensure!(lc_info.len() == comms.len());
            lc_info
                .into_iter()
                .zip_eq(comms)
                .map(|((label, d), c)| LabeledCommitment::new(label, c, d))
                .collect::<Vec<_>>()
        };

        Self::batch_check(vk, &lc_commitments, query_set, &evaluations, proof, fs_rng)
    }
}

impl<E: PairingEngine, S: AlgebraicSponge<E::Fq, 2>> SonicKZG10<E, S> {
    fn combine_polynomials<'a, B: Borrow<DensePolynomial<E::Fr>>>(
        coeffs_polys_rands: impl IntoIterator<Item = (E::Fr, B, &'a Randomness<E>)>,
    ) -> (DensePolynomial<E::Fr>, Randomness<E>) {
        let mut combined_poly = DensePolynomial::zero();
        let mut combined_rand = Randomness::empty();
        for (coeff, poly, rand) in coeffs_polys_rands {
            let poly = poly.borrow();
            if coeff.is_one() {
                combined_poly += poly;
                combined_rand += rand;
            } else {
                combined_poly += (coeff, poly);
                combined_rand += (coeff, rand);
            }
        }
        (combined_poly, combined_rand)
    }

    /// MSM for `commitments` and `coeffs`
    fn combine_commitments<'a>(
        coeffs_and_comms: impl IntoIterator<Item = (E::Fr, &'a Commitment<E>)>,
    ) -> E::G1Projective {
        let (scalars, bases): (Vec<_>, Vec<_>) = coeffs_and_comms.into_iter().map(|(f, c)| (f.into(), c.0)).unzip();
        VariableBase::msm(&bases, &scalars)
    }

    fn normalize_commitments(commitments: Vec<E::G1Projective>) -> impl ExactSizeIterator<Item = Commitment<E>> {
        let comms = E::G1Projective::batch_normalization_into_affine(commitments);
        comms.into_iter().map(|c| kzg10::KZGCommitment(c))
    }
}

impl<E: PairingEngine, S: AlgebraicSponge<E::Fq, 2>> SonicKZG10<E, S> {
    #[allow(clippy::too_many_arguments)]
    fn accumulate_elems<'a>(
        combined_comms: &mut BTreeMap<Option<usize>, E::G1Projective>,
        combined_witness: &mut E::G1Projective,
        combined_adjusted_witness: &mut E::G1Projective,
        vk: &UniversalVerifier<E>,
        commitments: impl ExactSizeIterator<Item = &'a LabeledCommitment<Commitment<E>>>,
        point: E::Fr,
        values: impl ExactSizeIterator<Item = E::Fr>,
        proof: &kzg10::KZGProof<E>,
        randomizer: Option<E::Fr>,
        fs_rng: &mut S,
    ) -> Result<()> {
        let acc_time = start_timer!(|| "Accumulating elements");
        defer! { end_timer!(acc_time); }
        // Keeps track of running combination of values
        let mut combined_values = E::Fr::zero();

        // Iterates through all of the commitments and accumulates common degree_bound
        // elements in a BTreeMap
        ensure!(commitments.len() == values.len());
        for (labeled_comm, value) in commitments.into_iter().zip_eq(values) {
            let acc_timer = start_timer!(|| format!("Accumulating {}", labeled_comm.label()));
            let curr_challenge = fs_rng.squeeze_short_nonnative_field_element::<E::Fr>();

            combined_values += &(value * curr_challenge);

            let comm = labeled_comm.commitment();
            let degree_bound = labeled_comm.degree_bound();

            // Applying opening challenge and randomness (used in batch_checking)
            let coeff = randomizer.unwrap_or_else(E::Fr::one) * curr_challenge;
            let comm_with_challenge: E::G1Projective = comm.0.mul(coeff);

            // Accumulate values in the BTreeMap
            *combined_comms.entry(degree_bound).or_insert_with(E::G1Projective::zero) += &comm_with_challenge;
            end_timer!(acc_timer);
        }

        // Push expected results into list of elems. Power will be the negative of the
        // expected power
        let mut bases = vec![vk.vk.g, -proof.w];
        let mut coeffs = vec![combined_values, point];
        if let Some(random_v) = proof.random_v {
            bases.push(vk.vk.gamma_g);
            coeffs.push(random_v);
        }
        *combined_witness += if let Some(randomizer) = randomizer {
            coeffs.iter_mut().for_each(|c| *c *= randomizer);
            proof.w.mul(randomizer)
        } else {
            proof.w.to_projective()
        };
        let coeffs = coeffs.into_iter().map(|c| c.into()).collect::<Vec<_>>();
        *combined_adjusted_witness += VariableBase::msm(&bases, &coeffs);
        Ok(())
    }

    fn check_elems(
        vk: &UniversalVerifier<E>,
        combined_comms: BTreeMap<Option<usize>, E::G1Projective>,
        combined_witness: E::G1Projective,
        combined_adjusted_witness: E::G1Projective,
    ) -> Result<bool> {
        let check_time = start_timer!(|| "Checking elems");
        defer! { end_timer!(check_time); }
        let mut g1_projective_elems = Vec::with_capacity(combined_comms.len() + 2);
        let mut g2_prepared_elems = Vec::with_capacity(combined_comms.len() + 2);

        for (degree_bound, comm) in combined_comms.into_iter() {
            let shift_power = if let Some(degree_bound) = degree_bound {
                // Find the appropriate prepared shift for the degree bound.
                vk.prepared_negative_powers_of_beta_h
                    .get(&degree_bound)
                    .cloned()
                    .ok_or(PCError::UnsupportedDegreeBound(degree_bound))?
            } else {
                vk.vk.prepared_h.clone()
            };

            g1_projective_elems.push(comm);
            g2_prepared_elems.push(shift_power);
        }

        g1_projective_elems.push(-combined_adjusted_witness);
        g2_prepared_elems.push(vk.vk.prepared_h.clone());

        g1_projective_elems.push(-combined_witness);
        g2_prepared_elems.push(vk.vk.prepared_beta_h.clone());

        let g1_prepared_elems_iter = E::G1Projective::batch_normalization_into_affine(g1_projective_elems)
            .into_iter()
            .map(|a| a.prepare())
            .collect::<Vec<_>>();

        ensure!(g1_prepared_elems_iter.len() == g2_prepared_elems.len());
        let g1_g2_prepared = g1_prepared_elems_iter.iter().zip_eq(g2_prepared_elems.iter());
        Ok(E::product_of_pairings(g1_g2_prepared).is_one())
    }
}

/// Contract tests for the device accumulation against the host sequence. They
/// require a device.
#[cfg(all(test, feature = "cuda", target_arch = "x86_64"))]
mod cuda_tests {
    use crate::fft::DensePolynomial;
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::Zero;
    use snarkvm_utilities::rand::{TestRng, Uniform};

    /// The fused chain has to reproduce all three host steps: the sum, the
    /// division by `X - z`, and the commitment to the quotient.
    #[test]
    fn accumulate_open_matches_the_host_sequence() {
        use crate::msm::variable_base::VariableBase;
        use snarkvm_curves::{ProjectiveCurve, bls12_377::G1Projective};
        use snarkvm_fields::PrimeField;

        let rng = &mut TestRng::default();
        let mut bad: Vec<String> = Vec::new();

        // The last case is the size of the largest query group in a real proof,
        // which the `varuna` suite's small circuits do not reach.
        for (out_len, lens) in [
            (1usize << 10, vec![1usize << 10]),
            (1 << 10, vec![1 << 10, 1 << 9, 700]),
            (1 << 12, vec![1 << 12, 1 << 11, 1 << 12, 3000]),
            (1 << 19, vec![1 << 19, 1 << 18, 1 << 18, 524287]),
        ] {
            let polys: Vec<DensePolynomial<Fr>> = lens
                .iter()
                .map(|n| DensePolynomial::from_coefficients_vec((0..*n).map(|_| Fr::rand(rng)).collect()))
                .collect();
            let coeffs: Vec<Fr> = lens.iter().map(|_| Fr::rand(rng)).collect();
            let z = Fr::rand(rng);
            // `bases[i] = (i + 1) · P`, built by repeated addition. The sum is
            // `(Σ (i + 1) · s_i) · P`, so any shift or mis-slice of the scalars
            // changes the result.
            let bases: Vec<_> = {
                let p = G1Projective::rand(rng);
                let mut acc = G1Projective::zero();
                let mut v = Vec::with_capacity(out_len - 1);
                for _ in 0..out_len - 1 {
                    acc += p;
                    v.push(acc);
                }
                G1Projective::batch_normalization_into_affine(v)
            };

            // The host sequence, written out.
            let mut combined = DensePolynomial::zero();
            for (c, p) in coeffs.iter().zip(&polys) {
                combined += (*c, p);
            }
            let (quotient, _) = combined.divide_by_monic_linear(z);
            let want = {
                let ints: Vec<_> = quotient.coeffs.iter().map(|c| c.to_bigint()).collect();
                VariableBase::msm(&bases[..ints.len()], &ints)
            };

            let terms: Vec<(Fr, &[Fr])> = coeffs.iter().zip(&polys).map(|(c, p)| (*c, p.coeffs.as_slice())).collect();
            match snarkvm_algorithms_cuda::accumulate_open::<_, G1Projective, _>(out_len, &terms, &z, &bases) {
                Err(_) => bad.push(format!("out {out_len}: the device call failed")),
                // The device commits to the untrimmed quotient and the host to
                // the trimmed one; zero scalars contribute nothing, so the
                // commitments agree.
                Ok(got) => {
                    if got.to_affine() != want.to_affine() {
                        bad.push(format!("out {out_len}: commitment differs"));
                    }
                }
            }
        }

        assert!(bad.is_empty(), "{}", bad.join("; "));
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_camel_case_types)]

    use super::{Bases, CommitterKey, CommitterUnionKey, SonicKZG10};
    use crate::{crypto_hash::PoseidonSponge, polycommit::test_templates::*};
    use snarkvm_curves::bls12_377::{Bls12_377, Fq};
    use snarkvm_utilities::{FromBytes, ToBytes, rand::TestRng};

    use itertools::Itertools;
    use rand::distr::Distribution;

    type Sponge = PoseidonSponge<Fq, 2, 1>;
    type PC_Bls12_377 = SonicKZG10<Bls12_377, Sponge>;

    #[test]
    fn test_committer_key_serialization() {
        let rng = &mut TestRng::default();
        let max_degree = rand::distr::Uniform::new_inclusive(8, 64).unwrap().sample(rng);
        let supported_degree = rand::distr::Uniform::new_inclusive(1, max_degree).unwrap().sample(rng);

        let lagrange_size = |d: usize| if d.is_power_of_two() { d } else { d.next_power_of_two() >> 1 };

        let pp = PC_Bls12_377::load_srs(max_degree).unwrap();

        let (ck, _vk) = PC_Bls12_377::trim(&pp, supported_degree, [lagrange_size(supported_degree)], 0, None).unwrap();

        let ck_bytes = ck.to_bytes_le().unwrap();
        let ck_recovered: CommitterKey<Bls12_377> = FromBytes::read_le(&ck_bytes[..]).unwrap();
        let ck_recovered_bytes = ck_recovered.to_bytes_le().unwrap();

        assert_eq!(&ck_bytes, &ck_recovered_bytes);
    }

    /// `trim` shares its bases with the SRS instead of copying them, and they
    /// are the same points a copy held.
    #[test]
    fn trim_shares_its_bases_with_the_srs() {
        let pp = PC_Bls12_377::load_srs((1 << 12) - 1).unwrap();
        let (ck, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        let top = pp.max_degree();

        assert!(matches!(ck.powers_of_beta_g, Bases::Shared { .. }));
        assert_eq!(ck.powers_of_beta_g.owned_capacity(), 0, "a shared prefix owns nothing");
        assert_eq!(&*ck.powers_of_beta_g, pp.powers_of_beta_g(0, 1001).unwrap().as_slice());

        let shifted = ck.shifted_powers_of_beta_g.as_ref().unwrap();
        assert!(matches!(shifted, Bases::Shared { .. }));
        assert_eq!(shifted.owned_capacity(), 0, "a shared suffix owns nothing");
        assert_eq!(&**shifted, pp.powers_of_beta_g(top - 500, top + 1).unwrap().as_slice());

        // Bytes, and so the key's hash, are those of the points, however held.
        let bytes = ck.to_bytes_le().unwrap();
        let read: CommitterKey<Bls12_377> = FromBytes::read_le(&bytes[..]).unwrap();
        assert!(matches!(read.powers_of_beta_g, Bases::Owned(_)), "a key read from bytes owns its bases");
        assert_eq!(read.to_bytes_le().unwrap(), bytes);
    }

    /// Growing the SRS replaces its snapshot, never mutating the one a key
    /// shares: a key trimmed before the growth reads the same points after it.
    #[cfg(feature = "filesystem")]
    #[test]
    fn a_key_keeps_its_snapshot_across_a_growth() {
        let pp = PC_Bls12_377::load_srs((1 << 15) - 1).unwrap();
        let (before, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        let points = before.powers_of_beta_g.to_vec();

        pp.download_powers_for(0..(1 << 16)).unwrap();
        let (after, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();

        assert_eq!(&*before.powers_of_beta_g, points.as_slice(), "the older snapshot changed");
        assert_eq!(&*after.powers_of_beta_g, points.as_slice());
        assert_ne!(
            before.powers_of_beta_g.as_ptr(),
            after.powers_of_beta_g.as_ptr(),
            "a key trimmed after the growth should share the new snapshot"
        );
    }

    /// Adding a file replaces the snapshot as a download does: a key trimmed
    /// before it reads the same points after it.
    #[test]
    #[cfg_attr(not(feature = "filesystem"), ignore = "reads the powers files that a run with `filesystem` caches")]
    fn a_key_keeps_its_snapshot_across_an_added_file() {
        let pp = PC_Bls12_377::load_srs((1 << 15) - 1).unwrap();
        let (before, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        let points = before.powers_of_beta_g.to_vec();

        let [file] = &pp.missing_files_for(0..(1 << 16)).unwrap()[..] else { panic!("expected one file") };
        pp.add_powers_file(file, &*cached_file_bytes(file)).unwrap();
        assert!(pp.missing_files_for(0..(1 << 16)).unwrap().is_empty());

        assert_eq!(&*before.powers_of_beta_g, points.as_slice(), "the older snapshot changed");
        let (after, _) = pp.shared_powers_of_beta_g(0, 1).unwrap();
        match &before.powers_of_beta_g {
            Bases::Shared { store, .. } => {
                assert!(!std::sync::Arc::ptr_eq(store, &after), "the file did not replace the snapshot")
            }
            Bases::Owned(_) => panic!("trim should share"),
        }
    }

    /// Without `filesystem`, `trim` names every file it needs in one error,
    /// and trims once they are added.
    #[cfg(not(feature = "filesystem"))]
    #[test]
    #[ignore = "reads the powers files that a run with `filesystem` caches"]
    fn trim_names_every_missing_file_at_once() {
        let (degree, bound) = (1 << 16, 1 << 16);
        let pp = super::UniversalParams::<Bls12_377>::load().unwrap();
        let top = pp.max_degree();
        let mut files = pp.missing_files_for(0..degree + 1).unwrap();
        let shifted = pp.missing_files_for(top - bound..top + 1).unwrap();
        assert!(files.len() == 2 && !shifted.is_empty());
        files.extend(shifted);

        let error = PC_Bls12_377::trim(&pp, degree, [], 1, Some(&[bound])).unwrap_err();
        assert_eq!(error.downcast::<snarkvm_parameters::mainnet::MissingPowers>().unwrap().files, files);

        for file in &files {
            pp.add_powers_file(file, &*cached_file_bytes(file)).unwrap();
        }
        let (ck, _) = PC_Bls12_377::trim(&pp, degree, [], 1, Some(&[bound])).unwrap();
        assert_eq!(&*ck.powers_of_beta_g, pp.powers_of_beta_g(0, degree + 1).unwrap().as_slice());
    }

    /// A `trim` whose Lagrange sizes grow the SRS shares the snapshot that
    /// growth made, not the one it replaced.
    #[cfg(feature = "filesystem")]
    #[test]
    fn trim_shares_the_snapshot_left_after_its_own_downloads() {
        let pp = PC_Bls12_377::load_srs((1 << 15) - 1).unwrap();
        let (ck, _) = PC_Bls12_377::trim(&pp, 1000, [1 << 16], 1, Some(&[500])).unwrap();
        let (current, _) = pp.shared_powers_of_beta_g(0, 1).unwrap();
        match &ck.powers_of_beta_g {
            Bases::Shared { store, .. } => {
                assert!(std::sync::Arc::ptr_eq(store, &current), "the key shares a snapshot its own trim replaced")
            }
            Bases::Owned(_) => panic!("trim should share"),
        }
    }

    /// An empty range asks for nothing, so it neither downloads nor replaces
    /// the snapshot keys share, even one starting where the held prefix ends.
    #[test]
    fn an_empty_range_leaves_the_snapshot_alone() {
        let pp = PC_Bls12_377::load_srs((1 << 15) - 1).unwrap();
        let (before, _) = pp.shared_powers_of_beta_g(0, 1).unwrap();
        let held = 1 << 15;
        assert!(pp.powers_of_beta_g(held, held).unwrap().is_empty());
        assert!(pp.powers_of_beta_g(0, 0).unwrap().is_empty());
        let (after, _) = pp.shared_powers_of_beta_g(0, 1).unwrap();
        assert!(std::sync::Arc::ptr_eq(&before, &after), "an empty range replaced the snapshot");
    }

    /// A `trim` that fails validation downloads nothing first, so a rejected
    /// call leaves the SRS, snapshot included, as it was.
    #[test]
    fn a_rejected_trim_downloads_nothing() {
        let pp = PC_Bls12_377::load_srs((1 << 15) - 1).unwrap();
        let (before, _) = pp.shared_powers_of_beta_g(0, 1).unwrap();
        let grown = 1 << 16;
        // A degree bound above the supported degree.
        assert!(PC_Bls12_377::trim(&pp, grown - 1, [], 1, Some(&[grown])).is_err());
        // A Lagrange size that is not a power of two, and one beyond the SRS.
        assert!(PC_Bls12_377::trim(&pp, grown - 1, [3], 1, None).is_err());
        assert!(PC_Bls12_377::trim(&pp, grown - 1, [1 << 29], 1, None).is_err());
        let (after, _) = pp.shared_powers_of_beta_g(0, 1).unwrap();
        assert!(std::sync::Arc::ptr_eq(&before, &after), "a rejected trim grew the SRS");
    }

    /// `to_mut` turns a shared range into an owned copy, leaving the SRS as it
    /// was.
    #[test]
    fn editing_a_shared_key_copies_it_first() {
        use super::Bases;
        let pp = PC_Bls12_377::load_srs((1 << 12) - 1).unwrap();
        let (mut ck, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        ck.powers_of_beta_g.to_mut().swap(0, 1);
        assert!(matches!(ck.powers_of_beta_g, Bases::Owned(_)));
        assert_ne!(&*ck.powers_of_beta_g, pp.powers_of_beta_g(0, 1001).unwrap().as_slice());
        let (fresh, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        assert_eq!(&*fresh.powers_of_beta_g, pp.powers_of_beta_g(0, 1001).unwrap().as_slice());
    }

    /// Reading with an SRS shares the ends of the powers it holds, and the key
    /// writes the same bytes it was read from.
    #[test]
    fn reading_with_the_srs_shares_what_it_holds() {
        let pp = PC_Bls12_377::load_srs((1 << 12) - 1).unwrap();
        let (ck, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        let bytes = ck.to_bytes_le().unwrap();

        // Another instance of the SRS holds the same powers.
        for srs in [&pp, &PC_Bls12_377::load_srs((1 << 12) - 1).unwrap()] {
            let read = CommitterKey::<Bls12_377>::read_le_with_srs(&bytes[..], srs).unwrap();
            assert!(matches!(read.powers_of_beta_g, Bases::Shared { .. }));
            assert!(matches!(read.shifted_powers_of_beta_g, Some(Bases::Shared { .. })));
            assert_eq!(read.to_bytes_le().unwrap(), bytes);
        }
    }

    /// A key whose powers the SRS does not hold does not read, and nothing is
    /// downloaded.
    #[test]
    fn reading_with_the_srs_rejects_what_it_lacks() {
        let fresh = PC_Bls12_377::load_srs((1 << 12) - 1).unwrap();
        let (ck, _) = PC_Bls12_377::trim(&fresh, 1000, [], 1, Some(&[500])).unwrap();
        let mut bytes = ck.to_bytes_le().unwrap();
        // A fresh SRS holds the first 2^15 powers, one fewer than the key now
        // claims. The read fails before it reaches a point.
        let powers_len: u32 = (1 << 15) + 1;
        bytes[..4].copy_from_slice(&powers_len.to_le_bytes());

        let (before, _) = fresh.shared_powers_of_beta_g(0, 1).unwrap();
        let err = CommitterKey::<Bls12_377>::read_le_with_srs(&bytes[..], &fresh).unwrap_err();
        assert!(err.to_string().contains(&powers_len.to_string()), "{err}");
        let (after, _) = fresh.shared_powers_of_beta_g(0, 1).unwrap();
        assert!(std::sync::Arc::ptr_eq(&before, &after), "reading downloaded powers");
    }

    /// The hash checks a key read with an SRS, including the points taken from
    /// the SRS. Points that were skipped are never used.
    #[test]
    fn reading_with_the_srs_checks_the_hash() {
        let pp = PC_Bls12_377::load_srs((1 << 12) - 1).unwrap();
        let (ck, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        let bytes = ck.to_bytes_le().unwrap();

        let mut wrong_hash = bytes.clone();
        *wrong_hash.last_mut().unwrap() ^= 1;
        assert!(CommitterKey::<Bls12_377>::read_le_with_srs(&wrong_hash[..], &pp).is_err());
        assert!(CommitterKey::<Bls12_377>::read_le_with_srs(&bytes[..bytes.len() - 1], &pp).is_err());

        // A byte inside the skipped prefix: `read_le` rejects it, and the key
        // read with the SRS is still the right one.
        let mut corrupt_point = bytes.clone();
        corrupt_point[4 + 10] ^= 1;
        assert!(CommitterKey::<Bls12_377>::read_le(&corrupt_point[..]).is_err());
        let read = CommitterKey::<Bls12_377>::read_le_with_srs(&corrupt_point[..], &pp).unwrap();
        assert_eq!(read.to_bytes_le().unwrap(), bytes);
    }

    /// A shifted length beyond the SRS is rejected before anything is
    /// allocated for it.
    #[test]
    fn reading_rejects_too_many_shifted_powers() {
        let pp = PC_Bls12_377::load_srs((1 << 12) - 1).unwrap();
        let (ck, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        let mut bytes = ck.to_bytes_le().unwrap();

        // The powers, an empty list of Lagrange bases, the hiding powers, and the
        // flag for the shifted powers come before the shifted length.
        let point = 97;
        let offset = 4 + 1001 * point + 4 + 4 + 3 * point + 1;
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(CommitterKey::<Bls12_377>::read_le(&bytes[..]).is_err());
        assert!(CommitterKey::<Bls12_377>::read_le_with_srs(&bytes[..], &pp).is_err());
    }

    /// A hiding length beyond the SRS is rejected before anything is allocated
    /// for it.
    #[test]
    fn reading_rejects_too_many_hiding_powers() {
        let pp = PC_Bls12_377::load_srs((1 << 12) - 1).unwrap();
        let (ck, _) = PC_Bls12_377::trim(&pp, 1000, [], 1, Some(&[500])).unwrap();
        let mut bytes = ck.to_bytes_le().unwrap();

        // The powers and an empty list of Lagrange bases come before the hiding
        // length.
        let point = 97;
        let offset = 4 + 1001 * point + 4;
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        for read in [CommitterKey::<Bls12_377>::read_le(&bytes[..]), CommitterKey::read_le_with_srs(&bytes[..], &pp)] {
            let err = read.unwrap_err();
            assert!(err.to_string().contains("too many hiding points"), "{err}");
        }
    }

    #[test]
    fn test_union_takes_each_array_from_the_key_where_it_is_longest() {
        let pp = PC_Bls12_377::load_srs(32).unwrap();
        // Each key holds the longest of a different array: the prefix, the shifted
        // powers, and the hiding powers, including for the bound all three enforce.
        let (long_prefix, _) = PC_Bls12_377::trim(&pp, 16, [], 0, Some(&[4])).unwrap();
        let (long_suffix, _) = PC_Bls12_377::trim(&pp, 12, [], 0, Some(&[4, 10])).unwrap();
        let (long_hiding, _) = PC_Bls12_377::trim(&pp, 8, [], 1, Some(&[4])).unwrap();
        let shifted_hiding = |ck: &CommitterKey<Bls12_377>, bound| {
            ck.shifted_powers_of_beta_times_gamma_g.as_ref().unwrap()[&bound].clone()
        };

        for keys in [&long_prefix, &long_suffix, &long_hiding].into_iter().permutations(3) {
            let union = CommitterUnionKey::union(keys);
            assert_eq!(&*union.powers().powers_of_beta_g, &*long_prefix.powers_of_beta_g);
            assert_eq!(union.powers().powers_of_beta_times_gamma_g, long_hiding.powers_of_beta_times_gamma_g);
            for (bound, hiding) in [(4, shifted_hiding(&long_hiding, 4)), (10, shifted_hiding(&long_suffix, 10))] {
                let shifted = union.shifted_powers_of_beta_g(bound).unwrap();
                let top = pp.max_degree();
                assert_eq!(
                    shifted.powers_of_beta_g,
                    pp.powers_of_beta_g(top - bound, top + 1).unwrap(),
                    "bound {bound}"
                );
                assert_eq!(shifted.powers_of_beta_times_gamma_g, hiding, "bound {bound}");
            }
        }
    }

    #[test]
    fn test_single_poly() {
        single_poly_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_quadratic_poly_degree_bound_multiple_queries() {
        quadratic_poly_degree_bound_multiple_queries_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_linear_poly_degree_bound() {
        linear_poly_degree_bound_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_single_poly_degree_bound() {
        single_poly_degree_bound_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_single_poly_degree_bound_multiple_queries() {
        single_poly_degree_bound_multiple_queries_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_two_polys_degree_bound_single_query() {
        two_polys_degree_bound_single_query_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
    }

    #[test]
    fn test_full_end_to_end() {
        full_end_to_end_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
        println!("Finished bls12-377");
    }

    #[test]
    fn test_single_equation() {
        single_equation_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
        println!("Finished bls12-377");
    }

    #[test]
    fn test_two_equation() {
        two_equation_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
        println!("Finished bls12-377");
    }

    #[test]
    fn test_two_equation_degree_bound() {
        two_equation_degree_bound_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
        println!("Finished bls12-377");
    }

    #[test]
    fn test_full_end_to_end_equation() {
        full_end_to_end_equation_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
        println!("Finished bls12-377");
    }

    #[test]
    #[should_panic]
    fn test_bad_degree_bound() {
        bad_degree_bound_test::<Bls12_377, Sponge>().expect("test failed for bls12-377");
        println!("Finished bls12-377");
    }

    #[test]
    fn test_lagrange_commitment() {
        crate::polycommit::test_templates::lagrange_test_template::<Bls12_377, Sponge>()
            .expect("test failed for bls12-377");
        println!("Finished bls12-377");
    }
}
