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

#![forbid(unsafe_code)]
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_console as console;

mod bytes;
mod serialize;
mod string;

use console::{
    account::{Address, ComputeKeyCache, Signature},
    prelude::*,
    types::Field,
};
use snarkvm_ledger_narwhal_batch_header::BatchHeader;
use snarkvm_ledger_narwhal_transmission_id::TransmissionID;

use core::hash::{Hash, Hasher};
use indexmap::IndexSet;
use std::{collections::HashSet, sync::OnceLock};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

#[derive(Clone)]
pub struct BatchCertificate<N: Network> {
    /// The batch header.
    batch_header: BatchHeader<N>,
    /// The signatures for the batch ID from the committee.
    signatures: IndexSet<Signature<N>>,
    /// The recovered address of each signer, in the same order as `signatures`.
    ///
    /// This is derived data, cached because recovering a signer address is expensive: it is a
    /// fixed-base scalar multiplication per signature (see `Signature::to_address`), and the
    /// same addresses were previously recomputed at every point that needed them.
    ///
    /// It is populated eagerly by `from`, which already recovers the addresses in order to
    /// validate them, and lazily on first use otherwise (see `signers`). It is never
    /// serialized, and it takes no part in `PartialEq`, `Eq`, or `Hash`, all of which are
    /// keyed on the batch ID alone.
    signers: OnceLock<Vec<Address<N>>>,
}

impl<N: Network> BatchCertificate<N> {
    /// The maximum number of signatures in a batch certificate.
    pub fn max_signatures() -> u16 {
        N::LATEST_MAX_CERTIFICATES()
    }
}

impl<N: Network> BatchCertificate<N> {
    /// Initializes a new batch certificate.
    pub fn from(batch_header: BatchHeader<N>, signatures: IndexSet<Signature<N>>) -> Result<Self> {
        Self::from_internal(batch_header, signatures, None)
    }

    /// Initializes a new batch certificate, verifying its signatures through `cache` if there is one.
    ///
    /// The caller counts the verifications in `cache` once the certificate passes its remaining checks.
    fn from_internal(
        batch_header: BatchHeader<N>,
        signatures: IndexSet<Signature<N>>,
        cache: Option<&ComputeKeyCache<N>>,
    ) -> Result<Self> {
        // Ensure that the number of signatures is within bounds.
        ensure!(signatures.len() <= Self::max_signatures() as usize, "Invalid number of signatures");

        // Collect the signatures so that they can be verified in parallel.
        let signature_list = signatures.iter().collect::<Vec<_>>();

        // Verify each signature and recover its signer's address, in the same order as `signatures`.
        // The addresses are cached on the certificate so that `signers` need not recompute them.
        let batch_id = batch_header.batch_id();
        let signers = cfg_iter!(signature_list)
            .map(|signature| {
                match cache {
                    Some(cache) => cache.verify_and_recover_signer(signature, &[batch_id]),
                    None => signature.verify_and_recover_signer(&[batch_id]),
                }
                .ok_or_else(|| anyhow!("Invalid batch certificate signature"))
            })
            .collect::<Result<Vec<_>>>()?;

        // Ensure that the signature is from a unique signer and not from the author.
        let signature_authors = signers.iter().copied().collect::<HashSet<_>>();
        ensure!(
            !signature_authors.contains(&batch_header.author()),
            "The author's signature was included in the signers"
        );
        ensure!(signature_authors.len() == signatures.len(), "A duplicate author was found in the set of signatures");

        // Drop the borrows of `signatures` before handing it over.
        drop(signature_list);

        // Return the batch certificate.
        let certificate = Self::from_unchecked(batch_header, signatures)?;
        // Cache the addresses recovered above. `from_unchecked` always returns an empty cache,
        // so this cannot fail.
        let _ = certificate.signers.set(signers);
        Ok(certificate)
    }

    /// Initializes a new batch certificate.
    pub fn from_unchecked(batch_header: BatchHeader<N>, signatures: IndexSet<Signature<N>>) -> Result<Self> {
        // Ensure the signatures are not empty.
        ensure!(!signatures.is_empty(), "Batch certificate must contain signatures");
        // Return the batch certificate. Note the signer cache starts out empty here, and is
        // populated on first use by `signers`.
        Ok(Self { batch_header, signatures, signers: OnceLock::new() })
    }
}

impl<N: Network> PartialEq for BatchCertificate<N> {
    fn eq(&self, other: &Self) -> bool {
        self.batch_id() == other.batch_id()
    }
}

impl<N: Network> Eq for BatchCertificate<N> {}

impl<N: Network> Hash for BatchCertificate<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.batch_header.batch_id().hash(state);
    }
}

impl<N: Network> BatchCertificate<N> {
    /// Returns the certificate ID.
    pub const fn id(&self) -> Field<N> {
        self.batch_header.batch_id()
    }

    /// Returns the batch header.
    pub const fn batch_header(&self) -> &BatchHeader<N> {
        &self.batch_header
    }

    /// Returns the batch ID.
    pub const fn batch_id(&self) -> Field<N> {
        self.batch_header().batch_id()
    }

    /// Returns the author.
    pub const fn author(&self) -> Address<N> {
        self.batch_header().author()
    }

    /// Returns the round.
    pub const fn round(&self) -> u64 {
        self.batch_header().round()
    }

    /// Returns the timestamp of the batch header.
    pub fn timestamp(&self) -> i64 {
        self.batch_header().timestamp()
    }

    /// Returns the committee ID.
    pub const fn committee_id(&self) -> Field<N> {
        self.batch_header().committee_id()
    }

    /// Returns the transmission IDs.
    pub const fn transmission_ids(&self) -> &IndexSet<TransmissionID<N>> {
        self.batch_header().transmission_ids()
    }

    /// Returns the batch certificate IDs for the previous round.
    pub const fn previous_certificate_ids(&self) -> &IndexSet<Field<N>> {
        self.batch_header().previous_certificate_ids()
    }

    /// Returns the signatures of the batch ID from the committee.
    pub fn signatures(&self) -> Box<dyn '_ + ExactSizeIterator<Item = &Signature<N>>> {
        Box::new(self.signatures.iter())
    }

    /// Returns the address of each signer, in the same order as `signatures`.
    ///
    /// Note that this does **not** include the certificate's author, whose signature is not
    /// part of `signatures`; use `author` for that.
    ///
    /// Prefer this over mapping `Signature::to_address` over `signatures`. Recovering a signer
    /// address is a fixed-base scalar multiplication, and certificates are checked, stored, and
    /// inspected many times over their lifetime, so recomputing it at each site is significant
    /// wasted work. Certificates built by `from` already have this populated.
    ///
    /// The lazy path takes a lock for the duration of the recovery. It is a leaf: nothing else
    /// is acquired underneath it, and the work is pure computation, so it cannot participate in
    /// a lock cycle.
    pub fn signers(&self) -> &[Address<N>] {
        self.signers.get_or_init(|| self.signatures.iter().map(|signature| signature.to_address()).collect())
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{account::PrivateKey, network::MainnetV0, prelude::TestRng, types::Field};

    use indexmap::IndexSet;

    type CurrentNetwork = MainnetV0;

    /// Returns a sample batch certificate, sampled at random.
    pub fn sample_batch_certificate(rng: &mut TestRng) -> BatchCertificate<CurrentNetwork> {
        sample_batch_certificate_for_round(rng.random(), rng)
    }

    /// Returns a sample batch certificate with a given round; the rest is sampled at random.
    pub fn sample_batch_certificate_for_round(round: u64, rng: &mut TestRng) -> BatchCertificate<CurrentNetwork> {
        // Sample certificate IDs.
        let certificate_ids = (0..10).map(|_| Field::<CurrentNetwork>::rand(rng)).collect::<IndexSet<_>>();
        // Return the batch certificate.
        sample_batch_certificate_for_round_with_previous_certificate_ids(round, certificate_ids, rng)
    }

    /// Returns a sample batch certificate with a given round and the given certificate ids as predecessors; the rest is sampled at random.
    pub fn sample_batch_certificate_for_round_with_previous_certificate_ids(
        round: u64,
        previous_certificate_ids: IndexSet<Field<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> BatchCertificate<CurrentNetwork> {
        let committee: Vec<_> = (0..5).map(|_| PrivateKey::new(rng).unwrap()).collect();
        sample_batch_certificate_for_round_with_committee(
            round,
            previous_certificate_ids,
            &committee[0],
            &committee[1..],
            rng,
        )
    }

    /// Same as `sample_batch_certificate_for_round_with_previous_certificate_ids`, but also allows you to set the private keys that sign the certificate.
    pub fn sample_batch_certificate_for_round_with_committee(
        round: u64,
        previous_certificate_ids: IndexSet<Field<CurrentNetwork>>,
        author: &PrivateKey<CurrentNetwork>,
        signers: &[PrivateKey<CurrentNetwork>],
        rng: &mut TestRng,
    ) -> BatchCertificate<CurrentNetwork> {
        // Sample a batch header.
        let batch_header =
            snarkvm_ledger_narwhal_batch_header::test_helpers::sample_batch_header_for_round_and_key_with_previous_certificate_ids(
                round,
                author,
                previous_certificate_ids,
                rng,
            );
        // Generate the endorsements.
        let signatures: IndexSet<_> =
            signers.iter().map(|private_key| private_key.sign(&[batch_header.batch_id()], rng).unwrap()).collect();

        // Return the batch certificate.
        BatchCertificate::from(batch_header, signatures).unwrap()
    }

    /// Returns a list of sample batch certificates, sampled at random.
    pub fn sample_batch_certificates(rng: &mut TestRng) -> IndexSet<BatchCertificate<CurrentNetwork>> {
        // Initialize a sample vector.
        let mut sample = IndexSet::with_capacity(10);
        // Append sample batch certificates.
        for _ in 0..10 {
            sample.insert(sample_batch_certificate(rng));
        }
        // Return the sample vector.
        sample
    }

    /// Returns a sample batch certificate with previous certificates, sampled at random.
    pub fn sample_batch_certificate_with_previous_certificates(
        round: u64,
        rng: &mut TestRng,
    ) -> (BatchCertificate<CurrentNetwork>, Vec<BatchCertificate<CurrentNetwork>>) {
        assert!(round > 1, "Round must be greater than 1");

        // Initialize the round parameters.
        let previous_round = round - 1; // <- This must be an even number, for `BFT::update_dag` to behave correctly below.
        let current_round = round;

        assert_eq!(previous_round % 2, 0, "Previous round must be even");

        // Sample the previous certificates.
        let previous_certificates = vec![
            sample_batch_certificate_for_round(previous_round, rng),
            sample_batch_certificate_for_round(previous_round, rng),
            sample_batch_certificate_for_round(previous_round, rng),
            sample_batch_certificate_for_round(previous_round, rng),
        ];
        // Construct the previous certificate IDs.
        let previous_certificate_ids: IndexSet<_> = previous_certificates.iter().map(|c| c.id()).collect();
        // Sample the leader certificate.
        let certificate = sample_batch_certificate_for_round_with_previous_certificate_ids(
            current_round,
            previous_certificate_ids,
            rng,
        );

        (certificate, previous_certificates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{account::PrivateKey, network::MainnetV0, prelude::TestRng, types::Field};

    type CurrentNetwork = MainnetV0;

    /// Recovers the signer addresses the naive way, which is what `signers` replaces.
    fn recompute_signers(certificate: &BatchCertificate<CurrentNetwork>) -> Vec<Address<CurrentNetwork>> {
        certificate.signatures().map(|signature| signature.to_address()).collect()
    }

    #[test]
    fn test_signers_matches_recomputation() {
        let rng = &mut TestRng::default();

        for _ in 0..8 {
            let certificate = test_helpers::sample_batch_certificate(rng);
            // The cache was populated eagerly by `from`; it must agree with recomputation,
            // and must preserve the order of `signatures`.
            assert_eq!(certificate.signers(), recompute_signers(&certificate));
        }
    }

    #[test]
    fn test_from_rejects_invalid_signers() {
        let rng = &mut TestRng::default();

        let committee: Vec<_> = (0..5).map(|_| PrivateKey::<CurrentNetwork>::new(rng).unwrap()).collect();
        let batch_header =
            snarkvm_ledger_narwhal_batch_header::test_helpers::sample_batch_header_for_round_and_key_with_previous_certificate_ids(
                rng.random(),
                &committee[0],
                (0..10).map(|_| Field::rand(rng)).collect(),
                rng,
            );
        let batch_id = batch_header.batch_id();
        let endorse = |signers: &[PrivateKey<CurrentNetwork>], message: Field<CurrentNetwork>, rng: &mut TestRng| {
            signers.iter().map(|private_key| private_key.sign(&[message], rng).unwrap()).collect::<IndexSet<_>>()
        };

        // An honest endorsement set is accepted.
        assert!(BatchCertificate::from(batch_header.clone(), endorse(&committee[1..], batch_id, rng)).is_ok());

        // A signature over another message is rejected, wherever it sits in the set.
        for position in 1..committee.len() {
            let mut signatures = endorse(&committee[1..], batch_id, rng);
            let forged = committee[position].sign(&[Field::rand(rng)], rng).unwrap();
            signatures.replace_index(position - 1, forged).unwrap();
            assert!(BatchCertificate::from(batch_header.clone(), signatures).is_err());
        }

        // The author's own signature is rejected.
        assert!(BatchCertificate::from(batch_header.clone(), endorse(&committee, batch_id, rng)).is_err());

        // Two signatures from one signer are rejected.
        let mut signatures = endorse(&committee[1..], batch_id, rng);
        signatures.insert(committee[1].sign(&[batch_id], rng).unwrap());
        assert!(BatchCertificate::from(batch_header, signatures).is_err());
    }

    #[test]
    fn test_signers_excludes_the_author() {
        let rng = &mut TestRng::default();

        let certificate = test_helpers::sample_batch_certificate(rng);
        assert!(!certificate.signers().is_empty());
        // `from` rejects a certificate whose author signed it, so the author must never appear.
        assert!(!certificate.signers().contains(&certificate.author()));
    }

    #[test]
    fn test_signers_is_lazily_populated_after_deserialization() {
        let rng = &mut TestRng::default();

        let certificate = test_helpers::sample_batch_certificate(rng);
        let expected = certificate.signers().to_vec();

        // `read_le_unchecked` goes through `from_unchecked`, which leaves the cache empty, so
        // this exercises the lazy path rather than the one populated by `from`.
        let bytes = certificate.to_bytes_le().unwrap();
        let recovered = BatchCertificate::<CurrentNetwork>::read_le_unchecked(&bytes[..]).unwrap();
        assert!(recovered.signers.get().is_none(), "the cache should start out empty");

        assert_eq!(recovered.signers(), expected);
        // A second call must return the same cached value.
        assert_eq!(recovered.signers(), expected);
    }

    #[test]
    fn test_signers_survives_cloning() {
        let rng = &mut TestRng::default();

        let certificate = test_helpers::sample_batch_certificate(rng);
        let expected = certificate.signers().to_vec();

        // Cloning a populated certificate carries the cache over.
        assert_eq!(certificate.clone().signers(), expected);

        // Cloning an unpopulated one leaves it unpopulated, and it still resolves correctly.
        let bytes = certificate.to_bytes_le().unwrap();
        let unpopulated = BatchCertificate::<CurrentNetwork>::read_le_unchecked(&bytes[..]).unwrap();
        let cloned = unpopulated.clone();
        assert!(cloned.signers.get().is_none(), "cloning must not populate the cache");
        assert_eq!(cloned.signers(), expected);
    }
}
