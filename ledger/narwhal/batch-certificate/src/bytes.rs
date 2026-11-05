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

use super::*;

impl<N: Network> BatchCertificate<N> {
    /// Reads the batch certificate either with or without checks on the data, decoding each
    /// compute key only if `cache` holds no earlier decode of the same bytes.
    pub fn read_le_with_cache<R: Read>(
        mut reader: R,
        unchecked: bool,
        cache: &mut ComputeKeyCache<N>,
    ) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid batch certificate version"));
        }

        // Read the batch header and signatures.
        let batch_header = BatchHeader::read_le_with_cache(&mut reader, unchecked, cache)?;
        let signatures = Self::read_signatures(reader, unchecked, cache)?;

        // Return the batch certificate, performing the additional checks only if `unchecked` is false.
        if unchecked {
            Self::from_unchecked(batch_header, signatures).map_err(error)
        } else {
            Self::from(batch_header, signatures).map_err(error)
        }
    }

    /// Reads the signatures of a batch certificate.
    fn read_signatures<R: Read>(
        mut reader: R,
        unchecked: bool,
        cache: &mut ComputeKeyCache<N>,
    ) -> IoResult<IndexSet<Signature<N>>> {
        // Read the number of signatures.
        let num_signatures = u16::read_le(&mut reader)?;
        // Ensure the number of signatures is within bounds.
        if num_signatures > Self::max_signatures() {
            return Err(error(format!(
                "Number of signatures ({num_signatures}) exceeds the maximum ({})",
                Self::max_signatures()
            )));
        }
        // Read the signature bytes.
        let mut signature_bytes = vec![0u8; num_signatures as usize * Signature::<N>::size_in_bytes()];
        reader.read_exact(&mut signature_bytes)?;
        // Read the signatures. This stays serial: with cached compute keys, a rayon fork-join costs more than the reads.
        let mut signatures = IndexSet::with_capacity(num_signatures as usize);
        for data in signature_bytes.chunks_exact(Signature::<N>::size_in_bytes()) {
            signatures.insert(Signature::read_le_with_cache(data, unchecked, cache)?);
        }
        // Ensure no signature was repeated. The set absorbs a repeat, so it would
        // otherwise give one certificate a second encoding.
        if signatures.len() != num_signatures as usize {
            return Err(error("Duplicate signature in batch certificate"));
        }
        Ok(signatures)
    }
}

impl<N: Network> FromBytes for BatchCertificate<N> {
    /// Reads the batch certificate from the buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_cache(reader, false, &mut ComputeKeyCache::default())
    }

    /// Reads the batch certificate from the buffer.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_cache(reader, true, &mut ComputeKeyCache::default())
    }
}

impl<N: Network> ToBytes for BatchCertificate<N> {
    /// Writes the batch certificate to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;
        // Write the batch header.
        self.batch_header.write_le(&mut writer)?;
        // Write the number of signatures.
        u16::try_from(self.signatures.len()).map_err(error)?.write_le(&mut writer)?;
        // Write the signatures.
        for signature in self.signatures.iter() {
            // Write the signature.
            signature.write_le(&mut writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        let rng = &mut TestRng::default();

        for expected in crate::test_helpers::sample_batch_certificates(rng) {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, BatchCertificate::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, BatchCertificate::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }

    /// Returns the `Debug` output of every compute key in `certificate`, which shows `sk_prf`.
    fn compute_key_debug(certificate: &BatchCertificate<console::network::MainnetV0>) -> Vec<String> {
        std::iter::once(certificate.batch_header().signature())
            .chain(certificate.signatures())
            .map(|signature| format!("{:?}", signature.compute_key()))
            .collect()
    }

    #[test]
    fn test_bytes_with_cache() {
        use console::{account::PrivateKey, types::Field};

        let rng = &mut TestRng::default();
        let committee: Vec<_> = (0..5).map(|_| PrivateKey::new(rng).unwrap()).collect();
        // Each member authors one certificate, and the others sign it.
        let certificates: Vec<_> = (0..committee.len())
            .map(|i| {
                let signers: Vec<_> = committee.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, k)| *k).collect();
                crate::test_helpers::sample_batch_certificate_for_round_with_committee(
                    rng.random(),
                    (0..10).map(|_| Field::rand(rng)).collect(),
                    &committee[i],
                    &signers,
                    rng,
                )
            })
            .collect();

        let mut cache = ComputeKeyCache::default();
        for unchecked in [false, true, false, true] {
            for certificate in &certificates {
                let bytes = certificate.to_bytes_le().unwrap();
                let cold = BatchCertificate::read_le_with_unchecked(&bytes[..], unchecked).unwrap();
                let cached = BatchCertificate::read_le_with_cache(&bytes[..], unchecked, &mut cache).unwrap();
                assert_eq!(certificate, &cached);
                assert_eq!(compute_key_debug(&cold), compute_key_debug(&cached));
            }
        }
        // One entry per committee member.
        assert_eq!(cache.len(), committee.len());

        // A warm cache still rejects a wrong signature on the checked path and a bad compute key on both paths.
        let exact = certificates[0].to_bytes_le().unwrap();
        let signatures_at = 1 + certificates[0].batch_header().to_bytes_le().unwrap().len() + 2;
        let mut bad_response = exact.clone();
        bad_response[signatures_at + 32] ^= 1;
        let mut bad_compute_key = exact.clone();
        bad_compute_key[signatures_at + 64..signatures_at + 96].fill(0xFF);
        assert!(BatchCertificate::read_le_with_cache(&bad_response[..], false, &mut cache).is_err());
        assert!(BatchCertificate::read_le_with_cache(&bad_response[..], true, &mut cache).is_ok());
        assert!(BatchCertificate::read_le_with_cache(&bad_compute_key[..], false, &mut cache).is_err());
        assert!(BatchCertificate::read_le_with_cache(&bad_compute_key[..], true, &mut cache).is_err());
        assert_eq!(cache.len(), committee.len());
    }

    #[test]
    fn test_first_invalid_signature_sets_the_error() {
        let rng = &mut TestRng::default();
        let certificate = crate::test_helpers::sample_batch_certificate(rng);
        let exact = certificate.to_bytes_le().unwrap();
        let width = Signature::<console::network::MainnetV0>::size_in_bytes();
        let signatures_at = 1 + certificate.batch_header().to_bytes_le().unwrap().len() + 2;
        let last_at = exact.len() - width;
        assert!(last_at > signatures_at, "a sampled certificate carries several signatures");

        // Two x-coordinates with no point in the subgroup, which fail with different messages.
        let mut invalid = (1u64..)
            .map(console::types::Field::<console::network::MainnetV0>::from_u64)
            .filter(|x| console::types::Group::<console::network::MainnetV0>::from_x_coordinate(*x).is_err());
        // The filter is over an unbounded range in which most x-coordinates are invalid, so the `unwrap`s cannot panic.
        let (x, y) = (invalid.next().unwrap().to_bytes_le().unwrap(), invalid.next().unwrap().to_bytes_le().unwrap());

        // An invalid `pk_sig` in the first signature and in the last.
        let mut bytes = exact.clone();
        bytes[signatures_at + 64..signatures_at + 96].copy_from_slice(&x);
        bytes[last_at + 64..last_at + 96].copy_from_slice(&y);

        for unchecked in [false, true] {
            let read = |at: usize| {
                Signature::<console::network::MainnetV0>::read_le_with_unchecked(&bytes[at..at + width], unchecked)
                    .unwrap_err()
                    .to_string()
            };
            let (first, last) = (read(signatures_at), read(last_at));
            assert_ne!(first, last);
            let error = BatchCertificate::<console::network::MainnetV0>::read_le_with_unchecked(&bytes[..], unchecked)
                .unwrap_err()
                .to_string();
            assert_eq!(error, first);
        }
    }

    #[test]
    fn test_duplicate_signature_is_rejected() {
        let rng = &mut TestRng::default();
        let certificate = crate::test_helpers::sample_batch_certificate(rng);
        let exact = certificate.to_bytes_le().unwrap();

        // The honest encoding must keep working.
        assert_eq!(certificate, BatchCertificate::read_le(&exact[..]).unwrap());

        // version, then the batch header, then the signature count.
        let count_at = 1 + certificate.batch_header().to_bytes_le().unwrap().len();
        let count = u16::from_le_bytes([exact[count_at], exact[count_at + 1]]) as usize;
        assert_eq!(count, certificate.signatures().count(), "offset arithmetic is wrong if this fails");
        assert!(count > 0, "a sampled certificate carries signatures");

        let width = certificate.signatures().next().unwrap().to_bytes_le().unwrap().len();
        let signatures_at = count_at + 2;
        let mut padded = exact.clone();
        padded[count_at..count_at + 2].copy_from_slice(&(u16::try_from(count).unwrap() + 1).to_le_bytes());
        let first = exact[signatures_at..signatures_at + width].to_vec();
        padded.splice(signatures_at + width..signatures_at + width, first);
        assert_ne!(padded, exact);

        // The set absorbs the repeat, so the certificate is unchanged and only
        // its bytes differ.
        assert!(
            BatchCertificate::<console::network::MainnetV0>::read_le(&padded[..]).is_err(),
            "a certificate repeating a signature must be rejected"
        );
    }
}
