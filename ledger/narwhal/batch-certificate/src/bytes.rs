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
    /// Used by FromBytes and FromBytesUnchecked.
    fn read_signatures<R: Read>(mut reader: R, unchecked: bool) -> IoResult<IndexSet<Signature<N>>> {
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
        // Read the signatures.
        let signatures = cfg_chunks!(signature_bytes, Signature::<N>::size_in_bytes())
            .map(|data| Signature::read_le_with_unchecked(data, unchecked))
            .collect::<Result<IndexSet<_>, _>>()?;
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
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid batch certificate version"));
        }

        // Read the batch header and signatures.
        let batch_header = BatchHeader::read_le(&mut reader)?;
        let signatures = Self::read_signatures(reader, false)?;

        // Return the batch certificate.
        Self::from(batch_header, signatures).map_err(error)
    }

    /// Reads the batch certificate from the buffer.
    fn read_le_unchecked<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid batch certificate version"));
        }

        // Read the batch header and signatures.
        let batch_header = BatchHeader::read_le_unchecked(&mut reader)?;
        let signatures = Self::read_signatures(reader, true)?;

        // Return the batch certificate without performing additional checks.
        Self::from_unchecked(batch_header, signatures).map_err(error)
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
