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

impl<N: Network> Subdag<N> {
    /// Shared functionality between FromBytes and FromBytesUnchecked.
    fn internal_read_le<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error(format!("Invalid subdag version ({version})")));
        }

        // Read the number of rounds.
        let num_rounds = u32::read_le(&mut reader)?;
        // Ensure the number of rounds is within bounds.
        if num_rounds as u64 > Self::MAX_ROUNDS {
            return Err(error(format!("Number of rounds ({num_rounds}) exceeds the maximum ({})", Self::MAX_ROUNDS)));
        }
        // Read the round certificates.
        let mut subdag = BTreeMap::new();
        // The writer emits rounds in `BTreeMap` order, so an encoding whose rounds
        // are not strictly ascending is a second encoding of the same subdag: the
        // map would sort and deduplicate it back into the canonical one.
        let mut previous_round: Option<u64> = None;
        for _ in 0..num_rounds {
            // Read the round.
            let round = u64::read_le(&mut reader)?;
            if let Some(previous) = previous_round
                && round <= previous
            {
                return Err(error(format!("Subdag round {round} does not follow {previous} in ascending order")));
            }
            previous_round = Some(round);
            // Read the number of certificates.
            let num_certificates = u16::read_le(&mut reader)?;
            // Ensure the number of certificates is within bounds.
            if num_certificates > N::LATEST_MAX_CERTIFICATES() {
                return Err(error(format!("Number of certificates ({num_certificates}) exceeds the maximum.",)));
            }
            // Read the certificates.
            let mut certificates = IndexSet::with_capacity(num_certificates as usize);
            for _ in 0..num_certificates {
                let cert = BatchCertificate::read_le_with_unchecked(&mut reader, unchecked)?;
                certificates.insert(cert);
            }
            // Ensure no certificate was repeated within the round.
            if certificates.len() != num_certificates as usize {
                return Err(error(format!("Duplicate certificate in subdag round {round}")));
            }
            // Insert the round and certificates.
            subdag.insert(round, certificates);
        }

        // Return the subdag.
        if unchecked { Ok(Self::from_unchecked(subdag)) } else { Self::from(subdag).map_err(error) }
    }
}
impl<N: Network> FromBytes for Subdag<N> {
    /// Reads the subDAG from the given buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::internal_read_le(reader, false)
    }

    /// Reads the subDAG from the given buffer without performing any checks on the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::internal_read_le(reader, true)
    }
}

impl<N: Network> ToBytes for Subdag<N> {
    /// Writes the subdag to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;
        // Write the number of rounds.
        u32::try_from(self.subdag.len()).map_err(error)?.write_le(&mut writer)?;
        // Write the round certificates.
        for (round, certificates) in &self.subdag {
            // Write the round.
            round.write_le(&mut writer)?;
            // Write the number of certificates.
            u16::try_from(certificates.len()).map_err(error)?.write_le(&mut writer)?;
            // Write the certificates.
            for certificate in certificates {
                // Write the certificate.
                certificate.write_le(&mut writer)?;
            }
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

        for expected in crate::test_helpers::sample_subdags(rng) {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, Subdag::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, Subdag::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }

    /// Encodes a subdag from its parts, so a test can control the round order
    /// and repeat a certificate -- neither of which `to_bytes_le` will produce.
    fn encode(rounds: &[(u64, Vec<BatchCertificate<console::network::MainnetV0>>)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        1u8.write_le(&mut bytes).unwrap();
        u32::try_from(rounds.len()).unwrap().write_le(&mut bytes).unwrap();
        for (round, certificates) in rounds {
            round.write_le(&mut bytes).unwrap();
            u16::try_from(certificates.len()).unwrap().write_le(&mut bytes).unwrap();
            for certificate in certificates {
                certificate.write_le(&mut bytes).unwrap();
            }
        }
        bytes
    }

    #[test]
    fn test_descending_rounds_are_rejected() {
        let rng = &mut TestRng::default();
        let subdag = crate::test_helpers::sample_subdag(rng);
        let rounds: Vec<(u64, Vec<_>)> =
            subdag.iter().map(|(round, certs)| (*round, certs.iter().cloned().collect())).collect();
        assert!(rounds.len() >= 2, "need at least two rounds to reverse");

        // Ascending is what `to_bytes_le` emits, and it must keep working.
        let ascending = encode(&rounds);
        assert_eq!(ascending, subdag.to_bytes_le().unwrap());
        assert_eq!(subdag, Subdag::read_le(&ascending[..]).unwrap());

        // The map would sort this back into the encoding above, so accepting it
        // would give one subdag two encodings.
        let mut reversed = rounds.clone();
        reversed.reverse();
        let descending = encode(&reversed);
        assert_ne!(descending, ascending);
        assert!(
            Subdag::<console::network::MainnetV0>::read_le(&descending[..]).is_err(),
            "a subdag whose rounds are not ascending must be rejected"
        );
    }

    #[test]
    fn test_duplicate_certificate_in_a_round_is_rejected() {
        let rng = &mut TestRng::default();
        let subdag = crate::test_helpers::sample_subdag(rng);
        let mut rounds: Vec<(u64, Vec<_>)> =
            subdag.iter().map(|(round, certs)| (*round, certs.iter().cloned().collect())).collect();

        // Repeat the first certificate of the first round. The set absorbs it, so
        // the subdag is unchanged and only its bytes differ.
        let first = rounds[0].1.first().expect("a sampled round carries certificates").clone();
        rounds[0].1.push(first);

        let padded = encode(&rounds);
        assert_ne!(padded, subdag.to_bytes_le().unwrap());
        assert!(
            Subdag::<console::network::MainnetV0>::read_le(&padded[..]).is_err(),
            "a subdag repeating a certificate within a round must be rejected"
        );
    }
}
