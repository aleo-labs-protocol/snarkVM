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

impl<N: Network> FromBytes for BatchHeader<N> {
    /// Read the batch header either with or without checks on the data.
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid batch header version"));
        }

        // Read the batch ID.
        let batch_id = Field::read_le(&mut reader)?;
        // Read the author.
        let author = Address::read_le(&mut reader)?;
        // Read the round number.
        let round = u64::read_le(&mut reader)?;
        // Read the timestamp.
        let timestamp = i64::read_le(&mut reader)?;
        // Read the committee ID.
        let committee_id = Field::read_le(&mut reader)?;

        // Read the number of transmission IDs.
        let num_transmission_ids = u32::read_le(&mut reader)?;
        // Ensure the number of transmission IDs is within bounds.
        if num_transmission_ids as usize > Self::MAX_TRANSMISSIONS_PER_BATCH {
            return Err(error(format!(
                "Number of transmission IDs ({num_transmission_ids}) exceeds the maximum ({})",
                Self::MAX_TRANSMISSIONS_PER_BATCH,
            )));
        }
        // Read the transmission IDs.
        let mut transmission_ids = IndexSet::new();
        for _ in 0..num_transmission_ids {
            // Insert the transmission ID.
            transmission_ids.insert(TransmissionID::read_le(&mut reader)?);
        }
        // Ensure no transmission ID was repeated. A repeat is absorbed by the set
        // before the batch ID is computed over it, so it leaves the batch ID and
        // the signature intact while changing the bytes -- a second encoding of
        // one batch header.
        if transmission_ids.len() != num_transmission_ids as usize {
            return Err(error("Duplicate transmission ID in batch header"));
        }

        // Read the number of previous certificate IDs.
        let num_previous_certificate_ids = u16::read_le(&mut reader)?;
        // Ensure the number of previous certificate IDs is within bounds.
        if num_previous_certificate_ids > N::LATEST_MAX_CERTIFICATES() {
            return Err(error(format!(
                "Number of previous certificate IDs ({num_previous_certificate_ids}) exceeds the maximum.",
            )));
        }

        // Read the previous certificate ID bytes.
        let mut previous_certificate_id_bytes =
            vec![0u8; num_previous_certificate_ids as usize * Field::<N>::size_in_bytes()];
        reader.read_exact(&mut previous_certificate_id_bytes)?;
        // Read the previous certificate IDs.
        let previous_certificate_ids = cfg_chunks!(previous_certificate_id_bytes, Field::<N>::size_in_bytes())
            .map(Field::read_le)
            .collect::<Result<IndexSet<_>, _>>()?;
        // Ensure no previous certificate ID was repeated, for the same reason.
        if previous_certificate_ids.len() != num_previous_certificate_ids as usize {
            return Err(error("Duplicate previous certificate ID in batch header"));
        }

        // Read the signature.

        // Construct the batch.
        let batch = if unchecked {
            let signature = Signature::read_le_unchecked(&mut reader)?;
            Self::from_unchecked(
                author,
                batch_id,
                round,
                timestamp,
                committee_id,
                transmission_ids,
                previous_certificate_ids,
                signature,
            )
        } else {
            let signature = Signature::read_le(&mut reader)?;
            Self::from(author, round, timestamp, committee_id, transmission_ids, previous_certificate_ids, signature)
                .map_err(io_error)?
        };

        // Return the batch.
        match batch.batch_id == batch_id {
            true => Ok(batch),
            false => Err(error("Invalid batch ID")),
        }
    }

    /// Reads the batch header from the buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads the batch header from the buffer *without* performing any checks
    /// for consistency/correctness.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for BatchHeader<N> {
    /// Writes the batch header to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;
        // Write the batch ID.
        self.batch_id.write_le(&mut writer)?;
        // Write the author.
        self.author.write_le(&mut writer)?;
        // Write the round number.
        self.round.write_le(&mut writer)?;
        // Write the timestamp.
        self.timestamp.write_le(&mut writer)?;
        // Write the committee ID.
        self.committee_id.write_le(&mut writer)?;
        // Write the number of transmission IDs.
        u32::try_from(self.transmission_ids.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the transmission IDs.
        for transmission_id in &self.transmission_ids {
            // Write the transmission ID.
            transmission_id.write_le(&mut writer)?;
        }
        // Write the number of previous certificate IDs.
        u16::try_from(self.previous_certificate_ids.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the previous certificate IDs.
        for certificate_id in &self.previous_certificate_ids {
            // Write the certificate ID.
            certificate_id.write_le(&mut writer)?;
        }
        // Write the signature.
        self.signature.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        let rng = &mut TestRng::default();

        for expected in crate::test_helpers::sample_batch_headers(rng) {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, BatchHeader::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, BatchHeader::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }

    type CurrentNetwork = console::network::MainnetV0;

    /// Offset of the transmission-ID count: version, batch ID, author, round,
    /// timestamp, committee ID.
    fn transmission_count_offset() -> usize {
        1 + Field::<CurrentNetwork>::size_in_bytes()
            + Address::<CurrentNetwork>::size_in_bytes()
            + 8
            + 8
            + Field::<CurrentNetwork>::size_in_bytes()
    }

    /// Repeats `entry` inside a count-prefixed run, bumping the count to match.
    fn repeat_entry(bytes: &[u8], count_at: usize, count_width: usize, entry_at: usize, entry_len: usize) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let count = match count_width {
            2 => u16::from_le_bytes([bytes[count_at], bytes[count_at + 1]]) as u64,
            _ => u32::from_le_bytes([bytes[count_at], bytes[count_at + 1], bytes[count_at + 2], bytes[count_at + 3]])
                as u64,
        };
        match count_width {
            2 => out[count_at..count_at + 2].copy_from_slice(&(u16::try_from(count).unwrap() + 1).to_le_bytes()),
            _ => out[count_at..count_at + 4].copy_from_slice(&(u32::try_from(count).unwrap() + 1).to_le_bytes()),
        }
        let entry = bytes[entry_at..entry_at + entry_len].to_vec();
        out.splice(entry_at + entry_len..entry_at + entry_len, entry);
        out
    }

    #[test]
    fn test_duplicate_transmission_id_is_rejected() {
        let rng = &mut TestRng::default();
        let header = crate::test_helpers::sample_batch_header(rng);
        let exact = header.to_bytes_le().unwrap();

        // The honest encoding must keep working, or the rejection below would be
        // refusing our own output.
        assert_eq!(header, BatchHeader::read_le(&exact[..]).unwrap());

        let first = header.transmission_ids().iter().next().expect("a sampled header has transmission IDs");
        let first_len = first.to_bytes_le().unwrap().len();
        let padded = repeat_entry(&exact, transmission_count_offset(), 4, transmission_count_offset() + 4, first_len);
        assert_ne!(padded, exact);

        // A repeat is absorbed by the set before the batch ID is computed, so it
        // leaves the batch ID and the signature intact. Only the bytes differ.
        assert!(
            BatchHeader::<CurrentNetwork>::read_le(&padded[..]).is_err(),
            "a batch header repeating a transmission ID must be rejected"
        );
    }

    #[test]
    fn test_duplicate_previous_certificate_id_is_rejected() {
        let rng = &mut TestRng::default();
        let header = crate::test_helpers::sample_batch_header_for_round(2, rng);
        let exact = header.to_bytes_le().unwrap();
        assert_eq!(header, BatchHeader::read_le(&exact[..]).unwrap());
        assert!(!header.previous_certificate_ids().is_empty(), "round 2 must carry previous certificates");

        // The previous-certificate count follows the transmission IDs, which are
        // variable width, so its offset is measured rather than assumed.
        let transmissions_len: usize = header.transmission_ids().iter().map(|id| id.to_bytes_le().unwrap().len()).sum();
        let count_at = transmission_count_offset() + 4 + transmissions_len;
        let field_len = Field::<CurrentNetwork>::size_in_bytes();
        assert_eq!(
            u16::from_le_bytes([exact[count_at], exact[count_at + 1]]) as usize,
            header.previous_certificate_ids().len(),
            "offset arithmetic is wrong if this fails"
        );

        let padded = repeat_entry(&exact, count_at, 2, count_at + 2, field_len);
        assert_ne!(padded, exact);
        assert!(
            BatchHeader::<CurrentNetwork>::read_le(&padded[..]).is_err(),
            "a batch header repeating a previous certificate ID must be rejected"
        );
    }
}
