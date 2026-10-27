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

impl<N: Network, Private: Visibility> FromBytes for Record<N, Private> {
    /// Reads the record from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the variant.
        let variant = U8::<N>::new(u8::read_le(&mut reader)?);

        // Set the version based on the variant.
        let version = match *variant {
            0 | 1 => U8::zero(),
            2 | 3 => U8::one(),
            4.. => return Err(error(format!("Failed to decode record variant ({variant}) for the version"))),
        };

        // Read the owner.
        let owner = match *variant {
            0 | 2 => Owner::Public(Address::read_le(&mut reader)?),
            1 | 3 => Owner::Private(Private::read_le(&mut reader)?),
            4.. => return Err(error(format!("Failed to decode record variant ({variant}) for the owner"))),
        };

        // Read the number of entries in the record data.
        let num_entries = u8::read_le(&mut reader)?;
        // Read the record data.
        let mut data = IndexMap::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            // Read the identifier.
            let identifier = Identifier::<N>::read_le(&mut reader)?;
            // Read the entry value (in 2 steps to prevent infinite recursion).
            let num_bytes = u16::read_le(&mut reader)?;
            // Read the entry bytes.
            let mut bytes = Vec::new();
            (&mut reader).take(num_bytes as u64).read_to_end(&mut bytes)?;
            // Ensure the declared region is entirely present.
            if bytes.len() != num_bytes as usize {
                return Err(error("Failed to read record: entry is truncated"));
            }
            // Recover the entry value.
            let mut slice = bytes.as_slice();
            let entry = Entry::read_le(&mut slice)?;
            // Ensure the entry fills its region. Bytes left unread would be dropped on
            // re-serialization, giving one value a second encoding.
            if !slice.is_empty() {
                return Err(error("Failed to read record: entry has trailing bytes"));
            }
            // Add the entry.
            data.insert(identifier, entry);
        }

        // Read the nonce.
        let nonce = Group::read_le(&mut reader)?;

        // Prepare the reserved entry names.
        let reserved = [Identifier::from_str("owner").map_err(|e| error(e.to_string()))?];
        // Ensure the entries has no duplicate names.
        if has_duplicates(data.keys().chain(reserved.iter())) {
            return Err(error("Duplicate entry type found in record"));
        }
        // Ensure the number of entries is within the maximum limit.
        if data.len() > N::MAX_DATA_ENTRIES {
            return Err(error("Failed to parse record - too many entries"));
        }

        Ok(Self { owner, data, nonce, version })
    }
}

impl<N: Network, Private: Visibility> ToBytes for Record<N, Private> {
    /// Writes the record to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Set the variant.
        let variant = match (*self.version, self.owner.is_public()) {
            (0, true) => 0u8,
            (0, false) => 1u8,
            (1, true) => 2u8,
            (1, false) => 3u8,
            (_, _) => {
                return Err(error(format!(
                    "Failed to encode record - variant mismatch (version = {}, hiding = {}, owner = {})",
                    self.version,
                    self.is_hiding(),
                    self.owner.is_public()
                )));
            }
        };

        #[cfg(debug_assertions)]
        {
            // Ensure the version is correct.
            let is_version_correct = match (!self.is_hiding(), self.owner.is_public()) {
                (true, true) => variant == 0,
                (true, false) => variant == 1,
                (false, true) => variant == 2,
                (false, false) => variant == 3,
            };
            if !is_version_correct {
                return Err(error(format!(
                    "Failed to encode record - version mismatch (version = {}, hiding = {}, owner = {})",
                    self.version,
                    self.is_hiding(),
                    self.owner.is_public()
                )));
            }
        }

        // Write the variant.
        variant.write_le(&mut writer)?;

        // Write the owner.
        match &self.owner {
            Owner::Public(owner) => owner.write_le(&mut writer)?,
            Owner::Private(owner) => owner.write_le(&mut writer)?,
        };

        // Write the number of entries in the record data.
        u8::try_from(self.data.len()).or_halt_with::<N>("Record length exceeds u8::MAX").write_le(&mut writer)?;
        // Write each entry.
        for (entry_name, entry_value) in &self.data {
            // Write the entry name.
            entry_name.write_le(&mut writer)?;
            // Write the entry value (performed in 2 steps to prevent infinite recursion).
            let bytes = entry_value.to_bytes_le().map_err(|e| error(e.to_string()))?;
            // Write the number of bytes.
            u16::try_from(bytes.len())
                .or_halt_with::<N>("Record entry exceeds u16::MAX bytes")
                .write_le(&mut writer)?;
            // Write the bytes.
            bytes.write_le(&mut writer)?;
        }

        // Write the nonce.
        self.nonce.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_bytes() -> Result<()> {
        // Construct a new record.
        let expected = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
            "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, token_amount: 100u64.private, _nonce: 0group.public }",
        )?;

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le()?;
        assert_eq!(expected, Record::read_le(&expected_bytes[..])?);

        // Construct a new record.
        let expected = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
            "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, token_amount: 100u64.private, _nonce: 0group.public, _version: 1u8.public }",
        )?;

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le()?;
        assert_eq!(expected, Record::read_le(&expected_bytes[..])?);
        Ok(())
    }

    #[test]
    fn test_record_entry_rejects_trailing_bytes() -> Result<()> {
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
            "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, token_amount: 100u64.private, _nonce: 0group.public }",
        )?;
        let exact = record.to_bytes_le()?;
        assert_eq!(record, Record::read_le(&exact[..])?);

        // Locate the sole data entry by its own encoding: the two bytes in front of it
        // are the `u16` that delimits its region.
        let identifier = Identifier::<CurrentNetwork>::from_str("token_amount")?;
        let entry_bytes = record.data().get(&identifier).expect("the record has this entry").to_bytes_le()?;
        let at = exact
            .windows(entry_bytes.len())
            .position(|window| window == entry_bytes.as_slice())
            .expect("the entry's bytes appear in the record's bytes");
        assert!(at >= 2);
        assert_eq!(u16::from_le_bytes([exact[at - 2], exact[at - 1]]) as usize, entry_bytes.len());

        // Declaring more bytes for the entry than it occupies leaves bytes unread.
        for padding in [1usize, 8, 32] {
            let mut padded = exact.clone();
            let declared = u16::try_from(entry_bytes.len() + padding)?;
            padded[at - 2..at].copy_from_slice(&declared.to_le_bytes());
            padded.splice(at + entry_bytes.len()..at + entry_bytes.len(), std::iter::repeat_n(0u8, padding));
            assert_ne!(padded, exact);
            assert!(
                Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::read_le(&padded[..]).is_err(),
                "a record entry declaring {padding} bytes more than it uses must be rejected"
            );
        }
        Ok(())
    }
}
