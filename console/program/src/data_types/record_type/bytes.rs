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

impl<N: Network> FromBytes for RecordType<N> {
    /// Reads a record type from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the name of the record type.
        let name = Identifier::read_le(&mut reader)?;
        // Read the visibility for the owner.
        let owner = PublicOrPrivate::read_le(&mut reader)?;

        // Read the number of entries.
        let num_entries = u16::read_le(&mut reader)?;
        // Ensure the number of entries is within the maximum limit.
        if num_entries as usize > N::MAX_DATA_ENTRIES {
            return Err(error(format!(
                "RecordType exceeds size: expected <= {}, found {num_entries}",
                N::MAX_DATA_ENTRIES
            )));
        }
        // Read the entries.
        let mut entries = IndexMap::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            // Read the identifier.
            let identifier = Identifier::read_le(&mut reader)?;
            // Read the entry type.
            let entry = EntryType::read_le(&mut reader)?;
            // Insert the entry, and ensure the entries has no duplicate names.
            if entries.insert(identifier, entry).is_some() {
                return Err(error(format!("Duplicate identifier in record '{name}'")));
            };
        }

        // Prepare the reserved entry names.
        let reserved = [Identifier::from_str("owner").map_err(|e| error(e.to_string()))?];
        // Ensure the entries has no duplicate names.
        if has_duplicates(entries.iter().map(|(identifier, _)| identifier).chain(reserved.iter())) {
            return Err(error(format!("Duplicate entry type found in record '{name}'")));
        }
        // Ensure the number of members is within the maximum limit.
        if entries.len() > N::MAX_DATA_ENTRIES {
            return Err(error("Failed to parse record: too many entries"));
        }

        Ok(Self { name, owner, entries })
    }
}

impl<N: Network> ToBytes for RecordType<N> {
    /// Writes the record type to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of entries is within the maximum limit.
        if self.entries.len() > N::MAX_DATA_ENTRIES {
            return Err(error("Failed to serialize record: too many entries"));
        }

        // Write the name of the record type.
        self.name.write_le(&mut writer)?;
        // Write the visibility for the owner.
        self.owner.write_le(&mut writer)?;

        // Write the number of entries.
        u16::try_from(self.entries.len()).or_halt_with::<N>("Record length exceeds u16").write_le(&mut writer)?;
        // Write the entries as bytes.
        for (identifier, value_type) in &self.entries {
            // Write the identifier.
            identifier.write_le(&mut writer)?;
            // Write the value type to the buffer.
            value_type.write_le(&mut writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_bytes() -> Result<()> {
        let expected = RecordType::<CurrentNetwork>::from_str(
            "record message:\n    owner as address.public;\n    first as field.constant;\n    second as field.public;",
        )?;
        let candidate = RecordType::from_bytes_le(&expected.to_bytes_le().unwrap()).unwrap();
        assert_eq!(expected, candidate);
        Ok(())
    }

    /// The owner's visibility has exactly one encoding: `0` for public, `1` for private.
    ///
    /// Any other byte used to decode as public and re-encode as `0`, which gave one record
    /// type, and so one program, many encodings.
    #[test]
    fn test_owner_visibility_has_one_encoding() -> Result<()> {
        let public = RecordType::<CurrentNetwork>::from_str("record data:\n    owner as address.public;")?;
        let private = RecordType::<CurrentNetwork>::from_str("record data:\n    owner as address.private;")?;

        // The name `data` (a length byte and four bytes), then the owner's visibility.
        let public_bytes = public.to_bytes_le()?;
        let private_bytes = private.to_bytes_le()?;
        assert_eq!(public_bytes, [4, b'd', b'a', b't', b'a', 0, 0, 0]);
        assert_eq!(private_bytes, [4, b'd', b'a', b't', b'a', 1, 0, 0]);
        assert_eq!(RecordType::<CurrentNetwork>::from_bytes_le(&public_bytes)?, public);
        assert_eq!(RecordType::<CurrentNetwork>::from_bytes_le(&private_bytes)?, private);

        // Every other indicator is rejected.
        for indicator in 2..=u8::MAX {
            let mut bytes = public_bytes.clone();
            bytes[5] = indicator;
            assert!(
                RecordType::<CurrentNetwork>::from_bytes_le(&bytes).is_err(),
                "owner visibility indicator {indicator} must be rejected"
            );
        }
        Ok(())
    }
}
