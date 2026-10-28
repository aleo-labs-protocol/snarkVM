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

impl<N: Network> FromBytes for DynamicRecord<N> {
    /// Reads the dynamic record from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the serialization format version.
        let encoding_version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if encoding_version != 1 && encoding_version != 2 {
            return Err(error(format!("Invalid dynamic record version: {encoding_version}")));
        }

        // Read the owner.
        let owner = Address::read_le(&mut reader)?;

        // Read the root.
        let root = Field::read_le(&mut reader)?;

        // Read the nonce.
        let nonce = Group::read_le(&mut reader)?;

        // Read the record version field.
        let version = U8::read_le(&mut reader)?;

        // Version 1 omits entry data. Version 2 includes it.
        let data = match encoding_version {
            1 => None,
            2 => Some(Self::read_data_le(&mut reader, &root)?),
            // Note that the version is validated above to be 1 or 2.
            _ => unreachable!(),
        };

        Ok(Self::new_unchecked(owner, root, nonce, version, data))
    }
}

impl<N: Network> DynamicRecord<N> {
    /// Reads a version-2 plaintext entry map and checks it against the Merkle root.
    fn read_data_le<R: Read>(mut reader: R, root: &Field<N>) -> IoResult<RecordData<N>> {
        // Read the number of entries.
        let num_entries = u8::read_le(&mut reader)?;
        // Ensure the number of entries is within the maximum limit.
        if num_entries as usize > N::MAX_DATA_ENTRIES {
            return Err(error("Failed to parse dynamic record - too many entries"));
        }

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
                return Err(error("Failed to read dynamic record: entry is truncated"));
            }
            // Recover the entry value.
            let mut slice = bytes.as_slice();
            let entry = Entry::read_le(&mut slice)?;
            // Ensure the entry fills its region. Bytes left unread would be dropped on
            // re-serialization, giving one value a second encoding.
            if !slice.is_empty() {
                return Err(error("Failed to read dynamic record: entry has trailing bytes"));
            }
            // Add the entry. A repeated name would overwrite the earlier value.
            if data.insert(identifier, entry).is_some() {
                return Err(error("Duplicate entry type found in dynamic record"));
            }
        }

        // Prepare the reserved entry names.
        let reserved = [Identifier::from_str("owner").map_err(|e| error(e.to_string()))?];
        // Ensure the entries have no duplicate names.
        if has_duplicates(data.keys().chain(reserved.iter())) {
            return Err(error("Duplicate entry type found in dynamic record"));
        }

        // Every nested length prefix in the bit encoding must fit.
        Self::ensure_data_encoding_fits(&data).map_err(|e| error(e.to_string()))?;

        // Check that the Merkle root matches the recovered data.
        let tree = Self::merkleize_data(&data).map_err(|e| error(e.to_string()))?;
        if tree.root() != root {
            return Err(error("The root in the dynamic record does not match the one computed from its data"));
        }

        Ok(data)
    }
}

impl<N: Network> ToBytes for DynamicRecord<N> {
    /// Writes the record to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the serialization format version.
        1u8.write_le(&mut writer)?;

        // Write the owner.
        self.owner.write_le(&mut writer)?;

        // Write the root.
        self.root.write_le(&mut writer)?;

        // Write the nonce.
        self.nonce.write_le(&mut writer)?;

        // Write the record version field.
        self.version.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Entry, Identifier, Literal, Owner, Plaintext, Record};
    use snarkvm_console_network::MainnetV0;
    use snarkvm_console_types::U64;
    use snarkvm_utilities::{TestRng, Uniform};

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    /// Verifies that a dynamic record round-trips through byte serialization.
    fn check_bytes(record: &Record<CurrentNetwork, Plaintext<CurrentNetwork>>) {
        let expected = DynamicRecord::from_record(record).unwrap();
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = DynamicRecord::<CurrentNetwork>::read_le(&expected_bytes[..]).unwrap();
        assert_eq!(expected.owner(), candidate.owner());
        assert_eq!(expected.root(), candidate.root());
        assert_eq!(expected.nonce(), candidate.nonce());
        assert_eq!(expected.version(), candidate.version());
    }

    #[test]
    fn test_bytes() {
        let rng = &mut TestRng::default();

        // Test with a simple record (one entry).
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        check_bytes(&record);

        // Test with an empty record.
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            indexmap::IndexMap::new(),
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        check_bytes(&record);

        // Test with multiple entries.
        let data = indexmap::indexmap! {
            Identifier::from_str("a").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("b").unwrap() => Entry::Public(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("c").unwrap() => Entry::Constant(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let owner = Owner::Private(Plaintext::from(Literal::Address(Address::rand(rng))));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        check_bytes(&record);
    }

    /// Encodes a dynamic record using the version-2 layout (header plus entry map).
    fn write_v2(record: &DynamicRecord<CurrentNetwork>) -> Vec<u8> {
        let mut writer = Vec::new();
        2u8.write_le(&mut writer).unwrap();
        record.owner().write_le(&mut writer).unwrap();
        record.root().write_le(&mut writer).unwrap();
        record.nonce().write_le(&mut writer).unwrap();
        record.version().write_le(&mut writer).unwrap();

        let data = record.data().as_ref().expect("expected populated dynamic record data");
        u8::try_from(data.len()).unwrap().write_le(&mut writer).unwrap();
        for (entry_name, entry_value) in data {
            entry_name.write_le(&mut writer).unwrap();
            let bytes = entry_value.to_bytes_le().unwrap();
            u16::try_from(bytes.len()).unwrap().write_le(&mut writer).unwrap();
            bytes.write_le(&mut writer).unwrap();
        }
        writer
    }

    #[test]
    fn test_read_le_version_2_recovers_data() {
        let rng = &mut TestRng::default();
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("memo").unwrap() => Entry::Public(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data.clone(),
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();

        let candidate = DynamicRecord::<CurrentNetwork>::read_le(&write_v2(&expected)[..]).unwrap();
        assert_eq!(expected.owner(), candidate.owner());
        assert_eq!(expected.root(), candidate.root());
        assert_eq!(expected.nonce(), candidate.nonce());
        assert_eq!(expected.version(), candidate.version());
        assert_eq!(expected.data(), candidate.data());
        assert_eq!(candidate.data().as_ref(), Some(&data));
    }

    #[test]
    fn test_read_le_version_1_omits_data() {
        let rng = &mut TestRng::default();
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();
        assert!(expected.data().is_some());

        let candidate = DynamicRecord::<CurrentNetwork>::read_le(&expected.to_bytes_le().unwrap()[..]).unwrap();
        assert!(candidate.data().is_none());
    }

    #[test]
    fn test_read_le_version_2_rejects_mismatched_root() {
        let rng = &mut TestRng::default();
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::new(1)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();
        let mut bytes = write_v2(&expected);
        // Overwrite the root (bytes after the encoding version and owner).
        let root_offset = 1 + expected.owner().to_bytes_le().unwrap().len();
        let root_bytes = Field::<CurrentNetwork>::from_u64(12345).to_bytes_le().unwrap();
        bytes[root_offset..root_offset + root_bytes.len()].copy_from_slice(&root_bytes);

        let error = DynamicRecord::<CurrentNetwork>::read_le(&bytes[..]).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn test_read_le_version_2_rejects_malformed_entry_regions() {
        let rng = &mut TestRng::default();
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();
        let bytes = write_v2(&expected);

        // Locate the sole data entry by its own encoding: the two bytes in front of it
        // are the `u16` that delimits its region.
        let entry_bytes = expected
            .data()
            .as_ref()
            .and_then(|data| data.values().next())
            .expect("expected populated dynamic record data")
            .to_bytes_le()
            .unwrap();
        let at = bytes
            .windows(entry_bytes.len())
            .position(|window| window == entry_bytes.as_slice())
            .expect("the entry's bytes appear in the dynamic record's bytes");
        assert!(at >= 2);
        assert_eq!(u16::from_le_bytes([bytes[at - 2], bytes[at - 1]]) as usize, entry_bytes.len());

        // Declaring more bytes for the entry than the buffer holds truncates the payload.
        let mut truncated = bytes.clone();
        let declared = u16::try_from(entry_bytes.len() + 1).unwrap();
        truncated[at - 2..at].copy_from_slice(&declared.to_le_bytes());
        assert!(
            DynamicRecord::<CurrentNetwork>::read_le(&truncated[..]).is_err(),
            "an entry declaring more bytes than it occupies must be rejected"
        );

        // Declaring fewer bytes for the entry than it occupies leaves bytes unread.
        let mut padded = bytes.clone();
        let declared = u16::try_from(entry_bytes.len() - 1).unwrap();
        padded[at - 2..at].copy_from_slice(&declared.to_le_bytes());
        assert!(
            DynamicRecord::<CurrentNetwork>::read_le(&padded[..]).is_err(),
            "an entry declaring fewer bytes than it occupies must be rejected"
        );
    }

    #[test]
    fn test_read_le_version_2_rejects_duplicate_names() {
        let rng = &mut TestRng::default();
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::new(1)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();
        let mut bytes = write_v2(&expected);

        // The entry count sits after the encoding version, owner, root, nonce, and version field.
        let count_at = 1
            + expected.owner().to_bytes_le().unwrap().len()
            + expected.root().to_bytes_le().unwrap().len()
            + expected.nonce().to_bytes_le().unwrap().len()
            + expected.version().to_bytes_le().unwrap().len();
        assert_eq!(bytes[count_at], 1);
        let entry = bytes[count_at + 1..].to_vec();
        bytes[count_at] = 2;
        bytes.extend_from_slice(&entry);

        let error = DynamicRecord::<CurrentNetwork>::read_le(&bytes[..]).unwrap_err();
        assert!(error.to_string().contains("Duplicate"), "{error}");
    }

    /// An outer array whose only element is an array of 1,024 `u64`s.
    ///
    /// The byte encoding fits in a `u16`. The inner array's bit encoding does not.
    fn oversized_nested_array() -> Plaintext<CurrentNetwork> {
        let inner = Plaintext::Array(
            (0..1024).map(|_| Plaintext::from(Literal::U64(U64::new(1)))).collect(),
            Default::default(),
        );
        Plaintext::Array(vec![inner], Default::default())
    }

    /// Encodes one version-2 entry under an arbitrary root.
    fn write_v2_entry(entry_name: &str, entry: Entry<CurrentNetwork, Plaintext<CurrentNetwork>>) -> Vec<u8> {
        let rng = &mut TestRng::default();
        let mut writer = Vec::new();
        2u8.write_le(&mut writer).unwrap();
        Address::<CurrentNetwork>::rand(rng).write_le(&mut writer).unwrap();
        Field::<CurrentNetwork>::zero().write_le(&mut writer).unwrap();
        Group::<CurrentNetwork>::rand(rng).write_le(&mut writer).unwrap();
        U8::<CurrentNetwork>::new(0).write_le(&mut writer).unwrap();
        1u8.write_le(&mut writer).unwrap();
        Identifier::<CurrentNetwork>::from_str(entry_name).unwrap().write_le(&mut writer).unwrap();
        let entry_bytes = entry.to_bytes_le().unwrap();
        assert!(entry_bytes.len() <= u16::MAX as usize, "the entry must pass the byte-length limit");
        u16::try_from(entry_bytes.len()).unwrap().write_le(&mut writer).unwrap();
        entry_bytes.write_le(&mut writer).unwrap();
        writer
    }

    #[test]
    fn test_read_le_version_2_rejects_oversized_nested_bits() {
        let bytes = write_v2_entry("amount", Entry::Private(oversized_nested_array()));
        let read = std::panic::catch_unwind(|| DynamicRecord::<CurrentNetwork>::read_le(bytes.as_slice()));
        let read = read.expect("oversized entry data panicked during decoding");
        assert!(read.is_err(), "oversized entry data must be rejected");
    }

    #[test]
    fn test_read_le_version_2_accepts_nested_array() {
        let rng = &mut TestRng::default();
        let inner = Plaintext::Array(
            vec![Plaintext::from(Literal::U64(U64::new(1))), Plaintext::from(Literal::U64(U64::new(2)))],
            Default::default(),
        );
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::Array(vec![inner], Default::default())),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();
        let candidate = DynamicRecord::<CurrentNetwork>::read_le(&write_v2(&expected)[..]).unwrap();
        assert_eq!(expected.data(), candidate.data());
    }
}
