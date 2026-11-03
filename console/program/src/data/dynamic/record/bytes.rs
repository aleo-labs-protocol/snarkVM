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
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid dynamic record version"));
        }

        // Read the owner.
        let owner = Address::read_le(&mut reader)?;

        // Read the root.
        let root = Field::read_le(&mut reader)?;

        // Read the nonce.
        let nonce = Group::read_le(&mut reader)?;

        // Read the record version field.
        let version = U8::read_le(&mut reader)?;

        Ok(Self::new_unchecked(owner, root, nonce, version, None))
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
}
