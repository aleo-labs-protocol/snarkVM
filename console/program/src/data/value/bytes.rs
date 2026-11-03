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

impl<N: Network> FromBytes for Value<N> {
    /// Reads the entry from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the index.
        let index = u8::read_le(&mut reader)?;
        // Read the entry.
        let entry = match index {
            0 => Self::Plaintext(Plaintext::read_le(&mut reader)?),
            1 => Self::Record(Record::read_le(&mut reader)?),
            2 => Self::Future(Future::read_le(&mut reader)?),
            3 => Self::DynamicRecord(DynamicRecord::read_le(&mut reader)?),
            4 => Self::DynamicFuture(DynamicFuture::read_le(&mut reader)?),
            5.. => return Err(error(format!("Failed to decode value variant {index}"))),
        };
        Ok(entry)
    }
}

impl<N: Network> ToBytes for Value<N> {
    /// Writes the entry to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Plaintext(plaintext) => {
                0u8.write_le(&mut writer)?;
                plaintext.write_le(&mut writer)
            }
            Self::Record(record) => {
                1u8.write_le(&mut writer)?;
                record.write_le(&mut writer)
            }
            Self::Future(future) => {
                2u8.write_le(&mut writer)?;
                future.write_le(&mut writer)
            }
            Self::DynamicRecord(dynamic_record) => {
                3u8.write_le(&mut writer)?;
                dynamic_record.write_le(&mut writer)
            }
            Self::DynamicFuture(dynamic_future) => {
                4u8.write_le(&mut writer)?;
                dynamic_future.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Argument, Entry, Identifier, Literal, Owner, ProgramID};
    use snarkvm_console_network::MainnetV0;
    use snarkvm_console_types::{Group, U8, U64};
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_value_plaintext_bytes() {
        // Construct a new plaintext value.
        let expected = Value::Plaintext(
            Plaintext::<CurrentNetwork>::from_str(
                "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah, token_amount: 100u64 }",
            )
            .unwrap(),
        );

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        assert_eq!(expected, Value::read_le(&expected_bytes[..]).unwrap());
    }

    #[test]
    fn test_value_record_bytes() {
        // Construct a new record value.
        let expected = Value::Record(
            Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
                "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, token_amount: 100u64.private, _nonce: 0group.public }",
            )
            .unwrap(),
        );

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        assert_eq!(expected, Value::read_le(&expected_bytes[..]).unwrap());
    }

    #[test]
    fn test_value_future_bytes() {
        // Construct a new future value.
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
        );
        let expected = Value::Future(future);

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        assert_eq!(expected, Value::read_le(&expected_bytes[..]).unwrap());
    }

    #[test]
    fn test_value_dynamic_record_bytes() {
        let rng = &mut TestRng::default();

        // Create a record.
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

        // Convert to dynamic record.
        let dynamic_record = DynamicRecord::from_record(&record).unwrap();
        let expected = Value::DynamicRecord(dynamic_record);

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = Value::<CurrentNetwork>::read_le(&expected_bytes[..]).unwrap();

        // Verify the fields match (DynamicRecord doesn't implement PartialEq).
        match (&expected, &candidate) {
            (Value::DynamicRecord(e), Value::DynamicRecord(c)) => {
                assert_eq!(e.owner(), c.owner());
                assert_eq!(e.root(), c.root());
                assert_eq!(e.nonce(), c.nonce());
                assert_eq!(e.version(), c.version());
            }
            _ => panic!("Expected DynamicRecord value"),
        }
    }

    #[test]
    fn test_value_dynamic_future_bytes() {
        // Create a future.
        let future = Future::<CurrentNetwork>::new(
            ProgramID::from_str("test.aleo").unwrap(),
            Identifier::from_str("foo").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
        );

        // Convert to dynamic future.
        let dynamic_future = DynamicFuture::from_future(&future).unwrap();
        let expected = Value::DynamicFuture(dynamic_future);

        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let candidate = Value::<CurrentNetwork>::read_le(&expected_bytes[..]).unwrap();

        // Verify the fields match (DynamicFuture doesn't implement PartialEq).
        match (&expected, &candidate) {
            (Value::DynamicFuture(e), Value::DynamicFuture(c)) => {
                assert_eq!(e.program_name(), c.program_name());
                assert_eq!(e.program_network(), c.program_network());
                assert_eq!(e.function_name(), c.function_name());
                assert_eq!(e.checksum(), c.checksum());
            }
            _ => panic!("Expected DynamicFuture value"),
        }
    }
}
