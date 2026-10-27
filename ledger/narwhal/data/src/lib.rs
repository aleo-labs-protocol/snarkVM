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

extern crate snarkvm_console as console;

use console::prelude::*;

use ::bytes::Bytes;

#[cfg(feature = "async")]
use tokio::task;

const PREFIX: &str = "data";

/// As a sanity check, we set a hardcoded upper-bound limit to the size of the data.
/// This is to prevent a malicious node from sending us a huge data object that would
/// cause us to run out of memory.
const MAX_DATA_SIZE: u32 = 1024 * 1024 * 1024; // 1 GB

/// The number of bytes a serialized `Data` adds around the object it carries: the version byte
/// that leads it, and the `u32` length prefix on the payload that follows.
///
/// This lets a caller size a buffer or a message around a serialized `Data` without serializing
/// one first - snarkOS adds it to `LATEST_MAX_TRANSACTION_SIZE` to get the frame size an
/// `UnconfirmedTransaction` carrying a maximum-size transaction takes on the wire. It lives here,
/// beside the `ToBytes` and `FromBytes` implementations that define the encoding, so that a change
/// to either is a change to this; `data_encoding_overhead_matches_the_encoding` pins it against
/// what `write_le` really emits.
pub const DATA_ENCODING_OVERHEAD: usize = size_of::<u8>() // the version byte
    + size_of::<u32>(); // the length prefix on the payload

/// This object enables deferred deserialization / ahead-of-time serialization for objects that
/// take a while to deserialize / serialize, in order to allow these operations to be non-blocking.
#[derive(Clone, PartialEq, Eq)]
pub enum Data<T: FromBytes + ToBytes + Send + 'static> {
    Object(T),
    Buffer(Bytes),
}

impl<T: FromBytes + ToBytes + Send + 'static> Data<T> {
    pub fn to_checksum<N: Network>(&self) -> Result<N::TransmissionChecksum> {
        // Convert to bits.
        let preimage = match self {
            Self::Object(object) => object.to_bytes_le()?.to_bits_le(),
            Self::Buffer(bytes) => bytes.deref().to_bits_le(),
        };
        // Hash the preimage bits.
        let hash = N::hash_sha3_256(&preimage)?;
        // Select the number of bits needed to parse the checksum.
        let num_bits = usize::try_from(N::TransmissionChecksum::BITS).map_err(error)?;
        // Return the checksum.
        N::TransmissionChecksum::from_bits_le(&hash[0..num_bits])
    }

    pub fn into<T2: From<Data<T>> + From<T> + FromBytes + ToBytes + Send + 'static>(self) -> Data<T2> {
        match self {
            Self::Object(x) => Data::Object(x.into()),
            Self::Buffer(bytes) => Data::Buffer(bytes),
        }
    }

    #[cfg(feature = "async")]
    pub async fn deserialize(self) -> Result<T> {
        match self {
            Self::Object(x) => Ok(x),
            Self::Buffer(bytes) => match task::spawn_blocking(move || T::from_bytes_le(&bytes)).await {
                Ok(x) => x,
                Err(err) => Err(err.into()),
            },
        }
    }

    pub fn deserialize_blocking(self) -> Result<T> {
        match self {
            Self::Object(x) => Ok(x),
            Self::Buffer(bytes) => T::from_bytes_le(&bytes),
        }
    }

    #[cfg(feature = "async")]
    pub async fn serialize(self) -> Result<Bytes> {
        match self {
            Self::Object(x) => match task::spawn_blocking(move || x.to_bytes_le()).await {
                Ok(bytes) => bytes.map(|vec| vec.into()),
                Err(err) => Err(err.into()),
            },
            Self::Buffer(bytes) => Ok(bytes),
        }
    }

    pub fn serialize_blocking_into<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Object(x) => Ok(x.write_le(writer)?),
            Self::Buffer(bytes) => Ok(writer.write_all(bytes)?),
        }
    }
}

impl<T: FromBytes + ToBytes + DeserializeOwned + Send + 'static> FromStr for Data<T> {
    type Err = Error;

    /// Initializes the data from a JSON-string.
    fn from_str(data: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(data)?)
    }
}

impl<T: FromBytes + ToBytes + Serialize + Send + 'static> Debug for Data<T> {
    /// Prints the data as a JSON-string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<T: FromBytes + ToBytes + Serialize + Send + 'static> Display for Data<T> {
    /// Displays the data as a JSON-string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).map_err::<fmt::Error, _>(ser::Error::custom)?)
    }
}

impl<T: FromBytes + ToBytes + Send + 'static> FromBytes for Data<T> {
    /// Reads the data from the buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid data version"));
        }

        // Read the number of bytes.
        let num_bytes = u32::read_le(&mut reader)?;
        // Ensure the number of bytes is with safe bound limits.
        if num_bytes > MAX_DATA_SIZE {
            return Err(error(format!("Failed to deserialize data ({num_bytes} bytes)")));
        }
        // Read the bytes.
        let mut bytes = Vec::new();
        (&mut reader).take(num_bytes as u64).read_to_end(&mut bytes)?;
        // Return the data.
        Ok(Self::Buffer(Bytes::from(bytes)))
    }
}

impl<T: FromBytes + ToBytes + Send + 'static> ToBytes for Data<T> {
    /// Writes the data to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;

        // Write the data.
        match self {
            Self::Object(object) => {
                // Serialize the object.
                let buffer =
                    object.to_bytes_le().map_err(|e| error(format!("Failed to serialize 'Data::Object' - {e}")))?;
                // Write the object.
                u32::try_from(buffer.len()).map_err(error)?.write_le(&mut writer)?;
                // Write the object.
                writer.write_all(&buffer)
            }
            Self::Buffer(buffer) => {
                // Write the number of bytes.
                u32::try_from(buffer.len()).map_err(error)?.write_le(&mut writer)?;
                // Write the bytes.
                writer.write_all(buffer)
            }
        }
    }
}

impl<T: FromBytes + ToBytes + Serialize + Send + 'static> Serialize for Data<T> {
    /// Serializes the data to a JSON-string or buffer.
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut data = serializer.serialize_struct("Data", 2)?;
                match self {
                    Self::Object(object) => {
                        data.serialize_field("type", "object")?;
                        data.serialize_field("data", object)?;
                    }
                    Self::Buffer(buffer) => {
                        use console::prelude::ser::Error;

                        data.serialize_field("type", "buffer")?;

                        // Encode to bech32m.
                        let buffer =
                            bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(PREFIX), buffer.as_ref())
                                .map_err(|_| S::Error::custom("Failed to encode data into bech32m"))?;

                        // Add the bech32m string.
                        data.serialize_field("data", &buffer)?;
                    }
                }
                data.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, T: FromBytes + ToBytes + DeserializeOwned + Send + 'static> Deserialize<'de> for Data<T> {
    /// Deserializes the data from a JSON-string or buffer.
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                let mut data = serde_json::Value::deserialize(deserializer)?;
                let type_: String = DeserializeExt::take_from_value::<D>(&mut data, "type")?;

                // Recover the data.
                match type_.as_str() {
                    "object" => {
                        let object = DeserializeExt::take_from_value::<D>(&mut data, "data")?;
                        Ok(Self::Object(object))
                    }
                    "buffer" => {
                        let encoding: String = DeserializeExt::take_from_value::<D>(&mut data, "data")?;

                        // Decode from bech32m.
                        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(&encoding)
                            .map_err(de::Error::custom)?;
                        let hrp = checked.hrp();
                        let data: Vec<u8> = checked.byte_iter().collect();
                        if hrp.as_str() != PREFIX {
                            return Err(de::Error::custom(error(format!("Invalid data HRP - {hrp}"))));
                        };
                        if data.is_empty() {
                            return Err(de::Error::custom(error("Invalid bech32m data (empty)")));
                        }
                        Ok(Self::Buffer(Bytes::from(data)))
                    }
                    _ => Err(de::Error::custom(error(format!("Invalid data type - {type_}")))),
                }
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "data"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;
    use snarkvm_ledger_block::Transaction;

    #[test]
    fn test_to_checksum() {
        let rng = &mut TestRng::default();

        // Sample transactions
        let transactions = [
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, false, rng),
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 0),
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(false, rng, 0),
            snarkvm_ledger_test_helpers::sample_fee_private_transaction(rng),
            snarkvm_ledger_test_helpers::sample_fee_public_transaction(rng),
        ];

        for transaction in transactions.into_iter() {
            // Convert the transaction to a Data buffer.
            let data_bytes: Data<Transaction<MainnetV0>> = Data::Buffer(transaction.to_bytes_le().unwrap().into());
            // Convert the transaction to a data object.
            let data = Data::Object(transaction);

            // Compute the checksums.
            let checksum_1 = data_bytes.to_checksum::<MainnetV0>().unwrap();
            let checksum_2 = data.to_checksum::<MainnetV0>().unwrap();

            // Ensure the checksums are equal.
            assert_eq!(checksum_1, checksum_2);
        }
    }

    /// Pins `DATA_ENCODING_OVERHEAD` against what `write_le` actually emits, rather than trusting
    /// the arithmetic in its doc comment: a serialized `Data` has to be exactly that much larger
    /// than the payload it carries, whichever representation it is in.
    #[test]
    fn data_encoding_overhead_matches_the_encoding() {
        let rng = &mut TestRng::default();

        let transaction = snarkvm_ledger_test_helpers::sample_fee_public_transaction(rng);
        let payload = transaction.to_bytes_le().unwrap();

        let object: Data<Transaction<MainnetV0>> = Data::Object(transaction);
        let buffer: Data<Transaction<MainnetV0>> = Data::Buffer(payload.clone().into());

        for data in [object, buffer] {
            assert_eq!(data.to_bytes_le().unwrap().len(), payload.len() + DATA_ENCODING_OVERHEAD);
        }
    }
}
