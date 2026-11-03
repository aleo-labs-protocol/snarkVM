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

impl<N: Network> Serialize for ConfirmedTxType<N> {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => match self {
                Self::AcceptedDeploy(index) => {
                    let mut confirmed_tx_type = serializer.serialize_struct("ConfirmedTxType", 2)?;
                    confirmed_tx_type.serialize_field("type", "AcceptedDeploy")?;
                    confirmed_tx_type.serialize_field("index", index)?;
                    confirmed_tx_type.end()
                }
                Self::AcceptedExecute(index) => {
                    let mut confirmed_tx_type = serializer.serialize_struct("ConfirmedTxType", 2)?;
                    confirmed_tx_type.serialize_field("type", "AcceptedExecute")?;
                    confirmed_tx_type.serialize_field("index", index)?;
                    confirmed_tx_type.end()
                }
                Self::RejectedDeploy(index, rejected) => {
                    let mut confirmed_tx_type = serializer.serialize_struct("ConfirmedTxType", 3)?;
                    confirmed_tx_type.serialize_field("type", "RejectedDeploy")?;
                    confirmed_tx_type.serialize_field("index", index)?;
                    confirmed_tx_type.serialize_field("rejected", rejected)?;
                    confirmed_tx_type.end()
                }
                Self::RejectedExecute(index, rejected) => {
                    let mut confirmed_tx_type = serializer.serialize_struct("ConfirmedTxType", 3)?;
                    confirmed_tx_type.serialize_field("type", "RejectedExecute")?;
                    confirmed_tx_type.serialize_field("index", index)?;
                    confirmed_tx_type.serialize_field("rejected", rejected)?;
                    confirmed_tx_type.end()
                }
            },
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for ConfirmedTxType<N> {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                let mut confirmed_tx_type = serde_json::Value::deserialize(deserializer)?;
                let type_: String = DeserializeExt::take_from_value::<D>(&mut confirmed_tx_type, "type")?;

                // Recover the confirmed transaction type.
                match type_.as_str() {
                    "AcceptedDeploy" => Ok(Self::AcceptedDeploy(
                        DeserializeExt::take_from_value::<D>(&mut confirmed_tx_type, "index")
                            .map_err(de::Error::custom)?,
                    )),
                    "AcceptedExecute" => Ok(Self::AcceptedExecute(
                        DeserializeExt::take_from_value::<D>(&mut confirmed_tx_type, "index")
                            .map_err(de::Error::custom)?,
                    )),
                    "RejectedDeploy" => {
                        let index = DeserializeExt::take_from_value::<D>(&mut confirmed_tx_type, "index")
                            .map_err(de::Error::custom)?;
                        let rejected = DeserializeExt::take_from_value::<D>(&mut confirmed_tx_type, "rejected")
                            .map_err(de::Error::custom)?;
                        Ok(Self::RejectedDeploy(index, rejected))
                    }
                    "RejectedExecute" => {
                        let index = DeserializeExt::take_from_value::<D>(&mut confirmed_tx_type, "index")
                            .map_err(de::Error::custom)?;
                        let rejected = DeserializeExt::take_from_value::<D>(&mut confirmed_tx_type, "rejected")
                            .map_err(de::Error::custom)?;
                        Ok(Self::RejectedExecute(index, rejected))
                    }
                    _ => Err(de::Error::custom(error("Invalid confirmed transaction type"))),
                }
            }
            false => FromBytesUncheckedDeserializer::<Self>::deserialize_with_size_encoding(
                deserializer,
                "confirmed transaction type",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_serde_json<
        T: Serialize + for<'a> Deserialize<'a> + Debug + Display + PartialEq + Eq + FromStr + ToBytes + FromBytes,
    >(
        expected: T,
    ) {
        // Serialize
        let expected_string = expected.to_string();
        let candidate_string = serde_json::to_string(&expected).unwrap();
        let candidate = serde_json::from_str::<T>(&candidate_string).unwrap();
        assert_eq!(expected, candidate);
        assert_eq!(expected_string, candidate_string);
        assert_eq!(expected_string, candidate.to_string());

        // Deserialize
        assert_eq!(expected, T::from_str(&expected_string).unwrap_or_else(|_| panic!("FromStr: {expected_string}")));
        assert_eq!(expected, serde_json::from_str(&candidate_string).unwrap());
    }

    fn check_bincode<
        T: Serialize + for<'a> Deserialize<'a> + Debug + Display + PartialEq + Eq + FromStr + ToBytes + FromBytes,
    >(
        expected: T,
    ) {
        // Serialize
        let expected_bytes = expected.to_bytes_le().unwrap();
        let expected_bytes_with_size_encoding = bincode::serialize(&expected).unwrap();
        assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

        // Deserialize
        assert_eq!(expected, T::read_le(&expected_bytes[..]).unwrap());
        assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..]).unwrap());
        assert_eq!(
            expected,
            snarkvm_utilities::bytes::unchecked_deserialize(&expected_bytes_with_size_encoding[..]).unwrap()
        );
    }

    #[test]
    fn test_serde_json() {
        for rejected in crate::confirmed_tx_type::test_helpers::sample_confirmed_tx_types() {
            check_serde_json(rejected);
        }
    }

    #[test]
    fn test_bincode() {
        for rejected in crate::confirmed_tx_type::test_helpers::sample_confirmed_tx_types() {
            check_bincode(rejected);
        }
    }
}
