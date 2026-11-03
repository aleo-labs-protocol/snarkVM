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

impl<N: Network> Serialize for Output<N> {
    /// Serializes the transition output into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => match self {
                Self::Constant(id, value) => {
                    let mut output = serializer.serialize_struct("Output", 2 + value.is_some() as usize)?;
                    output.serialize_field("type", "constant")?;
                    output.serialize_field("id", &id)?;
                    if let Some(value) = value {
                        output.serialize_field("value", &value)?;
                    }
                    output.end()
                }
                Self::Public(id, value) => {
                    let mut output = serializer.serialize_struct("Output", 2 + value.is_some() as usize)?;
                    output.serialize_field("type", "public")?;
                    output.serialize_field("id", &id)?;
                    if let Some(value) = value {
                        output.serialize_field("value", &value)?;
                    }
                    output.end()
                }
                Self::Private(id, value) => {
                    let mut output = serializer.serialize_struct("Output", 2 + value.is_some() as usize)?;
                    output.serialize_field("type", "private")?;
                    output.serialize_field("id", &id)?;
                    if let Some(value) = value {
                        output.serialize_field("value", &value)?;
                    }
                    output.end()
                }
                Self::Record(id, checksum, value, sender_ciphertext) => {
                    let mut output = serializer.serialize_struct(
                        "Output",
                        3 + value.is_some() as usize + sender_ciphertext.is_some() as usize,
                    )?;
                    output.serialize_field("type", "record")?;
                    output.serialize_field("id", &id)?;
                    output.serialize_field("checksum", &checksum)?;
                    if let Some(value) = value {
                        output.serialize_field("value", &value)?;
                    }
                    if let Some(sender_ciphertext) = sender_ciphertext {
                        output.serialize_field("sender_ciphertext", &sender_ciphertext)?;
                    }
                    output.end()
                }
                Self::ExternalRecord(id) => {
                    let mut output = serializer.serialize_struct("Output", 2)?;
                    output.serialize_field("type", "external_record")?;
                    output.serialize_field("id", &id)?;
                    output.end()
                }
                Self::Future(id, value) => {
                    let mut output = serializer.serialize_struct("Output", 2 + value.is_some() as usize)?;
                    output.serialize_field("type", "future")?;
                    output.serialize_field("id", &id)?;
                    if let Some(value) = value {
                        output.serialize_field("value", &value)?;
                    }
                    output.end()
                }
                Self::DynamicRecord(id) => {
                    let mut output = serializer.serialize_struct("Output", 2)?;
                    output.serialize_field("type", "record_dynamic")?;
                    output.serialize_field("id", &id)?;
                    output.end()
                }
                Self::RecordWithDynamicID(id, checksum, value, sender_ciphertext, dynamic_id) => {
                    let mut output = serializer.serialize_struct(
                        "Output",
                        4 + value.is_some() as usize + sender_ciphertext.is_some() as usize,
                    )?;
                    output.serialize_field("type", "record_with_dynamic_id")?;
                    output.serialize_field("id", &id)?;
                    output.serialize_field("checksum", &checksum)?;
                    if let Some(value) = value {
                        output.serialize_field("value", &value)?;
                    }
                    if let Some(sender_ciphertext) = sender_ciphertext {
                        output.serialize_field("sender_ciphertext", &sender_ciphertext)?;
                    }
                    output.serialize_field("dynamic_id", &dynamic_id)?;
                    output.end()
                }
                Self::ExternalRecordWithDynamicID(id, dynamic_id) => {
                    let mut output = serializer.serialize_struct("Output", 3)?;
                    output.serialize_field("type", "external_record_with_dynamic_id")?;
                    output.serialize_field("id", &id)?;
                    output.serialize_field("dynamic_id", &dynamic_id)?;
                    output.end()
                }
            },
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Output<N> {
    /// Deserializes the transition output from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Parse the output from a string into a value.
                let mut output = serde_json::Value::deserialize(deserializer)?;
                // Retrieve the ID.
                let id: Field<N> = DeserializeExt::take_from_value::<D>(&mut output, "id")?;

                // Recover the output.
                let output = match output.get("type").and_then(|t| t.as_str()) {
                    Some("constant") => Output::Constant(id, match output.get("value").and_then(|v| v.as_str()) {
                        Some(value) => Some(Plaintext::<N>::from_str(value).map_err(de::Error::custom)?),
                        None => None,
                    }),
                    Some("public") => Output::Public(id, match output.get("value").and_then(|v| v.as_str()) {
                        Some(value) => Some(Plaintext::<N>::from_str(value).map_err(de::Error::custom)?),
                        None => None,
                    }),
                    Some("private") => Output::Private(id, match output.get("value").and_then(|v| v.as_str()) {
                        Some(value) => Some(Ciphertext::<N>::from_str(value).map_err(de::Error::custom)?),
                        None => None,
                    }),
                    Some("record") => {
                        // Retrieve the checksum.
                        let checksum: Field<N> = DeserializeExt::take_from_value::<D>(&mut output, "checksum")?;
                        // Return the record.
                        Output::Record(
                            id,
                            checksum,
                            match output.get("value").and_then(|v| v.as_str()) {
                                Some(value) => {
                                    Some(Record::<N, Ciphertext<N>>::from_str(value).map_err(de::Error::custom)?)
                                }
                                None => None,
                            },
                            match output.get("sender_ciphertext").and_then(|v| v.as_str()) {
                                Some(value) => Some(Field::<N>::from_str(value).map_err(de::Error::custom)?),
                                None => None,
                            },
                        )
                    }
                    Some("external_record") => Output::ExternalRecord(id),
                    Some("future") => Output::Future(id, match output.get("value").and_then(|v| v.as_str()) {
                        Some(value) => Some(Future::<N>::from_str(value).map_err(de::Error::custom)?),
                        None => None,
                    }),
                    Some("record_dynamic") => Output::DynamicRecord(id),
                    Some("record_with_dynamic_id") => {
                        // Retrieve the checksum.
                        let checksum: Field<N> = DeserializeExt::take_from_value::<D>(&mut output, "checksum")?;
                        // Retrieve the dynamic ID.
                        let dynamic_id: Field<N> = DeserializeExt::take_from_value::<D>(&mut output, "dynamic_id")?;
                        // Return the record with dynamic ID.
                        Output::RecordWithDynamicID(
                            id,
                            checksum,
                            match output.get("value").and_then(|v| v.as_str()) {
                                Some(value) => {
                                    Some(Record::<N, Ciphertext<N>>::from_str(value).map_err(de::Error::custom)?)
                                }
                                None => None,
                            },
                            match output.get("sender_ciphertext").and_then(|v| v.as_str()) {
                                Some(value) => Some(Field::<N>::from_str(value).map_err(de::Error::custom)?),
                                None => None,
                            },
                            dynamic_id,
                        )
                    }
                    Some("external_record_with_dynamic_id") => {
                        // Retrieve the dynamic ID.
                        let dynamic_id: Field<N> = DeserializeExt::take_from_value::<D>(&mut output, "dynamic_id")?;
                        Output::ExternalRecordWithDynamicID(id, dynamic_id)
                    }
                    _ => return Err(de::Error::custom("Invalid output type")),
                };

                // Return the output.
                Ok(output)
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "transition output"),
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
    }

    #[test]
    fn test_serde_json() {
        for (_, expected) in crate::transition::output::test_helpers::sample_outputs() {
            check_serde_json(expected);
        }
    }

    #[test]
    fn test_bincode() {
        for (_, expected) in crate::transition::output::test_helpers::sample_outputs() {
            check_bincode(expected);
        }
    }
}
