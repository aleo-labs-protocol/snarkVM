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

impl<N: Network> Serialize for Input<N> {
    /// Serializes the transition input into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => match self {
                Self::Constant(id, value) => {
                    let mut input = serializer.serialize_struct("Input", 2 + value.is_some() as usize)?;
                    input.serialize_field("type", "constant")?;
                    input.serialize_field("id", &id)?;
                    if let Some(value) = value {
                        input.serialize_field("value", &value)?;
                    }
                    input.end()
                }
                Self::Public(id, value) => {
                    let mut input = serializer.serialize_struct("Input", 2 + value.is_some() as usize)?;
                    input.serialize_field("type", "public")?;
                    input.serialize_field("id", &id)?;
                    if let Some(value) = value {
                        input.serialize_field("value", &value)?;
                    }
                    input.end()
                }
                Self::Private(id, value) => {
                    let mut input = serializer.serialize_struct("Input", 2 + value.is_some() as usize)?;
                    input.serialize_field("type", "private")?;
                    input.serialize_field("id", &id)?;
                    if let Some(value) = value {
                        input.serialize_field("value", &value)?;
                    }
                    input.end()
                }
                Self::Record(id, tag) => {
                    let mut input = serializer.serialize_struct("Input", 3)?;
                    input.serialize_field("type", "record")?;
                    input.serialize_field("id", &id)?;
                    input.serialize_field("tag", &tag)?;
                    input.end()
                }
                Self::ExternalRecord(id) => {
                    let mut input = serializer.serialize_struct("Input", 2)?;
                    input.serialize_field("type", "external_record")?;
                    input.serialize_field("id", &id)?;
                    input.end()
                }
                Self::DynamicRecord(id) => {
                    let mut input = serializer.serialize_struct("Input", 2)?;
                    input.serialize_field("type", "record_dynamic")?;
                    input.serialize_field("id", &id)?;
                    input.end()
                }
                Self::RecordWithDynamicID(id, tag, dynamic_id) => {
                    let mut input = serializer.serialize_struct("Input", 4)?;
                    input.serialize_field("type", "record_with_dynamic_id")?;
                    input.serialize_field("id", &id)?;
                    input.serialize_field("tag", &tag)?;
                    input.serialize_field("dynamic_id", &dynamic_id)?;
                    input.end()
                }
                Self::ExternalRecordWithDynamicID(id, dynamic_id) => {
                    let mut input = serializer.serialize_struct("Input", 3)?;
                    input.serialize_field("type", "external_record_with_dynamic_id")?;
                    input.serialize_field("id", &id)?;
                    input.serialize_field("dynamic_id", &dynamic_id)?;
                    input.end()
                }
            },
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Input<N> {
    /// Deserializes the transition input from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Parse the input from a string into a value.
                let mut input = serde_json::Value::deserialize(deserializer)?;
                // Retrieve the ID.
                let id: Field<N> = DeserializeExt::take_from_value::<D>(&mut input, "id")?;

                // Recover the input.
                let input = match input.get("type").and_then(|t| t.as_str()) {
                    Some("constant") => Input::Constant(id, match input.get("value").and_then(|v| v.as_str()) {
                        Some(value) => Some(Plaintext::<N>::from_str(value).map_err(de::Error::custom)?),
                        None => None,
                    }),
                    Some("public") => Input::Public(id, match input.get("value").and_then(|v| v.as_str()) {
                        Some(value) => Some(Plaintext::<N>::from_str(value).map_err(de::Error::custom)?),
                        None => None,
                    }),
                    Some("private") => Input::Private(id, match input.get("value").and_then(|v| v.as_str()) {
                        Some(value) => Some(Ciphertext::<N>::from_str(value).map_err(de::Error::custom)?),
                        None => None,
                    }),
                    Some("record") => Input::Record(id, DeserializeExt::take_from_value::<D>(&mut input, "tag")?),
                    Some("external_record") => Input::ExternalRecord(id),
                    Some("record_dynamic") => Input::DynamicRecord(id),
                    Some("record_with_dynamic_id") => Input::RecordWithDynamicID(
                        id,
                        DeserializeExt::take_from_value::<D>(&mut input, "tag")?,
                        DeserializeExt::take_from_value::<D>(&mut input, "dynamic_id")?,
                    ),
                    Some("external_record_with_dynamic_id") => Input::ExternalRecordWithDynamicID(
                        id,
                        DeserializeExt::take_from_value::<D>(&mut input, "dynamic_id")?,
                    ),
                    _ => return Err(de::Error::custom("Invalid transition input type")),
                };
                // Return the input.
                Ok(input)
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "transition input"),
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
        for (_, input) in crate::transition::input::test_helpers::sample_inputs() {
            check_serde_json(input);
        }
    }

    #[test]
    fn test_bincode() {
        for (_, input) in crate::transition::input::test_helpers::sample_inputs() {
            check_bincode(input);
        }
    }
}
