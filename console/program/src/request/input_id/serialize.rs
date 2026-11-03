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

use snarkvm_utilities::DeserializeExt;

impl<N: Network> Serialize for InputID<N> {
    /// Serializes the input ID into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => match self {
                Self::Constant(id) => {
                    let mut input = serializer.serialize_struct("InputID", 2)?;
                    input.serialize_field("type", "constant")?;
                    input.serialize_field("id", &id)?;
                    input.end()
                }
                Self::Public(id) => {
                    let mut input = serializer.serialize_struct("InputID", 2)?;
                    input.serialize_field("type", "public")?;
                    input.serialize_field("id", &id)?;
                    input.end()
                }
                Self::Private(id) => {
                    let mut input = serializer.serialize_struct("InputID", 2)?;
                    input.serialize_field("type", "private")?;
                    input.serialize_field("id", &id)?;
                    input.end()
                }
                Self::Record(commitment, gamma, record_view_key, serial_number, tag) => {
                    let mut input = serializer.serialize_struct("InputID", 5)?;
                    input.serialize_field("type", "record")?;
                    input.serialize_field("commitment", &commitment)?;
                    input.serialize_field("gamma", &gamma)?;
                    input.serialize_field("record_view_key", &record_view_key)?;
                    input.serialize_field("serial_number", &serial_number)?;
                    input.serialize_field("tag", &tag)?;
                    input.end()
                }
                Self::ExternalRecord(id) => {
                    let mut input = serializer.serialize_struct("InputID", 2)?;
                    input.serialize_field("type", "external_record")?;
                    input.serialize_field("id", &id)?;
                    input.end()
                }
                Self::DynamicRecord(id) => {
                    let mut input = serializer.serialize_struct("InputID", 2)?;
                    input.serialize_field("type", "record_dynamic")?;
                    input.serialize_field("id", &id)?;
                    input.end()
                }
            },
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for InputID<N> {
    /// Deserializes the input ID from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Parse the input ID from a string into a value.
                let mut input = serde_json::Value::deserialize(deserializer)?;
                // Recover the input.
                let input_id = match input.get("type").and_then(|t| t.as_str()) {
                    Some("constant") => InputID::Constant(DeserializeExt::take_from_value::<D>(&mut input, "id")?),
                    Some("public") => InputID::Public(DeserializeExt::take_from_value::<D>(&mut input, "id")?),
                    Some("private") => InputID::Private(DeserializeExt::take_from_value::<D>(&mut input, "id")?),
                    Some("record") => InputID::Record(
                        DeserializeExt::take_from_value::<D>(&mut input, "commitment")?,
                        DeserializeExt::take_from_value::<D>(&mut input, "gamma")?,
                        DeserializeExt::take_from_value::<D>(&mut input, "record_view_key")?,
                        DeserializeExt::take_from_value::<D>(&mut input, "serial_number")?,
                        DeserializeExt::take_from_value::<D>(&mut input, "tag")?,
                    ),
                    Some("external_record") => {
                        InputID::ExternalRecord(DeserializeExt::take_from_value::<D>(&mut input, "id")?)
                    }
                    Some("record_dynamic") => {
                        InputID::DynamicRecord(DeserializeExt::take_from_value::<D>(&mut input, "id")?)
                    }
                    _ => return Err(de::Error::custom("Invalid input type")),
                };
                Ok(input_id)
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "input ID"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    /// Add test cases here to be checked for serialization.
    const TEST_CASES: &[&str] = &[
        "{\"type\":\"constant\",\"id\":\"5field\"}",
        "{\"type\":\"public\",\"id\":\"0field\"}",
        "{\"type\":\"private\",\"id\":\"123field\"}",
        "{\"type\":\"record\",\"commitment\":\"123123field\",\"tag\":\"0field\",\"record_view_key\":\"0field\",\"serial_number\":\"123456789field\",\"gamma\":\"0group\"}",
        "{\"type\":\"external_record\",\"id\":\"123456789field\"}",
        "{\"type\":\"record_dynamic\",\"id\":\"987654321field\"}",
    ];

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
        for case in TEST_CASES.iter() {
            check_serde_json(InputID::<CurrentNetwork>::from_str(case).unwrap());
        }
    }

    #[test]
    fn test_bincode() {
        for case in TEST_CASES.iter() {
            check_bincode(InputID::<CurrentNetwork>::from_str(case).unwrap());
        }
    }
}
