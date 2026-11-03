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

impl<N: Network> Serialize for RejectedReason<N> {
    /// Serializes the rejected reason into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => match self {
                Self::DuplicateProgramID(program_id) => {
                    let mut object = serializer.serialize_struct("RejectedReason", 2)?;
                    object.serialize_field("type", "duplicate_program_id")?;
                    object.serialize_field("program_id", program_id)?;
                    object.end()
                }
                Self::Finalize { program_id, edition, resource, index, command } => {
                    let mut object = serializer.serialize_struct("RejectedReason", 6)?;
                    object.serialize_field("type", "finalize")?;
                    object.serialize_field("program_id", program_id)?;
                    object.serialize_field("edition", edition)?;
                    object.serialize_field("resource", resource)?;
                    object.serialize_field("index", index)?;
                    // Serialize the command via its display string to keep the JSON human-readable.
                    object.serialize_field("command", &command.to_string())?;
                    object.end()
                }
                Self::VM(program_id, resource) => {
                    // Only include fields that are present.
                    let mut object = serializer.serialize_struct(
                        "RejectedReason",
                        1 + program_id.is_some() as usize * 2 + resource.is_some() as usize,
                    )?;
                    object.serialize_field("type", "non_finalize")?;
                    if let Some((pid, edition)) = program_id {
                        object.serialize_field("program_id", pid)?;
                        object.serialize_field("edition", edition)?;
                    }
                    if let Some(resource) = resource {
                        object.serialize_field("resource", resource)?;
                    }
                    object.end()
                }
            },
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for RejectedReason<N> {
    /// Deserializes the rejected reason from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Parse the rejected reason from a string into a value.
                let mut object = serde_json::Value::deserialize(deserializer)?;
                // Parse the type.
                let type_ = object.get("type").and_then(|t| t.as_str());
                // Recover the rejected reason.
                match type_ {
                    Some("duplicate_program_id") => {
                        let program_id: ProgramID<N> = DeserializeExt::take_from_value::<D>(&mut object, "program_id")?;
                        Ok(Self::DuplicateProgramID(program_id))
                    }
                    Some("finalize") => {
                        let program_id: ProgramID<N> = DeserializeExt::take_from_value::<D>(&mut object, "program_id")?;
                        let edition: u16 = DeserializeExt::take_from_value::<D>(&mut object, "edition")?;
                        let resource: Identifier<N> = DeserializeExt::take_from_value::<D>(&mut object, "resource")?;
                        let index: usize = DeserializeExt::take_from_value::<D>(&mut object, "index")?;
                        // The command is stored as a display string; parse it back.
                        let command_str: String = DeserializeExt::take_from_value::<D>(&mut object, "command")?;
                        let command = command_str.parse::<Command<N>>().map_err(de::Error::custom)?;
                        Ok(Self::Finalize { program_id, edition, resource, index, command: Box::new(command) })
                    }
                    Some("non_finalize") => {
                        // Both fields are optional; use `.get()` to check presence before parsing.
                        let program_id = match object.get("program_id").and_then(|v| v.as_str()) {
                            Some(s) => {
                                let pid = ProgramID::<N>::from_str(s).map_err(de::Error::custom)?;
                                let edition: u16 = DeserializeExt::take_from_value::<D>(&mut object, "edition")?;
                                Some((pid, edition))
                            }
                            None => None,
                        };
                        let resource = match object.get("resource").and_then(|v| v.as_str()) {
                            Some(s) => Some(Identifier::<N>::from_str(s).map_err(de::Error::custom)?),
                            None => None,
                        };
                        Ok(Self::VM(program_id, resource))
                    }
                    _ => Err(de::Error::custom("Invalid rejected reason type")),
                }
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "rejected reason"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    fn check_serde_json(expected: RejectedReason<CurrentNetwork>) {
        // Serialize.
        let expected_string = expected.to_string();
        let candidate_string = serde_json::to_string(&expected).unwrap();
        let candidate = serde_json::from_str::<RejectedReason<CurrentNetwork>>(&candidate_string).unwrap();
        assert_eq!(expected, candidate);
        assert_eq!(expected_string, candidate_string);
        assert_eq!(expected_string, candidate.to_string());

        // Deserialize.
        assert_eq!(expected, RejectedReason::from_str(&expected_string).unwrap());
        assert_eq!(expected, serde_json::from_str(&candidate_string).unwrap());
    }

    fn check_bincode(expected: RejectedReason<CurrentNetwork>) {
        // Serialize.
        let expected_bytes = expected.to_bytes_le().unwrap();
        let expected_bytes_with_size_encoding = bincode::serialize(&expected).unwrap();
        assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

        // Deserialize.
        assert_eq!(expected, RejectedReason::read_le(&expected_bytes[..]).unwrap());
        assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..]).unwrap());
    }

    #[test]
    fn test_serde_json() {
        for reason in test_helpers::sample_rejected_reasons::<CurrentNetwork>() {
            check_serde_json(reason);
        }
    }

    #[test]
    fn test_bincode() {
        for reason in test_helpers::sample_rejected_reasons::<CurrentNetwork>() {
            check_bincode(reason);
        }
    }
}
