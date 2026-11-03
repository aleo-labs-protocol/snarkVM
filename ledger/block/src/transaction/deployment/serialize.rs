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

impl<N: Network> Serialize for Deployment<N> {
    /// Serializes the deployment into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                // Note: `Deployment::version` checks optional fields to determine the version.
                // V1: edition, program, verifying_keys (3 fields)
                // V2: + program_checksum, program_owner (5 fields)
                // V3: + program_checksum (4 fields, no owner)
                let len = match self.version().map_err(ser::Error::custom)? {
                    DeploymentVersion::V1 => 3,
                    DeploymentVersion::V2 => 5,
                    DeploymentVersion::V3 => 4,
                };
                let mut deployment = serializer.serialize_struct("Deployment", len)?;
                deployment.serialize_field("edition", &self.edition)?;
                deployment.serialize_field("program", &self.program)?;
                deployment.serialize_field("verifying_keys", &self.verifying_keys)?;
                if let Some(program_checksum) = &self.program_checksum {
                    deployment.serialize_field("program_checksum", program_checksum)?;
                }
                if let Some(program_owner) = &self.program_owner {
                    deployment.serialize_field("program_owner", program_owner)?;
                }
                deployment.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Deployment<N> {
    /// Deserializes the deployment from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Parse the deployment from a string into a value.
                let mut deployment = serde_json::Value::deserialize(deserializer)?;

                // Recover the deployment.
                let deployment = Self::new(
                    // Retrieve the edition.
                    DeserializeExt::take_from_value::<D>(&mut deployment, "edition")?,
                    // Retrieve the program.
                    DeserializeExt::take_from_value::<D>(&mut deployment, "program")?,
                    // Retrieve the verifying keys.
                    DeserializeExt::take_from_value::<D>(&mut deployment, "verifying_keys")?,
                    // Retrieve the program checksum, if it exists.
                    serde_json::from_value(
                        deployment.get_mut("program_checksum").unwrap_or(&mut serde_json::Value::Null).take(),
                    )
                    .map_err(de::Error::custom)?,
                    // Retrieve the owner, if it exists.
                    serde_json::from_value(
                        deployment.get_mut("program_owner").unwrap_or(&mut serde_json::Value::Null).take(),
                    )
                    .map_err(de::Error::custom)?,
                )
                .map_err(de::Error::custom)?;

                Ok(deployment)
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "deployment"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_json() -> Result<()> {
        let rng = &mut TestRng::default();

        // Sample the deployments.
        for expected in [
            test_helpers::sample_deployment_v1(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v2_without_translation_keys(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v2_with_translation_keys(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v3(Uniform::rand(rng), rng),
        ] {
            // Serialize
            let expected_string = &expected.to_string();
            let candidate_string = serde_json::to_string(&expected)?;
            assert_eq!(expected, serde_json::from_str(&candidate_string)?);

            // Deserialize
            assert_eq!(expected, Deployment::from_str(expected_string)?);
            assert_eq!(expected, serde_json::from_str(&candidate_string)?);
        }

        Ok(())
    }

    #[test]
    fn test_bincode() -> Result<()> {
        let rng = &mut TestRng::default();

        // Sample the deployments
        for expected in [
            test_helpers::sample_deployment_v1(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v2_without_translation_keys(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v2_with_translation_keys(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v3(Uniform::rand(rng), rng),
        ] {
            // Serialize
            let expected_bytes = expected.to_bytes_le()?;
            let expected_bytes_with_size_encoding = bincode::serialize(&expected)?;
            assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

            // Deserialize
            assert_eq!(expected, Deployment::read_le(&expected_bytes[..])?);
            assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..])?);
        }

        Ok(())
    }
}
