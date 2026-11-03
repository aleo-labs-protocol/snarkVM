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

impl<N: Network> FromBytes for Deployment<N> {
    /// Reads the deployment from a buffer, either with or without checking the data.
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        // Read the version and ensure the version is valid.
        let version = match u8::read_le(&mut reader)? {
            1 => DeploymentVersion::V1,
            2 => DeploymentVersion::V2,
            3 => DeploymentVersion::V3,
            version => return Err(error(format!("Invalid deployment version: {version}"))),
        };

        // Read the edition.
        let edition = u16::read_le(&mut reader)?;
        // Read the program.
        let program = Program::read_le(&mut reader)?;

        // Read the number of entries in the bundle.
        let num_entries = u16::read_le(&mut reader)?;
        // Ensure the number of entries is within bounds.
        let max_entries = N::MAX_FUNCTIONS + N::MAX_RECORDS;
        if num_entries as usize > max_entries {
            return Err(error(format!(
                "Deployment (from 'read_le') has too many entries ({num_entries} > {max_entries})"
            )));
        }
        // Read the verifying keys.
        let mut verifying_keys = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            // Read the identifier.
            let identifier = Identifier::<N>::read_le(&mut reader)?;
            // Read the verifying key.
            let verifying_key = VerifyingKey::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
            // Read the certificate.
            let certificate = Certificate::<N>::read_le_with_unchecked(&mut reader, unchecked)?;
            // Add the entry.
            verifying_keys.push((identifier, (verifying_key, certificate)));
        }

        // If the deployment version is V2 or V3, read the program checksum and verify it.
        let program_checksum = match version {
            DeploymentVersion::V1 => None,
            DeploymentVersion::V2 | DeploymentVersion::V3 => {
                // Read the program checksum.
                let bytes: [u8; 32] = FromBytes::read_le(&mut reader)?;
                let checksum = bytes.map(U8::new);
                // Verify the checksum.
                if checksum != program.to_checksum() {
                    return Err(error(format!(
                        "Invalid checksum in the deployment: expected [{}], got [{}]",
                        program.to_checksum().iter().join(", "),
                        checksum.iter().join(", ")
                    )));
                }
                Some(checksum)
            }
        };
        // If the deployment version is V2, read the program owner.
        // Note: V3 (amendments) do not have a program owner.
        let program_owner = match version {
            DeploymentVersion::V1 | DeploymentVersion::V3 => None,
            DeploymentVersion::V2 => {
                // Read the program owner.
                let owner = Address::<N>::read_le(&mut reader)?;
                Some(owner)
            }
        };

        // Return the deployment.
        Self::new(edition, program, verifying_keys, program_checksum, program_owner)
            .map_err(|err| error(format!("{err}")))
    }

    /// Reads the deployment from a buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads the deployment from a buffer without checking the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for Deployment<N> {
    /// Writes the deployment to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Determine the version.
        // Note: This method determines the version based on the presence of checksum and owner fields.
        let version = self.version().map_err(error)?;
        // Write the version.
        (version as u8).write_le(&mut writer)?;
        // Write the edition.
        self.edition.write_le(&mut writer)?;
        // Write the program.
        self.program.write_le(&mut writer)?;
        // Write the number of entries in the bundle.
        (u16::try_from(self.verifying_keys.len()).map_err(|e| error(e.to_string()))?).write_le(&mut writer)?;
        // Write each entry.
        for (name, (verifying_key, certificate)) in &self.verifying_keys {
            // Write the name.
            name.write_le(&mut writer)?;
            // Write the verifying key.
            verifying_key.write_le(&mut writer)?;
            // Write the certificate.
            certificate.write_le(&mut writer)?;
        }
        // If the deployment version is V2 or V3, write the program checksum.
        // Note: The unwrap is safe because `Deployment::version` only returns V2/V3 if the checksum is present.
        if matches!(version, DeploymentVersion::V2 | DeploymentVersion::V3) {
            // Write the bytes of the checksum.
            for byte in &self.program_checksum.unwrap() {
                byte.write_le(&mut writer)?;
            }
        }
        // If the deployment version is V2, write the program owner.
        // Note: The unwrap is safe because `Deployment::version` only returns V2 if the owner is present.
        if matches!(version, DeploymentVersion::V2) {
            self.program_owner.unwrap().write_le(&mut writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        // Construct the deployments.
        for expected in [
            test_helpers::sample_deployment_v1(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v2_without_translation_keys(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v2_with_translation_keys(Uniform::rand(rng), rng),
            test_helpers::sample_deployment_v3(Uniform::rand(rng), rng),
        ] {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le()?;
            assert_eq!(expected, Deployment::read_le(&expected_bytes[..])?);
            assert_eq!(expected, Deployment::read_le_unchecked(&expected_bytes[..])?);
        }

        Ok(())
    }
}
