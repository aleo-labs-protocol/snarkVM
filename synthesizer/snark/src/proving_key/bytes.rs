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

impl<N: Network> FromBytes for ProvingKey<N> {
    /// Reads the proving key from a buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_sharing(reader, None)
    }
}

impl<N: Network> ProvingKey<N> {
    /// Reads a proving key as `read_le` does, but shares its committer key's
    /// powers with `universal_srs`. Fails if `universal_srs` does not hold
    /// them, so grow it to the largest degree any key needs before reading
    /// keys; see `CommitterKey::read_le_with_srs`. The first use of
    /// `universal_srs` loads it, and panics if it cannot be loaded.
    pub fn read_le_with_srs<R: Read>(reader: R, universal_srs: &UniversalSRS<N>) -> IoResult<Self> {
        Self::read_le_sharing(reader, Some(universal_srs))
    }

    /// Reads a proving key from bytes, as `read_le_with_srs` does.
    pub fn from_bytes_le_with_srs(bytes: &[u8], universal_srs: &UniversalSRS<N>) -> Result<Self> {
        Ok(Self::read_le_with_srs(bytes, universal_srs)?)
    }

    fn read_le_sharing<R: Read>(mut reader: R, universal_srs: Option<&UniversalSRS<N>>) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid proving key version"));
        }
        // Read the proving key.
        let proving_key = Arc::new(match universal_srs {
            Some(universal_srs) => varuna::CircuitProvingKey::read_le_with_srs(&mut reader, universal_srs)?,
            None => FromBytes::read_le(&mut reader)?,
        });
        // Return the proving key.
        Ok(Self { proving_key })
    }
}

impl<N: Network> ToBytes for ProvingKey<N> {
    /// Writes the proving key to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;
        // Write the bytes.
        self.proving_key.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{CurrentNetwork, sample_assignment, sample_keys};
    use circuit::environment::{Circuit, Environment};
    use snarkvm_algorithms::{
        polycommit::sonic_pc::{self, Bases},
        snark::varuna::VarunaVersion,
    };

    #[test]
    fn test_bytes_with_srs() -> Result<()> {
        let (expected, verifying_key) = sample_keys();
        let expected_bytes = expected.to_bytes_le()?;

        // Read with the SRS, the key shares its powers and writes the same bytes.
        let srs = UniversalSRS::<CurrentNetwork>::load()?;
        let candidate = ProvingKey::from_bytes_le_with_srs(&expected_bytes, &srs)?;
        assert!(matches!(candidate.committer_key.powers_of_beta_g, Bases::Shared { .. }));
        assert_eq!(candidate.to_bytes_le()?, expected_bytes);

        // The key proves.
        let assignment = sample_assignment();
        let proof = candidate.prove("test", VarunaVersion::V2, &assignment, &mut TestRng::default())?;
        let one = <Circuit as Environment>::BaseField::one();
        assert!(verifying_key.verify("test", VarunaVersion::V2, &[one, one], &proof));

        Ok(())
    }

    #[test]
    fn test_bytes_with_srs_rejects_other_points() -> Result<()> {
        let (proving_key, _) = sample_keys();
        let srs = UniversalSRS::<CurrentNetwork>::load()?;

        // A key whose first power is not the SRS's, with a hash that matches it.
        let committer_key = &proving_key.committer_key;
        let mut powers_of_beta_g = committer_key.powers_of_beta_g.to_vec();
        powers_of_beta_g.swap(0, 1);
        let edited = varuna::CircuitProvingKey {
            circuit_verifying_key: proving_key.circuit_verifying_key.clone(),
            circuit: proving_key.circuit.clone(),
            committer_key: Arc::new(sonic_pc::CommitterKey {
                powers_of_beta_g: powers_of_beta_g.into(),
                lagrange_bases_at_beta_g: committer_key.lagrange_bases_at_beta_g.clone(),
                powers_of_beta_times_gamma_g: committer_key.powers_of_beta_times_gamma_g.clone(),
                shifted_powers_of_beta_g: committer_key.shifted_powers_of_beta_g.clone(),
                shifted_powers_of_beta_times_gamma_g: committer_key.shifted_powers_of_beta_times_gamma_g.clone(),
                enforced_degree_bounds: committer_key.enforced_degree_bounds.clone(),
            }),
        };
        let bytes = ProvingKey::<CurrentNetwork>::new(Arc::new(edited)).to_bytes_le()?;

        // The key reads in full, and not with the SRS.
        assert!(ProvingKey::<CurrentNetwork>::from_bytes_le(&bytes).is_ok());
        assert!(ProvingKey::<CurrentNetwork>::from_bytes_le_with_srs(&bytes, &srs).is_err());

        Ok(())
    }
}
