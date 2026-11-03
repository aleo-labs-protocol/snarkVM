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

impl<N: Network> FromBytes for TransitionLeaf<N> {
    /// Reads the transition leaf from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the version.
        let version = FromBytes::read_le(&mut reader)?;
        // Read the index.
        let index = FromBytes::read_le(&mut reader)?;
        // Read the variant.
        let variant = FromBytes::read_le(&mut reader)?;
        // Read the ID.
        let id = FromBytes::read_le(&mut reader)?;
        // Return the transition leaf.
        Self::from(version, index, variant, id).map_err(|e| error(e.to_string()))
    }
}

impl<N: Network> ToBytes for TransitionLeaf<N> {
    /// Writes the transition leaf to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        self.version.write_le(&mut writer)?;
        // Write the index.
        self.index.write_le(&mut writer)?;
        // Write the variant.
        self.variant.write_le(&mut writer)?;
        // Write the ID.
        self.id.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_bytes() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a static leaf (version 1).
            let expected = test_helpers::sample_leaf(&mut rng);

            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le()?;
            assert_eq!(expected, TransitionLeaf::read_le(&expected_bytes[..])?);

            // Sample a dynamic leaf (version 2).
            let expected_dynamic = test_helpers::sample_dynamic_leaf(&mut rng);

            // Check the byte representation.
            let expected_dynamic_bytes = expected_dynamic.to_bytes_le()?;
            assert_eq!(expected_dynamic, TransitionLeaf::read_le(&expected_dynamic_bytes[..])?);
        }
        Ok(())
    }

    #[test]
    fn test_version_variant_validation() -> Result<()> {
        let mut rng = TestRng::default();
        let id = Uniform::rand(&mut rng);

        // Test that version 1 (static) works with any variant.
        for variant in 0..=7 {
            let leaf = TransitionLeaf::<CurrentNetwork>::new(0, variant, id);
            let bytes = leaf.to_bytes_le()?;
            assert!(TransitionLeaf::<CurrentNetwork>::read_le(&bytes[..]).is_ok());
        }

        // Test that version 2 (dynamic) only works with Record (3) and ExternalRecord (4).
        let leaf_record = TransitionLeaf::<CurrentNetwork>::new_record_with_dynamic_id(0, id);
        let bytes = leaf_record.to_bytes_le()?;
        assert!(TransitionLeaf::<CurrentNetwork>::read_le(&bytes[..]).is_ok());

        let leaf_external = TransitionLeaf::<CurrentNetwork>::new_external_record_with_dynamic_id(0, id);
        let bytes = leaf_external.to_bytes_le()?;
        assert!(TransitionLeaf::<CurrentNetwork>::read_le(&bytes[..]).is_ok());

        // Test that version 2 (dynamic) returns an error for invalid variants.
        for variant in [0u8, 1, 2, 5, 6, 7] {
            assert!(
                TransitionLeaf::<CurrentNetwork>::from(LeafVersion::Dynamic as u8, 0, variant, id).is_err(),
                "Expected error for dynamic variant {variant}"
            );
        }

        Ok(())
    }
}
