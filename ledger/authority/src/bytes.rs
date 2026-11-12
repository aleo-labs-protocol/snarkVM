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

impl<N: Network> Authority<N> {
    /// Reads the authority either with or without checks on the data, decoding each compute key
    /// only if `cache` holds no earlier decode of the same bytes.
    pub fn read_le_with_cache<R: Read>(
        mut reader: R,
        unchecked: bool,
        cache: &mut ComputeKeyCache<N>,
    ) -> IoResult<Self> {
        // Read the variant.
        let variant = u8::read_le(&mut reader)?;
        // Match the variant.
        match variant {
            0 => Ok(Self::Beacon(Signature::read_le_with_cache(&mut reader, unchecked, cache)?)),
            1 => Ok(Self::Quorum(Subdag::read_le_with_cache(&mut reader, unchecked, cache)?)),
            2.. => Err(error("Invalid authority variant")),
        }
    }
}

impl<N: Network> FromBytes for Authority<N> {
    /// Reads the authority from the buffer.
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_cache(reader, false, &mut ComputeKeyCache::default())
    }

    /// Reads the authority from the buffer without performing any checks on the data.
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_cache(reader, true, &mut ComputeKeyCache::default())
    }
}

impl<N: Network> ToBytes for Authority<N> {
    /// Writes the authority to the buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the authority.
        match self {
            Self::Beacon(signature) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the signature.
                signature.write_le(&mut writer)
            }
            Self::Quorum(subdag) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the subdag.
                subdag.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::prelude::TestRng;

    #[test]
    fn test_bytes() {
        let rng = &mut TestRng::default();

        for expected in crate::test_helpers::sample_authorities(rng) {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, Authority::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, Authority::read_le_unchecked(&expected_bytes[..]).unwrap());
        }
    }

    /// Returns the `Debug` output of every compute key in `authority`, which shows `sk_prf`.
    fn compute_key_debug(authority: &Authority<console::network::MainnetV0>) -> Vec<String> {
        let debug = |signature: &Signature<_>| format!("{:?}", signature.compute_key());
        match authority {
            Authority::Beacon(signature) => vec![debug(signature)],
            Authority::Quorum(subdag) => subdag
                .values()
                .flatten()
                .flat_map(|certificate| {
                    std::iter::once(certificate.batch_header().signature()).chain(certificate.signatures())
                })
                .map(debug)
                .collect(),
        }
    }

    #[test]
    fn test_bytes_with_cache() {
        let rng = &mut TestRng::default();
        let authorities = crate::test_helpers::sample_authorities(rng);

        // One cache across every authority and both modes, so later reads hit entries from earlier ones.
        let mut cache = ComputeKeyCache::default();
        for unchecked in [false, true, false, true] {
            for expected in &authorities {
                let bytes = expected.to_bytes_le().unwrap();
                let cold = Authority::read_le_with_unchecked(&bytes[..], unchecked).unwrap();
                let cached = Authority::read_le_with_cache(&bytes[..], unchecked, &mut cache).unwrap();
                assert_eq!(expected, &cached);
                assert_eq!(compute_key_debug(&cold), compute_key_debug(&cached));
            }
        }
        assert!(!cache.is_empty());
    }
}
