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

impl<N: Network> FromBytes for Signature<N> {
    /// Reads an account signature from a buffer, either with or without checking the data.
    #[inline]
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        let challenge = Scalar::new(FromBytes::read_le(&mut reader)?);
        let response = Scalar::new(FromBytes::read_le(&mut reader)?);
        let compute_key = ComputeKey::read_le_with_unchecked(&mut reader, unchecked)?;
        Ok(Self { challenge, response, compute_key })
    }

    /// Reads an account signature from a buffer.
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads an account signature from a buffer, without computing `sk_prf`.
    #[inline]
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> Signature<N> {
    /// Reads an account signature from a buffer as `read_le_with_unchecked` does, decoding the
    /// compute key only if `cache` holds no earlier decode of the same bytes.
    #[inline]
    pub fn read_le_with_cache<R: Read>(
        mut reader: R,
        unchecked: bool,
        cache: &mut ComputeKeyCache<N>,
    ) -> IoResult<Self> {
        let challenge = Scalar::new(FromBytes::read_le(&mut reader)?);
        let response = Scalar::new(FromBytes::read_le(&mut reader)?);
        let compute_key = cache.read_compute_key(&mut reader, unchecked)?;
        Ok(Self { challenge, response, compute_key })
    }
}

impl<N: Network> ToBytes for Signature<N> {
    /// Writes an account signature to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.challenge.write_le(&mut writer)?;
        self.response.write_le(&mut writer)?;
        self.compute_key.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 100;

    #[test]
    fn test_bytes() -> Result<()> {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a new signature.
            let signature = test_helpers::sample_signature(i, &mut rng);

            // Check the byte representation.
            let signature_bytes = signature.to_bytes_le()?;
            assert_eq!(signature, Signature::read_le(&signature_bytes[..])?);
            assert_eq!(signature, Signature::read_le_unchecked(&signature_bytes[..])?);
            assert!(Signature::<CurrentNetwork>::read_le(&signature_bytes[1..]).is_err());
            assert!(Signature::<CurrentNetwork>::read_le_unchecked(&signature_bytes[1..]).is_err());
        }
        Ok(())
    }

    #[test]
    fn test_bytes_with_cache() -> Result<()> {
        let mut rng = TestRng::default();
        let mut cache = ComputeKeyCache::default();

        for i in 0..ITERATIONS {
            let signature = test_helpers::sample_signature(i, &mut rng);
            let signature_bytes = signature.to_bytes_le()?;
            // The second read of each mode hits the cache.
            for unchecked in [false, true, false, true] {
                let cold = Signature::<CurrentNetwork>::read_le_with_unchecked(&signature_bytes[..], unchecked)?;
                let cached = Signature::read_le_with_cache(&signature_bytes[..], unchecked, &mut cache)?;
                assert_eq!(signature, cached);
                // `ComputeKey` equality ignores `sk_prf`, and `Debug` shows it.
                assert_eq!(format!("{:?}", cold.compute_key()), format!("{:?}", cached.compute_key()));
                assert!(Signature::read_le_with_cache(&signature_bytes[1..], unchecked, &mut cache).is_err());
            }
        }
        Ok(())
    }
}
