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

static VIEW_KEY_PREFIX: [u8; 7] = [14, 138, 223, 204, 247, 224, 122]; // AViewKey1

impl<N: Network> FromStr for ViewKey<N> {
    type Err = Error;

    /// Reads in an account view key from a base58 string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Encode the string into base58.
        let data = bs58::decode(s).into_vec().map_err(|err| anyhow!("{err:?}"))?;
        if data.len() != 39 {
            bail!("Invalid account view key length: found {}, expected 39", data.len())
        } else if data[0..7] != VIEW_KEY_PREFIX {
            bail!("Invalid account view key prefix: found {:?}, expected {:?}", &data[0..7], VIEW_KEY_PREFIX)
        }
        // Output the view key.
        Ok(Self::from_scalar(Scalar::new(FromBytes::read_le(&data[7..39])?)))
    }
}

impl<N: Network> fmt::Display for ViewKey<N> {
    /// Writes the account view key as a base58 string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write the view key bytes.
        let mut view_key = [0u8; 39];
        view_key[0..7].copy_from_slice(&VIEW_KEY_PREFIX);
        self.0.write_le(&mut view_key[7..39]).map_err(|_| fmt::Error)?;
        // Encode the view key into base58.
        write!(f, "{}", bs58::encode(view_key).into_string())
    }
}

impl<N: Network> fmt::Debug for ViewKey<N> {
    /// Writes the account view key without revealing its contents.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ViewKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_string() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new view key.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let expected = ViewKey::try_from(private_key)?;

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, ViewKey::from_str(&candidate)?);
            assert_eq!("AViewKey", candidate.split('1').next().unwrap());
        }
        Ok(())
    }

    #[test]
    fn test_debug_is_redacted() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new view key.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let view_key = ViewKey::try_from(private_key)?;

            // Check the debug representation reveals no secret.
            assert_eq!("ViewKey(..)", format!("{view_key:?}"));
            let candidate = format!("{view_key:#?}");
            for secret in [view_key.to_string(), (*view_key).to_string()] {
                assert!(!candidate.contains(&secret));
            }
        }
        Ok(())
    }
}
