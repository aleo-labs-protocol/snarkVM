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

static PRIVATE_KEY_PREFIX: [u8; 11] = [127, 134, 189, 116, 210, 221, 210, 137, 145, 18, 253]; // APrivateKey1

impl<N: Network> FromStr for PrivateKey<N> {
    type Err = Error;

    /// Reads in an account private key from a base58 string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Encode the string into base58.
        let data = bs58::decode(s).into_vec().map_err(|err| anyhow!("{err:?}"))?;
        if data.len() != 43 {
            bail!("Invalid account private key length: found {}, expected 43", data.len())
        } else if data[0..11] != PRIVATE_KEY_PREFIX {
            bail!("Invalid account private key prefix: found {:?}, expected {:?}", &data[0..11], PRIVATE_KEY_PREFIX)
        }
        // Output the private key.
        Ok(Self::try_from(Field::new(FromBytes::read_le(&data[11..43])?)).map_err(into_io_error)?)
    }
}

impl<N: Network> fmt::Display for PrivateKey<N> {
    /// Writes the account private key as a base58 string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write the private key bytes.
        let mut private_key = [0u8; 43];
        private_key[0..11].copy_from_slice(&PRIVATE_KEY_PREFIX);
        self.seed.write_le(&mut private_key[11..43]).map_err(|_| fmt::Error)?;
        // Encode the private key into base58.
        write!(f, "{}", bs58::encode(private_key).into_string())
    }
}

impl<N: Network> fmt::Debug for PrivateKey<N> {
    /// Writes the account private key without revealing its contents.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
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
            // Sample a new private key.
            let expected = PrivateKey::<CurrentNetwork>::new(&mut rng)?;

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, PrivateKey::from_str(&candidate)?);
            assert_eq!("APrivateKey", candidate.split('1').next().unwrap());
        }
        Ok(())
    }

    #[test]
    fn test_debug_is_redacted() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;

            // Check the debug representation reveals no secret.
            assert_eq!("PrivateKey { .. }", format!("{private_key:?}"));
            let candidate = format!("{private_key:#?}");
            for secret in [
                private_key.to_string(),
                private_key.seed().to_string(),
                private_key.sk_sig().to_string(),
                private_key.r_sig().to_string(),
            ] {
                assert!(!candidate.contains(&secret));
            }
        }
        Ok(())
    }
}
