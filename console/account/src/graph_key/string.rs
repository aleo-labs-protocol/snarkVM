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

static GRAPH_KEY_PREFIX: [u8; 9] = [42, 72, 193, 144, 65, 126, 212, 229, 211]; // AGraphKey1

impl<N: Network> FromStr for GraphKey<N> {
    type Err = Error;

    /// Reads in an account graph key from a base58 string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Encode the string into base58.
        let data = bs58::decode(s).into_vec().map_err(|err| anyhow!("{err:?}"))?;
        if data.len() != 41 {
            bail!("Invalid account graph key length: found {}, expected 41", data.len())
        } else if data[0..9] != GRAPH_KEY_PREFIX {
            bail!("Invalid account graph key prefix: found {:?}, expected {:?}", &data[0..9], GRAPH_KEY_PREFIX)
        }
        // Output the graph key.
        Self::try_from(Field::read_le(&data[9..41])?)
    }
}

impl<N: Network> fmt::Display for GraphKey<N> {
    /// Writes the account graph key as a base58 string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write the graph key bytes.
        let mut graph_key = [0u8; 41];
        graph_key[0..9].copy_from_slice(&GRAPH_KEY_PREFIX);
        self.sk_tag.write_le(&mut graph_key[9..41]).map_err(|_| fmt::Error)?;
        // Encode the graph key into base58.
        write!(f, "{}", bs58::encode(graph_key).into_string())
    }
}

impl<N: Network> fmt::Debug for GraphKey<N> {
    /// Writes the account graph key without revealing its contents.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("GraphKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateKey;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 10_000;

    #[test]
    fn test_string() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new graph key.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let view_key = ViewKey::try_from(private_key)?;
            let expected = GraphKey::try_from(view_key)?;

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, GraphKey::from_str(&candidate)?);
            assert_eq!("AGraphKey", candidate.split('1').next().unwrap());
        }
        Ok(())
    }

    #[test]
    fn test_debug_is_redacted() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new graph key.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let view_key = ViewKey::try_from(private_key)?;
            let graph_key = GraphKey::try_from(view_key)?;

            // Check the debug representation reveals no secret.
            assert_eq!("GraphKey { .. }", format!("{graph_key:?}"));
            let candidate = format!("{graph_key:#?}");
            for secret in [graph_key.to_string(), graph_key.sk_tag().to_string()] {
                assert!(!candidate.contains(&secret));
            }
        }
        Ok(())
    }
}
