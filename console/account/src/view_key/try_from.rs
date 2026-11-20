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

#[cfg(feature = "private_key")]
use super::*;

#[cfg(feature = "private_key")]
impl<N: Network> TryFrom<PrivateKey<N>> for ViewKey<N> {
    type Error = Error;

    /// Initializes a new account view key from an account private key.
    fn try_from(private_key: PrivateKey<N>) -> Result<Self, Self::Error> {
        Self::try_from(&private_key)
    }
}

#[cfg(feature = "private_key")]
impl<N: Network> TryFrom<&PrivateKey<N>> for ViewKey<N> {
    type Error = Error;

    /// Initializes a new account view key from an account private key.
    fn try_from(private_key: &PrivateKey<N>) -> Result<Self, Self::Error> {
        // Derive the compute key.
        let compute_key = ComputeKey::try_from(private_key)?;
        // Compute view_key := sk_sig + r_sig + sk_prf.
        Ok(Self::from_scalar(private_key.sk_sig() + private_key.r_sig() + compute_key.sk_prf()))
    }
}

#[cfg(feature = "private_key")]
impl<N: Network> TryFrom<(&PrivateKey<N>, &ComputeKey<N>)> for ViewKey<N> {
    type Error = Error;

    /// Initializes a new account view key from an account private key.
    fn try_from((private_key, compute_key): (&PrivateKey<N>, &ComputeKey<N>)) -> Result<Self, Self::Error> {
        // Compute view_key := sk_sig + r_sig + sk_prf.
        Ok(Self::from_scalar(private_key.sk_sig() + private_key.r_sig() + compute_key.sk_prf()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_try_from() -> Result<()> {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new compute key and view key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let compute_key = ComputeKey::try_from(private_key)?;
            let view_key = ViewKey::try_from(private_key)?;

            // Check that the view key matches.
            // Compute view_key := sk_sig + r_sig + sk_prf.
            let candidate = ViewKey(private_key.sk_sig() + private_key.r_sig() + compute_key.sk_prf());
            assert_eq!(view_key, candidate);

            let view_key2 = ViewKey::try_from((&private_key, &compute_key))?;
            assert_eq!(view_key2, candidate);
        }
        Ok(())
    }
}
