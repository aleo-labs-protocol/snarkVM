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

impl<N: Network> TryFrom<PrivateKey<N>> for Address<N> {
    type Error = Error;

    /// Derives the account address from an account private key.
    fn try_from(private_key: PrivateKey<N>) -> Result<Self, Self::Error> {
        Self::try_from(&private_key)
    }
}

impl<N: Network> TryFrom<&PrivateKey<N>> for Address<N> {
    type Error = Error;

    /// Derives the account address from an account private key.
    fn try_from(private_key: &PrivateKey<N>) -> Result<Self, Self::Error> {
        Self::try_from(ComputeKey::try_from(private_key)?)
    }
}

impl<N: Network> TryFrom<ComputeKey<N>> for Address<N> {
    type Error = Error;

    /// Derives the account address from an account compute key.
    fn try_from(compute_key: ComputeKey<N>) -> Result<Self, Self::Error> {
        Self::try_from(&compute_key)
    }
}

impl<N: Network> TryFrom<&ComputeKey<N>> for Address<N> {
    type Error = Error;

    /// Derives the account address from an account compute key.
    fn try_from(compute_key: &ComputeKey<N>) -> Result<Self, Self::Error> {
        Ok(compute_key.to_address())
    }
}

impl<N: Network> TryFrom<ViewKey<N>> for Address<N> {
    type Error = Error;

    /// Derives the account address from an account view key.
    fn try_from(view_key: ViewKey<N>) -> Result<Self, Self::Error> {
        Self::try_from(&view_key)
    }
}

impl<N: Network> TryFrom<&ViewKey<N>> for Address<N> {
    type Error = Error;

    /// Derives the account address from an account view key.
    fn try_from(view_key: &ViewKey<N>) -> Result<Self, Self::Error> {
        Ok(view_key.to_address())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1_000;

    #[test]
    fn test_try_from() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new address.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let expected = Address::try_from(private_key)?;

            // Check the address derived from the compute key.
            let compute_key = ComputeKey::<CurrentNetwork>::try_from(private_key)?;
            assert_eq!(expected, Address::try_from(compute_key)?);

            // Check the address derived from the view key.
            let view_key = ViewKey::<CurrentNetwork>::try_from(private_key)?;
            assert_eq!(expected, Address::try_from(view_key)?);
        }
        Ok(())
    }
}
