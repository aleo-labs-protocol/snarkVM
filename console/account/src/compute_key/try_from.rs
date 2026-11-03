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

#[cfg(feature = "private_key")]
impl<N: Network> TryFrom<PrivateKey<N>> for ComputeKey<N> {
    type Error = Error;

    /// Derives the account compute key from an account private key.
    fn try_from(private_key: PrivateKey<N>) -> Result<Self, Self::Error> {
        Self::try_from(&private_key)
    }
}

#[cfg(feature = "private_key")]
impl<N: Network> TryFrom<&PrivateKey<N>> for ComputeKey<N> {
    type Error = Error;

    /// Derives the account compute key from an account private key.
    fn try_from(private_key: &PrivateKey<N>) -> Result<Self, Self::Error> {
        // Compute pk_sig := G^sk_sig.
        let pk_sig = N::g_scalar_multiply(&private_key.sk_sig());
        // Compute pr_sig := G^r_sig.
        let pr_sig = N::g_scalar_multiply(&private_key.r_sig());
        // Output the compute key.
        Self::try_from((pk_sig, pr_sig))
    }
}

impl<N: Network> TryFrom<(Group<N>, Group<N>)> for ComputeKey<N> {
    type Error = Error;

    /// Derives the account compute key from a tuple `(pk_sig, pr_sig)`.
    fn try_from((pk_sig, pr_sig): (Group<N>, Group<N>)) -> Result<Self> {
        // Compute sk_prf := HashToScalar(pk_sig || pr_sig).
        let sk_prf = N::hash_to_scalar_psd4(&[pk_sig.to_x_coordinate(), pr_sig.to_x_coordinate()])?;
        // Output the compute key.
        Ok(Self { pk_sig, pr_sig, sk_prf: Some(sk_prf) })
    }
}

impl<N: Network> TryFrom<&(Group<N>, Group<N>)> for ComputeKey<N> {
    type Error = Error;

    /// Derives the account compute key from a tuple `(pk_sig, pr_sig)`.
    fn try_from((pk_sig, pr_sig): &(Group<N>, Group<N>)) -> Result<Self> {
        Self::try_from((*pk_sig, *pr_sig))
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
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new compute key.
            let private_key = PrivateKey::<CurrentNetwork>::new(&mut rng)?;
            let candidate = ComputeKey::try_from(private_key)?;

            // Check that sk_prf matches.
            // Compute sk_prf := HashToScalar(pk_sig || pr_sig).
            let candidate_sk_prf = CurrentNetwork::hash_to_scalar_psd4(&[
                candidate.pk_sig().to_x_coordinate(),
                candidate.pr_sig().to_x_coordinate(),
            ])?;
            assert_eq!(candidate.sk_prf(), candidate_sk_prf);

            // Check that compute key is derived correctly from the tuple `(pk_sig, pr_sig)`.
            assert_eq!(candidate, ComputeKey::try_from((candidate.pk_sig(), candidate.pr_sig()))?);
        }
        Ok(())
    }
}
