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

mod bytes;
mod serialize;
mod string;
mod to_address;
mod try_from;

#[cfg(feature = "compute_key")]
use crate::ComputeKey;
#[cfg(feature = "private_key")]
use crate::PrivateKey;

use snarkvm_console_network::prelude::*;
use snarkvm_console_types::{Address, Scalar};

use zeroize::Zeroize;

/// The account view key used to decrypt records and ciphertext.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Zeroize)]
pub struct ViewKey<N: Network>(Scalar<N>);

impl<N: Network> ViewKey<N> {
    /// Initializes the account view key from a scalar.
    pub const fn from_scalar(view_key: Scalar<N>) -> Self {
        Self(view_key)
    }
}

impl<N: Network> Deref for ViewKey<N> {
    type Target = Scalar<N>;

    /// Returns the account view key as a scalar.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1000;

    #[test]
    fn test_from_scalar() -> Result<()> {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new address.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let expected = ViewKey::try_from(private_key)?;

            // Check the scalar representation.
            let candidate = *expected;
            assert_eq!(expected, ViewKey::from_scalar(candidate));
        }
        Ok(())
    }
}
