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
mod parse;
mod serialize;
mod to_address;
mod to_bits;
mod to_fields;

use crate::Identifier;
use snarkvm_console_network::prelude::*;
use snarkvm_console_types::{Address, Boolean, Field};

/// Returns `true` if the string consists of lowercase alphanumeric characters.
fn is_lowercase_alphanumeric(s: &str) -> bool {
    s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='z' | '_'))
}

/// A program ID is of the form `{name}.{network}`.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct ProgramID<N: Network> {
    /// The program name.
    name: Identifier<N>,
    /// The network-level domain (NLD).
    network: Identifier<N>,
}

impl<N: Network> From<&ProgramID<N>> for ProgramID<N> {
    /// Returns a copy of the program ID.
    fn from(program_id: &ProgramID<N>) -> Self {
        *program_id
    }
}

impl<N: Network> TryFrom<(Identifier<N>, Identifier<N>)> for ProgramID<N> {
    type Error = Error;

    /// Initializes a program ID from a name and network-level domain identifier.
    fn try_from((name, network): (Identifier<N>, Identifier<N>)) -> Result<Self> {
        // Ensure the name is lowercase alphabets and numbers.
        ensure!(is_lowercase_alphanumeric(&name.to_string()), "Program name is invalid: {name}");
        // Construct the program ID.
        let id = Self { name, network };
        // Ensure the program network-level domain is `aleo`.
        ensure!(id.is_aleo(), "Program network is invalid: {network}");
        // Return the program ID.
        Ok(id)
    }
}

impl<N: Network> TryFrom<String> for ProgramID<N> {
    type Error = Error;

    /// Initializes a program ID from a name and network-level domain identifier.
    fn try_from(program_id: String) -> Result<Self> {
        Self::from_str(&program_id)
    }
}

impl<N: Network> TryFrom<&String> for ProgramID<N> {
    type Error = Error;

    /// Initializes a program ID from a name and network-level domain identifier.
    fn try_from(program_id: &String) -> Result<Self> {
        Self::from_str(program_id)
    }
}

impl<N: Network> TryFrom<&str> for ProgramID<N> {
    type Error = Error;

    /// Initializes a program ID from a name and network-level domain identifier.
    fn try_from(program_id: &str) -> Result<Self> {
        // Split the program ID into a name and network-level domain.
        let mut split = program_id.split('.');
        // Parse the name and network.
        if let (Some(name), Some(network), None) = (split.next(), split.next(), split.next()) {
            // Ensure the name is lowercase alphabets and numbers.
            ensure!(is_lowercase_alphanumeric(name), "Program name is invalid: {name}");
            // Construct the program ID.
            Self::try_from((Identifier::from_str(name)?, Identifier::from_str(network)?))
        } else {
            bail!("Invalid program ID '{program_id}'")
        }
    }
}

impl<N: Network> ProgramID<N> {
    /// Returns the program name.
    #[inline]
    pub const fn name(&self) -> &Identifier<N> {
        &self.name
    }

    /// Returns the network-level domain (NLD).
    #[inline]
    pub const fn network(&self) -> &Identifier<N> {
        &self.network
    }

    /// Returns `true` if the network-level domain is `aleo`.
    #[inline]
    pub fn is_aleo(&self) -> bool {
        self.network() == &Identifier::from_str("aleo").expect("Failed to parse Aleo domain")
    }

    /// Returns the `credits.aleo` program ID.
    pub fn credits() -> Self {
        Self::from_str("credits.aleo").expect("Failed to parse credits.aleo as a program ID")
    }
}

impl<N: Network> Ord for ProgramID<N> {
    /// Ordering is determined by the network first, then the program name second.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.network == other.network {
            true => self.name.to_string().cmp(&other.name.to_string()),
            false => self.network.to_string().cmp(&other.network.to_string()),
        }
    }
}

impl<N: Network> PartialOrd for ProgramID<N> {
    /// Ordering is determined by the network first, then the program name second.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<N: Network> Equal<Self> for ProgramID<N> {
    type Output = Boolean<N>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        Boolean::new(self == other)
    }

    /// Returns `true` if `self` and `other` are **not** equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        Boolean::new(self != other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_partial_ord() -> Result<()> {
        let import1 = ProgramID::<CurrentNetwork>::from_str("bar.aleo")?;
        let import2 = ProgramID::<CurrentNetwork>::from_str("foo.aleo")?;

        let import3 = ProgramID::<CurrentNetwork>::from_str("bar.aleo")?;
        let import4 = ProgramID::<CurrentNetwork>::from_str("foo.aleo")?;

        assert_eq!(import1.partial_cmp(&import1), Some(Ordering::Equal));
        assert_eq!(import1.partial_cmp(&import2), Some(Ordering::Less));
        assert_eq!(import1.partial_cmp(&import3), Some(Ordering::Equal));
        assert_eq!(import1.partial_cmp(&import4), Some(Ordering::Less));

        assert_eq!(import2.partial_cmp(&import1), Some(Ordering::Greater));
        assert_eq!(import2.partial_cmp(&import2), Some(Ordering::Equal));
        assert_eq!(import2.partial_cmp(&import3), Some(Ordering::Greater));
        assert_eq!(import2.partial_cmp(&import4), Some(Ordering::Equal));

        assert_eq!(import3.partial_cmp(&import1), Some(Ordering::Equal));
        assert_eq!(import3.partial_cmp(&import2), Some(Ordering::Less));
        assert_eq!(import3.partial_cmp(&import3), Some(Ordering::Equal));
        assert_eq!(import3.partial_cmp(&import4), Some(Ordering::Less));

        assert_eq!(import4.partial_cmp(&import1), Some(Ordering::Greater));
        assert_eq!(import4.partial_cmp(&import2), Some(Ordering::Equal));
        assert_eq!(import4.partial_cmp(&import3), Some(Ordering::Greater));
        assert_eq!(import4.partial_cmp(&import4), Some(Ordering::Equal));

        Ok(())
    }
}
