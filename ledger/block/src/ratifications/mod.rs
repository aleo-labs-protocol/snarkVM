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
mod merkle;
mod serialize;
mod string;

use crate::Ratify;
use console::{
    network::prelude::*,
    program::{RATIFICATIONS_DEPTH, RatificationsPath, RatificationsTree},
    types::Field,
};

use indexmap::IndexMap;

use rayon::prelude::*;

#[derive(Clone, PartialEq, Eq)]
pub struct Ratifications<N: Network> {
    /// The ratifications included in a block.
    ratifications: IndexMap<N::RatificationID, Ratify<N>>,
}

impl<N: Network> Ratifications<N> {
    /// Initializes from an iterator of ratifications.
    pub fn try_from_iter<T: IntoIterator<Item = Ratify<N>>>(iter: T) -> Result<Self> {
        Ok(Self {
            ratifications: iter
                .into_iter()
                .map(|ratification| Ok::<_, Error>((ratification.to_id()?, ratification)))
                .collect::<Result<IndexMap<_, _>, _>>()?,
        })
    }
}

impl<N: Network> TryFrom<Vec<Ratify<N>>> for Ratifications<N> {
    type Error = Error;

    /// Initializes from a given ratifications list.
    fn try_from(ratifications: Vec<Ratify<N>>) -> Result<Self> {
        Self::try_from_iter(ratifications)
    }
}

impl<N: Network> TryFrom<&Vec<Ratify<N>>> for Ratifications<N> {
    type Error = Error;

    /// Initializes from a given ratifications list.
    fn try_from(ratifications: &Vec<Ratify<N>>) -> Result<Self> {
        Self::try_from(ratifications.as_slice())
    }
}

impl<N: Network> TryFrom<&[Ratify<N>]> for Ratifications<N> {
    type Error = Error;

    /// Initializes from a given ratifications list.
    fn try_from(ratifications: &[Ratify<N>]) -> Result<Self> {
        Self::try_from(ratifications.to_vec())
    }
}

impl<N: Network> Ratifications<N> {
    /// Returns `true` if the ratifications contains the given commitment.
    pub fn contains(&self, ratification_id: &N::RatificationID) -> bool {
        self.ratifications.contains_key(ratification_id)
    }

    /// Returns the ratification for the given ratification ID.
    pub fn get(&self, ratification_id: &N::RatificationID) -> Option<&Ratify<N>> {
        self.ratifications.get(ratification_id)
    }

    /// Returns 'true' if there are no ratifications.
    pub fn is_empty(&self) -> bool {
        self.ratifications.is_empty()
    }

    /// Returns the number of ratifications.
    pub fn len(&self) -> usize {
        self.ratifications.len()
    }
}

impl<N: Network> Ratifications<N> {
    /// The maximum number of ratifications allowed in a block.
    pub const MAX_RATIFICATIONS: usize = usize::pow(2, RATIFICATIONS_DEPTH as u32);

    /// Returns an iterator over all ratifications, for all ratifications in `self`.
    pub fn iter(&self) -> impl '_ + ExactSizeIterator<Item = &Ratify<N>> {
        self.ratifications.values()
    }

    /// Returns a parallel iterator over all ratifications, for all ratifications in `self`.
    pub fn par_iter(&self) -> impl '_ + ParallelIterator<Item = &Ratify<N>> {
        self.ratifications.par_values()
    }

    /// Returns an iterator over the ratification IDs, for all ratifications in `self`.
    pub fn ratification_ids(&self) -> impl '_ + ExactSizeIterator<Item = &N::RatificationID> {
        self.ratifications.keys()
    }
}

impl<N: Network> IntoIterator for Ratifications<N> {
    type IntoIter = indexmap::map::IntoValues<N::RatificationID, Self::Item>;
    type Item = Ratify<N>;

    /// Returns a consuming iterator over all ratifications, for all ratifications in `self`.
    fn into_iter(self) -> Self::IntoIter {
        self.ratifications.into_values()
    }
}

impl<N: Network> Ratifications<N> {
    /// Returns a consuming iterator over the ratification IDs, for all ratifications in `self`.
    pub fn into_ratification_ids(self) -> impl ExactSizeIterator<Item = N::RatificationID> {
        self.ratifications.into_keys()
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    /// Samples a block ratifications.
    pub(crate) fn sample_block_ratifications(rng: &mut TestRng) -> Ratifications<CurrentNetwork> {
        Ratifications::try_from(crate::ratify::test_helpers::sample_ratifications(rng)).unwrap()
    }
}
