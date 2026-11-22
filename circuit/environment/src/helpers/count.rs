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

use core::fmt::{Debug, Display, Formatter};

pub type Constant = Measurement<u64>;
pub type Public = Measurement<u64>;
pub type Private = Measurement<u64>;
pub type Constraints = Measurement<u64>;

/// A `Measurement` is a quantity that can be measured.
/// The variants of the `Measurement` defines a condition associated with the measurable quantity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Measurement<V: Copy + Debug + Display + Ord> {
    Exact(V),
    UpperBound(V),
}

impl<V: Copy + Debug + Display + Ord> Measurement<V> {
    /// Returns `true` if the value matches the metric.
    ///
    /// For an `Exact` metric, `value` must be equal to the exact value defined by the metric.
    /// For an `UpperBound` metric, `value` must be satisfy the upper bound.
    pub fn matches(&self, candidate: V) -> bool {
        match self {
            Measurement::Exact(expected) => *expected == candidate,
            Measurement::UpperBound(bound) => candidate <= *bound,
        }
    }
}

impl<V: Copy + Debug + Display + Ord> Display for Measurement<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Measurement::Exact(value) => write!(f, "{value}"),
            Measurement::UpperBound(bound) => write!(f, "<={bound}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use snarkvm_utilities::{TestRng, Uniform};

    const ITERATIONS: u64 = 10;

    #[test]
    fn test_exact_matches() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Generate a random `Measurement` and candidate value.
            let value = u32::rand(&mut rng) as u64;
            let candidate = u32::rand(&mut rng) as u64;
            let metric = Measurement::Exact(value);

            // Check that the metric is only satisfied if the candidate is equal to the value.
            assert!(metric.matches(value));
            if candidate == value {
                assert!(metric.matches(candidate));
            } else {
                assert!(!metric.matches(candidate));
            }
        }
    }

    #[test]
    fn test_upper_matches() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Generate a random `Measurement::UpperBound` and candidate value.
            let upper = u32::rand(&mut rng) as u64;
            let candidate = u32::rand(&mut rng) as u64;
            let metric = Measurement::UpperBound(upper);

            // Check that the metric is only satisfied if the candidate is less than upper.
            assert!(metric.matches(upper));
            if candidate <= upper {
                assert!(metric.matches(candidate));
            } else {
                assert!(!metric.matches(candidate));
            }
        }
    }
}
