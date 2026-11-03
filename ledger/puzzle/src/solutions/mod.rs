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

use crate::{Solution, SolutionID};
use console::{network::prelude::*, prelude::DeserializeExt, types::Field};
use indexmap::IndexMap;

/// The individual solutions.
#[derive(Clone, Eq, PartialEq)]
pub struct PuzzleSolutions<N: Network> {
    /// The solutions for the puzzle.
    solutions: IndexMap<SolutionID<N>, Solution<N>>,
}

impl<N: Network> PuzzleSolutions<N> {
    /// Initializes a new instance of the solutions.
    pub fn new(solutions: Vec<Solution<N>>) -> Result<Self> {
        // Ensure the solutions are not empty.
        ensure!(!solutions.is_empty(), "There are no solutions to verify for the puzzle");
        // Ensure the number of solutions does not exceed `MAX_SOLUTIONS`.
        if solutions.len() > N::MAX_SOLUTIONS {
            bail!("Exceeded the maximum number of solutions ({} > {})", solutions.len(), N::MAX_SOLUTIONS);
        }
        // Ensure the solution IDs are unique.
        if has_duplicates(solutions.iter().map(Solution::id)) {
            bail!("The solutions contain duplicate solution IDs");
        }
        // Return the solutions.
        Ok(Self { solutions: solutions.into_iter().map(|solution| (solution.id(), solution)).collect() })
    }

    /// Returns the solution IDs.
    pub fn solution_ids(&self) -> impl '_ + Iterator<Item = &SolutionID<N>> {
        self.solutions.keys()
    }

    /// Returns the number of solutions.
    pub fn len(&self) -> usize {
        self.solutions.len()
    }

    /// Returns `true` if there are no solutions.
    pub fn is_empty(&self) -> bool {
        self.solutions.is_empty()
    }

    /// Returns the solution for the given solution ID.
    pub fn get_solution(&self, solution_id: &SolutionID<N>) -> Option<&Solution<N>> {
        self.solutions.get(solution_id)
    }

    /// Returns the accumulator challenge point.
    pub fn to_accumulator_point(&self) -> Result<Field<N>> {
        // Encode the solution IDs as field elements.
        let mut preimage = self.solution_ids().map(|id| Field::from_u64(**id)).collect::<Vec<_>>();
        // Pad the preimage to the required length.
        preimage.resize(N::MAX_SOLUTIONS, Field::zero());
        // Hash the preimage to obtain the accumulator point.
        N::hash_psd8(&preimage)
    }
}

impl<N: Network> Deref for PuzzleSolutions<N> {
    type Target = IndexMap<SolutionID<N>, Solution<N>>;

    fn deref(&self) -> &Self::Target {
        &self.solutions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PartialSolution;
    use console::account::{Address, PrivateKey};

    use std::collections::HashSet;

    type CurrentNetwork = console::network::MainnetV0;

    /// Returns the solutions for the given number of solutions.
    pub(crate) fn sample_solutions_with_count(
        num_solutions: usize,
        rng: &mut TestRng,
    ) -> PuzzleSolutions<CurrentNetwork> {
        // Sample a new solutions.
        let mut solutions = vec![];
        for _ in 0..num_solutions {
            let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
            let address = Address::try_from(private_key).unwrap();

            let partial_solution = PartialSolution::new(rng.random(), address, u64::rand(rng)).unwrap();
            let solution = Solution::new(partial_solution, u64::rand(rng));
            solutions.push(solution);
        }
        PuzzleSolutions::new(solutions).unwrap()
    }

    #[test]
    fn test_new_is_not_empty() {
        // Ensure the solutions are not empty.
        assert!(PuzzleSolutions::<CurrentNetwork>::new(vec![]).is_err());
    }

    #[test]
    fn test_len() {
        let mut rng = TestRng::default();

        for num_solutions in 1..<CurrentNetwork as Network>::MAX_SOLUTIONS {
            // Sample random solutions.
            let solutions = sample_solutions_with_count(num_solutions, &mut rng);
            // Ensure the number of solutions is correct.
            assert_eq!(num_solutions, solutions.len());
        }
    }

    #[test]
    fn test_is_empty() {
        let mut rng = TestRng::default();

        for num_solutions in 1..<CurrentNetwork as Network>::MAX_SOLUTIONS {
            // Sample random solutions.
            let solutions = sample_solutions_with_count(num_solutions, &mut rng);
            // Ensure the solutions are not empty.
            assert!(!solutions.is_empty());
        }
    }

    #[test]
    fn test_solution_ids() {
        let mut rng = TestRng::default();

        for num_solutions in 1..<CurrentNetwork as Network>::MAX_SOLUTIONS {
            // Sample random solutions.
            let solutions = sample_solutions_with_count(num_solutions, &mut rng);
            // Ensure the solution IDs are unique.
            assert_eq!(num_solutions, solutions.solution_ids().collect::<HashSet<_>>().len());
        }
    }

    #[test]
    fn test_get_solution() {
        let mut rng = TestRng::default();

        for num_solutions in 1..<CurrentNetwork as Network>::MAX_SOLUTIONS {
            // Sample random solutions.
            let solutions = sample_solutions_with_count(num_solutions, &mut rng);
            // Ensure the solutions are not empty.
            for solution_id in solutions.solution_ids() {
                assert_eq!(solutions.get_solution(solution_id).unwrap().id(), *solution_id);
            }
        }
    }

    #[test]
    fn test_to_accumulator_point() {
        let mut rng = TestRng::default();

        for num_solutions in 1..<CurrentNetwork as Network>::MAX_SOLUTIONS {
            // Sample random solutions.
            let solutions = crate::solutions::tests::sample_solutions_with_count(num_solutions, &mut rng);
            // Compute the candidate accumulator point.
            let candidate = solutions.to_accumulator_point().unwrap();
            // Compute the expected accumulator point.
            let mut preimage = vec![Field::zero(); <CurrentNetwork as Network>::MAX_SOLUTIONS];
            for (i, id) in solutions.keys().enumerate() {
                preimage[i] = Field::from_u64(**id);
            }
            let expected = <CurrentNetwork as Network>::hash_psd8(&preimage).unwrap();
            assert_eq!(expected, candidate);
        }
    }
}
