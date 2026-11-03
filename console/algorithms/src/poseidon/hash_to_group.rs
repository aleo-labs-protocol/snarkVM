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

impl<E: Environment, const RATE: usize> HashToGroup for Poseidon<E, RATE> {
    type Input = Field<E>;
    type Output = Group<E>;

    /// Returns a group element from hashing the input.
    #[inline]
    fn hash_to_group(&self, input: &[Self::Input]) -> Result<Self::Output> {
        // Ensure that the input is not empty.
        ensure!(!input.is_empty(), "Input to hash to group cannot be empty");
        // Compute the group element as `MapToGroup(HashMany(input)[0]) + MapToGroup(HashMany(input)[1])`.
        match self.hash_many(input, 2).iter().map(Elligator2::<E>::encode_without_cofactor_clear).collect_tuple() {
            Some((Ok((h0, _)), Ok((h1, _)))) => Ok(h0.mul_by_cofactor() + h1.mul_by_cofactor()),
            _ => bail!("Poseidon failed to compute hash to group on the given input"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_types::environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1000;

    macro_rules! check_hash_to_group {
        ($poseidon:ident) => {{
            // Initialize Poseidon.
            let poseidon = $poseidon::<CurrentEnvironment>::setup("HashToGroupTest")?;

            // Ensure an empty input fails.
            assert!(poseidon.hash_to_group(&[]).is_err());

            let mut rng = TestRng::default();

            for _ in 0..ITERATIONS {
                for num_inputs in 1..8 {
                    // Sample random field elements.
                    let inputs = (0..num_inputs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>();

                    // Compute the hash to group.
                    let candidate = poseidon.hash_to_group(&inputs)?;
                    assert!((*candidate).to_affine().is_on_curve());
                    assert!((*candidate).to_affine().is_in_correct_subgroup_assuming_on_curve());
                    assert_ne!(Group::<CurrentEnvironment>::zero(), candidate);
                    assert_ne!(Group::<CurrentEnvironment>::generator(), candidate);

                    let candidate_cofactor_inv = candidate.div_by_cofactor();
                    assert_eq!(candidate, candidate_cofactor_inv.mul_by_cofactor());
                }
            }
            Ok(())
        }};
    }

    macro_rules! check_hash_to_group_matches_encode {
        ($poseidon:ident) => {{
            // Initialize Poseidon.
            let poseidon = $poseidon::<CurrentEnvironment>::setup("HashToGroupTest")?;

            let mut rng = TestRng::default();

            for _ in 0..ITERATIONS {
                for num_inputs in 1..8 {
                    // Sample random field elements.
                    let inputs = (0..num_inputs).map(|_| Uniform::rand(&mut rng)).collect::<Vec<_>>();

                    // Compute `encode(HashMany(input)[0]) + encode(HashMany(input)[1])`.
                    let hashes = poseidon.hash_many(&inputs, 2);
                    let (h0, _) = Elligator2::<CurrentEnvironment>::encode(&hashes[0])?;
                    let (h1, _) = Elligator2::<CurrentEnvironment>::encode(&hashes[1])?;

                    assert_eq!(poseidon.hash_to_group(&inputs)?, h0 + h1);
                }
            }
            Ok(())
        }};
    }

    #[test]
    fn test_poseidon2_hash_to_group() -> Result<()> {
        check_hash_to_group!(Poseidon2)
    }

    #[test]
    fn test_poseidon4_hash_to_group() -> Result<()> {
        check_hash_to_group!(Poseidon4)
    }

    #[test]
    fn test_poseidon8_hash_to_group() -> Result<()> {
        check_hash_to_group!(Poseidon8)
    }

    #[test]
    fn test_poseidon2_hash_to_group_matches_encode() -> Result<()> {
        check_hash_to_group_matches_encode!(Poseidon2)
    }

    #[test]
    fn test_poseidon4_hash_to_group_matches_encode() -> Result<()> {
        check_hash_to_group_matches_encode!(Poseidon4)
    }

    #[test]
    fn test_poseidon8_hash_to_group_matches_encode() -> Result<()> {
        check_hash_to_group_matches_encode!(Poseidon8)
    }
}
