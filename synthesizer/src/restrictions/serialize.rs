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

use snarkvm_utilities::DeserializeExt;

impl<N: Network + Serialize> Serialize for Restrictions<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Restrictions", 4)?;
        state.serialize_field("restrictions_id", &self.restrictions_id)?;
        state.serialize_field("programs", &self.programs)?;
        state.serialize_field("functions", &self.functions)?;
        state.serialize_field("arguments", &self.arguments)?;
        state.end()
    }
}

impl<'de, N: Network> Deserialize<'de> for Restrictions<N> {
    /// Deserializes the restrictions from a JSON-string.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut restrictions = serde_json::Value::deserialize(deserializer)?;

        // Recover the restrictions.
        Ok(Self {
            restrictions_id: DeserializeExt::take_from_value::<D>(&mut restrictions, "restrictions_id")?,
            programs: DeserializeExt::take_from_value::<D>(&mut restrictions, "programs")?,
            functions: DeserializeExt::take_from_value::<D>(&mut restrictions, "functions")?,
            arguments: DeserializeExt::take_from_value::<D>(&mut restrictions, "arguments")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::types::Address;

    use rand::seq::IndexedRandom;

    type CurrentNetwork = console::network::MainnetV0;

    const ITERATIONS: usize = 10;

    const TEST_PROGRAM_CASES: &[&str] = &["testing.aleo", "hello.aleo", "abc_def.aleo", "a1234.aleo"];
    const TEST_FUNCTION_CASES: &[&str] = &["testing", "transfer", "hello", "foo", "bar"];

    /// Randomly select a program ID from the given test cases.
    fn sample_program_id<R: Rng + CryptoRng>(rng: &mut R) -> ProgramID<CurrentNetwork> {
        ProgramID::from_str(TEST_PROGRAM_CASES.choose(rng).unwrap()).unwrap()
    }

    /// Randomly select a program and function name from the given test cases.
    fn sample_locator<R: Rng + CryptoRng>(rng: &mut R) -> Locator<CurrentNetwork> {
        let program_id = ProgramID::from_str(TEST_PROGRAM_CASES.choose(rng).unwrap()).unwrap();
        let function_name = Identifier::from_str(TEST_FUNCTION_CASES.choose(rng).unwrap()).unwrap();
        Locator::new(program_id, function_name)
    }

    /// Randomly sample a block range.
    fn sample_block_range<R: Rng + CryptoRng>(rng: &mut R) -> BlockRange {
        let variant = rng.random_range(0..5);
        match variant {
            0 => {
                let start = rng.random();
                let end = rng.random_range(start..=u32::MAX);
                BlockRange::Range(start..end)
            }
            1 => BlockRange::RangeFrom(rng.random()..),
            2 => BlockRange::RangeTo(..rng.random()),
            3 => {
                let start = rng.random();
                let end = rng.random_range(start..=u32::MAX);
                BlockRange::RangeInclusive(start..=end)
            }
            4 => BlockRange::FullRange,
            _ => unreachable!(),
        }
    }

    /// Randomly sample a set of restrictions.
    fn sample_restrictions<R: Rng + CryptoRng>(rng: &mut R) -> Restrictions<CurrentNetwork> {
        const NUM_RESTRICTIONS: usize = 10;

        let mut restrictions = Restrictions::<CurrentNetwork>::new_blank().unwrap();
        // Add the program restrictions.
        for _ in 0..NUM_RESTRICTIONS {
            let program_id = sample_program_id(rng);
            let range = sample_block_range(rng);
            restrictions.programs.insert(program_id, range);
        }
        // Add the function restrictions.
        for _ in 0..NUM_RESTRICTIONS {
            let locator = sample_locator(rng);
            let range = sample_block_range(rng);
            restrictions.functions.insert(locator, range);
        }
        // Add the argument restrictions.
        for _ in 0..NUM_RESTRICTIONS {
            let locator = sample_locator(rng);

            // Add the argument locators.
            let mut arguments = IndexMap::new();
            for _ in 0..NUM_RESTRICTIONS {
                let argument_locator = ArgumentLocator::new(rng.random(), rng.random_range(0..16));

                // Add the literals.
                let mut literals = IndexMap::new();
                for _ in 0..NUM_RESTRICTIONS {
                    let literal = Literal::Address(Address::rand(rng));
                    let range = sample_block_range(rng);
                    literals.insert(literal, range);
                }
                arguments.insert(argument_locator, literals);
            }
            restrictions.arguments.insert(locator, arguments);
        }
        // Set the restrictions ID.
        restrictions.restrictions_id = Restrictions::compute_restrictions_id(
            &restrictions.programs,
            &restrictions.functions,
            &restrictions.arguments,
        )
        .unwrap();
        // Return the restrictions.
        restrictions
    }

    fn check_serde_json<T: Serialize + for<'a> Deserialize<'a> + Debug + Display + PartialEq + Eq + FromStr>(
        expected: T,
    ) {
        // Serialize
        let expected_string = expected.to_string();
        let candidate_string = serde_json::to_string_pretty(&expected).unwrap();
        let candidate = serde_json::from_str::<T>(&candidate_string).unwrap();
        assert_eq!(expected, candidate);
        assert_eq!(expected_string, candidate_string);
        assert_eq!(expected_string, candidate.to_string());

        // Deserialize
        assert_eq!(expected, T::from_str(&expected_string).unwrap_or_else(|_| panic!("FromStr: {expected_string}")));
        assert_eq!(expected, serde_json::from_str(&candidate_string).unwrap());
    }

    #[test]
    fn test_serde_json() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let expected = sample_restrictions(rng);
            check_serde_json(expected);
        }
    }
}
