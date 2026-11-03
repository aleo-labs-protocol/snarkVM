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

impl<E: Environment> Distribution<StringType<E>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> StringType<E> {
        // Sample a random number up to 1/4th of the maximum bytes.
        let num_bytes = rng.random_range(1..(E::MAX_STRING_BYTES / 4) as usize);
        // Sample a random string.
        StringType::new(&rng.sample_iter(&Alphanumeric).take(num_bytes).map(char::from).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    use std::collections::HashMap;

    type CurrentEnvironment = Console;

    const ITERATIONS: usize = 100;

    #[test]
    fn test_random() {
        // Initialize a map[string]=>occurrences to store all seen random elements.
        let mut map = HashMap::with_capacity(ITERATIONS);

        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random value.
            let string: StringType<CurrentEnvironment> = Uniform::rand(&mut rng);

            // Add the new random value to the set.
            map.entry(string).and_modify(|count| *count += 1).or_insert(1);
        }
        for (string, count) in map {
            let allowed_occurrences = 1 + ITERATIONS / (string.len() * 10);
            assert!(count <= allowed_occurrences, "Encountered an element with a count of {count}: {string}");
        }
    }
}
