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

impl<E: Environment> Distribution<Field<E>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Field<E> {
        Field::new(Uniform::rand(rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    use std::collections::HashSet;

    type CurrentEnvironment = Console;

    const ITERATIONS: usize = 100;

    #[test]
    fn test_random() {
        // Initialize a set to store all seen random elements.
        let mut set = HashSet::with_capacity(ITERATIONS);

        let mut rng = TestRng::default();

        // Note: This test technically has a `(1 + 2 + ... + ITERATIONS) / MODULUS` probability of being flaky.
        for _ in 0..ITERATIONS {
            // Sample a random value.
            let field: Field<CurrentEnvironment> = Uniform::rand(&mut rng);
            assert!(!set.contains(&field));

            // Add the new random value to the set.
            set.insert(field);
        }
    }
}
