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

impl<E: Environment> Distribution<IdentifierLiteral<E>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> IdentifierLiteral<E> {
        // Sample a random length between 1 and the maximum bytes.
        let num_bytes = rng.random_range(1..=SIZE_IN_BYTES);
        // Generate a random string: first character is alphabetic, rest are alphanumeric or underscore.
        let first_char = if rng.random_bool(0.5) {
            // Uppercase letter.
            char::from(b'A' + rng.random_range(0..26))
        } else {
            // Lowercase letter.
            char::from(b'a' + rng.random_range(0..26))
        };
        let rest: String = (0..num_bytes - 1)
            .map(|_| {
                // Choose from [a-zA-Z0-9_].
                let idx = rng.random_range(0..63);
                // Safety: idx is in range 0..63, so conversion to u8 always succeeds.
                match idx {
                    0..26 => char::from(b'a' + u8::try_from(idx).unwrap()),
                    26..52 => char::from(b'A' + u8::try_from(idx - 26).unwrap()),
                    52..62 => char::from(b'0' + u8::try_from(idx - 52).unwrap()),
                    _ => '_',
                }
            })
            .collect();
        let string = format!("{first_char}{rest}");
        // This is safe because we constructed a valid identifier string.
        IdentifierLiteral::new(&string).expect("Failed to generate random identifier literal")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    use std::collections::HashSet;

    type CurrentEnvironment = Console;

    const ITERATIONS: usize = 1000;

    #[test]
    fn test_random() {
        let mut rng = TestRng::default();
        let mut seen = HashSet::new();

        for _ in 0..ITERATIONS {
            let literal: IdentifierLiteral<CurrentEnvironment> = Uniform::rand(&mut rng);
            // Ensure the literal parses back correctly.
            let display = literal.to_string();
            let recovered = IdentifierLiteral::<CurrentEnvironment>::from_str(&display).unwrap();
            assert_eq!(literal, recovered);
            // Track uniqueness.
            seen.insert(display);
        }
        // Ensure reasonable diversity.
        assert!(seen.len() > ITERATIONS / 2);
    }
}
