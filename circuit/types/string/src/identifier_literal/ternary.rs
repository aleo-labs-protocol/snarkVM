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

impl<E: Environment> Ternary for IdentifierLiteral<E> {
    type Boolean = Boolean<E>;
    type Output = Self;

    /// Returns `first` if `condition` is `true`, otherwise returns `second`.
    fn ternary(condition: &Self::Boolean, first: &Self, second: &Self) -> Self::Output {
        // Both inputs are already validated identifier literals. Byte-wise selection with the same
        // condition on each byte returns either `first.bytes` or `second.bytes` in their entirety,
        // so the output is a valid identifier without revalidating.
        let bytes: [U8<E>; SIZE_IN_BYTES] =
            core::array::from_fn(|i| U8::ternary(condition, &first.bytes[i], &second.bytes[i]));
        Self { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentEnvironment = Circuit;

    const ITERATIONS: usize = 16;

    fn check_ternary(mode_condition: Mode, mode_a: Mode, mode_b: Mode) {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample two random identifier literals.
            let first = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);
            let second = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);

            for flag in [true, false] {
                let expected = if flag { first } else { second };

                let condition = Boolean::<CurrentEnvironment>::new(mode_condition, flag);
                let a = IdentifierLiteral::<CurrentEnvironment>::new(mode_a, first);
                let b = IdentifierLiteral::<CurrentEnvironment>::new(mode_b, second);

                Circuit::scope(format!("ternary {mode_condition}/{mode_a}/{mode_b} flag={flag}"), || {
                    let candidate = IdentifierLiteral::ternary(&condition, &a, &b);
                    assert_eq!(expected, candidate.eject_value());
                });
                Circuit::reset();
            }
        }
    }

    #[test]
    fn test_ternary_constant_condition_constant_inputs() {
        check_ternary(Mode::Constant, Mode::Constant, Mode::Constant);
    }

    #[test]
    fn test_ternary_constant_condition_variable_inputs() {
        check_ternary(Mode::Constant, Mode::Private, Mode::Private);
        check_ternary(Mode::Constant, Mode::Public, Mode::Private);
    }

    #[test]
    fn test_ternary_public_condition() {
        check_ternary(Mode::Public, Mode::Public, Mode::Public);
        check_ternary(Mode::Public, Mode::Private, Mode::Private);
    }

    #[test]
    fn test_ternary_private_condition() {
        check_ternary(Mode::Private, Mode::Private, Mode::Private);
        check_ternary(Mode::Private, Mode::Public, Mode::Private);
    }

    #[test]
    fn test_ternary_matches_console() {
        let mut rng = TestRng::default();
        for _ in 0..ITERATIONS {
            let first = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);
            let second = console::IdentifierLiteral::<<CurrentEnvironment as Environment>::Network>::rand(&mut rng);
            for flag in [true, false] {
                // Console ternary.
                let console_condition = console::Boolean::<<CurrentEnvironment as Environment>::Network>::new(flag);
                let expected = console::IdentifierLiteral::ternary(&console_condition, &first, &second);
                // Circuit ternary.
                let condition = Boolean::<CurrentEnvironment>::new(Mode::Private, flag);
                let a = IdentifierLiteral::<CurrentEnvironment>::new(Mode::Private, first);
                let b = IdentifierLiteral::<CurrentEnvironment>::new(Mode::Private, second);
                let candidate = IdentifierLiteral::ternary(&condition, &a, &b);
                assert_eq!(expected, candidate.eject_value());
                Circuit::reset();
            }
        }
    }
}
