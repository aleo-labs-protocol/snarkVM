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

impl<E: Environment> Double for Field<E> {
    type Output = Field<E>;

    fn double(&self) -> Self::Output {
        self + self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    fn check_double(name: &str, mode: Mode, rng: &mut TestRng) {
        for _ in 0..ITERATIONS {
            // Sample a random element.
            let given = Uniform::rand(rng);
            let candidate = Field::<Circuit>::new(mode, given);

            Circuit::scope(name, || {
                let result = candidate.double();
                assert_eq!(given.double(), result.eject_value());
                assert_scope!();
            });
        }
    }

    #[test]
    fn test_double() {
        let mut rng = TestRng::default();

        check_double("Constant", Mode::Constant, &mut rng);
        check_double("Public", Mode::Public, &mut rng);
        check_double("Private", Mode::Private, &mut rng);
    }

    #[test]
    fn test_0_double() {
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();

        let candidate = Field::<Circuit>::new(Mode::Public, zero).double();
        assert_eq!(zero, candidate.eject_value());
    }

    #[test]
    fn test_1_double() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();
        let two = one + one;

        let candidate = Field::<Circuit>::new(Mode::Public, one).double();
        assert_eq!(two, candidate.eject_value());
    }
}
