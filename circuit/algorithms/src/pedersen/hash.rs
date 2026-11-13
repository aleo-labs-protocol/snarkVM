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

impl<E: Environment, const NUM_BITS: u8> Hash for Pedersen<E, NUM_BITS> {
    type Input = Boolean<E>;
    type Output = Field<E>;

    /// Returns the Pedersen hash of the given input as a field element.
    fn hash(&self, input: &[Self::Input]) -> Self::Output {
        // Compute the Pedersen hash as an affine group element, and return the x-coordinate.
        self.hash_uncompressed(input).to_x_coordinate()
    }
}

impl<E: Environment, const NUM_BITS: u8> Metrics<dyn Hash<Input = Boolean<E>, Output = Field<E>>>
    for Pedersen<E, NUM_BITS>
{
    /// The input bits. A constant bit set to `false` selects a constant zero element.
    type Case = Vec<CircuitType<Boolean<E>>>;

    #[inline]
    fn count(case: &Self::Case) -> Count {
        count!(Pedersen<E, NUM_BITS>, HashUncompressed<Input = Boolean<E>, Output = Group<E>>, case)
    }
}

impl<E: Environment, const NUM_BITS: u8> OutputMode<dyn Hash<Input = Boolean<E>, Output = Field<E>>>
    for Pedersen<E, NUM_BITS>
{
    /// The input bits. A constant bit set to `false` selects a constant zero element.
    type Case = Vec<CircuitType<Boolean<E>>>;

    #[inline]
    fn output_mode(parameter: &Self::Case) -> Mode {
        output_mode!(Pedersen<E, NUM_BITS>, HashUncompressed<Input = Boolean<E>, Output = Group<E>>, parameter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_types::environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    const ITERATIONS: u64 = 10;
    const MESSAGE: &str = "PedersenCircuit0";
    const NUM_BITS_MULTIPLIER: u8 = 8;

    fn check_hash<const NUM_BITS: u8>(mode: Mode, rng: &mut TestRng) {
        use console::Hash as H;

        // Initialize the Pedersen hash.
        let native = console::Pedersen::<<Circuit as Environment>::Network, NUM_BITS>::setup(MESSAGE);
        let circuit = Pedersen::<Circuit, NUM_BITS>::constant(native.clone());

        for i in 0..ITERATIONS {
            // Sample a random input.
            let input = (0..NUM_BITS).map(|_| bool::rand(rng)).collect::<Vec<bool>>();
            // Compute the expected hash.
            let expected = native.hash(&input).expect("Failed to hash native input");
            // Prepare the circuit input.
            let circuit_input: Vec<Boolean<_>> = Inject::new(mode, input);

            Circuit::scope(format!("Pedersen {mode} {i}"), || {
                // Perform the hash operation.
                let candidate = circuit.hash(&circuit_input);
                assert_eq!(expected, candidate.eject_value());

                // Check constraint counts and output mode.
                let case = circuit_input.iter().map(CircuitType::from).collect::<Vec<_>>();
                assert_count!(
                    Pedersen<Circuit, NUM_BITS>,
                    HashUncompressed<Input = Boolean<Circuit>, Output = Group<Circuit>>,
                    &case
                );
                assert_output_mode!(
                    Pedersen<Circuit, NUM_BITS>,
                    HashUncompressed<Input = Boolean<Circuit>, Output = Group<Circuit>>,
                    &case,
                    candidate
                );
            });
        }
    }

    #[test]
    fn test_hash_constant() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_hash::<NUM_BITS_MULTIPLIER>(Mode::Constant, &mut rng);
        check_hash::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_hash::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_hash::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_hash::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
    }

    #[test]
    fn test_hash_public() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_hash::<NUM_BITS_MULTIPLIER>(Mode::Public, &mut rng);
        check_hash::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_hash::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_hash::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_hash::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
    }

    #[test]
    fn test_hash_private() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_hash::<NUM_BITS_MULTIPLIER>(Mode::Private, &mut rng);
        check_hash::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_hash::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_hash::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_hash::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
    }
}
