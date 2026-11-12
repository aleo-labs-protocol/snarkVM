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

use std::borrow::Cow;

impl<E: Environment, const NUM_BITS: u8> HashUncompressed for Pedersen<E, NUM_BITS> {
    type Input = Boolean<E>;
    type Output = Group<E>;

    /// Returns the Pedersen hash of the given input as an affine group element.
    fn hash_uncompressed(&self, input: &[Self::Input]) -> Self::Output {
        // Ensure the input is within the size bounds.
        let mut input = Cow::Borrowed(input);
        match input.len() <= NUM_BITS as usize {
            // Pad the input if it is under the required parameter size.
            true => input.to_mut().resize(NUM_BITS as usize, Boolean::constant(false)),
            // Ensure the input size is within the parameter size.
            false => E::halt(format!("The Pedersen hash input cannot exceed {NUM_BITS} bits.")),
        }

        // Compute the sum of base_i^{input_i} for all i.
        input
            .iter()
            .zip_eq(&self.base_window)
            .map(|(bit, base)| Group::ternary(bit, base, &Group::zero()))
            .fold(Group::<E>::zero(), |acc, x| acc + x)
    }
}

impl<E: Environment, const NUM_BITS: u8> Metrics<dyn HashUncompressed<Input = Boolean<E>, Output = Group<E>>>
    for Pedersen<E, NUM_BITS>
{
    /// The input bits. A constant bit set to `false` selects a constant zero element.
    type Case = Vec<CircuitType<Boolean<E>>>;

    #[inline]
    fn count(case: &Self::Case) -> Count {
        // Calculate the counts for constructing each of the individual group elements from the bits of the input.
        let group_initialization_counts = case
            .iter()
            .map(|bit| {
                count!(
                    Group<E>,
                    Ternary<Boolean = Boolean<E>, Output = Group<E>>,
                    &(bit.mode(), Mode::Constant, Mode::Constant)
                )
            })
            .fold(Count::zero(), |cumulative, count| cumulative + count);

        // Determine the mode of each of the group elements, and whether it is a constant zero.
        let mut elements = case.iter().map(|bit| match bit {
            // The `first` and `second` inputs to `Group::ternary` are a constant base and a constant zero, so a constant `false` bit
            // selects a constant zero.
            CircuitType::Constant(constant) => (Mode::Constant, !constant.eject_value()),
            _ => (Mode::Private, false),
        });

        // Calculate the cost of summing the group elements.
        let sum_counts = match elements.next() {
            Some(start) => {
                elements
                    .fold(
                        (start, Count::zero()),
                        |((prev_mode, prev_is_zero), cumulative), (curr_mode, curr_is_zero)| {
                            // The running sum is a constant zero only while every element so far is one.
                            let case = (prev_mode, curr_mode, prev_is_zero, curr_is_zero);
                            let mode = output_mode!(Group<E>, Add<Group<E>, Output = Group<E>>, &case);
                            let sum_count = count!(Group<E>, Add<Group<E>, Output = Group<E>>, &case);
                            ((mode, prev_is_zero && curr_is_zero), cumulative + sum_count)
                        },
                    )
                    .1
            }
            None => Count::zero(),
        };

        group_initialization_counts + sum_counts
    }
}

impl<E: Environment, const NUM_BITS: u8> OutputMode<dyn HashUncompressed<Input = Boolean<E>, Output = Group<E>>>
    for Pedersen<E, NUM_BITS>
{
    /// The input bits. A constant bit set to `false` selects a constant zero element.
    type Case = Vec<CircuitType<Boolean<E>>>;

    #[inline]
    fn output_mode(parameter: &Self::Case) -> Mode {
        match parameter.iter().all(|bit| bit.mode().is_constant()) {
            true => Mode::Constant,
            false => Mode::Private,
        }
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

    fn check_hash_uncompressed<const NUM_BITS: u8>(mode: Mode, rng: &mut TestRng) {
        use console::HashUncompressed as H;

        // Initialize the Pedersen hash.
        let native = console::Pedersen::<<Circuit as Environment>::Network, NUM_BITS>::setup(MESSAGE);
        let circuit = Pedersen::<Circuit, NUM_BITS>::constant(native.clone());

        for i in 0..ITERATIONS {
            // Sample a random input.
            let input = (0..NUM_BITS).map(|_| bool::rand(rng)).collect::<Vec<bool>>();
            // Compute the expected hash.
            let expected = native.hash_uncompressed(&input).expect("Failed to hash native input");
            // Prepare the circuit input.
            let circuit_input: Vec<Boolean<_>> = Inject::new(mode, input);

            Circuit::scope(format!("Pedersen {mode} {i}"), || {
                // Perform the hash operation.
                let candidate = circuit.hash_uncompressed(&circuit_input);
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

    fn check_homomorphic_addition<C: Display + Eject + Add<Output = C> + ToBits<Boolean = Boolean<Circuit>>>(
        pedersen: &impl HashUncompressed<Input = Boolean<Circuit>, Output = Group<Circuit>>,
        first: C,
        second: C,
    ) {
        println!("Checking homomorphic addition on {first} + {second}");

        // Compute the expected hash, by hashing them individually and summing their results.
        let a = pedersen.hash_uncompressed(&first.to_bits_le());
        let b = pedersen.hash_uncompressed(&second.to_bits_le());
        let expected = a + b;

        // Sum the two integers, and then hash the sum.
        let candidate = pedersen.hash_uncompressed(&(first + second).to_bits_le());
        assert_eq!(expected.eject(), candidate.eject());
        assert!(Circuit::is_satisfied());
    }

    #[test]
    fn test_hash_uncompressed_constant() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_hash_uncompressed::<NUM_BITS_MULTIPLIER>(Mode::Constant, &mut rng);
        check_hash_uncompressed::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_hash_uncompressed::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_hash_uncompressed::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_hash_uncompressed::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
    }

    #[test]
    fn test_hash_uncompressed_public() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_hash_uncompressed::<NUM_BITS_MULTIPLIER>(Mode::Public, &mut rng);
        check_hash_uncompressed::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_hash_uncompressed::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_hash_uncompressed::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_hash_uncompressed::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
    }

    #[test]
    fn test_hash_uncompressed_private() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_hash_uncompressed::<NUM_BITS_MULTIPLIER>(Mode::Private, &mut rng);
        check_hash_uncompressed::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_hash_uncompressed::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_hash_uncompressed::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_hash_uncompressed::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_hash_uncompressed_mixed() {
        use console::HashUncompressed as H;

        let mut rng = TestRng::default();
        let native = console::Pedersen::<<Circuit as Environment>::Network, NUM_BITS_MULTIPLIER>::setup(MESSAGE);
        let circuit = Pedersen::<Circuit, NUM_BITS_MULTIPLIER>::constant(native.clone());

        for i in 0..ITERATIONS {
            let input = (0..NUM_BITS_MULTIPLIER).map(|_| bool::rand(&mut rng)).collect::<Vec<bool>>();
            let expected = native.hash_uncompressed(&input).expect("Failed to hash native input");
            let modes = [Mode::Constant, Mode::Public, Mode::Private];
            let circuit_input =
                input.into_iter().enumerate().map(|(j, bit)| Boolean::new(modes[j % 3], bit)).collect::<Vec<_>>();

            Circuit::scope(format!("Pedersen mixed {i}"), || {
                let candidate = circuit.hash_uncompressed(&circuit_input);
                assert_eq!(expected, candidate.eject_value());

                let case = circuit_input.iter().map(CircuitType::from).collect::<Vec<_>>();
                assert_count!(
                    Pedersen<Circuit, NUM_BITS_MULTIPLIER>,
                    HashUncompressed<Input = Boolean<Circuit>, Output = Group<Circuit>>,
                    &case
                );
                assert_output_mode!(
                    Pedersen<Circuit, NUM_BITS_MULTIPLIER>,
                    HashUncompressed<Input = Boolean<Circuit>, Output = Group<Circuit>>,
                    &case,
                    candidate
                );
            });
        }
    }

    #[test]
    fn test_pedersen64_homomorphism_private() {
        // Initialize Pedersen64.
        let pedersen = Pedersen64::constant(console::Pedersen64::setup("Pedersen64HomomorphismTest"));

        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample two random unsigned integers, with the MSB set to 0.
            let first = U8::<Circuit>::new(Mode::Private, console::U8::new(u8::rand(&mut rng) >> 1));
            let second = U8::new(Mode::Private, console::U8::new(u8::rand(&mut rng) >> 1));
            check_homomorphic_addition(&pedersen, first, second);

            // Sample two random unsigned integers, with the MSB set to 0.
            let first = U16::<Circuit>::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
            let second = U16::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
            check_homomorphic_addition(&pedersen, first, second);

            // Sample two random unsigned integers, with the MSB set to 0.
            let first = U32::<Circuit>::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
            let second = U32::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
            check_homomorphic_addition(&pedersen, first, second);

            // Sample two random unsigned integers, with the MSB set to 0.
            let first = U64::<Circuit>::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
            let second = U64::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
            check_homomorphic_addition(&pedersen, first, second);
        }
    }

    #[test]
    fn test_pedersen_homomorphism_private() {
        fn check_pedersen_homomorphism(
            pedersen: &impl HashUncompressed<Input = Boolean<Circuit>, Output = Group<Circuit>>,
        ) {
            let mut rng = TestRng::default();

            for _ in 0..ITERATIONS {
                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U8::<Circuit>::new(Mode::Private, console::U8::new(u8::rand(&mut rng) >> 1));
                let second = U8::new(Mode::Private, console::U8::new(u8::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U16::<Circuit>::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
                let second = U16::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U32::<Circuit>::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
                let second = U32::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U64::<Circuit>::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
                let second = U64::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U128::<Circuit>::new(Mode::Private, console::U128::new(u128::rand(&mut rng) >> 1));
                let second = U128::new(Mode::Private, console::U128::new(u128::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second);
            }
        }

        // Check Pedersen128.
        let pedersen128 = Pedersen128::constant(console::Pedersen128::setup("Pedersen128HomomorphismTest"));
        check_pedersen_homomorphism(&pedersen128);
    }
}
