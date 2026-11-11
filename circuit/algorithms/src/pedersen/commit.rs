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

impl<E: Environment, const NUM_BITS: u8> Commit for Pedersen<E, NUM_BITS> {
    type Input = Boolean<E>;
    type Output = Field<E>;
    type Randomizer = Scalar<E>;

    /// Returns the Pedersen commitment of the given input and randomizer as a field element.
    fn commit(&self, input: &[Self::Input], randomizer: &Self::Randomizer) -> Self::Output {
        self.commit_uncompressed(input, randomizer).to_x_coordinate()
    }
}

impl<E: Environment, const NUM_BITS: u8>
    Metrics<dyn Commit<Input = Boolean<E>, Output = Field<E>, Randomizer = Scalar<E>>> for Pedersen<E, NUM_BITS>
{
    type Case = (Vec<CircuitType<Boolean<E>>>, Vec<CircuitType<Boolean<E>>>);

    fn count(case: &Self::Case) -> Count {
        let (input, randomizer) = case;
        let uncompressed_count =
            count!(Pedersen<E, NUM_BITS>, HashUncompressed<Input = Boolean<E>, Output = Group<E>>, input);
        let uncompressed_mode =
            output_mode!(Pedersen<E, NUM_BITS>, HashUncompressed<Input = Boolean<E>, Output = Group<E>>, input);
        // The hash is a constant zero if every input bit is a constant `false`.
        let uncompressed_is_zero =
            input.iter().all(|bit| matches!(bit, CircuitType::Constant(constant) if !constant.eject_value()));

        // Compute the const of constructing the group elements.
        let group_initialize_count = randomizer
            .iter()
            .map(|bit| {
                count!(
                    Group<E>,
                    Ternary<Boolean = Boolean<E>, Output = Group<E>>,
                    &(bit.mode(), Mode::Constant, Mode::Constant)
                )
            })
            .fold(Count::zero(), |cumulative, count| cumulative + count);

        // Compute the count for converting the randomizer into bits.
        let randomizer_to_bits_count =
            match Mode::combine(randomizer[0].mode(), randomizer.iter().map(CircuitType::mode)).is_constant() {
                true => Count::is(251, 0, 0, 0),
                false => Count::is(0, 0, 501, 503),
            };

        // Determine the mode of each of the group elements, and whether it is a constant zero.
        let elements = randomizer.iter().map(|bit| match bit {
            // The `first` and `second` inputs to `Group::ternary` are a constant base and a constant zero, so a constant `false` bit
            // selects a constant zero.
            CircuitType::Constant(constant) => (Mode::Constant, !constant.eject_value()),
            _ => (Mode::Private, false),
        });

        // Calculate the cost of summing the group elements.
        let (_, summation_count) = elements.fold(
            ((uncompressed_mode, uncompressed_is_zero), Count::zero()),
            |((prev_mode, prev_is_zero), cumulative), (curr_mode, curr_is_zero)| {
                let case = (prev_mode, curr_mode, prev_is_zero, curr_is_zero);
                let mode = output_mode!(Group<E>, Add<Group<E>, Output = Group<E>>, &case);
                let sum_count = count!(Group<E>, Add<Group<E>, Output = Group<E>>, &case);
                ((mode, prev_is_zero && curr_is_zero), cumulative + sum_count)
            },
        );

        // Compute the cost of summing the hash and random elements.
        uncompressed_count + group_initialize_count + randomizer_to_bits_count + summation_count
    }
}

impl<E: Environment, const NUM_BITS: u8>
    OutputMode<dyn Commit<Input = Boolean<E>, Output = Field<E>, Randomizer = Scalar<E>>> for Pedersen<E, NUM_BITS>
{
    type Case = (Vec<CircuitType<Boolean<E>>>, Vec<CircuitType<Boolean<E>>>);

    fn output_mode(parameters: &Self::Case) -> Mode {
        let (input, randomizer) = parameters;
        match input.iter().all(|bit| bit.mode().is_constant()) && randomizer.iter().all(|bit| bit.mode().is_constant())
        {
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

    fn check_commit<const NUM_BITS: u8>(mode: Mode, rng: &mut TestRng) {
        use console::Commit as C;

        // Initialize Pedersen.
        let native = console::Pedersen::<<Circuit as Environment>::Network, NUM_BITS>::setup(MESSAGE);
        let circuit = Pedersen::<Circuit, NUM_BITS>::constant(native.clone());

        for i in 0..ITERATIONS {
            // Sample a random input.
            let input = (0..NUM_BITS).map(|_| bool::rand(rng)).collect::<Vec<bool>>();
            // Sample a randomizer.
            let randomizer = Uniform::rand(rng);
            // Compute the expected commitment.
            let expected = native.commit(&input, &randomizer).expect("Failed to commit native input");
            // Prepare the circuit input.
            let circuit_input: Vec<Boolean<_>> = Inject::new(mode, input);
            // Prepare the circuit randomizer.
            let circuit_randomizer: Scalar<_> = Inject::new(mode, randomizer);

            Circuit::scope(format!("Pedersen {mode} {i}"), || {
                // Perform the commit operation.
                let candidate = circuit.commit(&circuit_input, &circuit_randomizer);
                assert_eq!(expected, candidate.eject_value());

                // Check constraint counts and output mode.
                let input = circuit_input.iter().map(CircuitType::from).collect::<Vec<_>>();
                let randomizer = circuit_randomizer.to_bits_le().iter().map(CircuitType::from).collect::<Vec<_>>();
                assert_count!(
                    Pedersen<Circuit, NUM_BITS>,
                    Commit<Input = Boolean<Circuit>, Output = Field<Circuit>, Randomizer = Scalar<Circuit>>,
                    &(input.clone(), randomizer.clone())
                );
                assert_output_mode!(
                    Pedersen<Circuit, NUM_BITS>,
                    Commit<Input = Boolean<Circuit>, Output = Field<Circuit>, Randomizer = Scalar<Circuit>>,
                    &(input, randomizer),
                    candidate
                );
            });
        }
    }

    fn check_homomorphic_addition<
        C: Display + Eject + Add<Output = C> + ToBits<Boolean = Boolean<Circuit>>,
        P: Commit<Input = Boolean<Circuit>, Randomizer = Scalar<Circuit>, Output = Field<Circuit>>
            + CommitUncompressed<Input = Boolean<Circuit>, Randomizer = Scalar<Circuit>, Output = Group<Circuit>>,
    >(
        pedersen: &P,
        first: C,
        second: C,
        rng: &mut TestRng,
    ) {
        println!("Checking homomorphic addition on {first} + {second}");

        // Sample the circuit randomizers.
        let first_randomizer: Scalar<_> = Inject::new(Mode::Private, Uniform::rand(rng));
        let second_randomizer: Scalar<_> = Inject::new(Mode::Private, Uniform::rand(rng));

        // Compute the expected commitment, by committing them individually and summing their results.
        let a = pedersen.commit_uncompressed(&first.to_bits_le(), &first_randomizer);
        let b = pedersen.commit_uncompressed(&second.to_bits_le(), &second_randomizer);
        let expected = (a + b).to_x_coordinate();

        let combined_randomizer = first_randomizer + second_randomizer;

        // Sum the two integers, and then commit the sum.
        let candidate = pedersen.commit(&(first + second).to_bits_le(), &combined_randomizer);
        assert_eq!(expected.eject(), candidate.eject());
        assert!(Circuit::is_satisfied());
    }

    #[test]
    fn test_commit_constant() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_commit::<NUM_BITS_MULTIPLIER>(Mode::Constant, &mut rng);
        check_commit::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_commit::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_commit::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
        check_commit::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Constant, &mut rng);
    }

    #[test]
    fn test_commit_public() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_commit::<NUM_BITS_MULTIPLIER>(Mode::Public, &mut rng);
        check_commit::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_commit::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_commit::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
        check_commit::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Public, &mut rng);
    }

    #[test]
    fn test_commit_private() {
        // Set the number of windows, and modulate the window size.
        let mut rng = TestRng::default();
        check_commit::<NUM_BITS_MULTIPLIER>(Mode::Private, &mut rng);
        check_commit::<{ 2 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_commit::<{ 3 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_commit::<{ 4 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
        check_commit::<{ 5 * NUM_BITS_MULTIPLIER }>(Mode::Private, &mut rng);
    }

    #[test]
    fn test_commit_mixed() {
        use console::Commit as C;

        let mut rng = TestRng::default();
        let native = console::Pedersen::<<Circuit as Environment>::Network, NUM_BITS_MULTIPLIER>::setup(MESSAGE);
        let circuit = Pedersen::<Circuit, NUM_BITS_MULTIPLIER>::constant(native.clone());

        let modes = [Mode::Constant, Mode::Public, Mode::Private];
        for randomizer_mode in modes {
            for i in 0..ITERATIONS {
                let input = (0..NUM_BITS_MULTIPLIER).map(|_| bool::rand(&mut rng)).collect::<Vec<bool>>();
                let randomizer = Uniform::rand(&mut rng);
                let expected = native.commit(&input, &randomizer).expect("Failed to commit native input");
                let circuit_input =
                    input.into_iter().enumerate().map(|(j, bit)| Boolean::new(modes[j % 3], bit)).collect::<Vec<_>>();
                let circuit_randomizer = Scalar::new(randomizer_mode, randomizer);

                Circuit::scope(format!("Pedersen mixed {randomizer_mode} {i}"), || {
                    let candidate = circuit.commit(&circuit_input, &circuit_randomizer);
                    assert_eq!(expected, candidate.eject_value());

                    let case = (
                        circuit_input.iter().map(CircuitType::from).collect::<Vec<_>>(),
                        circuit_randomizer.to_bits_le().iter().map(CircuitType::from).collect::<Vec<_>>(),
                    );
                    assert_count!(
                        Pedersen<Circuit, NUM_BITS_MULTIPLIER>,
                        Commit<Input = Boolean<Circuit>, Output = Field<Circuit>, Randomizer = Scalar<Circuit>>,
                        &case
                    );
                    assert_output_mode!(
                        Pedersen<Circuit, NUM_BITS_MULTIPLIER>,
                        Commit<Input = Boolean<Circuit>, Output = Field<Circuit>, Randomizer = Scalar<Circuit>>,
                        &case,
                        candidate
                    );
                });
            }
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
            check_homomorphic_addition(&pedersen, first, second, &mut rng);

            // Sample two random unsigned integers, with the MSB set to 0.
            let first = U16::<Circuit>::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
            let second = U16::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
            check_homomorphic_addition(&pedersen, first, second, &mut rng);

            // Sample two random unsigned integers, with the MSB set to 0.
            let first = U32::<Circuit>::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
            let second = U32::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
            check_homomorphic_addition(&pedersen, first, second, &mut rng);

            // Sample two random unsigned integers, with the MSB set to 0.
            let first = U64::<Circuit>::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
            let second = U64::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
            check_homomorphic_addition(&pedersen, first, second, &mut rng);
        }
    }

    #[test]
    fn test_pedersen_homomorphism_private() {
        fn check_pedersen_homomorphism<
            P: Commit<Input = Boolean<Circuit>, Randomizer = Scalar<Circuit>, Output = Field<Circuit>>
                + CommitUncompressed<Input = Boolean<Circuit>, Randomizer = Scalar<Circuit>, Output = Group<Circuit>>,
        >(
            pedersen: &P,
        ) {
            let mut rng = TestRng::default();

            for _ in 0..ITERATIONS {
                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U8::<Circuit>::new(Mode::Private, console::U8::new(u8::rand(&mut rng) >> 1));
                let second = U8::new(Mode::Private, console::U8::new(u8::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second, &mut rng);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U16::<Circuit>::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
                let second = U16::new(Mode::Private, console::U16::new(u16::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second, &mut rng);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U32::<Circuit>::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
                let second = U32::new(Mode::Private, console::U32::new(u32::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second, &mut rng);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U64::<Circuit>::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
                let second = U64::new(Mode::Private, console::U64::new(u64::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second, &mut rng);

                // Sample two random unsigned integers, with the MSB set to 0.
                let first = U128::<Circuit>::new(Mode::Private, console::U128::new(u128::rand(&mut rng) >> 1));
                let second = U128::new(Mode::Private, console::U128::new(u128::rand(&mut rng) >> 1));
                check_homomorphic_addition(pedersen, first, second, &mut rng);
            }
        }

        // Check Pedersen128.
        let pedersen128 = Pedersen128::constant(console::Pedersen128::setup("Pedersen128HomomorphismTest"));
        check_pedersen_homomorphism(&pedersen128);
    }
}
