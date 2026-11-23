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

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> HashUncompressed
    for BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE>
{
    type Input = Boolean<E>;
    type Output = Group<E>;

    /// Returns the BHP hash of the given input as an affine group element.
    ///
    /// This uncompressed variant of the BHP hash function is provided to support
    /// the BHP commitment scheme, as it is typically not used by applications.
    fn hash_uncompressed(&self, input: &[Self::Input]) -> Self::Output {
        self.hash_uncompressed_inner(input, true)
    }
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE> {
    /// Returns the uncompressed BHP hash, computing each `lambda` and Edwards coordinate with its own inversion unless
    /// `batch_inversions`.
    fn hash_uncompressed_inner(&self, input: &[Boolean<E>], batch_inversions: bool) -> Group<E> {
        // Ensure the input size is at least the window size.
        if input.len() <= Self::MIN_BITS {
            E::halt(format!("Inputs to this BHP must be greater than {} bits", Self::MIN_BITS))
        }

        // Ensure the input size is within the parameter size.
        let input = match input.len() <= Self::MAX_BITS {
            true => {
                // Pad the input to a multiple of `BHP_CHUNK_SIZE` for hashing.
                if !input.len().is_multiple_of(BHP_CHUNK_SIZE) {
                    // Compute the number of padding bits.
                    let padding = BHP_CHUNK_SIZE - (input.len() % BHP_CHUNK_SIZE);
                    // Pad the input with `false` bits.
                    let mut padded_input = Vec::with_capacity(input.len() + padding);
                    padded_input.extend_from_slice(input);
                    padded_input.resize(input.len() + padding, Boolean::constant(false));
                    // Ensure the input is a multiple of `BHP_CHUNK_SIZE`.
                    assert_eq!(padded_input.len() % BHP_CHUNK_SIZE, 0, "Input must be a multiple of {BHP_CHUNK_SIZE}");
                    // Return the padded input.
                    Cow::Owned(padded_input)
                } else {
                    // Return the input as a borrowed slice.
                    Cow::Borrowed(input)
                }
            }
            false => E::halt(format!("Inputs to this BHP cannot exceed {} bits", Self::MAX_BITS)),
        };

        // Declare the 1 constant field element.
        let one = Field::one();
        // Declare the 1/2 constant field element.
        let one_half = Field::constant(console::Field::<E::Network>::half());

        // Declare the constant coefficients A and B for the Montgomery curve.
        let coeff_a = Field::constant(console::Group::<E::Network>::MONTGOMERY_A);
        let coeff_b = Field::constant(console::Group::<E::Network>::MONTGOMERY_B);

        // `batched_witnesses` runs outside `witness!`, so a mode that skips witness logic must skip it too.
        let (mut lambdas, mut edwards) = match batch_inversions.then(|| self.batched_witnesses(&input)).flatten() {
            Some((lambdas, edwards)) => (Some(lambdas.into_iter().flatten()), Some(edwards.into_iter())),
            None => (None, None),
        };

        // Incomplete addition of two Montgomery points. The denominator is `that_x - this_x`.
        // Setup accepts only non-identity bases, and only a window whose absolute sum is below the group order.
        // Those checks keep every pair of summands in a window at distinct x-coordinates.
        let montgomery_add = |(this_x, this_y): (&Field<E>, &Field<E>),
                              (that_x, that_y): (&Field<E>, &Field<E>),
                              precomputed: Option<console::Field<E::Network>>| {
            // Construct `lambda` as a witness defined as:
            // `lambda := (that_y - this_y) / (that_x - this_x)`
            let lambda: Field<E> = match precomputed {
                Some(lambda) => E::new_witness(witness_mode!(this_x, this_y, that_x, that_y), || lambda),
                None => witness!(|this_x, this_y, that_x, that_y| (that_y - this_y) / (that_x - this_x)),
            };

            // Ensure `lambda` is correct by enforcing:
            // `(that_x - this_x) * lambda == (that_y - this_y)`
            E::enforce(|| (that_x - this_x, &lambda, that_y - this_y)).expect("BHP lambda constraint unsatisfied");

            // Construct `sum_x` as a witness defined as:
            // `sum_x := (B * lambda^2) - A - this_x - that_x`
            let sum_x: Field<E> = witness!(|lambda, that_x, this_x, coeff_a, coeff_b| {
                coeff_b * lambda.square() - coeff_a - this_x - that_x
            });

            // Ensure `sum_x` is correct by enforcing:
            // `(B * lambda) * lambda == (A + this_x + that_x + sum_x)`
            E::enforce(|| (&coeff_b * &lambda, &lambda, &coeff_a + this_x + that_x + &sum_x))
                .expect("BHP sum_x constraint unsatisfied");

            // Construct `sum_y` as a witness defined as:
            // `sum_y := -(this_y + (lambda * (this_x - sum_x)))`
            let sum_y: Field<E> = witness!(|lambda, sum_x, this_x, this_y| -(this_y + (lambda * (sum_x - this_x))));

            // Ensure `sum_y` is correct by enforcing:
            // `(this_x - sum_x) * lambda == (this_y + sum_y)`
            E::enforce(|| (this_x - &sum_x, &lambda, this_y + &sum_y)).expect("BHP sum_y constraint unsatisfied");

            (sum_x, sum_y)
        };

        // Matches `Field::div_unchecked`, taking the quotient from `precomputed` when both operands are variables.
        let div_unchecked = |numerator: &Field<E>,
                             denominator: &Field<E>,
                             precomputed: Option<console::Field<E::Network>>| {
            match precomputed {
                Some(quotient) if !numerator.is_constant() && !denominator.is_constant() => {
                    let quotient: Field<E> = E::new_witness(Mode::Private, || quotient);
                    E::enforce(|| (&quotient, denominator, numerator)).expect("Field division constraint unsatisfied");
                    quotient
                }
                _ => numerator.div_unchecked(denominator),
            }
        };

        // Compute sum of h_i^{sum of (1-2*c_{i,j,2})*(1+c_{i,j,0}+2*c_{i,j,1})*2^{4*(j-1)} for all j in segment}
        // for all i. Described in section 5.4.1.7 in the Zcash protocol specification.
        //
        // Note: `.zip()` is used here (as opposed to `.zip_eq()`) as the input can be less than
        // `NUM_WINDOWS * WINDOW_SIZE * BHP_CHUNK_SIZE` in length, which is the parameter size here.
        input
            .chunks(WINDOW_SIZE as usize * BHP_CHUNK_SIZE)
            .zip(self.bases.iter())
            .map(|(bits, bases)| {
                // Initialize accumulating sum variables for the x- and y-coordinates.
                let mut sum = None;

                // One iteration costs 5 constraints.
                bits.chunks(BHP_CHUNK_SIZE).zip(bases).for_each(|(chunk_bits, base_lookups)| {
                    // Unzip the base lookups into `x_bases` and `y_bases`.
                    let (x_bases, y_bases) = base_lookups;

                    // Cast each input chunk bit as a field element.
                    let bit_0 = Field::from_boolean(&chunk_bits[0]);
                    let bit_1 = Field::from_boolean(&chunk_bits[1]);
                    let bit_2 = Field::from_boolean(&chunk_bits[2]);
                    let bit_0_and_1 = Field::from_boolean(&(&chunk_bits[0] & &chunk_bits[1])); // 1 constraint

                    // Compute the x-coordinate of the Montgomery curve point.
                    let montgomery_x: Field<E> = &x_bases[0]
                        + &bit_0 * (&x_bases[1] - &x_bases[0])
                        + &bit_1 * (&x_bases[2] - &x_bases[0])
                        + &bit_0_and_1 * (&x_bases[3] - &x_bases[2] - &x_bases[1] + &x_bases[0]);

                    // Compute the y-coordinate of the Montgomery curve point.
                    let montgomery_y = {
                        // Compute the y-coordinate of the Montgomery curve point, without any negation.
                        let y: Field<E> = &y_bases[0]
                            + bit_0 * (&y_bases[1] - &y_bases[0])
                            + bit_1 * (&y_bases[2] - &y_bases[0])
                            + bit_0_and_1 * (&y_bases[3] - &y_bases[2] - &y_bases[1] + &y_bases[0]);

                        // Determine the correct sign of the y-coordinate, as a witness.
                        //
                        // Instead of using `Field::ternary`, we create a witness & custom constraint to reduce
                        // the number of nonzero entries in the circuit, improving setup & proving time for Varuna.
                        let montgomery_y: Field<E> = witness!(|chunk_bits, y| if chunk_bits[2] { -y } else { y });

                        // Ensure the conditional negation of `witness_y` is correct as follows (1 constraint):
                        //     `(bit_2 - 1/2) * (-2 * y) == montgomery_y`
                        // which is equivalent to:
                        //     if `bit_2 == 0`, then `montgomery_y = -1/2 * -2 * y = y`
                        //     if `bit_2 == 1`, then `montgomery_y = 1/2 * -2 * y = -y`
                        E::enforce(|| (-y.double(), bit_2 - &one_half, &montgomery_y))
                            .expect("BHP montgomery_y constraint unsatisfied"); // 1 constraint

                        montgomery_y
                    };

                    // Update the accumulating sum, with a constraint-saving technique as follows:
                    match &sum {
                        // If `(sum_x, sum_y)` is `None`, then this is the first iteration,
                        // and we can save constraints by initializing `(sum_x, sum_y)` as
                        // `(montgomery_x, montgomery_y)` (instead of calling `montgomery_add`).
                        None => sum = Some((montgomery_x, montgomery_y)),
                        // Otherwise, call `montgomery_add` to add  to the accumulating sum.
                        Some((sum_x, sum_y)) => {
                            // Sum the new Montgomery point into the accumulating sum.
                            let precomputed = lambdas.as_mut().and_then(Iterator::next);
                            sum = Some(montgomery_add((sum_x, sum_y), (&montgomery_x, &montgomery_y), precomputed));
                            // 3 constraints
                        }
                    }
                });

                // Convert the accumulating sum into the twisted Edwards point.
                match &sum {
                    Some((sum_x, sum_y)) => {
                        // Convert the accumulated sum into a point on the twisted Edwards curve.
                        let (x, y) = edwards.as_mut().and_then(Iterator::next).unzip();
                        let edwards_x = div_unchecked(sum_x, sum_y, x); // 1 constraint (`sum_y` is never 0)
                        let edwards_y = div_unchecked(&(sum_x - &one), &(sum_x + &one), y); // 1 constraint (numerator & denominator are never both 0)
                        Group::from_xy_coordinates_unchecked(edwards_x, edwards_y)
                        // 0 constraints (this is safe)
                    }
                    None => E::halt("Invalid iteration of BHP detected, a window was not evaluated"),
                }
            })
            .fold(Group::zero(), |acc, group| acc + group) // 6 constraints
    }

    /// Returns each window's Montgomery `lambda`s and twisted Edwards coordinates, with one inversion per step and one
    /// for the conversion, or `None` if a denominator is zero.
    #[allow(clippy::type_complexity)]
    fn batched_witnesses(
        &self,
        input: &[Boolean<E>],
    ) -> Option<(Vec<Vec<console::Field<E::Network>>>, Vec<(console::Field<E::Network>, console::Field<E::Network>)>)>
    {
        let one = console::Field::<E::Network>::one();
        let coeff_a = console::Group::<E::Network>::MONTGOMERY_A;
        let coeff_b = console::Group::<E::Network>::MONTGOMERY_B;
        let points: Vec<Vec<_>> = input
            .chunks(WINDOW_SIZE as usize * BHP_CHUNK_SIZE)
            .zip(self.bases.iter())
            .map(|(bits, bases)| {
                bits.chunks(BHP_CHUNK_SIZE)
                    .zip(bases)
                    .map(|(chunk, (x_bases, y_bases))| {
                        let index = chunk[0].eject_value() as usize + 2 * chunk[1].eject_value() as usize;
                        let y = y_bases[index].eject_value();
                        (x_bases[index].eject_value(), if chunk[2].eject_value() { -y } else { y })
                    })
                    .collect()
            })
            .collect();
        let mut sums: Vec<_> = points.iter().map(|p| p[0]).collect();
        let mut lambdas: Vec<Vec<_>> = points.iter().map(|p| Vec::with_capacity(p.len())).collect();
        let steps = points.iter().map(|p| p.len()).max().unwrap_or(0);
        let mut denominators = Vec::with_capacity(2 * points.len());
        let mut prefixes = Vec::with_capacity(2 * points.len());
        for step in 1..steps {
            let active = || points.iter().enumerate().filter(|(_, p)| step < p.len());
            denominators.clear();
            denominators.extend(active().map(|(w, p)| p[step].0 - sums[w].0));
            Self::batch_invert(&mut denominators, &mut prefixes)?;
            for ((w, p), d_inv) in active().zip_eq(&denominators) {
                let (that_x, that_y) = p[step];
                let (this_x, this_y) = sums[w];
                let lambda = (that_y - this_y) * d_inv;
                let sum_x = coeff_b * lambda.square() - coeff_a - this_x - that_x;
                let sum_y = -(this_y + (lambda * (sum_x - this_x)));
                sums[w] = (sum_x, sum_y);
                lambdas[w].push(lambda);
            }
        }
        denominators.clear();
        denominators.extend(sums.iter().flat_map(|(x, y)| [*y, *x + one]));
        Self::batch_invert(&mut denominators, &mut prefixes)?;
        let edwards =
            sums.iter().zip_eq(denominators.chunks_exact(2)).map(|((x, _), inv)| (*x * inv[0], (*x - one) * inv[1]));
        Some((lambdas, edwards.collect()))
    }

    /// Inverts every element in place with one shared inversion, or returns `None` if any element is zero.
    /// `prefixes` is scratch space, reused across calls.
    fn batch_invert(
        values: &mut [console::Field<E::Network>],
        prefixes: &mut Vec<console::Field<E::Network>>,
    ) -> Option<()> {
        prefixes.clear();
        let mut acc = console::Field::<E::Network>::one();
        for value in values.iter() {
            prefixes.push(acc);
            acc *= value;
        }
        let mut inv = acc.inverse().ok()?;
        for (value, prefix) in values.iter_mut().rev().zip_eq(prefixes.iter().rev()) {
            let value_inv = inv * prefix;
            inv *= *value;
            *value = value_inv;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::Rng;
    use snarkvm_circuit_types::environment::Circuit;
    use snarkvm_curves::{AffineCurve, ProjectiveCurve};
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    const ITERATIONS: usize = 10;
    const MESSAGE: &str = "BHPCircuit0";

    fn check_hash_uncompressed<const NUM_WINDOWS: u8, const WINDOW_SIZE: u8>(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) -> Result<()> {
        use console::HashUncompressed as H;

        // Initialize the native BHP hasher.
        let native =
            console::bhp::hasher::BHPHasher::<<Circuit as Environment>::Network, NUM_WINDOWS, WINDOW_SIZE>::setup(
                MESSAGE,
            )?;

        // Initialize the circuit BHP hasher.
        let primitive = console::BHP::<<Circuit as Environment>::Network, NUM_WINDOWS, WINDOW_SIZE>::setup(MESSAGE)?;
        let circuit = BHPHasher::<Circuit, NUM_WINDOWS, WINDOW_SIZE>::new(Mode::Constant, primitive);
        // Determine the number of inputs.
        let num_input_bits = NUM_WINDOWS as usize * WINDOW_SIZE as usize * BHP_CHUNK_SIZE;

        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random input.
            let input = (0..num_input_bits).map(|_| bool::rand(&mut rng)).collect::<Vec<bool>>();
            // Compute the expected hash.
            let expected = native.hash_uncompressed(&input).expect("Failed to hash native input");
            // Prepare the circuit input.
            let circuit_input: Vec<Boolean<_>> = Inject::new(mode, input);

            Circuit::scope(format!("BHP {mode} {i}"), || {
                // Perform the hash operation.
                let candidate = circuit.hash_uncompressed(&circuit_input);
                assert_scope!(num_constants, num_public, num_private, num_constraints);
                assert_eq!(expected, candidate.eject_value());
                assert!(candidate.eject_value().to_affine().is_on_curve());
                assert!(candidate.eject_value().to_affine().is_in_correct_subgroup_assuming_on_curve());
            });
        }
        Ok(())
    }

    #[test]
    fn test_hash_uncompressed_constant() -> Result<()> {
        check_hash_uncompressed::<32, 48>(Mode::Constant, 6239, 0, 0, 0)
    }

    #[test]
    fn test_hash_uncompressed_public() -> Result<()> {
        check_hash_uncompressed::<32, 48>(Mode::Public, 65, 0, 7834, 7834)
    }

    #[test]
    fn test_hash_uncompressed_private() -> Result<()> {
        check_hash_uncompressed::<32, 48>(Mode::Private, 65, 0, 7834, 7834)
    }

    fn inject(input: &[bool], mode: &dyn Fn(usize) -> Mode) -> Vec<Boolean<Circuit>> {
        input.iter().enumerate().map(|(i, bit)| Boolean::new(mode(i), *bit)).collect()
    }

    fn synthesize<const NUM_WINDOWS: u8, const WINDOW_SIZE: u8>(
        circuit: &BHPHasher<Circuit, NUM_WINDOWS, WINDOW_SIZE>,
        input: &[bool],
        mode: &dyn Fn(usize) -> Mode,
        batch_inversions: bool,
    ) -> String {
        Circuit::reset();
        let output = circuit.hash_uncompressed_inner(&inject(input, mode), batch_inversions).eject_value();
        let num_constants = Circuit::num_constants();
        format!("{output} {num_constants} {:?}", Circuit::eject_assignment_and_reset())
    }

    fn check_batched_witnesses<const NUM_WINDOWS: u8, const WINDOW_SIZE: u8>() -> Result<()> {
        type Hasher<const N: u8, const W: u8> = BHPHasher<Circuit, N, W>;
        let primitive = console::BHP::<<Circuit as Environment>::Network, NUM_WINDOWS, WINDOW_SIZE>::setup(MESSAGE)?;
        let circuit = Hasher::<NUM_WINDOWS, WINDOW_SIZE>::new(Mode::Constant, primitive);
        let (min, max) = (Hasher::<NUM_WINDOWS, WINDOW_SIZE>::MIN_BITS, Hasher::<NUM_WINDOWS, WINDOW_SIZE>::MAX_BITS);
        let mut rng = TestRng::default();
        let mut lengths = vec![max, max - 1, max - 2, min + 1, min + BHP_CHUNK_SIZE + 1];
        lengths.extend((0..ITERATIONS).map(|_| rng.random_range(min + 1..=max)));
        let modes: [&dyn Fn(usize) -> Mode; 5] = [
            &|_| Mode::Constant,
            &|_| Mode::Public,
            &|_| Mode::Private,
            &|i| [Mode::Constant, Mode::Public, Mode::Private][(i + i / 7) % 3],
            &|i| if i < min { Mode::Constant } else { Mode::Private },
        ];
        for (m, mode) in modes.iter().enumerate() {
            for &length in &lengths {
                let input = (0..length).map(|_| bool::rand(&mut rng)).collect::<Vec<bool>>();
                let mut padded = inject(&input, mode);
                padded.resize(length.next_multiple_of(BHP_CHUNK_SIZE), Boolean::constant(false));
                assert!(circuit.batched_witnesses(&padded).is_some());
                let expected = synthesize(&circuit, &input, mode, false);
                assert_eq!(expected, synthesize(&circuit, &input, mode, true), "modes {m}, length {length}");
            }
        }
        Ok(())
    }

    #[test]
    fn test_batched_witnesses_match_unbatched() -> Result<()> {
        check_batched_witnesses::<32, 48>()?;
        check_batched_witnesses::<3, 57>()?;
        check_batched_witnesses::<6, 43>()?;
        check_batched_witnesses::<15, 23>()?;
        check_batched_witnesses::<8, 54>()
    }

    #[test]
    fn test_batched_witnesses_zero_lambda_denominator() -> Result<()> {
        let primitive = console::BHP::<<Circuit as Environment>::Network, 6, 43>::setup(MESSAGE)?;
        let circuit = BHPHasher::<Circuit, 6, 43>::new(Mode::Constant, primitive);
        let mut bases = circuit.bases().clone();
        // Step 1 of window 2 reuses step 0's bases, so equal chunks add `P + P` and a flipped sign bit adds `P + (-P)`.
        bases[2][1] = bases[2][0].clone();
        let forged = BHPHasher::<Circuit, 6, 43> { bases, random_base: circuit.random_base().clone() };
        let mut rng = TestRng::default();
        for negate in [false, true] {
            for mode in [Mode::Constant, Mode::Private] {
                let mut input = (0..6 * 43 * BHP_CHUNK_SIZE).map(|_| bool::rand(&mut rng)).collect::<Vec<bool>>();
                let step_0 = 2 * 43 * BHP_CHUNK_SIZE;
                input.copy_within(step_0..step_0 + BHP_CHUNK_SIZE, step_0 + BHP_CHUNK_SIZE);
                input[step_0 + 5] ^= negate;
                assert!(forged.batched_witnesses(&inject(&input, &|_| mode)).is_none());
                let outcomes = [false, true].map(|batch_inversions| {
                    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        synthesize(&forged, &input, &|_| mode, batch_inversions)
                    }))
                    .expect_err("a zero denominator must halt");
                    let message = error.downcast_ref::<String>().cloned().unwrap_or_default();
                    let counts = (
                        Circuit::num_constants(),
                        Circuit::num_public(),
                        Circuit::num_private(),
                        Circuit::num_constraints(),
                    );
                    Circuit::reset();
                    (message, counts)
                });
                assert!(outcomes[0].0.starts_with("Field division by zero"), "{}", outcomes[0].0);
                assert_eq!(outcomes[0], outcomes[1], "negate {negate}, mode {mode}");
            }
        }
        Ok(())
    }

    #[test]
    fn test_batched_witnesses_zero_edwards_denominator() -> Result<()> {
        let primitive = console::BHP::<<Circuit as Environment>::Network, 6, 43>::setup(MESSAGE)?;
        let circuit = BHPHasher::<Circuit, 6, 43>::new(Mode::Constant, primitive);
        let mut bases = circuit.bases().clone();
        // The last window holds one chunk, so its sum is that chunk's base, here forged to `y = 0`.
        bases[5][0].1 = vec![Field::zero(); 4];
        let forged = BHPHasher::<Circuit, 6, 43> { bases, random_base: circuit.random_base().clone() };
        let mut rng = TestRng::default();
        for mode in [Mode::Constant, Mode::Private] {
            let input = (0..(5 * 43 + 1) * BHP_CHUNK_SIZE).map(|_| bool::rand(&mut rng)).collect::<Vec<bool>>();
            assert!(forged.batched_witnesses(&inject(&input, &|_| mode)).is_none());
            let outcomes = [false, true].map(|batch_inversions| {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    synthesize(&forged, &input, &|_| mode, batch_inversions)
                }))
                .map_err(|error| error.downcast_ref::<String>().cloned().unwrap_or_default());
                Circuit::reset();
                outcome
            });
            assert_eq!(outcomes[0], outcomes[1], "mode {mode}");
        }
        Ok(())
    }
}
