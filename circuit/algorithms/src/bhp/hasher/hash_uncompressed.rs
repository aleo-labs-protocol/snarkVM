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
        // Ensure the input size is at least the window size.
        if input.len() <= Self::MIN_BITS {
            E::halt(format!("Inputs to this BHP must be greater than {} bits", Self::MIN_BITS))
        }

        // Ensure the input size is within the parameter size.
        let input = match input.len() <= Self::MAX_BITS {
            true => {
                // Pad the input to a multiple of `BHP_CHUNK_SIZE` for hashing.
                if input.len() % BHP_CHUNK_SIZE != 0 {
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

        // Incomplete addition of two Montgomery points. The denominator is `that_x - this_x`.
        // Setup accepts only non-identity bases, and only a window whose absolute sum is below the group order.
        // Those checks keep every pair of summands in a window at distinct x-coordinates.
        let montgomery_add = |(this_x, this_y): (&Field<E>, &Field<E>), (that_x, that_y): (&Field<E>, &Field<E>)| {
            // Construct `lambda` as a witness defined as:
            // `lambda := (that_y - this_y) / (that_x - this_x)`
            let lambda: Field<E> = witness!(|this_x, this_y, that_x, that_y| (that_y - this_y) / (that_x - this_x));

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
                            sum = Some(montgomery_add((sum_x, sum_y), (&montgomery_x, &montgomery_y)));
                            // 3 constraints
                        }
                    }
                });

                // Convert the accumulating sum into the twisted Edwards point.
                match &sum {
                    Some((sum_x, sum_y)) => {
                        // Convert the accumulated sum into a point on the twisted Edwards curve.
                        let edwards_x = sum_x.div_unchecked(sum_y); // 1 constraint (`sum_y` is never 0)
                        let edwards_y = (sum_x - &one).div_unchecked(&(sum_x + &one)); // 1 constraint (numerator & denominator are never both 0)
                        Group::from_xy_coordinates_unchecked(edwards_x, edwards_y)
                        // 0 constraints (this is safe)
                    }
                    None => E::halt("Invalid iteration of BHP detected, a window was not evaluated"),
                }
            })
            .fold(Group::zero(), |acc, group| acc + group) // 6 constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
