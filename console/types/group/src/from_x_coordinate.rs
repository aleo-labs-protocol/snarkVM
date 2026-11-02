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

impl<E: Environment> Group<E> {
    /// Attempts to recover an affine group element from a given x-coordinate field element.
    /// For safety, the resulting point is always enforced to be on the curve and in the correct subgroup.
    pub fn from_x_coordinate(x_coordinate: Field<E>) -> Result<Self> {
        if let Some((p1, p2)) = E::Affine::pair_from_x_coordinate(*x_coordinate) {
            // `p2 = -(p1 + T)` for the order-two point `T = (0, -1)`, and the subgroup order `r` is odd,
            // so `[r]p2` is the identity iff `p2` is in the subgroup, and is `T` iff `p1` is.
            let r_p2 = p2.mul_bits(E::Scalar::modulus().to_bits_be().into_iter());
            if r_p2.is_zero() {
                return Ok(Self::new(p2));
            }
            if E::Affine::from_coordinates_unchecked((E::Field::zero(), -E::Field::one())) == r_p2 {
                return Ok(Self::new(p1));
            }
        }
        bail!("Failed to recover an affine group from an x-coordinate of {x_coordinate}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;
    type Affine = <CurrentEnvironment as Environment>::Affine;
    type Projective = <CurrentEnvironment as Environment>::Projective;
    type BaseField = <CurrentEnvironment as Environment>::Field;

    const ITERATIONS: usize = 1000;

    /// Tries `p2`, then `p1`, each with a plain double-and-add subgroup check.
    fn reference_from_x_coordinate(x: Field<CurrentEnvironment>) -> Option<Group<CurrentEnvironment>> {
        let (p1, p2) = Affine::pair_from_x_coordinate(*x)?;
        [p2, p1]
            .into_iter()
            .find(|point| {
                let mut acc = Projective::zero();
                for bit in <CurrentEnvironment as Environment>::Scalar::modulus().to_bits_be() {
                    acc.double_in_place();
                    if bit {
                        acc.add_assign_mixed(point);
                    }
                }
                acc.is_zero()
            })
            .map(Group::new)
    }

    /// Asserts that both decoders agree on `x`, and counts the outcome as
    /// `[no y, no point in the subgroup, returned p2, returned p1]`.
    fn check(x: BaseField, outcomes: &mut [usize; 4]) {
        let x = Field::new(x);
        let expected = reference_from_x_coordinate(x);
        assert_eq!(Group::from_x_coordinate(x).ok(), expected, "x = {x}");
        let outcome = match (Affine::pair_from_x_coordinate(*x), expected) {
            (None, _) => 0,
            (Some(_), None) => 1,
            (Some((_, p2)), Some(group)) if (*group).to_affine() == p2 => 2,
            (Some(_), Some(_)) => 3,
        };
        outcomes[outcome] += 1;
    }

    #[test]
    fn test_from_x_coordinate_matches_reference() {
        let mut rng = TestRng::default();
        let mut outcomes = [0; 4];

        // -1 is a square in the base field, so (sqrt(-1), 0) exists. It has order four, and its double is (0, -1).
        let t4 = Affine::from_y_coordinate(BaseField::zero(), false).unwrap().to_projective();
        assert_eq!(t4.double(), Affine::from_coordinates_unchecked((BaseField::zero(), -BaseField::one())));

        for x in [BaseField::zero(), BaseField::one(), -BaseField::one(), t4.to_affine().x, -t4.to_affine().x] {
            check(x, &mut outcomes);
        }
        for _ in 0..ITERATIONS {
            check(Uniform::rand(&mut rng), &mut outcomes);
            let point = *Group::<CurrentEnvironment>::rand(&mut rng);
            for torsion in [Projective::zero(), t4] {
                check((point + torsion).to_affine().x, &mut outcomes);
            }
        }
        assert!(outcomes.iter().all(|count| *count > 0), "outcomes: {outcomes:?}");
    }
}
