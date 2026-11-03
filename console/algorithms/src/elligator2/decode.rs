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

impl<E: Environment> Elligator2<E> {
    /// Returns the decoded field element, given the encoded affine group element and sign.
    pub fn decode(group: &Group<E>, sign_high: bool) -> Result<Field<E>> {
        // A property of the curve's constants, so only debug builds check it.
        debug_assert!(
            Group::<E>::EDWARDS_D.legendre().is_qnr(),
            "D on the twisted Edwards curve must be a quadratic nonresidue"
        );
        ensure!(!group.is_zero(), "Inputs to Elligator2 must be nonzero (inverses will fail)");
        ensure!((**group).to_affine().is_on_curve(), "Inputs to Elligator2 must be on the twisted Edwards curve");

        // Compute the coefficients for the Weierstrass form: v^2 == u^3 + A * u^2 + B * u.
        let (montgomery_b_inverse, a, b) = match Group::<E>::MONTGOMERY_B.inverse() {
            Ok(b_inverse) => (b_inverse, Group::MONTGOMERY_A * b_inverse, b_inverse.square()),
            Err(_) => bail!("Montgomery B must be invertible in order to use Elligator2"),
        };

        let (x, y) = group.to_xy_coordinates();

        // Ensure that x != -A.
        ensure!(x != -a, "Elligator2 failed: x == -A");

        // Ensure that if y is 0, then x is 0.
        if y.is_zero() {
            ensure!(x.is_zero(), "Elligator2 failed: y == 0 but x != 0");
        }

        // Convert the twisted Edwards element (x, y) to the Weierstrass element (u, v)
        let (u, v) = {
            let one = Field::<E>::one();

            let numerator = one + y;
            let denominator = one - y;

            // Compute u = (1 + y) / (1 - y).
            let u = numerator * denominator.inverse().map_err(|_| anyhow!("Elligator2 failed: (1 - y) == 0"))?;

            // Compute v = (1 + y) / ((1 - y) * x).
            let v =
                numerator * (denominator * x).inverse().map_err(|_| anyhow!("Elligator2 failed: x * (1 - y) == 0"))?;

            // Ensure (u, v) is a valid Montgomery element on: B * v^2 == u^3 + A * u^2 + u
            let u2 = u.square();
            ensure!(
                Group::MONTGOMERY_B * v.square() == (u2 * u) + (Group::MONTGOMERY_A * u2) + u,
                "Elligator2 failed: B * v^2 != u^3 + A * u^2 + u"
            );

            let u = u * montgomery_b_inverse;
            let v = v * montgomery_b_inverse;

            // Ensure (u, v) is a valid Weierstrass element on: v^2 == u^3 + A * u^2 + B * u
            let u2 = u.square();
            ensure!(v.square() == (u2 * u) + (a * u2) + (b * u), "Elligator2 failed: v^2 != u^3 + A * u^2 + B * u");

            (u, v)
        };

        // Ensure -D * u * (u + A) is a residue.
        let du = Group::EDWARDS_D * u;
        let u_plus_a = u + a;
        ensure!((-du * u_plus_a).legendre().is_qr(), "Elligator2 failed: -D * u * (u + A) is not a quadratic residue");

        let v_reconstructed = v
            .square()
            .even_square_root()
            .map_err(|_| anyhow!("Elligator2 failed: cannot compute the even square root for v^2"))?;
        let exists_in_sqrt_fq2 = v_reconstructed == v;

        let element = match exists_in_sqrt_fq2 {
            // Let element = sqrt(-u / ((u + A) * D)).
            true => {
                -u * (u_plus_a * Group::EDWARDS_D)
                    .inverse()
                    .map_err(|_| anyhow!("Elligator2 failed: (u+A) * D == 0"))?
            }
            // Let element = sqrt(-(u + A) / Du)).
            false => -u_plus_a * du.inverse().map_err(|_| anyhow!("Elligator2 failed: D * u == 0"))?,
        }
        .even_square_root()
        .map_err(|_| anyhow!("Elligator2 failed: cannot compute the even square root for the element"))?;

        match sign_high {
            true => Ok(cmp::max(element, -element)),
            false => Ok(cmp::min(element, -element)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_types::environment::Console;

    type CurrentEnvironment = Console;

    pub(crate) const ITERATIONS: usize = 10000;

    #[test]
    fn test_encode_and_decode() -> Result<()> {
        let rng = &mut TestRng::default();

        let mut high_ctr = 0usize;
        let mut low_ctr = 0usize;

        for _ in 0..ITERATIONS {
            let expected = Uniform::rand(rng);

            let (encoded, sign_high) = Elligator2::<CurrentEnvironment>::encode_without_cofactor_clear(&expected)?;
            let decoded = Elligator2::<CurrentEnvironment>::decode(&encoded, sign_high)?;
            assert_eq!(expected, decoded);

            match sign_high {
                true => high_ctr += 1,
                false => low_ctr += 1,
            }
        }

        println!("Sign high: {high_ctr}, sign low: {low_ctr}");
        Ok(())
    }

    #[test]
    fn test_zero_fails() {
        let encode = Elligator2::<CurrentEnvironment>::encode(&Zero::zero());
        assert!(encode.is_err());

        let decode = Elligator2::<CurrentEnvironment>::decode(&Zero::zero(), true);
        assert!(decode.is_err());
        let decode = Elligator2::<CurrentEnvironment>::decode(&Zero::zero(), false);
        assert!(decode.is_err());
    }
}
