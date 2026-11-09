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
    /// Returns the encoded affine group element and sign, given a field element.
    pub fn encode(input: &Field<E>) -> Result<(Group<E>, bool)> {
        // Compute the encoding of the input field element.
        let (encoding, sign_high) = Self::encode_without_cofactor_clear(input)?;

        // Cofactor clear the twisted Edwards element (x, y).
        let group = encoding.mul_by_cofactor().normalized();
        let affine = group.to_affine();
        ensure!(affine.is_on_curve(), "Elligator2 failed: element is not on curve");
        // The curve order is `COFACTOR * r` with `r` prime, so clearing the cofactor of a point on the curve
        // always lands in the prime-order subgroup. Only debug builds check it
        // (see `test_encode_is_in_prime_order_subgroup`).
        debug_assert!(
            affine.is_in_correct_subgroup_assuming_on_curve(),
            "Elligator2 failed: element in incorrect subgroup"
        );

        Ok((group, sign_high))
    }

    /// Returns the encoded affine group element and sign, given a field element.
    pub(crate) fn encode_without_cofactor_clear(input: &Field<E>) -> Result<(Group<E>, bool)> {
        // A property of the curve's constants, so only debug builds check it
        // (see `test_edwards_d_is_quadratic_nonresidue`).
        debug_assert!(
            Group::<E>::EDWARDS_D.legendre().is_qnr(),
            "D on the twisted Edwards curve must be a quadratic nonresidue"
        );
        ensure!(!input.is_zero(), "Inputs to Elligator2 must be nonzero (inverses will fail)");

        let one = Field::<E>::one();

        // Store the sign of the input, to be returned with the output.
        let sign_high = input > &input.neg();

        // Compute the mapping from Fq to E(Fq) as a Montgomery element (u, v).
        let (u, v) = {
            // Compute the coefficients for the Weierstrass form: y^2 == x^3 + A * x^2 + B * x.
            let (a, b) = match Group::<E>::MONTGOMERY_B.inverse() {
                Ok(b_inverse) => (Group::MONTGOMERY_A * b_inverse, b_inverse.square()),
                Err(_) => bail!("Montgomery B must be invertible in order to use Elligator2"),
            };

            // Let (u, r) = (D, input).
            let (u, r) = (Group::EDWARDS_D, input);

            // Let ur2 = u * r^2;
            let ur2 = u * r.square();

            // Ensure A^2 * ur^2 != B(1 + ur^2)^2.
            ensure!(a.square() * ur2 != b * (one + ur2).square(), "Elligator2 failed: A^2 * ur^2 == B(1 + ur^2)^2");

            // Let v = -A / (1 + ur^2).
            let v = -a * (one + ur2).inverse().map_err(|_| anyhow!("Elligator2 failed: (1 + ur^2) == 0"))?;

            // Ensure v is nonzero.
            ensure!(!v.is_zero(), "Elligator2 failed: v == 0");

            // Let e = legendre(v^3 + Av^2 + Bv).
            let v2 = v.square();
            let e = ((v2 * v) + (a * v2) + (b * v)).legendre();

            // Ensure e is nonzero.
            ensure!(!e.is_zero(), "Elligator2 failed: e == 0");

            // Let x = ev - ((1 - e) * A/2).
            let x = match e {
                LegendreSymbol::Zero => -a * Field::<E>::half(),
                LegendreSymbol::QuadraticResidue => v,
                LegendreSymbol::QuadraticNonResidue => -v - a,
            };

            // Ensure x is nonzero.
            ensure!(!x.is_zero(), "Elligator2 failed: x == 0");

            // Let y = -e * sqrt(x^3 + Ax^2 + Bx).
            let x2 = x.square();
            let rhs = (x2 * x) + (a * x2) + (b * x);
            let value =
                rhs.even_square_root().map_err(|_| anyhow!("Elligator2 failed: even_sqrt(x^3 + Ax^2 + Bx) failed"))?;

            let y = match e {
                LegendreSymbol::Zero => Field::<E>::zero(),
                LegendreSymbol::QuadraticResidue => -value,
                LegendreSymbol::QuadraticNonResidue => value,
            };

            // Ensure y is nonzero.
            ensure!(!y.is_zero(), "Elligator2 failed: y == 0");

            // Ensure (x, y) is a valid Weierstrass element on: y^2 == x^3 + A * x^2 + B * x.
            ensure!(y.square() == rhs, "Elligator2 failed: y^2 != x^3 + A * x^2 + B * x");

            // Convert the Weierstrass element (x, y) to Montgomery element (u, v).
            let u = x * Group::MONTGOMERY_B;
            let v = y * Group::MONTGOMERY_B;

            // Ensure (u, v) is a valid Montgomery element on: B * v^2 == u^3 + A * u^2 + u
            let u2 = u.square();
            ensure!(
                Group::MONTGOMERY_B * v.square() == (u2 * u) + (Group::MONTGOMERY_A * u2) + u,
                "Elligator2 failed: B * v^2 != u^3 + A * u^2 + u"
            );

            (u, v)
        };

        // Convert the Montgomery element (u, v) to the twisted Edwards element (x, y).
        let x = u * v.inverse().map_err(|_| anyhow!("Elligator2 failed: v == 0"))?;
        let y = (u - one) * (u + one).inverse().map_err(|_| anyhow!("Elligator2 failed: (u + 1) == 0"))?;

        // Recover the point from the twisted Edwards element (x, y).
        let point = Group::from_xy_coordinates_unchecked(x, y);
        // Ensure the recovered point is on the curve.
        ensure!(point.to_affine().is_on_curve(), "Elligator2 failed: point is not on the curve");
        // Return the recovered point.
        Ok((point, sign_high))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_types::environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: usize = 1000;

    #[test]
    fn test_edwards_d_is_quadratic_nonresidue() {
        // `encode` only checks this in debug builds.
        assert!(Group::<CurrentEnvironment>::EDWARDS_D.legendre().is_qnr());
    }

    #[test]
    fn test_encode_is_in_prime_order_subgroup() -> Result<()> {
        // `encode` only checks subgroup membership in debug builds, so this also asserts it in release builds.
        let rng = &mut TestRng::default();
        for _ in 0..ITERATIONS {
            let (group, _) = Elligator2::<CurrentEnvironment>::encode(&Uniform::rand(rng))?;
            let affine = group.to_affine();
            assert!(affine.is_on_curve());
            assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        }
        Ok(())
    }
}
