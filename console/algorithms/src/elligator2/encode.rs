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

    /// Known-answer vectors for the current implementation, as
    /// `(input, sign_high, encode_without_cofactor_clear (x, y), encode (x, y))`.
    /// An input and its negation map to the same point with opposite signs.
    const KNOWN_ANSWERS: [(&str, bool, [&str; 2], [&str; 2]); 7] = [
        ("1field", false, ONE_UNCLEARED, ONE_ENCODED),
        ("-1field", true, ONE_UNCLEARED, ONE_ENCODED),
        ("2field", false, TWO_UNCLEARED, TWO_ENCODED),
        // (p - 1) / 2, the largest input with a low sign.
        (
            "4222230874714185212124412469390773265687949667577031913967616727958704619520field",
            false,
            HALF_UNCLEARED,
            HALF_ENCODED,
        ),
        // (p + 1) / 2, the smallest input with a high sign.
        (
            "4222230874714185212124412469390773265687949667577031913967616727958704619521field",
            true,
            HALF_UNCLEARED,
            HALF_ENCODED,
        ),
        (
            "6199665387880421202190719500997492414281196623741980396576895215768716409050field",
            true,
            [
                "2614656381146069564219764429971987907629874147823420053131295746410190545291field",
                "7770605923201681931637256908510996790852808217987890251274564360905975556332field",
            ],
            [
                "3481047323577070684909128288224709053596657151800730176128843267935908192189field",
                "374601353785978431174931485624478630806528088315095281942952052952780495867field",
            ],
        ),
        (
            "2503564330031745204948172878790002415920311580108564962928368377509658926647field",
            false,
            [
                "6570261678491278854666453741435763484082095000778606497506952200210355333710field",
                "8124137036267510859997284721576153533252229269990320535488096509221368397185field",
            ],
            [
                "430827258705824611081272160018411483419662419846871805922474265604649548598field",
                "5688599815372504533458016184878089537281734929562852759700403120511758342527field",
            ],
        ),
    ];

    const ONE_UNCLEARED: [&str; 2] = [
        "2804851425443654006319077719552675391162276496000525756282536066043948582878field",
        "5907342307010590383418942072403487908244666986928808241779432283417674045606field",
    ];
    const ONE_ENCODED: [&str; 2] = [
        "7627221839140354733956343745544226351748105647935800185264148075630363284948field",
        "129010033160355624196925663517867534105180443592116012424056376324585759811field",
    ];
    const TWO_UNCLEARED: [&str; 2] = [
        "3118606935849571841293119423457642928890269780253953541739413204165823116116field",
        "1117988272719432079481377839234226730006617733442683457378417030671512003428field",
    ];
    const TWO_ENCODED: [&str; 2] = [
        "7941703434189617095327902898199692901996971718138767769717344327865357644837field",
        "1360981434976799445256741457662742411568125607377400233769317125193242706753field",
    ];
    const HALF_UNCLEARED: [&str; 2] = [
        "3898284817480620139186733529485919578789049445523947846188507270303856979826field",
        "1882812514825141955545054011422780071953700387537634041051121832240191146008field",
    ];
    const HALF_ENCODED: [&str; 2] = [
        "6743116691783509059218107409963086050985250456455135191871845538377218801915field",
        "3511438699925827998003518730983124782728528917560381607885514489836416377854field",
    ];

    #[test]
    fn test_known_answers() -> Result<()> {
        let point = |[x, y]: [&str; 2]| -> Result<_> {
            Ok((Field::<CurrentEnvironment>::from_str(x)?, Field::<CurrentEnvironment>::from_str(y)?))
        };

        for (input, expected_sign_high, expected_uncleared, expected_encoded) in KNOWN_ANSWERS {
            let input = Field::<CurrentEnvironment>::from_str(input)?;

            let (uncleared, sign_high) = Elligator2::<CurrentEnvironment>::encode_without_cofactor_clear(&input)?;
            assert_eq!(sign_high, expected_sign_high);
            assert_eq!(uncleared.to_xy_coordinates(), point(expected_uncleared)?);

            let (encoded, sign_high) = Elligator2::<CurrentEnvironment>::encode(&input)?;
            assert_eq!(sign_high, expected_sign_high);
            assert_eq!(encoded.to_xy_coordinates(), point(expected_encoded)?);

            assert_eq!(Elligator2::<CurrentEnvironment>::decode(&uncleared, sign_high)?, input);
            assert_eq!(Elligator2::<CurrentEnvironment>::decode(&uncleared, !sign_high)?, -input);
        }
        Ok(())
    }
}
