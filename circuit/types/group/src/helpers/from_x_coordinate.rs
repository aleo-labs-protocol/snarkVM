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
    /// Initializes an affine group element from a given x-coordinate field element.
    /// For safety, the resulting point is always enforced to be on the curve with constraints.
    pub fn from_x_coordinate(x: Field<E>) -> Self {
        // Derive the y-coordinate.
        let y = witness!(|x| match console::Group::from_x_coordinate(x) {
            Ok(point) => point.to_y_coordinate(),
            Err(_) => console::Field::zero(),
        });

        Self::from_xy_coordinates(x, y)
    }

    /// Initializes an affine group element from a given x-coordinate field element.
    /// Additionally, returns an error flag.
    /// If the error flag is set, there is **no** group element with the given x-coordinate.
    /// If the error flag is set, the returned point is `(0, 0)`.
    pub fn from_x_coordinate_flagged(x: Field<E>) -> (Self, Boolean<E>) {
        // Obtain the A and D coefficients of the elliptic curve.
        let a = Field::constant(console::Field::new(E::EDWARDS_A));
        let d = Field::constant(console::Field::new(E::EDWARDS_D));

        // Compute x^2.
        let xx = &x * &x;

        // Compute a * x^2 - 1.
        let a_xx_minus_1 = a * &xx - Field::one();

        // Compute d * x^2 - 1.
        let d_xx_minus_1 = d * &xx - Field::one();

        // Compute y^2 = (a * x^2 - 1) / (d * x^2 - 1), i.e. solve the curve equation for y^2.
        let yy: Field<E> = witness!(|a_xx_minus_1, d_xx_minus_1| { a_xx_minus_1 / d_xx_minus_1 });
        E::enforce(|| (&yy, &d_xx_minus_1, &a_xx_minus_1)).expect("Group from_x_coordinate y^2 constraint unsatisfied");

        // Compute both square roots of y^2, with a flag indicating whether y^2 is a square or not.
        // Note that there is **no** ordering on the square roots in the circuit computation.
        // Note that if the x-coordinate line does not intersect the elliptic curve, this returns (0, 0, true).
        let (y1, y2, yy_is_not_square) = yy.square_roots_flagged_nondeterministic();

        // Construct the two points.
        // Note that if `yy_is_not_square` is `false`, the points are guaranteed to be on the curve.
        // Note that the two points are **not** necessarily in the subgroup.
        let point1 = Self { x: x.clone(), y: y1.clone() };
        let point2 = Self { x: x.clone(), y: y2.clone() };

        // Determine if either of the two points is in the subgroup.
        // Note that at most **one** of the points can be in the subgroup.
        let point1_is_in_group = point1.is_in_group();
        let point2_is_in_group = point2.is_in_group();

        // Select y1 if (x, y1) is in the subgroup.
        // Otherwise, select y2 if (x, y2) is in the subgroup.
        // Otherwise, use the zero field element.
        let y2_or_zero = Field::ternary(&point2_is_in_group, &y2, &Field::zero());
        let y1_or_y2_or_zero = Field::ternary(&point1_is_in_group, &y1, &y2_or_zero);
        let y = Field::ternary(&yy_is_not_square, &Field::zero(), &y1_or_y2_or_zero);

        // The error flag is set iff x does not intersect the elliptic curve or neither intersection point is in the subgroup.
        let neither_in_subgroup = point1_is_in_group.not().bitand(point2_is_in_group.not());
        let error_flag = yy_is_not_square.bitor(&neither_in_subgroup);

        (Self { x, y }, error_flag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;
    use snarkvm_utilities::try_vm_runtime;

    use core::str::FromStr;

    const ITERATIONS: u64 = 10;

    /// Values of `x` with no group element, where synthesizing `Group::from_x_coordinate` panics.
    ///
    /// A rejected `x` gets the off-curve witness `(x, 0)`, and `enforce_in_group` divides it by the cofactor. On these
    /// values, the additions and doublings of that scalar multiplication reach `Z = 0`, and the conversion to affine
    /// panics. Deployment verification rejects a program that synthesizes such a value, so this list is consensus
    /// behavior. It depends on the exact sequence of operations in `Affine::mul_bits`.
    /// This list is not complete. See https://gist.github.com/cbeck88/e3c1de2c277754330e3d9d7702d1c54f for the search that found these values.
    const PANICKING_X: [&str; 8] = [
        "796759711718485194403126097657075135760429205353416317620271785354282588780",
        "1646887550125418539688483748007992615780454861634823357515367456465219956426",
        "3191513760873258386957126988742004355611086354488696025237095095423557019205",
        "3731578311095584543118774412074246841508098021618500437186623585706364357852",
        "4712883438332785881130050526707299689867801313535563390748609870211044881189",
        "5252947988555112037291697950039542175764812980665367802698138360493852219836",
        "6797574199302951884560341190773553915595444473519240470419865999452189282615",
        "7647702037709885229845698841124471395615470129800647510314961670563126650261",
    ];

    /// Values of `x` with no group element, where synthesizing `Group::from_x_coordinate` does not panic.
    /// A `mul_bits` with a different sequence of operations can panic on these values. The 4-bit sliding window of
    /// #3644 panics on 14 of them, including `993836843171880604782108004137850162404213406205532410908816984011375463874`.
    const NON_PANICKING_X: [&str; 34] = [
        "326388504612651405530442693138611165507040138194223459045676289122298132443",
        "691769809417834627886074228954081133072504848955644007490490573902669790128",
        "894024122588081933162013164463240380723086743145725170988669962210234028625",
        "920260061556636250077122174351962699029177925231276869362581798979738908320",
        "993836843171880604782108004137850162404213406205532410908816984011375463874",
        "1099404816875239244755211204519496798688468523421073887296750614246871521831",
        "1189726838290002595315280755289655649555592078913195292402895637041627734457",
        "1971098395194888988445701753474052279256675531124723409967840471748370136249",
        "2623170080518631255628812199824246444494916268929246901657564264103010252129",
        "2625342301233593868235457462670090813401823690762055991546889516775703965432",
        "2824240598588596099942891267864540616560035368170348884850989002960136163497",
        "3476600679654463942410406509009995646943828640051410470613823395833820467364",
        "3564855117016366438386603277642426329669749855622646795862550096230785530439",
        "3637270322189267934533227681487675661571501320626739402956556048564800615331",
        "3749941068530464699296117102880452817088443445822974503831371446190224410286",
        "3922567627264247540549817064383924549165731638379379606494165166415702058276",
        "4053670307688197006846272699522489892155887372362521134142863737805411405290",
        "4390791441740173417402552239259056639220011962791542693792369718111997833751",
        "4521894122164122883699007874397621982210167696774684221441068289501707180765",
        "4694520680897905724952707835901093714287455889331089324103862009727184828755",
        "4807191427239102489715597257293870869804398014527324424978677407352608623710",
        "4879606632412003985862221661139120201706149479531417032072683359686623708602",
        "4967861069773906481838418429771550884432070695102653357321410060083588771677",
        "5620221150839774324305933670917005914815863966983714943084244452957273075544",
        "5819119448194776556013367476111455717974075644392007836388343939141705273609",
        "5821291668909739168620012738957300086880983066224816926277669191814398986912",
        "6473363354233481435803123185307494252119223804029340417967392984169039102792",
        "7254734911138367828933544183491890881820307256240868535532337818875781504584",
        "7345056932553131179493613734262049732687430811732989940638482841670537717210",
        "7450624906256489819466716934643696368971685928948531417026416471906033775167",
        "7524201687871734174171702764429583832346721409922786958572651656937670330721",
        "7550437626840288491086811774318306150652812592008338656946563493707175210416",
        "7752691940010535796362750709827465398303394486198419820444742882014739448913",
        "8118073244815719018718382245642935365868859196959840368889557166795111106598",
    ];

    /// The values from `PANICKING_X` and `NON_PANICKING_X` where synthesizing `Group::from_x_coordinate_flagged` panics.
    ///
    /// A value with no square root gets the off-curve point `(x, 0)`, and `is_in_group` multiplies it by the subgroup
    /// order. On these values, the witness of the circuit `Group::double` divides by zero. This path does not use
    /// `Affine::mul_bits`. The values were not searched for this path, so this list covers only those two lists.
    const FLAGGED_PANICKING_X: [&str; 8] = [
        "326388504612651405530442693138611165507040138194223459045676289122298132443",
        "796759711718485194403126097657075135760429205353416317620271785354282588780",
        "3191513760873258386957126988742004355611086354488696025237095095423557019205",
        "3731578311095584543118774412074246841508098021618500437186623585706364357852",
        "4712883438332785881130050526707299689867801313535563390748609870211044881189",
        "5252947988555112037291697950039542175764812980665367802698138360493852219836",
        "7647702037709885229845698841124471395615470129800647510314961670563126650261",
        "8118073244815719018718382245642935365868859196959840368889557166795111106598",
    ];

    fn check_from_x_coordinate(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random element.
            let point: console::Group<<Circuit as Environment>::Network> = Uniform::rand(&mut rng);

            // Inject the x-coordinate.
            let x_coordinate = Field::new(mode, point.to_x_coordinate());

            Circuit::scope(format!("{mode} {i}"), || {
                let affine = Group::<Circuit>::from_x_coordinate(x_coordinate);
                assert_eq!(point, affine.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    fn check_from_x_coordinate_flagged(
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        let mut rng = TestRng::default();

        for i in 0..ITERATIONS {
            // Sample a random x coordinate.
            let x: console::Field<<Circuit as Environment>::Network> = Uniform::rand(&mut rng);
            // Compute error flag and point in console-land.
            let (expected_error_flag, expected_point) = match console::Group::from_x_coordinate(x) {
                Ok(point) => (false, point),
                Err(_) => (true, console::Group::from_xy_coordinates_unchecked(x, console::Field::zero())),
            };
            // Compute error flag and point in circuit-land.
            let input = Field::<Circuit>::new(mode, x);
            Circuit::scope(format!("{mode} {i}"), || {
                let (candidate_point, candidate_error_flag) = Group::from_x_coordinate_flagged(input);
                assert_eq!(expected_error_flag, candidate_error_flag.eject_value());
                assert_eq!(expected_point, candidate_point.eject_value());
                assert_scope!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    #[test]
    fn test_from_x_coordinate_flagged_off_curve_witness_panics() {
        for x in PANICKING_X.iter().chain(&NON_PANICKING_X) {
            let panics = FLAGGED_PANICKING_X.contains(x);
            let x = console::Field::from_str(&format!("{x}field")).unwrap();

            let result = try_vm_runtime(|| Group::<Circuit>::from_x_coordinate_flagged(Field::new(Mode::Private, x)));
            assert_eq!(result.is_err(), panics, "x = {x}");
            Circuit::reset();
        }
    }

    /// Programs inject public and private inputs as `Mode::Private`. A constant input halts on all of these values.
    #[test]
    fn test_from_x_coordinate_off_curve_witness_panics() {
        for (values, panics) in [(PANICKING_X.as_slice(), true), (NON_PANICKING_X.as_slice(), false)] {
            for x in values {
                let x = console::Field::from_str(&format!("{x}field")).unwrap();
                assert!(console::Group::<<Circuit as Environment>::Network>::from_x_coordinate(x).is_err());

                let result = try_vm_runtime(|| Group::<Circuit>::from_x_coordinate(Field::new(Mode::Private, x)));
                assert_eq!(result.is_err(), panics, "x = {x}");
                // A proof cannot use the off-curve witness.
                assert!(panics || !Circuit::is_satisfied(), "x = {x}");
                Circuit::reset();
            }
        }
    }

    #[test]
    fn test_from_x_coordinate_constant() {
        check_from_x_coordinate(Mode::Constant, 9, 0, 0, 0);
    }

    #[test]
    fn test_from_x_coordinate_public() {
        check_from_x_coordinate(Mode::Public, 4, 0, 13, 13);
    }

    #[test]
    fn test_from_x_coordinate_private() {
        check_from_x_coordinate(Mode::Private, 4, 0, 13, 13);
    }

    #[test]
    fn test_from_x_coordinate_flagged_constant() {
        check_from_x_coordinate_flagged(Mode::Constant, 3764, 0, 0, 0);
    }

    #[test]
    fn test_from_x_coordinate_flagged_public() {
        check_from_x_coordinate_flagged(Mode::Public, 1756, 0, 5861, 5861);
    }

    #[test]
    fn test_from_x_coordinate_flagged_private() {
        check_from_x_coordinate_flagged(Mode::Private, 1756, 0, 5861, 5861);
    }
}
