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

use crate::{
    AffineCurve,
    templates::{
        bls12::{
            g1::{G1Affine, G1Prepared, G1Projective},
            g2::{G2Affine, G2Prepared, G2Projective},
        },
        short_weierstrass_jacobian,
    },
    traits::{ModelParameters, PairingCurve, PairingEngine, ShortWeierstrassParameters},
};
use snarkvm_fields::{
    Field,
    Fp2,
    Fp2Parameters,
    Fp12,
    Fp12Parameters,
    One,
    PrimeField,
    SquareRootField,
    Zero,
    fp6_3over2::Fp6Parameters,
};
use snarkvm_utilities::bititerator::BitIteratorBE;

use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use serde::{Deserialize, Serialize};

pub enum TwistType {
    M,
    D,
}

/// This trait is sealed. Only snarkVM implements it.
pub trait Bls12Parameters:
    crate::sealed::Sealed + 'static + Copy + Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Sized
{
    const X: &'static [u64];
    const X_IS_NEGATIVE: bool;
    const TWIST_TYPE: TwistType;
    type Fp: PrimeField + SquareRootField + Into<<Self::Fp as PrimeField>::BigInteger>;
    type Fp2Params: Fp2Parameters<Fp = Self::Fp>;
    type Fp6Params: Fp6Parameters<Fp2Params = Self::Fp2Params>;
    type Fp12Params: Fp12Parameters<Fp6Params = Self::Fp6Params>;
    type G1Parameters: ShortWeierstrassParameters<BaseField = Self::Fp>;
    type G2Parameters: ShortWeierstrassParameters<
            BaseField = Fp2<Self::Fp2Params>,
            ScalarField = <Self::G1Parameters as ModelParameters>::ScalarField,
        >;

    fn g1_is_in_correct_subgroup(p: &short_weierstrass_jacobian::Affine<Self::G1Parameters>) -> bool {
        p.mul_bits(BitIteratorBE::new(<Self::G1Parameters as ModelParameters>::ScalarField::characteristic())).is_zero()
    }

    fn g2_is_in_correct_subgroup(p: &short_weierstrass_jacobian::Affine<Self::G1Parameters>) -> bool {
        p.mul_bits(BitIteratorBE::new(<Self::G1Parameters as ModelParameters>::ScalarField::characteristic())).is_zero()
    }

    /// Returns the value of the loop of `miller_loop` over `pairs`, before its final conjugation.
    #[doc(hidden)]
    fn miller_loop_fp12(pairs: &[(&G1Prepared<Self>, &G2Prepared<Self>)]) -> Fp12<Self::Fp12Params> {
        Bls12::<Self>::miller_loop_scalar(pairs)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Bls12<P: Bls12Parameters>(PhantomData<P>);

type CoeffPair<T> = (Fp2<T>, Fp2<T>);

impl<P: Bls12Parameters> Bls12<P> {
    /// Returns `[x / y, 1 / y]` for each pair when every `y` is nonzero, or `None` if any `y` is zero.
    pub(crate) fn g1_d_scales(pairs: &[(&G1Prepared<P>, &G2Prepared<P>)]) -> Option<Vec<[P::Fp; 2]>> {
        let n = pairs.len();
        if n == 0 {
            return Some(Vec::new());
        }
        if pairs.iter().any(|(p, _)| p.0.y.is_zero()) {
            return None;
        }
        if n == 1 {
            // `pairs[0].0.0.y` is nonzero, so it has an inverse.
            let y_inv = pairs[0].0.0.y.inverse().unwrap();
            return Some(vec![[pairs[0].0.0.x * y_inv, y_inv]]);
        }
        let mut prefixes = Vec::with_capacity(n);
        let mut acc = P::Fp::one();
        for (p, _) in pairs {
            prefixes.push(acc);
            acc *= p.0.y;
        }
        // Every `p.0.y` is nonzero, so their product `acc` is nonzero.
        let mut inv = acc.inverse().unwrap();
        let mut scales = vec![[P::Fp::zero(); 2]; n];
        for ((scale, (p, _)), prefix) in scales.iter_mut().zip(pairs.iter()).zip(prefixes.iter()).rev() {
            let y_inv = inv * prefix;
            inv *= p.0.y;
            *scale = [p.0.x * y_inv, y_inv];
        }
        Some(scales)
    }

    /// Evaluates the D-twist affine line `1 + (c1 * x / y) * w + (c2 / y) * w^3`.
    #[inline]
    fn ell_d(f: &mut Fp12<P::Fp12Params>, coeffs: &CoeffPair<P::Fp2Params>, [x_over_y, y_inv]: &[P::Fp; 2]) {
        let mut c3 = coeffs.0;
        let mut c4 = coeffs.1;
        c3.mul_by_fp(x_over_y);
        c4.mul_by_fp(y_inv);
        f.mul_by_34(&c3, &c4);
    }

    /// Evaluates a D-twist line when `p` may have `y == 0` (outside the prime-order subgroup).
    #[inline]
    fn ell_d_general(f: &mut Fp12<P::Fp12Params>, coeffs: &CoeffPair<P::Fp2Params>, p: &G1Affine<P>) {
        if let Some(y_inv) = p.y.inverse() {
            Self::ell_d(f, coeffs, &[p.x * y_inv, y_inv]);
        } else {
            let mut c3 = coeffs.0;
            c3.mul_by_fp(&p.x);
            f.mul_by_034(&Fp2::zero(), &c3, &coeffs.1);
        }
    }

    /// Evaluates the M-twist affine line `(1 + c1 * x * v) + (c2 * y * v) * w`.
    #[inline]
    fn ell_m(f: &mut Fp12<P::Fp12Params>, coeffs: &CoeffPair<P::Fp2Params>, p: &G1Affine<P>) {
        let mut c1 = coeffs.0;
        let mut c4 = coeffs.1;
        c1.mul_by_fp(&p.x);
        c4.mul_by_fp(&p.y);
        f.mul_by_14(&c1, &c4);
    }

    /// Returns the value of the loop of `miller_loop` over `pairs`, before its final conjugation, by
    /// the scalar path, without `Bls12Parameters::miller_loop_fp12`.
    #[doc(hidden)]
    pub fn miller_loop_scalar(pairs: &[(&G1Prepared<P>, &G2Prepared<P>)]) -> Fp12<P::Fp12Params> {
        #[inline]
        fn run_loop<P: Bls12Parameters, T>(
            mut items: Vec<(T, core::slice::Iter<'_, CoeffPair<P::Fp2Params>>)>,
            mut step: impl FnMut(&mut Fp12<P::Fp12Params>, &CoeffPair<P::Fp2Params>, &T),
        ) -> Fp12<P::Fp12Params> {
            let mut f = Fp12::one();

            // `prepare` gives a G2 point one line for each step of this loop. A `G2Prepared` with
            // fewer lines panics at its `unwrap`.
            for i in BitIteratorBE::new(P::X).skip(1) {
                f.square_in_place();

                for (item, coeffs) in &mut items {
                    // `prepare` supplies one doubling line for each bit of `P::X` after the top bit.
                    step(&mut f, coeffs.next().unwrap(), item);
                }

                if i {
                    for (item, coeffs) in &mut items {
                        // `prepare` supplies one addition line for each set bit of `P::X` after the top bit.
                        step(&mut f, coeffs.next().unwrap(), item);
                    }
                }
            }

            f
        }

        match P::TWIST_TYPE {
            TwistType::D => {
                if let Some(scales) = Self::g1_d_scales(pairs) {
                    let items =
                        scales.into_iter().zip(pairs).map(|(scale, (_, q))| (scale, q.ell_coeffs.iter())).collect();
                    run_loop::<P, _>(items, Self::ell_d)
                } else {
                    let items = pairs.iter().map(|(p, q)| (p.0, q.ell_coeffs.iter())).collect();
                    run_loop::<P, _>(items, Self::ell_d_general)
                }
            }
            TwistType::M => {
                let items = pairs.iter().map(|(p, q)| (p.0, q.ell_coeffs.iter())).collect();
                run_loop::<P, _>(items, Self::ell_m)
            }
        }
    }

    fn exp_by_x(mut f: Fp12<P::Fp12Params>) -> Fp12<P::Fp12Params> {
        f = f.cyclotomic_exp(P::X);
        if P::X_IS_NEGATIVE {
            f.conjugate();
        }
        f
    }
}

impl<P: Bls12Parameters> crate::sealed::Sealed for Bls12<P> {}

impl<P: Bls12Parameters> PairingEngine for Bls12<P>
where
    G1Affine<P>: PairingCurve<
            BaseField = <P::G1Parameters as ModelParameters>::BaseField,
            ScalarField = <P::G1Parameters as ModelParameters>::ScalarField,
            Projective = G1Projective<P>,
            Coordinates = (P::Fp, P::Fp, bool),
            PairWith = G2Affine<P>,
            Prepared = G1Prepared<P>,
            PairingResult = Fp12<P::Fp12Params>,
        >,
    G2Affine<P>: PairingCurve<
            BaseField = <P::G2Parameters as ModelParameters>::BaseField,
            ScalarField = <P::G1Parameters as ModelParameters>::ScalarField,
            Projective = G2Projective<P>,
            PairWith = G1Affine<P>,
            Prepared = G2Prepared<P>,
            PairingResult = Fp12<P::Fp12Params>,
        >,
{
    type Fq = P::Fp;
    type Fqe = Fp2<P::Fp2Params>;
    type Fqk = Fp12<P::Fp12Params>;
    type Fr = <P::G1Parameters as ModelParameters>::ScalarField;
    type G1Affine = G1Affine<P>;
    type G1Projective = G1Projective<P>;
    type G2Affine = G2Affine<P>;
    type G2Projective = G2Projective<P>;

    fn miller_loop<'a, I>(i: I) -> Self::Fqk
    where
        I: Iterator<
            Item = (&'a <Self::G1Affine as PairingCurve>::Prepared, &'a <Self::G2Affine as PairingCurve>::Prepared),
        >,
    {
        let mut pairs = vec![];
        for (p, q) in i {
            if !p.is_zero() && !q.is_zero() {
                pairs.push((p, q));
            }
        }

        let mut f = P::miller_loop_fp12(&pairs);

        if P::X_IS_NEGATIVE {
            f.conjugate();
        }

        f
    }

    fn final_exponentiation(f: &Self::Fqk) -> Option<Self::Fqk> {
        // Computing the final exponentiation following
        // https://eprint.iacr.org/2016/130.pdf.
        // We don't use their "faster" formula because it is difficult to make
        // it work for curves with odd `P::X`.
        // Hence we implement the algorithm from Table 1 below.

        // f1 = r.conjugate() = f^(p^6)
        let mut f1 = *f;
        f1.conjugate();

        match f.inverse() {
            Some(mut f2) => {
                // f2 = f^(-1);
                // r = f^(p^6 - 1)
                let mut r = f1 * f2;

                // f2 = f^(p^6 - 1)
                f2 = r;
                // r = f^((p^6 - 1)(p^2))
                r.frobenius_map(2);

                // r = f^((p^6 - 1)(p^2) + (p^6 - 1))
                // r = f^((p^6 - 1)(p^2 + 1))
                r *= &f2;

                // Hard part of the final exponentiation is below:
                // From https://eprint.iacr.org/2016/130.pdf, Table 1
                let mut y0 = r.cyclotomic_square();
                y0.conjugate();

                let mut y5 = Self::exp_by_x(r);

                let mut y1 = y5.cyclotomic_square();
                let mut y3 = y0 * y5;
                y0 = Self::exp_by_x(y3);
                let y2 = Self::exp_by_x(y0);
                let mut y4 = Self::exp_by_x(y2);
                y4 *= &y1;
                y1 = Self::exp_by_x(y4);
                y3.conjugate();
                y1 *= &y3;
                y1 *= &r;
                y3 = r;
                y3.conjugate();
                y0 *= &r;
                y0.frobenius_map(3);
                y4 *= &y3;
                y4.frobenius_map(1);
                y5 *= &y2;
                y5.frobenius_map(2);
                y5 *= &y0;
                y5 *= &y4;
                y5 *= &y1;
                Some(y5)
            }
            None => None,
        }
    }
}
