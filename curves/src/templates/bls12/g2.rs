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
    templates::{
        bls12::{Bls12Parameters, TwistType},
        short_weierstrass_jacobian::{Affine, Projective},
    },
    traits::{AffineCurve, ShortWeierstrassParameters},
};
use snarkvm_fields::{Field, Fp2, One, Zero};
use snarkvm_utilities::{ToBytes, bititerator::BitIteratorBE, serialize::*};

use std::io::{Result as IoResult, Write};

pub type G2Affine<P> = Affine<<P as Bls12Parameters>::G2Parameters>;
pub type G2Projective<P> = Projective<<P as Bls12Parameters>::G2Parameters>;
type CoeffPair<T> = (Fp2<T>, Fp2<T>);
type CoeffTriplet<T> = (Fp2<T>, Fp2<T>, Fp2<T>);

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct G2Prepared<P: Bls12Parameters> {
    /// The affine line coefficients `(c1 / c0, c2 / c0)` for each step of the Miller loop.
    pub ell_coeffs: Vec<CoeffPair<P::Fp2Params>>,
    pub infinity: bool,
}

#[derive(Copy, Clone, Debug)]
struct G2HomProjective<P: Bls12Parameters> {
    x: Fp2<P::Fp2Params>,
    y: Fp2<P::Fp2Params>,
    z: Fp2<P::Fp2Params>,
}

impl<P: Bls12Parameters> Default for G2Prepared<P> {
    fn default() -> Self {
        Self::from_affine(G2Affine::<P>::prime_subgroup_generator())
    }
}

impl<P: Bls12Parameters> ToBytes for G2Prepared<P> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.ell_coeffs.len() as u32).write_le(&mut writer)?;
        for coeff in &self.ell_coeffs {
            coeff.0.write_le(&mut writer)?;
            coeff.1.write_le(&mut writer)?;
        }
        self.infinity.write_le(writer)
    }
}

impl<P: Bls12Parameters> G2Prepared<P> {
    pub fn is_zero(&self) -> bool {
        self.infinity
    }

    pub fn from_affine(q: G2Affine<P>) -> Self {
        if q.is_zero() {
            return Self { ell_coeffs: vec![], infinity: true };
        }

        let mut r = G2HomProjective { x: q.x, y: q.y, z: Fp2::one() };

        let num_lines = BitIteratorBE::new(P::X).skip(1).map(|b| 1 + usize::from(b)).sum();
        let mut ell_coeffs = Vec::with_capacity(num_lines);
        let mut c0_and_prefix = Vec::with_capacity(num_lines);
        let mut acc = Fp2::<P::Fp2Params>::one();

        // `one_half` = 1/2 in the field.
        let one_half = P::Fp::half();

        let mut push_step = |(c0, c1, c2): CoeffTriplet<P::Fp2Params>| {
            c0_and_prefix.push((c0, acc));
            if !c0.is_zero() {
                acc *= c0;
            }
            ell_coeffs.push((c1, c2));
        };

        for i in BitIteratorBE::new(P::X).skip(1) {
            push_step(doubling_step::<P>(&mut r, &one_half));

            if i {
                push_step(addition_step::<P>(&mut r, &q));
            }
        }

        // `acc` starts at one and only multiplies by nonzero `Fp2` elements, so it is nonzero.
        let mut inv = acc.inverse().unwrap();
        for (ell, (c0, prefix)) in ell_coeffs.iter_mut().zip(c0_and_prefix.iter()).rev() {
            if !c0.is_zero() {
                let c0_inv = inv * prefix;
                inv *= c0;
                ell.0 *= c0_inv;
                ell.1 *= c0_inv;
            } else {
                *ell = (Fp2::zero(), Fp2::zero());
            }
        }

        Self { ell_coeffs, infinity: false }
    }
}

#[allow(clippy::many_single_char_names)]
fn doubling_step<B: Bls12Parameters>(r: &mut G2HomProjective<B>, two_inv: &B::Fp) -> CoeffTriplet<B::Fp2Params> {
    // Formula for line function when working with
    // homogeneous projective coordinates.

    let mut a = r.x * r.y;
    a.mul_by_fp(two_inv);
    let b = r.y.square();
    let c = r.z.square();
    let e = B::G2Parameters::WEIERSTRASS_B * (c.double() + c);
    let f = e.double() + e;
    let mut g = b + f;
    g.mul_by_fp(two_inv);
    let h = (r.y + r.z).square() - (b + c);
    let i = e - b;
    let j = r.x.square();
    let e_square = e.square();

    r.x = a * (b - f);
    r.y = g.square() - (e_square.double() + e_square);
    r.z = b * h;
    match B::TWIST_TYPE {
        TwistType::M => (i, j.double() + j, -h),
        TwistType::D => (-h, j.double() + j, i),
    }
}

#[allow(clippy::many_single_char_names)]
fn addition_step<B: Bls12Parameters>(r: &mut G2HomProjective<B>, q: &G2Affine<B>) -> CoeffTriplet<B::Fp2Params> {
    // Formula for line function when working with
    // homogeneous projective coordinates.
    let theta = r.y - (q.y * r.z);
    let lambda = r.x - (q.x * r.z);
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * d;
    let f = r.z * c;
    let g = r.x * d;
    let h = e + f - g.double();
    r.x = lambda * h;
    r.y = theta * (g - h) - (e * r.y);
    r.z *= &e;
    let j = theta * q.x - (lambda * q.y);

    match B::TWIST_TYPE {
        TwistType::M => (j, -theta, lambda),
        TwistType::D => (lambda, -theta, j),
    }
}
