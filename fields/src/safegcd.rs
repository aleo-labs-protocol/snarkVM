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

//! Variable-time modular inversion by Bernstein-Yang safegcd, over `W` 64-bit words held as `L` signed 62-bit limbs.

// The loop in `inverse` and the functions `divsteps_62_var`, `update_de_62`, `update_fg_62_var`
// and `normalize_62` are ported from `src/modinv64_impl.h` in libsecp256k1
// (https://github.com/bitcoin-core/secp256k1). That file carries the copyright line
// "Copyright (c) 2020 Peter Dettman" and is distributed under the project's MIT license:
//
// Copyright (c) 2013 Pieter Wuille
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

pub(crate) const M62: u64 = u64::MAX >> 2;

/// Splits `a` into `L` limbs of 62 bits; the top limb takes the remaining bits.
pub(crate) const fn to_signed62<const W: usize, const L: usize>(a: &[u64; W]) -> [i64; L] {
    assert!(62 * (L - 1) < 64 * W && 64 * W < 62 * L);
    let mut out = [0i64; L];
    let mut j = 0;
    while j < L {
        let (w, s) = (62 * j / 64, 62 * j % 64);
        let mut limb = a[w] >> s;
        if s > 2 && w + 1 < W {
            limb |= a[w + 1] << (64 - s);
        }
        out[j] = (if j + 1 < L { limb & M62 } else { limb }) as i64;
        j += 1;
    }
    out
}

/// Joins `L` nonnegative limbs of 62 bits into `W` words.
#[inline]
fn from_signed62<const W: usize, const L: usize>(v: &[i64; L]) -> [u64; W] {
    let mut out = [0u64; W];
    for (j, &limb) in v.iter().enumerate() {
        let (w, s) = (62 * j / 64, 62 * j % 64);
        out[w] |= (limb as u64) << s;
        if s > 2 && w + 1 < W {
            out[w + 1] |= limb as u64 >> (64 - s);
        }
    }
    out
}

/// Returns `a^-1 * r2 mod p` for a nonzero `a` in `[0, p)`.
///
/// `modulus` is `p` from `to_signed62`, and `modulus_inv_62` is `p^-1 mod 2^62`.
/// Its branches and running time depend on `a`.
pub(crate) fn inverse<const W: usize, const L: usize>(
    a: &[u64; W],
    modulus: &[i64; L],
    modulus_inv_62: u64,
    r2: &[i64; L],
) -> [u64; W] {
    let mut d = [0i64; L];
    let mut e = *r2;
    let mut f = *modulus;
    let mut g = to_signed62(a);
    let mut len = L;
    let mut eta = -1;
    loop {
        let t;
        (eta, t) = divsteps_62_var(eta, f[0] as u64, g[0] as u64);
        update_de_62(&mut d, &mut e, t, modulus, modulus_inv_62);
        update_fg_62_var(len, &mut f, &mut g, t);
        if g[..len].iter().all(|&limb| limb == 0) {
            break;
        }
        let (f_top, g_top) = (f[len - 1], g[len - 1]);
        if len > 1 && f_top ^ (f_top >> 63) == 0 && g_top ^ (g_top >> 63) == 0 {
            f[len - 2] |= f_top << 62;
            g[len - 2] |= g_top << 62;
            len -= 1;
        }
    }
    // `f` is the gcd of `p` and `a` up to sign, which is 1.
    debug_assert!(
        (f[..len - 1].iter().all(|&limb| limb == 0) && f[len - 1] == 1)
            || (f[..len - 1].iter().all(|&limb| limb == M62 as i64) && f[len - 1] == -1)
    );
    from_signed62(&normalize_62(d, f[len - 1], modulus))
}

#[inline]
/// Runs 62 divsteps on the low limbs of `f` and `g`, returning `eta` and the transition matrix `[u, v, q, r]`.
fn divsteps_62_var(mut eta: i64, mut f: u64, mut g: u64) -> (i64, [i64; 4]) {
    let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
    let mut i = 62u32;
    loop {
        let zeros = (g | (u64::MAX << i)).trailing_zeros();
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros as i64;
        i -= zeros;
        if i == 0 {
            break;
        }
        let w = if eta < 0 {
            eta = -eta;
            (f, g) = (g, f.wrapping_neg());
            (u, q) = (q, u.wrapping_neg());
            (v, r) = (r, v.wrapping_neg());
            let limit = (eta + 1).min(i as i64) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 63;
            f.wrapping_mul(g).wrapping_mul(f.wrapping_mul(f).wrapping_sub(2)) & mask
        } else {
            let limit = (eta + 1).min(i as i64) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 15;
            f.wrapping_add((f.wrapping_add(1) & 4) << 1).wrapping_neg().wrapping_mul(g) & mask
        };
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
    }
    let t = [u as i64, v as i64, q as i64, r as i64];
    let [u, v, q, r] = t.map(i128::from);
    debug_assert_eq!(u * r - v * q, 1 << 62);
    debug_assert!(u.abs() + v.abs() <= 1 << 62 && q.abs() + r.abs() <= 1 << 62);
    (eta, t)
}

#[inline]
/// Sets `[d, e]` to `t [d, e] / 2^62 mod p`, keeping both in `(-2p, p)`.
fn update_de_62<const L: usize>(
    d: &mut [i64; L],
    e: &mut [i64; L],
    t: [i64; 4],
    modulus: &[i64; L],
    modulus_inv_62: u64,
) {
    let [u, v, q, r] = t;
    let (sd, se) = (d[L - 1] >> 63, e[L - 1] >> 63);
    let mut md = (u & sd) + (v & se);
    let mut me = (q & sd) + (r & se);
    let [u, v, q, r] = t.map(i128::from);
    let mut cd = u * d[0] as i128 + v * e[0] as i128;
    let mut ce = q * d[0] as i128 + r * e[0] as i128;
    md -= (modulus_inv_62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64;
    me -= (modulus_inv_62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64;
    cd += modulus[0] as i128 * md as i128;
    ce += modulus[0] as i128 * me as i128;
    debug_assert_eq!(cd & M62 as i128, 0);
    debug_assert_eq!(ce & M62 as i128, 0);
    cd >>= 62;
    ce >>= 62;
    for i in 1..L {
        cd += u * d[i] as i128 + v * e[i] as i128 + modulus[i] as i128 * md as i128;
        ce += q * d[i] as i128 + r * e[i] as i128 + modulus[i] as i128 * me as i128;
        d[i - 1] = (cd as u64 & M62) as i64;
        e[i - 1] = (ce as u64 & M62) as i64;
        cd >>= 62;
        ce >>= 62;
    }
    d[L - 1] = cd as i64;
    e[L - 1] = ce as i64;
    debug_assert!([d, e].iter().all(|x| sign_62(x, modulus, 2) > 0 && sign_62(x, modulus, -1) < 0));
}

#[inline]
/// Sets `[f, g]` to `t [f, g] / 2^62` over their low `len` limbs.
fn update_fg_62_var<const L: usize>(len: usize, f: &mut [i64; L], g: &mut [i64; L], t: [i64; 4]) {
    let [u, v, q, r] = t.map(i128::from);
    let mut cf = u * f[0] as i128 + v * g[0] as i128;
    let mut cg = q * f[0] as i128 + r * g[0] as i128;
    debug_assert_eq!(cf & M62 as i128, 0);
    debug_assert_eq!(cg & M62 as i128, 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..len {
        cf += u * f[i] as i128 + v * g[i] as i128;
        cg += q * f[i] as i128 + r * g[i] as i128;
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[len - 1] = cf as i64;
    g[len - 1] = cg as i64;
}

#[inline]
/// Maps `r` in `(-2p, p)` to `sign(sign) * r mod p` in `[0, p)`.
fn normalize_62<const L: usize>(mut r: [i64; L], sign: i64, modulus: &[i64; L]) -> [i64; L] {
    let add = r[L - 1] >> 63;
    let negate = sign >> 63;
    for (limb, m) in r.iter_mut().zip(modulus) {
        *limb = ((*limb + (m & add)) ^ negate) - negate;
    }
    carry_62(&mut r);
    let add = r[L - 1] >> 63;
    for (limb, m) in r.iter_mut().zip(modulus) {
        *limb += m & add;
    }
    carry_62(&mut r);
    r
}

#[inline]
fn carry_62<const L: usize>(r: &mut [i64; L]) {
    for i in 0..L - 1 {
        r[i + 1] += r[i] >> 62;
        r[i] &= M62 as i64;
    }
}

/// Returns the sign of `a + k * modulus`.
fn sign_62<const L: usize>(a: &[i64; L], modulus: &[i64; L], k: i64) -> i64 {
    let (mut carry, mut nonzero) = (0i128, false);
    for (limb, m) in a.iter().zip(modulus) {
        carry += *limb as i128 + k as i128 * *m as i128;
        nonzero |= carry as u64 & M62 != 0;
        carry >>= 62;
    }
    if carry != 0 { carry.signum() as i64 } else { nonzero as i64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ops::{Add, Mul, Neg};

    // The BLS12-377 scalar field modulus.
    const FR_MODULUS: [u64; 4] = [725501752471715841, 6461107452199829505, 6968279316240510977, 1345280370688173398];
    // The BLS12-377 base field modulus.
    const FQ_MODULUS: [u64; 6] = [
        0x8508c00000000001,
        0x170b5d4430000000,
        0x1ef3622fba094800,
        0x1a22d9f300f5138f,
        0xc63b05c06ca1493b,
        0x1ae3a4617c510ea,
    ];

    fn signed<F: From<u64> + Neg<Output = F>>(x: i64) -> F {
        if x < 0 { -F::from(x.unsigned_abs()) } else { F::from(x as u64) }
    }

    /// Returns the value of the signed limbs `x` in `F`.
    fn to_field<F, const L: usize>(x: &[i64; L]) -> F
    where
        F: Copy + From<u64> + Neg<Output = F> + Add<Output = F> + Mul<Output = F>,
    {
        x.iter().rev().fold(F::from(0u64), |acc, &limb| acc * F::from(1u64 << 62) + signed(limb))
    }

    /// `F` is the field with the modulus `modulus`.
    fn check_update_de_62_at_the_range_bounds<F, const W: usize, const L: usize>(modulus: &[u64; W])
    where
        F: Copy + std::fmt::Debug + PartialEq + From<u64> + Neg<Output = F> + Add<Output = F> + Mul<Output = F>,
    {
        let inv = (0..6).fold(modulus[0], |x, _| x.wrapping_mul(2u64.wrapping_sub(modulus[0].wrapping_mul(x)))) & M62;
        assert_eq!(modulus[0].wrapping_mul(inv) & M62, 1);
        let modulus = to_signed62::<W, L>(modulus);
        let at = |k: i64, offset: i64| {
            let mut x = modulus.map(|m| k * m);
            x[0] += offset;
            carry_62(&mut x);
            x
        };
        let bounds = [at(-2, 1), at(1, -1), [0; L]];
        for k in [1, 3, 1 << 20, (1 << 61) - 1] {
            let w = (1i64 << 62) - k;
            for t in [[w, k, k, w], [-w, -k, -k, -w], [w, -k, -k, w], [-w, k, k, -w]] {
                let [u, v, q, r] = t.map(signed::<F>);
                for (d, e) in bounds.iter().flat_map(|d| bounds.iter().map(move |e| (*d, *e))) {
                    let (mut d_next, mut e_next) = (d, e);
                    update_de_62(&mut d_next, &mut e_next, t, &modulus, inv);
                    for x in [d_next, e_next] {
                        assert!(sign_62(&x, &modulus, 2) > 0 && sign_62(&x, &modulus, -1) < 0, "{t:?}");
                    }
                    let (d, e) = (to_field::<F, L>(&d), to_field::<F, L>(&e));
                    let two_62 = F::from(1u64 << 62);
                    assert_eq!(to_field::<F, L>(&d_next) * two_62, u * d + v * e, "{t:?}");
                    assert_eq!(to_field::<F, L>(&e_next) * two_62, q * d + r * e, "{t:?}");
                }
            }
        }
    }

    #[test]
    fn test_signed62_round_trip() {
        fn round_trip<const W: usize, const L: usize>(a: [u64; W]) {
            assert_eq!(from_signed62::<W, L>(&to_signed62::<W, L>(&a)), a);
        }
        for a in [FR_MODULUS, [u64::MAX; 4], [0x5555_5555_5555_5555; 4]] {
            round_trip::<4, 5>(a);
        }
        for a in [FQ_MODULUS, [u64::MAX; 6], [0x5555_5555_5555_5555; 6]] {
            round_trip::<6, 7>(a);
        }
    }

    #[test]
    fn test_update_de_62_at_the_range_bounds() {
        check_update_de_62_at_the_range_bounds::<snarkvm_curves::bls12_377::Fr, 4, 5>(&FR_MODULUS);
        check_update_de_62_at_the_range_bounds::<snarkvm_curves::bls12_377::Fq, 6, 7>(&FQ_MODULUS);
    }
}
