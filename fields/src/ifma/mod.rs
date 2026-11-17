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

//! Lane programs over `Fp384` with AVX-512 IFMA, and the entry points that dispatch to them.
//!
//! # Representation
//!
//! A program holds 8 integers in a vector group `[__m512i; 8]`: vector `k` holds limb `k`, in
//! radix 2^52, of each of the 8 lanes. A field element `x` is resident in a lane as an integer in
//! `[0, 2 p)` congruent to `x 2^416 mod p`. `Fp384` stores `x 2^384 mod p`, so an element enters
//! a program shifted left by 32 bits, as an integer below `2^32 p`, and leaves it through one
//! `kernel::mont` by an operand in `Fp384`'s form, which divides by 2^416. A result is canonical,
//! in `[0, p)`, when it is stored.
//!
//! # Fallback
//!
//! An entry point whose scalar path is in this crate falls back to it, and always returns the
//! result. Any other entry point returns `None` when it does not run, and its caller runs the
//! scalar path.
//!
//! The programs run only after `is_supported` detects AVX-512F and AVX-512 IFMA at run time;
//! `std` caches the detection. Every program carries `target_feature` for both, and every
//! `unsafe` block names the check it relies on. On other architectures, no program runs. The
//! environment variable `SNARKVM_NO_IFMA`, set to a non-empty value, also keeps every entry point
//! on the scalar path; `is_supported` reads it once, on its first call.

#![allow(unsafe_code)]

#[cfg(target_arch = "x86_64")]
mod fp12;
#[cfg(target_arch = "x86_64")]
mod glv;
#[cfg(target_arch = "x86_64")]
mod kernel;
#[cfg(target_arch = "x86_64")]
mod layout;
#[cfg(all(test, target_arch = "x86_64"))]
mod tests;

use crate::{
    Fp2,
    Fp2Parameters,
    Fp12,
    Fp12Parameters,
    Fp384,
    Fp384Parameters,
    One,
    Zero,
    fp6_3over2::Fp6Parameters,
    fp12_2over3over2::Fp2Params,
};

/// Whether the lane programs run for `P` on this CPU: `2^366 <= p < 2^377`, `SNARKVM_NO_IFMA` is
/// unset or empty in the environment, and the CPU supports AVX-512F and AVX-512 IFMA.
pub fn is_supported<P: Fp384Parameters>() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        (367..=377).contains(&P::MODULUS_BITS)
            && !disabled()
            && is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512ifma")
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

/// Whether `SNARKVM_NO_IFMA` had a non-empty value in the environment at the first call.
#[cfg(target_arch = "x86_64")]
fn disabled() -> bool {
    static DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISABLED.get_or_init(|| std::env::var_os("SNARKVM_NO_IFMA").is_some_and(|value| !value.is_empty()))
}

/// Whether the lane programs run for the tower `P` over `Fp384<Q>`: `is_supported::<Q>()`, and the
/// tower is Fp12 = Fp6[w] / (w^2 - v), Fp6 = Fp2[v] / (v^3 - u) and Fp2 = Fp[u] / (u^2 + 5).
pub fn is_supported_tower<P, Q>() -> bool
where
    P: Fp12Parameters,
    Fp2Params<P>: Fp2Parameters<Fp = Fp384<Q>>,
    Q: Fp384Parameters,
{
    if !is_supported::<Q>() {
        return false;
    }
    let u = Fp2::new(Fp384::zero(), Fp384::one());
    let one = Fp384::<Q>::one();
    let minus_five = -(one + one + one + one + one);
    <Fp2Params<P> as Fp2Parameters>::NONRESIDUE == minus_five && <P::Fp6Params as Fp6Parameters>::NONRESIDUE == u
}

/// Sets `a` to `a * b`, in lanes if `is_supported_tower::<P, Q>()`.
pub fn mul_assign_fp12<P, Q>(a: &mut Fp12<P>, b: &Fp12<P>)
where
    P: Fp12Parameters,
    Fp2Params<P>: Fp2Parameters<Fp = Fp384<Q>>,
    Q: Fp384Parameters,
{
    #[cfg(target_arch = "x86_64")]
    if is_supported_tower::<P, Q>() {
        // SAFETY: `is_supported` detected both target features that `mul_assign_fp12_avx512` enables.
        unsafe { fp12::mul_assign_fp12_avx512(fp12::coefficients_mut(a), fp12::coefficients(b)) };
        return;
    }
    a.mul_assign_scalar(b)
}

/// The relative cost of the doublings of one `glv_mul_8` call, which every call runs: the
/// instruction count of `glv_double`, in thousands, times 128.
pub const GLV_CALL_COST: usize = 420;

/// The relative cost per digit stream of a lane in one `glv_mul_8` call, its additions and its half
/// of a table: the instruction count of `glv_add`, in thousands, times 33.
pub const GLV_STREAM_COST: usize = 180;

/// Returns, at index `l`, Jacobian coordinates `[X, Y, Z]` of
/// `sum_w 16^w sum_k (digits[k][w][0][l] P_kl + digits[k][w][1][l] phi(P_kl))` for each lane `l`; or
/// `None` if `is_supported::<P>()` is false, `points` is empty, `digits` does not hold one slice per
/// entry of `points`, the slices differ in length, or a digit is outside `[-8, 8]`.
///
/// `digits[k]` lists the windows of slot `k`, the least significant first. `P_kl` is the affine
/// point `points[k][l]` of a curve `y^2 = x^3 + b`, and `phi(x, y) = (beta x, y)`. `Z` is zero
/// exactly where the sum is the point at infinity or an addition met one of the cases the formulas
/// exclude: a point at infinity, or two points with the same `x`. `X` and `Y` are then unspecified.
pub fn glv_mul_8<P: Fp384Parameters>(
    points: &[[[Fp384<P>; 2]; 8]],
    beta: &Fp384<P>,
    digits: &[&[[[i8; 8]; 2]]],
) -> Option<[[Fp384<P>; 3]; 8]> {
    if !is_supported::<P>() || points.is_empty() || digits.len() != points.len() {
        return None;
    }
    if digits.iter().any(|slot| slot.len() != digits[0].len()) {
        return None;
    }
    if digits.iter().copied().flatten().flatten().flatten().any(|d| d.unsigned_abs() > 8) {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let mut out = [[Fp384::zero(); 3]; 8];
        // SAFETY: `is_supported` detected both target features that `glv_mul_8_avx512` enables.
        unsafe { glv::glv_mul_8_avx512(points, beta, digits, &mut out) };
        Some(out)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = beta;
        None
    }
}
