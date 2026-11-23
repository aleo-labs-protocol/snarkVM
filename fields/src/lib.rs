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

#![allow(clippy::module_inception)]
#![deny(unsafe_code)]

#[macro_use]
extern crate thiserror;

#[macro_use]
mod macros;

/// Expands to `$asm` when the target can run the assembly in `adx`, and to `$scalar` otherwise.
macro_rules! adx_or {
    ($asm:expr, $scalar:expr) => {{
        #[cfg(all(
            target_arch = "x86_64",
            target_pointer_width = "64",
            target_feature = "adx",
            target_feature = "bmi2"
        ))]
        {
            $asm
        }
        #[cfg(not(all(
            target_arch = "x86_64",
            target_pointer_width = "64",
            target_feature = "adx",
            target_feature = "bmi2"
        )))]
        {
            $scalar
        }
    }};
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64", target_feature = "adx", target_feature = "bmi2"))]
mod adx;

pub mod errors;
pub use errors::*;

mod fp_256;
pub use fp_256::*;

mod fp_384;
pub use fp_384::*;

mod fp2;
pub use fp2::*;

pub mod fp6_3over2;

mod fp12_2over3over2;
pub use fp12_2over3over2::*;

#[doc(hidden)]
pub mod ifma;

mod legendre;
pub use legendre::*;

mod safegcd;

mod sqrt_tables;
#[doc(hidden)]
pub use sqrt_tables::ExponentSchedule;
pub use sqrt_tables::SqrtTables;

mod to_field_vec;
#[allow(unused_imports)]
pub use to_field_vec::*;

pub mod traits;
pub use traits::*;

/// Seals [`Field`]. Only the field types of this crate implement it.
///
/// The parameter traits have their own seal, [`sealed_parameters::Sealed`], which is public
/// for `snarkvm-curves`. Code outside snarkVM that implements one of them does not compile:
///
/// ```compile_fail,E0277
/// use snarkvm_fields::FftParameters;
/// use snarkvm_utilities::biginteger::BigInteger256;
///
/// struct Parameters;
///
/// impl FftParameters for Parameters {
///     type BigInteger = BigInteger256;
///
///     const TWO_ADICITY: u32 = 1;
///     const TWO_ADIC_ROOT_OF_UNITY: BigInteger256 = BigInteger256([0; 4]);
/// }
/// ```
mod sealed {
    pub trait Sealed {}
}

/// Seals [`FftParameters`], [`Fp2Parameters`], [`Fp6Parameters`](fp6_3over2::Fp6Parameters)
/// and [`Fp12Parameters`]. `snarkvm-curves` implements it for its fields, so it is public, but it
/// is not part of the API.
#[doc(hidden)]
pub mod sealed_parameters {
    pub trait Sealed {}
}

use snarkvm_utilities::{
    FromBytes,
    ToBytes,
    biginteger::*,
    serialize::{CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize, CanonicalSerializeWithFlags},
};

impl_field_to_biginteger!(Fp256, BigInteger256, Fp256Parameters);
impl_field_to_biginteger!(Fp384, BigInteger384, Fp384Parameters);

impl_primefield_serializer!(Fp256, Fp256Parameters, 32);
impl_primefield_serializer!(Fp384, Fp384Parameters, 48);

// Given a vector of field elements {v_i}, compute the vector {v_i^(-1)}
pub fn batch_inversion<F: Field>(v: &mut [F]) {
    batch_inversion_and_mul(v, &F::one());
}

// Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}
pub fn batch_inversion_and_mul<F: Field>(v: &mut [F], coeff: &F) {
    use rayon::prelude::*;
    let num_cpus_available = snarkvm_utilities::parallel::max_available_threads();
    let num_elems = v.len();
    // Below 4 elements per thread, waking the pool costs more than one serial pass.
    if num_elems < 4 * num_cpus_available {
        serial_batch_inversion_and_mul(v, coeff);
        return;
    }
    // Divide the vector v evenly between all available cores
    let num_elem_per_thread = num_elems / num_cpus_available;

    // Batch invert in parallel, without copying the vector
    v.par_chunks_mut(num_elem_per_thread).for_each(|chunk| {
        serial_batch_inversion_and_mul(chunk, coeff);
    });
}

/// Given a vector of field elements {v_i}, compute the vector {coeff * v_i^(-1)}.
/// This method is explicitly single-threaded.
fn serial_batch_inversion_and_mul<F: Field>(v: &mut [F], coeff: &F) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2
    // but with an optimization to multiply every element in the returned vector by
    // coeff

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = F::one();
    for f in v.iter().filter(|f| !f.is_zero()) {
        tmp.mul_assign(f);
        prod.push(tmp);
    }

    // Invert `tmp`.
    tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

    // Multiply product by coeff, so all inverses will be scaled by coeff
    tmp *= coeff;

    // Second pass: iterate backwards to compute inverses
    for (f, s) in v.iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|f| !f.is_zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(F::one())))
    {
        // tmp := tmp * f; f := tmp * s = 1/f
        let new_tmp = tmp * *f;
        *f = tmp * s;
        tmp = new_tmp;
    }
}
