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

#[allow(unused_imports)]
use blst::*;

use core::ffi::c_void;
use snarkvm_curves::bls12_377::{Fr, G1Affine, G1Projective};
use snarkvm_utilities::BigInteger256;
use std::any::TypeId;
sppark::cuda_error!();

#[repr(C)]
pub enum NTTInputOutputOrder {
    NN = 0,
    NR = 1,
    RN = 2,
    RR = 3,
}

#[repr(C)]
pub enum NTTDirection {
    Forward = 0,
    Inverse = 1,
}

#[repr(C)]
pub enum NTTType {
    Standard = 0,
    Coset = 1,
}

unsafe extern "C" {
    fn snarkvm_cuda_device_count() -> usize;

    fn snarkvm_cuda_pool_elements() -> usize;

    fn snarkvm_ntt(
        inout: *mut core::ffi::c_void,
        lg_domain_size: u32,
        ntt_order: NTTInputOutputOrder,
        ntt_direction: NTTDirection,
        ntt_type: NTTType,
    ) -> cuda::Error;

    fn snarkvm_polymul(
        out: *mut core::ffi::c_void,
        pcount: usize,
        polynomials: *const core::ffi::c_void,
        plens: *const core::ffi::c_void,
        ecount: usize,
        evaluations: *const core::ffi::c_void,
        elens: *const core::ffi::c_void,
        lg_domain_size: u32,
    ) -> cuda::Error;

    fn snarkvm_blst_platform_cap() -> core::ffi::c_int;

    fn snarkvm_msm(
        out: *mut c_void,
        points_with_infinity: *const c_void,
        npoints: usize,
        scalars: *const c_void,
        ffi_affine_sz: usize,
    ) -> cuda::Error;
}

///////////////////////////////////////////////////////////////////////////////
// Rust functions
///////////////////////////////////////////////////////////////////////////////

// The C++ reads `fr_t` as 32 bytes, an affine point as 104 bytes with
// `infinity` at byte 96, and writes `point_t` as 144 bytes.
const _: () = assert!(
    size_of::<Fr>() == 32
        && size_of::<BigInteger256>() == 32
        && size_of::<G1Affine>() == 104
        && std::mem::offset_of!(G1Affine, infinity) == 96
        && size_of::<G1Projective>() == 144
);

/// Panics unless `T` is `Expected`. The FFI takes `c_void` pointers and the C++
/// is compiled for BLS12-377, so another type of the same width, such as
/// another curve's scalar field, would be computed with the wrong modulus.
#[track_caller]
fn assert_type<T: 'static, Expected: 'static>() {
    assert!(
        TypeId::of::<T>() == TypeId::of::<Expected>(),
        "the C++ reads this as {}, got {}",
        std::any::type_name::<Expected>(),
        std::any::type_name::<T>()
    );
}

/// Whether the build found nvcc and compiled the kernels. Without nvcc this
/// crate still builds, so a workspace build, clippy and rust-analyzer need no
/// nvcc, but nothing it declares links.
pub const HAVE_NVCC: bool = cfg!(have_nvcc);

/// How many CUDA devices the runtime reports. Zero means none, or that the
/// runtime could not be queried at all. sppark uses only those of compute
/// capability 7.0 or later that support cooperative launch.
pub fn device_count() -> usize {
    unsafe { snarkvm_cuda_device_count() }
}

/// The largest domain a proof can multiply here, as an element count. Zero
/// means there is no usable pool.
///
/// The prover multiplies over the constraint domain in round two, the variable
/// domain in round three, and each matrix's non-zero domain in round four, so
/// all three must fit. Compare `CircuitInfo::num_constraints`,
/// `num_public_and_private_variables` and each of `num_non_zero_a`,
/// `num_non_zero_b` and `num_non_zero_c`, rounded up to a power of two, and
/// refuse above it. No consensus limit caps the non-zero counts.
///
/// `snarkvm_t::PolyMul` admits a domain up to a quarter of
/// [`pool_elements()`], and `PolyMultiplier::multiply` asks for `2n` to
/// multiply two polynomials over a domain of `n`, so the bound is `pool / 8`.
/// The factor depends on the prover: a multiply of three polynomials would make
/// it `pool / 16`. The contract test in `fft::domain` checks it.
///
/// This builds the pool if it is not built, and a failed build is never
/// retried, so calling it before the device is ready latches the failure for
/// the life of the process. [`device_count()`] has no such side effect.
pub fn max_domain() -> usize {
    unsafe { snarkvm_cuda_pool_elements() / 8 }
}

/// Elements the pool reserves per device per stream slot.
///
/// `snarkvm_t::NTT` refuses a domain above it and `snarkvm_t::PolyMul` above a
/// quarter of it. It is for diagnostics, not a refusal criterion: use
/// [`max_domain()`] for that. Zero, and the construction side effect, are as
/// for [`max_domain()`].
pub fn pool_elements() -> usize {
    unsafe { snarkvm_cuda_pool_elements() }
}

/// Compute an in-place NTT on the input data.
///
/// A domain larger than the device pool is refused with
/// `cudaErrorNotSupported`, whose message names the domain and the limit.
#[allow(non_snake_case)]
pub fn NTT<T: 'static>(
    domain_size: usize,
    inout: &mut [T],
    ntt_order: NTTInputOutputOrder,
    ntt_direction: NTTDirection,
    ntt_type: NTTType,
) -> Result<(), cuda::Error> {
    assert_type::<T, Fr>();
    // Zero passes the power-of-two test, and `trailing_zeros()` is then 64,
    // which the C++ shifts by.
    if domain_size == 0 || (domain_size & (domain_size - 1)) != 0 {
        panic!("domain_size must be a non-zero power of 2, got {domain_size}");
    }
    // The C++ reads and writes `domain_size` elements through this pointer.
    assert_eq!(inout.len(), domain_size, "the buffer must be exactly the domain the NTT runs over");
    let lg_domain_size = domain_size.trailing_zeros();

    let err = unsafe {
        snarkvm_ntt(inout.as_mut_ptr() as *mut core::ffi::c_void, lg_domain_size, ntt_order, ntt_direction, ntt_type)
    };

    if err.code != 0 {
        return Err(err);
    }
    Ok(())
}

/// Whether [`polymul`] can multiply this many operands over a domain of this
/// size. Two or more operands over a one-element domain reach
/// `Polynomial::Mul`, which launches `1 << 31` threads for it.
pub fn polymul_supports(domain_size: usize, operands: usize) -> bool {
    domain_size > 1 || operands < 2
}

/// Compute a polynomial multiply
pub fn polymul<T: std::clone::Clone + 'static>(
    domain: usize,
    polynomials: &[&[T]],
    evaluations: &[&[T]],
    zero: &T,
) -> Result<Vec<T>, cuda::Error> {
    assert_type::<T, Fr>();
    let initial_domain_size = domain;
    if initial_domain_size == 0 || (initial_domain_size & (initial_domain_size - 1)) != 0 {
        panic!("domain_size must be a non-zero power of 2, got {initial_domain_size}");
    }
    assert!(
        polymul_supports(initial_domain_size, polynomials.len() + evaluations.len()),
        "Polynomial::Mul cannot multiply {} operands over a one-element domain",
        polynomials.len() + evaluations.len()
    );
    // The C++ copies each polynomial into a domain-sized buffer, and reads
    // each evaluation as a full domain.
    assert!(
        polynomials.iter().all(|p| p.len() <= initial_domain_size),
        "a polynomial is longer than the domain of {initial_domain_size}"
    );
    assert!(
        evaluations.iter().all(|e| e.len() == initial_domain_size),
        "an evaluation does not fill the domain of {initial_domain_size}"
    );

    let lg_domain_size = initial_domain_size.trailing_zeros();

    let mut pptrs = Vec::with_capacity(polynomials.len());
    let mut plens = Vec::with_capacity(polynomials.len());
    for polynomial in polynomials {
        pptrs.push(polynomial.as_ptr() as *const core::ffi::c_void);
        plens.push(polynomial.len());
    }
    let mut eptrs = Vec::with_capacity(evaluations.len());
    let mut elens = Vec::with_capacity(evaluations.len());
    for evaluation in evaluations {
        eptrs.push(evaluation.as_ptr() as *const core::ffi::c_void);
        elens.push(evaluation.len());
    }

    let mut out = vec![zero.clone(); initial_domain_size];
    let err = unsafe {
        snarkvm_polymul(
            out.as_mut_ptr() as *mut core::ffi::c_void,
            pptrs.len(),
            pptrs.as_ptr() as *const core::ffi::c_void,
            plens.as_ptr() as *const core::ffi::c_void,
            eptrs.len(),
            eptrs.as_ptr() as *const core::ffi::c_void,
            elens.as_ptr() as *const core::ffi::c_void,
            lg_domain_size,
        )
    };

    if err.code != 0 {
        return Err(err);
    }
    Ok(out)
}

/// Compute a multi-scalar multiplication over scalars reduced out of
/// Montgomery form.
pub fn msm<Affine: 'static, Projective: 'static, Scalar: 'static>(
    points: &[Affine],
    scalars: &[Scalar],
) -> Result<Projective, cuda::Error> {
    assert_type::<Affine, G1Affine>();
    assert_type::<Projective, G1Projective>();
    assert_type::<Scalar, BigInteger256>();

    let npoints = scalars.len();
    if npoints > points.len() {
        panic!("length mismatch {} points < {} scalars", points.len(), scalars.len())
    }
    let mut ret = std::mem::MaybeUninit::<Projective>::uninit();
    let err = unsafe {
        snarkvm_msm(
            ret.as_mut_ptr() as *mut c_void,
            points as *const _ as *const c_void,
            npoints,
            scalars as *const _ as *const c_void,
            std::mem::size_of::<Affine>(),
        )
    };
    if err.code != 0 {
        return Err(err);
    }
    // SAFETY: the C++ writes `*out` whenever it returns success.
    Ok(unsafe { ret.assume_init() })
}

/// The CPU features blst's routines run with. Bit 0 is ADX.
#[doc(hidden)]
pub fn blst_platform_cap() -> i32 {
    unsafe { snarkvm_blst_platform_cap() }
}

/// Argument guards that a caller can trip.
///
/// The device-failure paths — `cudaSetDevice` throwing, the pool allocation
/// failing — cannot be provoked from a test, so nothing here covers them.
#[cfg(all(test, have_nvcc))]
mod argument_guards {
    use super::Fr;

    /// Zero passes the power-of-two test, so it has a check of its own.
    #[test]
    #[should_panic(expected = "non-zero power of 2")]
    fn ntt_refuses_a_zero_domain() {
        let mut v: Vec<Fr> = Vec::new();
        let _ = super::NTT(
            0,
            &mut v,
            super::NTTInputOutputOrder::NN,
            super::NTTDirection::Forward,
            super::NTTType::Standard,
        );
    }

    #[test]
    #[should_panic(expected = "non-zero power of 2")]
    fn polymul_refuses_a_zero_domain() {
        let one = [Fr::default()];
        let polys: Vec<&[Fr]> = vec![&one, &one];
        let _ = super::polymul(0, &polys, &[], &Fr::default());
    }

    /// The C++ transforms `domain_size` elements through this pointer and has
    /// no length to check, so a short buffer is an overrun.
    #[test]
    #[should_panic(expected = "exactly the domain")]
    fn ntt_refuses_a_buffer_shorter_than_its_domain() {
        let mut v = vec![Fr::default(); 2];
        let _ = super::NTT(
            4,
            &mut v,
            super::NTTInputOutputOrder::NN,
            super::NTTDirection::Forward,
            super::NTTType::Standard,
        );
    }

    /// The staging buffer is sliced at `domain_size` strides and the
    /// single-polynomial path memcpys the input's own length into an output
    /// allocated at `domain_size`, so an over-long input overruns either way.
    #[test]
    #[should_panic(expected = "longer than the domain")]
    fn polymul_refuses_an_input_longer_than_the_domain() {
        let long = vec![Fr::default(); 8];
        let polys: Vec<&[Fr]> = vec![&long];
        let _ = super::polymul(4, &polys, &[], &Fr::default());
    }

    #[test]
    #[should_panic(expected = "does not fill the domain")]
    fn polymul_refuses_an_evaluation_that_is_not_the_domain() {
        let long = vec![Fr::default(); 8];
        let evals: Vec<&[Fr]> = vec![&long];
        let _ = super::polymul(4, &[], &evals, &Fr::default());
    }

    #[test]
    #[should_panic(expected = "does not fill the domain")]
    fn polymul_refuses_an_evaluation_shorter_than_the_domain() {
        let short = vec![Fr::default(); 2];
        let evals: Vec<&[Fr]> = vec![&short];
        let _ = super::polymul(4, &[], &evals, &Fr::default());
    }

    /// Another curve's scalar field has `fr_t`'s width, so only the type check
    /// stops the C++ computing with the wrong modulus.
    #[test]
    #[should_panic(expected = "the C++ reads this as")]
    fn ntt_refuses_another_fields_elements() {
        let mut v = vec![snarkvm_curves::edwards_bls12::Fr::default(); 4];
        let _ = super::NTT(
            4,
            &mut v,
            super::NTTInputOutputOrder::NN,
            super::NTTDirection::Forward,
            super::NTTType::Standard,
        );
    }

    /// A scalar the width of `fr_t` that is not `BigInteger256` is read as a
    /// different integer.
    #[test]
    #[should_panic(expected = "BigInteger256, got")]
    fn msm_refuses_scalars_of_another_type() {
        let _ = super::msm::<super::G1Affine, super::G1Projective, snarkvm_curves::edwards_bls12::Fr>(&[], &[]);
    }

    #[test]
    #[should_panic(expected = "0 points < 1 scalars")]
    fn msm_refuses_more_scalars_than_points() {
        let scalars = [super::BigInteger256::default()];
        let _ = super::msm::<super::G1Affine, super::G1Projective, super::BigInteger256>(&[], &scalars);
    }

    /// The shape `polymul_supports` refuses.
    #[test]
    #[should_panic(expected = "over a one-element domain")]
    fn polymul_refuses_a_one_element_domain() {
        let one = [Fr::default()];
        let polys: Vec<&[Fr]> = vec![&one, &one];
        let _ = super::polymul(1, &polys, &[], &Fr::default());
    }
}
