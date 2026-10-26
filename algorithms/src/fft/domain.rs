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

//! This module contains an `EvaluationDomain` abstraction for
//! performing various kinds of polynomial arithmetic on top of
//! the scalar field.
//!
//! In pairing-based SNARKs like GM17, we need to calculate
//! a quotient polynomial over a target polynomial with roots
//! at distinct points associated with each constraint of the
//! constraint system. In order to be efficient, we choose these
//! roots to be the powers of a 2^n root of unity in the field.
//! This allows us to perform polynomial operations in O(n)
//! by performing an O(n log n) FFT over such a domain.

use crate::{
    cfg_chunks_mut,
    cfg_into_iter,
    cfg_iter,
    cfg_iter_mut,
    fft::{DomainCoeff, SparsePolynomial},
};
use snarkvm_fields::{FftField, FftParameters, Field, batch_inversion};
#[cfg(not(feature = "serial"))]
use snarkvm_utilities::max_available_threads;
use snarkvm_utilities::{execute_with_max_available_threads, serialize::*};

use rand::RngExt;
use std::{borrow::Cow, fmt};

use anyhow::{Result, ensure};

#[cfg(feature = "serial")]
use itertools::Itertools;
#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// Returns the ceiling of the base-2 logarithm of `x`.
///
/// ```
/// use snarkvm_algorithms::fft::domain::log2;
///
/// assert_eq!(log2(16), 4);
/// assert_eq!(log2(17), 5);
/// assert_eq!(log2(1), 0);
/// assert_eq!(log2(0), 0);
/// assert_eq!(log2(usize::MAX), (core::mem::size_of::<usize>() * 8) as u32);
/// assert_eq!(log2(1 << 15), 15);
/// assert_eq!(log2(2usize.pow(18)), 18);
/// ```
pub fn log2(x: usize) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}

// minimum size of a parallelized chunk
#[allow(unused)]
#[cfg(not(feature = "serial"))]
const MIN_PARALLEL_CHUNK_SIZE: usize = 1 << 7;

/// Defines a domain over which finite field (I)FFTs can be performed. Works
/// only for fields that have a large multiplicative subgroup of size that is
/// a power-of-2.
#[derive(Copy, Clone, Hash, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct EvaluationDomain<F: FftField> {
    /// The size of the domain.
    pub size: u64,
    /// `log_2(self.size)`.
    pub log_size_of_group: u32,
    /// Size of the domain as a field element.
    pub size_as_field_element: F,
    /// Inverse of the size in the field.
    pub size_inv: F,
    /// A generator of the subgroup.
    pub group_gen: F,
    /// Inverse of the generator of the subgroup.
    pub group_gen_inv: F,
    /// Inverse of the multiplicative generator of the finite field.
    pub generator_inv: F,
}

impl<F: FftField> fmt::Debug for EvaluationDomain<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Multiplicative subgroup of size {}", self.size)
    }
}

impl<F: FftField> EvaluationDomain<F> {
    /// Sample an element that is *not* in the domain.
    pub fn sample_element_outside_domain<R: RngExt>(&self, rng: &mut R) -> F {
        let mut t = F::rand(rng);
        while self.evaluate_vanishing_polynomial(t).is_zero() {
            t = F::rand(rng);
        }
        t
    }

    /// Construct a domain that is large enough for evaluations of a polynomial
    /// having `num_coeffs` coefficients.
    pub fn new(num_coeffs: usize) -> Option<Self> {
        // Compute the size of our evaluation domain
        let size = num_coeffs.checked_next_power_of_two()? as u64;
        let log_size_of_group = size.trailing_zeros();

        // libfqfft uses > https://github.com/scipr-lab/libfqfft/blob/e0183b2cef7d4c5deb21a6eaf3fe3b586d738fe0/libfqfft/evaluation_domain/domains/basic_radix2_domain.tcc#L33
        if log_size_of_group > F::FftParameters::TWO_ADICITY {
            return None;
        }

        // Compute the generator for the multiplicative subgroup.
        // It should be the 2^(log_size_of_group) root of unity.
        let group_gen = F::get_root_of_unity(size as usize)?;

        // Check that it is indeed the 2^(log_size_of_group) root of unity.
        debug_assert_eq!(group_gen.pow([size]), F::one());

        let size_as_field_element = F::from(size);
        let size_inv = size_as_field_element.inverse()?;

        Some(EvaluationDomain {
            size,
            log_size_of_group,
            size_as_field_element,
            size_inv,
            group_gen,
            group_gen_inv: group_gen.inverse()?,
            generator_inv: F::multiplicative_generator().inverse()?,
        })
    }

    /// Return the size of a domain that is large enough for evaluations of a
    /// polynomial having `num_coeffs` coefficients.
    pub fn compute_size_of_domain(num_coeffs: usize) -> Option<usize> {
        let size = num_coeffs.checked_next_power_of_two()?;
        if size.trailing_zeros() <= F::FftParameters::TWO_ADICITY { Some(size) } else { None }
    }

    /// Return the size of `self`.
    pub fn size(&self) -> usize {
        self.size as usize
    }

    /// Compute an FFT.
    pub fn fft<T: DomainCoeff<F>>(&self, coeffs: &[T]) -> Vec<T> {
        let mut coeffs = coeffs.to_vec();
        self.fft_in_place(&mut coeffs);
        coeffs
    }

    /// Compute an FFT, modifying the vector in place.
    pub fn fft_in_place<T: DomainCoeff<F>>(&self, coeffs: &mut Vec<T>) {
        execute_with_max_available_threads(|| {
            coeffs.resize(self.size(), T::zero());
            self.in_order_fft_in_place(&mut *coeffs);
        });
    }

    /// Compute an IFFT.
    pub fn ifft<T: DomainCoeff<F>>(&self, evals: &[T]) -> Vec<T> {
        let mut evals = evals.to_vec();
        self.ifft_in_place(&mut evals);
        evals
    }

    /// Compute an IFFT, modifying the vector in place.
    #[inline]
    pub fn ifft_in_place<T: DomainCoeff<F>>(&self, evals: &mut Vec<T>) {
        execute_with_max_available_threads(|| {
            evals.resize(self.size(), T::zero());
            self.in_order_ifft_in_place(&mut *evals);
        });
    }

    /// Compute an FFT over a coset of the domain.
    pub fn coset_fft<T: DomainCoeff<F>>(&self, coeffs: &[T]) -> Vec<T> {
        let mut coeffs = coeffs.to_vec();
        self.coset_fft_in_place(&mut coeffs);
        coeffs
    }

    /// Compute an FFT over a coset of the domain, modifying the input vector
    /// in place.
    pub fn coset_fft_in_place<T: DomainCoeff<F>>(&self, coeffs: &mut Vec<T>) {
        execute_with_max_available_threads(|| {
            Self::distribute_powers(coeffs, F::multiplicative_generator());
            self.fft_in_place(coeffs);
        });
    }

    /// Compute an IFFT over a coset of the domain.
    pub fn coset_ifft<T: DomainCoeff<F>>(&self, evals: &[T]) -> Vec<T> {
        let mut evals = evals.to_vec();
        self.coset_ifft_in_place(&mut evals);
        evals
    }

    /// Compute an IFFT over a coset of the domain, modifying the input vector
    /// in place.
    pub fn coset_ifft_in_place<T: DomainCoeff<F>>(&self, evals: &mut Vec<T>) {
        execute_with_max_available_threads(|| {
            evals.resize(self.size(), T::zero());
            self.in_order_coset_ifft_in_place(&mut *evals);
        });
    }

    /// Multiply the `i`-th element of `coeffs` with `g^i`.
    fn distribute_powers<T: DomainCoeff<F>>(coeffs: &mut [T], g: F) {
        Self::distribute_powers_and_mul_by_const(coeffs, g, F::one());
    }

    /// Multiply the `i`-th element of `coeffs` with `c*g^i`.
    #[cfg(feature = "serial")]
    fn distribute_powers_and_mul_by_const<T: DomainCoeff<F>>(coeffs: &mut [T], g: F, c: F) {
        // invariant: pow = c*g^i at the ith iteration of the loop
        let mut pow = c;
        coeffs.iter_mut().for_each(|coeff| {
            *coeff *= pow;
            pow *= &g
        })
    }

    /// Multiply the `i`-th element of `coeffs` with `c*g^i`.
    #[cfg(not(feature = "serial"))]
    fn distribute_powers_and_mul_by_const<T: DomainCoeff<F>>(coeffs: &mut [T], g: F, c: F) {
        let min_parallel_chunk_size = 1024;
        let num_cpus_available = max_available_threads();
        let num_elem_per_thread = core::cmp::max(coeffs.len() / num_cpus_available, min_parallel_chunk_size);

        cfg_chunks_mut!(coeffs, num_elem_per_thread).enumerate().for_each(|(i, chunk)| {
            let offset = c * g.pow([(i * num_elem_per_thread) as u64]);
            let mut pow = offset;
            chunk.iter_mut().for_each(|coeff| {
                *coeff *= pow;
                pow *= &g
            })
        });
    }

    /// Evaluate all the lagrange polynomials defined by this domain at the
    /// point `tau`.
    pub fn evaluate_all_lagrange_coefficients(&self, tau: F) -> Vec<F> {
        // Evaluate all Lagrange polynomials
        let size = self.size as usize;
        let t_size = tau.pow([self.size]);
        let one = F::one();
        if t_size.is_one() {
            let mut u = vec![F::zero(); size];
            let mut omega_i = one;
            for x in u.iter_mut().take(size) {
                if omega_i == tau {
                    *x = one;
                    break;
                }
                omega_i *= &self.group_gen;
            }
            u
        } else {
            let l0 = (t_size - one) * self.size_inv;
            let mut u = vec![F::zero(); size];
            let mut ls = vec![F::zero(); size];

            // Fill `u[i] = tau - g^i` and `ls[i] = l0 * g^i`, where `g = group_gen`. Both
            // sequences are powers of `g`, so a block can seed itself with `g^start`
            // instead of walking there from zero, which is what lets the fill
            // run in parallel.
            //
            // Same shape as `distribute_powers_and_mul_by_const` above.
            #[cfg(not(feature = "serial"))]
            let chunk = core::cmp::max(size / max_available_threads(), 1024);
            #[cfg(feature = "serial")]
            let chunk = core::cmp::max(size, 1);

            // The chunks run unordered, so each seeds itself rather than carrying `r` from
            // its predecessor. `chunk_gen^i` is the same seed as `g^(i*chunk)` from a
            // ladder over `log2(chunks)` bits instead of 64.
            let chunk_gen = self.group_gen.pow([chunk as u64]);
            cfg_chunks_mut!(u, chunk).zip(cfg_chunks_mut!(ls, chunk)).enumerate().for_each(
                |(i, (u_chunk, ls_chunk))| {
                    let mut r = chunk_gen.pow([i as u64]);
                    let mut l = l0 * r;
                    u_chunk.iter_mut().zip(ls_chunk.iter_mut()).for_each(|(tau_minus_r, l_i)| {
                        *tau_minus_r = tau - r;
                        *l_i = l;
                        r *= &self.group_gen;
                        l *= &self.group_gen;
                    });
                },
            );

            batch_inversion(u.as_mut_slice());
            cfg_iter_mut!(u, 1_000).zip_eq(ls).for_each(|(tau_minus_r, l)| {
                *tau_minus_r = l * *tau_minus_r;
            });
            u
        }
    }

    /// Return the sparse vanishing polynomial.
    pub fn vanishing_polynomial(&self) -> SparsePolynomial<F> {
        let coeffs = [(0, -F::one()), (self.size(), F::one())];
        SparsePolynomial::from_coefficients(coeffs)
    }

    /// This evaluates the vanishing polynomial for this domain at tau.
    /// For multiplicative subgroups, this polynomial is `z(X) = X^self.size -
    /// 1`.
    pub fn evaluate_vanishing_polynomial(&self, tau: F) -> F {
        tau.pow([self.size]) - F::one()
    }

    /// Return an iterator over the elements of the domain.
    pub fn elements(&self) -> Elements<F> {
        Elements { cur_elem: F::one(), cur_pow: 0, domain: *self }
    }

    /// The target polynomial is the zero polynomial in our
    /// evaluation domain, so we must perform division over
    /// a coset.
    pub fn divide_by_vanishing_poly_on_coset_in_place(&self, evals: &mut [F]) {
        let i = self.evaluate_vanishing_polynomial(F::multiplicative_generator()).inverse().unwrap();

        cfg_iter_mut!(evals).for_each(|eval| *eval *= &i);
    }

    /// Given an index in the `other` subdomain, return an index into this
    /// domain `self` This assumes the `other`'s elements are also `self`'s
    /// first elements
    pub fn reindex_by_subdomain(&self, other: &Self, index: usize) -> Result<usize> {
        ensure!(self.size() > other.size(), "other.size() must be smaller than self.size()");

        // Let this subgroup be G, and the subgroup we're re-indexing by be S.
        // Since its a subgroup, the 0th element of S is at index 0 in G, the first
        // element of S is at index |G|/|S|, the second at 2*|G|/|S|, etc.
        // Thus for an index i that corresponds to S, the index in G is i*|G|/|S|
        let period = self.size() / other.size();
        if index < other.size() {
            Ok(index * period)
        } else {
            // Let i now be the index of this element in G \ S
            // Let x be the number of elements in G \ S, for every element in S. Then x =
            // (|G|/|S| - 1). At index i in G \ S, the number of elements in S
            // that appear before the index in G to which i corresponds to, is
            // floor(i / x) + 1. The +1 is because index 0 of G is S_0, so the
            // position is offset by at least one. The floor(i / x) term is
            // because after x elements in G \ S, there is one more element from S
            // that will have appeared in G.
            let i = index - other.size();
            let x = period - 1;
            Ok(i + (i / x) + 1)
        }
    }

    /// Perform O(n) multiplication of two polynomials that are presented by
    /// their evaluations in the domain.
    /// Returns the evaluations of the product over the domain.
    pub fn mul_polynomials_in_evaluation_domain(&self, self_evals: Vec<F>, other_evals: &[F]) -> Result<Vec<F>> {
        let mut result = self_evals;

        ensure!(result.len() == other_evals.len());
        cfg_iter_mut!(result).zip_eq(other_evals).for_each(|(a, b)| *a *= b);

        Ok(result)
    }
}

impl<F: FftField> EvaluationDomain<F> {
    pub fn precompute_fft(&self) -> FFTPrecomputation<F> {
        execute_with_max_available_threads(|| FFTPrecomputation {
            roots: self.roots_of_unity(self.group_gen),
            domain: *self,
        })
    }

    pub fn precompute_ifft(&self) -> IFFTPrecomputation<F> {
        execute_with_max_available_threads(|| IFFTPrecomputation {
            inverse_roots: self.roots_of_unity(self.group_gen_inv),
            domain: *self,
        })
    }

    /// Runs an in-order transform on the device, and returns whether it did.
    /// A device error panics.
    ///
    /// The kernels are compiled for BLS12-377's `Fr` and read every buffer as
    /// one, so any other coefficient or field takes the host path.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    fn ntt_on_device<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        direction: snarkvm_algorithms_cuda::NTTDirection,
        ntt_type: snarkvm_algorithms_cuda::NTTType,
    ) -> bool {
        // SNP TODO: how to set threshold
        if self.size < 32
            || x_s.len() as u64 != self.size
            || !super::is_cuda_field::<T>()
            || !super::is_cuda_field::<F>()
        {
            return false;
        }
        let result = snarkvm_algorithms_cuda::NTT(
            self.size as usize,
            x_s,
            snarkvm_algorithms_cuda::NTTInputOutputOrder::NN,
            direction,
            ntt_type,
        );
        crate::cuda_must_succeed!(result, "ntt");
        true
    }

    pub(crate) fn in_order_fft_in_place<T: DomainCoeff<F>>(&self, x_s: &mut [T]) {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if self.ntt_on_device(
            x_s,
            snarkvm_algorithms_cuda::NTTDirection::Forward,
            snarkvm_algorithms_cuda::NTTType::Standard,
        ) {
            return;
        }

        let pc = self.precompute_fft();
        self.fft_helper_in_place_with_pc(x_s, FFTOrder::II, &pc)
    }

    pub fn in_order_fft_with_pc<T: DomainCoeff<F>>(&self, x_s: &[T], pc: &FFTPrecomputation<F>) -> Vec<T> {
        let mut x_s = x_s.to_vec();
        if self.size() != x_s.len() {
            x_s.extend(core::iter::repeat_n(T::zero(), self.size() - x_s.len()));
        }
        self.fft_helper_in_place_with_pc(&mut x_s, FFTOrder::II, pc);
        x_s
    }

    pub(crate) fn in_order_ifft_in_place<T: DomainCoeff<F>>(&self, x_s: &mut [T]) {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if self.ntt_on_device(
            x_s,
            snarkvm_algorithms_cuda::NTTDirection::Inverse,
            snarkvm_algorithms_cuda::NTTType::Standard,
        ) {
            return;
        }

        let pc = self.precompute_ifft();
        self.ifft_helper_in_place_with_pc(x_s, FFTOrder::II, &pc);
        cfg_iter_mut!(x_s, 1_000).for_each(|val| *val *= self.size_inv);
    }

    pub(crate) fn in_order_coset_ifft_in_place<T: DomainCoeff<F>>(&self, x_s: &mut [T]) {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if self.ntt_on_device(
            x_s,
            snarkvm_algorithms_cuda::NTTDirection::Inverse,
            snarkvm_algorithms_cuda::NTTType::Coset,
        ) {
            return;
        }

        let pc = self.precompute_ifft();
        self.ifft_helper_in_place_with_pc(x_s, FFTOrder::II, &pc);
        let coset_shift = self.generator_inv;
        Self::distribute_powers_and_mul_by_const(x_s, coset_shift, self.size_inv);
    }

    #[allow(unused)]
    pub(crate) fn in_order_fft_in_place_with_pc<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        pre_comp: &FFTPrecomputation<F>,
    ) {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if self.ntt_on_device(
            x_s,
            snarkvm_algorithms_cuda::NTTDirection::Forward,
            snarkvm_algorithms_cuda::NTTType::Standard,
        ) {
            return;
        }

        self.fft_helper_in_place_with_pc(x_s, FFTOrder::II, pre_comp)
    }

    pub(crate) fn out_order_fft_in_place_with_pc<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        pre_comp: &FFTPrecomputation<F>,
    ) {
        self.fft_helper_in_place_with_pc(x_s, FFTOrder::IO, pre_comp)
    }

    pub(crate) fn in_order_ifft_in_place_with_pc<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        pre_comp: &IFFTPrecomputation<F>,
    ) {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if self.ntt_on_device(
            x_s,
            snarkvm_algorithms_cuda::NTTDirection::Inverse,
            snarkvm_algorithms_cuda::NTTType::Standard,
        ) {
            return;
        }

        self.in_order_ifft_in_place_with_pc_on_host(x_s, pre_comp)
    }

    /// The in-order inverse on the host.
    ///
    /// Under `cuda` on x86_64, the `in_order_*_in_place` and
    /// `in_order_*_in_place_with_pc` transforms run on the device for a domain
    /// of 32 or more over `Fr`, so they are not host references for a test. The
    /// host references are `in_order_fft_with_pc` (forward) and this (inverse).
    pub(crate) fn in_order_ifft_in_place_with_pc_on_host<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        pre_comp: &IFFTPrecomputation<F>,
    ) {
        self.ifft_helper_in_place_with_pc(x_s, FFTOrder::II, pre_comp);
        cfg_iter_mut!(x_s, 1_000).for_each(|val| *val *= self.size_inv);
    }

    pub(crate) fn out_order_ifft_in_place_with_pc<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        pre_comp: &IFFTPrecomputation<F>,
    ) {
        self.ifft_helper_in_place_with_pc(x_s, FFTOrder::OI, pre_comp);
        cfg_iter_mut!(x_s, 1_000).for_each(|val| *val *= self.size_inv);
    }

    #[allow(unused)]
    pub(crate) fn in_order_coset_ifft_in_place_with_pc<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        pre_comp: &IFFTPrecomputation<F>,
    ) {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if self.ntt_on_device(
            x_s,
            snarkvm_algorithms_cuda::NTTDirection::Inverse,
            snarkvm_algorithms_cuda::NTTType::Coset,
        ) {
            return;
        }

        self.ifft_helper_in_place_with_pc(x_s, FFTOrder::II, pre_comp);
        let coset_shift = self.generator_inv;
        Self::distribute_powers_and_mul_by_const(x_s, coset_shift, self.size_inv);
    }

    fn fft_helper_in_place_with_pc<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        ord: FFTOrder,
        pre_comp: &FFTPrecomputation<F>,
    ) {
        use FFTOrder::*;
        let pc = pre_comp.precomputation_for_subdomain(self).unwrap();

        let log_len = log2(x_s.len());

        if ord == OI {
            self.oi_helper_with_roots(x_s, &pc.roots);
        } else {
            self.io_helper_with_roots(x_s, &pc.roots);
        }

        if ord == II {
            derange_helper(x_s, log_len);
        }
    }

    // Handles doing an IFFT with handling of being in order and out of order.
    // The results here must all be divided by |x_s|,
    // which is left up to the caller to do.
    fn ifft_helper_in_place_with_pc<T: DomainCoeff<F>>(
        &self,
        x_s: &mut [T],
        ord: FFTOrder,
        pre_comp: &IFFTPrecomputation<F>,
    ) {
        use FFTOrder::*;
        let pc = pre_comp.precomputation_for_subdomain(self).unwrap();

        let log_len = log2(x_s.len());

        if ord == II {
            derange_helper(x_s, log_len);
        }

        if ord == IO {
            self.io_helper_with_roots(x_s, &pc.inverse_roots);
        } else {
            self.oi_helper_with_roots(x_s, &pc.inverse_roots);
        }
    }

    /// Computes the first `self.size / 2` roots of unity for the entire domain.
    /// e.g. for the domain [1, g, g^2, ..., g^{n - 1}], it computes
    // [1, g, g^2, ..., g^{(n/2) - 1}]
    #[cfg(feature = "serial")]
    pub fn roots_of_unity(&self, root: F) -> Vec<F> {
        compute_powers_serial((self.size as usize) / 2, root)
    }

    /// Computes the first `self.size / 2` roots of unity.
    #[cfg(not(feature = "serial"))]
    pub fn roots_of_unity(&self, root: F) -> Vec<F> {
        // TODO: check if this method can replace parallel compute powers.
        let log_size = log2(self.size as usize);
        // early exit for short inputs
        if log_size <= LOG_ROOTS_OF_UNITY_PARALLEL_SIZE {
            compute_powers_serial((self.size as usize) / 2, root)
        } else {
            let mut temp = root;
            // w, w^2, w^4, w^8, ..., w^(2^(log_size - 1))
            let log_powers: Vec<F> = (0..(log_size - 1))
                .map(|_| {
                    let old_value = temp;
                    temp.square_in_place();
                    old_value
                })
                .collect();

            // allocate the return array and start the recursion
            let mut powers = vec![F::zero(); 1 << (log_size - 1)];
            Self::roots_of_unity_recursive(&mut powers, &log_powers);
            powers
        }
    }

    #[cfg(not(feature = "serial"))]
    fn roots_of_unity_recursive(out: &mut [F], log_powers: &[F]) {
        assert_eq!(out.len(), 1 << log_powers.len());
        // base case: just compute the powers sequentially,
        // g = log_powers[0], out = [1, g, g^2, ...]
        if log_powers.len() <= LOG_ROOTS_OF_UNITY_PARALLEL_SIZE as usize {
            out[0] = F::one();
            for idx in 1..out.len() {
                out[idx] = out[idx - 1] * log_powers[0];
            }
            return;
        }

        // recursive case:
        // 1. split log_powers in half
        let (lr_lo, lr_hi) = log_powers.split_at(log_powers.len().div_ceil(2));
        let mut scr_lo = vec![F::default(); 1 << lr_lo.len()];
        let mut scr_hi = vec![F::default(); 1 << lr_hi.len()];
        // 2. compute each half individually
        rayon::join(
            || Self::roots_of_unity_recursive(&mut scr_lo, lr_lo),
            || Self::roots_of_unity_recursive(&mut scr_hi, lr_hi),
        );
        // 3. recombine halves
        // At this point, out is a blank slice.
        out.par_chunks_mut(scr_lo.len()).zip(&scr_hi).for_each(|(out_chunk, scr_hi)| {
            for (out_elem, scr_lo) in out_chunk.iter_mut().zip(&scr_lo) {
                *out_elem = *scr_hi * scr_lo;
            }
        });
    }

    #[inline(always)]
    fn butterfly_fn_io<T: DomainCoeff<F>>(((lo, hi), root): ((&mut T, &mut T), &F)) {
        let neg = *lo - *hi;
        *lo += *hi;
        *hi = neg;
        *hi *= *root;
    }

    #[inline(always)]
    fn butterfly_fn_oi<T: DomainCoeff<F>>(((lo, hi), root): ((&mut T, &mut T), &F)) {
        *hi *= *root;
        let neg = *lo - *hi;
        *lo += *hi;
        *hi = neg;
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_butterfly<T: DomainCoeff<F>, G: Fn(((&mut T, &mut T), &F)) + Copy + Sync + Send>(
        g: G,
        xi: &mut [T],
        roots: &[F],
        step: usize,
        chunk_size: usize,
        num_chunks: usize,
        max_threads: usize,
        gap: usize,
    ) {
        cfg_chunks_mut!(xi, chunk_size).for_each(|cxi| {
            let (lo, hi) = cxi.split_at_mut(gap);
            // If the chunk is sufficiently big that parallelism helps,
            // we parallelize the butterfly operation within the chunk.

            if gap > MIN_GAP_SIZE_FOR_PARALLELISATION && num_chunks < max_threads {
                cfg_iter_mut!(lo, 1000).zip(hi).zip(cfg_iter!(roots, 1000).step_by(step)).for_each(g);
            } else {
                lo.iter_mut().zip(hi).zip(roots.iter().step_by(step)).for_each(g);
            }
        });
    }

    #[allow(clippy::unnecessary_to_owned)]
    fn io_helper_with_roots<T: DomainCoeff<F>>(&self, xi: &mut [T], roots: &[F]) {
        let mut roots = std::borrow::Cow::Borrowed(roots);

        let mut step = 1;
        let mut first = true;

        #[cfg(not(feature = "serial"))]
        let max_threads = snarkvm_utilities::parallel::max_available_threads();
        #[cfg(feature = "serial")]
        let max_threads = 1;

        let mut gap = xi.len() / 2;
        while gap > 0 {
            // each butterfly cluster uses 2*gap positions
            let chunk_size = 2 * gap;
            let num_chunks = xi.len() / chunk_size;

            // Only compact roots to achieve cache locality/compactness if
            // the roots lookup is done a significant amount of times
            // Which also implies a large lookup stride.
            if num_chunks >= MIN_NUM_CHUNKS_FOR_COMPACTION {
                if !first {
                    roots = Cow::Owned(cfg_into_iter!(roots.into_owned()).step_by(step * 2).collect());
                }
                step = 1;
                roots.to_mut().shrink_to_fit();
            } else {
                step = num_chunks;
            }
            first = false;

            Self::apply_butterfly(
                Self::butterfly_fn_io,
                xi,
                &roots[..],
                step,
                chunk_size,
                num_chunks,
                max_threads,
                gap,
            );

            gap /= 2;
        }
    }

    fn oi_helper_with_roots<T: DomainCoeff<F>>(&self, xi: &mut [T], roots_cache: &[F]) {
        // The `cmp::min` is only necessary for the case where
        // `MIN_NUM_CHUNKS_FOR_COMPACTION = 1`. Else, notice that we compact
        // the roots cache by a stride of at least `MIN_NUM_CHUNKS_FOR_COMPACTION`.

        let compaction_max_size =
            core::cmp::min(roots_cache.len() / 2, roots_cache.len() / MIN_NUM_CHUNKS_FOR_COMPACTION);
        let mut compacted_roots = vec![F::default(); compaction_max_size];

        #[cfg(not(feature = "serial"))]
        let max_threads = snarkvm_utilities::parallel::max_available_threads();
        #[cfg(feature = "serial")]
        let max_threads = 1;

        let mut gap = 1;
        while gap < xi.len() {
            // each butterfly cluster uses 2*gap positions
            let chunk_size = 2 * gap;
            let num_chunks = xi.len() / chunk_size;

            // Only compact roots to achieve cache locality/compactness if
            // the roots lookup is done a significant amount of times
            // Which also implies a large lookup stride.
            let (roots, step) = if num_chunks >= MIN_NUM_CHUNKS_FOR_COMPACTION && gap < xi.len() / 2 {
                cfg_iter_mut!(compacted_roots[..gap], 1_000)
                    .zip(cfg_iter!(roots_cache[..(gap * num_chunks)], 1_000).step_by(num_chunks))
                    .for_each(|(a, b)| *a = *b);
                (&compacted_roots[..gap], 1)
            } else {
                (roots_cache, num_chunks)
            };

            Self::apply_butterfly(Self::butterfly_fn_oi, xi, roots, step, chunk_size, num_chunks, max_threads, gap);

            gap *= 2;
        }
    }
}

/// The minimum number of chunks at which root compaction
/// is beneficial.
const MIN_NUM_CHUNKS_FOR_COMPACTION: usize = 1 << 7;

/// The minimum size of a chunk at which parallelization of `butterfly`s is
/// beneficial. This value was chosen empirically.
const MIN_GAP_SIZE_FOR_PARALLELISATION: usize = 1 << 10;

// minimum size at which to parallelize.
#[cfg(not(feature = "serial"))]
const LOG_ROOTS_OF_UNITY_PARALLEL_SIZE: u32 = 7;

#[inline]
pub(super) fn bitrev(a: u64, log_len: u32) -> u64 {
    a.reverse_bits() >> (64 - log_len)
}

pub(crate) fn derange<T>(xi: &mut [T]) {
    derange_helper(xi, log2(xi.len()))
}

fn derange_helper<T>(xi: &mut [T], log_len: u32) {
    for idx in 1..(xi.len() as u64 - 1) {
        let ridx = bitrev(idx, log_len);
        if idx < ridx {
            xi.swap(idx as usize, ridx as usize);
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum FFTOrder {
    /// Both the input and the output of the FFT must be in-order.
    II,
    /// The input of the FFT must be in-order, but the output does not have to
    /// be.
    IO,
    /// The input of the FFT can be out of order, but the output must be
    /// in-order.
    OI,
}

pub(crate) fn compute_powers_serial<F: Field>(size: usize, root: F) -> Vec<F> {
    compute_powers_and_mul_by_const_serial(size, root, F::one())
}

pub(crate) fn compute_powers_and_mul_by_const_serial<F: Field>(size: usize, root: F, c: F) -> Vec<F> {
    let mut value = c;
    (0..size)
        .map(|_| {
            let old_value = value;
            value *= root;
            old_value
        })
        .collect()
}

#[allow(unused)]
#[cfg(not(feature = "serial"))]
pub(crate) fn compute_powers<F: Field>(size: usize, g: F) -> Vec<F> {
    if size < MIN_PARALLEL_CHUNK_SIZE {
        return compute_powers_serial(size, g);
    }
    // compute the number of threads we will be using.
    let num_cpus_available = max_available_threads();
    let num_elem_per_thread = core::cmp::max(size / num_cpus_available, MIN_PARALLEL_CHUNK_SIZE);
    let num_cpus_used = size / num_elem_per_thread;

    // Split up the powers to compute across each thread evenly.
    let res: Vec<F> = (0..num_cpus_used)
        .into_par_iter()
        .flat_map(|i| {
            let offset = g.pow([(i * num_elem_per_thread) as u64]);
            // Compute the size that this chunks' output should be
            // (num_elem_per_thread, unless there are less than num_elem_per_thread elements
            // remaining)
            let num_elements_to_compute = core::cmp::min(size - i * num_elem_per_thread, num_elem_per_thread);
            compute_powers_and_mul_by_const_serial(num_elements_to_compute, g, offset)
        })
        .collect();
    res
}

/// An iterator over the elements of the domain.
#[derive(Clone)]
pub struct Elements<F: FftField> {
    cur_elem: F,
    cur_pow: u64,
    domain: EvaluationDomain<F>,
}

impl<F: FftField> Iterator for Elements<F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        if self.cur_pow == self.domain.size {
            None
        } else {
            let cur_elem = self.cur_elem;
            self.cur_elem *= &self.domain.group_gen;
            self.cur_pow += 1;
            Some(cur_elem)
        }
    }
}

/// An iterator over the elements of the domain.
#[derive(Clone, Eq, PartialEq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct FFTPrecomputation<F: FftField> {
    roots: Vec<F>,
    domain: EvaluationDomain<F>,
}

impl<F: FftField> FFTPrecomputation<F> {
    pub fn to_ifft_precomputation(&self) -> IFFTPrecomputation<F> {
        let mut inverse_roots = self.roots.clone();
        snarkvm_fields::batch_inversion(&mut inverse_roots);
        IFFTPrecomputation { inverse_roots, domain: self.domain }
    }

    pub fn precomputation_for_subdomain<'a>(&'a self, domain: &EvaluationDomain<F>) -> Option<Cow<'a, Self>> {
        if domain.size() == 1 {
            return Some(Cow::Owned(Self { roots: vec![], domain: *domain }));
        }
        if &self.domain == domain {
            Some(Cow::Borrowed(self))
        } else if domain.size() < self.domain.size() {
            let size_ratio = self.domain.size() / domain.size();
            let roots = self.roots.iter().step_by(size_ratio).copied().collect();
            Some(Cow::Owned(Self { roots, domain: *domain }))
        } else {
            None
        }
    }
}

/// An iterator over the elements of the domain.
#[derive(Clone, Eq, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct IFFTPrecomputation<F: FftField> {
    inverse_roots: Vec<F>,
    domain: EvaluationDomain<F>,
}

impl<F: FftField> IFFTPrecomputation<F> {
    pub fn precomputation_for_subdomain<'a>(&'a self, domain: &EvaluationDomain<F>) -> Option<Cow<'a, Self>> {
        if domain.size() == 1 {
            return Some(Cow::Owned(Self { inverse_roots: vec![], domain: *domain }));
        }
        if &self.domain == domain {
            Some(Cow::Borrowed(self))
        } else if domain.size() < self.domain.size() {
            let size_ratio = self.domain.size() / domain.size();
            let inverse_roots = self.inverse_roots.iter().step_by(size_ratio).copied().collect();
            Some(Cow::Owned(Self { inverse_roots, domain: *domain }))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    use crate::fft::domain::FFTOrder;
    use crate::fft::{DensePolynomial, EvaluationDomain};
    use rand::RngExt;
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::{FftField, Field, One, Zero};
    use snarkvm_utilities::{TestRng, Uniform};

    #[test]
    fn vanishing_polynomial_evaluation() {
        let rng = &mut TestRng::default();
        for coeffs in 0..10 {
            let domain = EvaluationDomain::<Fr>::new(coeffs).unwrap();
            let z = domain.vanishing_polynomial();
            for _ in 0..100 {
                let point = rng.random();
                assert_eq!(z.evaluate(point), domain.evaluate_vanishing_polynomial(point))
            }
        }
    }

    #[test]
    fn vanishing_polynomial_vanishes_on_domain() {
        for coeffs in 0..1000 {
            let domain = EvaluationDomain::<Fr>::new(coeffs).unwrap();
            let z = domain.vanishing_polynomial();
            for point in domain.elements() {
                assert!(z.evaluate(point).is_zero())
            }
        }
    }

    #[test]
    fn size_of_elements() {
        for coeffs in 1..10 {
            let size = 1 << coeffs;
            let domain = EvaluationDomain::<Fr>::new(size).unwrap();
            let domain_size = domain.size();
            assert_eq!(domain_size, domain.elements().count());
        }
    }

    #[test]
    fn elements_contents() {
        for coeffs in 1..10 {
            let size = 1 << coeffs;
            let domain = EvaluationDomain::<Fr>::new(size).unwrap();
            for (i, element) in domain.elements().enumerate() {
                assert_eq!(element, domain.group_gen.pow([i as u64]));
            }
        }
    }

    /// Test that lagrange interpolation for a random polynomial at a random
    /// point works.
    #[test]
    fn non_systematic_lagrange_coefficients_test() {
        let mut rng = TestRng::default();
        for domain_dimension in 1..10 {
            let domain_size = 1 << domain_dimension;
            let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
            // Get random point & lagrange coefficients
            let random_point = Fr::rand(&mut rng);
            let lagrange_coefficients = domain.evaluate_all_lagrange_coefficients(random_point);

            // Sample the random polynomial, evaluate it over the domain and the random
            // point.
            let random_polynomial = DensePolynomial::<Fr>::rand(domain_size - 1, &mut rng);
            let polynomial_evaluations = domain.fft(random_polynomial.coeffs());
            let actual_evaluations = random_polynomial.evaluate(random_point);

            // Do lagrange interpolation, and compare against the actual evaluation
            let mut interpolated_evaluation = Fr::zero();
            for i in 0..domain_size {
                interpolated_evaluation += lagrange_coefficients[i] * polynomial_evaluations[i];
            }
            assert_eq!(actual_evaluations, interpolated_evaluation);
        }
    }

    /// Test that lagrange coefficients for a point in the domain is correct.
    #[test]
    fn systematic_lagrange_coefficients_test() {
        // This runs in time O(N^2) in the domain size, so keep the domain dimension
        // low. We generate lagrange coefficients for each element in the
        // domain.
        for domain_dimension in 1..5 {
            let domain_size = 1 << domain_dimension;
            let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let all_domain_elements: Vec<Fr> = domain.elements().collect();
            for (i, domain_element) in all_domain_elements.iter().enumerate().take(domain_size) {
                let lagrange_coefficients = domain.evaluate_all_lagrange_coefficients(*domain_element);
                for (j, lagrange_coefficient) in lagrange_coefficients.iter().enumerate().take(domain_size) {
                    // Lagrange coefficient for the evaluation point, which should be 1
                    if i == j {
                        assert_eq!(*lagrange_coefficient, Fr::one());
                    } else {
                        assert_eq!(*lagrange_coefficient, Fr::zero());
                    }
                }
            }
        }
    }

    /// Tests that the roots of unity result is the same as domain.elements().
    #[test]
    fn test_roots_of_unity() {
        let max_degree = 10;
        for log_domain_size in 0..max_degree {
            let domain_size = 1 << log_domain_size;
            let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let actual_roots = domain.roots_of_unity(domain.group_gen);
            for &value in &actual_roots {
                assert!(domain.evaluate_vanishing_polynomial(value).is_zero());
            }
            let expected_roots_elements = domain.elements();
            for (expected, &actual) in expected_roots_elements.zip(&actual_roots) {
                assert_eq!(expected, actual);
            }
            assert_eq!(actual_roots.len(), domain_size / 2);
        }
    }

    /// Tests that the FFTs output the correct result.
    #[test]
    fn test_fft_correctness() {
        // This assumes a correct polynomial evaluation at point procedure.
        // It tests consistency of FFT/IFFT, and coset_fft/coset_ifft,
        // along with testing that each individual evaluation is correct.

        let mut rng = TestRng::default();

        // Runs in time O(degree^2)
        let log_degree = 5;
        let degree = 1 << log_degree;
        let random_polynomial = DensePolynomial::<Fr>::rand(degree - 1, &mut rng);

        for log_domain_size in log_degree..(log_degree + 2) {
            let domain_size = 1 << log_domain_size;
            let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let polynomial_evaluations = domain.fft(&random_polynomial.coeffs);
            let polynomial_coset_evaluations = domain.coset_fft(&random_polynomial.coeffs);
            for (i, x) in domain.elements().enumerate() {
                let coset_x = Fr::multiplicative_generator() * x;

                assert_eq!(polynomial_evaluations[i], random_polynomial.evaluate(x));
                assert_eq!(polynomial_coset_evaluations[i], random_polynomial.evaluate(coset_x));
            }

            let randon_polynomial_from_subgroup =
                DensePolynomial::from_coefficients_vec(domain.ifft(&polynomial_evaluations));
            let random_polynomial_from_coset =
                DensePolynomial::from_coefficients_vec(domain.coset_ifft(&polynomial_coset_evaluations));

            assert_eq!(
                random_polynomial, randon_polynomial_from_subgroup,
                "degree = {degree}, domain size = {domain_size}"
            );
            assert_eq!(
                random_polynomial, random_polynomial_from_coset,
                "degree = {degree}, domain size = {domain_size}"
            );
        }
    }

    /// Tests that FFT precomputation is correctly subdomained
    #[test]
    fn test_fft_precomputation() {
        for i in 1..10 {
            let big_domain = EvaluationDomain::<Fr>::new(i).unwrap();
            let pc = big_domain.precompute_fft();
            for j in 1..i {
                let small_domain = EvaluationDomain::<Fr>::new(j).unwrap();
                let small_pc = small_domain.precompute_fft();
                assert_eq!(pc.precomputation_for_subdomain(&small_domain).unwrap().as_ref(), &small_pc);
            }
        }
    }

    /// Tests that IFFT precomputation is correctly subdomained
    #[test]
    fn test_ifft_precomputation() {
        for i in 1..10 {
            let big_domain = EvaluationDomain::<Fr>::new(i).unwrap();
            let pc = big_domain.precompute_ifft();
            for j in 1..i {
                let small_domain = EvaluationDomain::<Fr>::new(j).unwrap();
                let small_pc = small_domain.precompute_ifft();
                assert_eq!(pc.precomputation_for_subdomain(&small_domain).unwrap().as_ref(), &small_pc);
            }
        }
    }

    /// Tests that IFFT precomputation can be correctly computed from
    /// FFT precomputation
    #[test]
    fn test_ifft_precomputation_from_fft() {
        for i in 1..10 {
            let domain = EvaluationDomain::<Fr>::new(i).unwrap();
            let pc = domain.precompute_ifft();
            let fft_pc = domain.precompute_fft();
            assert_eq!(pc, fft_pc.to_ifft_precomputation())
        }
    }

    /// A multiply of two polynomials over `max_domain()` fits the pool.
    ///
    /// `PolyMul` is the guard that binds: its product domain is
    /// `2 * max_domain()`, which is exactly its `pool / 4` limit.
    /// `snarkvm_t::NTT` admits eight times the bound, so an FFT here would
    /// prove nothing.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn test_max_domain_is_a_bound_polymul_accepts_cuda() {
        use crate::fft::polynomial::PolyMultiplier;

        let max = snarkvm_algorithms_cuda::max_domain();
        assert!(max > 0, "no usable pool: either no device, or its construction failed");

        let mut rng = TestRng::default();
        let a = DensePolynomial::<Fr>::rand(max - 1, &mut rng);
        let b = DensePolynomial::<Fr>::rand(max - 1, &mut rng);
        let expected_degree = a.degree() + b.degree();

        let mut multiplier = PolyMultiplier::new();
        multiplier.add_polynomial_ref(&a, "a");
        multiplier.add_polynomial_ref(&b, "b");
        let product = multiplier.multiply().expect("the product domain is within the pool");

        assert_eq!(product.degree(), expected_degree, "the multiply ran but did not produce the product");
    }

    /// One step past `PolyMul`'s pool guard is refused with
    /// `cudaErrorNotSupported`, and the error names the domain and the limit it
    /// exceeds.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn test_polymul_pool_guard_names_the_domain_and_limit_cuda() {
        let pool = snarkvm_algorithms_cuda::pool_elements();
        assert!(pool > 0, "no usable pool: either no device, or its construction failed");

        let (limit, one) = (pool / 4, [Fr::one()]);
        let domain = 2 * limit;
        let err = snarkvm_algorithms_cuda::polymul(domain, &[&one, &one], &[], &Fr::zero())
            .expect_err("a multiply larger than the pool must be refused");
        assert_eq!(err.code, 801);
        assert_eq!(
            String::from(&err),
            format!("PolyMul domain of {domain} exceeds the device pool's limit of {limit}")
        );
    }

    /// Tests that the FFTs output the correct result.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn test_fft_correctness_cuda() {
        let mut rng = TestRng::default();
        for log_domain in 2..20 {
            println!("Testing domain size {log_domain}");
            let domain_size = 1 << log_domain;
            let random_polynomial = DensePolynomial::<Fr>::rand(domain_size - 1, &mut rng);
            let mut polynomial_evaluations = random_polynomial.coeffs.clone();
            let mut polynomial_evaluations_cuda = random_polynomial.coeffs.clone();

            let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let pc = domain.precompute_fft();
            domain.fft_helper_in_place_with_pc(&mut polynomial_evaluations, FFTOrder::II, &pc);

            if snarkvm_algorithms_cuda::NTT::<Fr>(
                domain_size,
                &mut polynomial_evaluations_cuda,
                snarkvm_algorithms_cuda::NTTInputOutputOrder::NN,
                snarkvm_algorithms_cuda::NTTDirection::Forward,
                snarkvm_algorithms_cuda::NTTType::Standard,
            )
            .is_err()
            {
                println!("cuda error!");
            }

            assert_eq!(polynomial_evaluations, polynomial_evaluations_cuda, "domain size = {domain_size}");

            // iNTT
            if snarkvm_algorithms_cuda::NTT::<Fr>(
                domain_size,
                &mut polynomial_evaluations_cuda,
                snarkvm_algorithms_cuda::NTTInputOutputOrder::NN,
                snarkvm_algorithms_cuda::NTTDirection::Inverse,
                snarkvm_algorithms_cuda::NTTType::Standard,
            )
            .is_err()
            {
                println!("cuda error!");
            }
            assert_eq!(random_polynomial.coeffs, polynomial_evaluations_cuda, "domain size = {domain_size}");

            // Coset NTT
            polynomial_evaluations = random_polynomial.coeffs.clone();
            let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let pc = domain.precompute_fft();
            EvaluationDomain::<Fr>::distribute_powers(&mut polynomial_evaluations, Fr::multiplicative_generator());
            domain.fft_helper_in_place_with_pc(&mut polynomial_evaluations, FFTOrder::II, &pc);

            if snarkvm_algorithms_cuda::NTT::<Fr>(
                domain_size,
                &mut polynomial_evaluations_cuda,
                snarkvm_algorithms_cuda::NTTInputOutputOrder::NN,
                snarkvm_algorithms_cuda::NTTDirection::Forward,
                snarkvm_algorithms_cuda::NTTType::Coset,
            )
            .is_err()
            {
                println!("cuda error!");
            }

            assert_eq!(polynomial_evaluations, polynomial_evaluations_cuda, "domain size = {domain_size}");

            // Coset iNTT
            if snarkvm_algorithms_cuda::NTT::<Fr>(
                domain_size,
                &mut polynomial_evaluations_cuda,
                snarkvm_algorithms_cuda::NTTInputOutputOrder::NN,
                snarkvm_algorithms_cuda::NTTDirection::Inverse,
                snarkvm_algorithms_cuda::NTTType::Coset,
            )
            .is_err()
            {
                println!("cuda error!");
            }
            assert_eq!(random_polynomial.coeffs, polynomial_evaluations_cuda, "domain size = {domain_size}");
        }
    }

    /// A `DomainCoeff` as wide as `Fr` and not `Fr`.
    ///
    /// Scaling multiplies twice, so a transform over it differs from one over
    /// the same bytes as `Fr`.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    struct Squared(Fr);

    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    mod squared_impls {
        use super::{Fr, Squared};
        use snarkvm_fields::Zero;

        impl Zero for Squared {
            fn zero() -> Self {
                Self(Fr::zero())
            }

            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl core::ops::Add for Squared {
            type Output = Self;

            fn add(self, other: Self) -> Self {
                Self(self.0 + other.0)
            }
        }

        impl core::ops::Sub for Squared {
            type Output = Self;

            fn sub(self, other: Self) -> Self {
                Self(self.0 - other.0)
            }
        }

        impl core::ops::AddAssign for Squared {
            fn add_assign(&mut self, other: Self) {
                self.0 += other.0;
            }
        }

        impl core::ops::SubAssign for Squared {
            fn sub_assign(&mut self, other: Self) {
                self.0 -= other.0;
            }
        }

        impl core::ops::MulAssign<Fr> for Squared {
            fn mul_assign(&mut self, f: Fr) {
                self.0 *= f;
                self.0 *= f;
            }
        }
    }

    /// A coefficient the width of `Fr` and not `Fr` must take the host path.
    ///
    /// The kernel reads any buffer as `fr_t`, so on the device it would give a
    /// wrong answer without an error.
    #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
    #[test]
    fn a_type_the_width_of_fr_still_takes_the_host_path() {
        assert_eq!(
            core::mem::size_of::<Squared>(),
            core::mem::size_of::<Fr>(),
            "the fixture must be as wide as `Fr` to show that a width check is not enough"
        );

        let mut rng = TestRng::default();
        let domain = EvaluationDomain::<Fr>::new(64).unwrap();
        let pc = domain.precompute_ifft();
        let values: Vec<Squared> = (0..domain.size()).map(|_| Squared(Fr::rand(&mut rng))).collect();

        let mut got = values.clone();
        domain.in_order_ifft_in_place_with_pc(&mut got, &pc);
        let mut want = values.clone();
        domain.in_order_ifft_in_place_with_pc_on_host(&mut want, &pc);

        assert_eq!(got, want, "a non-Fr coefficient must not reach the device");

        // The assertion above means something only while the fixture's
        // arithmetic differs from `Fr`'s.
        let mut as_fr: Vec<Fr> = values.iter().map(|s| s.0).collect();
        domain.in_order_ifft_in_place_with_pc_on_host(&mut as_fr, &pc);
        assert_ne!(
            got.iter().map(|s| s.0).collect::<Vec<_>>(),
            as_fr,
            "the fixture must not agree with `Fr` over the same bytes, or it distinguishes nothing"
        );
    }

    #[test]
    fn test_reindex_by_subdomain_is_a_permutation() {
        // `(4, 2)` makes `period - 1` equal 1, and `(8, 1)` is the smallest subdomain.
        for (big, small) in [(8usize, 2usize), (16, 4), (32, 8), (64, 2), (128, 32), (4, 2), (8, 1)] {
            let g = EvaluationDomain::<Fr>::new(big).unwrap();
            let s = EvaluationDomain::<Fr>::new(small).unwrap();
            let mut image = (0..g.size()).map(|i| g.reindex_by_subdomain(&s, i).unwrap()).collect::<Vec<_>>();
            // The subdomain's elements are every `period`-th element of the domain.
            for (i, j) in image.iter().enumerate().take(s.size()) {
                assert_eq!(*j, i * (big / small), "big={big} small={small} i={i}");
            }
            image.sort_unstable();
            assert_eq!(image, (0..g.size()).collect::<Vec<_>>(), "big={big} small={small} not a permutation");
        }
    }
}
