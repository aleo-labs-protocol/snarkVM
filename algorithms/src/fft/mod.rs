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

//! This crate implements functions for manipulating polynomials over finite
//! fields, including FFTs.

pub mod domain;
pub use domain::EvaluationDomain;

pub mod evaluations;
pub use evaluations::Evaluations;

pub mod polynomial;
pub use polynomial::{DensePolynomial, Polynomial, SparsePolynomial};

#[cfg(test)]
mod tests;

use snarkvm_fields::FftField;

/// Whether the CUDA kernels, which are compiled for BLS12-377's `Fr`, can read
/// a buffer of `T`.
#[cfg(all(feature = "cuda", target_arch = "x86_64"))]
pub(crate) fn is_cuda_field<T: 'static>() -> bool {
    core::any::TypeId::of::<T>() == core::any::TypeId::of::<snarkvm_curves::bls12_377::Fr>()
}

/// Types that can be FFT-ed must implement this trait.
pub trait DomainCoeff<F: FftField>:
    'static
    + Copy
    + Send
    + Sync
    + core::ops::Add<Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::AddAssign
    + core::ops::SubAssign
    + snarkvm_fields::Zero
    + core::ops::MulAssign<F>
{
}

impl<T, F> DomainCoeff<F> for T
where
    F: FftField,
    T: 'static
        + Copy
        + Send
        + Sync
        + snarkvm_fields::Zero
        + core::ops::AddAssign
        + core::ops::SubAssign
        + core::ops::MulAssign<F>
        + core::ops::Add<Output = Self>
        + core::ops::Sub<Output = Self>,
{
}
