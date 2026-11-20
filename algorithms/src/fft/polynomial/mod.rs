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

//! Work with sparse and dense polynomials.

use crate::fft::{EvaluationDomain, Evaluations};
use Polynomial::*;
use snarkvm_fields::{Field, PrimeField};
use snarkvm_utilities::{SerializationError, cfg_iter_mut, serialize::*};

use anyhow::{Result, ensure};
use std::{borrow::Cow, convert::TryInto};

use rayon::prelude::*;

mod dense;
pub use dense::DensePolynomial;

mod sparse;
pub use sparse::SparsePolynomial;

mod multiplier;
pub use multiplier::*;

/// Represents either a sparse polynomial or a dense one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Polynomial<'a, F: Field> {
    /// Represents the case where `self` is a sparse polynomial
    Sparse(Cow<'a, SparsePolynomial<F>>),
    /// Represents the case where `self` is a dense polynomial
    Dense(Cow<'a, DensePolynomial<F>>),
}

impl<F: Field> CanonicalSerialize for Polynomial<'_, F> {
    fn serialize_with_mode<W: Write>(&self, writer: W, compress: Compress) -> Result<(), SerializationError> {
        match self {
            Sparse(p) => {
                let p: DensePolynomial<F> = p.clone().into_owned().into();
                CanonicalSerialize::serialize_with_mode(&p.coeffs, writer, compress)
            }
            Dense(p) => CanonicalSerialize::serialize_with_mode(&p.coeffs, writer, compress),
        }
    }

    fn serialized_size(&self, mode: Compress) -> usize {
        match self {
            Sparse(p) => {
                let p: DensePolynomial<F> = p.clone().into_owned().into();
                p.serialized_size(mode)
            }
            Dense(p) => p.serialized_size(mode),
        }
    }
}

impl<F: Field> Valid for Polynomial<'_, F> {
    fn check(&self) -> Result<(), SerializationError> {
        // Check that the polynomial contains a trailing zero coefficient.
        let has_trailing_zero = match self {
            Sparse(p) => p.coeffs().last().map(|(_, c)| c.is_zero()),
            Dense(p) => p.coeffs.last().map(|c| c.is_zero()),
        };
        // Fail if the trailing coefficient is zero.
        match has_trailing_zero {
            Some(true) => Err(SerializationError::InvalidData),
            Some(false) | None => Ok(()),
        }
    }
}

impl<F: Field> CanonicalDeserialize for Polynomial<'_, F> {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        DensePolynomial::<F>::deserialize_with_mode(reader, compress, validate).map(|e| Self::Dense(Cow::Owned(e)))
    }
}

impl<F: Field> From<DensePolynomial<F>> for Polynomial<'_, F> {
    fn from(other: DensePolynomial<F>) -> Self {
        Dense(Cow::Owned(other))
    }
}

impl<'a, F: Field> From<&'a DensePolynomial<F>> for Polynomial<'a, F> {
    fn from(other: &'a DensePolynomial<F>) -> Self {
        Dense(Cow::Borrowed(other))
    }
}

impl<F: Field> From<SparsePolynomial<F>> for Polynomial<'_, F> {
    fn from(other: SparsePolynomial<F>) -> Self {
        Sparse(Cow::Owned(other))
    }
}

impl<'a, F: Field> From<&'a SparsePolynomial<F>> for Polynomial<'a, F> {
    fn from(other: &'a SparsePolynomial<F>) -> Self {
        Sparse(Cow::Borrowed(other))
    }
}

#[allow(clippy::from_over_into)]
impl<F: Field> Into<DensePolynomial<F>> for Polynomial<'_, F> {
    fn into(self) -> DensePolynomial<F> {
        match self {
            Dense(p) => p.into_owned(),
            Sparse(p) => p.into_owned().into(),
        }
    }
}

impl<F: Field> TryInto<SparsePolynomial<F>> for Polynomial<'_, F> {
    type Error = ();

    fn try_into(self) -> Result<SparsePolynomial<F>, ()> {
        match self {
            Sparse(p) => Ok(p.into_owned()),
            _ => Err(()),
        }
    }
}

impl<'a, F: Field> Polynomial<'a, F> {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Sparse(Cow::Owned(SparsePolynomial::zero()))
    }

    /// Checks if the given polynomial is zero.
    pub fn is_zero(&self) -> bool {
        match self {
            Sparse(s) => s.is_zero(),
            Dense(d) => d.is_zero(),
        }
    }

    /// Return the degree of `self.
    pub fn degree(&self) -> usize {
        match self {
            Sparse(s) => s.degree(),
            Dense(d) => d.degree(),
        }
    }

    #[inline]
    pub fn leading_coefficient(&self) -> Option<&F> {
        match self {
            Sparse(p) => p.coeffs().last().map(|(_, c)| c),
            Dense(p) => p.last(),
        }
    }

    #[inline]
    pub fn as_dense(&self) -> Option<&DensePolynomial<F>> {
        match self {
            Dense(p) => Some(p.as_ref()),
            _ => None,
        }
    }

    #[inline]
    pub fn to_dense(&self) -> Cow<'_, DensePolynomial<F>> {
        match self {
            Dense(p) => Cow::Borrowed(p.as_ref()),
            Sparse(p) => Cow::Owned(p.clone().into_owned().into()),
        }
    }

    #[inline]
    pub fn as_dense_mut(&mut self) -> Option<&mut DensePolynomial<F>> {
        match self {
            Dense(p) => Some(p.to_mut()),
            _ => None,
        }
    }

    #[inline]
    pub fn as_sparse(&self) -> Option<&SparsePolynomial<F>> {
        match self {
            Sparse(p) => Some(p.as_ref()),
            _ => None,
        }
    }

    #[inline]
    pub fn into_dense(&self) -> DensePolynomial<F> {
        self.clone().into()
    }

    #[inline]
    pub fn evaluate(&self, point: F) -> F {
        match self {
            Sparse(p) => p.evaluate(point),
            Dense(p) => p.evaluate(point),
        }
    }

    pub fn coeffs(&'a self) -> Box<dyn Iterator<Item = (usize, &'a F)> + 'a> {
        match self {
            Sparse(p) => Box::new(p.coeffs().map(|(c, f)| (*c, f))),
            Dense(p) => Box::new(p.coeffs.iter().enumerate()),
        }
    }

    /// Divide self by another (sparse or dense) polynomial, and returns the
    /// quotient and remainder.
    pub fn divide_with_q_and_r(&self, divisor: &Self) -> Result<(DensePolynomial<F>, DensePolynomial<F>)> {
        ensure!(!divisor.is_zero(), "Dividing by zero polynomial is undefined");

        if self.is_zero() {
            Ok((DensePolynomial::zero(), DensePolynomial::zero()))
        } else if self.degree() < divisor.degree() {
            Ok((DensePolynomial::zero(), self.clone().into()))
        } else {
            // Now we know that self.degree() >= divisor.degree();
            let mut quotient = vec![F::zero(); self.degree() - divisor.degree() + 1];
            let mut remainder: DensePolynomial<F> = self.clone().into();
            // Can unwrap here because we know self is not zero.
            let divisor_leading_inv = divisor.leading_coefficient().unwrap().inverse().unwrap();
            while !remainder.is_zero() && remainder.degree() >= divisor.degree() {
                let cur_q_coeff = *remainder.coeffs.last().unwrap() * divisor_leading_inv;
                let cur_q_degree = remainder.degree() - divisor.degree();
                quotient[cur_q_degree] = cur_q_coeff;

                if let Sparse(p) = divisor {
                    for (i, div_coeff) in p.coeffs() {
                        remainder[cur_q_degree + i] -= &(cur_q_coeff * div_coeff);
                    }
                } else if let Dense(p) = divisor {
                    for (i, div_coeff) in p.iter().enumerate() {
                        remainder[cur_q_degree + i] -= &(cur_q_coeff * div_coeff);
                    }
                }

                while let Some(true) = remainder.coeffs.last().map(|c| c.is_zero()) {
                    remainder.coeffs.pop();
                }
            }
            Ok((DensePolynomial::from_coefficients_vec(quotient), remainder))
        }
    }
}

impl<F: PrimeField> Polynomial<'_, F> {
    /// Construct `Evaluations` by evaluating a polynomial over the domain
    /// `domain`.
    pub fn evaluate_over_domain(poly: impl Into<Self>, domain: EvaluationDomain<F>) -> Evaluations<F> {
        let poly = poly.into();
        poly.eval_over_domain_helper(domain)
    }

    fn eval_over_domain_helper(self, domain: EvaluationDomain<F>) -> Evaluations<F> {
        match self {
            Sparse(Cow::Borrowed(s)) => {
                let evals = domain.elements().map(|elem| s.evaluate(elem)).collect();
                Evaluations::from_vec_and_domain(evals, domain)
            }
            Sparse(Cow::Owned(s)) => {
                let evals = domain.elements().map(|elem| s.evaluate(elem)).collect();
                Evaluations::from_vec_and_domain(evals, domain)
            }
            Dense(Cow::Borrowed(d)) => {
                if d.degree() >= domain.size() {
                    d.coeffs
                        .chunks(domain.size())
                        .map(|d| Evaluations::from_vec_and_domain(domain.fft(d), domain))
                        .fold(Evaluations::from_vec_and_domain(vec![F::zero(); domain.size()], domain), |mut acc, e| {
                            acc.evaluations.iter_mut().zip(e.evaluations).for_each(|(a, e)| *a += e);
                            acc
                        })
                } else {
                    Evaluations::from_vec_and_domain(domain.fft(&d.coeffs), domain)
                }
            }
            Dense(Cow::Owned(mut d)) => {
                if d.degree() >= domain.size() {
                    d.coeffs
                        .chunks(domain.size())
                        .map(|d| Evaluations::from_vec_and_domain(domain.fft(d), domain))
                        .fold(Evaluations::from_vec_and_domain(vec![F::zero(); domain.size()], domain), |mut acc, e| {
                            cfg_iter_mut!(acc.evaluations).zip(e.evaluations).for_each(|(a, e)| *a += e);
                            acc
                        })
                } else {
                    domain.fft_in_place(&mut d.coeffs);
                    Evaluations::from_vec_and_domain(d.coeffs, domain)
                }
            }
        }
    }
}
