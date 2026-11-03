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

use super::PolynomialLabel;
use crate::fft::{DensePolynomial, EvaluationDomain, Evaluations as EvaluationsOnDomain, Polynomial, SparsePolynomial};
use snarkvm_fields::{Field, PrimeField};
use snarkvm_utilities::{CanonicalDeserialize, CanonicalSerialize, cfg_iter, cfg_iter_mut};

use anyhow::Result;
use std::borrow::Cow;

#[cfg(feature = "serial")]
use itertools::Itertools;
#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, Eq, PartialEq)]
pub struct PolynomialInfo {
    label: PolynomialLabel,
    degree_bound: Option<usize>,
    hiding_bound: Option<usize>,
}

impl PolynomialInfo {
    /// Construct a new labeled polynomial by consuming `polynomial`.
    pub fn new(label: PolynomialLabel, degree_bound: Option<usize>, hiding_bound: Option<usize>) -> Self {
        Self { label, degree_bound, hiding_bound }
    }

    /// Return the label for `self`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Retrieve the degree bound in `self`.
    pub fn degree_bound(&self) -> Option<usize> {
        self.degree_bound
    }

    /// Retrieve whether the polynomial in `self` should be hidden.
    pub fn is_hiding(&self) -> bool {
        self.hiding_bound.is_some()
    }

    /// Retrieve the hiding bound for the polynomial in `self`.
    pub fn hiding_bound(&self) -> Option<usize> {
        self.hiding_bound
    }
}

/// A polynomial along with information about its degree bound (if any), and the
/// maximum number of queries that will be made to it. This latter number
/// determines the amount of protection that will be provided to a commitment
/// for this polynomial.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct LabeledPolynomial<F: Field> {
    pub info: PolynomialInfo,
    pub polynomial: Polynomial<'static, F>,
}

impl<F: Field> core::ops::Deref for LabeledPolynomial<F> {
    type Target = Polynomial<'static, F>;

    fn deref(&self) -> &Self::Target {
        &self.polynomial
    }
}

impl<F: Field> LabeledPolynomial<F> {
    /// Construct a new labeled polynomial by consuming `polynomial`.
    pub fn new(
        label: impl Into<PolynomialLabel>,
        polynomial: impl Into<Polynomial<'static, F>>,
        degree_bound: impl Into<Option<usize>>,
        hiding_bound: impl Into<Option<usize>>,
    ) -> Self {
        let info = PolynomialInfo::new(label.into(), degree_bound.into(), hiding_bound.into());
        Self { info, polynomial: polynomial.into() }
    }

    pub fn info(&self) -> &PolynomialInfo {
        &self.info
    }

    /// Return the label for `self`.
    pub fn label(&self) -> &str {
        &self.info.label
    }

    /// Return the label for `self`.
    pub fn to_label(&self) -> String {
        self.info.label.clone()
    }

    /// Retrieve the polynomial from `self`.
    pub fn polynomial(&self) -> &Polynomial<'_, F> {
        &self.polynomial
    }

    /// Retrieve a mutable reference to the enclosed polynomial.
    pub fn polynomial_mut(&mut self) -> &mut Polynomial<'static, F> {
        &mut self.polynomial
    }

    /// Evaluate the polynomial in `self`.
    pub fn evaluate(&self, point: F) -> F {
        self.polynomial.evaluate(point)
    }

    /// Retrieve the degree bound in `self`.
    pub fn degree_bound(&self) -> Option<usize> {
        self.info.degree_bound
    }

    /// Retrieve whether the polynomial in `self` should be hidden.
    pub fn is_hiding(&self) -> bool {
        self.info.hiding_bound.is_some()
    }

    /// Retrieve the hiding bound for the polynomial in `self`.
    pub fn hiding_bound(&self) -> Option<usize> {
        self.info.hiding_bound
    }
}

/////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone)]
pub struct LabeledPolynomialWithBasis<'a, F: PrimeField> {
    pub info: PolynomialInfo,
    pub polynomial: PolynomialWithBasis<'a, F>,
}

impl<'a, F: PrimeField> LabeledPolynomialWithBasis<'a, F> {
    /// Construct a new labeled polynomial by consuming `polynomial`.
    pub fn new_monomial_basis(
        label: PolynomialLabel,
        polynomial: &'a Polynomial<F>,
        degree_bound: Option<usize>,
        hiding_bound: Option<usize>,
    ) -> Self {
        let polynomial = PolynomialWithBasis::new_monomial_basis_ref(polynomial, degree_bound);
        let info = PolynomialInfo::new(label, degree_bound, hiding_bound);
        Self { info, polynomial }
    }

    pub fn new_lagrange_basis(
        label: PolynomialLabel,
        polynomial: EvaluationsOnDomain<F>,
        hiding_bound: Option<usize>,
    ) -> Self {
        let polynomial = PolynomialWithBasis::new_lagrange_basis(polynomial);
        let info = PolynomialInfo::new(label, None, hiding_bound);
        Self { info, polynomial }
    }

    pub fn new_lagrange_basis_ref(
        label: PolynomialLabel,
        polynomial: &'a EvaluationsOnDomain<F>,
        hiding_bound: Option<usize>,
    ) -> Self {
        let polynomial = PolynomialWithBasis::new_lagrange_basis_ref(polynomial);
        let info = PolynomialInfo::new(label, None, hiding_bound);
        Self { info, polynomial }
    }

    /// Return the label for `self`.
    pub fn label(&self) -> &str {
        &self.info.label
    }

    /// Return the information about the label, degree bound, and hiding bound
    /// of `self`.
    pub fn info(&self) -> &PolynomialInfo {
        &self.info
    }

    pub fn degree(&self) -> usize {
        match &self.polynomial {
            PolynomialWithBasis::Lagrange { evaluations } => evaluations.domain().size() - 1,
            PolynomialWithBasis::Monomial { polynomial, .. } => polynomial.degree(),
        }
    }

    /// Evaluate the polynomial in `self`.
    pub fn evaluate(&self, point: F) -> F {
        self.polynomial.evaluate(point)
    }

    /// Retrieve the degree bound in `self`.
    pub fn degree_bound(&self) -> Option<usize> {
        match self.polynomial {
            PolynomialWithBasis::Monomial { degree_bound, .. } => degree_bound,
            _ => None,
        }
    }

    /// Retrieve whether the polynomial in `self` should be hidden.
    pub fn is_hiding(&self) -> bool {
        self.info.hiding_bound.is_some()
    }

    /// Retrieve the hiding bound for the polynomial in `self`.
    pub fn hiding_bound(&self) -> Option<usize> {
        self.info.hiding_bound
    }
}

impl<'a, F: PrimeField> From<&'a LabeledPolynomial<F>> for LabeledPolynomialWithBasis<'a, F> {
    fn from(other: &'a LabeledPolynomial<F>) -> Self {
        let polynomial = PolynomialWithBasis::Monomial {
            polynomial: Cow::Borrowed(other.polynomial()),
            degree_bound: other.degree_bound(),
        };
        Self { info: other.info.clone(), polynomial }
    }
}

impl<F: PrimeField> From<LabeledPolynomial<F>> for LabeledPolynomialWithBasis<'_, F> {
    fn from(other: LabeledPolynomial<F>) -> Self {
        let polynomial = PolynomialWithBasis::Monomial {
            polynomial: Cow::Owned(other.polynomial),
            degree_bound: other.info.degree_bound,
        };
        Self { info: other.info.clone(), polynomial }
    }
}

#[derive(Debug, Clone)]
pub enum PolynomialWithBasis<'a, F: PrimeField> {
    /// A polynomial in monomial basis, along with information about
    /// its degree bound (if any).
    Monomial { polynomial: Cow<'a, Polynomial<'a, F>>, degree_bound: Option<usize> },

    /// A polynomial in Lagrange basis, along with information about
    /// its degree bound (if any).
    Lagrange { evaluations: Cow<'a, EvaluationsOnDomain<F>> },
}

impl<'a, F: PrimeField> PolynomialWithBasis<'a, F> {
    pub fn new_monomial_basis_ref(polynomial: &'a Polynomial<F>, degree_bound: Option<usize>) -> Self {
        Self::Monomial { polynomial: Cow::Borrowed(polynomial), degree_bound }
    }

    pub fn new_monomial_basis(polynomial: Polynomial<'a, F>, degree_bound: Option<usize>) -> Self {
        Self::Monomial { polynomial: Cow::Owned(polynomial), degree_bound }
    }

    pub fn new_dense_monomial_basis_ref(polynomial: &'a DensePolynomial<F>, degree_bound: Option<usize>) -> Self {
        let polynomial = Polynomial::Dense(Cow::Borrowed(polynomial));
        Self::Monomial { polynomial: Cow::Owned(polynomial), degree_bound }
    }

    pub fn new_dense_monomial_basis(polynomial: DensePolynomial<F>, degree_bound: Option<usize>) -> Self {
        let polynomial = Polynomial::from(polynomial);
        Self::Monomial { polynomial: Cow::Owned(polynomial), degree_bound }
    }

    pub fn new_sparse_monomial_basis_ref(polynomial: &'a SparsePolynomial<F>, degree_bound: Option<usize>) -> Self {
        let polynomial = Polynomial::Sparse(Cow::Borrowed(polynomial));
        Self::Monomial { polynomial: Cow::Owned(polynomial), degree_bound }
    }

    pub fn new_sparse_monomial_basis(polynomial: SparsePolynomial<F>, degree_bound: Option<usize>) -> Self {
        let polynomial = Polynomial::from(polynomial);
        Self::Monomial { polynomial: Cow::Owned(polynomial), degree_bound }
    }

    pub fn new_lagrange_basis(evaluations: EvaluationsOnDomain<F>) -> Self {
        Self::Lagrange { evaluations: Cow::Owned(evaluations) }
    }

    pub fn new_lagrange_basis_ref(evaluations: &'a EvaluationsOnDomain<F>) -> Self {
        Self::Lagrange { evaluations: Cow::Borrowed(evaluations) }
    }

    pub fn is_in_monomial_basis(&self) -> bool {
        matches!(self, Self::Monomial { .. })
    }

    /// Retrieve the degree bound in `self`.
    pub fn degree_bound(&self) -> Option<usize> {
        match self {
            Self::Monomial { degree_bound, .. } => *degree_bound,
            _ => None,
        }
    }

    /// Retrieve the degree bound in `self`.
    pub fn is_sparse(&self) -> bool {
        match self {
            Self::Monomial { polynomial, .. } => matches!(polynomial.as_ref(), Polynomial::Sparse(_)),
            _ => false,
        }
    }

    pub fn is_in_lagrange_basis(&self) -> bool {
        matches!(self, Self::Lagrange { .. })
    }

    pub fn domain(&self) -> Option<EvaluationDomain<F>> {
        match self {
            Self::Lagrange { evaluations } => Some(evaluations.domain()),
            _ => None,
        }
    }

    pub fn evaluate(&self, point: F) -> F {
        match self {
            Self::Monomial { polynomial, .. } => polynomial.evaluate(point),
            Self::Lagrange { evaluations } => {
                let domain = evaluations.domain();
                let degree = domain.size() as u64;
                let multiplier = (point.pow([degree]) - F::one()) / F::from(degree);
                let powers: Vec<_> = domain.elements().collect();
                let mut denominators = cfg_iter!(powers).map(|pow| point - pow).collect::<Vec<_>>();
                snarkvm_fields::batch_inversion(&mut denominators);
                cfg_iter_mut!(denominators)
                    .zip_eq(powers)
                    .zip_eq(&evaluations.evaluations)
                    .map(|((denom, power), coeff)| *denom * power * coeff)
                    .sum::<F>()
                    * multiplier
            }
        }
    }
}
