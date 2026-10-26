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

//! A polynomial represented in coefficient form.

use super::PolyMultiplier;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use snarkvm_fields::{Field, PrimeField};
use snarkvm_utilities::{cfg_iter_mut, serialize::*};

use anyhow::Result;
use num_traits::CheckedDiv;
use rand::RngExt;
use std::{
    fmt,
    ops::{Add, AddAssign, Deref, DerefMut, Div, Mul, MulAssign, Neg, Sub, SubAssign},
};

use itertools::Itertools;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// Stores a polynomial in coefficient form.
#[derive(Clone, PartialEq, Eq, Hash, Default, CanonicalSerialize, CanonicalDeserialize)]
#[must_use]
pub struct DensePolynomial<F: Field> {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub coeffs: Vec<F>,
}

impl<F: Field> fmt::Debug for DensePolynomial<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        for (i, coeff) in self.coeffs.iter().enumerate().filter(|(_, c)| !c.is_zero()) {
            if i == 0 {
                write!(f, "\n{coeff:?}",)?;
            } else if i == 1 {
                write!(f, " + \n{coeff:?} * x")?;
            } else {
                write!(f, " + \n{coeff:?} * x^{i}")?;
            }
        }
        Ok(())
    }
}

impl<F: Field> DensePolynomial<F> {
    /// Drops trailing zero coefficients, so that `degree()` is the real degree.
    ///
    /// `degree()` asserts that the last coefficient is non-zero, and
    /// `apply_randomized_selector` divides by degree, so a polynomial that
    /// skips this is a live panic rather than an untidy one. The loop was
    /// written out seven times in this file and once in `second.rs`; naming it
    /// means the next person changing one changes all of them.
    ///
    /// `from_coefficients_vec` still writes the loop out, and has to: it trims
    /// a bare `Vec<F>` before there is a `Self` to call this on.
    pub(crate) fn trim_trailing_zeros(&mut self) {
        while let Some(true) = self.coeffs.last().map(|c| c.is_zero()) {
            self.coeffs.pop();
        }
    }

    /// Returns the zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: Vec::new() }
    }

    /// Checks if the given polynomial is zero.
    pub fn is_zero(&self) -> bool {
        self.coeffs.is_empty() || self.coeffs.iter().all(|coeff| coeff.is_zero())
    }

    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_slice(coeffs: &[F]) -> Self {
        Self::from_coefficients_vec(coeffs.to_vec())
    }

    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_vec(mut coeffs: Vec<F>) -> Self {
        // While there are zeros at the end of the coefficient vector, pop them off.
        while let Some(true) = coeffs.last().map(|c| c.is_zero()) {
            coeffs.pop();
        }
        // Check that either the coefficients vec are empty or that the last coeff is
        // non-zero.
        assert!(coeffs.last().is_none_or(|coeff| !coeff.is_zero()));

        Self { coeffs }
    }

    /// Returns the degree of the polynomial.
    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            assert!(self.coeffs.last().is_some_and(|coeff| !coeff.is_zero()));
            self.coeffs.len() - 1
        }
    }

    /// Evaluates `self` at the given `point` in the field.
    pub fn evaluate(&self, point: F) -> F {
        if self.is_zero() {
            return F::zero();
        } else if point.is_zero() {
            return self.coeffs[0];
        }

        // Horner's rule. It never calls `degree()`, so unlike the powers form it
        // replaced it tolerates trailing zero coefficients, which reach it
        // because `coeffs` is public. `evaluate_tolerates_trailing_zeros` pins
        // that.
        let mut acc = F::zero();
        for coeff in self.coeffs.iter().rev() {
            acc = acc * point + *coeff;
        }
        acc
    }

    /// The powers form that `evaluate` replaced, kept so the equivalence test
    /// has something to compare against.
    #[cfg(test)]
    fn evaluate_by_powers(&self, point: F) -> F {
        if self.is_zero() {
            return F::zero();
        } else if point.is_zero() {
            return self.coeffs[0];
        }
        let mut powers_of_point = Vec::with_capacity(1 + self.degree());
        powers_of_point.push(F::one());
        let mut cur = point;
        for _ in 0..self.degree() {
            powers_of_point.push(cur);
            cur *= point;
        }
        let zero = F::zero();
        let mapping = crate::cfg_into_iter!(powers_of_point).zip_eq(&self.coeffs).map(|(power, coeff)| power * coeff);
        crate::cfg_reduce!(mapping, || zero, |a, b| a + b)
    }

    /// Outputs a univariate polynomial of degree `d` where each non-leading
    /// coefficient is sampled uniformly at random from R and the leading
    /// coefficient is sampled uniformly at random from among the non-zero
    /// elements of R.
    pub fn rand<R: RngExt>(d: usize, rng: &mut R) -> Self {
        let mut random_coeffs = (0..(d + 1)).map(|_| F::rand(rng)).collect_vec();
        while random_coeffs[d].is_zero() {
            // In the extremely unlikely event, sample again.
            random_coeffs[d] = F::rand(rng);
        }
        Self::from_coefficients_vec(random_coeffs)
    }

    /// Returns the coefficients of `self`.
    pub fn coeffs(&self) -> &[F] {
        &self.coeffs
    }

    /// Perform a naive n^2 multiplication of `self` by `other`.
    #[cfg(test)]
    fn naive_mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            DensePolynomial::zero()
        } else {
            let mut result = vec![F::zero(); self.degree() + other.degree() + 1];
            for (i, self_coeff) in self.coeffs.iter().enumerate() {
                for (j, other_coeff) in other.coeffs.iter().enumerate() {
                    result[i + j] += *self_coeff * other_coeff;
                }
            }
            DensePolynomial::from_coefficients_vec(result)
        }
    }
}

impl<F: PrimeField> DensePolynomial<F> {
    /// Multiply `self` by the vanishing polynomial for the domain `domain`.
    pub fn mul_by_vanishing_poly(&self, domain: EvaluationDomain<F>) -> DensePolynomial<F> {
        let mut shifted = vec![F::zero(); domain.size()];
        shifted.extend_from_slice(&self.coeffs);
        shifted[..self.coeffs.len()].iter_mut().zip_eq(&self.coeffs).for_each(|(s, c)| *s -= c);
        DensePolynomial::from_coefficients_vec(shifted)
    }

    /// Divides by the monic linear polynomial `X - z` using Ruffini's rule,
    /// returning the quotient and the remainder `self(z)`.
    pub fn divide_by_monic_linear(&self, z: F) -> (Self, F) {
        match self.coeffs.len() {
            0 => (Self::zero(), F::zero()),
            1 => (Self::zero(), self.coeffs[0]),
            n => {
                let mut quotient = vec![F::zero(); n - 1];
                quotient[n - 2] = self.coeffs[n - 1];
                for i in (1..n - 1).rev() {
                    quotient[i - 1] = self.coeffs[i] + z * quotient[i];
                }
                let remainder = self.coeffs[0] + z * quotient[0];
                (Self::from_coefficients_vec(quotient), remainder)
            }
        }
    }

    /// Divides by the vanishing polynomial `X^n - 1` of `domain`, returning
    /// `(quotient, remainder)`.
    ///
    /// Matching coefficients on `p = q(X^n - 1) + r`, with `deg(r) < n`:
    ///
    /// ```text
    ///     q[j] = p[j+n] + q[j+n]      (q[k] = 0 for k >= len(q))
    ///     r[i] = p[i]   + q[i]
    /// ```
    ///
    /// The recurrence is `n` independent chains, one per residue class mod `n`.
    /// For `deg(p) < 2n` each chain is a single step and the quotient is
    /// `p[n..]`.
    pub fn divide_by_vanishing_poly(
        &self,
        domain: EvaluationDomain<F>,
    ) -> Result<(DensePolynomial<F>, DensePolynomial<F>)> {
        let n = domain.size();
        anyhow::ensure!(n > 0, "Dividing by the vanishing polynomial of an empty domain");

        let p = &self.coeffs;
        // deg(p) < n: the quotient is zero and the remainder is `p`.
        if p.len() <= n {
            return Ok((DensePolynomial::zero(), Self::from_coefficients_slice(p)));
        }

        let q_len = p.len() - n;
        let q = if q_len <= n {
            // Single-step chains.
            p[n..].to_vec()
        } else {
            // Chains span several steps, so each carries into the next.
            let mut q = vec![F::zero(); q_len];
            for j in (0..q_len).rev() {
                let carry = if j + n < q_len { q[j + n] } else { F::zero() };
                q[j] = p[j + n] + carry;
            }
            q
        };

        let mut r = p[..n].to_vec();
        let overlap = q_len.min(n);
        cfg_iter_mut!(r[..overlap]).enumerate().for_each(|(i, r_i)| *r_i += q[i]);

        Ok((DensePolynomial::from_coefficients_vec(q), DensePolynomial::from_coefficients_vec(r)))
    }

    /// Evaluate `self` over `domain`.
    pub fn evaluate_over_domain_by_ref(&self, domain: EvaluationDomain<F>) -> Evaluations<F> {
        let poly: Polynomial<'_, F> = self.into();
        Polynomial::<F>::evaluate_over_domain(poly, domain)
    }

    /// Evaluate `self` over `domain`.
    pub fn evaluate_over_domain(self, domain: EvaluationDomain<F>) -> Evaluations<F> {
        let poly: Polynomial<'_, F> = self.into();
        Polynomial::<F>::evaluate_over_domain(poly, domain)
    }
}

impl<F: Field> From<super::SparsePolynomial<F>> for DensePolynomial<F> {
    fn from(other: super::SparsePolynomial<F>) -> Self {
        let mut result = vec![F::zero(); other.degree() + 1];
        for (i, coeff) in other.coeffs() {
            result[*i] = *coeff;
        }
        DensePolynomial::from_coefficients_vec(result)
    }
}

impl<'a, F: Field> Add<&'a DensePolynomial<F>> for &'_ DensePolynomial<F> {
    type Output = DensePolynomial<F>;

    fn add(self, other: &'a DensePolynomial<F>) -> DensePolynomial<F> {
        let mut result = if self.is_zero() {
            other.clone()
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            // Zip safety: `result` and `other` could have different lengths.
            cfg_iter_mut!(result.coeffs).zip(&other.coeffs).for_each(|(a, b)| *a += b);
            result
        } else {
            let mut result = other.clone();
            // Zip safety: `result` and `other` could have different lengths.
            cfg_iter_mut!(result.coeffs).zip(&self.coeffs).for_each(|(a, b)| *a += b);
            result
        };
        result.trim_trailing_zeros();
        result
    }
}

impl<'a, F: Field> AddAssign<&'a DensePolynomial<F>> for DensePolynomial<F> {
    fn add_assign(&mut self, other: &'a DensePolynomial<F>) {
        if self.is_zero() {
            self.coeffs.clear();
            self.coeffs.extend_from_slice(&other.coeffs);
        } else if other.is_zero() {
            // return
        } else if self.degree() >= other.degree() {
            // Zip safety: `self` and `other` could have different lengths.
            cfg_iter_mut!(self.coeffs, 1_000).zip(&other.coeffs).for_each(|(a, b)| *a += b);
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), F::zero());
            // Zip safety: `self` and `other` have the same length.
            cfg_iter_mut!(self.coeffs, 1_000).zip(&other.coeffs).for_each(|(a, b)| *a += b);
        }
        self.trim_trailing_zeros();
    }
}

impl<'a, F: Field> AddAssign<&'a Polynomial<'a, F>> for DensePolynomial<F> {
    fn add_assign(&mut self, other: &'a Polynomial<F>) {
        match other {
            Polynomial::Sparse(p) => *self += &Self::from(p.clone().into_owned()),
            Polynomial::Dense(p) => *self += p.as_ref(),
        }
    }
}

impl<'a, F: Field> AddAssign<(F, &'a Polynomial<'a, F>)> for DensePolynomial<F> {
    fn add_assign(&mut self, (f, other): (F, &'a Polynomial<F>)) {
        match other {
            Polynomial::Sparse(p) => *self += (f, &Self::from(p.clone().into_owned())),
            Polynomial::Dense(p) => *self += (f, p.as_ref()),
        }
    }
}

impl<'a, F: Field> AddAssign<(F, &'a DensePolynomial<F>)> for DensePolynomial<F> {
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, (f, other): (F, &'a DensePolynomial<F>)) {
        if self.is_zero() {
            // One pass, not two. The scale has to happen either way; the copy
            // does not have to be a separate walk over the coefficients.
            //
            // `clear()` rather than assigning a fresh vector, because `self`
            // being zero does not mean it is empty -- a polynomial whose
            // coefficients are all zero reaches here too, and its allocation is
            // worth keeping.
            self.coeffs.clear();
            self.coeffs.extend(other.coeffs.iter().map(|c| *c * f));
        } else if other.is_zero() {
            // return
        } else if self.degree() >= other.degree() {
            // Zip safety: `self` and `other` could have different lengths.
            cfg_iter_mut!(self.coeffs, 1_000).zip(&other.coeffs).for_each(|(a, b)| {
                *a += f * b;
            });
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), F::zero());
            // Zip safety: `self` and `other` have the same length after the resize.
            cfg_iter_mut!(self.coeffs, 1_000).zip(&other.coeffs).for_each(|(a, b)| {
                *a += f * b;
            });
        }
        self.trim_trailing_zeros();
    }
}

impl<F: Field> Neg for DensePolynomial<F> {
    type Output = DensePolynomial<F>;

    #[inline]
    fn neg(mut self) -> DensePolynomial<F> {
        for coeff in &mut self.coeffs {
            *coeff = -*coeff;
        }
        self
    }
}

impl<'a, F: Field> Sub<&'a DensePolynomial<F>> for &'_ DensePolynomial<F> {
    type Output = DensePolynomial<F>;

    #[inline]
    fn sub(self, other: &'a DensePolynomial<F>) -> DensePolynomial<F> {
        let mut result = if self.is_zero() {
            let mut result = other.clone();
            for coeff in &mut result.coeffs {
                *coeff = -(*coeff);
            }
            result
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            // Zip safety: `result` and `other` could have different degrees.
            cfg_iter_mut!(result.coeffs, 1_000).zip(&other.coeffs).for_each(|(a, b)| *a -= b);
            result
        } else {
            let mut result = self.clone();
            result.coeffs.resize(other.coeffs.len(), F::zero());
            // Zip safety: `result` and `other` have the same length after the resize.
            cfg_iter_mut!(result.coeffs, 1_000).zip(&other.coeffs).for_each(|(a, b)| {
                *a -= b;
            });
            result
        };
        result.trim_trailing_zeros();
        result
    }
}

impl<'a, F: Field> SubAssign<&'a DensePolynomial<F>> for DensePolynomial<F> {
    #[inline]
    fn sub_assign(&mut self, other: &'a DensePolynomial<F>) {
        if self.is_zero() {
            self.coeffs.resize(other.coeffs.len(), F::zero());
            for (i, coeff) in other.coeffs.iter().enumerate() {
                self.coeffs[i] -= coeff;
            }
        } else if other.is_zero() {
            // return
        } else if self.degree() >= other.degree() {
            // Zip safety: self and other could have different lengths.
            cfg_iter_mut!(self.coeffs).zip(&other.coeffs).for_each(|(a, b)| *a -= b);
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), F::zero());
            // Zip safety: self and other have the same length after the resize.
            cfg_iter_mut!(self.coeffs).zip(&other.coeffs).for_each(|(a, b)| *a -= b);
        }
        self.trim_trailing_zeros();
    }
}

impl<'a, F: Field> AddAssign<&'a super::SparsePolynomial<F>> for DensePolynomial<F> {
    #[inline]
    fn add_assign(&mut self, other: &'a super::SparsePolynomial<F>) {
        if self.degree() < other.degree() {
            self.coeffs.resize(other.degree() + 1, F::zero());
        }
        for (i, b) in other.coeffs() {
            self.coeffs[*i] += b;
        }
        self.trim_trailing_zeros();
    }
}

impl<'a, F: Field> Sub<&'a super::SparsePolynomial<F>> for DensePolynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, other: &'a super::SparsePolynomial<F>) -> Self::Output {
        if self.degree() < other.degree() {
            self.coeffs.resize(other.degree() + 1, F::zero());
        }
        for (i, b) in other.coeffs() {
            self.coeffs[*i] -= b;
        }
        self.trim_trailing_zeros();
        self
    }
}

impl<'a, F: Field> Div<&'a DensePolynomial<F>> for &'_ DensePolynomial<F> {
    type Output = DensePolynomial<F>;

    /// This division can panic and ignores remainders
    #[inline]
    fn div(self, divisor: &'a DensePolynomial<F>) -> DensePolynomial<F> {
        let a: Polynomial<_> = self.into();
        let b: Polynomial<_> = divisor.into();
        a.divide_with_q_and_r(&b).expect("division failed").0
    }
}

impl<F: Field> Div<DensePolynomial<F>> for DensePolynomial<F> {
    type Output = DensePolynomial<F>;

    /// This division can panic and ignores remainders
    #[inline]
    fn div(self, divisor: DensePolynomial<F>) -> DensePolynomial<F> {
        let a: Polynomial<_> = self.into();
        let b: Polynomial<_> = divisor.into();
        a.divide_with_q_and_r(&b).expect("division failed").0
    }
}

impl<F: Field> CheckedDiv for DensePolynomial<F> {
    #[inline]
    fn checked_div(&self, divisor: &DensePolynomial<F>) -> Option<DensePolynomial<F>> {
        let a: Polynomial<_> = self.into();
        let b: Polynomial<_> = divisor.into();
        match a.divide_with_q_and_r(&b) {
            Ok((divisor, remainder)) => {
                if remainder.is_zero() {
                    Some(divisor)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

/// Performs O(nlogn) multiplication of polynomials if F is smooth.
impl<'a, F: PrimeField> Mul<&'a DensePolynomial<F>> for &'_ DensePolynomial<F> {
    type Output = DensePolynomial<F>;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, other: &'a DensePolynomial<F>) -> DensePolynomial<F> {
        if self.is_zero() || other.is_zero() {
            DensePolynomial::zero()
        } else {
            let mut m = PolyMultiplier::new();
            m.add_polynomial_ref(self, "");
            m.add_polynomial_ref(other, "");
            m.multiply().unwrap()
        }
    }
}

/// Multiplies `self` by `other: F`.
impl<F: Field> Mul<F> for DensePolynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, other: F) -> Self {
        self.iter_mut().for_each(|c| *c *= other);
        self
    }
}

/// Multiplies `self` by `other: F`.
impl<F: Field> Mul<F> for &'_ DensePolynomial<F> {
    type Output = DensePolynomial<F>;

    #[inline]
    fn mul(self, other: F) -> Self::Output {
        let result = self.clone();
        result * other
    }
}

/// Multiplies `self` by `other: F`.
impl<F: Field> MulAssign<F> for DensePolynomial<F> {
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul_assign(&mut self, other: F) {
        self.iter_mut().for_each(|c| *c *= other);
    }
}

/// Multiplies `self` by `other: F`.
impl<F: Field> std::iter::Sum for DensePolynomial<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(DensePolynomial::zero(), |a, b| &a + &b)
    }
}

impl<F: Field> Deref for DensePolynomial<F> {
    type Target = [F];

    fn deref(&self) -> &[F] {
        &self.coeffs
    }
}

impl<F: Field> DerefMut for DensePolynomial<F> {
    fn deref_mut(&mut self) -> &mut [F] {
        &mut self.coeffs
    }
}

#[cfg(test)]
mod tests {
    use crate::fft::polynomial::*;
    use num_traits::CheckedDiv;
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::{Field, One, Zero};
    use snarkvm_utilities::rand::{TestRng, Uniform};

    use rand::Rng;

    #[test]
    fn double_polynomials_random() {
        let rng = &mut TestRng::default();
        for degree in 0..70 {
            let p = DensePolynomial::<Fr>::rand(degree, rng);
            let p_double = &p + &p;
            let p_quad = &p_double + &p_double;
            assert_eq!(&(&(&p + &p) + &p) + &p, p_quad);
        }
    }

    #[test]
    fn add_polynomials() {
        let rng = &mut TestRng::default();
        for a_degree in 0..70 {
            for b_degree in 0..70 {
                let p1 = DensePolynomial::<Fr>::rand(a_degree, rng);
                let p2 = DensePolynomial::<Fr>::rand(b_degree, rng);
                let res1 = &p1 + &p2;
                let res2 = &p2 + &p1;
                assert_eq!(res1, res2);
            }
        }
    }

    #[test]
    fn add_polynomials_with_mul() {
        let rng = &mut TestRng::default();
        for a_degree in 0..70 {
            for b_degree in 0..70 {
                let mut p1 = DensePolynomial::rand(a_degree, rng);
                let p2 = DensePolynomial::rand(b_degree, rng);
                let f = Fr::rand(rng);
                let f_p2 = DensePolynomial::from_coefficients_vec(p2.coeffs.iter().map(|c| f * c).collect());
                let res2 = &f_p2 + &p1;
                p1 += (f, &p2);
                let res1 = p1;
                assert_eq!(res1, res2);
            }
        }
    }

    #[test]
    fn add_scaled_polynomial_to_zero() {
        // `DensePolynomial::rand` resamples until the leading coefficient is
        // non-zero, so `add_polynomials_with_mul` never enters `add_assign`'s
        // `self.is_zero()` branch. These do, both ways it can be reached: an
        // empty polynomial, and a non-empty one whose coefficients are all zero
        // -- which is why that branch still has to `clear()`.
        let rng = &mut TestRng::default();
        for degree in 0..70 {
            let q = DensePolynomial::rand(degree, rng);
            let f = Fr::rand(rng);
            let expected = DensePolynomial::from_coefficients_vec(q.coeffs.iter().map(|c| f * c).collect());

            let mut empty = DensePolynomial::zero();
            empty += (f, &q);
            assert_eq!(empty, expected, "scaled add onto an empty polynomial");

            // Built through the field, not `from_coefficients_vec`, which strips
            // trailing zeros and would hand back the empty representation --
            // making this the same case as `empty` above and testing nothing.
            let mut zeroed = DensePolynomial::zero();
            zeroed.coeffs = vec![Fr::zero(); degree + 3];
            assert!(zeroed.is_zero() && !zeroed.coeffs.is_empty());
            zeroed += (f, &q);
            assert_eq!(zeroed, expected, "scaled add onto a non-empty all-zero polynomial");
        }

        // A zero scalar still normalises to the empty representation.
        let q = DensePolynomial::rand(16, rng);
        let mut p = DensePolynomial::zero();
        p += (Fr::zero(), &q);
        assert!(p.is_zero());
        assert!(p.coeffs.is_empty());
    }

    #[test]
    fn sub_polynomials() {
        let rng = &mut TestRng::default();
        let p1 = DensePolynomial::<Fr>::rand(5, rng);
        let p2 = DensePolynomial::<Fr>::rand(3, rng);
        let res1 = &p1 - &p2;
        let res2 = &p2 - &p1;
        assert_eq!(&res1 + &p2, p1, "Subtraction should be inverse of addition!");
        assert_eq!(res1, -res2, "p2 - p1 = -(p1 - p2)");
    }

    #[test]
    fn divide_polynomials_fixed() {
        let dividend = DensePolynomial::from_coefficients_slice(&[
            "4".parse().unwrap(),
            "8".parse().unwrap(),
            "5".parse().unwrap(),
            "1".parse().unwrap(),
        ]);
        let divisor = DensePolynomial::from_coefficients_slice(&[Fr::one(), Fr::one()]); // Construct a monic linear polynomial.
        let result = dividend.checked_div(&divisor).unwrap();
        let expected_result = DensePolynomial::from_coefficients_slice(&[
            "4".parse().unwrap(),
            "4".parse().unwrap(),
            "1".parse().unwrap(),
        ]);
        assert_eq!(expected_result, result);
    }

    #[test]
    #[allow(clippy::needless_borrow)]
    fn divide_polynomials_random() {
        let rng = &mut TestRng::default();

        for a_degree in 0..70 {
            for b_degree in 0..70 {
                let dividend = DensePolynomial::<Fr>::rand(a_degree, rng);
                let divisor = DensePolynomial::<Fr>::rand(b_degree, rng);
                let (quotient, remainder) =
                    Polynomial::divide_with_q_and_r(&(&dividend).into(), &(&divisor).into()).unwrap();
                assert_eq!(dividend, &(&divisor * &quotient) + &remainder)
            }
        }
    }

    #[test]
    fn evaluate_polynomials() {
        let rng = &mut TestRng::default();
        for a_degree in 0..70 {
            let p = DensePolynomial::rand(a_degree, rng);
            let point: Fr = Fr::from(10u64);
            let mut total = Fr::zero();
            for (i, coeff) in p.coeffs.iter().enumerate() {
                total += point.pow([i as u64]) * coeff;
            }
            assert_eq!(p.evaluate(point), total);
        }
    }

    #[test]
    fn divide_poly_by_zero() {
        let a = Polynomial::<Fr>::zero();
        let b = Polynomial::<Fr>::zero();
        assert!(a.divide_with_q_and_r(&b).is_err());
    }

    #[test]
    fn mul_polynomials_random() {
        let rng = &mut TestRng::default();
        for a_degree in 0..70 {
            for b_degree in 0..70 {
                dbg!(a_degree);
                dbg!(b_degree);
                let a = DensePolynomial::<Fr>::rand(a_degree, rng);
                let b = DensePolynomial::<Fr>::rand(b_degree, rng);
                assert_eq!(&a * &b, a.naive_mul(&b))
            }
        }
    }

    #[test]
    fn mul_polynomials_n_random() {
        let rng = &mut TestRng::default();

        let max_degree = 1 << 8;

        for _ in 0..10 {
            let mut multiplier = PolyMultiplier::new();
            let a = DensePolynomial::<Fr>::rand(max_degree / 2, rng);
            let mut mul_degree = a.degree() + 1;
            multiplier.add_polynomial(a.clone(), "a");
            let mut naive = a.clone();

            // Include polynomials and evaluations
            let num_polys = (rng.next_u32() as usize) % 8;
            let num_evals = (rng.next_u32() as usize) % 4;
            println!("\nnum_polys {num_polys}, num_evals {num_evals}");

            for _ in 1..num_polys {
                let degree = (rng.next_u32() as usize) % max_degree;
                mul_degree += degree + 1;
                println!("poly degree {degree}");
                let a = DensePolynomial::<Fr>::rand(degree, rng);
                naive = naive.naive_mul(&a);
                multiplier.add_polynomial(a.clone(), "a");
            }

            // Add evaluations but don't overflow the domain
            let mut eval_degree = mul_degree;
            let domain = EvaluationDomain::new(mul_degree).unwrap();
            println!("mul_degree {}, domain {}", mul_degree, domain.size());
            for _ in 0..num_evals {
                let a = DensePolynomial::<Fr>::rand(mul_degree / 8, rng);
                eval_degree += a.len() + 1;
                if eval_degree < domain.size() {
                    println!("eval degree {eval_degree}");
                    let mut a_evals = a.clone().coeffs;
                    domain.fft_in_place(&mut a_evals);
                    let a_evals = Evaluations::from_vec_and_domain(a_evals, domain);

                    naive = naive.naive_mul(&a);
                    multiplier.add_evaluation(a_evals, "a");
                }
            }

            assert_eq!(multiplier.multiply().unwrap(), naive);
        }
    }

    #[test]
    fn mul_polynomials_corner_cases() {
        let rng = &mut TestRng::default();

        let a_degree = 70;

        // Single polynomial
        println!("Test single polynomial");
        let a = DensePolynomial::<Fr>::rand(a_degree, rng);
        let mut multiplier = PolyMultiplier::new();
        multiplier.add_polynomial(a.clone(), "a");
        assert_eq!(multiplier.multiply().unwrap(), a);

        // A constant, which gives the smallest domain, of size one.
        println!("Test a single constant");
        let c = DensePolynomial::from_coefficients_vec(vec![Fr::rand(rng)]);
        assert_eq!(c.degree(), 0);
        let mut multiplier = PolyMultiplier::new();
        multiplier.add_polynomial(c.clone(), "c");
        assert_eq!(multiplier.multiply().unwrap(), c);

        // Note PolyMultiplier doesn't support evaluations with no polynomials
    }

    #[test]
    fn mul_by_vanishing_poly() {
        let rng = &mut TestRng::default();
        for size in 1..10 {
            let domain = EvaluationDomain::new(1 << size).unwrap();
            for degree in 0..70 {
                let p = DensePolynomial::<Fr>::rand(degree, rng);
                let ans1 = p.mul_by_vanishing_poly(domain);
                let ans2 = &p * &domain.vanishing_polynomial().into();
                assert_eq!(ans1, ans2);
            }
        }
    }
}

#[cfg(test)]
mod vanishing_divide_tests {
    use crate::fft::{DensePolynomial, EvaluationDomain, Polynomial};
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::Zero;
    use snarkvm_utilities::rand::{TestRng, Uniform};

    pub(super) fn rand_poly(len: usize, rng: &mut TestRng) -> DensePolynomial<Fr> {
        DensePolynomial::from_coefficients_vec((0..len).map(|_| Fr::rand(rng)).collect())
    }

    /// `q * (X^n - 1) + r == p`, and `deg(r) < n`.
    ///
    /// Compared against the canonical form of `p`: results are trimmed on
    /// construction, so an input carrying trailing zeros would otherwise differ
    /// from an equal output by representation alone.
    fn check_identity(p: &DensePolynomial<Fr>, domain: EvaluationDomain<Fr>, label: &str) {
        let n = domain.size();
        let (q, r) = p.divide_by_vanishing_poly(domain).unwrap();
        let v = DensePolynomial::from(domain.vanishing_polynomial());
        let canonical = DensePolynomial::from_coefficients_vec(p.coeffs.clone());
        assert_eq!(&(&q * &v) + &r, canonical, "q*v + r != p [{label}]");
        assert!(r.is_zero() || r.degree() < n, "deg(r) >= n [{label}]");
    }

    /// Agrees with generic long division across inputs shorter than the
    /// divisor, on the `deg(p) < 2n` path, and long enough for a chain to
    /// carry.
    #[test]
    fn agrees_with_generic_long_division() {
        let rng = &mut TestRng::default();
        for log_n in [3usize, 5, 8] {
            let domain = EvaluationDomain::<Fr>::new(1 << log_n).unwrap();
            let n = domain.size();
            for len in [0, 1, n / 2, n, n + 1, 2 * n - 1, 2 * n, 2 * n + 3, 4 * n + 5] {
                let p = rand_poly(len, rng);
                let (q, r) = p.divide_by_vanishing_poly(domain).unwrap();

                let expect =
                    Polynomial::from(&p).divide_with_q_and_r(&Polynomial::from(domain.vanishing_polynomial())).unwrap();
                assert_eq!(q, expect.0, "quotient differs at n={n} len={len}");
                assert_eq!(r, expect.1, "remainder differs at n={n} len={len}");
                check_identity(&p, domain, &format!("n={n} len={len}"));
            }
        }
    }

    /// Random lengths spanning every branch, including chains long enough to
    /// carry several times.
    #[test]
    fn identity_holds_for_random_inputs() {
        let rng = &mut TestRng::default();
        for _ in 0..200 {
            let log_n = 2 + (u64::rand(rng) % 7) as usize;
            let domain = EvaluationDomain::<Fr>::new(1 << log_n).unwrap();
            let len = (u64::rand(rng) % (6 * domain.size() as u64 + 2)) as usize;
            let p = rand_poly(len, rng);
            check_identity(&p, domain, &format!("n={} len={len}", domain.size()));
        }
    }

    /// `coeffs` is public, so a caller can hand over a polynomial carrying
    /// trailing zeros. The quotient's own leading zeros are trimmed on
    /// construction, so the identity still holds.
    #[test]
    fn tolerates_trailing_zeros() {
        let rng = &mut TestRng::default();
        let domain = EvaluationDomain::<Fr>::new(16).unwrap();
        for len in [0usize, 5, 16, 17, 33, 70] {
            for pad in [1usize, 4, 20] {
                let mut p = rand_poly(len, rng);
                p.coeffs.resize(p.coeffs.len() + pad, Fr::zero());
                check_identity(&p, domain, &format!("len={len} pad={pad}"));
            }
        }
    }

    /// A polynomial that is exactly a multiple of the vanishing polynomial
    /// divides with no remainder, which is what the selector paths assert.
    #[test]
    fn exact_multiples_leave_no_remainder() {
        let rng = &mut TestRng::default();
        for log_n in [3usize, 6] {
            let domain = EvaluationDomain::<Fr>::new(1 << log_n).unwrap();
            let v = DensePolynomial::from(domain.vanishing_polynomial());
            for len in [1usize, 5, domain.size(), 3 * domain.size()] {
                let p = &rand_poly(len, rng) * &v;
                let (q, r) = p.divide_by_vanishing_poly(domain).unwrap();
                assert!(r.is_zero(), "expected no remainder [n={} len={len}]", domain.size());
                assert_eq!(&q * &v, p, "q*v != p [n={} len={len}]", domain.size());
            }
        }
    }

    /// The zero polynomial divides to zero and zero.
    #[test]
    fn zero_divides_to_zero() {
        let domain = EvaluationDomain::<Fr>::new(8).unwrap();
        let (q, r) = DensePolynomial::<Fr>::zero().divide_by_vanishing_poly(domain).unwrap();
        assert!(q.is_zero());
        assert!(r.is_zero());
    }
}

#[cfg(test)]
mod monic_linear_divide_tests {
    use crate::fft::{DensePolynomial, Polynomial};
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::{One, Zero};
    use snarkvm_utilities::{TestRng, Uniform};

    /// What generic long division would have produced, for comparison.
    fn generic(p: &DensePolynomial<Fr>, z: Fr) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
        let divisor = DensePolynomial::from_coefficients_vec(vec![-z, Fr::one()]);
        Polynomial::from(p.clone()).divide_with_q_and_r(&Polynomial::from(divisor)).unwrap()
    }

    #[test]
    fn agrees_with_generic_long_division() {
        let rng = &mut TestRng::default();
        for degree in [0usize, 1, 2, 3, 7, 64, 255, 1024] {
            let p = DensePolynomial::<Fr>::rand(degree, rng);
            let z = Fr::rand(rng);
            let (q, r) = p.divide_by_monic_linear(z);
            let (gq, gr) = generic(&p, z);
            assert_eq!(q, gq, "quotient differs at degree {degree}");
            assert_eq!(DensePolynomial::from_coefficients_vec(vec![r]), gr, "remainder differs at degree {degree}");
        }
    }

    /// p = (X - z) q + r, over enough random inputs to catch an off-by-one that
    /// hand-picked shapes would step over.
    #[test]
    fn satisfies_the_defining_identity() {
        let rng = &mut TestRng::default();
        for _ in 0..200 {
            let degree = (u64::rand(rng) % 128) as usize;
            let p = DensePolynomial::<Fr>::rand(degree, rng);
            let z = Fr::rand(rng);
            let (q, r) = p.divide_by_monic_linear(z);
            let divisor = DensePolynomial::from_coefficients_vec(vec![-z, Fr::one()]);
            let reconstructed = &(&divisor * &q) + &DensePolynomial::from_coefficients_vec(vec![r]);
            assert_eq!(reconstructed, p);
        }
    }

    /// The remainder of dividing by `X - z` is the evaluation at `z`.
    #[test]
    fn the_remainder_is_the_evaluation() {
        let rng = &mut TestRng::default();
        for degree in [0usize, 1, 5, 100, 513] {
            let p = DensePolynomial::<Fr>::rand(degree, rng);
            let z = Fr::rand(rng);
            let (_, r) = p.divide_by_monic_linear(z);
            assert_eq!(r, p.evaluate(z), "at degree {degree}");
        }
    }

    /// A root divides exactly, and the quotient must come back canonical --
    /// this is the shape that carried a real defect in the vanishing-poly case.
    #[test]
    fn a_root_divides_exactly() {
        let rng = &mut TestRng::default();
        for degree in [1usize, 2, 9, 200] {
            let q = DensePolynomial::<Fr>::rand(degree, rng);
            let z = Fr::rand(rng);
            let divisor = DensePolynomial::from_coefficients_vec(vec![-z, Fr::one()]);
            let p = &divisor * &q;
            let (quotient, r) = p.divide_by_monic_linear(z);
            assert!(r.is_zero(), "remainder at degree {degree}");
            assert_eq!(quotient, q);
            assert!(quotient.coeffs.last().is_none_or(|c| !c.is_zero()), "non-canonical quotient");
        }
    }

    /// Trailing zeros in the coefficient vector must not change the answer.
    #[test]
    fn tolerates_non_canonical_input() {
        let rng = &mut TestRng::default();
        let p = DensePolynomial::<Fr>::rand(30, rng);
        let z = Fr::rand(rng);
        let mut padded = p.clone();
        padded.coeffs.extend(std::iter::repeat_n(Fr::zero(), 5));
        let (q1, r1) = p.divide_by_monic_linear(z);
        let (q2, r2) = padded.divide_by_monic_linear(z);
        assert_eq!(q1, q2);
        assert_eq!(r1, r2);
    }

    #[test]
    fn zero_and_constant_polynomials() {
        let rng = &mut TestRng::default();
        let z = Fr::rand(rng);

        let (q, r) = DensePolynomial::<Fr>::zero().divide_by_monic_linear(z);
        assert!(q.is_zero() && r.is_zero());

        let c = Fr::rand(rng);
        let (q, r) = DensePolynomial::from_coefficients_vec(vec![c]).divide_by_monic_linear(z);
        assert!(q.is_zero());
        assert_eq!(r, c);
    }
}

#[cfg(test)]
mod evaluate_tests {
    use super::vanishing_divide_tests::rand_poly;
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_fields::{One, Zero};
    use snarkvm_utilities::rand::{TestRng, Uniform};

    /// Horner agrees with the powers form it replaced, on well-formed input.
    ///
    /// Field addition is associative, so the tree reduction the powers form
    /// used and Horner's serial accumulation agree exactly rather than
    /// approximately -- `assert_eq!` is the right strength here, not an
    /// epsilon.
    #[test]
    fn evaluate_agrees_with_the_powers_form() {
        let rng = &mut TestRng::default();
        for len in [0usize, 1, 2, 5, 16, 17, 33, 70] {
            let p = rand_poly(len, rng);
            for point in [Fr::zero(), Fr::one(), Fr::rand(rng), Fr::rand(rng)] {
                assert_eq!(p.evaluate(point), p.evaluate_by_powers(point), "len={len}");
            }
        }
    }

    /// `evaluate` tolerates trailing zero coefficients. The powers form it
    /// replaced panicked in `degree()` on exactly this input, so the tolerance
    /// is a deliberate widening rather than an accident.
    #[test]
    fn evaluate_tolerates_trailing_zeros() {
        let rng = &mut TestRng::default();
        for len in [1usize, 5, 17] {
            for pad in [1usize, 4, 20] {
                let mut p = rand_poly(len, rng);
                let point = Fr::rand(rng);
                let expected = p.evaluate(point);
                p.coeffs.resize(p.coeffs.len() + pad, Fr::zero());
                assert_eq!(p.evaluate(point), expected, "len={len} pad={pad}");
            }
        }
    }
}
