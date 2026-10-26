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

use crate::{Mode, *};
use snarkvm_fields::PrimeField;

use core::{
    fmt,
    ops::{Add, AddAssign, Mul, Neg, Sub},
};
use smallvec::SmallVec;

// Before high level program operations are converted into constraints, they are first tracked as linear combinations.
// Each linear combination corresponds to a portion or all of a single row of an R1CS matrix, and consists of:
// \begin{itemize}
//     \item constant and variable terms, representing the constraint system at 'compile time'.
//           It can be seen as a multivariate polynomial, a sum of monomials.
//     \item value term, representing the value of the assigned linear combination at 'proving time'.
//           Which means it is the fully assigned subset of a row of a matrix.
// \end{itemize}
// The constant and variable terms directly refer to how often the R1CS variables are invoked in a row.
// A full R1CS row is "completed" when we introduce a multiplication between three non-const linear combinations (a*b=c).
#[derive(Clone, Hash)]
pub struct LinearCombination<F: PrimeField> {
    constant: F,
    /// The list of terms is kept sorted in order to speed up lookups.
    terms: SmallVec<[(Variable<F>, F); 1]>,
    /// The value of this linear combination, defined as the sum of the `terms` and `constant`.
    value: F,
}

impl<F: PrimeField> LinearCombination<F> {
    /// Returns the `zero` constant.
    pub(crate) fn zero() -> Self {
        Self { constant: F::zero(), terms: Default::default(), value: Default::default() }
    }

    /// Returns the `one` constant.
    pub(crate) fn one() -> Self {
        Self { constant: F::one(), terms: Default::default(), value: F::one() }
    }

    /// Returns `true` if there are no terms in the linear combination.
    pub fn is_constant(&self) -> bool {
        self.terms.is_empty()
    }

    /// Returns `true` if there is exactly one term with a coefficient of one,
    /// and the term contains a public variable.
    pub fn is_public(&self) -> bool {
        self.constant.is_zero()
            && self.terms.len() == 1
            && match self.terms.first() {
                Some((Variable::Public(..), coefficient)) => *coefficient == F::one(),
                _ => false,
            }
    }

    /// Returns `true` if the linear combination is not constant or public.
    pub fn is_private(&self) -> bool {
        !self.is_constant() && !self.is_public()
    }

    /// Returns the mode of this linear combination.
    pub fn mode(&self) -> Mode {
        if self.is_constant() {
            Mode::Constant
        } else if self.is_public() {
            Mode::Public
        } else {
            Mode::Private
        }
    }

    /// Returns the computed value of the linear combination.
    pub fn value(&self) -> F {
        self.value
    }

    ///
    /// Returns `true` if the linear combination represents a `Boolean` type,
    /// and is well-formed.
    ///
    /// Properties:
    /// 1. Either `constant` or `terms` is utilized, however never both.
    /// 2. Every individual variable in the linear combination must always be either `0` or `1`.
    /// 3. The value of the linear combination must always be either `0` or `1`.
    pub fn is_boolean_type(&self) -> bool {
        // Constant case (enforce Property 1)
        if self.terms.is_empty() {
            self.constant.is_zero() || self.constant.is_one()
        }
        // Public and private cases (enforce Property 1)
        else if self.constant.is_zero() {
            // Enforce property 2.
            // Note: This branch is triggered if ANY term is not (zero or one).
            if self.terms.iter().any(|(v, _)| !(v.value().is_zero() || v.value().is_one())) {
                eprintln!("Property 2 of the `Boolean` type was violated in {self}");
                return false;
            }

            // Enforce property 3.
            if !(self.value.is_zero() || self.value.is_one()) {
                eprintln!("Property 3 of the `Boolean` type was violated");
                return false;
            }

            true
        } else {
            // Property 1 of the `Boolean` type was violated.
            // Both self.constant and self.terms contain elements.
            eprintln!("Both LC::constant and LC::terms contain elements, which is a violation");
            false
        }
    }

    /// Returns only the constant value (excluding the terms) in the linear combination.
    pub(super) fn to_constant(&self) -> F {
        self.constant
    }

    /// Returns the terms (excluding the constant value) in the linear combination.
    pub(super) fn to_terms(&self) -> &[(Variable<F>, F)] {
        &self.terms
    }

    /// Returns the number of nonzeros in the linear combination.
    // This now combines the Public(0) variable with the linear combination's constant, as was
    // always done by generate_constraints at the end of circuit synthesis (and therefore, as
    // exposed in circuit verifying keys)
    pub(super) fn num_nonzeros(&self) -> u64 {
        let n_terms = self.terms.len() as u64;

        // We operate depending on whether the Public(0) variable appears in the linear combination.
        if let Some(constant_as_var_coeff) = self
            .terms
            .iter()
            .find_map(|(var, coeff)| if var.index() == 0 && var.is_public() { Some(*coeff) } else { None })
        {
            if constant_as_var_coeff + self.constant == F::zero() {
                // The the Public(0) variable (counted in n_terms) and self.constant will cancel out
                // when added together. Note this subtraction is safe as n_terms contains Public(0).
                n_terms - 1
            } else {
                // Public(0) + self.constant != 0 will merge into a single non-zero entry, already
                // counted in n_terms.
                n_terms
            }
        } else if self.constant.is_zero() {
            // No term for the Public(0) variable and no constant in the final linear
            // combination.
            n_terms
        } else {
            // No term for the Public(0) variable, but the constant will appear in the final
            // linear combination.
            n_terms + 1
        }
    }

    /// Returns the number of addition gates in the linear combination.
    #[cfg(test)]
    pub(super) fn num_additions(&self) -> u64 {
        // Increment by one if the constant is nonzero and the number of terms is nonzero.
        match !self.constant.is_zero() && !self.terms.is_empty() {
            true => self.terms.len() as u64,
            false => (self.terms.len() as u64).saturating_sub(1),
        }
    }
}

impl<F: PrimeField> From<Variable<F>> for LinearCombination<F> {
    fn from(variable: Variable<F>) -> Self {
        Self::from(&variable)
    }
}

impl<F: PrimeField> From<&Variable<F>> for LinearCombination<F> {
    fn from(variable: &Variable<F>) -> Self {
        Self::from(std::slice::from_ref(variable))
    }
}

impl<F: PrimeField, const N: usize> From<[Variable<F>; N]> for LinearCombination<F> {
    fn from(variables: [Variable<F>; N]) -> Self {
        Self::from(&variables[..])
    }
}

impl<F: PrimeField, const N: usize> From<&[Variable<F>; N]> for LinearCombination<F> {
    fn from(variables: &[Variable<F>; N]) -> Self {
        Self::from(&variables[..])
    }
}

impl<F: PrimeField> From<Vec<Variable<F>>> for LinearCombination<F> {
    fn from(variables: Vec<Variable<F>>) -> Self {
        Self::from(variables.as_slice())
    }
}

impl<F: PrimeField> From<&Vec<Variable<F>>> for LinearCombination<F> {
    fn from(variables: &Vec<Variable<F>>) -> Self {
        Self::from(variables.as_slice())
    }
}

impl<F: PrimeField> From<&[Variable<F>]> for LinearCombination<F> {
    fn from(variables: &[Variable<F>]) -> Self {
        let mut output = Self::zero();
        for variable in variables {
            match variable.is_constant() {
                true => output.constant += variable.value(),
                false => {
                    match output.terms.binary_search_by(|(v, _)| v.cmp(variable)) {
                        Ok(idx) => {
                            // Increment the existing coefficient by 1.
                            output.terms[idx].1 += F::one();
                            // If the coefficient of the term is now zero, remove the entry.
                            if output.terms[idx].1.is_zero() {
                                output.terms.remove(idx);
                            }
                        }
                        Err(idx) => {
                            // Insert the variable and a coefficient of 1 as a new term.
                            output.terms.insert(idx, (variable.clone(), F::one()));
                        }
                    }
                }
            }
            // Increment the value of the linear combination by the variable.
            output.value += variable.value();
        }
        output
    }
}

impl<F: PrimeField> Neg for LinearCombination<F> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        let mut output = self;
        output.constant = -output.constant;
        output.terms.iter_mut().for_each(|(_, coefficient)| *coefficient = -(*coefficient));
        output.value = -output.value;
        output
    }
}

impl<F: PrimeField> Neg for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    #[inline]
    fn neg(self) -> Self::Output {
        -(self.clone())
    }
}

impl<F: PrimeField> Add<Variable<F>> for LinearCombination<F> {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn add(self, other: Variable<F>) -> Self::Output {
        self + &other
    }
}

impl<F: PrimeField> Add<&Variable<F>> for LinearCombination<F> {
    type Output = Self;

    fn add(self, other: &Variable<F>) -> Self::Output {
        self + Self::from(other)
    }
}

impl<F: PrimeField> Add<Variable<F>> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    #[allow(clippy::op_ref)]
    fn add(self, other: Variable<F>) -> Self::Output {
        self.clone() + &other
    }
}

impl<F: PrimeField> Add<LinearCombination<F>> for LinearCombination<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        self + &other
    }
}

impl<F: PrimeField> Add<&LinearCombination<F>> for LinearCombination<F> {
    type Output = Self;

    fn add(self, other: &Self) -> Self::Output {
        &self + other
    }
}

impl<F: PrimeField> Add<LinearCombination<F>> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: LinearCombination<F>) -> Self::Output {
        self + &other
    }
}

impl<F: PrimeField> Add<&LinearCombination<F>> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: &LinearCombination<F>) -> Self::Output {
        if self.constant.is_zero() && self.terms.is_empty() {
            other.clone()
        } else if other.constant.is_zero() && other.terms.is_empty() {
            self.clone()
        } else if self.terms.len() > other.terms.len() {
            let mut output = self.clone();
            output += other;
            output
        } else {
            let mut output = other.clone();
            output += self;
            output
        }
    }
}

impl<F: PrimeField> AddAssign<LinearCombination<F>> for LinearCombination<F> {
    fn add_assign(&mut self, other: Self) {
        *self += &other;
    }
}

impl<F: PrimeField> AddAssign<&LinearCombination<F>> for LinearCombination<F> {
    fn add_assign(&mut self, other: &Self) {
        // If `other` is empty, return immediately.
        if other.constant.is_zero() && other.terms.is_empty() {
            return;
        }

        if self.constant.is_zero() && self.terms.is_empty() {
            *self = other.clone();
        } else {
            // Add the constant value from `other` to `self`.
            self.constant += other.constant;

            // Add the terms from `other` to the terms of `self`.
            for (variable, coefficient) in other.terms.iter() {
                match variable.is_constant() {
                    true => panic!("Malformed linear combination found"),
                    false => {
                        match self.terms.binary_search_by(|(v, _)| v.cmp(variable)) {
                            Ok(idx) => {
                                // Add the coefficient to the existing coefficient for this term.
                                self.terms[idx].1 += *coefficient;
                                // If the coefficient of the term is now zero, remove the entry.
                                if self.terms[idx].1.is_zero() {
                                    self.terms.remove(idx);
                                }
                            }
                            Err(idx) => {
                                // Insert the variable and coefficient as a new term.
                                self.terms.insert(idx, (variable.clone(), *coefficient));
                            }
                        }
                    }
                }
            }

            // Add the value from `other` to `self`.
            self.value += other.value;
        }
    }
}

impl<F: PrimeField> Sub<Variable<F>> for LinearCombination<F> {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn sub(self, other: Variable<F>) -> Self::Output {
        self - &other
    }
}

impl<F: PrimeField> Sub<&Variable<F>> for LinearCombination<F> {
    type Output = Self;

    fn sub(self, other: &Variable<F>) -> Self::Output {
        self - Self::from(other)
    }
}

impl<F: PrimeField> Sub<Variable<F>> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    #[allow(clippy::op_ref)]
    fn sub(self, other: Variable<F>) -> Self::Output {
        self.clone() - &other
    }
}

impl<F: PrimeField> Sub<LinearCombination<F>> for LinearCombination<F> {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        self - &other
    }
}

impl<F: PrimeField> Sub<&LinearCombination<F>> for LinearCombination<F> {
    type Output = Self;

    fn sub(self, other: &Self) -> Self::Output {
        &self - other
    }
}

impl<F: PrimeField> Sub<LinearCombination<F>> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: LinearCombination<F>) -> Self::Output {
        self - &other
    }
}

impl<F: PrimeField> Sub<&LinearCombination<F>> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: &LinearCombination<F>) -> Self::Output {
        self + &(-other)
    }
}

impl<F: PrimeField> Mul<F> for LinearCombination<F> {
    type Output = Self;

    #[allow(clippy::op_ref)]
    fn mul(self, coefficient: F) -> Self::Output {
        self * &coefficient
    }
}

impl<F: PrimeField> Mul<&F> for LinearCombination<F> {
    type Output = Self;

    fn mul(self, coefficient: &F) -> Self::Output {
        let mut output = self;
        output.constant *= coefficient;
        output.terms.retain_mut(|(_v, current_coefficient)| {
            *current_coefficient *= coefficient;
            !current_coefficient.is_zero()
        });
        output.value *= coefficient;
        output
    }
}

impl<F: PrimeField> Mul<F> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    #[allow(clippy::op_ref)]
    fn mul(self, coefficient: F) -> Self::Output {
        self * &coefficient
    }
}

impl<F: PrimeField> Mul<&F> for &LinearCombination<F> {
    type Output = LinearCombination<F>;

    fn mul(self, coefficient: &F) -> Self::Output {
        self.clone() * coefficient
    }
}

impl<F: PrimeField> fmt::Debug for LinearCombination<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let mut output = format!("Constant({})", self.constant);

        for (variable, coefficient) in &self.terms {
            output += &match (variable.mode(), coefficient.is_one()) {
                (Mode::Constant, _) => panic!("Malformed linear combination at: ({coefficient} * {variable:?})"),
                (_, true) => format!(" + {variable:?}"),
                _ => format!(" + {coefficient} * {variable:?}"),
            };
        }
        write!(f, "{output}")
    }
}

impl<F: PrimeField> fmt::Display for LinearCombination<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_fields::{One as O, Zero as Z};

    use std::sync::Arc;

    #[test]
    fn test_zero() {
        let zero = <Circuit as Environment>::BaseField::zero();

        let candidate = LinearCombination::zero();
        assert_eq!(zero, candidate.constant);
        assert!(candidate.terms.is_empty());
        assert_eq!(zero, candidate.value());
    }

    #[test]
    fn test_one() {
        let one = <Circuit as Environment>::BaseField::one();

        let candidate = LinearCombination::one();
        assert_eq!(one, candidate.constant);
        assert!(candidate.terms.is_empty());
        assert_eq!(one, candidate.value());
    }

    #[test]
    fn test_two() {
        let one = <Circuit as Environment>::BaseField::one();
        let two = one + one;

        let candidate = LinearCombination::one() + LinearCombination::one();
        assert_eq!(two, candidate.constant);
        assert!(candidate.terms.is_empty());
        assert_eq!(two, candidate.value());
    }

    #[test]
    fn test_is_constant() {
        let zero = <Circuit as Environment>::BaseField::zero();
        let one = <Circuit as Environment>::BaseField::one();

        let candidate = LinearCombination::zero();
        assert!(candidate.is_constant());
        assert_eq!(zero, candidate.constant);
        assert_eq!(zero, candidate.value());

        let candidate = LinearCombination::one();
        assert!(candidate.is_constant());
        assert_eq!(one, candidate.constant);
        assert_eq!(one, candidate.value());
    }

    #[test]
    fn test_mul() {
        let zero = <Circuit as Environment>::BaseField::zero();
        let one = <Circuit as Environment>::BaseField::one();
        let two = one + one;
        let four = two + two;

        let start = LinearCombination::from(Variable::Public(Arc::new((1, one))));
        assert!(!start.is_constant());
        assert_eq!(one, start.value());

        // Compute 1 * 4.
        let candidate = start * four;
        assert_eq!(four, candidate.value());
        assert_eq!(zero, candidate.constant);
        assert_eq!(1, candidate.terms.len());

        let (candidate_variable, candidate_coefficient) = candidate.terms.first().unwrap();
        assert!(candidate_variable.is_public());
        assert_eq!(one, candidate_variable.value());
        assert_eq!(four, *candidate_coefficient);
    }

    #[test]
    fn test_debug() {
        let one_public = &Circuit::new_variable(Mode::Public, <Circuit as Environment>::BaseField::one());
        let one_private = &Circuit::new_variable(Mode::Private, <Circuit as Environment>::BaseField::one());
        {
            let expected = "Constant(1) + Public(1, 1) + Private(0, 1)";

            let candidate = LinearCombination::one() + one_public + one_private;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_private + one_public + LinearCombination::one();
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_private + LinearCombination::one() + one_public;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_public + LinearCombination::one() + one_private;
            assert_eq!(expected, format!("{candidate:?}"));
        }
        {
            let expected = "Constant(1) + 2 * Public(1, 1) + Private(0, 1)";

            let candidate = LinearCombination::one() + one_public + one_public + one_private;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_private + one_public + LinearCombination::one() + one_public;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_public + one_private + LinearCombination::one() + one_public;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_public + LinearCombination::one() + one_private + one_public;
            assert_eq!(expected, format!("{candidate:?}"));
        }
        {
            let expected = "Constant(1) + Public(1, 1) + 2 * Private(0, 1)";

            let candidate = LinearCombination::one() + one_public + one_private + one_private;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_private + one_public + LinearCombination::one() + one_private;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_private + one_private + LinearCombination::one() + one_public;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_public + LinearCombination::one() + one_private + one_private;
            assert_eq!(expected, format!("{candidate:?}"));
        }
        {
            let expected = "Constant(1) + Public(1, 1)";

            let candidate = LinearCombination::one() + one_public + one_private - one_private;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_private + one_public + LinearCombination::one() - one_private;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_private - one_private + LinearCombination::one() + one_public;
            assert_eq!(expected, format!("{candidate:?}"));

            let candidate = one_public + LinearCombination::one() + one_private - one_private;
            assert_eq!(expected, format!("{candidate:?}"));
        }
    }

    #[rustfmt::skip]
    #[test]
    fn test_num_additions() {
        let one_public = &Circuit::new_variable(Mode::Public, <Circuit as Environment>::BaseField::one());
        let one_private = &Circuit::new_variable(Mode::Private, <Circuit as Environment>::BaseField::one());
        let two_private = one_private + one_private;

        let candidate = LinearCombination::<<Circuit as Environment>::BaseField>::zero();
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::<<Circuit as Environment>::BaseField>::one();
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public + one_public;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public + one_public;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public + one_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public + one_private;
        assert_eq!(2, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public + one_private + one_public;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public + one_private + one_public;
        assert_eq!(2, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public + one_private + one_public + one_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public + one_private + one_public + one_private;
        assert_eq!(2, candidate.num_additions());

        let candidate = LinearCombination::zero() + LinearCombination::zero() + one_public + one_private + one_public + one_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + one_public + one_private + one_public + one_private;
        assert_eq!(2, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + LinearCombination::one() + one_public + one_private + one_public + one_private;
        assert_eq!(2, candidate.num_additions());

        let candidate = LinearCombination::zero() + LinearCombination::zero() + one_public + one_private + one_public + one_private + &two_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + one_public + one_private + one_public + one_private + &two_private;
        assert_eq!(2, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + LinearCombination::one() + one_public + one_private + one_public + one_private + &two_private;
        assert_eq!(2, candidate.num_additions());

        // Now check with subtractions.

        let candidate = LinearCombination::zero() - one_public;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() - one_public;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public - one_public;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public - one_public;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public - one_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public - one_private;
        assert_eq!(2, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public + one_private - one_public;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public + one_private - one_public;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::zero() + one_public + one_private + one_public - one_private;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() + one_public + one_private + one_public - one_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::zero() + LinearCombination::zero() + one_public + one_private + one_public - one_private;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + one_public + one_private + one_public - one_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + LinearCombination::one() + one_public + one_private + one_public - one_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::zero() + LinearCombination::zero() + one_public + one_private + one_public + one_private - &two_private;
        assert_eq!(0, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + one_public + one_private + one_public + one_private - &two_private;
        assert_eq!(1, candidate.num_additions());

        let candidate = LinearCombination::one() + LinearCombination::zero() + LinearCombination::one() + one_public + one_private + one_public + one_private - &two_private;
        assert_eq!(1, candidate.num_additions());
    }
}
