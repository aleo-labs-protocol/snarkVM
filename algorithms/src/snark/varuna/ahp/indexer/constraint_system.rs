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

use crate::r1cs::{ConstraintSystem as CS, Index as VarIndex, LinearCombination, Variable, errors::SynthesisError};
use snarkvm_fields::Field;

use anyhow::Result;
#[cfg(feature = "test")]
use itertools::Itertools;

/// Stores constraints during index generation.
pub struct ConstraintSystem<F: Field> {
    pub a: Vec<Vec<(F, VarIndex)>>,
    pub b: Vec<Vec<(F, VarIndex)>>,
    pub c: Vec<Vec<(F, VarIndex)>>,
    pub num_public_variables: usize,
    pub num_private_variables: usize,
    pub num_constraints: usize,
}

impl<F: Field> ConstraintSystem<F> {
    #[inline]
    pub fn new() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            num_public_variables: 1,
            num_private_variables: 0,
            num_constraints: 0,
        }
    }

    /// Returns `true` if every constraint holds for the given variable values.
    /// The public values start with the constant one at index 0.
    #[cfg(feature = "test")]
    pub fn is_satisfied(&self, public: &[F], private: &[F]) -> bool {
        let evaluate = |row: &[(F, VarIndex)]| {
            row.iter().fold(F::zero(), |sum, (coefficient, index)| match index {
                VarIndex::Public(i) => sum + *coefficient * public[*i],
                VarIndex::Private(i) => sum + *coefficient * private[*i],
            })
        };
        self.a.iter().zip_eq(&self.b).zip_eq(&self.c).all(|((a, b), c)| evaluate(a) * evaluate(b) == evaluate(c))
    }

    #[inline]
    fn make_row(l: &LinearCombination<F>) -> Vec<(F, VarIndex)> {
        l.as_ref().iter().map(|(var, coeff)| (*coeff, var.get_unchecked())).collect()
    }
}

impl<F: Field> Default for ConstraintSystem<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> CS<F> for ConstraintSystem<F> {
    type Root = Self;

    #[inline]
    fn alloc<Fn, A, AR>(&mut self, _: A, _: Fn) -> Result<Variable, SynthesisError>
    where
        Fn: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        // There is no assignment, so we don't invoke the
        // function for obtaining one.

        let index = self.num_private_variables;
        self.num_private_variables += 1;

        Ok(Variable::new_unchecked(VarIndex::Private(index)))
    }

    #[inline]
    fn alloc_input<Fn, A, AR>(&mut self, _: A, _: Fn) -> Result<Variable, SynthesisError>
    where
        Fn: FnOnce() -> Result<F, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        // There is no assignment, so we don't invoke the
        // function for obtaining one.

        let index = self.num_public_variables;
        self.num_public_variables += 1;

        Ok(Variable::new_unchecked(VarIndex::Public(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: AsRef<str>,
        LA: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LB: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
        LC: FnOnce(LinearCombination<F>) -> LinearCombination<F>,
    {
        self.a.push(Self::make_row(&a(LinearCombination::zero())));
        self.b.push(Self::make_row(&b(LinearCombination::zero())));
        self.c.push(Self::make_row(&c(LinearCombination::zero())));

        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: AsRef<str>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    fn num_public_variables(&self) -> usize {
        self.num_public_variables
    }

    fn num_private_variables(&self) -> usize {
        self.num_private_variables
    }

    fn is_in_setup_mode(&self) -> bool {
        true
    }
}
