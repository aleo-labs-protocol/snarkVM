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

use crate::{LinearCombination, Mode};
use snarkvm_fields::traits::*;

use core::{
    cmp::Ordering,
    fmt,
    ops::{Add, Sub},
};
use std::sync::Arc;

pub type Index = u64;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Variable<F: PrimeField> {
    Constant(Arc<F>),
    Public(Arc<(Index, F)>),
    Private(Arc<(Index, F)>),
}

impl<F: PrimeField> Variable<F> {
    ///
    /// Returns `true` if the variable is a constant.
    ///
    pub fn is_constant(&self) -> bool {
        matches!(self, Self::Constant(..))
    }

    ///
    /// Returns `true` if the variable is public.
    ///
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public(..))
    }

    ///
    /// Returns `true` if the variable is private.
    ///
    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private(..))
    }

    ///
    /// Returns the mode of the variable.
    ///
    pub fn mode(&self) -> Mode {
        match self {
            Self::Constant(..) => Mode::Constant,
            Self::Public(..) => Mode::Public,
            Self::Private(..) => Mode::Private,
        }
    }

    ///
    /// Returns the relative index of the variable.
    ///
    pub fn index(&self) -> Index {
        match self {
            Self::Constant(..) => 0,
            Self::Public(index_value) | Self::Private(index_value) => {
                let (index, _value) = index_value.as_ref();
                *index
            }
        }
    }

    ///
    /// Returns the value of the variable.
    ///
    pub fn value(&self) -> F {
        match self {
            Self::Constant(value) => **value,
            Self::Public(index_value) | Self::Private(index_value) => {
                let (_index, value) = index_value.as_ref();
                *value
            }
        }
    }

    ///
    /// Returns the relative index and value of the variable.
    ///
    pub fn index_value(&self) -> (Index, F) {
        match self {
            Self::Constant(value) => (0, **value),
            Self::Public(index_value) | Self::Private(index_value) => {
                let (index, value) = index_value.as_ref();
                (*index, *value)
            }
        }
    }
}

impl<F: PrimeField> PartialOrd for Variable<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: PrimeField> Ord for Variable<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Constant(v1), Self::Constant(v2)) => v1.cmp(v2),
            (Self::Constant(..), Self::Public(..)) => Ordering::Less,
            (Self::Constant(..), Self::Private(..)) => Ordering::Less,
            (Self::Public(..), Self::Constant(..)) => Ordering::Greater,
            (Self::Private(..), Self::Constant(..)) => Ordering::Greater,
            (Self::Public(a), Self::Public(b)) | (Self::Private(a), Self::Private(b)) => {
                // `a.cmp(b)` orders the same, but `F::cmp` takes both sides out of Montgomery form, even when equal.
                a.0.cmp(&b.0).then_with(|| if a.1 == b.1 { Ordering::Equal } else { a.1.cmp(&b.1) })
            }
            (Self::Public(..), Self::Private(..)) => Ordering::Less,
            (Self::Private(..), Self::Public(..)) => Ordering::Greater,
        }
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Add<Variable<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: Variable<F>) -> Self::Output {
        self + &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Add<Variable<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: Variable<F>) -> Self::Output {
        self + &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Add<&Variable<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: &Variable<F>) -> Self::Output {
        &self + other
    }
}

impl<F: PrimeField> Add<&Variable<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: &Variable<F>) -> Self::Output {
        match (self, other) {
            (Variable::Constant(a), Variable::Constant(b)) => Variable::Constant(Arc::new(**a + **b)).into(),
            (first, second) => LinearCombination::from([first.clone(), second.clone()]),
        }
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Add<LinearCombination<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: LinearCombination<F>) -> Self::Output {
        self + &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Add<LinearCombination<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: LinearCombination<F>) -> Self::Output {
        self + &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Add<&LinearCombination<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: &LinearCombination<F>) -> Self::Output {
        &self + other
    }
}

impl<F: PrimeField> Add<&LinearCombination<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn add(self, other: &LinearCombination<F>) -> Self::Output {
        LinearCombination::from(self) + other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Sub<Variable<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: Variable<F>) -> Self::Output {
        self - &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Sub<Variable<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: Variable<F>) -> Self::Output {
        self - &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Sub<&Variable<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: &Variable<F>) -> Self::Output {
        &self - other
    }
}

impl<F: PrimeField> Sub<&Variable<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: &Variable<F>) -> Self::Output {
        match (self, other) {
            (Variable::Constant(a), Variable::Constant(b)) => Variable::Constant(Arc::new(**a - **b)).into(),
            (first, second) => LinearCombination::from(first) - second,
        }
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Sub<LinearCombination<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: LinearCombination<F>) -> Self::Output {
        self - &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Sub<LinearCombination<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: LinearCombination<F>) -> Self::Output {
        self - &other
    }
}

#[allow(clippy::op_ref)]
impl<F: PrimeField> Sub<&LinearCombination<F>> for Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: &LinearCombination<F>) -> Self::Output {
        &self - other
    }
}

impl<F: PrimeField> Sub<&LinearCombination<F>> for &Variable<F> {
    type Output = LinearCombination<F>;

    fn sub(self, other: &LinearCombination<F>) -> Self::Output {
        LinearCombination::from(self) - other
    }
}

impl<F: PrimeField> fmt::Debug for Variable<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Constant(value) => format!("Constant({value})"),
            Self::Public(index_value) => {
                let (index, value) = index_value.as_ref();
                format!("Public({index}, {value})")
            }
            Self::Private(index_value) => {
                let (index, value) = index_value.as_ref();
                format!("Private({index}, {value})")
            }
        })
    }
}

impl<F: PrimeField> fmt::Display for Variable<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use snarkvm_fields::One;
    use snarkvm_utilities::{TestRng, Uniform};

    use core::cmp::Ordering;
    use std::sync::Arc;

    type F = <Circuit as Environment>::BaseField;

    /// Orders by kind, then constants by value, then variables by their `(index, value)` tuple.
    fn reference_cmp(a: &Variable<F>, b: &Variable<F>) -> Ordering {
        match (a, b) {
            (Variable::Constant(v1), Variable::Constant(v2)) => v1.cmp(v2),
            (Variable::Constant(..), _) => Ordering::Less,
            (_, Variable::Constant(..)) => Ordering::Greater,
            (Variable::Public(i1), Variable::Public(i2)) => i1.cmp(i2),
            (Variable::Private(i1), Variable::Private(i2)) => i1.cmp(i2),
            (Variable::Public(..), Variable::Private(..)) => Ordering::Less,
            (Variable::Private(..), Variable::Public(..)) => Ordering::Greater,
        }
    }

    #[test]
    fn test_size() {
        assert_eq!(16, std::mem::size_of::<Variable<<Circuit as Environment>::BaseField>>());
    }

    #[test]
    fn test_cmp_matches_reference() {
        let mut rng = TestRng::default();
        for _ in 0..100 {
            let mut pool = vec![Variable::Public(Arc::new((0, F::one())))];
            for index in 0..4 {
                let value = F::rand(&mut rng);
                pool.push(Variable::Constant(Arc::new(F::from(u32::rand(&mut rng) as u128 % 3))));
                pool.push(Variable::Public(Arc::new((index, value))));
                pool.push(Variable::Public(Arc::new((index, value))));
                pool.push(Variable::Public(Arc::new((index, F::rand(&mut rng)))));
                pool.push(Variable::Private(Arc::new((index, value))));
                pool.push(Variable::Private(Arc::new((index, value))));
                pool.push(Variable::Private(Arc::new((index, F::rand(&mut rng)))));
            }
            for a in &pool {
                for b in &pool {
                    assert_eq!(reference_cmp(a, b), a.cmp(b), "{a:?} vs {b:?}");
                }
            }
        }
    }
}
