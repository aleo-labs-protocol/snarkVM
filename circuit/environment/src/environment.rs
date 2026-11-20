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

use crate::{Assignment, ConstraintUnsatisfied, Inject, LinearCombination, Mode, R1CS, Variable, witness_mode};
use snarkvm_curves::AffineCurve;
use snarkvm_fields::traits::*;

use core::{fmt, hash, marker::PhantomData};

/// Attention: Do not use `Send + Sync` on this trait, as it is not thread-safe.
///
/// This trait is sealed. Only snarkVM implements it.
pub trait Environment:
    crate::sealed_circuit_environment::Sealed
    + 'static
    + Copy
    + Clone
    + fmt::Debug
    + fmt::Display
    + Eq
    + PartialEq
    + hash::Hash
{
    type Network: console::Network<Affine = Self::Affine, Field = Self::BaseField, Scalar = Self::ScalarField>;

    type Affine: AffineCurve<
            BaseField = Self::BaseField,
            ScalarField = Self::ScalarField,
            Coordinates = (Self::BaseField, Self::BaseField),
        >;
    type BaseField: PrimeField + SquareRootField + Copy;
    type ScalarField: PrimeField<BigInteger = <Self::BaseField as PrimeField>::BigInteger> + Copy;

    /// The coefficient `A` of the twisted Edwards curve.
    const EDWARDS_A: Self::BaseField = <Self::Network as console::Environment>::EDWARDS_A;
    /// The coefficient `D` of the twisted Edwards curve.
    const EDWARDS_D: Self::BaseField = <Self::Network as console::Environment>::EDWARDS_D;

    /// The coefficient `A` of the Montgomery curve.
    const MONTGOMERY_A: Self::BaseField = <Self::Network as console::Environment>::MONTGOMERY_A;
    /// The coefficient `B` of the Montgomery curve.
    const MONTGOMERY_B: Self::BaseField = <Self::Network as console::Environment>::MONTGOMERY_B;

    /// The maximum number of bytes allowed in a string.
    const MAX_STRING_BYTES: u32 = <Self::Network as console::Environment>::MAX_STRING_BYTES;

    /// Returns the `zero` constant.
    fn zero() -> LinearCombination<Self::BaseField>;

    /// Returns the `one` constant.
    fn one() -> LinearCombination<Self::BaseField>;

    /// Returns a new variable of the given mode and value.
    fn new_variable(mode: Mode, value: Self::BaseField) -> Variable<Self::BaseField>;

    /// Returns a new witness of the given mode and value.
    fn new_witness<Fn: FnOnce() -> Output::Primitive, Output: Inject>(mode: Mode, value: Fn) -> Output;

    /// Enters a new scope for the environment.
    fn scope<S: Into<String>, Fn, Output>(name: S, logic: Fn) -> Output
    where
        Fn: FnOnce() -> Output;

    /// Adds one constraint enforcing that `(A * B) == C`.
    fn enforce<Fn, A, B, C>(constraint: Fn) -> Result<(), ConstraintUnsatisfied>
    where
        Fn: FnOnce() -> (A, B, C),
        A: Into<LinearCombination<Self::BaseField>>,
        B: Into<LinearCombination<Self::BaseField>>,
        C: Into<LinearCombination<Self::BaseField>>;

    /// Adds one constraint enforcing that the given boolean is `true`.
    fn assert<Boolean: Into<LinearCombination<Self::BaseField>>>(
        boolean: Boolean,
    ) -> Result<(), ConstraintUnsatisfied> {
        Self::enforce(|| (boolean, Self::one(), Self::one()))
    }

    /// Adds one constraint enforcing that the `A == B`.
    fn assert_eq<A, B>(a: A, b: B) -> Result<(), ConstraintUnsatisfied>
    where
        A: Into<LinearCombination<Self::BaseField>>,
        B: Into<LinearCombination<Self::BaseField>>,
    {
        Self::enforce(|| (a, Self::one(), b))
    }

    /// Adds one constraint enforcing that the `A != B`.
    fn assert_neq<A, B>(a: A, b: B) -> Result<(), ConstraintUnsatisfied>
    where
        A: Into<LinearCombination<Self::BaseField>>,
        B: Into<LinearCombination<Self::BaseField>>,
    {
        let (a, b) = (a.into(), b.into());
        let mode = witness_mode!(a, b);

        // Compute `(a - b)`.
        let a_minus_b = a - b;

        // Compute `multiplier` as `1 / (a - b)`.
        let multiplier = match a_minus_b.value().inverse() {
            Some(inverse) => Self::new_variable(mode, inverse).into(),
            None => Self::zero(),
        };

        // Enforce `(a - b) * multiplier == 1`.
        Self::enforce(|| (a_minus_b, multiplier, Self::one()))
    }

    /// Returns `true` if all constraints in the environment are satisfied.
    fn is_satisfied() -> bool;

    /// Returns `true` if all constraints in the current scope are satisfied.
    fn is_satisfied_in_scope() -> bool;

    /// Returns the number of constants in the entire environment.
    fn num_constants() -> u64;

    /// Returns the number of public variables in the entire environment.
    fn num_public() -> u64;

    /// Returns the number of private variables in the entire environment.
    fn num_private() -> u64;

    /// Returns the number of constant, public, and private variables in the entire environment.
    fn num_variables() -> u64;

    /// Returns the number of constraints in the entire environment.
    fn num_constraints() -> u64;

    /// Returns the number of nonzeros in the entire circuit.
    fn num_nonzeros() -> (u64, u64, u64);

    /// Returns a tuple containing the number of constants, public variables, private variables, constraints, and nonzeros in the entire environment.
    fn count() -> (u64, u64, u64, u64, (u64, u64, u64)) {
        (Self::num_constants(), Self::num_public(), Self::num_private(), Self::num_constraints(), Self::num_nonzeros())
    }

    /// Returns the number of constants for the current scope.
    fn num_constants_in_scope() -> u64;

    /// Returns the number of public variables for the current scope.
    fn num_public_in_scope() -> u64;

    /// Returns the number of private variables for the current scope.
    fn num_private_in_scope() -> u64;

    /// Returns the number of constraints for the current scope.
    fn num_constraints_in_scope() -> u64;

    /// Returns the number of nonzeros for the current scope.
    fn num_nonzeros_in_scope() -> (u64, u64, u64);

    /// Returns a tuple containing the number of constants, public variables, private variables, constraints, and nonzeros for the current scope.
    fn count_in_scope() -> (u64, u64, u64, u64, (u64, u64, u64)) {
        (
            Self::num_constants_in_scope(),
            Self::num_public_in_scope(),
            Self::num_private_in_scope(),
            Self::num_constraints_in_scope(),
            Self::num_nonzeros_in_scope(),
        )
    }

    /// Returns the variable limit for the circuit, if one exists.
    fn get_variable_limit() -> Option<u64>;

    /// Sets the variable limit for the circuit.
    fn set_variable_limit(limit: Option<u64>);

    /// Returns the constraint limit for the circuit, if one exists.
    fn get_constraint_limit() -> Option<u64>;

    /// Sets the constraint limit for the circuit.
    fn set_constraint_limit(limit: Option<u64>);

    /// Returns the density limit for the circuit, if one exists.
    fn get_non_zero_limit() -> Option<(u64, u64, u64)>;

    /// Sets the density limit for the circuit.
    fn set_non_zero_limit(limit: Option<(u64, u64, u64)>);

    /// Halts the program from further synthesis, evaluation, and execution in the current environment.
    fn halt<S: Into<String>, T>(message: S) -> T {
        <Self::Network as console::Environment>::halt(message)
    }

    /// Returns the R1CS circuit, resetting the circuit.
    fn inject_r1cs(r1cs: R1CS<Self::BaseField>);

    /// Returns the R1CS circuit, resetting the circuit.
    fn eject_r1cs_and_reset() -> R1CS<Self::BaseField>;

    /// Returns the R1CS assignment of the circuit, resetting the circuit.
    fn eject_assignment_and_reset() -> Assignment<<Self::Network as console::Environment>::Field>;

    /// Clears and initializes an empty environment.
    fn reset();

    /// Replaces this thread's circuit state with the given state, and returns the previous one.
    // Exists for `fresh_circuit` and `CircuitGuard`. A direct call breaks the guards' reverse-order restore.
    #[doc(hidden)]
    fn swap_circuit_state(state: CircuitState<Self::BaseField>) -> CircuitState<Self::BaseField>;

    /// Gives this thread a fresh circuit state until the returned guard drops.
    fn fresh_circuit() -> CircuitGuard<Self> {
        CircuitGuard { outer: Some(Self::swap_circuit_state(CircuitState::default())), _not_send: PhantomData }
    }
}

/// The thread-local state of a circuit: the R1CS, the limits and the witness flag.
pub struct CircuitState<F: PrimeField> {
    pub(crate) r1cs: R1CS<F>,
    pub(crate) variable_limit: Option<u64>,
    pub(crate) constraint_limit: Option<u64>,
    pub(crate) non_zero_limit: Option<(u64, u64, u64)>,
    pub(crate) in_witness: bool,
}

impl<F: PrimeField> Default for CircuitState<F> {
    fn default() -> Self {
        Self {
            r1cs: R1CS::new(),
            variable_limit: None,
            constraint_limit: None,
            non_zero_limit: None,
            in_witness: false,
        }
    }
}

/// Restores the circuit state that `Environment::fresh_circuit` replaced, when dropped or unwound.
///
/// Guards on a thread must drop in reverse order of creation, or an outer state is restored over an inner one.
#[must_use]
pub struct CircuitGuard<E: Environment> {
    outer: Option<CircuitState<E::BaseField>>,
    _not_send: PhantomData<*const ()>,
}

impl<E: Environment> Drop for CircuitGuard<E> {
    fn drop(&mut self) {
        if let Some(outer) = self.outer.take() {
            E::swap_circuit_state(outer);
        }
    }
}

#[cfg(test)]
pub(crate) mod fresh_circuit_tests {
    use super::*;

    type Snapshot = ((u64, u64, u64, u64, (u64, u64, u64)), Option<u64>, Option<u64>, Option<(u64, u64, u64)>, bool);

    const FRESH: Snapshot = ((0, 1, 0, 0, (0, 0, 0)), None, None, None, false);

    fn snapshot<E: Environment>(in_witness: fn() -> bool) -> Snapshot {
        (E::count(), E::get_variable_limit(), E::get_constraint_limit(), E::get_non_zero_limit(), in_witness())
    }

    fn enforce<E: Environment>(num_constraints: usize) {
        for _ in 0..num_constraints {
            let variable = E::new_variable(Mode::Private, E::BaseField::one());
            E::enforce(|| (variable.clone(), E::one(), variable)).unwrap();
        }
    }

    fn seed_outer<E: Environment>(set_in_witness: fn(bool)) {
        enforce::<E>(3);
        E::set_variable_limit(Some(100));
        E::set_constraint_limit(Some(101));
        E::set_non_zero_limit(Some((102, 103, 104)));
        set_in_witness(true);
    }

    pub(crate) fn check_nested<E: Environment>(in_witness: fn() -> bool, set_in_witness: fn(bool)) {
        let _outer = E::fresh_circuit();
        seed_outer::<E>(set_in_witness);
        let outer = snapshot::<E>(in_witness);
        {
            let _inner = E::fresh_circuit();
            assert_eq!(snapshot::<E>(in_witness), FRESH);
            enforce::<E>(2);
            E::set_variable_limit(Some(7));
            E::set_constraint_limit(Some(8));
            E::set_non_zero_limit(Some((9, 10, 11)));
            set_in_witness(true);
        }
        assert_eq!(snapshot::<E>(in_witness), outer);
    }

    pub(crate) fn check_unwind<E: Environment>(in_witness: fn() -> bool, set_in_witness: fn(bool)) {
        let _outer = E::fresh_circuit();
        seed_outer::<E>(set_in_witness);
        let outer = snapshot::<E>(in_witness);
        let result = std::panic::catch_unwind(|| {
            let _inner = E::fresh_circuit();
            enforce::<E>(2);
            E::set_constraint_limit(Some(1));
            enforce::<E>(1);
        });
        assert!(result.is_err(), "the constraint limit must halt synthesis");
        assert_eq!(snapshot::<E>(in_witness), outer);
    }
}
