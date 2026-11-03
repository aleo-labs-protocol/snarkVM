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

use crate::{ConstraintUnsatisfied, Mode, helpers::Constraint, *};

use core::{
    cell::{Cell, RefCell},
    fmt,
};

type Field = <console::CanaryV0 as console::Environment>::Field;

thread_local! {
    static VARIABLE_LIMIT: Cell<Option<u64>> = const { Cell::new(None) };
    static CONSTRAINT_LIMIT: Cell<Option<u64>> = const { Cell::new(None) };
    static NON_ZERO_LIMIT: Cell<Option<(u64, u64, u64)>> = const { Cell::new(None) };
    pub(super) static CANARY_CIRCUIT: RefCell<R1CS<Field>> = RefCell::new(R1CS::new());
    static IN_WITNESS: Cell<bool> = const { Cell::new(false) };
    static ZERO: LinearCombination<Field> = LinearCombination::zero();
    static ONE: LinearCombination<Field> = LinearCombination::one();
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct CanaryCircuit;

impl Environment for CanaryCircuit {
    type Affine = <console::CanaryV0 as console::Environment>::Affine;
    type BaseField = Field;
    type Network = console::CanaryV0;
    type ScalarField = <console::CanaryV0 as console::Environment>::Scalar;

    /// Returns the `zero` constant.
    fn zero() -> LinearCombination<Self::BaseField> {
        ZERO.with(|zero| zero.clone())
    }

    /// Returns the `one` constant.
    fn one() -> LinearCombination<Self::BaseField> {
        ONE.with(|one| one.clone())
    }

    /// Returns a new variable of the given mode and value.
    fn new_variable(mode: Mode, value: Self::BaseField) -> Variable<Self::BaseField> {
        IN_WITNESS.with(|in_witness| {
            // Ensure we are not in witness mode.
            if !in_witness.get() {
                // Ensure that we do not surpass the variable limit for the circuit.
                VARIABLE_LIMIT.with(|variable_limit| {
                    if let Some(limit) = variable_limit.get() {
                        // Note: because we check > here, one could theoretically construct a
                        // circuit with variable_limit + 1 variables.
                        if Self::num_variables() > limit {
                            Self::halt(format!("Surpassed the variable limit ({limit})"))
                        }
                    }
                });
                CANARY_CIRCUIT.with(|circuit| match mode {
                    Mode::Constant => circuit.borrow_mut().new_constant(value),
                    Mode::Public => circuit.borrow_mut().new_public(value),
                    Mode::Private => circuit.borrow_mut().new_private(value),
                })
            } else {
                Self::halt("Tried to initialize a new variable in witness mode")
            }
        })
    }

    /// Returns a new witness of the given mode and value.
    fn new_witness<Fn: FnOnce() -> Output::Primitive, Output: Inject>(mode: Mode, logic: Fn) -> Output {
        IN_WITNESS.with(|in_witness| {
            // Set the entire environment to witness mode.
            in_witness.replace(true);

            // Run the logic.
            let output = logic();

            // Return the entire environment from witness mode.
            in_witness.replace(false);

            Inject::new(mode, output)
        })
    }

    /// Enters a new scope for the environment.
    fn scope<S: Into<String>, Fn, Output>(name: S, logic: Fn) -> Output
    where
        Fn: FnOnce() -> Output,
    {
        IN_WITNESS.with(|in_witness| {
            // Ensure we are not in witness mode.
            if !in_witness.get() {
                CANARY_CIRCUIT.with(|circuit| {
                    // Set the entire environment to the new scope.
                    let name = name.into();
                    if let Err(error) = circuit.borrow_mut().push_scope(&name) {
                        Self::halt(error)
                    }

                    // Run the logic.
                    let output = logic();

                    // Return the entire environment to the previous scope.
                    if let Err(error) = circuit.borrow_mut().pop_scope(name) {
                        Self::halt(error)
                    }

                    output
                })
            } else {
                Self::halt("Tried to initialize a new scope in witness mode")
            }
        })
    }

    /// Adds one constraint enforcing that `(A * B) == C`.
    fn enforce<Fn, A, B, C>(constraint: Fn) -> Result<(), ConstraintUnsatisfied>
    where
        Fn: FnOnce() -> (A, B, C),
        A: Into<LinearCombination<Self::BaseField>>,
        B: Into<LinearCombination<Self::BaseField>>,
        C: Into<LinearCombination<Self::BaseField>>,
    {
        IN_WITNESS.with(|in_witness| {
            // Ensure we are not in witness mode.
            if !in_witness.get() {
                CANARY_CIRCUIT.with(|circuit| {
                    // Ensure that we do not surpass the constraint limit for the circuit.
                    CONSTRAINT_LIMIT.with(|constraint_limit| {
                        if let Some(limit) = constraint_limit.get() {
                            // Note: because we check > here, one could theoretically construct a
                            // circuit with constraint_limit + 1 constraints.
                            if circuit.borrow().num_constraints() > limit {
                                Self::halt(format!("Surpassed the constraint limit ({limit})"))
                            }
                        }
                    });

                    let (a, b, c) = constraint();
                    let (a, b, c) = (a.into(), b.into(), c.into());

                    // Ensure the constraint is not comprised of constants.
                    match a.is_constant() && b.is_constant() && c.is_constant() {
                        true => {
                            // Evaluate the constant constraint.
                            if a.value() * b.value() != c.value() {
                                return Err(ConstraintUnsatisfied {
                                    a: a.to_string(),
                                    b: b.to_string(),
                                    c: c.to_string(),
                                });
                            }
                        }
                        false => {
                            // Construct the constraint object.
                            let constraint = Constraint(circuit.borrow().scope(), a, b, c);

                            // Ensure that we do not surpass the density limit for the circuit.
                            NON_ZERO_LIMIT.with(|non_zero_limit| {
                                if let Some((limit_a, limit_b, limit_c)) = non_zero_limit.get() {
                                    let (curr_d_a, curr_d_b, curr_d_c) = circuit.borrow().num_nonzeros();
                                    let (d_a, d_b, d_c) = constraint.num_nonzeros();
                                    if curr_d_a.saturating_add(d_a) > limit_a
                                        || curr_d_b.saturating_add(d_b) > limit_b
                                        || curr_d_c.saturating_add(d_c) > limit_c
                                    {
                                        Self::halt(format!(
                                            "Surpassed the circuit density limit (A: {limit_a}, B: {limit_b}, C: {limit_c}). Was ({curr_d_a}, {curr_d_b}, {curr_d_c}) before, tried to add ({d_a}, {d_b}, {d_c})"
                                        ))
                                    }
                                }
                            });

                            // Append the constraint.
                            circuit.borrow_mut().enforce(constraint)
                        }
                    }
                    Ok(())
                })
            } else {
                Self::halt("Tried to add a new constraint in witness mode")
            }
        })
    }

    /// Returns `true` if all constraints in the environment are satisfied.
    fn is_satisfied() -> bool {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().is_satisfied())
    }

    /// Returns `true` if all constraints in the current scope are satisfied.
    fn is_satisfied_in_scope() -> bool {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().is_satisfied_in_scope())
    }

    /// Returns the number of constants in the entire circuit.
    fn num_constants() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_constants())
    }

    /// Returns the number of public variables in the entire circuit.
    fn num_public() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_public())
    }

    /// Returns the number of private variables in the entire circuit.
    fn num_private() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_private())
    }

    /// Returns the number of constant, public, and private variables in the entire circuit.
    fn num_variables() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_variables())
    }

    /// Returns the number of constraints in the entire circuit.
    fn num_constraints() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_constraints())
    }

    /// Returns the number of nonzeros in the entire circuit.
    fn num_nonzeros() -> (u64, u64, u64) {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_nonzeros())
    }

    /// Returns the number of constants for the current scope.
    fn num_constants_in_scope() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_constants_in_scope())
    }

    /// Returns the number of public variables for the current scope.
    fn num_public_in_scope() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_public_in_scope())
    }

    /// Returns the number of private variables for the current scope.
    fn num_private_in_scope() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_private_in_scope())
    }

    /// Returns the number of constraints for the current scope.
    fn num_constraints_in_scope() -> u64 {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_constraints_in_scope())
    }

    /// Returns the number of nonzeros for the current scope.
    fn num_nonzeros_in_scope() -> (u64, u64, u64) {
        CANARY_CIRCUIT.with(|circuit| circuit.borrow().num_nonzeros_in_scope())
    }

    /// Returns the variable limit for the circuit, if one exists.
    fn get_variable_limit() -> Option<u64> {
        VARIABLE_LIMIT.with(|current_limit| current_limit.get())
    }

    /// Sets the variable limit for the circuit.
    fn set_variable_limit(limit: Option<u64>) {
        VARIABLE_LIMIT.with(|current_limit| current_limit.replace(limit));
    }

    /// Returns the constraint limit for the circuit, if one exists.
    fn get_constraint_limit() -> Option<u64> {
        CONSTRAINT_LIMIT.with(|current_limit| current_limit.get())
    }

    /// Sets the constraint limit for the circuit.
    fn set_constraint_limit(limit: Option<u64>) {
        CONSTRAINT_LIMIT.with(|current_limit| current_limit.replace(limit));
    }

    /// Returns the density limit for the circuit, if one exists.
    fn get_non_zero_limit() -> Option<(u64, u64, u64)> {
        NON_ZERO_LIMIT.with(|current_limit| current_limit.get())
    }

    /// Sets the density limit for the circuit.
    fn set_non_zero_limit(limit: Option<(u64, u64, u64)>) {
        NON_ZERO_LIMIT.with(|current_limit| current_limit.replace(limit));
    }

    /// Halts the program from further synthesis, evaluation, and execution in the current environment.
    fn halt<S: Into<String>, T>(message: S) -> T {
        let error = message.into();
        // eprintln!("{}", &error);
        panic!("{}", &error)
    }

    /// Returns the R1CS circuit, resetting the circuit.
    fn inject_r1cs(r1cs: R1CS<Self::BaseField>) {
        CANARY_CIRCUIT.with(|circuit| {
            // Ensure the circuit is empty before injecting.
            assert_eq!(0, circuit.borrow().num_constants());
            assert_eq!(1, circuit.borrow().num_public());
            assert_eq!(0, circuit.borrow().num_private());
            assert_eq!(1, circuit.borrow().num_variables());
            assert_eq!(0, circuit.borrow().num_constraints());
            // Inject the R1CS instance.
            let r1cs = circuit.replace(r1cs);
            // Ensure the circuit that was replaced is empty.
            assert_eq!(0, r1cs.num_constants());
            assert_eq!(1, r1cs.num_public());
            assert_eq!(0, r1cs.num_private());
            assert_eq!(1, r1cs.num_variables());
            assert_eq!(0, r1cs.num_constraints());
        })
    }

    /// Returns the R1CS circuit, resetting the circuit.
    fn eject_r1cs_and_reset() -> R1CS<Self::BaseField> {
        CANARY_CIRCUIT.with(|circuit| {
            // Reset the witness mode.
            IN_WITNESS.with(|in_witness| in_witness.replace(false));
            // Reset the variable limit.
            Self::set_variable_limit(None);
            // Reset the constraint limit.
            Self::set_constraint_limit(None);
            // Reset the density limit.
            Self::set_non_zero_limit(None);
            // Eject the R1CS instance.
            let r1cs = circuit.replace(R1CS::<<Self as Environment>::BaseField>::new());
            // Ensure the circuit is now empty.
            assert_eq!(0, circuit.borrow().num_constants());
            assert_eq!(1, circuit.borrow().num_public());
            assert_eq!(0, circuit.borrow().num_private());
            assert_eq!(1, circuit.borrow().num_variables());
            assert_eq!(0, circuit.borrow().num_constraints());
            // Return the R1CS instance.
            r1cs
        })
    }

    /// Returns the R1CS assignment of the circuit, resetting the circuit.
    fn eject_assignment_and_reset() -> Assignment<<Self::Network as console::Environment>::Field> {
        CANARY_CIRCUIT.with(|circuit| {
            // Reset the witness mode.
            IN_WITNESS.with(|in_witness| in_witness.replace(false));
            // Reset the variable limit.
            Self::set_variable_limit(None);
            // Reset the constraint limit.
            Self::set_constraint_limit(None);
            // Reset the density limit.
            Self::set_non_zero_limit(None);
            // Eject the R1CS instance.
            let r1cs = circuit.replace(R1CS::<<Self as Environment>::BaseField>::new());
            assert_eq!(0, circuit.borrow().num_constants());
            assert_eq!(1, circuit.borrow().num_public());
            assert_eq!(0, circuit.borrow().num_private());
            assert_eq!(1, circuit.borrow().num_variables());
            assert_eq!(0, circuit.borrow().num_constraints());
            // Convert the R1CS instance to an assignment.
            Assignment::from(r1cs)
        })
    }

    /// Clears the circuit and initializes an empty environment.
    fn reset() {
        CANARY_CIRCUIT.with(|circuit| {
            // Reset the witness mode.
            IN_WITNESS.with(|in_witness| in_witness.replace(false));
            // Reset the variable limit.
            Self::set_variable_limit(None);
            // Reset the constraint limit.
            Self::set_constraint_limit(None);
            // Reset the density limit.
            Self::set_non_zero_limit(None);
            // Reset the circuit.
            *circuit.borrow_mut() = R1CS::<<Self as Environment>::BaseField>::new();
            assert_eq!(0, circuit.borrow().num_constants());
            assert_eq!(1, circuit.borrow().num_public());
            assert_eq!(0, circuit.borrow().num_private());
            assert_eq!(1, circuit.borrow().num_variables());
            assert_eq!(0, circuit.borrow().num_constraints());
        });
    }
}

impl fmt::Display for CanaryCircuit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        CANARY_CIRCUIT.with(|circuit| write!(f, "{}", circuit.borrow()))
    }
}

#[cfg(test)]
mod tests {
    use snarkvm_circuit::prelude::*;

    /// Compute 2^EXPONENT - 1, in a purposefully constraint-inefficient manner for testing.
    fn create_example_circuit<E: Environment>() -> Field<E> {
        let one = snarkvm_console_types::Field::<E::Network>::one();
        let two = one + one;

        const EXPONENT: u64 = 64;

        // Compute 2^EXPONENT - 1, in a purposefully constraint-inefficient manner for testing.
        let mut candidate = Field::<E>::new(Mode::Public, one);
        let mut accumulator = Field::new(Mode::Private, two);
        for _ in 0..EXPONENT {
            candidate += &accumulator;
            accumulator *= Field::new(Mode::Private, two);
        }

        assert_eq!((accumulator - Field::one()).eject_value(), candidate.eject_value());
        assert_eq!(2, E::num_public());
        assert_eq!(2 * EXPONENT + 1, E::num_private());
        assert_eq!(EXPONENT, E::num_constraints());
        assert!(E::is_satisfied());

        candidate
    }

    #[test]
    fn test_print_circuit() {
        let _candidate = create_example_circuit::<CanaryCircuit>();
        let output = format!("{CanaryCircuit}");
        println!("{output}");
    }

    #[test]
    fn test_circuit_scope() {
        CanaryCircuit::scope("test_circuit_scope", || {
            assert_eq!(0, CanaryCircuit::num_constants());
            assert_eq!(1, CanaryCircuit::num_public());
            assert_eq!(0, CanaryCircuit::num_private());
            assert_eq!(0, CanaryCircuit::num_constraints());

            assert_eq!(0, CanaryCircuit::num_constants_in_scope());
            assert_eq!(0, CanaryCircuit::num_public_in_scope());
            assert_eq!(0, CanaryCircuit::num_private_in_scope());
            assert_eq!(0, CanaryCircuit::num_constraints_in_scope());
        })
    }
}
