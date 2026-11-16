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

use crate::{
    helpers::{Constraint, Counter},
    prelude::*,
};
use snarkvm_fields::PrimeField;

#[cfg(feature = "save_r1cs_hashes")]
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[cfg(feature = "save_r1cs_hashes")]
use std::{
    hash::{Hash, Hasher},
    sync::Mutex,
};

#[cfg(feature = "save_r1cs_hashes")]
struct Sha256Hasher(Sha256);

#[cfg(feature = "save_r1cs_hashes")]
impl Hasher for Sha256Hasher {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finish(&self) -> u64 {
        unimplemented!("Use Digest::finalize instead to get the full SHA-256 digest");
    }
}

#[cfg(feature = "save_r1cs_hashes")]
fn hash_to_sha256<T: Hash>(t: &T) -> [u8; 32] {
    let mut hasher = Sha256Hasher(Sha256::new());
    t.hash(&mut hasher);
    hasher.0.finalize().into()
}

pub type Scope = String;

/// A list of hashes of all the R1CS objects that have reached the
/// conversion to Assignment stage. It's a vector in case there are
/// any duplicates (which could indicate no change or redundant
/// work) and since they need to eventually be sorted in order to
/// have deterministic order, as they may be created in parallel.
#[cfg(feature = "save_r1cs_hashes")]
pub static R1CS_HASHES: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());

#[derive(Debug, Hash)]
pub struct R1CS<F: PrimeField> {
    constants: Vec<Variable<F>>,
    pub(crate) public: Vec<Variable<F>>,
    pub(crate) private: Vec<Variable<F>>,
    pub(crate) constraints: Vec<Arc<Constraint<F>>>,
    counter: Counter<F>,
    pub(crate) num_variables: u64,
    nonzeros: (u64, u64, u64),
}

impl<F: PrimeField> R1CS<F> {
    /// Returns a new instance of a constraint system.
    pub(crate) fn new() -> Self {
        Self {
            constants: Default::default(),
            public: vec![Variable::Public(Arc::new((0u64, F::one())))],
            private: Default::default(),
            constraints: Default::default(),
            counter: Default::default(),
            num_variables: 1u64,
            nonzeros: (0, 0, 0),
        }
    }

    /// Appends the given scope to the current environment.
    pub(crate) fn push_scope<S: Into<String>>(&mut self, name: S) -> Result<(), String> {
        self.counter.push(name)
    }

    /// Removes the given scope from the current environment.
    pub(crate) fn pop_scope<S: Into<String>>(&mut self, name: S) -> Result<(), String> {
        self.counter.pop(name)
    }

    /// Returns a new constant with the given value and scope.
    pub(crate) fn new_constant(&mut self, value: F) -> Variable<F> {
        let variable = Variable::Constant(Arc::new(value));
        self.constants.push(variable.clone());
        self.counter.increment_constant();
        self.num_variables += 1;
        variable
    }

    /// Returns a new public variable with the given value and scope.
    pub(crate) fn new_public(&mut self, value: F) -> Variable<F> {
        let variable = Variable::Public(Arc::new((self.public.len() as u64, value)));
        self.public.push(variable.clone());
        self.counter.increment_public();
        self.num_variables += 1;
        variable
    }

    /// Returns a new private variable with the given value and scope.
    pub(crate) fn new_private(&mut self, value: F) -> Variable<F> {
        let variable = Variable::Private(Arc::new((self.private.len() as u64, value)));
        self.private.push(variable.clone());
        self.counter.increment_private();
        self.num_variables += 1;
        variable
    }

    /// Adds one constraint enforcing that `(A * B) == C`.
    pub(crate) fn enforce(&mut self, constraint: Constraint<F>) {
        let (a_nonzeros, b_nonzeros, c_nonzeros) = constraint.num_nonzeros();
        self.nonzeros.0 += a_nonzeros;
        self.nonzeros.1 += b_nonzeros;
        self.nonzeros.2 += c_nonzeros;

        let constraint = Arc::new(constraint);
        self.constraints.push(Arc::clone(&constraint));
        self.counter.add_constraint(constraint);
    }

    /// Returns `true` if all of the constraints are satisfied.
    ///
    /// In addition, when in debug mode, this function also checks that
    /// all constraints use variables corresponding to the declared variables.
    pub fn is_satisfied(&self) -> bool {
        // Ensure all constraints are satisfied.
        let constraints_satisfied = self.constraints.iter().all(|constraint| constraint.is_satisfied());
        if !constraints_satisfied {
            return false;
        }

        // In debug mode, ensure all constraints use variables corresponding to the declared variables.
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        self.constraints.iter().all(|constraint| {
            let (a, b, c) = constraint.to_terms();
            [a, b, c].into_iter().all(|lc| {
                lc.to_terms().iter().all(|(variable, _)| match variable {
                    Variable::Constant(_value) => false, // terms should not contain Constants
                    // `new_private` sets the index to a length of `self.private`, which is a `usize`.
                    #[allow(clippy::cast_possible_truncation)]
                    Variable::Private(private) => {
                        let (index, value) = private.as_ref();
                        self.private.get(*index as usize).map_or_else(|| false, |v| v.value() == *value)
                    }
                    // `new_public` sets the index to a length of `self.public`, which is a `usize`.
                    #[allow(clippy::cast_possible_truncation)]
                    Variable::Public(public) => {
                        let (index, value) = public.as_ref();
                        self.public.get(*index as usize).map_or_else(|| false, |v| v.value() == *value)
                    }
                })
            })
        })
    }

    /// Returns `true` if all constraints in the current scope are satisfied.
    pub(crate) fn is_satisfied_in_scope(&self) -> bool {
        self.counter.is_satisfied_in_scope()
    }

    /// Returns the current scope.
    pub(crate) fn scope(&self) -> Scope {
        self.counter.scope()
    }

    /// Returns the number of constants in the constraint system.
    pub fn num_constants(&self) -> u64 {
        self.constants.len() as u64
    }

    /// Returns the number of public variables in the constraint system.
    pub fn num_public(&self) -> u64 {
        self.public.len() as u64
    }

    /// Returns the number of private variables in the constraint system.
    pub fn num_private(&self) -> u64 {
        self.private.len() as u64
    }

    /// Returns the number of constant, public, and private variables in the constraint system.
    pub fn num_variables(&self) -> u64 {
        self.num_variables
    }

    /// Returns the number of constraints in the constraint system.
    pub fn num_constraints(&self) -> u64 {
        self.constraints.len() as u64
    }

    /// Returns the number of nonzeros in the constraint system.
    pub fn num_nonzeros(&self) -> (u64, u64, u64) {
        self.nonzeros
    }

    /// Returns the number of constants for the current scope.
    pub(crate) fn num_constants_in_scope(&self) -> u64 {
        self.counter.num_constants_in_scope()
    }

    /// Returns the number of public variables for the current scope.
    pub(crate) fn num_public_in_scope(&self) -> u64 {
        self.counter.num_public_in_scope()
    }

    /// Returns the number of private variables for the current scope.
    pub(crate) fn num_private_in_scope(&self) -> u64 {
        self.counter.num_private_in_scope()
    }

    /// Returns the number of constraints for the current scope.
    pub(crate) fn num_constraints_in_scope(&self) -> u64 {
        self.counter.num_constraints_in_scope()
    }

    /// Returns the number of nonzeros for the current scope.
    pub(crate) fn num_nonzeros_in_scope(&self) -> (u64, u64, u64) {
        self.counter.num_nonzeros_in_scope()
    }

    /// Returns the public variables in the constraint system.
    pub fn to_public_variables(&self) -> &Vec<Variable<F>> {
        &self.public
    }

    /// Returns the private variables in the constraint system.
    pub fn to_private_variables(&self) -> &Vec<Variable<F>> {
        &self.private
    }

    /// Returns the constraints in the constraint system.
    pub fn to_constraints(&self) -> &Vec<Arc<Constraint<F>>> {
        &self.constraints
    }

    /// Register the current hash of the entire R1CS and add
    /// it to the R1CS_HASHES collection.
    #[cfg(feature = "save_r1cs_hashes")]
    pub(crate) fn save_hash(&self) {
        let r1cs_hash = hash_to_sha256(self);
        R1CS_HASHES.lock().unwrap().push(r1cs_hash);
    }
}

impl<F: PrimeField> Display for R1CS<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::default();
        for constraint in self.to_constraints() {
            output += &constraint.to_string();
        }
        output += "\n";

        write!(f, "{output}")
    }
}
