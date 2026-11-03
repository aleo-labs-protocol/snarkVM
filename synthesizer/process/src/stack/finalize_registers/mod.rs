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

mod registers_trait;

use crate::FinalizeTypes;
use console::{
    network::prelude::*,
    program::{Identifier, Literal, Plaintext, Register, Value},
    types::{I64, U16, U32},
};
use snarkvm_synthesizer_program::{FinalizeGlobalState, FinalizeRegistersState, Operand, RegistersTrait, StackTrait};

use indexmap::IndexMap;

#[derive(Clone)]
pub struct FinalizeRegisters<N: Network> {
    /// The global state for the finalize scope.
    state: FinalizeGlobalState,
    /// The transition ID for the finalize scope.
    /// `None` on the view path (views have no associated transition); always `Some(...)`
    /// on the finalize / constructor paths.
    transition_id: Option<N::TransitionID>,
    /// The function name for the finalize scope.
    /// This is set to the program ID for constructors.
    function_name: Identifier<N>,
    /// The mapping of all registers to their defined types.
    finalize_types: FinalizeTypes<N>,
    /// The mapping of assigned registers to their values.
    registers: IndexMap<u64, Value<N>>,
    /// A nonce for finalize registers.
    /// `None` on the view path; always `Some(...)` on the finalize / constructor paths.
    nonce: Option<u64>,
    /// The tracker for the last register locator.
    last_register: Option<u64>,
}

impl<N: Network> FinalizeRegisters<N> {
    /// Initializes a new set of registers, given the finalize types.
    ///
    /// `transition_id` and `nonce` are `Option`s so that callers can express "no transition is
    /// associated with this scope" (the view path) without needing a sentinel default value.
    /// On the finalize / constructor paths, both are always `Some(...)` and the absence of a
    /// transition ID at any read site (e.g. `rand.chacha`) is treated as a runtime error.
    #[inline]
    pub fn new(
        state: FinalizeGlobalState,
        transition_id: Option<N::TransitionID>,
        function_name: Identifier<N>,
        finalize_types: FinalizeTypes<N>,
        nonce: Option<u64>,
    ) -> Self {
        // Bound the initial allocation for scopes with large, conditionally executed bodies.
        let capacity = finalize_types.num_registers().min(256);
        Self {
            state,
            transition_id,
            finalize_types,
            function_name,
            registers: IndexMap::with_capacity(capacity),
            nonce,
            last_register: None,
        }
    }
}

impl<N: Network> FinalizeRegistersState<N> for FinalizeRegisters<N> {
    /// Returns the global state for the finalize scope.
    #[inline]
    fn state(&self) -> &FinalizeGlobalState {
        &self.state
    }

    /// Returns the transition ID for the finalize scope, if one is associated with this scope.
    #[inline]
    fn transition_id(&self) -> Option<&N::TransitionID> {
        self.transition_id.as_ref()
    }

    /// Returns the function name for the finalize scope.
    #[inline]
    fn function_name(&self) -> &Identifier<N> {
        &self.function_name
    }

    /// Returns the nonce for the finalize registers, if one is associated with this scope.
    #[inline]
    fn nonce(&self) -> Option<u64> {
        self.nonce
    }
}
