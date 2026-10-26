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

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
// #![warn(clippy::cast_possible_truncation)]
// TODO (howardwu): Update the return type on `execute` after stabilizing the interface.
#![allow(clippy::type_complexity)]

extern crate snarkvm_circuit as circuit;
extern crate snarkvm_console as console;

mod cost;
pub use cost::*;

mod stack;
pub use stack::*;

mod trace;
pub use trace::*;

mod authorize;
mod deploy;
mod evaluate;
mod execute;
mod finalize;
mod view;

mod verify_deployment;
mod verify_execution;
mod verify_fee;

#[cfg(test)]
mod tests;

use console::{
    account::PrivateKey,
    network::prelude::*,
    program::{
        DynamicFuture,
        Identifier,
        Literal,
        Locator,
        OutputID,
        Plaintext,
        PlaintextType,
        ProgramID,
        Record,
        Request,
        Response,
        Value,
        ValueType,
        compute_function_id,
    },
    types::{Field, U16, U64},
};
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_ledger_block::{Deployment, DeploymentVersion, Execution, Fee, Input, Output, Transaction, Transition};
use snarkvm_ledger_store::{FinalizeStorage, FinalizeStore, atomic_batch_scope};
use snarkvm_synthesizer_program::{
    Branch,
    CastType,
    Command,
    FinalizeGlobalState,
    FinalizeOperation,
    Function,
    Instruction,
    Operand,
    Program,
    StackTrait,
};
use snarkvm_synthesizer_snark::{ProvingKey, UniversalSRS, VerifyingKey};
use snarkvm_utilities::{defer, dev_println};

use aleo_std::prelude::{finish, lap, timer};
use indexmap::{IndexMap, IndexSet};

#[cfg(feature = "locktick")]
use locktick::{
    LockGuard,
    parking_lot::{Mutex, RwLock},
};
use parking_lot::MutexGuard;
#[cfg(not(feature = "locktick"))]
use parking_lot::{Mutex, RwLock};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// The kind of a key that [`Process::execution_keys`] returns.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionKeyKind {
    /// A function's key, which `execute` synthesizes unless its proving key is held.
    Function,
    /// A record's translation key, which `execute` synthesizes unless its proving and verifying keys are held.
    Translation,
}

// Note: a `Process` and all of its fields are meant to be completely stateless. They have no
// notion of block height or consensus version.
pub struct Process<N: Network> {
    /// The universal SRS.
    universal_srs: UniversalSRS<N>,
    /// The mapping of program IDs to stacks.
    stacks: Arc<RwLock<IndexMap<ProgramID<N>, Arc<Stack<N>>>>>,
    /// The mapping of program IDs to old stacks.
    old_stacks: RwLock<IndexMap<ProgramID<N>, Option<Arc<Stack<N>>>>>,
    /// A lock used to create instances of `ProcessExclusiveGuard`, which ensures that only
    /// one of them may ever exist at a time.
    lock: Mutex<()>,
}

/// A wrapper ensuring exclusive access to the Process for the purposes of methods which
/// affect the state of the stacks.
pub struct ProcessExclusiveGuard<'a, N: Network> {
    process: &'a Process<N>,
    #[cfg(not(feature = "locktick"))]
    _guard: MutexGuard<'a, ()>,
    #[cfg(feature = "locktick")]
    _guard: LockGuard<MutexGuard<'a, ()>>,
}

impl<'a, N: Network> std::ops::Deref for ProcessExclusiveGuard<'a, N> {
    type Target = Process<N>;

    fn deref(&self) -> &Self::Target {
        self.process
    }
}

impl<'a, N: Network> ProcessExclusiveGuard<'a, N> {
    /// Panics, since this guard already holds the process lock.
    #[inline]
    pub fn lock(&self) -> ! {
        panic!("Attempted to lock `Process` from `ProcessExclusiveGuard`; this would deadlock")
    }

    /// Adds a new stack to the process.
    /// If the program already exists, then the existing stack is replaced and the original stack is returned.
    /// Note. This method assumes that the provided stack is valid.
    #[inline]
    pub fn add_stack(&self, stack: Stack<N>) -> Option<Arc<Stack<N>>> {
        // Get the program ID.
        let program_id = *stack.program_id();
        // Arc the stack first to limit the scope of the write lock.
        let stack = Arc::new(stack);
        // Insert the stack into the process, replacing the existing stack if it exists.
        self.process.stacks.write().insert(program_id, stack)
    }

    /// Stages a stack to be added to the process.
    /// The new stack is active, while the old stack is retained in `old_stacks`.
    /// The `commit_stacks` method must be called to finalize the addition of the new stack.
    /// The `revert_stacks` method can be called to revert the staged stacks.
    #[inline]
    pub fn stage_stack(&self, stack: Stack<N>) {
        // Get the program ID.
        let program_id = *stack.program_id();
        // Arc the stack first to limit the scope of the write lock.
        let stack = Arc::new(stack);
        // If no entry in `old_stacks` exists for `program_id`, store the old stack.
        // Note: If `old_stack` is `None`, it means that we are adding a new program to the process.
        let old_stack = self.process.stacks.write().insert(program_id, stack);
        let mut old_stacks = self.process.old_stacks.write();
        if !old_stacks.contains_key(&program_id) {
            old_stacks.insert(program_id, old_stack);
        }
    }

    /// Commits the staged stacks to the process.
    /// This finalizes the addition of the new stacks and clears the old stacks.
    #[inline]
    pub fn commit_stacks(&self) {
        // Clear the old stacks.
        self.process.old_stacks.write().clear();
    }

    /// Reverts the staged stacks, restoring the previous state of the process.
    /// This will remove the new stacks and restore the old stacks.
    #[inline]
    pub fn revert_stacks(&self) {
        // Restore the old stacks.
        let mut stacks = self.process.stacks.write();
        for (program_id, stack) in self.process.old_stacks.write().drain(..) {
            // If the stack is `None`, remove the program from the process.
            // Otherwise, insert the old stack back into the process.
            if let Some(stack) = stack {
                stacks.insert(program_id, stack);
            } else {
                stacks.shift_remove(&program_id);
            }
        }
    }

    /// Adds a new program to the process, verifying that it is a valid addition.
    /// If the program exists, then the existing stack is replaced and discarded.
    /// Note. This method should **NOT** be used by the on-chain VM to add new program, use `finalize_deployment` or `load_deployment` instead instead.
    #[inline]
    pub fn add_program(&self, program: &Program<N>) -> Result<()> {
        // Initialize the 'credits.aleo' program ID.
        let credits_program_id = ProgramID::<N>::from_str("credits.aleo")?;
        // If the program is not 'credits.aleo', compute the program stack, and add it to the process.
        if program.id() != &credits_program_id {
            self.add_stack(Stack::new(self.process, program)?);
        }
        Ok(())
    }

    /// Adds a new program with the given edition to the process, verifying that it is a valid addition.
    /// If the program exists, then the existing stack is replaced and discarded.
    /// Note. This method should **NOT** be used by the on-chain VM to add new program, use `finalize_deployment` or `load_deployment` instead instead.
    #[inline]
    pub fn add_program_with_edition(&self, program: &Program<N>, edition: u16) -> Result<()> {
        // Initialize the 'credits.aleo' program ID.
        let credits_program_id = ProgramID::<N>::from_str("credits.aleo")?;
        // If the program is not 'credits.aleo', compute the program stack, and add it to the process.
        if program.id() != &credits_program_id {
            let stack = Stack::new_raw(self.process, program, edition)?;
            stack.initialize_and_check(self.process)?;
            self.add_stack(stack);
        }
        Ok(())
    }

    /// Adds a set of programs and editions, in topological order, to the process, deferring validation of the programs until all programs are added.
    /// If a program exists, then the existing stack is replaced and discarded.
    /// Either all programs are added or none are.
    /// Note. This method should **NOT** be used by the on-chain VM to add new program, use `finalize_deployment` or `load_deployment` instead instead.
    #[inline]
    pub fn add_programs_with_editions(&self, programs: &[(Program<N>, u16)]) -> Result<()> {
        // Initialize the 'credits.aleo' program ID.
        let credits_program_id = ProgramID::<N>::from_str("credits.aleo")?;
        // Defer cleanup of the uncommitted stacks.
        defer! {
            self.revert_stacks()
        }
        // Initialize raw stacks for each of the programs, skipping `credits.aleo`.
        for (program, edition) in programs {
            if program.id() != &credits_program_id {
                self.stage_stack(Stack::new_raw(self.process, program, *edition)?)
            }
        }
        // For each stack, check and initialize it before adding it to the process.
        for (program, _) in programs {
            // Retrieve the stack.
            let stack = self.process.get_stack(program.id())?;
            // Initialize and check the stack for well-formedness.
            stack.initialize_and_check(self.process)?;
        }
        // Commit the staged stacks.
        self.commit_stacks();
        Ok(())
    }

    /// Update the `credits.aleo` program in the VM with the latest verifying keys.
    pub fn update_credits_verifying_keys(&self) -> Result<()> {
        // Initialize the store for 'credits.aleo'.
        let credits = Program::<N>::credits()?;

        // Synthesize the 'credits.aleo' verifying keys.
        for function_name in credits.functions().keys() {
            // Remove the proving key.
            self.process.remove_proving_key(credits.id(), function_name)?;
            // Load the verifying key.
            let verifying_key = N::get_credits_verifying_key(function_name.to_string())?;
            // Retrieve the number of public and private variables.
            // Note: This number does *NOT* include the number of constants. This is safe because
            // this program is never deployed, as it is a first-class citizen of the protocol.
            let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
            // Insert the verifying key.
            self.process.insert_verifying_key(
                credits.id(),
                function_name,
                VerifyingKey::new(verifying_key.clone(), num_variables),
            )?;
        }

        // Load the verifying key for translating the native credits record.
        let record_name = Identifier::from_str("credits")?;
        let verifying_key = N::translation_credits_verifying_key();
        let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
        self.process.insert_verifying_key(
            credits.id(),
            &record_name,
            VerifyingKey::new(verifying_key.clone(), num_variables),
        )?;

        Ok(())
    }
}

impl<N: Network> Process<N> {
    /// Initializes a new process.
    #[inline]
    pub fn setup<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(rng: &mut R) -> Result<Self> {
        let timer = timer!("Process:setup");

        // Initialize the process.
        let process = Self {
            universal_srs: UniversalSRS::load()?,
            stacks: Default::default(),
            old_stacks: Default::default(),
            lock: Default::default(),
        };
        lap!(timer, "Initialize process");

        // Initialize the 'credits.aleo' program.
        let program = Program::credits()?;
        lap!(timer, "Load credits program");

        // Compute the 'credits.aleo' program stack.
        let stack = Stack::new(&process, &program)?;
        lap!(timer, "Initialize stack");

        // Synthesize the 'credits.aleo' circuit keys.
        for function_name in program.functions().keys() {
            stack.synthesize_key::<A, _>(function_name, rng)?;
            lap!(timer, "Synthesize circuit keys for {function_name}");
        }
        let rng = &mut rand::rng();
        let credits_record_name = Identifier::<N>::from_str("credits").unwrap(); // Safe: "credits" is always a valid identifier.
        stack.synthesize_translation_key::<A, _>(&credits_record_name, rng)?;
        lap!(timer, "Synthesize credits program keys");

        // Add the 'credits.aleo' stack to the process.
        process.lock().add_stack(stack);

        finish!(timer);
        // Return the process.
        Ok(process)
    }

    /// Guard the Process against any concurrent reads or writes.
    pub fn lock(&self) -> ProcessExclusiveGuard<'_, N> {
        ProcessExclusiveGuard { process: self, _guard: self.lock.lock() }
    }

    /// Ensure that the types referred to in this program's mappings exist.
    pub fn mapping_types_exist(&self, program: &Program<N>) -> Result<()> {
        for mapping in program.mappings().values() {
            self.plaintext_exists(mapping.key().plaintext_type(), program)?;
            self.plaintext_exists(mapping.value().plaintext_type(), program)?;
        }
        Ok(())
    }

    // If `type_` is a struct or an array containing a struct, ensure the struct type exists.
    fn plaintext_exists(&self, type_: &PlaintextType<N>, program: &Program<N>) -> Result<()> {
        match type_ {
            PlaintextType::Literal(..) => Ok(()),
            PlaintextType::Struct(struct_name) => {
                // Retrieve the struct from the program.
                ensure!(
                    program.get_struct(struct_name).is_ok(),
                    "Struct '{struct_name}' in '{}' is not defined.",
                    program.id()
                );
                Ok(())
            }
            PlaintextType::ExternalStruct(locator) => {
                let stack = self.get_stack(locator.program_id())?;
                ensure!(
                    stack.program().get_struct(locator.resource()).is_ok(),
                    "Struct '{}' in '{}' is not defined.",
                    locator.resource(),
                    stack.program().id(),
                );
                Ok(())
            }
            PlaintextType::Array(array_type) => self.plaintext_exists(array_type.base_element_type(), program),
        }
    }
}

impl<N: Network> Process<N> {
    /// Initializes a new process.
    #[inline]
    pub fn load() -> Result<Self> {
        let timer = timer!("Process::load");

        // Initialize the process.
        let process = Self {
            universal_srs: UniversalSRS::load()?,
            stacks: Default::default(),
            old_stacks: Default::default(),
            lock: Default::default(),
        };
        lap!(timer, "Initialize process");

        // Initialize the 'credits.aleo' program.
        let program = Program::credits()?;
        lap!(timer, "Load credits program");

        // Compute the 'credits.aleo' program stack.
        let stack = Stack::new(&process, &program)?;
        lap!(timer, "Initialize stack");

        // Synthesize the 'credits.aleo' verifying keys.
        for function_name in program.functions().keys() {
            // Load the verifying key.
            let verifying_key = N::get_credits_verifying_key(function_name.to_string())?;
            // Retrieve the number of public and private variables.
            // Note: This number does *NOT* include the number of constants. This is safe because
            // this program is never deployed, as it is a first-class citizen of the protocol.
            let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
            // Insert the verifying key.
            stack.insert_verifying_key(function_name, VerifyingKey::new(verifying_key.clone(), num_variables))?;
            lap!(timer, "Load verifying key for {function_name}");
        }

        // Load the verifying key for translating the native credits record.
        let record_name = Identifier::from_str("credits")?;
        let verifying_key = N::translation_credits_verifying_key();
        let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
        stack.insert_verifying_key(&record_name, VerifyingKey::new(verifying_key.clone(), num_variables))?;
        lap!(timer, "Load circuit keys");

        // Add the stack to the process.
        process.lock().add_stack(stack);

        finish!(timer, "Process::load");
        // Return the process.
        Ok(process)
    }

    /// Initializes a new process with the V0 credits.aleo verifiying keys.
    #[inline]
    pub fn load_v0() -> Result<Self> {
        let timer = timer!("Process::load_v0");

        // Initialize the process.
        let process = Self {
            universal_srs: UniversalSRS::load()?,
            stacks: Default::default(),
            old_stacks: Default::default(),
            lock: Default::default(),
        };
        lap!(timer, "Initialize process");

        // Initialize the 'credits.aleo' program.
        let program = Program::credits()?;
        lap!(timer, "Load credits program");

        // Compute the 'credits.aleo' program stack.
        let stack = Stack::new(&process, &program)?;
        lap!(timer, "Initialize stack");

        // Synthesize the 'credits.aleo' verifying keys.
        for function_name in program.functions().keys() {
            // Load the verifying key.
            let verifying_key = N::get_credits_v0_verifying_key(function_name.to_string())?;
            // Retrieve the number of public and private variables.
            // Note: This number does *NOT* include the number of constants. This is safe because
            // this program is never deployed, as it is a first-class citizen of the protocol.
            let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
            // Insert the verifying key.
            stack.insert_verifying_key(function_name, VerifyingKey::new(verifying_key.clone(), num_variables))?;
            lap!(timer, "Load verifying key for {function_name}");
        }
        lap!(timer, "Load circuit keys");

        // Add the stack to the process.
        process.lock().add_stack(stack);

        finish!(timer, "Process::load_v0");
        // Return the process.
        Ok(process)
    }

    /// Initializes a new process without downloading the 'credits.aleo' circuit keys (for web contexts).
    #[inline]
    #[cfg(feature = "wasm")]
    pub fn load_web() -> Result<Self> {
        // Initialize the process.
        let process = Self {
            universal_srs: UniversalSRS::load()?,
            stacks: Default::default(),
            old_stacks: Default::default(),
            lock: Default::default(),
        };

        // Initialize the 'credits.aleo' program.
        let program = Program::credits()?;

        // Compute the 'credits.aleo' program stack.
        let stack = Stack::new(&process, &program)?;

        // Add the stack to the process.
        process.lock().add_stack(stack);

        // Return the process.
        Ok(process)
    }

    /// Returns the universal SRS.
    #[inline]
    pub const fn universal_srs(&self) -> &UniversalSRS<N> {
        &self.universal_srs
    }

    /// Returns `true` if the process contains the program with the given ID.
    #[inline]
    pub fn contains_program(&self, program_id: &ProgramID<N>) -> bool {
        self.stacks.read().contains_key(program_id)
    }

    /// Returns the program IDs of all programs in the process.
    #[inline]
    pub fn program_ids(&self) -> Vec<ProgramID<N>> {
        self.stacks.read().keys().copied().collect()
    }

    /// Returns the stack for the given program ID.
    #[inline]
    pub fn get_stack(&self, program_id: impl TryInto<ProgramID<N>>) -> Result<Arc<Stack<N>>> {
        // Prepare the program ID.
        let program_id = program_id.try_into().map_err(|_| anyhow!("Invalid program ID"))?;
        // Retrieve the stack.
        let stack = self
            .stacks
            .read()
            .get(&program_id)
            .ok_or_else(|| anyhow!("Program '{program_id}' does not exist"))?
            .clone();
        // Ensure the program ID matches.
        ensure!(stack.program_id() == &program_id, "Expected program '{}', found '{program_id}'", stack.program_id());
        // Return the stack.
        Ok(stack)
    }

    /// Returns the stacks of the programs corresponding to all given transitions, keyed by
    /// `ProgramID`. If `include_direct_imports` is true, the stacks of the programs *directly*
    /// imported by those are also included.
    #[inline]
    pub fn get_stacks<'a>(
        &self,
        transitions: impl IntoIterator<Item = &'a Transition<N>>,
        include_direct_imports: bool,
    ) -> Result<IndexMap<ProgramID<N>, Arc<Stack<N>>>>
    where
        N: 'a,
    {
        let mut execution_stacks = indexmap::IndexMap::new();

        for transition in transitions.into_iter() {
            let program_id = transition.program_id();

            // If the program's stack has not been fetched before, fetch it.
            if !execution_stacks.contains_key(program_id) {
                execution_stacks.insert(*program_id, self.get_stack(program_id)?);
            }
        }

        // Fetch stacks of direct dependencies. Note some of these may have been fetched in the
        // previous loop.
        if include_direct_imports {
            let imported_program_ids: Vec<ProgramID<N>> =
                execution_stacks.values().flat_map(|stack| stack.program().imports().keys().copied()).collect();

            for imported_program_id in imported_program_ids {
                if !execution_stacks.contains_key(&imported_program_id) {
                    execution_stacks.insert(imported_program_id, self.get_stack(imported_program_id)?);
                }
            }
        }

        Ok(execution_stacks)
    }

    /// Returns the latest deployed edition for the given program ID, defaulting to 0 if unknown.
    #[inline]
    pub fn get_latest_edition_for_program(&self, program_id: &ProgramID<N>) -> u16 {
        self.get_stack(program_id).ok().map(|s| *s.program_edition()).unwrap_or(0u16)
    }

    /// Returns the proving key for the given program ID and function name.
    #[inline]
    pub fn get_proving_key(
        &self,
        program_id: impl TryInto<ProgramID<N>>,
        function_name: impl TryInto<Identifier<N>>,
    ) -> Result<ProvingKey<N>> {
        // Prepare the function name.
        let function_name = function_name.try_into().map_err(|_| anyhow!("Invalid function name"))?;
        // Return the proving key.
        self.get_stack(program_id)?.get_proving_key(&function_name)
    }

    /// Returns the verifying key for the given program ID and function name.
    #[inline]
    pub fn get_verifying_key(
        &self,
        program_id: impl TryInto<ProgramID<N>>,
        function_name: impl TryInto<Identifier<N>>,
    ) -> Result<VerifyingKey<N>> {
        // Prepare the function name.
        let function_name = function_name.try_into().map_err(|_| anyhow!("Invalid function name"))?;
        // Return the verifying key.
        self.get_stack(program_id)?.get_verifying_key(&function_name)
    }

    /// Inserts the given proving key, for the given program ID and function name.
    #[inline]
    pub fn insert_proving_key(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        proving_key: ProvingKey<N>,
    ) -> Result<()> {
        self.get_stack(program_id)?.insert_proving_key(function_name, proving_key)
    }

    /// Removes the given proving key, for the given program ID and function name.
    #[inline]
    pub fn remove_proving_key(&self, program_id: &ProgramID<N>, function_name: &Identifier<N>) -> Result<()> {
        self.get_stack(program_id)?.remove_proving_key(function_name);
        Ok(())
    }

    /// Inserts the given verifying key, for the given program ID and function name.
    #[inline]
    pub fn insert_verifying_key(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        verifying_key: VerifyingKey<N>,
    ) -> Result<()> {
        self.get_stack(program_id)?.insert_verifying_key(function_name, verifying_key)
    }

    /// Removes the given verifying key, for the given program ID and function name.
    #[inline]
    pub fn remove_verifying_key(&self, program_id: &ProgramID<N>, function_name: &Identifier<N>) -> Result<()> {
        self.get_stack(program_id)?.remove_verifying_key(function_name);
        Ok(())
    }

    /// Returns the keys that executing the given authorization uses, as pairs of a program ID and a function or
    /// record name, each mapped to its [`ExecutionKeyKind`] and whether `execute` needs to synthesize it.
    ///
    /// These are the function key of each request, and the translation key of each record in the inputs and
    /// outputs of a dynamic callee's function. The inclusion key is not among them: it is a network parameter, not a
    /// key a stack holds, and `execute` neither uses nor synthesizes it.
    ///
    /// This takes each request's target and `is_dynamic` flag as given, without checking them against the call that
    /// takes the request. The result is exact for requests that `Stack::authorize_requests` accepts.
    ///
    /// `execute` consumes the requests, and clones of an authorization share them. Call this before executing the
    /// authorization or any clone of it.
    ///
    /// Fails if a request or a translated record type names a program that is not loaded, a request names no function,
    /// a translated record type names no record, or a program replaced during the call changes a key's kind.
    #[inline]
    pub fn execution_keys(
        &self,
        authorization: &Authorization<N>,
    ) -> Result<IndexMap<(ProgramID<N>, Identifier<N>), (ExecutionKeyKind, bool)>> {
        let mut keys = IndexMap::new();
        // The bail is unreachable unless a program is replaced during this call without the upgrade checks.
        let mut insert = |key: (ProgramID<N>, Identifier<N>), kind, missing| match keys.insert(key, (kind, missing)) {
            Some((previous, _)) if previous != kind => bail!("'{}/{}' changed kind during this call", key.0, key.1),
            _ => Ok(()),
        };
        for (index, request) in authorization.to_vec_deque().into_iter().enumerate() {
            let stack = self.get_stack(request.program_id())?;
            let function = stack.get_function_ref(request.function_name())?;
            insert(
                (*request.program_id(), *request.function_name()),
                ExecutionKeyKind::Function,
                !stack.contains_proving_key(request.function_name()),
            )?;
            // The root request has no caller, so `execute` translates none of its records.
            if index == 0 || !request.is_dynamic() {
                continue;
            }
            let inputs = function.inputs().iter().map(|input| input.value_type());
            for value_type in inputs.chain(function.outputs().iter().map(|output| output.value_type())) {
                let (program_id, record_name) = match value_type {
                    ValueType::Record(record_name) => (*request.program_id(), *record_name),
                    ValueType::ExternalRecord(locator) => (*locator.program_id(), *locator.resource()),
                    _ => continue,
                };
                let record_stack = self.get_stack(program_id)?;
                ensure!(
                    record_stack.program().contains_record(&record_name),
                    "Record '{program_id}/{record_name}' is not defined."
                );
                let held = record_stack.contains_proving_key(&record_name)
                    && record_stack.contains_verifying_key(&record_name);
                insert((program_id, record_name), ExecutionKeyKind::Translation, !held)?;
            }
        }
        Ok(keys)
    }

    /// Synthesizes the proving and verifying key for the given program ID and function name.
    #[inline]
    pub fn synthesize_key<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        rng: &mut R,
    ) -> Result<()> {
        // Synthesize the proving and verifying key.
        self.get_stack(program_id)?.synthesize_key::<A, R>(function_name, rng)
    }

    /// Synthesizes the translation key for the given record name.
    #[inline]
    pub fn synthesize_translation_key<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        program_id: &ProgramID<N>,
        record_name: &Identifier<N>,
        rng: &mut R,
    ) -> Result<()> {
        self.get_stack(program_id)?.synthesize_translation_key::<A, R>(record_name, rng)
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use console::{account::PrivateKey, network::MainnetV0, program::Identifier};
    use snarkvm_ledger_block::Transition;
    use snarkvm_ledger_query::Query;
    use snarkvm_ledger_store::{BlockStore, helpers::memory::BlockMemory};
    use snarkvm_synthesizer_program::Program;

    use aleo_std::StorageMode;
    use std::sync::OnceLock;

    type CurrentNetwork = MainnetV0;
    type CurrentAleo = circuit::network::AleoV0;

    /// Returns an execution for the given program and function name.
    pub fn get_execution(
        process: &mut Process<CurrentNetwork>,
        program: &Program<CurrentNetwork>,
        function_name: &Identifier<CurrentNetwork>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<CurrentNetwork>>>,
    ) -> Execution<CurrentNetwork> {
        // Initialize a new rng.
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = PrivateKey::new(rng).unwrap();

        // Add the program to the process if doesn't yet exist.
        if !process.contains_program(program.id()) {
            process.lock().add_program(program).unwrap();
        }

        // Compute the authorization.
        let authorization =
            process.authorize::<CurrentAleo, _>(&private_key, program.id(), function_name, inputs, rng).unwrap();

        // Execute the program.
        let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

        // Prepare the assignments from the block store.
        trace.prepare(&snarkvm_ledger_query::Query::from(block_store)).unwrap();

        // Get the locator.
        let locator = format!("{:?}:{function_name:?}", program.id());

        // Return the execution object.
        trace.prove_execution::<CurrentAleo, _>(&locator, VarunaVersion::V1, rng).unwrap()
    }

    pub fn sample_key() -> (Identifier<CurrentNetwork>, ProvingKey<CurrentNetwork>, VerifyingKey<CurrentNetwork>) {
        static INSTANCE: OnceLock<(
            Identifier<CurrentNetwork>,
            ProvingKey<CurrentNetwork>,
            VerifyingKey<CurrentNetwork>,
        )> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new program.
                let (string, program) = Program::<CurrentNetwork>::parse(
                    r"
program testing.aleo;

function compute:
    input r0 as u32.private;
    input r1 as u32.public;
    add r0 r1 into r2;
    output r2 as u32.public;",
                )
                .unwrap();
                assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

                // Declare the function name.
                let function_name = Identifier::from_str("compute").unwrap();

                // Initialize the RNG.
                let rng = &mut TestRng::default();

                // Construct the process.
                let process = sample_process(&program);

                // Synthesize a proving and verifying key.
                process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

                // Get the proving and verifying key.
                let proving_key = process.get_proving_key(program.id(), function_name).unwrap();
                let verifying_key = process.get_verifying_key(program.id(), function_name).unwrap();

                (function_name, proving_key, verifying_key)
            })
            .clone()
    }

    pub(crate) fn sample_execution() -> Execution<CurrentNetwork> {
        static INSTANCE: OnceLock<Execution<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new program.
                let (string, program) = Program::<CurrentNetwork>::parse(
                    r"
program testing.aleo;

function compute:
    input r0 as u32.private;
    input r1 as u32.public;
    add r0 r1 into r2;
    output r2 as u32.public;",
                )
                .unwrap();
                assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

                // Declare the function name.
                let function_name = Identifier::from_str("compute").unwrap();

                // Initialize the RNG.
                let rng = &mut TestRng::default();
                // Initialize a new caller account.
                let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

                // Initialize a new block store.
                let block_store =
                    BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

                // Construct the process.
                let process = sample_process(&program);
                // Authorize the function call.
                let authorization = process
                    .authorize::<CurrentAleo, _>(
                        &caller_private_key,
                        program.id(),
                        function_name,
                        ["5u32", "10u32"].into_iter(),
                        rng,
                    )
                    .unwrap();
                assert_eq!(authorization.len(), 1);
                // Execute the request.
                let (_response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
                assert_eq!(trace.transitions().len(), 1);

                // Prepare the trace.
                trace.prepare(&Query::from(block_store)).unwrap();
                // Compute the execution.
                trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V1, rng).unwrap()
            })
            .clone()
    }

    pub fn sample_transition() -> Transition<CurrentNetwork> {
        // Retrieve the execution.
        let mut execution = sample_execution();
        // Ensure the execution is not empty.
        assert!(!execution.is_empty());
        // Return the transition.
        execution.pop().unwrap()
    }

    /// Initializes a new process with the given program.
    pub(crate) fn sample_process(program: &Program<CurrentNetwork>) -> Process<CurrentNetwork> {
        // Construct a new process.
        let process = Process::load().unwrap();
        // Add the program to the process.
        process.lock().add_program(program).unwrap();
        // Return the process.
        process
    }
}
