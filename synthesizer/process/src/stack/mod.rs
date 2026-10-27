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

mod authorization;
pub use authorization::*;

mod call;
pub use call::*;

mod finalize_registers;
pub use finalize_registers::*;

mod finalize_types;
pub use finalize_types::*;

mod register_types;
pub use register_types::*;

mod registers;
pub use registers::*;

mod authorize;
mod deploy;
mod evaluate;
mod execute;
mod helpers;

use crate::{CallMetrics, Process, Trace, TranslationAssignment, compute_console_dynamic_or_external_record_id};
use console::{
    account::{Address, PrivateKey},
    network::prelude::*,
    program::{
        Argument,
        DynamicFuture,
        DynamicRecord,
        Entry,
        EntryType,
        FinalizeType,
        Future,
        Identifier,
        Literal,
        Locator,
        Owner as RecordOwner,
        Plaintext,
        PlaintextType,
        ProgramID,
        Record,
        RecordType,
        RegisterType,
        Request,
        Response,
        ToFields,
        U8,
        U16,
        Value,
        ValueType,
    },
    types::{Field, Group},
};
use snarkvm_ledger_block::{Deployment, Transaction, Transition};
use snarkvm_synthesizer_error::*;
use snarkvm_synthesizer_program::{
    CallOperator,
    Closure,
    FinalizeGlobalState,
    FinalizeStoreTrait,
    Function,
    Instruction,
    Operand,
    Program,
    RegistersCircuit,
    RegistersSigner,
    RegistersTrait,
    StackTrait,
};
use snarkvm_synthesizer_snark::{Certificate, ProvingKey, UniversalSRS, VerifyingKey};

use aleo_std::prelude::{finish, lap, timer};
use indexmap::IndexMap;
#[cfg(feature = "locktick")]
use locktick::parking_lot::RwLock;
#[cfg(not(feature = "locktick"))]
use parking_lot::RwLock;
use rand::{CryptoRng, RngExt as Rng, SeedableRng, rngs::StdRng};
use std::{
    cell::OnceCell,
    collections::HashMap,
    sync::{Arc, Weak},
};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

pub type Assignments<N> = Arc<RwLock<Vec<(circuit::Assignment<<N as Environment>::Field>, CallMetrics<N>)>>>;
/// A stack of translations for the transitions in the execution. Each function execution level pushes a new group,
/// and translations for dynamic calls made at that level are collected into the top group. When the transition is
/// inserted, the top group is popped and its translations are associated with that transition (the caller's
/// transition ID). Each translation datum is paired with the proving key for its record type.
pub type Translations<N> = Arc<RwLock<Vec<Vec<(TranslationAssignment<N>, ProvingKey<N>)>>>>;

/// A tracker for static records minted in a transaction. The key is the record's nonce and the value
/// `(i, r)` contains the index `i` of the minting request in the transaction and the register `r`
/// where that request outputs the record.
pub type MintedRecordTracker<N> = HashMap<Field<N>, (usize, u64)>;

/// A tracker for input record-like values (static `Record`s, `ExternalRecord`s and
/// `DynamicRecord`s) received by any request in a given transaction. The key is the nonce of the
/// corresponding static record and the value `(i, j)` contains the index `i` of the request
/// receiving the value and the input index `j`.
pub type InputRecordLikeTracker<N> = HashMap<Field<N>, Vec<(usize, usize)>>;

/// The `CallStack` is used to track the current state of the program execution.
#[derive(Clone, Debug)]
pub enum CallStack<N: Network> {
    /// Authorize an `Execute` transaction.
    Authorize(Vec<Request<N>>, Option<PrivateKey<N>>, Authorization<N>),
    /// Mock an evaluation.
    AuthorizeMocked(
        Vec<Request<N>>,
        Address<N>,
        Authorization<N>,
        Arc<RwLock<MintedRecordTracker<N>>>,
        Arc<RwLock<InputRecordLikeTracker<N>>>,
    ),
    /// Authorize a collection of requests coming from a single root call.
    // (full vector of requests in pre-order, index of the request currently being explored, authorization being constructed)
    AuthorizeRequests(Vec<Request<N>>, Arc<RwLock<usize>>, Authorization<N>),
    /// Synthesize a function circuit before a `Deploy` transaction.
    Synthesize(Vec<Request<N>>, PrivateKey<N>, Authorization<N>),
    /// Validate a `Deploy` transaction's function circuit.
    CheckDeployment(Vec<Request<N>>, PrivateKey<N>, Assignments<N>, Option<u64>, Option<u64>, Option<(u64, u64, u64)>),
    /// Evaluate a function.
    Evaluate(Authorization<N>),
    /// Execute a function and produce a proof.
    Execute(Authorization<N>, Arc<RwLock<Trace<N>>>, Translations<N>),
    /// Execute a function and create the circuit assignment.
    PackageRun(Vec<Request<N>>, PrivateKey<N>, Assignments<N>),
}

// impl to_string for CallStack<N>
impl<N: Network> CallStack<N> {
    fn type_as_string(&self) -> String {
        match self {
            CallStack::Authorize(..) => "Authorize".to_string(),
            CallStack::AuthorizeMocked(..) => "Mock".to_string(),
            CallStack::AuthorizeRequests(..) => "AuthorizeRequests".to_string(),
            CallStack::Synthesize(..) => "Synthesize".to_string(),
            CallStack::CheckDeployment(..) => "CheckDeployment".to_string(),
            CallStack::Evaluate(..) => "Evaluate".to_string(),
            CallStack::Execute(..) => "Execute".to_string(),
            CallStack::PackageRun(..) => "PackageRun".to_string(),
        }
    }
}

impl<N: Network> CallStack<N> {
    /// Initializes a call stack as `Self::Evaluate`.
    pub fn evaluate(authorization: Authorization<N>) -> Result<Self> {
        Ok(CallStack::Evaluate(authorization))
    }

    /// Initializes a call stack as `Self::Execute`.
    pub fn execute(
        authorization: Authorization<N>,
        trace: Arc<RwLock<Trace<N>>>,
        translations: Translations<N>,
    ) -> Result<Self> {
        Ok(CallStack::Execute(authorization, trace, translations))
    }
}

impl<N: Network> CallStack<N> {
    /// Returns a new and independent replica of the call stack.
    pub fn replicate(&self) -> Self {
        match self {
            CallStack::Authorize(requests, private_key, authorization) => {
                CallStack::Authorize(requests.clone(), *private_key, authorization.replicate())
            }
            CallStack::AuthorizeMocked(requests, address, authorization, minted_static_records, input_records) => {
                CallStack::AuthorizeMocked(
                    requests.clone(),
                    *address,
                    authorization.replicate(),
                    Arc::new(RwLock::new(minted_static_records.read().clone())),
                    Arc::new(RwLock::new(input_records.read().clone())),
                )
            }
            CallStack::AuthorizeRequests(requests, current_index, authorization) => CallStack::AuthorizeRequests(
                requests.clone(),
                Arc::new(RwLock::new(*current_index.read())),
                authorization.replicate(),
            ),
            CallStack::Synthesize(requests, private_key, authorization) => {
                CallStack::Synthesize(requests.clone(), *private_key, authorization.replicate())
            }
            CallStack::CheckDeployment(
                requests,
                private_key,
                assignments,
                constraint_limit,
                variable_limit,
                non_zero_limit,
            ) => CallStack::CheckDeployment(
                requests.clone(),
                *private_key,
                Arc::new(RwLock::new(assignments.read().clone())),
                *constraint_limit,
                *variable_limit,
                *non_zero_limit,
            ),
            CallStack::Evaluate(authorization) => CallStack::Evaluate(authorization.replicate()),
            CallStack::Execute(authorization, trace, translations) => CallStack::Execute(
                authorization.replicate(),
                Arc::new(RwLock::new(trace.read().clone())),
                Arc::new(RwLock::new(translations.read().clone())),
            ),
            CallStack::PackageRun(requests, private_key, assignments) => {
                CallStack::PackageRun(requests.clone(), *private_key, Arc::new(RwLock::new(assignments.read().clone())))
            }
        }
    }

    /// Pushes the request to the stack.
    pub fn push(&mut self, request: Request<N>) -> Result<()> {
        match self {
            CallStack::Authorize(requests, ..)
            | CallStack::AuthorizeMocked(requests, ..)
            | CallStack::Synthesize(requests, ..)
            | CallStack::CheckDeployment(requests, ..)
            | CallStack::PackageRun(requests, ..) => {
                // Check that the number of requests does not exceed the maximum.
                ensure!(
                    requests.len() < Transaction::<N>::MAX_TRANSITIONS,
                    "The number of requests in the authorization must be less than '{}'.",
                    Transaction::<N>::MAX_TRANSITIONS
                );
                // Push the request to the stack.
                requests.push(request)
            }
            CallStack::AuthorizeRequests(..) => {
                bail!("Cannot push a request to the stack in AuthorizeRequests mode");
            }
            CallStack::Evaluate(authorization) => authorization.push(request)?,
            CallStack::Execute(authorization, ..) => authorization.push(request)?,
        }
        Ok(())
    }

    /// Pops the request from the stack.
    pub fn pop(&mut self) -> Result<Request<N>> {
        match self {
            CallStack::Authorize(requests, ..)
            | CallStack::AuthorizeMocked(requests, ..)
            | CallStack::Synthesize(requests, ..)
            | CallStack::CheckDeployment(requests, ..)
            | CallStack::PackageRun(requests, ..) => {
                requests.pop().ok_or_else(|| anyhow!("No more requests on the stack"))
            }
            CallStack::AuthorizeRequests(..) => {
                Err(anyhow!("Cannot pop a request from the stack in AuthorizeRequests mode"))
            }
            CallStack::Evaluate(authorization) => authorization.next(),
            CallStack::Execute(authorization, ..) => authorization.next(),
        }
    }

    /// Peeks at the next request from the stack.
    pub fn peek(&self) -> Result<Request<N>> {
        match self {
            CallStack::Authorize(requests, ..)
            | CallStack::AuthorizeMocked(requests, ..)
            | CallStack::Synthesize(requests, ..)
            | CallStack::CheckDeployment(requests, ..)
            | CallStack::PackageRun(requests, ..) => {
                requests.last().cloned().ok_or_else(|| anyhow!("No more requests on the stack"))
            }
            CallStack::AuthorizeRequests(requests, current_index, ..) => {
                requests.get(*current_index.read()).cloned().ok_or_else(|| anyhow!(
                    "CallStack::peek attempted to retrieve request at index {}, but the AuthorizeRequests call stack only contains {} request(s)",
                    *current_index.read(),
                    requests.len()
                ))
            }
            CallStack::Evaluate(authorization) => authorization.peek_next(),
            CallStack::Execute(authorization, ..) => authorization.peek_next(),
        }
    }
}

#[derive(Clone)]
pub struct Stack<N: Network> {
    /// The program (record types, structs, functions).
    program: Program<N>,
    /// A reference to the global stack map.
    stacks: Weak<RwLock<IndexMap<ProgramID<N>, Arc<Stack<N>>>>>,
    /// The register types for the program constructor, if it exists.
    constructor_types: Arc<RwLock<Option<FinalizeTypes<N>>>>,
    /// The mapping of closure and function names to their register types.
    register_types: Arc<RwLock<IndexMap<Identifier<N>, RegisterTypes<N>>>>,
    /// The mapping of finalize names to their register types.
    finalize_types: Arc<RwLock<IndexMap<Identifier<N>, FinalizeTypes<N>>>>,
    /// The mapping of view function names to their register types.
    view_types: Arc<RwLock<IndexMap<Identifier<N>, FinalizeTypes<N>>>>,
    /// The universal SRS.
    universal_srs: UniversalSRS<N>,
    /// The mapping of function name or record name to proving key.
    /// Function names map to function proving keys, record names map to translation proving keys.
    proving_keys: Arc<RwLock<IndexMap<Identifier<N>, ProvingKey<N>>>>,
    /// The mapping of function name or record name to verifying key.
    /// Function names map to function verifying keys, record names map to translation verifying keys.
    verifying_keys: Arc<RwLock<IndexMap<Identifier<N>, VerifyingKey<N>>>>,
    /// The program address.
    program_address: Address<N>,
    /// The program checksum.
    program_checksum: [U8<N>; 32],
    /// The checksum of each component (function, closure, or view) in the program.
    component_checksums: IndexMap<Identifier<N>, [U8<N>; 32]>,
    /// The program edition.
    program_edition: U16<N>,
    /// The number of amendments applied to the current program edition.
    program_amendment_count: u64,
    /// The program owner.
    program_owner: Option<Address<N>>,
}

impl<N: Network> Stack<N> {
    /// Initializes a new stack given the process and the program.
    pub fn new(process: &Process<N>, program: &Program<N>) -> Result<Self> {
        // Retrieve the program ID.
        let program_id = program.id();
        // Check that the program is well-formed.
        check_program_is_well_formed(program)?;

        // If the program exists in the process, check that the new program is valid.
        if let Ok(existing_stack) = process.get_stack(program_id) {
            // Ensure the program is not `credits.aleo`.
            ensure!(program_id != &ProgramID::from_str("credits.aleo")?, "Cannot re-initialize the 'credits.aleo'.");
            // Get the existing program.
            let existing_program = existing_stack.program();
            // If the existing program does not have a constructor, check that the new program matches the existing program.
            // Otherwise, ensure that the upgrade is valid.
            match existing_program.contains_constructor() {
                false => ensure!(
                    existing_stack.program() == program,
                    "Program '{program_id}' already exists with different contents."
                ),
                true => Self::check_upgrade_is_valid(existing_program, program)?,
            }
        }

        // Return the stack.
        Stack::initialize(process, program)
    }

    /// Partially initializes a new stack, given the process and the program, without checking for validity.
    /// Unlike `Stack::new`, this method accepts an explicit edition and skips upgrade validation,
    /// which is necessary for amendments that preserve the existing edition rather than incrementing it.
    /// A `Stack` created by this method must also call `initialize_and_check`.
    pub fn new_raw(process: &Process<N>, program: &Program<N>, edition: u16) -> Result<Self> {
        // Check that the program is well-formed.
        check_program_is_well_formed(program)?;
        // Return the stack.
        Stack::create_raw(process, program, edition)
    }

    /// Initializes and checks the register state and well-formedness of the stack, even if it has already been initialized.
    pub fn initialize_and_check(&self, process: &Process<N>) -> Result<()> {
        // Acquire the locks for the constructor, register, finalize, and view types.
        let mut constructor_types = self.constructor_types.write();
        let mut register_types = self.register_types.write();
        let mut finalize_types = self.finalize_types.write();
        let mut view_types = self.view_types.write();

        // Clear the existing constructor, closure, function, and view types.
        constructor_types.take();
        register_types.clear();
        finalize_types.clear();
        view_types.clear();

        // Add all the imports into the stack.
        for import in self.program.imports().keys() {
            // Ensure that the program does not import itself.
            ensure!(import != self.program.id(), "Program cannot import itself");
            // Ensure the program imports all exist in the process already.
            if !process.contains_program(import) {
                bail!("Cannot add program '{}' because its import '{import}' must be added first", self.program.id())
            }
        }

        // Add the constructor to the stack if it exists.
        if let Some(constructor) = self.program.constructor() {
            // Compute the constructor types.
            let types = FinalizeTypes::from_constructor(self, constructor)?;
            // Add the constructor types to the stack.
            constructor_types.replace(types);
        }

        // Add the program closures to the stack.
        for closure in self.program.closures().values() {
            // Retrieve the closure name.
            let name = closure.name();
            // Ensure the closure name is not already added.
            ensure!(!register_types.contains_key(name), "Closure '{name}' already exists");
            // Compute the register types.
            let types = RegisterTypes::from_closure(self, closure)?;
            // Add the closure name and register types to the stack.
            register_types.insert(*name, types);
        }

        // Add the program functions to the stack.
        for function in self.program.functions().values() {
            // Retrieve the function name.
            let name = function.name();
            // Ensure the function name is not already added.
            ensure!(!register_types.contains_key(name), "Function '{name}' already exists");
            // Compute the register types.
            let types = RegisterTypes::from_function(self, function)?;
            // Add the function name and register types to the stack.
            register_types.insert(*name, types);

            // If the function contains a finalize, insert it.
            if let Some(finalize) = function.finalize_logic() {
                // Compute the finalize types.
                let types = FinalizeTypes::from_finalize(self, finalize)?;
                // Add the finalize name and finalize types to the stack.
                finalize_types.insert(*name, types);
            }
        }

        // Type-check every view function and cache the result. Finalize reads the cached types
        // when it calls a view, so the types are not recomputed on every invocation.
        for view in self.program.views().values() {
            let name = view.name();
            ensure!(!view_types.contains_key(name), "View '{name}' already exists");
            let types = FinalizeTypes::from_view(self, view)?;
            view_types.insert(*name, types);
        }

        // Drop the locks since the types have been initialized.
        drop(constructor_types);
        drop(register_types);
        drop(finalize_types);
        drop(view_types);

        // Check that the functions are valid.
        for function in self.program.functions().values() {
            // Determine the minimum number of calls for the function.
            // This includes a safety check against maximum allowed number of calls.
            self.get_minimum_number_of_calls(function.name())?;
        }
        Ok(())
    }

    /// Returns the constructor types for the program.
    #[inline]
    pub fn get_constructor_types(&self) -> Result<FinalizeTypes<N>> {
        // Retrieve the constructor types.
        match self.constructor_types.read().as_ref() {
            Some(constructor_types) => Ok(constructor_types.clone()),
            None => bail!("Constructor types do not exist"),
        }
    }

    /// Returns the register types for the given closure or function name.
    #[inline]
    pub fn get_register_types(&self, name: &Identifier<N>) -> Result<RegisterTypes<N>> {
        // Retrieve the register types.
        match self.register_types.read().get(name) {
            Some(register_types) => Ok(register_types.clone()),
            None => bail!("Register types for '{name}' do not exist"),
        }
    }

    /// Returns the register types for the given finalize name.
    #[inline]
    pub fn get_finalize_types(&self, name: &Identifier<N>) -> Result<FinalizeTypes<N>> {
        // Retrieve the finalize types.
        match self.finalize_types.read().get(name) {
            Some(finalize_types) => Ok(finalize_types.clone()),
            None => bail!("Finalize types for '{name}' do not exist"),
        }
    }

    /// Returns the register types for the given view function name.
    #[inline]
    pub fn get_view_types(&self, name: &Identifier<N>) -> Result<FinalizeTypes<N>> {
        match self.view_types.read().get(name) {
            Some(view_types) => Ok(view_types.clone()),
            None => bail!("View types for '{name}' do not exist"),
        }
    }

    /// Returns the proving keys this stack holds, by function or record name, without loading any.
    #[inline]
    pub fn proving_keys(&self) -> Vec<(Identifier<N>, ProvingKey<N>)> {
        self.proving_keys.read().iter().map(|(name, key)| (*name, key.clone())).collect()
    }

    /// Inserts the proving key if the program ID is 'credits.aleo'.
    fn try_insert_credits_function_proving_key(&self, function_name: &Identifier<N>) -> Result<()> {
        // If the program is 'credits.aleo' and it does not exist yet, load the proving key directly.
        if self.program_id() == &ProgramID::from_str("credits.aleo")?
            && !self.proving_keys.read().contains_key(function_name)
        {
            // Load the 'credits.aleo' function proving key.
            let proving_key = N::get_credits_proving_key(function_name.to_string())?;
            // Insert the 'credits.aleo' function proving key.
            self.insert_proving_key(function_name, ProvingKey::new(proving_key.clone()))?;
        }
        Ok(())
    }
}

impl<N: Network> PartialEq for Stack<N> {
    fn eq(&self, other: &Self) -> bool {
        self.program == other.program
            && *self.register_types.read() == *other.register_types.read()
            && *self.finalize_types.read() == *other.finalize_types.read()
    }
}

impl<N: Network> Eq for Stack<N> {}

// A helper enum to avoid cloning stacks.
#[derive(Clone)]
pub(crate) enum StackRef<'a, N: Network> {
    // Self's stack.
    Internal(&'a Stack<N>),
    // An external stack.
    External(Arc<Stack<N>>),
}

impl<N: Network> Deref for StackRef<'_, N> {
    type Target = Stack<N>;

    fn deref(&self) -> &Self::Target {
        match self {
            StackRef::Internal(stack) => stack,
            StackRef::External(stack) => stack,
        }
    }
}

// A helper function to check that a program is well-formed.
fn check_program_is_well_formed<N: Network>(program: &Program<N>) -> Result<()> {
    // Ensure the program contains functions.
    ensure!(!program.functions().is_empty(), "No functions present in the deployment for program '{}'", program.id());

    // Serialize the program into bytes.
    let program_bytes = program.to_bytes_le()?;
    // Ensure the program deserializes from bytes correctly.
    ensure!(program == &Program::from_bytes_le(&program_bytes)?, "Program byte serialization failed");

    // Serialize the program into string.
    let program_string = program.to_string();
    // Ensure the program deserializes from a string correctly.
    ensure!(program == &Program::from_str(&program_string)?, "Program string serialization failed");

    Ok(())
}
