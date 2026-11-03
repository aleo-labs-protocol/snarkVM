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

use std::{collections::HashSet, sync::Arc};

use crate::{FinalizeGlobalState, FinalizeStoreTrait, Function, Operand, Program};
use console::{
    account::Group,
    network::Network,
    prelude::{Result, bail},
    program::{
        Future,
        Identifier,
        Literal,
        Locator,
        Plaintext,
        PlaintextType,
        ProgramID,
        Record,
        Register,
        RegisterType,
        Request,
        Value,
        ValueType,
    },
    types::{Address, Field, U8, U16},
};
use rand::{CryptoRng, Rng};
use snarkvm_synthesizer_snark::{ProvingKey, VerifyingKey};

/// This trait is intended to be implemented only by `snarkvm_synthesizer_process::Stack`.
///
/// We make it a trait only to avoid circular dependencies.
pub trait StackTrait<N: Network> {
    /// Returns `true` if the proving key for the given name exists.
    /// The name can be a function name or a record name (for translation keys).
    fn contains_proving_key(&self, function_or_record_name: &Identifier<N>) -> bool;

    /// Returns the proving key for the given name.
    /// The name can be a function name or a record name (for translation keys).
    fn get_proving_key(&self, function_or_record_name: &Identifier<N>) -> Result<ProvingKey<N>>;

    /// Inserts the proving key for the given name.
    /// The name can be a function name or a record name (for translation keys).
    fn insert_proving_key(&self, function_or_record_name: &Identifier<N>, proving_key: ProvingKey<N>) -> Result<()>;

    /// Removes the proving key for the given name.
    /// The name can be a function name or a record name (for translation keys).
    fn remove_proving_key(&self, function_or_record_name: &Identifier<N>);

    /// Returns `true` if the verifying key for the given name exists.
    /// The name can be a function name or a record name (for translation keys).
    fn contains_verifying_key(&self, function_or_record_name: &Identifier<N>) -> bool;

    /// Returns the verifying key for the given name.
    /// The name can be a function name or a record name (for translation keys).
    fn get_verifying_key(&self, function_or_record_name: &Identifier<N>) -> Result<VerifyingKey<N>>;

    /// Inserts the verifying key for the given name.
    /// The name can be a function name or a record name (for translation keys).
    fn insert_verifying_key(
        &self,
        function_or_record_name: &Identifier<N>,
        verifying_key: VerifyingKey<N>,
    ) -> Result<()>;

    /// Removes the verifying key for the given name.
    /// The name can be a function name or a record name (for translation keys).
    fn remove_verifying_key(&self, function_or_record_name: &Identifier<N>);

    /// Checks that the given value matches the layout of the value type.
    fn matches_value_type(&self, value: &Value<N>, value_type: &ValueType<N>) -> Result<()>;

    /// Checks that the given stack value matches the layout of the register type.
    fn matches_register_type(&self, stack_value: &Value<N>, register_type: &RegisterType<N>) -> Result<()>;

    /// Checks that the given record matches the layout of the external record type.
    fn matches_external_record(&self, record: &Record<N, Plaintext<N>>, locator: &Locator<N>) -> Result<()>;

    /// Checks that the given record matches the layout of the record type.
    fn matches_record(&self, record: &Record<N, Plaintext<N>>, record_name: &Identifier<N>) -> Result<()>;

    /// Checks that the given plaintext matches the layout of the plaintext type.
    fn matches_plaintext(&self, plaintext: &Plaintext<N>, plaintext_type: &PlaintextType<N>) -> Result<()>;

    /// Checks that the given future matches the layout of the future type.
    fn matches_future(&self, future: &Future<N>, locator: &Locator<N>) -> Result<()>;

    /// Returns the program.
    fn program(&self) -> &Program<N>;

    /// Returns the program ID.
    fn program_id(&self) -> &ProgramID<N>;

    /// Returns the program address.
    fn program_address(&self) -> &Address<N>;

    /// Returns the program checksum.
    fn program_checksum(&self) -> &[U8<N>; 32];

    /// Returns the program checksum as a field element.
    fn program_checksum_as_field(&self) -> Result<Field<N>>;

    /// Returns the checksum of the program component (function, closure, or view) with the given name.
    fn component_checksum(&self, name: &Identifier<N>) -> Result<&[U8<N>; 32]>;

    /// Returns the program edition.
    fn program_edition(&self) -> U16<N>;

    /// Returns the number of amendments for the current program edition.
    fn program_amendment_count(&self) -> u64;

    /// Sets the number of amendments for the current program edition.
    fn set_program_amendment_count(&mut self, program_amendment_count: u64);

    /// Returns the program owner.
    /// The program owner should only be set for programs that are deployed after `ConsensusVersion::V9` is active.
    fn program_owner(&self) -> &Option<Address<N>>;

    /// Sets the program owner.
    fn set_program_owner(&mut self, program_owner: Option<Address<N>>);

    /// Returns the external stack for the given program ID.
    fn get_external_stack(&self, program_id: &ProgramID<N>) -> Result<Arc<Self>>;

    /// Returns the external stack for the given program ID, without checking that:
    ///
    /// - The program ID is different from the current program ID.
    /// - The program ID is imported by the current program.
    ///
    /// This function is only to be used for resolution during dynamic dispatch.
    fn get_stack_global(&self, program_id: &ProgramID<N>) -> Result<Arc<Self>>;

    /// Returns the function with the given function name.
    fn get_function(&self, function_name: &Identifier<N>) -> Result<Function<N>>;

    /// Returns a reference to the function with the given function name.
    fn get_function_ref(&self, function_name: &Identifier<N>) -> Result<&Function<N>>;

    /// Returns the minimum number of calls for the given function name.
    /// Note: In a static call graph (no dynamic dispatch), the minimum is the actual count.
    fn get_minimum_number_of_calls(&self, function_name: &Identifier<N>) -> Result<usize>;

    /// Returns whether or not a function has a dynamic call in its execution.
    fn contains_dynamic_call(&self, function_name: &Identifier<N>) -> Result<bool>;

    /// Samples a value for the given value_type.
    fn sample_value<R: Rng + CryptoRng>(
        &self,
        burner_address: &Address<N>,
        value_type: &RegisterType<N>,
        rng: &mut R,
    ) -> Result<Value<N>>;

    /// Returns a record for the given record name, with the given burner address and nonce.
    fn sample_record<R: Rng + CryptoRng>(
        &self,
        burner_address: &Address<N>,
        record_name: &Identifier<N>,
        record_nonce: Group<N>,
        rng: &mut R,
    ) -> Result<Record<N, Plaintext<N>>>;

    /// Returns a record for the given record name, deriving the nonce from tvk and index.
    fn sample_record_using_tvk<R: Rng + CryptoRng>(
        &self,
        burner_address: &Address<N>,
        record_name: &Identifier<N>,
        tvk: Field<N>,
        index: Field<N>,
        rng: &mut R,
    ) -> Result<Record<N, Plaintext<N>>>;

    /// Evaluates a view function on this stack against the given finalize-store state.
    ///
    /// The caller (`Call::finalize`) loads operand values from the caller's registers and
    /// passes them as `inputs`; this method runs the view body and returns its outputs. It
    /// is the cross-crate hook that lets `Call::finalize` (in `snarkvm-synthesizer-program`)
    /// dispatch view-call evaluation into `snarkvm-synthesizer-process` without depending on
    /// concrete `Stack` / `FinalizeRegisters` types.
    fn evaluate_view(
        &self,
        state: FinalizeGlobalState,
        store: &dyn FinalizeStoreTrait<N>,
        view_name: &Identifier<N>,
        inputs: Vec<Value<N>>,
    ) -> Result<Vec<Value<N>>>;
}

/// Are the two types either the same, or both structurally equivalent `PlaintextType`s?
pub fn register_types_equivalent<N: Network>(
    stack0: &impl StackTrait<N>,
    type0: &RegisterType<N>,
    stack1: &impl StackTrait<N>,
    type1: &RegisterType<N>,
) -> Result<bool> {
    use RegisterType::*;
    if let (Plaintext(plaintext0), Plaintext(plaintext1)) = (type0, type1) {
        types_equivalent(stack0, plaintext0, stack1, plaintext1)
    } else {
        Ok(type0 == type1)
    }
}

/// Determines whether two `PlaintextType` values are equivalent.
///
/// Equivalence of literals means they're the same type.
///
/// Equivalence of structs means they have the same local names (regardless of whether
/// they're local or external), and their members have the same names and equivalent
/// types in the same order, recursively.
///
/// Equivalence of arrays means they have the same length and their element types are
/// equivalent.
///
/// This definition of equivalence was chosen to balance these concerns:
///
/// 1. All programs from before the existence of external structs will continue to work;
///    thus it's necessary for a struct created from another program to be considered equivalent
///    to a local one with the same name and structure, as in practice that was the behavior.
/// 2. We don't want to allow a fork. Thus we do need to check names, not just structural
///    equivalence - otherwise we could get a program deployable to a node which is using
///    this check, but not deployable to a node running an earlier SnarkVM.
///
/// The stacks are passed because struct types need to access their stack to get their
/// structure.
pub fn types_equivalent<N: Network>(
    stack0: &impl StackTrait<N>,
    type0: &PlaintextType<N>,
    stack1: &impl StackTrait<N>,
    type1: &PlaintextType<N>,
) -> Result<bool> {
    // Track the `(program0, program1, struct)` triples that have already been confirmed equivalent, so that a
    // struct shared by many members is compared at most once. Without this, a program in which every member of
    // each struct refers to the same earlier struct forms an acyclic graph with exponentially many paths, and the
    // walk below would make up to `MAX_STRUCT_ENTRIES ^ MAX_STRUCTS` recursive calls.
    // `in_progress` holds the pairs currently on the recursion path, and re-entering one means the cross-program
    // struct graph is cyclic.
    let mut confirmed = HashSet::new();
    let mut in_progress = HashSet::new();
    types_equivalent_inner(stack0, type0, stack1, type1, &mut confirmed, &mut in_progress)
}

/// The memoized inner traversal for [`types_equivalent`].
fn types_equivalent_inner<N: Network>(
    stack0: &impl StackTrait<N>,
    type0: &PlaintextType<N>,
    stack1: &impl StackTrait<N>,
    type1: &PlaintextType<N>,
    confirmed: &mut HashSet<(ProgramID<N>, ProgramID<N>, Identifier<N>)>,
    in_progress: &mut HashSet<(ProgramID<N>, ProgramID<N>, Identifier<N>)>,
) -> Result<bool> {
    use PlaintextType::*;

    // Equivalence requires equal struct names, so each arm below compares one name across the two stacks.
    match (type0, type1) {
        (Array(array0), Array(array1)) => Ok(array0.length() == array1.length()
            && types_equivalent_inner(
                stack0,
                array0.next_element_type(),
                stack1,
                array1.next_element_type(),
                confirmed,
                in_progress,
            )?),
        (Literal(lit0), Literal(lit1)) => Ok(lit0 == lit1),
        (Struct(id0), Struct(id1)) => match id0 == id1 {
            true => structs_equivalent_inner(stack0, stack1, id0, confirmed, in_progress),
            false => Ok(false),
        },
        (ExternalStruct(loc0), ExternalStruct(loc1)) => match loc0.resource() == loc1.resource() {
            true => structs_equivalent_inner(
                &*stack0.get_external_stack(loc0.program_id())?,
                &*stack1.get_external_stack(loc1.program_id())?,
                loc0.resource(),
                confirmed,
                in_progress,
            ),
            false => Ok(false),
        },
        (ExternalStruct(loc), Struct(id)) => match loc.resource() == id {
            true => structs_equivalent_inner(
                &*stack0.get_external_stack(loc.program_id())?,
                stack1,
                id,
                confirmed,
                in_progress,
            ),
            false => Ok(false),
        },
        (Struct(id), ExternalStruct(loc)) => match id == loc.resource() {
            true => structs_equivalent_inner(
                stack0,
                &*stack1.get_external_stack(loc.program_id())?,
                id,
                confirmed,
                in_progress,
            ),
            false => Ok(false),
        },
        _ => Ok(false),
    }
}

/// Compares the struct named `name` in `stack0` against the one of that name in `stack1`, threading the
/// memoization set from [`types_equivalent_inner`].
///
/// `in_progress` holds the pairs currently on the recursion path, and re-entering one means the cross-program
/// struct graph is cyclic.
///
/// The key is `(program0, program1, name)`, which uniquely identifies the pair being compared, since a name
/// resolves to one struct per program.
fn structs_equivalent_inner<N: Network>(
    stack0: &impl StackTrait<N>,
    stack1: &impl StackTrait<N>,
    name: &Identifier<N>,
    confirmed: &mut HashSet<(ProgramID<N>, ProgramID<N>, Identifier<N>)>,
    in_progress: &mut HashSet<(ProgramID<N>, ProgramID<N>, Identifier<N>)>,
) -> Result<bool> {
    // If this pair of structs has already been confirmed equivalent, there is nothing left to compare.
    let key = (*stack0.program_id(), *stack1.program_id(), *name);
    if confirmed.contains(&key) {
        return Ok(true);
    }

    // Reject cyclic struct references instead of recursing until the process exhausts its stack.
    if !in_progress.insert(key) {
        bail!(
            "Cyclic struct reference detected while comparing '{name}' in '{}' and '{}'",
            stack0.program_id(),
            stack1.program_id()
        )
    }

    let result: Result<bool> = (|| {
        let st0 = stack0.program().get_struct(name)?;
        let st1 = stack1.program().get_struct(name)?;

        if st0.members().len() != st1.members().len() {
            return Ok(false);
        }

        for ((name0, type0), (name1, type1)) in st0.members().iter().zip(st1.members()) {
            if name0 != name1 || !types_equivalent_inner(stack0, type0, stack1, type1, confirmed, in_progress)? {
                return Ok(false);
            }
        }

        Ok(true)
    })();

    in_progress.remove(&key);

    if !result? {
        return Ok(false);
    }

    // Record only confirmed equivalences: a mismatch short-circuits the whole comparison to `false`, so a hit
    // above always denotes a genuine equivalence, and the memoization changes only the running time.
    confirmed.insert(key);
    Ok(true)
}

pub trait FinalizeRegistersState<N: Network>: RegistersTrait<N> {
    /// Returns the global state for the finalize scope.
    fn state(&self) -> &FinalizeGlobalState;

    /// Returns the transition ID for the finalize scope, if one is associated with this scope.
    /// View functions are externally-callable and have no associated transition, so this is
    /// `None` on the view path; finalize and constructor scopes always have `Some(...)`.
    fn transition_id(&self) -> Option<&N::TransitionID>;

    /// Returns the function name for the finalize scope.
    fn function_name(&self) -> &Identifier<N>;

    /// Returns the nonce for the finalize registers, if one is associated with this scope.
    /// `None` on the view path (no transition → no nonce); always `Some(...)` on finalize.
    fn nonce(&self) -> Option<u64>;
}

pub trait RegistersSigner<N: Network>: RegistersTrait<N> {
    /// Returns the transition signer.
    fn signer(&self) -> Result<Address<N>>;

    /// Sets the transition signer.
    fn set_signer(&mut self, signer: Address<N>);

    /// Returns the root transition view key.
    fn root_tvk(&self) -> Result<Field<N>>;

    /// Sets the root transition view key.
    fn set_root_tvk(&mut self, root_tvk: Field<N>);

    /// Returns the transition caller.
    fn caller(&self) -> Result<Address<N>>;

    /// Sets the transition caller.
    fn set_caller(&mut self, caller: Address<N>);

    /// Returns the transition view key.
    fn tvk(&self) -> Result<Field<N>>;

    /// Sets the transition view key.
    fn set_tvk(&mut self, tvk: Field<N>);

    /// Returns the request.
    fn request(&self) -> Result<&Request<N>>;

    /// Sets the request.
    fn set_request(&mut self, request: Request<N>);
}

pub trait RegistersTrait<N: Network> {
    /// Loads the value of a given operand.
    ///
    /// # Errors
    /// This method should halt if the register locator is not found.
    /// In the case of register members, this method should halt if the member is not found.
    fn load(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<Value<N>>;

    /// Loads the literal of a given operand.
    ///
    /// # Errors
    /// This method should halt if the given operand is not a literal.
    /// This method should halt if the register locator is not found.
    /// In the case of register members, this method should halt if the member is not found.
    fn load_literal(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<Literal<N>> {
        match self.load(stack, operand)? {
            Value::Plaintext(Plaintext::Literal(literal, ..)) => Ok(literal),
            Value::Plaintext(Plaintext::Struct(..))
            | Value::Plaintext(Plaintext::Array(..))
            | Value::Record(..)
            | Value::Future(..)
            | Value::DynamicRecord(..)
            | Value::DynamicFuture(..) => {
                bail!("Operand must be a literal")
            }
        }
    }

    /// Loads the plaintext of a given operand.
    ///
    /// # Errors
    /// This method should halt if the given operand is not a plaintext.
    /// This method should halt if the register locator is not found.
    /// In the case of register members, this method should halt if the member is not found.
    fn load_plaintext(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<Plaintext<N>> {
        match self.load(stack, operand)? {
            Value::Plaintext(plaintext) => Ok(plaintext),
            Value::Record(..) | Value::Future(..) | Value::DynamicRecord(..) | Value::DynamicFuture(..) => {
                bail!("Operand must be a plaintext")
            }
        }
    }

    /// Assigns the given value to the given register, assuming the register is not already assigned.
    ///
    /// # Errors
    /// This method should halt if the given register is a register member.
    /// This method should halt if the given register is an input register.
    /// This method should halt if the register is already used.
    fn store(&mut self, stack: &impl StackTrait<N>, register: &Register<N>, stack_value: Value<N>) -> Result<()>;

    /// Assigns the given literal to the given register, assuming the register is not already assigned.
    ///
    /// # Errors
    /// This method should halt if the given register is a register member.
    /// This method should halt if the given register is an input register.
    /// This method should halt if the register is already used.
    fn store_literal(&mut self, stack: &impl StackTrait<N>, register: &Register<N>, literal: Literal<N>) -> Result<()> {
        self.store(stack, register, Value::Plaintext(Plaintext::from(literal)))
    }
}

/// This trait is intended to be implemented only by `snarkvm_synthesizer_process::Registers`.
///
/// We make it a trait only to avoid circular dependencies.
pub trait RegistersCircuit<N: Network, A: circuit::Aleo<Network = N>> {
    /// Returns the transition signer, as a circuit.
    fn signer_circuit(&self) -> Result<circuit::Address<A>>;

    /// Sets the transition signer, as a circuit.
    fn set_signer_circuit(&mut self, signer_circuit: circuit::Address<A>);

    /// Returns the root transition view key, as a circuit.
    fn root_tvk_circuit(&self) -> Result<circuit::Field<A>>;

    /// Sets the root transition view key, as a circuit.
    fn set_root_tvk_circuit(&mut self, root_tvk_circuit: circuit::Field<A>);

    /// Returns the transition caller, as a circuit.
    fn caller_circuit(&self) -> Result<circuit::Address<A>>;

    /// Sets the transition caller, as a circuit.
    fn set_caller_circuit(&mut self, caller_circuit: circuit::Address<A>);

    /// Returns the transition view key, as a circuit.
    fn tvk_circuit(&self) -> Result<circuit::Field<A>>;

    /// Sets the transition view key, as a circuit.
    fn set_tvk_circuit(&mut self, tvk_circuit: circuit::Field<A>);

    /// Loads the value of a given operand.
    ///
    /// # Errors
    /// This method should halt if the register locator is not found.
    /// In the case of register members, this method should halt if the member is not found.
    fn load_circuit(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<circuit::Value<A>>;

    /// Loads the literal of a given operand.
    ///
    /// # Errors
    /// This method should halt if the given operand is not a literal.
    /// This method should halt if the register locator is not found.
    /// In the case of register members, this method should halt if the member is not found.
    fn load_literal_circuit(&self, stack: &impl StackTrait<N>, operand: &Operand<N>) -> Result<circuit::Literal<A>> {
        match self.load_circuit(stack, operand)? {
            circuit::Value::Plaintext(circuit::Plaintext::Literal(literal, ..)) => Ok(literal),
            circuit::Value::Plaintext(circuit::Plaintext::Struct(..))
            | circuit::Value::Plaintext(circuit::Plaintext::Array(..))
            | circuit::Value::Record(..)
            | circuit::Value::Future(..)
            | circuit::Value::DynamicRecord(..)
            | circuit::Value::DynamicFuture(..) => bail!("Operand must be a literal"),
        }
    }

    /// Loads the plaintext of a given operand.
    ///
    /// # Errors
    /// This method should halt if the given operand is not a plaintext.
    /// This method should halt if the register locator is not found.
    /// In the case of register members, this method should halt if the member is not found.
    fn load_plaintext_circuit(
        &self,
        stack: &impl StackTrait<N>,
        operand: &Operand<N>,
    ) -> Result<circuit::Plaintext<A>> {
        match self.load_circuit(stack, operand)? {
            circuit::Value::Plaintext(plaintext) => Ok(plaintext),
            circuit::Value::Record(..)
            | circuit::Value::Future(..)
            | circuit::Value::DynamicRecord(..)
            | circuit::Value::DynamicFuture(..) => bail!("Operand must be a plaintext"),
        }
    }

    /// Assigns the given value to the given register, assuming the register is not already assigned.
    ///
    /// # Errors
    /// This method should halt if the given register is a register member.
    /// This method should halt if the given register is an input register.
    /// This method should halt if the register is already used.
    fn store_circuit(
        &mut self,
        stack: &impl StackTrait<N>,
        register: &Register<N>,
        stack_value: circuit::Value<A>,
    ) -> Result<()>;

    /// Assigns the given literal to the given register, assuming the register is not already assigned.
    ///
    /// # Errors
    /// This method should halt if the given register is a register member.
    /// This method should halt if the given register is an input register.
    /// This method should halt if the register is already used.
    fn store_literal_circuit(
        &mut self,
        stack: &impl StackTrait<N>,
        register: &Register<N>,
        literal: circuit::Literal<A>,
    ) -> Result<()> {
        self.store_circuit(stack, register, circuit::Value::Plaintext(circuit::Plaintext::from(literal)))
    }

    /// Checks that the given circuit value matches the layout of the register type. This is a circuit analogue of [`StackTrait::matches_register_type`].
    fn circuit_matches_register_type(
        stack: &impl StackTrait<N>,
        circuit_value: &circuit::Value<A>,
        register_type: &RegisterType<N>,
    ) -> Result<()>;
}
