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
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_circuit as circuit;
extern crate snarkvm_console as console;

pub type Program<N> = crate::ProgramCore<N>;
pub type Function<N> = crate::FunctionCore<N>;
pub type Finalize<N> = crate::FinalizeCore<N>;
pub type Closure<N> = crate::ClosureCore<N>;
pub type Constructor<N> = crate::ConstructorCore<N>;

mod closure;
pub use closure::*;

mod constructor;
pub use constructor::*;

pub mod finalize;
pub use finalize::*;

mod function;
pub use function::*;

mod import;
pub use import::*;

pub mod view;
pub use view::ViewCore;

pub type View<N> = crate::ViewCore<N>;

pub mod logic;
pub use logic::*;

mod mapping;
pub use mapping::*;

mod traits;
pub use traits::*;

mod bytes;
mod parse;
mod serialize;
mod to_checksum;

use console::{
    network::{
        ConsensusVersion,
        consensus_config_value,
        prelude::{
            Debug,
            Deserialize,
            Deserializer,
            Display,
            Err,
            Error,
            ErrorKind,
            Formatter,
            FromBytes,
            FromBytesDeserializer,
            FromStr,
            IoResult,
            Itertools,
            Network,
            Parser,
            ParserResult,
            Read,
            Result,
            Sanitizer,
            Serialize,
            Serializer,
            ToBytes,
            ToBytesSerializer,
            TypeName,
            Write,
            anyhow,
            bail,
            de,
            ensure,
            error,
            fmt,
            make_error,
            many0,
            many1,
            map,
            map_res,
            tag,
            take,
        },
    },
    program::{
        EntryType,
        FinalizeType,
        Identifier,
        Locator,
        PlaintextType,
        ProgramID,
        RecordType,
        RegisterType,
        StructType,
        ValueType,
    },
    types::U8,
};
use snarkvm_utilities::{cfg_find_map, cfg_iter};

use indexmap::{IndexMap, IndexSet};
use std::collections::BTreeSet;
use tiny_keccak::{Hasher, Sha3 as TinySha3};

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum ProgramLabel<N: Network> {
    /// A program constructor.
    Constructor,
    /// A named component.
    Identifier(Identifier<N>),
}

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum ProgramDefinition {
    /// A program constructor.
    Constructor,
    /// A program mapping.
    Mapping,
    /// A program struct.
    Struct,
    /// A program record.
    Record,
    /// A program closure.
    Closure,
    /// A program function.
    Function,
    /// A program view function.
    View,
}

#[derive(Clone)]
pub struct ProgramCore<N: Network> {
    /// The ID of the program.
    id: ProgramID<N>,
    /// A map of the declared imports for the program.
    imports: IndexMap<ProgramID<N>, Import<N>>,
    /// A map of program labels to their program definitions.
    components: IndexMap<ProgramLabel<N>, ProgramDefinition>,
    /// An optional constructor for the program.
    constructor: Option<ConstructorCore<N>>,
    /// A map of the declared mappings for the program.
    mappings: IndexMap<Identifier<N>, Mapping<N>>,
    /// A map of the declared structs for the program.
    structs: IndexMap<Identifier<N>, StructType<N>>,
    /// A map of the declared record types for the program.
    records: IndexMap<Identifier<N>, RecordType<N>>,
    /// A map of the declared closures for the program.
    closures: IndexMap<Identifier<N>, ClosureCore<N>>,
    /// A map of the declared functions for the program.
    functions: IndexMap<Identifier<N>, FunctionCore<N>>,
    /// A map of the declared view functions for the program.
    views: IndexMap<Identifier<N>, ViewCore<N>>,
}

impl<N: Network> PartialEq for ProgramCore<N> {
    /// Compares two programs for equality, verifying that the components are in the same order.
    /// The order of the components must match to ensure that deployment tree is well-formed.
    fn eq(&self, other: &Self) -> bool {
        // Check that the number of components is the same.
        if self.components.len() != other.components.len() {
            return false;
        }
        // Check that the components match in order.
        for (left, right) in self.components.iter().zip_eq(other.components.iter()) {
            if left != right {
                return false;
            }
        }
        // Check that the remaining fields match.
        self.id == other.id
            && self.imports == other.imports
            && self.mappings == other.mappings
            && self.structs == other.structs
            && self.records == other.records
            && self.closures == other.closures
            && self.functions == other.functions
            && self.views == other.views
    }
}

impl<N: Network> Eq for ProgramCore<N> {}

impl<N: Network> ProgramCore<N> {
    /// A list of reserved keywords for Aleo programs, enforced at the parser level.
    // New keywords should be enforced through `RESTRICTED_KEYWORDS` instead, if possible.
    // Adding keywords to this list will require a backwards-compatible versioning for programs.
    #[rustfmt::skip]
    pub const KEYWORDS: &'static [&'static str] = &[
        // Mode
        "const",
        "constant",
        "public",
        "private",
        // Literals
        "address",
        "boolean",
        "field",
        "group",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "scalar",
        "signature",
        "string",
        // Boolean
        "true",
        "false",
        // Statements
        "input",
        "output",
        "as",
        "into",
        // Record
        "record",
        "owner",
        // Program
        "transition",
        "import",
        "function",
        "struct",
        "closure",
        "program",
        "aleo",
        "self",
        "storage",
        "mapping",
        "key",
        "value",
        "async",
        "finalize",
        // Reserved (catch all)
        "global",
        "block",
        "return",
        "break",
        "assert",
        "continue",
        "let",
        "if",
        "else",
        "while",
        "for",
        "switch",
        "case",
        "default",
        "match",
        "enum",
        "struct",
        "union",
        "trait",
        "impl",
        "type",
        "future",
    ];
    /// A list of restricted keywords for Aleo programs, enforced at the VM-level for program hygiene.
    /// Each entry is a tuple of the consensus version and a list of keywords.
    /// If the current consensus version is greater than or equal to the specified version,
    /// the keywords in the list should be restricted.
    #[rustfmt::skip]
    pub const RESTRICTED_KEYWORDS: &'static [(ConsensusVersion, &'static [&'static str])] = &[
        (ConsensusVersion::V6, &["constructor"]),
        (ConsensusVersion::V14, &["dynamic", "identifier"]),
        (ConsensusVersion::V15, &["view"]),
    ];

    /// Initializes an empty program.
    #[inline]
    pub fn new(id: ProgramID<N>) -> Result<Self> {
        // Ensure the program name is valid.
        ensure!(!Self::is_reserved_keyword(id.name()), "Program name is invalid: {}", id.name());

        Ok(Self {
            id,
            imports: IndexMap::new(),
            constructor: None,
            components: IndexMap::new(),
            mappings: IndexMap::new(),
            structs: IndexMap::new(),
            records: IndexMap::new(),
            closures: IndexMap::new(),
            functions: IndexMap::new(),
            views: IndexMap::new(),
        })
    }

    /// Initializes the credits program.
    #[inline]
    pub fn credits() -> Result<Self> {
        Self::from_str(include_str!("./resources/credits.aleo"))
    }

    /// Returns the ID of the program.
    pub const fn id(&self) -> &ProgramID<N> {
        &self.id
    }

    /// Returns the imports in the program.
    pub const fn imports(&self) -> &IndexMap<ProgramID<N>, Import<N>> {
        &self.imports
    }

    /// Returns the constructor for the program.
    pub const fn constructor(&self) -> Option<&ConstructorCore<N>> {
        self.constructor.as_ref()
    }

    /// Returns the mappings in the program.
    pub const fn mappings(&self) -> &IndexMap<Identifier<N>, Mapping<N>> {
        &self.mappings
    }

    /// Returns the structs in the program.
    pub const fn structs(&self) -> &IndexMap<Identifier<N>, StructType<N>> {
        &self.structs
    }

    /// Returns the records in the program.
    pub const fn records(&self) -> &IndexMap<Identifier<N>, RecordType<N>> {
        &self.records
    }

    /// Returns the closures in the program.
    pub const fn closures(&self) -> &IndexMap<Identifier<N>, ClosureCore<N>> {
        &self.closures
    }

    /// Returns the functions in the program.
    pub const fn functions(&self) -> &IndexMap<Identifier<N>, FunctionCore<N>> {
        &self.functions
    }

    /// Returns the view functions in the program.
    pub const fn views(&self) -> &IndexMap<Identifier<N>, ViewCore<N>> {
        &self.views
    }

    /// Returns `true` if the program contains an import with the given program ID.
    pub fn contains_import(&self, id: &ProgramID<N>) -> bool {
        self.imports.contains_key(id)
    }

    /// Returns `true` if the program contains a constructor.
    pub const fn contains_constructor(&self) -> bool {
        self.constructor.is_some()
    }

    /// Returns `true` if the program contains a mapping with the given name.
    pub fn contains_mapping(&self, name: &Identifier<N>) -> bool {
        self.mappings.contains_key(name)
    }

    /// Returns `true` if the program contains a struct with the given name.
    pub fn contains_struct(&self, name: &Identifier<N>) -> bool {
        self.structs.contains_key(name)
    }

    /// Returns `true` if the program contains a record with the given name.
    pub fn contains_record(&self, name: &Identifier<N>) -> bool {
        self.records.contains_key(name)
    }

    /// Returns `true` if the program contains a closure with the given name.
    pub fn contains_closure(&self, name: &Identifier<N>) -> bool {
        self.closures.contains_key(name)
    }

    /// Returns `true` if the program contains a function with the given name.
    pub fn contains_function(&self, name: &Identifier<N>) -> bool {
        self.functions.contains_key(name)
    }

    /// Returns `true` if the program contains a view function with the given name.
    pub fn contains_view(&self, name: &Identifier<N>) -> bool {
        self.views.contains_key(name)
    }

    /// Returns the mapping with the given name.
    pub fn get_mapping(&self, name: &Identifier<N>) -> Result<Mapping<N>> {
        // Attempt to retrieve the mapping.
        let mapping = self.mappings.get(name).cloned().ok_or_else(|| anyhow!("Mapping '{name}' is not defined."))?;
        // Ensure the mapping name matches.
        ensure!(mapping.name() == name, "Expected mapping '{name}', but found mapping '{}'", mapping.name());
        // Return the mapping.
        Ok(mapping)
    }

    /// Returns the struct with the given name.
    pub fn get_struct(&self, name: &Identifier<N>) -> Result<&StructType<N>> {
        // Attempt to retrieve the struct.
        let struct_ = self.structs.get(name).ok_or_else(|| anyhow!("Struct '{name}' is not defined."))?;
        // Ensure the struct name matches.
        ensure!(struct_.name() == name, "Expected struct '{name}', but found struct '{}'", struct_.name());
        // Ensure the struct contains members.
        ensure!(!struct_.members().is_empty(), "Struct '{name}' is missing members.");
        // Return the struct.
        Ok(struct_)
    }

    /// Returns the record with the given name.
    pub fn get_record(&self, name: &Identifier<N>) -> Result<&RecordType<N>> {
        // Attempt to retrieve the record.
        let record = self.records.get(name).ok_or_else(|| anyhow!("Record '{name}' is not defined."))?;
        // Ensure the record name matches.
        ensure!(record.name() == name, "Expected record '{name}', but found record '{}'", record.name());
        // Return the record.
        Ok(record)
    }

    /// Returns the closure with the given name.
    pub fn get_closure(&self, name: &Identifier<N>) -> Result<ClosureCore<N>> {
        self.get_closure_ref(name).cloned()
    }

    /// Returns a reference to the closure with the given name.
    pub fn get_closure_ref(&self, name: &Identifier<N>) -> Result<&ClosureCore<N>> {
        // Attempt to retrieve the closure.
        let closure = self.closures.get(name).ok_or_else(|| anyhow!("Closure '{name}' is not defined."))?;
        // Ensure the closure name matches.
        ensure!(closure.name() == name, "Expected closure '{name}', but found closure '{}'", closure.name());
        // Ensure there are input statements in the closure.
        ensure!(!closure.inputs().is_empty(), "Cannot evaluate a closure without input statements");
        // Ensure the number of inputs is within the allowed range.
        ensure!(closure.inputs().len() <= N::MAX_INPUTS, "Closure exceeds maximum number of inputs");
        // Ensure there are instructions in the closure.
        ensure!(!closure.instructions().is_empty(), "Cannot evaluate a closure without instructions");
        // Ensure the number of outputs is within the allowed range.
        ensure!(closure.outputs().len() <= N::MAX_OUTPUTS, "Closure exceeds maximum number of outputs");
        // Return the closure.
        Ok(closure)
    }

    /// Returns the function with the given name.
    pub fn get_function(&self, name: &Identifier<N>) -> Result<FunctionCore<N>> {
        self.get_function_ref(name).cloned()
    }

    /// Returns a reference to the function with the given name.
    pub fn get_function_ref(&self, name: &Identifier<N>) -> Result<&FunctionCore<N>> {
        // Attempt to retrieve the function.
        let function = self.functions.get(name).ok_or(anyhow!("Function '{}/{name}' is not defined.", self.id))?;
        // Ensure the function name matches.
        ensure!(function.name() == name, "Expected function '{name}', but found function '{}'", function.name());
        // Ensure the number of inputs is within the allowed range.
        ensure!(function.inputs().len() <= N::MAX_INPUTS, "Function exceeds maximum number of inputs");
        // Ensure the number of instructions is within the allowed range.
        ensure!(function.instructions().len() <= N::MAX_INSTRUCTIONS, "Function exceeds maximum instructions");
        // Ensure the number of outputs is within the allowed range.
        ensure!(function.outputs().len() <= N::MAX_OUTPUTS, "Function exceeds maximum number of outputs");
        // Return the function.
        Ok(function)
    }

    /// Returns the view function with the given name.
    pub fn get_view(&self, name: &Identifier<N>) -> Result<ViewCore<N>> {
        self.get_view_ref(name).cloned()
    }

    /// Returns a reference to the view function with the given name.
    pub fn get_view_ref(&self, name: &Identifier<N>) -> Result<&ViewCore<N>> {
        let view = self.views.get(name).ok_or(anyhow!("View '{}/{name}' is not defined.", self.id))?;
        ensure!(view.name() == name, "Expected view '{name}', but found view '{}'", view.name());
        ensure!(view.inputs().len() <= N::MAX_INPUTS, "View exceeds maximum number of inputs");
        ensure!(view.commands().len() <= N::MAX_COMMANDS, "View exceeds maximum number of commands");
        ensure!(view.outputs().len() <= N::MAX_OUTPUTS, "View exceeds maximum number of outputs");
        Ok(view)
    }

    /// Adds a new import statement to the program.
    ///
    /// # Errors
    /// This method will halt if the imported program was previously added.
    #[inline]
    fn add_import(&mut self, import: Import<N>) -> Result<()> {
        // Retrieve the imported program name.
        let import_name = *import.name();

        // Ensure that the number of imports is within the allowed range.
        ensure!(self.imports.len() < N::MAX_IMPORTS, "Program exceeds the maximum number of imports");

        // Ensure the import name is new.
        ensure!(self.is_unique_name(&import_name), "'{import_name}' is already in use.");
        // Ensure the import name is not a reserved opcode.
        ensure!(!Self::is_reserved_opcode(&import_name.to_string()), "'{import_name}' is a reserved opcode.");
        // Ensure the import name is not a reserved keyword.
        ensure!(!Self::is_reserved_keyword(&import_name), "'{import_name}' is a reserved keyword.");

        // Ensure the import is new.
        ensure!(
            !self.imports.contains_key(import.program_id()),
            "Import '{}' is already defined.",
            import.program_id()
        );

        // Add the import statement to the program.
        if self.imports.insert(*import.program_id(), import.clone()).is_some() {
            bail!("'{}' already exists in the program.", import.program_id())
        }
        Ok(())
    }

    /// Adds a constructor to the program.
    ///
    /// # Errors
    /// This method will halt if a constructor was previously added.
    /// This method will halt if a constructor exceeds the maximum number of commands.
    fn add_constructor(&mut self, constructor: ConstructorCore<N>) -> Result<()> {
        // Ensure the program does not already have a constructor.
        ensure!(self.constructor.is_none(), "Program already has a constructor.");
        // Ensure the number of commands is within the allowed range.
        ensure!(!constructor.commands().is_empty(), "Constructor must have at least one command");
        ensure!(constructor.commands().len() <= N::MAX_COMMANDS, "Constructor exceeds maximum number of commands");
        // Add the constructor to the components.
        if self.components.insert(ProgramLabel::Constructor, ProgramDefinition::Constructor).is_some() {
            bail!("Constructor already exists in the program.")
        }
        // Add the constructor to the program.
        self.constructor = Some(constructor);
        Ok(())
    }

    /// Adds a new mapping to the program.
    ///
    /// # Errors
    /// This method will halt if the mapping name is already in use.
    /// This method will halt if the mapping name is a reserved opcode or keyword.
    #[inline]
    fn add_mapping(&mut self, mapping: Mapping<N>) -> Result<()> {
        // Retrieve the mapping name.
        let mapping_name = *mapping.name();

        // Ensure the program has not exceeded the maximum number of mappings.
        ensure!(self.mappings.len() < N::LATEST_MAX_MAPPINGS(), "Program exceeds the maximum number of mappings");

        // Ensure the mapping name is new.
        ensure!(self.is_unique_name(&mapping_name), "'{mapping_name}' is already in use.");
        // Ensure the mapping name is not a reserved keyword.
        ensure!(!Self::is_reserved_keyword(&mapping_name), "'{mapping_name}' is a reserved keyword.");
        // Ensure the mapping name is not a reserved opcode.
        ensure!(!Self::is_reserved_opcode(&mapping_name.to_string()), "'{mapping_name}' is a reserved opcode.");

        // Add the mapping name to the identifiers.
        if self.components.insert(ProgramLabel::Identifier(mapping_name), ProgramDefinition::Mapping).is_some() {
            bail!("'{mapping_name}' already exists in the program.")
        }
        // Add the mapping to the program.
        if self.mappings.insert(mapping_name, mapping).is_some() {
            bail!("'{mapping_name}' already exists in the program.")
        }
        Ok(())
    }

    /// Adds a new struct to the program.
    ///
    /// # Errors
    /// This method will halt if the struct was previously added.
    /// This method will halt if the struct name is already in use in the program.
    /// This method will halt if the struct name is a reserved opcode or keyword.
    /// This method will halt if any structs in the struct's members are not already defined.
    #[inline]
    fn add_struct(&mut self, struct_: StructType<N>) -> Result<()> {
        // Retrieve the struct name.
        let struct_name = *struct_.name();

        // Ensure the program has not exceeded the maximum number of structs.
        ensure!(self.structs.len() < N::MAX_STRUCTS, "Program exceeds the maximum number of structs.");

        // Ensure the struct name is new.
        ensure!(self.is_unique_name(&struct_name), "'{struct_name}' is already in use.");
        // Ensure the struct name is not a reserved opcode.
        ensure!(!Self::is_reserved_opcode(&struct_name.to_string()), "'{struct_name}' is a reserved opcode.");
        // Ensure the struct name is not a reserved keyword.
        ensure!(!Self::is_reserved_keyword(&struct_name), "'{struct_name}' is a reserved keyword.");

        // Ensure the struct contains members.
        ensure!(!struct_.members().is_empty(), "Struct '{struct_name}' is missing members.");

        // Ensure all struct members are well-formed.
        // Note: This design ensures cyclic references are not possible.
        for (identifier, plaintext_type) in struct_.members() {
            // Ensure the member name is not a reserved keyword.
            ensure!(!Self::is_reserved_keyword(identifier), "'{identifier}' is a reserved keyword.");
            // Ensure the member type is already defined in the program.
            match plaintext_type {
                PlaintextType::Literal(_) => continue,
                PlaintextType::Struct(member_identifier) => {
                    // Ensure the member struct name exists in the program.
                    if !self.structs.contains_key(member_identifier) {
                        bail!("'{member_identifier}' in struct '{struct_name}' is not defined.")
                    }
                }
                PlaintextType::ExternalStruct(locator) => {
                    if !self.imports.contains_key(locator.program_id()) {
                        bail!(
                            "External program {} referenced in struct '{struct_name}' does not exist",
                            locator.program_id()
                        );
                    }
                }
                PlaintextType::Array(array_type) => {
                    match array_type.base_element_type() {
                        PlaintextType::Struct(struct_name) =>
                        // Ensure the member struct name exists in the program.
                        {
                            if !self.structs.contains_key(struct_name) {
                                bail!("'{struct_name}' in array '{array_type}' is not defined.")
                            }
                        }
                        PlaintextType::ExternalStruct(locator) => {
                            if !self.imports.contains_key(locator.program_id()) {
                                bail!(
                                    "External program {} in array '{array_type}' does not exist",
                                    locator.program_id()
                                );
                            }
                        }
                        PlaintextType::Array(..) | PlaintextType::Literal(..) => {}
                    }
                }
            }
        }

        // Add the struct name to the identifiers.
        if self.components.insert(ProgramLabel::Identifier(struct_name), ProgramDefinition::Struct).is_some() {
            bail!("'{struct_name}' already exists in the program.")
        }
        // Add the struct to the program.
        if self.structs.insert(struct_name, struct_).is_some() {
            bail!("'{struct_name}' already exists in the program.")
        }
        Ok(())
    }

    /// Adds a new record to the program.
    ///
    /// # Errors
    /// This method will halt if the record was previously added.
    /// This method will halt if the record name is already in use in the program.
    /// This method will halt if the record name is a reserved opcode or keyword.
    /// This method will halt if any records in the record's members are not already defined.
    #[inline]
    fn add_record(&mut self, record: RecordType<N>) -> Result<()> {
        // Retrieve the record name.
        let record_name = *record.name();

        // Ensure the program has not exceeded the maximum number of records.
        ensure!(self.records.len() < N::MAX_RECORDS, "Program exceeds the maximum number of records.");

        // Ensure the record name is new.
        ensure!(self.is_unique_name(&record_name), "'{record_name}' is already in use.");
        // Ensure the record name is not a reserved opcode.
        ensure!(!Self::is_reserved_opcode(&record_name.to_string()), "'{record_name}' is a reserved opcode.");
        // Ensure the record name is not a reserved keyword.
        ensure!(!Self::is_reserved_keyword(&record_name), "'{record_name}' is a reserved keyword.");

        // Ensure all record entries are well-formed.
        // Note: This design ensures cyclic references are not possible.
        for (identifier, entry_type) in record.entries() {
            // Ensure the member name is not a reserved keyword.
            ensure!(!Self::is_reserved_keyword(identifier), "'{identifier}' is a reserved keyword.");
            // Ensure the member type is already defined in the program.
            match entry_type.plaintext_type() {
                PlaintextType::Literal(_) => continue,
                PlaintextType::Struct(identifier) => {
                    if !self.structs.contains_key(identifier) {
                        bail!("Struct '{identifier}' in record '{record_name}' is not defined.")
                    }
                }
                PlaintextType::ExternalStruct(locator) => {
                    if !self.imports.contains_key(locator.program_id()) {
                        bail!(
                            "External program {} referenced in record '{record_name}' does not exist",
                            locator.program_id()
                        );
                    }
                }
                PlaintextType::Array(array_type) => {
                    match array_type.base_element_type() {
                        PlaintextType::Struct(struct_name) =>
                        // Ensure the member struct name exists in the program.
                        {
                            if !self.structs.contains_key(struct_name) {
                                bail!("'{struct_name}' in array '{array_type}' is not defined.")
                            }
                        }
                        PlaintextType::ExternalStruct(locator) => {
                            if !self.imports.contains_key(locator.program_id()) {
                                bail!(
                                    "External program {} in array '{array_type}' does not exist",
                                    locator.program_id()
                                );
                            }
                        }
                        PlaintextType::Array(..) | PlaintextType::Literal(..) => {}
                    }
                }
            }
        }

        // Add the record name to the identifiers.
        if self.components.insert(ProgramLabel::Identifier(record_name), ProgramDefinition::Record).is_some() {
            bail!("'{record_name}' already exists in the program.")
        }
        // Add the record to the program.
        if self.records.insert(record_name, record).is_some() {
            bail!("'{record_name}' already exists in the program.")
        }
        Ok(())
    }

    /// Adds a new closure to the program.
    ///
    /// # Errors
    /// This method will halt if the closure was previously added.
    /// This method will halt if the closure name is already in use in the program.
    /// This method will halt if the closure name is a reserved opcode or keyword.
    /// This method will halt if any registers are assigned more than once.
    /// This method will halt if the registers are not incrementing monotonically.
    /// This method will halt if an input type references a non-existent definition.
    /// This method will halt if an operand register does not already exist in memory.
    /// This method will halt if a destination register already exists in memory.
    /// This method will halt if an output register does not already exist.
    /// This method will halt if an output type references a non-existent definition.
    #[inline]
    fn add_closure(&mut self, closure: ClosureCore<N>) -> Result<()> {
        // Retrieve the closure name.
        let closure_name = *closure.name();

        // Ensure the program has not exceeded the maximum number of closures.
        ensure!(self.closures.len() < N::MAX_CLOSURES, "Program exceeds the maximum number of closures.");

        // Ensure the closure name is new.
        ensure!(self.is_unique_name(&closure_name), "'{closure_name}' is already in use.");
        // Ensure the closure name is not a reserved opcode.
        ensure!(!Self::is_reserved_opcode(&closure_name.to_string()), "'{closure_name}' is a reserved opcode.");
        // Ensure the closure name is not a reserved keyword.
        ensure!(!Self::is_reserved_keyword(&closure_name), "'{closure_name}' is a reserved keyword.");

        // Ensure there are input statements in the closure.
        ensure!(!closure.inputs().is_empty(), "Cannot evaluate a closure without input statements");
        // Ensure the number of inputs is within the allowed range.
        ensure!(closure.inputs().len() <= N::MAX_INPUTS, "Closure exceeds maximum number of inputs");
        // Ensure there are instructions in the closure.
        ensure!(!closure.instructions().is_empty(), "Cannot evaluate a closure without instructions");
        // Ensure the number of outputs is within the allowed range.
        ensure!(closure.outputs().len() <= N::MAX_OUTPUTS, "Closure exceeds maximum number of outputs");

        // Add the function name to the identifiers.
        if self.components.insert(ProgramLabel::Identifier(closure_name), ProgramDefinition::Closure).is_some() {
            bail!("'{closure_name}' already exists in the program.")
        }
        // Add the closure to the program.
        if self.closures.insert(closure_name, closure).is_some() {
            bail!("'{closure_name}' already exists in the program.")
        }
        Ok(())
    }

    /// Adds a new function to the program.
    ///
    /// # Errors
    /// This method will halt if the function was previously added.
    /// This method will halt if the function name is already in use in the program.
    /// This method will halt if the function name is a reserved opcode or keyword.
    /// This method will halt if any registers are assigned more than once.
    /// This method will halt if the registers are not incrementing monotonically.
    /// This method will halt if an input type references a non-existent definition.
    /// This method will halt if an operand register does not already exist in memory.
    /// This method will halt if a destination register already exists in memory.
    /// This method will halt if an output register does not already exist.
    /// This method will halt if an output type references a non-existent definition.
    #[inline]
    fn add_function(&mut self, function: FunctionCore<N>) -> Result<()> {
        // Retrieve the function name.
        let function_name = *function.name();

        // Ensure the program has not exceeded the maximum number of functions.
        ensure!(self.functions.len() < N::MAX_FUNCTIONS, "Program exceeds the maximum number of functions");

        // Ensure the function name is new.
        ensure!(self.is_unique_name(&function_name), "'{function_name}' is already in use.");
        // Ensure the function name is not a reserved opcode.
        ensure!(!Self::is_reserved_opcode(&function_name.to_string()), "'{function_name}' is a reserved opcode.");
        // Ensure the function name is not a reserved keyword.
        ensure!(!Self::is_reserved_keyword(&function_name), "'{function_name}' is a reserved keyword.");

        // Ensure the number of inputs is within the allowed range.
        ensure!(function.inputs().len() <= N::MAX_INPUTS, "Function exceeds maximum number of inputs");
        // Ensure the number of instructions is within the allowed range.
        ensure!(function.instructions().len() <= N::MAX_INSTRUCTIONS, "Function exceeds maximum instructions");
        // Ensure the number of outputs is within the allowed range.
        ensure!(function.outputs().len() <= N::MAX_OUTPUTS, "Function exceeds maximum number of outputs");

        // Add the function name to the identifiers.
        if self.components.insert(ProgramLabel::Identifier(function_name), ProgramDefinition::Function).is_some() {
            bail!("'{function_name}' already exists in the program.")
        }
        // Add the function to the program.
        if self.functions.insert(function_name, function).is_some() {
            bail!("'{function_name}' already exists in the program.")
        }
        Ok(())
    }

    /// Adds a new view function to the program.
    ///
    /// # Errors
    /// This method will halt if the view function name is already in use in the program.
    /// This method will halt if the view function name is a reserved opcode or keyword.
    #[inline]
    fn add_view(&mut self, view: ViewCore<N>) -> Result<()> {
        let view_name = *view.name();

        ensure!(self.views.len() < N::MAX_VIEWS, "Program exceeds the maximum number of view functions.");

        ensure!(self.is_unique_name(&view_name), "'{view_name}' is already in use.");
        ensure!(!Self::is_reserved_opcode(&view_name.to_string()), "'{view_name}' is a reserved opcode.");
        ensure!(!Self::is_reserved_keyword(&view_name), "'{view_name}' is a reserved keyword.");

        // Views permit zero commands (passthrough / no-op) and zero outputs (guard views: the
        // body asserts and the caller observes success via tx acceptance, failure via tx
        // rejection; mirrors Solidity's zero-return `view` functions).
        ensure!(view.inputs().len() <= N::MAX_INPUTS, "View exceeds maximum number of inputs");
        ensure!(view.outputs().len() <= N::MAX_OUTPUTS, "View exceeds maximum number of outputs");

        if self.components.insert(ProgramLabel::Identifier(view_name), ProgramDefinition::View).is_some() {
            bail!("'{view_name}' already exists in the program.")
        }
        if self.views.insert(view_name, view).is_some() {
            bail!("'{view_name}' already exists in the program.")
        }
        Ok(())
    }

    /// Returns `true` if the given name does not already exist in the program.
    fn is_unique_name(&self, name: &Identifier<N>) -> bool {
        !self.components.contains_key(&ProgramLabel::Identifier(*name))
    }

    /// Returns `true` if the given name is a reserved opcode.
    pub fn is_reserved_opcode(name: &str) -> bool {
        Instruction::<N>::is_reserved_opcode(name)
    }

    /// Returns `true` if the given name uses a reserved keyword.
    pub fn is_reserved_keyword(name: &Identifier<N>) -> bool {
        // Convert the given name to a string.
        let name = name.to_string();
        // Check if the name is a keyword.
        Self::KEYWORDS.iter().any(|keyword| *keyword == name)
    }

    /// Returns an iterator over the restricted keywords for the given consensus version.
    pub fn restricted_keywords_for_consensus_version(
        consensus_version: ConsensusVersion,
    ) -> impl Iterator<Item = &'static str> {
        Self::RESTRICTED_KEYWORDS
            .iter()
            .filter(move |(version, _)| *version <= consensus_version)
            .flat_map(|(_, keywords)| *keywords)
            .copied()
    }

    /// Checks a program for restricted keywords for the given consensus version.
    /// Returns an error if any restricted keywords are found.
    /// Note: Restrictions are not enforced on the import names in case they were deployed before the restrictions were added.
    pub fn check_restricted_keywords_for_consensus_version(&self, consensus_version: ConsensusVersion) -> Result<()> {
        // Get all keywords that are restricted for the consensus version.
        let keywords =
            Program::<N>::restricted_keywords_for_consensus_version(consensus_version).collect::<IndexSet<_>>();
        // Check if the program name is a restricted keywords.
        let program_name = self.id().name().to_string();
        if keywords.contains(&program_name.as_str()) {
            bail!("Program name '{program_name}' is a restricted keyword for the current consensus version")
        }
        // Check that all top-level program components are not restricted keywords.
        for component in self.components.keys() {
            match component {
                ProgramLabel::Identifier(identifier) => {
                    if keywords.contains(identifier.to_string().as_str()) {
                        bail!(
                            "Program component '{identifier}' is a restricted keyword for the current consensus version"
                        )
                    }
                }
                ProgramLabel::Constructor => continue,
            }
        }
        // Check that all record entry names are not restricted keywords.
        for record_type in self.records().values() {
            for entry_name in record_type.entries().keys() {
                if keywords.contains(entry_name.to_string().as_str()) {
                    bail!("Record entry '{entry_name}' is a restricted keyword for the current consensus version")
                }
            }
        }
        // Check that all struct member names are not restricted keywords.
        for struct_type in self.structs().values() {
            for member_name in struct_type.members().keys() {
                if keywords.contains(member_name.to_string().as_str()) {
                    bail!("Struct member '{member_name}' is a restricted keyword for the current consensus version")
                }
            }
        }
        // Check that all `finalize` positions.
        // Note: It is sufficient to only check the positions in `FinalizeCore` since `FinalizeTypes::initialize` checks that every
        // `Branch` instruction targets a valid position.
        for function in self.functions().values() {
            if let Some(finalize_logic) = function.finalize_logic() {
                for position in finalize_logic.positions().keys() {
                    if keywords.contains(position.to_string().as_str()) {
                        bail!(
                            "Finalize position '{position}' is a restricted keyword for the current consensus version"
                        )
                    }
                }
            }
        }
        Ok(())
    }

    /// Checks that the program structure is well-formed under the following rules:
    ///  1. The program ID must not contain the keyword "aleo" in the program name.
    ///  2. The record name must not contain the keyword "aleo".
    ///  3. Record names must not be prefixes of other record names.
    ///  4. Record entry names must not contain the keyword "aleo".
    pub fn check_program_naming_structure(&self) -> Result<()> {
        // 1. Check if the program ID contains the "aleo" substring
        let program_id = self.id().name().to_string();
        if program_id.contains("aleo") {
            bail!("Program ID '{program_id}' can't contain the reserved keyword 'aleo'.");
        }

        // Fetch the record names in a sorted BTreeSet.
        let record_names: BTreeSet<String> = self.records.keys().map(|name| name.to_string()).collect();

        // 2. Check if any record name contains the "aleo" substring.
        for record_name in &record_names {
            if record_name.contains("aleo") {
                bail!("Record name '{record_name}' can't contain the reserved keyword 'aleo'.");
            }
        }

        // 3. Check if any of the record names are a prefix of another.
        let mut record_names_iter = record_names.iter();
        let mut previous_record_name = record_names_iter.next();
        for record_name in record_names_iter {
            if let Some(previous) = previous_record_name
                && record_name.starts_with(previous)
            {
                bail!("Record name '{previous}' can't be a prefix of record name '{record_name}'.");
            }
            previous_record_name = Some(record_name);
        }

        // 4. Check if any record entry names contain the "aleo" substring.
        for record_entry_name in self.records.values().flat_map(|record_type| record_type.entries().keys()) {
            if record_entry_name.to_string().contains("aleo") {
                bail!("Record entry name '{record_entry_name}' can't contain the reserved keyword 'aleo'.");
            }
        }

        Ok(())
    }

    /// Checks that the program does not make external calls to `credits.aleo/upgrade`.
    pub fn check_external_calls_to_credits_upgrade(&self) -> Result<()> {
        // Check if the program makes external calls to `credits.aleo/upgrade`.
        cfg_iter!(self.functions()).flat_map(|(_, function)| function.instructions()).try_for_each(|instruction| {
            if let Some(CallOperator::Locator(locator)) = instruction.call_operator() {
                // Check if the locator is restricted.
                if locator.to_string() == "credits.aleo/upgrade" {
                    bail!("External call to restricted locator '{locator}'")
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Returns `true` if a program contains any V9 syntax.
    /// This includes `constructor`, `Operand::Edition`, `Operand::Checksum`, and `Operand::ProgramOwner`.
    /// This is enforced to be `false` for programs before `ConsensusVersion::V9`.
    #[inline]
    pub fn contains_v9_syntax(&self) -> bool {
        // Check if the program contains a constructor.
        if self.contains_constructor() {
            return true;
        }
        // Check each instruction and output in each function's finalize scope for the use of
        // `Operand::Checksum`, `Operand::Edition` or `Operand::ProgramOwner`.
        for function in self.functions().values() {
            // Check the finalize scope if it exists.
            if let Some(finalize_logic) = function.finalize_logic() {
                // Check the command operands.
                for command in finalize_logic.commands() {
                    for operand in command.operands() {
                        if matches!(operand, Operand::Checksum(_) | Operand::Edition(_) | Operand::ProgramOwner(_)) {
                            return true;
                        }
                    }
                }
            }
        }
        // Return `false` since no V9 syntax was found.
        false
    }

    /// Returns whether this program explicitly refers to an external struct, like `other_program.aleo/StructType`?
    ///
    /// This function exists to check if programs to be deployed use external structs so they can be gated
    /// by consensus version.
    pub fn contains_external_struct(&self) -> bool {
        self.mappings.values().any(|mapping| mapping.contains_external_struct())
            || self
                .structs
                .values()
                .flat_map(|struct_| struct_.members().values())
                .any(|plaintext_type| plaintext_type.contains_external_struct())
            || self
                .records
                .values()
                .flat_map(|record| record.entries().values())
                .any(|entry| entry.plaintext_type().contains_external_struct())
            || self.closures.values().any(|closure| closure.contains_external_struct())
            || self.functions.values().any(|function| function.contains_external_struct())
            || self.constructor.iter().any(|constructor| constructor.contains_external_struct())
            || self.views.values().any(|view| view.contains_external_struct())
    }

    /// Returns `true` if this program violates pre-V13 rules for external records
    /// or futures by containing registers with non-local struct types across program boundaries.
    ///
    /// Notes:
    /// 1. We only need to check functions because closures and constructors cannot reference
    ///    external records or futures.
    /// 2. We need to check function inputs.
    /// 3. No need to check instructions other than `Call`. The only other instruction that can
    ///    refer to a record is a `cast` but we cannot cast to external records anyways.
    ///4.  No need to check function outputs, because they have already been checked in either the
    ///    inputs or call instruction.
    pub fn violates_pre_v13_external_record_and_future_rules<F0, F1, F2, F3>(
        &self,
        get_external_record: &F0,
        get_external_function: &F1,
        get_external_future: &F2,
        is_local_struct: &F3,
    ) -> bool
    where
        F0: Fn(&Locator<N>) -> Result<RecordType<N>>,
        F1: Fn(&Locator<N>) -> Result<FunctionCore<N>>,
        F2: Fn(&Locator<N>) -> Result<FinalizeCore<N>>,
        F3: Fn(&Identifier<N>) -> bool,
    {
        // Helper: does a plaintext type (possibly nested in arrays) reference a struct not defined locally?
        fn plaintext_uses_nonlocal_struct<N: Network>(
            ty: &PlaintextType<N>,
            is_local_struct: &impl Fn(&Identifier<N>) -> bool,
        ) -> bool {
            match ty {
                PlaintextType::Struct(name) => !is_local_struct(name),
                PlaintextType::Array(array_type) => {
                    plaintext_uses_nonlocal_struct(array_type.base_element_type(), is_local_struct)
                }
                _ => false,
            }
        }

        // Helper: does a record contain any struct not defined locally?
        let record_uses_nonlocal_struct = |record: &RecordType<N>| {
            record.entries().iter().any(|(_, member)| match member {
                EntryType::Constant(ty) | EntryType::Private(ty) | EntryType::Public(ty) => {
                    plaintext_uses_nonlocal_struct(ty, is_local_struct)
                }
            })
        };

        for function in self.functions.values() {
            // Scan function inputs for external record types.
            for input in function.inputs() {
                let ValueType::ExternalRecord(locator) = input.value_type() else {
                    continue;
                };
                let Ok(record) = get_external_record(locator) else {
                    continue;
                };
                if record_uses_nonlocal_struct(&record) {
                    return true;
                }
            }

            // Scan instructions for calls to external programs.
            for instruction in function.instructions() {
                let Instruction::Call(call) = instruction else { continue };
                let CallOperator::Locator(locator) = call.operator() else { continue };
                let Ok(external_function) = get_external_function(locator) else {
                    continue;
                };

                // Check if the outputs of the external function reference a struct that is not
                // locally available.
                for output in external_function.outputs() {
                    match output.value_type() {
                        ValueType::Record(identifier) => {
                            let locator = Locator::new(*locator.program_id(), *identifier);
                            let Ok(record) = get_external_record(&locator) else {
                                continue;
                            };
                            if record_uses_nonlocal_struct(&record) {
                                return true;
                            }
                        }

                        ValueType::Future(loc) => {
                            let Ok(future) = get_external_future(loc) else {
                                continue;
                            };
                            for input in future.input_types() {
                                let FinalizeType::Plaintext(ty) = input else {
                                    continue;
                                };

                                // We intentionally ignore `FinalizeType::Future(_)` here. Any such future
                                // originates from another program whose deployment would already have been
                                // validated under the same pre-V13 rules. At this point, only plaintext inputs
                                // can introduce new non-local struct violations.

                                if plaintext_uses_nonlocal_struct(&ty, is_local_struct) {
                                    return true;
                                }
                            }
                        }

                        _ => {}
                    }
                }
            }
        }

        false
    }

    /// Returns `true` if the program contains an array type with a size that exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        self.mappings.values().any(|mapping| mapping.exceeds_max_array_size(max_array_size))
            || self.structs.values().any(|struct_type| struct_type.exceeds_max_array_size(max_array_size))
            || self.records.values().any(|record_type| record_type.exceeds_max_array_size(max_array_size))
            || self.closures.values().any(|closure| closure.exceeds_max_array_size(max_array_size))
            || self.functions.values().any(|function| function.exceeds_max_array_size(max_array_size))
            || self.constructor.iter().any(|constructor| constructor.exceeds_max_array_size(max_array_size))
            || self.views.values().any(|view| view.exceeds_max_array_size(max_array_size))
    }

    /// Returns `true` if a program contains any V11 syntax.
    /// This includes:
    /// 1. `.raw` hash or signature verification variants
    /// 2. `ecdsa.verify.*` opcodes
    #[inline]
    pub fn contains_v11_syntax(&self) -> bool {
        // Helper to check if any of the opcodes:
        // - start with `ecdsa.verify`, `serialize`, or `deserialize`
        // - end with `.raw` or `.native`
        let has_op = |opcode: &str| {
            opcode.starts_with("ecdsa.verify")
                || opcode.starts_with("serialize")
                || opcode.starts_with("deserialize")
                || opcode.ends_with(".raw")
                || opcode.ends_with(".native")
        };

        // Determine if any function instructions contain the new syntax.
        let function_contains = cfg_iter!(self.functions())
            .flat_map(|(_, function)| function.instructions())
            .any(|instruction| has_op(*instruction.opcode()));

        // Determine if any closure instructions contain the new syntax.
        let closure_contains = cfg_iter!(self.closures())
            .flat_map(|(_, closure)| closure.instructions())
            .any(|instruction| has_op(*instruction.opcode()));

        // Determine if any finalize commands or constructor commands contain the new syntax.
        let command_contains = cfg_iter!(self.functions())
            .flat_map(|(_, function)| function.finalize_logic().map(|finalize| finalize.commands()))
            .flatten()
            .chain(cfg_iter!(self.constructor).flat_map(|constructor| constructor.commands()))
            .any(|command| matches!(command, Command::Instruction(instruction) if has_op(*instruction.opcode())));

        function_contains || closure_contains || command_contains
    }

    /// Returns `true` if a program contains any V12 syntax.
    /// This includes `Operand::BlockTimestamp`.
    /// This is enforced to be `false` for programs before `ConsensusVersion::V12`.
    #[inline]
    pub fn contains_v12_syntax(&self) -> bool {
        // Check each instruction and output in each function's finalize scope for the use of
        // `Operand::BlockTimestamp`.
        cfg_iter!(self.functions()).any(|(_, function)| {
            function.finalize_logic().is_some_and(|finalize_logic| {
                cfg_iter!(finalize_logic.commands()).any(|command| {
                    cfg_iter!(command.operands()).any(|operand| matches!(operand, Operand::BlockTimestamp))
                })
            })
        })
    }

    /// Checks that the program size does not exceed the maximum allowed size for the given block height.
    pub fn check_program_size(&self, block_height: u32) -> Result<()> {
        // Calculate the program size.
        let program_size = self.to_string().len();
        // Determine the maximum allowed program size for the current consensus version.
        let maximum_allowed_program_size = consensus_config_value!(N, MAX_PROGRAM_SIZE, block_height)
            .ok_or(anyhow!("Failed to fetch maximum program size"))?;

        ensure!(
            program_size <= maximum_allowed_program_size,
            "Program size of {program_size} bytes exceeds the maximum allowed size of {maximum_allowed_program_size} bytes for the current height {block_height} (consensus version {}).",
            N::CONSENSUS_VERSION(block_height)?
        );

        Ok(())
    }

    /// Checks that the program writes size does not exceed the maximum allowed size for the given block height.
    pub fn check_program_writes(&self, block_height: u32) -> Result<()> {
        // Determine the maximum allowed number of writes for the current consensus version.
        let max_num_writes = consensus_config_value!(N, MAX_WRITES, block_height)
            .ok_or(anyhow!("Failed to fetch maximum number of writes"))?;

        // Check if the constructor exceeds the maximum number of writes.
        if self.constructor().is_some_and(|constructor| constructor.num_writes() > max_num_writes) {
            bail!(
                "Program constructor exceeds the maximum allowed writes ({max_num_writes}) for the current height {block_height} (consensus version {}).",
                N::CONSENSUS_VERSION(block_height)?
            );
        }

        // Find the first function whose finalize logic exceeds the maximum writes.
        if let Some(name) = cfg_find_map!(self.functions(), |function| {
            function
                .finalize_logic()
                .is_some_and(|finalize| finalize.num_writes() > max_num_writes)
                .then(|| *function.name())
        }) {
            bail!(
                "Program function '{name}' exceeds the maximum allowed writes ({max_num_writes}) for the current height {block_height} (consensus version {}).",
                N::CONSENSUS_VERSION(block_height)?
            );
        }

        Ok(())
    }

    /// Returns `true` if a program contains any V14 syntax.
    /// This includes:
    /// 1. `snark.verify.*` opcodes.
    /// 2. `Operand::AleoGenerator` or `Operand::AleoGeneratorPowers` operands.
    /// 3. `Literal::Identifier` operands.
    /// 4. `call.dynamic` instructions.
    /// 5. `get.record.dynamic` instructions.
    /// 6. `cast` instructions targeting `dynamic.record`.
    /// 7. `dynamic.record` or `dynamic.future` in function input or output types.
    /// 8. `contains.dynamic`, `get.dynamic`, or `get.or_use.dynamic` commands in finalize blocks.
    /// 9. `dynamic.record` or `dynamic.future` in closure input or output types.
    /// 10. `dynamic.future` in finalize block input types.
    /// 11. Identifier types in any type declarations.
    ///
    /// This is enforced to be `false` for programs before `ConsensusVersion::V14`.
    #[inline]
    pub fn contains_v14_syntax(&self) -> Result<bool> {
        /// Returns `true` if the instruction uses V14-only opcodes or operands (infallible checks).
        fn is_v14_instruction<N: Network>(instr: &Instruction<N>) -> bool {
            matches!(instr, Instruction::CallDynamic(_) | Instruction::GetRecordDynamic(_))
                || matches!(instr, Instruction::Cast(cast) if *cast.cast_type() == CastType::DynamicRecord)
                || instr.opcode().starts_with("snark.verify")
                || cfg_iter!(instr.operands()).any(|operand| {
                    matches!(
                        operand,
                        Operand::AleoGenerator
                            | Operand::AleoGeneratorPowers(_)
                            | Operand::Literal(console::program::Literal::Identifier(..))
                    )
                })
        }

        /// Returns `true` if the command uses V14-only syntax (infallible checks).
        fn is_v14_command<N: Network>(cmd: &Command<N>) -> bool {
            matches!(cmd, Command::ContainsDynamic(_) | Command::GetDynamic(_) | Command::GetOrUseDynamic(_))
                || matches!(cmd, Command::Instruction(instr) if is_v14_instruction(instr))
        }

        // Helper to check if a value type is a V14-only dynamic type.
        let is_dynamic_value_type =
            |vt: &ValueType<N>| matches!(vt, ValueType::DynamicRecord | ValueType::DynamicFuture);

        // Helper to check if a register type is a V14-only dynamic type.
        let is_dynamic_register_type =
            |rt: &RegisterType<N>| matches!(rt, RegisterType::DynamicRecord | RegisterType::DynamicFuture);

        // Check functions: instructions, finalize commands, and type declarations.
        for (_, function) in self.functions() {
            if function.instructions().iter().any(is_v14_instruction)
                || function.inputs().iter().any(|input| is_dynamic_value_type(input.value_type()))
                || function.outputs().iter().any(|output| is_dynamic_value_type(output.value_type()))
            {
                return Ok(true);
            }
            if let Some(finalize) = function.finalize_logic()
                && (finalize.inputs().iter().any(|input| matches!(input.finalize_type(), FinalizeType::DynamicFuture))
                    || finalize.commands().iter().any(is_v14_command))
            {
                return Ok(true);
            }
            if function.contains_identifier_type()? {
                return Ok(true);
            }
        }

        // Check closures: instructions and type declarations.
        for (_, closure) in self.closures() {
            if closure.instructions().iter().any(is_v14_instruction)
                || closure.inputs().iter().any(|input| is_dynamic_register_type(input.register_type()))
                || closure.outputs().iter().any(|output| is_dynamic_register_type(output.register_type()))
            {
                return Ok(true);
            }
            if closure.contains_identifier_type()? {
                return Ok(true);
            }
        }

        // Check constructor commands and identifier types.
        if let Some(constructor) = &self.constructor {
            if constructor.commands().iter().any(is_v14_command) {
                return Ok(true);
            }
            if constructor.contains_identifier_type()? {
                return Ok(true);
            }
        }

        // Check remaining type definitions: mappings, structs, records.
        for mapping in self.mappings.values() {
            if mapping.contains_identifier_type()? {
                return Ok(true);
            }
        }
        for struct_type in self.structs.values() {
            if struct_type.contains_identifier_type()? {
                return Ok(true);
            }
        }
        for record_type in self.records.values() {
            if record_type.contains_identifier_type()? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Returns `true` if a program contains any V15 syntax.
    /// This includes:
    /// 1. `commit.*.raw` opcodes (raw commit variants).
    /// 2. `view` blocks (new on-disk component variant 6).
    /// 3. `call` instructions inside `finalize` bodies (pre-V15 finalize forbade `call`).
    ///
    /// This is enforced to be `false` for programs before `ConsensusVersion::V15`.
    #[inline]
    pub fn contains_v15_syntax(&self) -> bool {
        // Helper to check if an opcode is a raw commit variant.
        let has_op = |opcode: &str| opcode.starts_with("commit.") && opcode.ends_with(".raw");

        // Determine if any function instructions contain the new syntax.
        let function_contains = cfg_iter!(self.functions())
            .flat_map(|(_, function)| function.instructions())
            .any(|instruction| has_op(*instruction.opcode()));

        // Determine if any closure instructions contain the new syntax.
        let closure_contains = cfg_iter!(self.closures())
            .flat_map(|(_, closure)| closure.instructions())
            .any(|instruction| has_op(*instruction.opcode()));

        // Determine if any finalize commands or constructor commands contain the new syntax.
        let command_contains = cfg_iter!(self.functions())
            .flat_map(|(_, function)| function.finalize_logic().map(|finalize| finalize.commands()))
            .flatten()
            .chain(cfg_iter!(self.constructor).flat_map(|constructor| constructor.commands()))
            .any(|command| matches!(command, Command::Instruction(instruction) if has_op(*instruction.opcode())));

        // Detect `call` instructions inside finalize bodies. Pre-V15 finalize forbade `call`
        // entirely, so any deployed program with one is necessarily V15+ syntax.
        //
        // Intentionally matches only `Instruction::Call` — `CallDynamic` in a finalize body is
        // rejected at parse time by `Finalize::add_command`, so it can never reach a deployed
        // program. If `call.dynamic` is ever permitted in finalize, this clause must be widened
        // (and `Finalize::add_command`, `cost::cost_per_command`, and the finalize
        // type-checker's `Opcode::Call` arm need re-review at the same time).
        let finalize_has_call = cfg_iter!(self.functions())
            .filter_map(|(_, function)| function.finalize_logic())
            .flat_map(|finalize| finalize.commands())
            .any(|command| matches!(command, Command::Instruction(Instruction::Call(_))));

        function_contains || closure_contains || command_contains || finalize_has_call || !self.views.is_empty()
    }

    /// Returns `true` if a program contains any V16 syntax.
    /// This includes the `Operand::ComponentChecksum` operand.
    /// This is enforced to be `false` for programs before `ConsensusVersion::V16`.
    #[inline]
    pub fn contains_v16_syntax(&self) -> bool {
        // Check each command operand in every finalize, constructor, and view scope for `Operand::ComponentChecksum`.
        let command_contains = cfg_iter!(self.functions())
            .flat_map(|(_, function)| function.finalize_logic().map(|finalize| finalize.commands()))
            .flatten()
            .chain(cfg_iter!(self.constructor).flat_map(|constructor| constructor.commands()))
            .chain(cfg_iter!(self.views).flat_map(|(_, view)| view.commands()))
            .flat_map(|command| command.operands())
            .any(|operand| matches!(operand, Operand::ComponentChecksum(..)));

        // Views additionally have output operands, which are not commands and so are checked separately.
        let view_output_contains = self
            .views
            .values()
            .any(|view| view.outputs().iter().any(|output| matches!(output.operand(), Operand::ComponentChecksum(..))));

        command_contains || view_output_contains
    }

    /// Returns `true` if a program contains any string type.
    /// Before ConsensusVersion::V12, variable-length string sampling when using them as inputs caused deployment synthesis to be inconsistent and abort with probability 63/64.
    /// After ConsensusVersion::V12, string types are disallowed.
    #[inline]
    pub fn contains_string_type(&self) -> bool {
        self.mappings.values().any(|mapping| mapping.contains_string_type())
            || self.structs.values().any(|struct_type| struct_type.contains_string_type())
            || self.records.values().any(|record_type| record_type.contains_string_type())
            || self.closures.values().any(|closure| closure.contains_string_type())
            || self.functions.values().any(|function| function.contains_string_type())
            || self.constructor.iter().any(|constructor| constructor.contains_string_type())
            || self.views.values().any(|view| view.contains_string_type())
    }
}

impl<N: Network> TypeName for ProgramCore<N> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "program"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        network::MainnetV0,
        program::{Locator, ValueType},
    };

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_program_mapping() -> Result<()> {
        // Create a new mapping.
        let mapping = Mapping::<CurrentNetwork>::from_str(
            r"
mapping message:
    key as field.public;
    value as field.public;",
        )?;

        // Initialize a new program.
        let program = Program::<CurrentNetwork>::from_str(&format!("program unknown.aleo; {mapping}"))?;
        // Ensure the mapping was added.
        assert!(program.contains_mapping(&Identifier::from_str("message")?));
        // Ensure the retrieved mapping matches.
        assert_eq!(mapping.to_string(), program.get_mapping(&Identifier::from_str("message")?)?.to_string());

        Ok(())
    }

    #[test]
    fn test_program_struct() -> Result<()> {
        // Create a new struct.
        let struct_ = StructType::<CurrentNetwork>::from_str(
            r"
struct message:
    first as field;
    second as field;",
        )?;

        // Initialize a new program.
        let program = Program::<CurrentNetwork>::from_str(&format!("program unknown.aleo; {struct_}"))?;
        // Ensure the struct was added.
        assert!(program.contains_struct(&Identifier::from_str("message")?));
        // Ensure the retrieved struct matches.
        assert_eq!(&struct_, program.get_struct(&Identifier::from_str("message")?)?);

        Ok(())
    }

    #[test]
    fn test_program_record() -> Result<()> {
        // Create a new record.
        let record = RecordType::<CurrentNetwork>::from_str(
            r"
record foo:
    owner as address.private;
    first as field.private;
    second as field.public;",
        )?;

        // Initialize a new program.
        let program = Program::<CurrentNetwork>::from_str(&format!("program unknown.aleo; {record}"))?;
        // Ensure the record was added.
        assert!(program.contains_record(&Identifier::from_str("foo")?));
        // Ensure the retrieved record matches.
        assert_eq!(&record, program.get_record(&Identifier::from_str("foo")?)?);

        Ok(())
    }

    #[test]
    fn test_program_function() -> Result<()> {
        // Create a new function.
        let function = Function::<CurrentNetwork>::from_str(
            r"
function compute:
    input r0 as field.public;
    input r1 as field.private;
    add r0 r1 into r2;
    output r2 as field.private;",
        )?;

        // Initialize a new program.
        let program = Program::<CurrentNetwork>::from_str(&format!("program unknown.aleo; {function}"))?;
        // Ensure the function was added.
        assert!(program.contains_function(&Identifier::from_str("compute")?));
        // Ensure the retrieved function matches.
        assert_eq!(function, program.get_function(&Identifier::from_str("compute")?)?);

        Ok(())
    }

    #[test]
    fn test_program_import() -> Result<()> {
        // Initialize a new program.
        let program = Program::<CurrentNetwork>::from_str(
            r"
import eth.aleo;
import usdc.aleo;

program swap.aleo;

// The `swap` function transfers ownership of the record
// for token A to the record owner of token B, and vice-versa.
function swap:
    // Input the record for token A.
    input r0 as eth.aleo/eth.record;
    // Input the record for token B.
    input r1 as usdc.aleo/usdc.record;

    // Send the record for token A to the owner of token B.
    call eth.aleo/transfer r0 r1.owner r0.amount into r2 r3;

    // Send the record for token B to the owner of token A.
    call usdc.aleo/transfer r1 r0.owner r1.amount into r4 r5;

    // Output the new record for token A.
    output r2 as eth.aleo/eth.record;
    // Output the new record for token B.
    output r4 as usdc.aleo/usdc.record;
    ",
        )
        .unwrap();

        // Ensure the program imports exist.
        assert!(program.contains_import(&ProgramID::from_str("eth.aleo")?));
        assert!(program.contains_import(&ProgramID::from_str("usdc.aleo")?));

        // Retrieve the 'swap' function.
        let function = program.get_function(&Identifier::from_str("swap")?)?;

        // Ensure there are two inputs.
        assert_eq!(function.inputs().len(), 2);
        assert_eq!(function.input_types().len(), 2);

        // Declare the expected input types.
        let expected_input_type_1 = ValueType::ExternalRecord(Locator::from_str("eth.aleo/eth")?);
        let expected_input_type_2 = ValueType::ExternalRecord(Locator::from_str("usdc.aleo/usdc")?);

        // Ensure the inputs are external records.
        assert_eq!(function.input_types()[0], expected_input_type_1);
        assert_eq!(function.input_types()[1], expected_input_type_2);

        // Ensure the input variants are correct.
        assert_eq!(function.input_types()[0].variant(), expected_input_type_1.variant());
        assert_eq!(function.input_types()[1].variant(), expected_input_type_2.variant());

        // Ensure there are two instructions.
        assert_eq!(function.instructions().len(), 2);

        // Ensure the instructions are calls.
        assert_eq!(function.instructions()[0].opcode(), Opcode::Call("call"));
        assert_eq!(function.instructions()[1].opcode(), Opcode::Call("call"));

        // Ensure there are two outputs.
        assert_eq!(function.outputs().len(), 2);
        assert_eq!(function.output_types().len(), 2);

        // Declare the expected output types.
        let expected_output_type_1 = ValueType::ExternalRecord(Locator::from_str("eth.aleo/eth")?);
        let expected_output_type_2 = ValueType::ExternalRecord(Locator::from_str("usdc.aleo/usdc")?);

        // Ensure the outputs are external records.
        assert_eq!(function.output_types()[0], expected_output_type_1);
        assert_eq!(function.output_types()[1], expected_output_type_2);

        // Ensure the output variants are correct.
        assert_eq!(function.output_types()[0].variant(), expected_output_type_1.variant());
        assert_eq!(function.output_types()[1].variant(), expected_output_type_2.variant());

        Ok(())
    }

    #[test]
    fn test_program_with_constructor() {
        // Initialize a new program.
        let program_string = r"import credits.aleo;

program good_constructor.aleo;

constructor:
    assert.eq edition 0u16;
    assert.eq credits.aleo/edition 0u16;
    assert.neq checksum 0field;
    assert.eq credits.aleo/checksum 6192738754253668739186185034243585975029374333074931926190215457304721124008field;
    set 1u8 into data[0u8];

mapping data:
    key as u8.public;
    value as u8.public;

function dummy:

function check:
    async check into r0;
    output r0 as good_constructor.aleo/check.future;

finalize check:
    get data[0u8] into r0;
    assert.eq r0 1u8;
";
        let program = Program::<CurrentNetwork>::from_str(program_string).unwrap();

        // Check that the string and bytes (de)serialization works.
        let serialized = program.to_string();
        let deserialized = Program::<CurrentNetwork>::from_str(&serialized).unwrap();
        assert_eq!(program, deserialized);

        let serialized = program.to_bytes_le().unwrap();
        let deserialized = Program::<CurrentNetwork>::from_bytes_le(&serialized).unwrap();
        assert_eq!(program, deserialized);

        // Check that the display works.
        let display = format!("{program}");
        assert_eq!(display, program_string);

        // Ensure the program contains a constructor.
        assert!(program.contains_constructor());
        assert_eq!(program.constructor().unwrap().commands().len(), 5);
    }

    #[test]
    fn test_program_equality_and_checksum() {
        fn run_test(program1: &str, program2: &str, expected_equal: bool) {
            println!("Comparing programs:\n{program1}\n{program2}");
            let program1 = Program::<CurrentNetwork>::from_str(program1).unwrap();
            let program2 = Program::<CurrentNetwork>::from_str(program2).unwrap();
            assert_eq!(program1 == program2, expected_equal);
            assert_eq!(program1.to_checksum() == program2.to_checksum(), expected_equal);
        }

        // Test two identical programs, with different whitespace.
        run_test(r"program test.aleo; function dummy:    ", r"program  test.aleo;     function dummy:   ", true);

        // Test two programs, one with a different function name.
        run_test(r"program test.aleo; function dummy:    ", r"program test.aleo; function bummy:   ", false);

        // Test two programs, one with a constructor and one without.
        run_test(
            r"program test.aleo; function dummy:    ",
            r"program test.aleo; constructor: assert.eq true true; function dummy: ",
            false,
        );

        // Test two programs, both with a struct and function, but in different order.
        run_test(
            r"program test.aleo; struct foo: data as u8; function dummy:",
            r"program test.aleo; function dummy: struct foo: data as u8;",
            false,
        );
    }

    #[test]
    fn test_contains_v14_syntax() -> Result<()> {
        // A baseline program with no V14 syntax.
        let no_v14 = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as u64.public;
    output r0 as u64.public;",
        )?;
        assert!(!no_v14.contains_v14_syntax()?);

        // A program with `dynamic.record` as a function input type.
        let dynamic_record_input = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as dynamic.record;",
        )?;
        assert!(dynamic_record_input.contains_v14_syntax()?);

        // A program with `dynamic.future` as a function output type.
        let dynamic_future_output = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    output r0 as dynamic.future;",
        )?;
        assert!(dynamic_future_output.contains_v14_syntax()?);

        // A program with a `call.dynamic` instruction.
        let call_dynamic = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    call.dynamic r0 r1 r2 into r3 (as u64.public);
    output r3 as u64.public;",
        )?;
        assert!(call_dynamic.contains_v14_syntax()?);

        // A program with a `get.record.dynamic` instruction.
        let get_record_dynamic = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as dynamic.record;
    get.record.dynamic r0.amount into r1 as field;
    output r1 as field.public;",
        )?;
        assert!(get_record_dynamic.contains_v14_syntax()?);

        // A program with a `cast ... as dynamic.record` instruction.
        let cast_dynamic_record = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
record token:
    owner as address.private;
    amount as u64.private;
function foo:
    input r0 as token.record;
    cast r0 into r1 as dynamic.record;
    output r0.owner as address.private;",
        )?;
        assert!(cast_dynamic_record.contains_v14_syntax()?);

        // A program with `contains.dynamic` in a finalize block.
        let contains_dynamic = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function bar:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as field.public;
    async bar r0 r1 r2 r3 into r4;
    output r4 as test.aleo/bar.future;
finalize bar:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as field.public;
    contains.dynamic r0 r1 r2[r3] into r4;",
        )?;
        assert!(contains_dynamic.contains_v14_syntax()?);

        // A program with `get.dynamic` in a finalize block.
        let get_dynamic = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function bar:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as field.public;
    async bar r0 r1 r2 r3 into r4;
    output r4 as test.aleo/bar.future;
finalize bar:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as field.public;
    get.dynamic r0 r1 r2[r3] into r4 as field;",
        )?;
        assert!(get_dynamic.contains_v14_syntax()?);

        // A program with `dynamic.future` as a finalize input type.
        let dynamic_future_finalize_input = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as field.public;
    async foo r0 into r1;
    output r1 as test.aleo/foo.future;
finalize foo:
    input r0 as dynamic.future;
    await r0;",
        )?;
        assert!(dynamic_future_finalize_input.contains_v14_syntax()?);

        // A program with `dynamic.record` as a closure input type.
        let closure_dynamic_input = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
closure bar:
    input r0 as dynamic.record;
    input r1 as field;
    add r1 r1 into r2;",
        )?;
        assert!(closure_dynamic_input.contains_v14_syntax()?);

        // A program with `dynamic.record` as a closure output type.
        let closure_dynamic_output = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
closure bar:
    input r0 as field;
    add r0 r0 into r1;
    output r1 as dynamic.record;",
        )?;
        assert!(closure_dynamic_output.contains_v14_syntax()?);

        // A program with `get.or_use.dynamic` in a finalize block.
        let get_or_use_dynamic = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function bar:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as field.public;
    input r4 as u64.public;
    async bar r0 r1 r2 r3 r4 into r5;
    output r5 as test.aleo/bar.future;
finalize bar:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as field.public;
    input r4 as u64.public;
    get.or_use.dynamic r0 r1 r2[r3] r4 into r5 as u64;",
        )?;
        assert!(get_or_use_dynamic.contains_v14_syntax()?);

        // A program with `snark.verify` in a finalize block.
        let snark_verify = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as [u8; 8u32].public;
    input r1 as [field; 1u32].public;
    input r2 as [u8; 8u32].public;
    async foo r0 r1 r2 into r3;
    output r3 as test.aleo/foo.future;
finalize foo:
    input r0 as [u8; 8u32].public;
    input r1 as [field; 1u32].public;
    input r2 as [u8; 8u32].public;
    snark.verify r0 1u8 r1 r2 into r3;",
        )?;
        assert!(snark_verify.contains_v14_syntax()?);

        // A program with `snark.verify.batch` in a finalize block.
        let snark_verify_batch = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as [[u8; 8u32]; 1u32].public;
    input r1 as [[[field; 1u32]; 1u32]; 1u32].public;
    input r2 as [u8; 8u32].public;
    async foo r0 r1 r2 into r3;
    output r3 as test.aleo/foo.future;
finalize foo:
    input r0 as [[u8; 8u32]; 1u32].public;
    input r1 as [[[field; 1u32]; 1u32]; 1u32].public;
    input r2 as [u8; 8u32].public;
    snark.verify.batch r0 1u8 r1 r2 into r3;",
        )?;
        assert!(snark_verify_batch.contains_v14_syntax()?);

        // A program with `aleo::GENERATOR` as an operand.
        let aleo_generator = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as scalar.public;
    mul aleo::GENERATOR r0 into r1;
    output r1 as group.public;",
        )?;
        assert!(aleo_generator.contains_v14_syntax()?);

        // A program with `aleo::GENERATOR_POWERS` as an operand.
        let aleo_generator_powers = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function foo:
    input r0 as scalar.public;
    mul aleo::GENERATOR_POWERS[0u32] r0 into r1;
    output r1 as group.public;",
        )?;
        assert!(aleo_generator_powers.contains_v14_syntax()?);

        // A program with `dynamic.future` as a closure output type.
        let closure_dynamic_future_output = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
closure bar:
    input r0 as field;
    add r0 r0 into r1;
    output r1 as dynamic.future;",
        )?;
        assert!(closure_dynamic_future_output.contains_v14_syntax()?);

        // A program with a V14 opcode (`aleo::GENERATOR`) in a constructor block.
        let constructor_v14 = Program::<CurrentNetwork>::from_str(
            r"program test.aleo;
function dummy:
    input r0 as field.public;
    output r0 as field.public;
constructor:
    assert.eq aleo::GENERATOR aleo::GENERATOR;",
        )?;
        assert!(constructor_v14.contains_v14_syntax()?);

        Ok(())
    }
}
