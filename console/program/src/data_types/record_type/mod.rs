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

mod entry_type;
pub use entry_type::EntryType;

mod helpers;
use helpers::PublicOrPrivate;

mod bytes;
mod parse;
mod serialize;
mod size_in_bits;

use crate::Identifier;
use snarkvm_console_network::prelude::*;

use indexmap::IndexMap;

/// The declared layout for program data.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordType<N: Network> {
    /// The name of the record type.
    name: Identifier<N>,
    /// The visibility for the owner of the program record.
    owner: PublicOrPrivate,
    /// The name and value type for the entries in data.
    entries: IndexMap<Identifier<N>, EntryType<N>>,
}

impl<N: Network> RecordType<N> {
    /// Returns the name of the record type.
    pub const fn name(&self) -> &Identifier<N> {
        &self.name
    }

    /// Returns the visibility for the owner of the program record.
    pub const fn owner(&self) -> PublicOrPrivate {
        self.owner
    }

    /// Returns the entries of the record type.
    pub const fn entries(&self) -> &IndexMap<Identifier<N>, EntryType<N>> {
        &self.entries
    }

    /// Returns `true` if the record contains a string type.
    pub fn contains_string_type(&self) -> bool {
        self.entries.values().any(|entry_type| entry_type.plaintext_type().contains_string_type())
    }

    /// Returns `true` if the record contains an identifier type.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        for entry_type in self.entries.values() {
            if entry_type.plaintext_type().contains_identifier_type()? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns `true` if the record contains an array type with a size that exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        self.entries.values().any(|entry_type| entry_type.plaintext_type().exceeds_max_array_size(max_array_size))
    }
}

impl<N: Network> TypeName for RecordType<N> {
    /// Returns the type name.
    fn type_name() -> &'static str {
        "record"
    }
}
