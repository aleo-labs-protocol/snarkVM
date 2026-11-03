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

#[cfg(test)]
use snarkvm_circuit_types::environment::assert_scope;

mod entry;
pub use entry::Entry;

mod helpers;
pub use helpers::Owner;

mod encrypt;
mod equal;
mod find;
mod num_randomizers;
mod serial_number;
mod tag;
mod to_bits;
mod to_commitment;
mod to_fields;

use crate::{Access, Ciphertext, Identifier, Literal, Plaintext, ProgramID, Visibility};
use snarkvm_circuit_account::PrivateKey;
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Boolean, Field, Group, Scalar, U8, U32, environment::prelude::*, prelude::ToFields};

#[derive(Clone)]
pub struct Record<A: Aleo, Private: Visibility<A>> {
    /// The owner of the program record.
    owner: Owner<A, Private>,
    /// The program data.
    data: IndexMap<Identifier<A>, Entry<A, Private>>,
    /// The nonce of the program record.
    nonce: Group<A>,
    /// The version of the program record.
    ///   - Version 0 uses a BHP hash to derive the record commitment.
    ///   - Version 1 uses a BHP commitment to derive the record commitment.
    version: U8<A>,
}

impl<A: Aleo> Inject for Record<A, Plaintext<A>> {
    type Primitive = console::Record<A::Network, console::Plaintext<A::Network>>;

    /// Initializes a plaintext record from a primitive.
    fn new(_: Mode, record: Self::Primitive) -> Self {
        Self {
            owner: Owner::new(Mode::Private, record.owner().clone()),
            data: record
                .data()
                .clone()
                .into_iter()
                .map(|(identifier, entry)| (Identifier::constant(identifier), Inject::new(Mode::Private, entry)))
                .collect(),
            nonce: Group::new(Mode::Private, *record.nonce()),
            version: U8::new(Mode::Private, *record.version()),
        }
    }
}

impl<A: Aleo> Inject for Record<A, Ciphertext<A>> {
    type Primitive = console::Record<A::Network, console::Ciphertext<A::Network>>;

    /// Initializes a ciphertext record from a primitive.
    fn new(_: Mode, record: Self::Primitive) -> Self {
        Self {
            owner: Owner::new(Mode::Private, record.owner().clone()),
            data: record
                .data()
                .clone()
                .into_iter()
                .map(|(identifier, entry)| (Identifier::constant(identifier), Inject::new(Mode::Private, entry)))
                .collect(),
            nonce: Group::new(Mode::Private, *record.nonce()),
            version: U8::new(Mode::Private, *record.version()),
        }
    }
}

impl<A: Aleo, Private: Visibility<A>> Record<A, Private> {
    /// Initializes a new record plaintext.
    pub fn from_plaintext(
        owner: Owner<A, Plaintext<A>>,
        data: IndexMap<Identifier<A>, Entry<A, Plaintext<A>>>,
        nonce: Group<A>,
        version: U8<A>,
    ) -> Result<Record<A, Plaintext<A>>> {
        // Ensure the members has no duplicate names.
        ensure!(!has_duplicates(data.iter().map(|(name, ..)| name)), "A duplicate entry name was found in a record");
        // Ensure the number of entries is within the maximum limit.
        ensure!(
            data.len() <= <A::Network as console::Network>::MAX_DATA_ENTRIES,
            "Found a record that exceeds size ({})",
            data.len()
        );
        // Return the record.
        Ok(Record { owner, data, nonce, version })
    }

    /// Initializes a new record ciphertext.
    pub fn from_ciphertext(
        owner: Owner<A, Ciphertext<A>>,
        data: IndexMap<Identifier<A>, Entry<A, Ciphertext<A>>>,
        nonce: Group<A>,
        version: U8<A>,
    ) -> Result<Record<A, Ciphertext<A>>> {
        // Ensure the members has no duplicate names.
        ensure!(!has_duplicates(data.iter().map(|(name, ..)| name)), "A duplicate entry name was found in a record");
        // Ensure the number of entries is within the maximum limit.
        ensure!(
            data.len() <= <A::Network as console::Network>::MAX_DATA_ENTRIES,
            "Found a record that exceeds size ({})",
            data.len()
        );
        // Return the record.
        Ok(Record { owner, data, nonce, version })
    }
}

impl<A: Aleo, Private: Visibility<A>> Record<A, Private> {
    /// Returns the owner of the program record.
    pub const fn owner(&self) -> &Owner<A, Private> {
        &self.owner
    }

    /// Returns the program data.
    pub const fn data(&self) -> &IndexMap<Identifier<A>, Entry<A, Private>> {
        &self.data
    }

    /// Returns the nonce of the program record.
    pub const fn nonce(&self) -> &Group<A> {
        &self.nonce
    }

    /// Returns the version of the program record.
    pub const fn version(&self) -> &U8<A> {
        &self.version
    }

    /// Returns `true` if the program record is a hiding variant.
    pub fn is_hiding(&self) -> Boolean<A> {
        !self.version.is_zero()
    }
}

impl<A: Aleo> Eject for Record<A, Plaintext<A>> {
    type Primitive = console::Record<A::Network, console::Plaintext<A::Network>>;

    /// Ejects the mode of the record.
    fn eject_mode(&self) -> Mode {
        let owner = match &self.owner {
            Owner::Public(owner) => match owner.eject_mode() == Mode::Public {
                true => Mode::Public,
                false => A::halt("Record::<Plaintext>::eject_mode: 'owner' is not public."),
            },
            Owner::Private(plaintext) => match plaintext.eject_mode() == Mode::Private {
                true => Mode::Private,
                false => A::halt("Record::<Plaintext>::eject_mode: 'owner' is not private."),
            },
        };

        let data = self.data.iter().map(|(_, entry)| entry.eject_mode()).collect::<Vec<_>>().eject_mode();
        let nonce = self.nonce.eject_mode();
        let version = self.version.eject_mode();

        Mode::combine(owner, [data, nonce, version])
    }

    /// Ejects the record.
    fn eject_value(&self) -> Self::Primitive {
        let owner = match &self.owner {
            Owner::Public(owner) => console::Owner::Public(owner.eject_value()),
            Owner::Private(plaintext) => console::Owner::Private(plaintext.eject_value()),
        };

        match Self::Primitive::from_plaintext(
            owner,
            self.data.iter().map(|(identifier, entry)| (identifier, entry).eject_value()).collect::<IndexMap<_, _>>(),
            self.nonce.eject_value(),
            self.version.eject_value(),
        ) {
            Ok(record) => record,
            Err(error) => A::halt(format!("Record::<Plaintext>::eject_value: {error}")),
        }
    }
}

impl<A: Aleo> Eject for Record<A, Ciphertext<A>> {
    type Primitive = console::Record<A::Network, console::Ciphertext<A::Network>>;

    /// Ejects the mode of the record.
    fn eject_mode(&self) -> Mode {
        let owner = match &self.owner {
            Owner::Public(owner) => match owner.eject_mode() == Mode::Public {
                true => Mode::Public,
                false => A::halt("Record::<Ciphertext>::eject_mode: 'owner' is not public."),
            },
            Owner::Private(plaintext) => match plaintext.eject_mode() == Mode::Private {
                true => Mode::Private,
                false => A::halt("Record::<Ciphertext>::eject_mode: 'owner' is not private."),
            },
        };

        let data = self.data.iter().map(|(_, entry)| entry.eject_mode()).collect::<Vec<_>>().eject_mode();
        let nonce = self.nonce.eject_mode();
        let version = self.version.eject_mode();

        Mode::combine(owner, [data, nonce, version])
    }

    /// Ejects the record.
    fn eject_value(&self) -> Self::Primitive {
        let owner = match &self.owner {
            Owner::Public(owner) => console::Owner::Public(owner.eject_value()),
            Owner::Private(plaintext) => console::Owner::Private(plaintext.eject_value()),
        };

        match Self::Primitive::from_ciphertext(
            owner,
            self.data.iter().map(|(identifier, entry)| (identifier, entry).eject_value()).collect::<IndexMap<_, _>>(),
            self.nonce.eject_value(),
            self.version.eject_value(),
        ) {
            Ok(record) => record,
            Err(error) => A::halt(format!("Record::<Ciphertext>::eject_value: {error}")),
        }
    }
}

impl<A: Aleo, Private: Visibility<A>> TypeName for Record<A, Private> {
    fn type_name() -> &'static str {
        "record"
    }
}
