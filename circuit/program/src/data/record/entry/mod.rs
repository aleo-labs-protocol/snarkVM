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

mod equal;
mod find;
mod num_randomizers;
mod to_bits;
mod to_fields;

use crate::{Access, Ciphertext, Plaintext, Visibility};
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Boolean, Field, environment::prelude::*};

/// An entry stored in program data.
#[derive(Clone)]
pub enum Entry<A: Aleo, Private: Visibility<A>> {
    /// A constant entry.
    Constant(Plaintext<A>),
    /// A publicly-visible entry.
    Public(Plaintext<A>),
    /// A private entry encrypted under the address of the record owner.
    Private(Private),
}

impl<A: Aleo> Inject for Entry<A, Plaintext<A>> {
    type Primitive = console::Entry<A::Network, console::Plaintext<A::Network>>;

    /// Initializes a new plaintext entry from a primitive.
    fn new(mode: Mode, plaintext: Self::Primitive) -> Self {
        match plaintext {
            Self::Primitive::Constant(plaintext) => Self::Constant(Plaintext::new(mode, plaintext)),
            Self::Primitive::Public(plaintext) => Self::Public(Plaintext::new(mode, plaintext)),
            Self::Primitive::Private(plaintext) => Self::Private(Plaintext::new(mode, plaintext)),
        }
    }
}

impl<A: Aleo> Inject for Entry<A, Ciphertext<A>> {
    type Primitive = console::Entry<A::Network, console::Ciphertext<A::Network>>;

    /// Initializes a new ciphertext entry from a primitive.
    fn new(mode: Mode, plaintext: Self::Primitive) -> Self {
        match plaintext {
            Self::Primitive::Constant(plaintext) => Self::Constant(Plaintext::new(mode, plaintext)),
            Self::Primitive::Public(plaintext) => Self::Public(Plaintext::new(mode, plaintext)),
            Self::Primitive::Private(ciphertext) => Self::Private(Ciphertext::new(mode, ciphertext)),
        }
    }
}

impl<A: Aleo> Eject for Entry<A, Plaintext<A>> {
    type Primitive = console::Entry<A::Network, console::Plaintext<A::Network>>;

    /// Ejects the mode of the entry.
    fn eject_mode(&self) -> Mode {
        match self {
            Entry::Constant(_) => Mode::Constant,
            Entry::Public(_) => Mode::Public,
            Entry::Private(_) => Mode::Private,
        }
    }

    /// Ejects the entry.
    fn eject_value(&self) -> Self::Primitive {
        match self {
            Entry::Constant(plaintext) => Self::Primitive::Constant(plaintext.eject_value()),
            Entry::Public(plaintext) => Self::Primitive::Public(plaintext.eject_value()),
            Entry::Private(plaintext) => Self::Primitive::Private(plaintext.eject_value()),
        }
    }
}

impl<A: Aleo> Eject for Entry<A, Ciphertext<A>> {
    type Primitive = console::Entry<A::Network, console::Ciphertext<A::Network>>;

    /// Ejects the mode of the entry.
    fn eject_mode(&self) -> Mode {
        match self {
            Entry::Constant(_) => Mode::Constant,
            Entry::Public(_) => Mode::Public,
            Entry::Private(_) => Mode::Private,
        }
    }

    /// Ejects the entry.
    fn eject_value(&self) -> Self::Primitive {
        match self {
            Entry::Constant(plaintext) => Self::Primitive::Constant(plaintext.eject_value()),
            Entry::Public(plaintext) => Self::Primitive::Public(plaintext.eject_value()),
            Entry::Private(ciphertext) => Self::Primitive::Private(ciphertext.eject_value()),
        }
    }
}
