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

use crate::{Ciphertext, Entry, Literal, Plaintext, Visibility};
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Address, Boolean, Field, environment::prelude::*};

/// A value stored in program data.
#[derive(Clone)]
pub enum Owner<A: Aleo, Private: Visibility<A>> {
    /// A publicly-visible value.
    Public(Address<A>),
    /// A private value is encrypted under the account owner's address.
    Private(Private),
}

impl<A: Aleo> Inject for Owner<A, Plaintext<A>> {
    type Primitive = console::Owner<A::Network, console::Plaintext<A::Network>>;

    /// Initializes plaintext owner from a primitive.
    fn new(_: Mode, owner: Self::Primitive) -> Self {
        match owner {
            console::Owner::Public(owner) => Self::Public(Address::new(Mode::Private, owner)),
            console::Owner::Private(console::Plaintext::Literal(console::Literal::Address(owner), ..)) => {
                Self::Private(Plaintext::Literal(
                    Literal::Address(Address::new(Mode::Private, owner)),
                    Default::default(),
                ))
            }
            _ => A::halt("Owner::<Plaintext>::new: Invalid primitive type for owner"),
        }
    }
}

impl<A: Aleo> Inject for Owner<A, Ciphertext<A>> {
    type Primitive = console::Owner<A::Network, console::Ciphertext<A::Network>>;

    /// Initializes ciphertext owner from a primitive.
    fn new(_: Mode, owner: Self::Primitive) -> Self {
        match owner {
            console::Owner::Public(owner) => Self::Public(Address::new(Mode::Private, owner)),
            console::Owner::Private(ciphertext) => Self::Private(Ciphertext::new(Mode::Private, ciphertext)),
        }
    }
}

impl<A: Aleo> Deref for Owner<A, Plaintext<A>> {
    type Target = Address<A>;

    /// Returns the address of the owner.
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Public(public) => public,
            Self::Private(Plaintext::Literal(Literal::Address(address), ..)) => address,
            _ => A::halt("Internal error: plaintext deref corrupted in record owner"),
        }
    }
}

impl<A: Aleo, Private: Visibility<A>> Owner<A, Private> {
    /// Returns `true` if `self` is public.
    pub fn is_public(&self) -> Boolean<A> {
        Boolean::constant(matches!(self, Self::Public(..)))
    }

    /// Returns `true` if `self` is private.
    pub fn is_private(&self) -> Boolean<A> {
        Boolean::constant(matches!(self, Self::Private(..)))
    }
}

impl<A: Aleo> Owner<A, Plaintext<A>> {
    /// Returns the owner as an `Entry`.
    pub fn to_entry(&self) -> Entry<A, Plaintext<A>> {
        match self {
            Self::Public(owner) => Entry::Public(Plaintext::from(Literal::Address(owner.clone()))),
            Self::Private(plaintext, ..) => Entry::Private(plaintext.clone()),
        }
    }
}

impl<A: Aleo, Private: Visibility<A>> Equal<Self> for Owner<A, Private> {
    type Output = Boolean<A>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Public(a), Self::Public(b)) => a.is_equal(b),
            (Self::Private(a), Self::Private(b)) => a.is_equal(b),
            (Self::Public(_), _) | (Self::Private(_), _) => Boolean::constant(false),
        }
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Public(a), Self::Public(b)) => a.is_not_equal(b),
            (Self::Private(a), Self::Private(b)) => a.is_not_equal(b),
            (Self::Public(_), _) | (Self::Private(_), _) => Boolean::constant(true),
        }
    }
}

impl<A: Aleo> Owner<A, Plaintext<A>> {
    /// Encrypts `self` under the given randomizer.
    pub fn encrypt(&self, randomizer: &[Field<A>]) -> Owner<A, Ciphertext<A>> {
        match self {
            Self::Public(public) => {
                // Ensure there is exactly zero randomizers.
                if !randomizer.is_empty() {
                    A::halt(format!("Expected 0 randomizers, found {}", randomizer.len()))
                }
                // Return the owner.
                Owner::Public(public.clone())
            }
            Self::Private(Plaintext::Literal(Literal::Address(address), ..)) => {
                // Ensure there is exactly one randomizer.
                if randomizer.len() != 1 {
                    A::halt(format!("Expected 1 randomizer, found {}", randomizer.len()))
                }
                // Encrypt the owner.
                let ciphertext = address.to_field() + &randomizer[0];
                // Return the encrypted owner.
                Owner::Private(Ciphertext::from_fields(&[ciphertext]))
            }
            _ => A::halt("Internal error: plaintext encryption corrupted in record owner"),
        }
    }
}
