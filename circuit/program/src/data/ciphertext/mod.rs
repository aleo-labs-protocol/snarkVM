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
mod from_bits;
mod from_fields;
mod size_in_fields;
mod to_bits;
mod to_fields;

use crate::Visibility;
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Boolean, Field, environment::prelude::*};

use core::ops::Deref;

#[derive(Clone)]
pub struct Ciphertext<A: Aleo>(Vec<Field<A>>);

impl<A: Aleo> Inject for Ciphertext<A> {
    type Primitive = console::Ciphertext<A::Network>;

    /// Initializes a new ciphertext circuit from a primitive.
    fn new(mode: Mode, ciphertext: Self::Primitive) -> Self {
        // Ensure the number of field elements does not exceed the maximum allowed size.
        match (*ciphertext).len() <= A::MAX_DATA_SIZE_IN_FIELDS as usize {
            true => Self(Inject::new(mode, (*ciphertext).to_vec())),
            false => A::halt("Ciphertext exceeds maximum allowed size"),
        }
    }
}

impl<A: Aleo> Eject for Ciphertext<A> {
    type Primitive = console::Ciphertext<A::Network>;

    /// Ejects the mode of the ciphertext.
    fn eject_mode(&self) -> Mode {
        self.0.eject_mode()
    }

    /// Ejects the ciphertext.
    fn eject_value(&self) -> Self::Primitive {
        match console::FromFields::from_fields(&self.0.eject_value()) {
            Ok(ciphertext) => ciphertext,
            Err(error) => A::halt(format!("Failed to eject ciphertext: {error}")),
        }
    }
}

impl<A: Aleo> Deref for Ciphertext<A> {
    type Target = [Field<A>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
