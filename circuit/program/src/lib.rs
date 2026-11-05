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
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]

#[cfg(test)]
use snarkvm_circuit_network::AleoV0 as Circuit;

#[cfg(test)]
extern crate snarkvm_console as console_root;

extern crate snarkvm_console_program as console;

mod data;
pub use data::*;

mod function_id;
pub use function_id::*;

mod id;
pub use id::*;

mod request;
pub use request::*;

mod response;
pub use response::*;

mod state_path;
pub use state_path::*;

use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Boolean, environment::prelude::*};

pub trait Visibility<A: Aleo>:
    Equal<Self, Output = <Self as ToBits>::Boolean> + ToBits<Boolean = Boolean<A>> + ToFields
{
    /// Returns the number of field elements to encode `self`.
    fn size_in_fields(&self) -> u16;
}
