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

#[macro_use]
extern crate thiserror;

pub mod biginteger;
pub use biginteger::*;

pub mod bititerator;
pub use bititerator::*;

#[macro_use]
pub mod bits;
pub use bits::*;

#[macro_use]
pub mod bytes;
pub use bytes::*;

#[macro_use]
pub mod defer;
pub use defer::*;

mod vm_error;
pub use vm_error::*;

pub mod iterator;
pub use iterator::*;

#[macro_use]
pub mod parallel;
pub use parallel::*;

#[macro_use]
mod print;

pub mod rand;
pub use self::rand::*;

/// Helpers for data (de-)serialization.
pub mod serialize;
pub use serialize::*;

/// The storage mode of a node, and the directories that it resolves to.
#[cfg(feature = "storage")]
pub mod storage;
#[cfg(feature = "storage")]
pub use storage::*;

/// Helpers for error handling.
pub mod errors;
pub use errors::*;

/// Use old name for backward-compatibility.
pub use errors::io_error as error;
