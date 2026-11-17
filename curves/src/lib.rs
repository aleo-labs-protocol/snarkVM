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

#![allow(clippy::module_inception)]
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]
#![doc = include_str!("../documentation/the_aleo_curves/00_overview.md")]

#[macro_use]
extern crate thiserror;

pub mod bls12_377;

pub mod edwards_bls12;

pub mod errors;
pub use errors::*;

pub mod templates;

#[cfg_attr(test, macro_use)]
pub mod traits;
pub use traits::*;
