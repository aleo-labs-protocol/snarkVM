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
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]

#[macro_use]
extern crate enum_index_derive;

pub use snarkvm_console_account::Signature;
pub use snarkvm_console_network::Network;
#[doc(no_inline)]
pub use snarkvm_console_types::prelude::*;

mod data;
pub use data::*;

mod data_types;
pub use data_types::*;

mod function_id;
pub use function_id::*;

mod id;
pub use id::*;

mod locator;
pub use locator::*;

mod owner;
pub use owner::*;

mod request;
pub use request::*;

mod response;
pub use response::*;

pub mod state_path;
pub use state_path::*;
