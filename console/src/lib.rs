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

#[cfg(all(feature = "dev_skip_checks", not(feature = "test_consensus_heights")))]
compile_error!("feature \"dev_skip_checks\" requires feature \"test_consensus_heights\".");

#[cfg(feature = "account")]
pub use snarkvm_console_account as account;

#[cfg(feature = "algorithms")]
pub use snarkvm_console_algorithms as algorithms;

#[cfg(feature = "collections")]
pub use snarkvm_console_collections as collections;

#[cfg(feature = "network")]
pub use snarkvm_console_network as network;

#[cfg(feature = "program")]
pub use snarkvm_console_program as program;

#[cfg(feature = "types")]
pub use snarkvm_console_types as types;

pub mod prelude {
    #[cfg(feature = "network")]
    pub use crate::network::prelude::*;
}

#[cfg(all(feature = "filesystem", any(target_arch = "wasm32", target_arch = "wasm64")))]
compile_error!("Filesystem feature is not supported on wasm32 or wasm64");
