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
#![allow(clippy::module_inception)]
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]

#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "package")]
pub mod package;

#[cfg(feature = "algorithms")]
pub use snarkvm_algorithms as algorithms;
#[cfg(feature = "circuit")]
pub use snarkvm_circuit as circuit;
#[cfg(feature = "console")]
pub use snarkvm_console as console;
#[cfg(feature = "curves")]
pub use snarkvm_curves as curves;
#[cfg(feature = "fields")]
pub use snarkvm_fields as fields;
#[cfg(feature = "ledger")]
pub use snarkvm_ledger as ledger;
#[cfg(feature = "metrics")]
pub use snarkvm_metrics as metrics;
#[cfg(feature = "parameters")]
pub use snarkvm_parameters as parameters;
#[cfg(feature = "synthesizer")]
pub use snarkvm_synthesizer as synthesizer;
#[cfg(feature = "utilities")]
pub use snarkvm_utilities as utilities;
#[cfg(feature = "wasm")]
pub use snarkvm_wasm as wasm;

pub mod prelude {
    #[cfg(feature = "console")]
    pub use crate::console::{account::*, network::prelude::*, program::*};
    #[cfg(feature = "ledger")]
    pub use crate::ledger::prelude::*;
    #[cfg(feature = "synthesizer")]
    pub use crate::synthesizer::prelude::*;
}
