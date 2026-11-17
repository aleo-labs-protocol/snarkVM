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
#![warn(clippy::cast_possible_truncation)]

pub use modules::*;

pub mod modules {
    pub use snarkvm_circuit_account as account;
    pub use snarkvm_circuit_account::*;

    pub use snarkvm_circuit_algorithms as algorithms;
    pub use snarkvm_circuit_algorithms::*;

    pub use snarkvm_circuit_collections as collections;
    pub use snarkvm_circuit_collections::*;

    pub use snarkvm_circuit_environment as environment;
    pub use snarkvm_circuit_environment::{
        Assignment,
        CanaryCircuit,
        Circuit,
        Eject,
        Environment,
        Inject,
        Mode,
        TestnetCircuit,
    };

    pub use snarkvm_circuit_network as network;
    pub use snarkvm_circuit_network::*;

    pub use snarkvm_circuit_program as program;
    pub use snarkvm_circuit_program::*;

    pub use snarkvm_circuit_types as types;
    pub use snarkvm_circuit_types::*;
}

pub mod traits {
    pub use snarkvm_circuit_algorithms::traits::*;
    pub use snarkvm_circuit_environment::traits::*;
}

pub mod prelude {
    pub use crate::modules::*;
    pub use snarkvm_circuit_environment::prelude::*;
}
