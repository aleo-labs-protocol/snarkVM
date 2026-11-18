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
// TODO (howardwu): Update the return type on `execute` after stabilizing the interface.
#![allow(clippy::type_complexity)]

#[allow(unused_imports)] // Only needed for some features
#[macro_use]
extern crate tracing;

extern crate snarkvm_circuit as circuit;
extern crate snarkvm_console as console;

pub use snarkvm_synthesizer_process as process;
pub use snarkvm_synthesizer_program as program;
pub use snarkvm_synthesizer_snark as snark;

#[doc(hidden)]
pub use crate::program::{Command, Instruction};
pub use crate::{
    process::{Authorization, CallMetrics, Process, Stack, Trace},
    program::{Closure, Finalize, Function, Program},
};

mod restrictions;
pub use restrictions::*;

pub mod vm;
pub use vm::*;

pub mod prelude {
    #[doc(hidden)]
    pub use crate::program::Instruction;
    pub use crate::{
        process::*,
        program::{Closure, Finalize, Function, Mapping, Program},
        snark::{Certificate, Proof, ProvingKey, UniversalSRS, VerifyingKey},
        vm::*,
    };
}
