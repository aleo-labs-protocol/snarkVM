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

use crate::Process;
use circuit::network::AleoV0;
use console::network::MainnetV0;

use std::sync::OnceLock;

pub type CurrentNetwork = MainnetV0;
pub type CurrentAleo = AleoV0;

/// The circuit counts and limits on this thread.
pub type CircuitSnapshot = ((u64, u64, u64, u64, (u64, u64, u64)), Option<u64>, Option<u64>, Option<(u64, u64, u64)>);

/// Returns the circuit counts and limits on this thread.
pub fn circuit_snapshot() -> CircuitSnapshot {
    use circuit::Environment as _;

    (
        CurrentAleo::count(),
        CurrentAleo::get_variable_limit(),
        CurrentAleo::get_constraint_limit(),
        CurrentAleo::get_non_zero_limit(),
    )
}

/// Leaves a caller part way through its own synthesis on this thread, and returns its snapshot.
pub fn start_callers_synthesis() -> CircuitSnapshot {
    use circuit::{Environment as _, Inject as _};

    let a = circuit::Field::<CurrentAleo>::new(circuit::Mode::Private, console::types::Field::from_u64(3));
    CurrentAleo::assert_eq(&a, &a).unwrap();
    CurrentAleo::set_variable_limit(Some(1 << 30));
    CurrentAleo::set_constraint_limit(Some(1 << 31));
    CurrentAleo::set_non_zero_limit(Some((1 << 32, 1 << 33, 1 << 34)));
    circuit_snapshot()
}

/// Returns a process loaded once and shared by every later caller in the same test process.
/// Only use it where the test never mutates the process, e.g. via `add_program` or `execute`.
pub fn shared_process() -> &'static Process<CurrentNetwork> {
    static PROCESS: OnceLock<Process<CurrentNetwork>> = OnceLock::new();
    PROCESS.get_or_init(|| Process::load().unwrap())
}
