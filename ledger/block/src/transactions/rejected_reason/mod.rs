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

mod bytes;
mod serialize;
mod string;

use super::*;

/// The reason a transaction was rejected.
#[derive(Clone, PartialEq, Eq)]
pub enum RejectedReason<N: Network> {
    /// The transaction was rejected due to a duplicate program ID deployment in the same block.
    DuplicateProgramID(ProgramID<N>),

    /// The transaction was rejected due to a failed finalize command. (program ID, edition, resource, index, command).
    /// Note: We do not log the actual error message from the finalize command, as it may contain
    /// sensitive information or lead to DOS vectors by storing string representations of large structs.
    Finalize { program_id: ProgramID<N>, edition: u16, resource: Identifier<N>, index: usize, command: Box<Command<N>> },

    /// The transaction was rejected due to a VM error not captured by a finalize command.
    /// The programID and resource are logged if they are available.
    VM(Option<(ProgramID<N>, u16)>, Option<Identifier<N>>),
}

impl<N: Network> RejectedReason<N> {
    /// Initializes the rejected reason from an indexed finalize error.
    ///
    /// `C` may be any type whose `Display` output is a valid `Command<N>` string (e.g. `Command<N>`
    /// itself or `String`). If the command string cannot be re-parsed, the reason falls back to
    /// `VM` so that a bad string never causes a panic in consensus code.
    pub fn from_indexed_finalize_error<C: ToString>(error: IndexedFinalizeError<N, C>) -> Self {
        let program_id = error.program_id;
        let resource = error.resource;
        match error.command.map(|b| *b) {
            Some((index, command)) => {
                // Parse the command from its display string. Falls back to VM on failure.
                match (program_id, resource, command.to_string().parse::<Command<N>>()) {
                    (Some((program_id, edition)), Some(resource), Ok(command)) => {
                        Self::Finalize { program_id, edition, resource, index, command: Box::new(command) }
                    }
                    (program_id, resource, _) => Self::VM(program_id, resource),
                }
            }
            None => Self::VM(program_id, resource),
        }
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use std::str::FromStr;

    /// Returns one instance of each `RejectedReason` variant for testing.
    pub(crate) fn sample_rejected_reasons<N: Network>() -> Vec<RejectedReason<N>> {
        let program = ProgramID::<N>::from_str("dummy_program.aleo").unwrap();
        let credits = ProgramID::<N>::from_str("credits.aleo").unwrap();
        let transfer = Identifier::<N>::from_str("transfer_public").unwrap();
        let bond = Identifier::<N>::from_str("bond_public").unwrap();
        let command = Command::<N>::from_str("assert.eq r0 r1;").unwrap();
        vec![
            RejectedReason::DuplicateProgramID(program),
            RejectedReason::Finalize {
                program_id: credits,
                edition: 1,
                resource: transfer,
                index: 3,
                command: Box::new(command),
            },
            RejectedReason::VM(Some((credits, 0u16)), Some(bond)),
            RejectedReason::VM(None, Some(bond)),
            RejectedReason::VM(Some((credits, 0u16)), None),
            RejectedReason::VM(None, None),
        ]
    }
}
