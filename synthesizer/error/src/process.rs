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

use crate::{EvalError, ExecError, FinalizeError};
use anyhow::Error;
use snarkvm_circuit_environment::ConstraintUnsatisfied;
use snarkvm_console_network::Network;
use snarkvm_console_program::{Identifier, ProgramID};
use thiserror::Error;

// NOTE: Many errors in this module temporarily contain `Anyhow` variants.
// Remove these variants as we migrate errors to thiserror.

/// Errors that may occur during process authorization.
#[derive(Debug, Error)]
pub enum ProcessAuthError {
    /// Stack authorization failed.
    #[error("Stack authorization failed")]
    StackAuth(#[from] StackAuthError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during process evaluation.
#[derive(Debug, Error)]
pub enum ProcessEvalError {
    /// Stack evaluation failed.
    #[error("Stack evaluation failed")]
    StackEval(#[from] StackEvalError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during process execution.
#[derive(Debug, Error)]
pub enum ProcessExecError {
    /// Stack execution failed.
    #[error("Stack execution failed")]
    StackExec(#[from] StackExecError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during process deployment.
#[derive(Debug, Error)]
pub enum ProcessDeployError {
    /// Stack execution failed during synthesis.
    #[error("Stack synthesis failed")]
    StackExec(#[from] StackExecError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during call evaluation.
#[derive(Debug, Error)]
pub enum CallEvalError {
    /// An error occurred during substack evaluation.
    #[error("Substack evaluation failed")]
    StackEval(#[from] StackEvalError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during call execution.
#[derive(Debug, Error)]
pub enum CallExecError {
    /// An error occurred during substack execution.
    #[error("Substack execution failed")]
    StackExec(#[from] StackExecError),
    /// An error occurred during substack evaluation.
    #[error("Substack evaluation failed")]
    StackEval(#[from] StackEvalError),
    /// A circuit constraint was not satisfied.
    #[error(transparent)]
    Constraint(#[from] ConstraintUnsatisfied),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during stack authorization.
#[derive(Debug, Error)]
pub enum StackAuthError {
    /// Stack execution failed.
    #[error("Stack execution failed")]
    Exec(#[from] StackExecError),
    /// Stack evaluation failed.
    #[error("Stack evaluation failed")]
    Eval(#[from] StackEvalError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during stack execution.
#[derive(Debug, Error)]
pub enum StackExecError {
    /// Instruction at the given index failed.
    #[error(transparent)]
    Instruction(#[from] IndexedInstructionError<InstructionError>),
    /// A circuit constraint was not satisfied.
    #[error(transparent)]
    Constraint(#[from] ConstraintUnsatisfied),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during stack evaluation.
#[derive(Debug, Error)]
pub enum StackEvalError {
    /// Instruction at the given index failed.
    #[error(transparent)]
    Instruction(#[from] IndexedInstructionError<InstructionEvalError>),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// An instruction error occurred at a particular index.
#[derive(Debug, Error)]
#[error("Instruction ({instruction}) at index {index} failed")]
pub struct IndexedInstructionError<E> {
    /// The index of the failing instruction.
    pub index: usize,
    /// The failing instruction formatted.
    pub instruction: String,
    /// The instruction error.
    #[source]
    pub error: E,
}

/// An error occurred during the execution/evaluation/synthesis of an
/// instruction.
#[derive(Debug, Error)]
pub enum InstructionError {
    /// Failed to evaluate an instruction.
    #[error("Failed to evaluate")]
    Eval(#[from] InstructionEvalError),
    /// Failed to execute an instruction.
    #[error("Failed to execute")]
    Exec(#[from] InstructionExecError),
}

/// An error occurred during the evaluation of an instruction.
#[derive(Debug, Error)]
pub enum InstructionEvalError {
    /// An instruction evaluation failed.
    #[error(transparent)]
    Eval(#[from] EvalError),
    /// An error occurred during a `Call` instruction.
    #[error("Call failed")]
    Call(#[from] Box<CallEvalError>),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// An error occurred during the execution of an instruction.
#[derive(Debug, Error)]
pub enum InstructionExecError {
    /// An error occurred during a `Call` instruction.
    #[error("Call failed")]
    Call(#[from] Box<CallExecError>),
    /// An instruction execution error.
    #[error(transparent)]
    Exec(#[from] ExecError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl<E> IndexedInstructionError<E> {
    /// Short-hand constructor for the `IndexedInstructionError` type.
    pub fn new(index: usize, instruction: String, error: E) -> Self {
        Self { index, instruction, error }
    }
}

/// `C` is the command type stored in the error. Callers that have a concrete command type (e.g.
/// `Command<N>` from synthesizer-program) may use it directly; callers without access to that
/// type may use `String` (via `Display`). Using a generic avoids a circular crate dependency
/// between `snarkvm-synthesizer-error` and `snarkvm-synthesizer-program`.
pub struct IndexedFinalizeError<N: Network, C: ToString> {
    /// The program ID of the failing command, if available.
    pub program_id: Option<(ProgramID<N>, u16)>,
    /// The resource (function or constructor name) of the failing command, if available.
    pub resource: Option<Identifier<N>>,
    /// The index and the failing command, if available. Boxed to keep the struct small.
    pub command: Option<Box<(usize, C)>>,
    /// The finalize error.
    pub error: FinalizeError,
}

impl<N: Network, C: ToString> std::fmt::Debug for IndexedFinalizeError<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl<N: Network, C: ToString> std::fmt::Display for IndexedFinalizeError<N, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Build a display string from the optional program ID and resource.
        let locator = match (&self.program_id, &self.resource) {
            (Some((program_id, _)), Some(resource)) => format!("{program_id}/{resource}"),
            (Some((program_id, _)), None) => format!("{program_id}"),
            (None, Some(resource)) => format!("{resource}"),
            (None, None) => "None".to_string(),
        };
        match &self.command {
            Some(cmd) => {
                let (index, command) = cmd.as_ref();
                write!(
                    f,
                    "Failed to finalize '{locator}' command ({}) at index {index}: {}",
                    command.to_string(),
                    self.error
                )
            }
            None => write!(f, "Failed to finalize '{locator}': {}", self.error),
        }
    }
}

impl<N: Network, C: ToString> std::error::Error for IndexedFinalizeError<N, C> {}

impl<N: Network, C: ToString> From<Error> for IndexedFinalizeError<N, C> {
    /// Converts an anyhow error into an `IndexedFinalizeError` with no location or command context.
    fn from(error: Error) -> Self {
        Self::new(None, None, None, FinalizeError::Anyhow(error))
    }
}

impl<N: Network, C: ToString> IndexedFinalizeError<N, C> {
    /// Constructs an `IndexedFinalizeError` from its components.
    pub fn new(
        program_id: Option<(ProgramID<N>, u16)>,
        resource: Option<Identifier<N>>,
        command: Option<(usize, C)>,
        error: FinalizeError,
    ) -> Self {
        Self { program_id, resource, command: command.map(Box::new), error }
    }
}

/// A helper macro to bail with an `IndexedFinalizeError`.
///
/// Two forms:
///   - `indexed_finalize_bail!(program_id, resource, index, command, error message)` — with command context.
///   - `indexed_finalize_bail!(program_id, resource, error message)` — without command context.
///
/// `program_id` must be `Option<(ProgramID<N>, u16)>` and `resource` must be `Option<Identifier<N>>`.
#[macro_export]
macro_rules! indexed_finalize_bail {
    // With program_id + resource + index + command + message.
    ($program_id:expr, $resource:expr, $index:expr, $command:expr, $($arg:tt)+) => {{
        return Err(IndexedFinalizeError::new(
            $program_id,
            $resource,
            Some(($index, $command)),
            FinalizeError::Anyhow(anyhow!($($arg)+)),
        ));
    }};
    // With program_id + resource + message only (no command context).
    ($program_id:expr, $resource:expr, $($arg:tt)+) => {{
        return Err(IndexedFinalizeError::new(
            $program_id,
            $resource,
            None,
            FinalizeError::Anyhow(anyhow!($($arg)+)),
        ));
    }};
}

pub trait IntoIndexedFinalize<N: Network, C: ToString, T> {
    fn into_indexed(
        self,
        program_id: Option<(ProgramID<N>, u16)>,
        resource: Option<Identifier<N>>,
        command: Option<(usize, C)>,
    ) -> anyhow::Result<T, IndexedFinalizeError<N, C>>;
}

impl<N: Network, C: ToString, T> IntoIndexedFinalize<N, C, T> for anyhow::Result<T, Error> {
    fn into_indexed(
        self,
        program_id: Option<(ProgramID<N>, u16)>,
        resource: Option<Identifier<N>>,
        command: Option<(usize, C)>,
    ) -> anyhow::Result<T, IndexedFinalizeError<N, C>> {
        self.map_err(|e| IndexedFinalizeError::new(program_id, resource, command, FinalizeError::Anyhow(e)))
    }
}
