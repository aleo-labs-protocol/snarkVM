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

pub type SynthesisResult<T> = Result<T, SynthesisError>;

/// This is an error that could occur during circuit synthesis contexts,
/// such as CRS generation, proving or verification.
#[derive(Debug, Error)]
pub enum SynthesisError {
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),
    /// During synthesis, we lacked knowledge of a variable assignment.
    #[error("An assignment for a variable could not be computed")]
    AssignmentMissing,
    /// Handles a failed conversion of objects into constraint field elements.
    #[error("Failed to convert object into constraint field elements")]
    ConstraintFieldError(#[from] snarkvm_fields::ConstraintFieldError),
    /// During synthesis, we divided by zero.
    #[error("Division by zero during synthesis")]
    DivisionByZero,
    /// During synthesis, we constructed an unsatisfiable constraint system.
    #[error("Unsatisfiable constraint system")]
    Unsatisfiable,
    /// During synthesis, our polynomials ended up being too high of degree
    #[error("Polynomial degree is too large")]
    PolyTooLarge,
    /// During proof generation, we encountered an identity in the CRS
    #[error("Encountered an identity element in the CRS")]
    UnexpectedIdentity,
    /// During proof generation, we encountered an I/O error with the CRS
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    /// During verification, our verifying key was malformed.
    #[error("Malformed verifying key, public input count was {} but expected {}", _0, _1)]
    MalformedVerifyingKey(usize, usize),
    /// During CRS generation, we observed an unconstrained auxiliary variable
    #[error("Auxiliary variable was unconstrained")]
    UnconstrainedVariable,
}
