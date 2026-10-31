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

use crate::{r1cs::SynthesisError, snark::varuna::ahp::AHPError};
use snarkvm_fields::ConstraintFieldError;

#[derive(Debug, Error)]
pub enum SNARKError {
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),

    #[error("constraint field error")]
    ConstraintFieldError(#[from] ConstraintFieldError),

    #[error("{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[error("Expected a circuit-specific SRS in SNARK")]
    ExpectedCircuitSpecificSRS,

    #[error("{}", _0)]
    Message(String),

    #[error("synthesis error")]
    SynthesisError(#[from] SynthesisError),

    #[error("Batch size was zero; must be at least 1")]
    EmptyBatch,

    #[error("Batch size was different between public input and proof")]
    BatchSizeMismatch,

    #[error("Public input size was different from the circuit")]
    PublicInputSizeMismatch,
}

impl From<AHPError> for SNARKError {
    fn from(err: AHPError) -> Self {
        SNARKError::Crate("AHPError", format!("{err:?}"))
    }
}
