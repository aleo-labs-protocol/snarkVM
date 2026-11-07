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

/// Describes the failure modes of the AHP scheme.
#[derive(Debug, Error)]
pub enum AHPError {
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),

    #[error("Batch size was zero; must be at least 1.")]
    BatchSizeIsZero,

    #[error("constraint generation error")]
    ConstraintSystemError(#[from] crate::r1cs::errors::SynthesisError),

    #[error("The instance generated during proving does not match that in the index.")]
    InstanceDoesNotMatchIndex,

    #[error("The number of public inputs is incorrect.")]
    InvalidPublicInputLength,

    #[error("During verification, a required evaluation is missing: {}", _0)]
    MissingEval(String),

    #[error("Currently we only support square constraint matrices.")]
    NonSquareMatrix,

    #[error("During synthesis, our polynomials ended up being too high of degree.")]
    PolyTooLarge,
}
