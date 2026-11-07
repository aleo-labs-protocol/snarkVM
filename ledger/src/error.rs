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

use snarkvm_synthesizer_error::{VmDeployError, VmExecError};
use thiserror::Error;

// NOTE: Many errors in this module temporarily contain `Anyhow` variants.
// Remove these variants as we migrate errors to thiserror.

/// Errors that may occur when creating a transfer transaction.
#[derive(Debug, Error)]
pub enum CreateTransferError {
    /// VM execution failed.
    #[error("VM execution failed")]
    VmExec(#[from] VmExecError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur when creating a deploy transaction.
#[derive(Debug, Error)]
pub enum CreateDeployError {
    /// VM deployment failed.
    #[error("VM deployment failed")]
    VmDeploy(#[from] VmDeployError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}
