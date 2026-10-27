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

use crate::{ProcessAuthError, ProcessDeployError, ProcessExecError};
use thiserror::Error;

// NOTE: Many errors in this module temporarily contain `Anyhow` variants.
// Remove these variants as we migrate errors to thiserror.

/// Errors that may occur during VM execution.
#[derive(Debug, Error)]
pub enum VmExecError {
    /// Authorization failed.
    #[error("Authorization failed: {0}")]
    Auth(#[from] VmAuthError),
    /// Process execution failed (contains instruction index).
    #[error("Process execution failed: {0}")]
    Process(#[from] ProcessExecError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors that may occur during VM authorization.
#[derive(Debug, Error)]
pub enum VmAuthError {
    /// Process authorization failed.
    #[error("Process authorization failed: {0}")]
    Process(#[from] ProcessAuthError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors from `VM::check_block_content_inner`: speculation dry-run vs block verification.
#[derive(Debug, Error)]
pub enum VmCheckBlockContentError {
    /// `VM::check_speculate` rejected the block's ratifications or transactions.
    #[error("Failed to speculate over unconfirmed transactions - {0}")]
    Speculation(#[source] anyhow::Error),
    /// [`snarkvm_ledger_block::Block::verify`] failed (header, authority, duplicate IDs, etc.).
    #[error("Failed to verify block - {0}")]
    Verification(#[source] anyhow::Error),
}

/// Errors that may occur during VM deployment.
#[derive(Debug, Error)]
pub enum VmDeployError {
    /// Process deployment failed.
    #[error("Process deployment failed: {0}")]
    Process(#[from] ProcessDeployError),
    /// Fee execution failed.
    #[error("Fee execution failed: {0}")]
    FeeExec(#[from] VmExecError),
    /// A temporary variant for type-erased anyhow errors.
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}
