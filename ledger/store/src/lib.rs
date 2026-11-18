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

extern crate snarkvm_console as console;

pub mod helpers;

mod block;
pub use block::*;

mod consensus;
pub use consensus::*;

mod program;
pub use program::*;

mod transaction;
pub use transaction::*;

mod transition;
pub use transition::*;

pub use snarkvm_utilities::storage::{StorageMode, aleo_dir, aleo_ledger_dir, aleo_secondary_ledger_dir};

/// Seals the storage traits. Only the storage backends of this crate implement them.
///
/// ```compile_fail,E0277
/// use snarkvm_console::network::MainnetV0;
/// use snarkvm_ledger_store::{
///     BlockStore,
///     ConsensusStorage,
///     FinalizeStore,
///     StorageMode,
///     helpers::memory::{BlockMemory, ConsensusMemory, FinalizeMemory, TransactionMemory, TransitionMemory},
/// };
///
/// #[derive(Clone)]
/// struct Wrapper(ConsensusMemory<MainnetV0>);
///
/// impl ConsensusStorage<MainnetV0> for Wrapper {
///     type FinalizeStorage = FinalizeMemory<MainnetV0>;
///     type BlockStorage = BlockMemory<MainnetV0>;
///     type TransactionStorage = TransactionMemory<MainnetV0>;
///     type TransitionStorage = TransitionMemory<MainnetV0>;
///
///     fn open<S: Into<StorageMode>>(storage: S) -> anyhow::Result<Self> {
///         ConsensusMemory::open(storage).map(Self)
///     }
///
///     fn finalize_store(&self) -> &FinalizeStore<MainnetV0, Self::FinalizeStorage> {
///         self.0.finalize_store()
///     }
///
///     fn block_store(&self) -> &BlockStore<MainnetV0, Self::BlockStorage> {
///         self.0.block_store()
///     }
/// }
/// ```
mod sealed {
    pub trait Sealed {}
}

use console::prelude::{Result, bail};

/// A store this build will not open as asked, though nothing is wrong with it: its schema is newer
/// than this build, or the consensus storage cannot prune authority data. Do not delete it.
#[derive(Debug)]
pub struct IncompatibleStore(pub String);

impl std::fmt::Display for IncompatibleStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IncompatibleStore {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FinalizeMode {
    /// Invoke finalize as a real run.
    RealRun,
    /// Invoke finalize as a dry run.
    DryRun,
}

impl FinalizeMode {
    /// Returns the u8 value of the finalize mode.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::RealRun => 0,
            Self::DryRun => 1,
        }
    }

    /// Returns a finalize mode from a given u8.
    #[inline]
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::RealRun),
            1 => Ok(Self::DryRun),
            _ => bail!("Invalid finalize mode of '{value}'"),
        }
    }
}
