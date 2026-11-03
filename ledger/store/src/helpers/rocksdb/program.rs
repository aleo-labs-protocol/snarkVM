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

#![allow(clippy::type_complexity)]

use crate::{
    CommitteeStorage,
    CommitteeStore,
    FinalizeStorage,
    helpers::rocksdb::{self, CommitteeMap, DataMap, Database, MapID, NestedDataMap, ProgramMap},
};

use console::{
    prelude::*,
    program::{Identifier, Plaintext, ProgramID, Value},
    types::Field,
};
use snarkvm_ledger_block::RejectedReason;
use snarkvm_ledger_committee::Committee;

use aleo_std_storage::StorageMode;
use indexmap::IndexSet;

/// A RocksDB finalize storage.
#[derive(Clone)]
pub struct FinalizeDB<N: Network> {
    /// The committee store.
    committee_store: CommitteeStore<N, CommitteeDB<N>>,
    /// The program ID map.
    program_id_map: DataMap<ProgramID<N>, IndexSet<Identifier<N>>>,
    /// The key-value map.
    key_value_map: NestedDataMap<(ProgramID<N>, Identifier<N>), Plaintext<N>, Value<N>>,
    /// The rejection reason map.
    rejected_reason_map: DataMap<Field<N>, RejectedReason<N>>,

    /// The storage mode.
    storage_mode: StorageMode,
}

#[rustfmt::skip]
impl<N: Network> FinalizeStorage<N> for FinalizeDB<N> {
    type CommitteeStorage = CommitteeDB<N>;
    type ProgramIDMap = DataMap<ProgramID<N>, IndexSet<Identifier<N>>>;
    type KeyValueMap = NestedDataMap<(ProgramID<N>, Identifier<N>), Plaintext<N>, Value<N>>;
    type RejectedReasonMap = DataMap<Field<N>, RejectedReason<N>>;

    /// Initializes the finalize storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        // Initialize the committee store.
        let committee_store = CommitteeStore::<N, CommitteeDB<N>>::open(storage.clone())?;

        // Return the finalize storage.
        Ok(Self {
            committee_store,
            program_id_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Program(ProgramMap::ProgramID))?,
            key_value_map: rocksdb::RocksDB::open_nested_map(N::ID, storage.clone(), MapID::Program(ProgramMap::KeyValueID))?,
            rejected_reason_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Program(ProgramMap::RejectedReason))?,

            storage_mode: storage,
        })
    }

    /// Returns the committee store.
    fn committee_store(&self) -> &CommitteeStore<N, Self::CommitteeStorage> {
        &self.committee_store
    }

    /// Returns the program ID map.
    fn program_id_map(&self) -> &Self::ProgramIDMap {
        &self.program_id_map
    }

    /// Returns the key-value map.
    fn key_value_map(&self) -> &Self::KeyValueMap {
        &self.key_value_map
    }

    /// Returns the rejection reason map.
    fn rejected_reason_map(&self) -> &Self::RejectedReasonMap {
        &self.rejected_reason_map
    }

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        &self.storage_mode
    }

}

/// A RocksDB committee storage.
#[derive(Clone)]
pub struct CommitteeDB<N: Network> {
    /// The current round map.
    current_round_map: DataMap<u8, u64>,
    /// The round to height map.
    round_to_height_map: DataMap<u64, u32>,
    /// The committee map.
    committee_map: DataMap<u32, Committee<N>>,
    /// The storage mode.
    storage_mode: StorageMode,
}

#[rustfmt::skip]
impl<N: Network> CommitteeStorage<N> for CommitteeDB<N> {
    type CurrentRoundMap = DataMap<u8, u64>;
    type RoundToHeightMap = DataMap<u64, u32>;
    type CommitteeMap = DataMap<u32, Committee<N>>;

    /// Initializes the committee storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        Ok(Self {
            current_round_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Committee(CommitteeMap::CurrentRound))?,
            round_to_height_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Committee(CommitteeMap::RoundToHeight))?,
            committee_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Committee(CommitteeMap::Committee))?,
            storage_mode: storage,
        })
    }

    /// Returns the current round map.
    fn current_round_map(&self) -> &Self::CurrentRoundMap {
        &self.current_round_map
    }

    /// Returns the round to height map.
    fn round_to_height_map(&self) -> &Self::RoundToHeightMap {
        &self.round_to_height_map
    }

    /// Returns the committee map.
    fn committee_map(&self) -> &Self::CommitteeMap {
        &self.committee_map
    }

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        &self.storage_mode
    }
}
