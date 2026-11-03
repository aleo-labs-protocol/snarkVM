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

use crate::{
    InputStorage,
    InputStore,
    OutputStorage,
    OutputStore,
    TransitionStorage,
    helpers::rocksdb::{self, DataMap, Database, MapID, TransitionInputMap, TransitionMap, TransitionOutputMap},
};
use console::{
    prelude::*,
    program::{Ciphertext, Future, Identifier, Plaintext, ProgramID, Record},
    types::{Field, Group},
};

use aleo_std_storage::StorageMode;

/// A database transition storage.
#[derive(Clone)]
pub struct TransitionDB<N: Network> {
    /// The transition program IDs and function names.
    locator_map: DataMap<N::TransitionID, (ProgramID<N>, Identifier<N>)>,
    /// The transition input store.
    input_store: InputStore<N, InputDB<N>>,
    /// The transition output store.
    output_store: OutputStore<N, OutputDB<N>>,
    /// The transition public keys.
    tpk_map: DataMap<N::TransitionID, Group<N>>,
    /// The reverse `tpk` map.
    reverse_tpk_map: DataMap<Group<N>, N::TransitionID>,
    /// The transition commitments.
    tcm_map: DataMap<N::TransitionID, Field<N>>,
    /// The reverse `tcm` map.
    reverse_tcm_map: DataMap<Field<N>, N::TransitionID>,
    /// The signer commitments.
    scm_map: DataMap<N::TransitionID, Field<N>>,
}

#[rustfmt::skip]
impl<N: Network> TransitionStorage<N> for TransitionDB<N> {
    type LocatorMap = DataMap<N::TransitionID, (ProgramID<N>, Identifier<N>)>;
    type InputStorage = InputDB<N>;
    type OutputStorage = OutputDB<N>;
    type TPKMap = DataMap<N::TransitionID, Group<N>>;
    type ReverseTPKMap = DataMap<Group<N>, N::TransitionID>;
    type TCMMap = DataMap<N::TransitionID, Field<N>>;
    type ReverseTCMMap = DataMap<Field<N>, N::TransitionID>;
    type SCMMap = DataMap<N::TransitionID, Field<N>>;

    /// Initializes the transition storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        Ok(Self {
            locator_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Transition(TransitionMap::Locator))?,
            input_store: InputStore::open(storage.clone())?,
            output_store: OutputStore::open(storage.clone())?,
            tpk_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Transition(TransitionMap::TPK))?,
            reverse_tpk_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Transition(TransitionMap::ReverseTPK))?,
            tcm_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::Transition(TransitionMap::TCM))?,
            reverse_tcm_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(),  MapID::Transition(TransitionMap::ReverseTCM))?,
            scm_map: rocksdb::RocksDB::open_map(N::ID, storage, MapID::Transition(TransitionMap::SCM))?,
        })
    }

    /// Returns the transition program IDs and function names.
    fn locator_map(&self) -> &Self::LocatorMap {
        &self.locator_map
    }

    /// Returns the transition input store.
    fn input_store(&self) -> &InputStore<N, Self::InputStorage> {
        &self.input_store
    }

    /// Returns the transition output store.
    fn output_store(&self) -> &OutputStore<N, Self::OutputStorage> {
        &self.output_store
    }

    /// Returns the transition public keys.
    fn tpk_map(&self) -> &Self::TPKMap {
        &self.tpk_map
    }

    /// Returns the reverse `tpk` map.
    fn reverse_tpk_map(&self) -> &Self::ReverseTPKMap {
        &self.reverse_tpk_map
    }

    /// Returns the transition commitments.
    fn tcm_map(&self) -> &Self::TCMMap {
        &self.tcm_map
    }

    /// Returns the reverse `tcm` map.
    fn reverse_tcm_map(&self) -> &Self::ReverseTCMMap {
        &self.reverse_tcm_map
    }

    /// Returns the signer commitments.
    fn scm_map(&self) -> &Self::SCMMap {
        &self.scm_map
    }

}

/// An database transition input storage.
#[derive(Clone)]
pub struct InputDB<N: Network> {
    /// The mapping of `transition ID` to `input IDs`.
    id_map: DataMap<N::TransitionID, Vec<Field<N>>>,
    /// The mapping of `input ID` to `transition ID`.
    reverse_id_map: DataMap<Field<N>, N::TransitionID>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    constant: DataMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    public: DataMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `ciphertext hash` to `(optional) ciphertext`.
    private: DataMap<Field<N>, Option<Ciphertext<N>>>,
    /// The mapping of `serial number` to `tag`.
    record: DataMap<Field<N>, Field<N>>,
    /// The mapping of `record tag` to `serial number`.
    record_tag: DataMap<Field<N>, Field<N>>,
    /// The mapping of `external hash` to `()`. Note: This is **not** the record commitment.
    external_record: DataMap<Field<N>, ()>,
    /// The mapping of `dynamic hash` to `()`. Note: This is **not** the record commitment.
    dynamic_record: DataMap<Field<N>, ()>,
    /// The mapping of `input ID` to `dynamic ID` for inputs with dynamic IDs.
    dynamic_id: DataMap<Field<N>, Field<N>>,
    /// The storage mode.
    storage_mode: StorageMode,
}

#[rustfmt::skip]
impl<N: Network> InputStorage<N> for InputDB<N> {
    type IDMap = DataMap<N::TransitionID, Vec<Field<N>>>;
    type ReverseIDMap = DataMap<Field<N>, N::TransitionID>;
    type ConstantMap = DataMap<Field<N>, Option<Plaintext<N>>>;
    type PublicMap = DataMap<Field<N>, Option<Plaintext<N>>>;
    type PrivateMap = DataMap<Field<N>, Option<Ciphertext<N>>>;
    type RecordMap = DataMap<Field<N>, Field<N>>;
    type RecordTagMap = DataMap<Field<N>, Field<N>>;
    type ExternalRecordMap = DataMap<Field<N>, ()>;
    type DynamicRecordMap = DataMap<Field<N>, ()>;
    type DynamicIDMap = DataMap<Field<N>, Field<N>>;

    /// Initializes the transition input storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        Ok(Self {
            id_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::ID))?,
            reverse_id_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::ReverseID))?,
            constant: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::Constant))?,
            public: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::Public))?,
            private: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::Private))?,
            record: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::Record))?,
            record_tag: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::RecordTag))?,
            external_record: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::ExternalRecord))?,
            dynamic_record: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::DynamicRecord))?,
            dynamic_id: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionInput(TransitionInputMap::DynamicID))?,
            storage_mode: storage,
        })
    }

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap {
        &self.id_map
    }

    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap {
        &self.reverse_id_map
    }

    /// Returns the constant map.
    fn constant_map(&self) -> &Self::ConstantMap {
        &self.constant
    }

    /// Returns the public map.
    fn public_map(&self) -> &Self::PublicMap {
        &self.public
    }

    /// Returns the private map.
    fn private_map(&self) -> &Self::PrivateMap {
        &self.private
    }

    /// Returns the record map.
    fn record_map(&self) -> &Self::RecordMap {
        &self.record
    }

    /// Returns the record tag map.
    fn record_tag_map(&self) -> &Self::RecordTagMap {
        &self.record_tag
    }

    /// Returns the external record map.
    fn external_record_map(&self) -> &Self::ExternalRecordMap {
        &self.external_record
    }

    /// Returns the dynamic record map.
    fn dynamic_record_map(&self) -> &Self::DynamicRecordMap {
        &self.dynamic_record
    }

    /// Returns the dynamic ID map.
    fn dynamic_id_map(&self) -> &Self::DynamicIDMap {
        &self.dynamic_id
    }

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        &self.storage_mode
    }
}

/// A database transition output storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct OutputDB<N: Network> {
    /// The mapping of `transition ID` to `output IDs`.
    id_map: DataMap<N::TransitionID, Vec<Field<N>>>,
    /// The mapping of `output ID` to `transition ID`.
    reverse_id_map: DataMap<Field<N>, N::TransitionID>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    constant: DataMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    public: DataMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `ciphertext hash` to `(optional) ciphertext`.
    private: DataMap<Field<N>, Option<Ciphertext<N>>>,
    /// The mapping of `commitment` to `(checksum, (optional) record ciphertext)`.
    record: DataMap<Field<N>, (Field<N>, Option<Record<N, Ciphertext<N>>>)>,
    /// The mapping of `record nonce` to `commitment`.
    record_nonce: DataMap<Group<N>, Field<N>>,
    /// The mapping of `record nonce` to `sender ciphertext`.
    record_sender: DataMap<Group<N>, Option<Field<N>>>,
    /// The mapping of `external hash` to `()`. Note: This is **not** the record commitment.
    external_record: DataMap<Field<N>, ()>,
    /// The mapping of `future hash` to `(optional) future`.
    future: DataMap<Field<N>, Option<Future<N>>>,
    /// The mapping of `dynamic hash` to `()`. Note: This is **not** the record commitment.
    dynamic_record: DataMap<Field<N>, ()>,
    /// The mapping of `output ID` to `dynamic ID` for outputs with dynamic IDs.
    dynamic_id: DataMap<Field<N>, Field<N>>,
    /// The storage mode.
    storage_mode: StorageMode,
}

#[rustfmt::skip]
impl<N: Network> OutputStorage<N> for OutputDB<N> {
    type IDMap = DataMap<N::TransitionID, Vec<Field<N>>>;
    type ReverseIDMap = DataMap<Field<N>, N::TransitionID>;
    type ConstantMap = DataMap<Field<N>, Option<Plaintext<N>>>;
    type PublicMap = DataMap<Field<N>, Option<Plaintext<N>>>;
    type PrivateMap = DataMap<Field<N>, Option<Ciphertext<N>>>;
    type RecordMap = DataMap<Field<N>, (Field<N>, Option<Record<N, Ciphertext<N>>>)>;
    type RecordSenderMap = DataMap<Group<N>, Option<Field<N>>>;
    type RecordNonceMap = DataMap<Group<N>, Field<N>>;
    type ExternalRecordMap = DataMap<Field<N>, ()>;
    type FutureMap = DataMap<Field<N>, Option<Future<N>>>;
    type DynamicRecordMap = DataMap<Field<N>, ()>;
    type DynamicIDMap = DataMap<Field<N>, Field<N>>;

    /// Initializes the transition output storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        Ok(Self {
            id_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::ID))?,
            reverse_id_map: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::ReverseID))?,
            constant: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::Constant))?,
            public: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::Public))?,
            private: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::Private))?,
            record: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::Record))?,
            record_nonce: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::RecordNonce))?,
            record_sender: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::RecordSender))?,
            external_record: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::ExternalRecord))?,
            future: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::Future))?,
            dynamic_record: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::DynamicRecord))?,
            dynamic_id: rocksdb::RocksDB::open_map(N::ID, storage.clone(), MapID::TransitionOutput(TransitionOutputMap::DynamicID))?,
            storage_mode: storage,
        })
    }

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap {
        &self.id_map
    }

    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap {
        &self.reverse_id_map
    }

    /// Returns the constant map.
    fn constant_map(&self) -> &Self::ConstantMap {
        &self.constant
    }

    /// Returns the public map.
    fn public_map(&self) -> &Self::PublicMap {
        &self.public
    }

    /// Returns the private map.
    fn private_map(&self) -> &Self::PrivateMap {
        &self.private
    }

    /// Returns the record map.
    fn record_map(&self) -> &Self::RecordMap {
        &self.record
    }

    /// Returns the record nonce map.
    fn record_nonce_map(&self) -> &Self::RecordNonceMap {
        &self.record_nonce
    }
    
    /// Returns the record sender map.
    fn record_sender_map(&self) -> &Self::RecordSenderMap {
        &self.record_sender
    }

    /// Returns the external record map.
    fn external_record_map(&self) -> &Self::ExternalRecordMap {
        &self.external_record
    }

    /// Returns the future map.
    fn future_map(&self) -> &Self::FutureMap {
        &self.future
    }

    fn dynamic_record_map(&self) -> &Self::DynamicRecordMap {
        &self.dynamic_record
    }

    /// Returns the dynamic ID map.
    fn dynamic_id_map(&self) -> &Self::DynamicIDMap {
        &self.dynamic_id
    }

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        &self.storage_mode
    }
}
