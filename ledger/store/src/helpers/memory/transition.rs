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

use crate::{InputStorage, InputStore, OutputStorage, OutputStore, TransitionStorage, helpers::memory::MemoryMap};
use console::{
    prelude::*,
    program::{Ciphertext, Future, Identifier, Plaintext, ProgramID, Record},
    types::{Field, Group},
};

use aleo_std_storage::StorageMode;

/// An in-memory transition storage.
#[derive(Clone)]
pub struct TransitionMemory<N: Network> {
    /// The transition program IDs and function names.
    locator_map: MemoryMap<N::TransitionID, (ProgramID<N>, Identifier<N>)>,
    /// The transition input store.
    input_store: InputStore<N, InputMemory<N>>,
    /// The transition output store.
    output_store: OutputStore<N, OutputMemory<N>>,
    /// The transition public keys.
    tpk_map: MemoryMap<N::TransitionID, Group<N>>,
    /// The reverse `tpk` map.
    reverse_tpk_map: MemoryMap<Group<N>, N::TransitionID>,
    /// The transition commitments.
    tcm_map: MemoryMap<N::TransitionID, Field<N>>,
    /// The reverse `tcm` map.
    reverse_tcm_map: MemoryMap<Field<N>, N::TransitionID>,
    /// The signer commitments.
    scm_map: MemoryMap<N::TransitionID, Field<N>>,
}

#[rustfmt::skip]
impl<N: Network> TransitionStorage<N> for TransitionMemory<N> {
    type LocatorMap = MemoryMap<N::TransitionID, (ProgramID<N>, Identifier<N>)>;
    type InputStorage = InputMemory<N>;
    type OutputStorage = OutputMemory<N>;
    type TPKMap = MemoryMap<N::TransitionID, Group<N>>;
    type ReverseTPKMap = MemoryMap<Group<N>, N::TransitionID>;
    type TCMMap = MemoryMap<N::TransitionID, Field<N>>;
    type ReverseTCMMap = MemoryMap<Field<N>, N::TransitionID>;
    type SCMMap = MemoryMap<N::TransitionID, Field<N>>;

    /// Initializes the transition storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        let storage = storage.into();
        Ok(Self {
            locator_map: MemoryMap::default(),
            input_store: InputStore::open(storage.clone())?,
            output_store: OutputStore::open(storage)?,
            tpk_map: MemoryMap::default(),
            reverse_tpk_map: MemoryMap::default(),
            tcm_map: MemoryMap::default(),
            reverse_tcm_map: MemoryMap::default(),
            scm_map: MemoryMap::default(),
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

/// An in-memory transition input storage.
#[derive(Clone)]
pub struct InputMemory<N: Network> {
    /// The mapping of `transition ID` to `input IDs`.
    id_map: MemoryMap<N::TransitionID, Vec<Field<N>>>,
    /// The mapping of `input ID` to `transition ID`.
    reverse_id_map: MemoryMap<Field<N>, N::TransitionID>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    constant: MemoryMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    public: MemoryMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `ciphertext hash` to `(optional) ciphertext`.
    private: MemoryMap<Field<N>, Option<Ciphertext<N>>>,
    /// The mapping of `serial number` to `tag`.
    record: MemoryMap<Field<N>, Field<N>>,
    /// The mapping of `record tag` to `serial number`.
    record_tag: MemoryMap<Field<N>, Field<N>>,
    /// The mapping of `external hash` to `()`. Note: This is **not** the record commitment.
    external_record: MemoryMap<Field<N>, ()>,
    /// The mapping of `dynamic hash` to `()`. Note: This is **not** the record commitment.
    dynamic_record: MemoryMap<Field<N>, ()>,
    /// The mapping of `input ID` to `dynamic ID` for inputs with dynamic IDs.
    dynamic_id: MemoryMap<Field<N>, Field<N>>,
    /// The storage mode.
    storage_mode: StorageMode,
}

#[rustfmt::skip]
impl<N: Network> InputStorage<N> for InputMemory<N> {
    type IDMap = MemoryMap<N::TransitionID, Vec<Field<N>>>;
    type ReverseIDMap = MemoryMap<Field<N>, N::TransitionID>;
    type ConstantMap = MemoryMap<Field<N>, Option<Plaintext<N>>>;
    type PublicMap = MemoryMap<Field<N>, Option<Plaintext<N>>>;
    type PrivateMap = MemoryMap<Field<N>, Option<Ciphertext<N>>>;
    type RecordMap = MemoryMap<Field<N>, Field<N>>;
    type RecordTagMap = MemoryMap<Field<N>, Field<N>>;
    type ExternalRecordMap = MemoryMap<Field<N>, ()>;
    type DynamicRecordMap = MemoryMap<Field<N>, ()>;
    type DynamicIDMap = MemoryMap<Field<N>, Field<N>>;

    /// Initializes the transition input storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        Ok(Self {
            id_map: MemoryMap::default(),
            reverse_id_map: MemoryMap::default(),
            constant: MemoryMap::default(),
            public: MemoryMap::default(),
            private: MemoryMap::default(),
            record: MemoryMap::default(),
            record_tag: MemoryMap::default(),
            external_record: MemoryMap::default(),
            dynamic_record: MemoryMap::default(),
            dynamic_id: MemoryMap::default(),
            storage_mode: storage.into(),
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

/// An in-memory transition output storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct OutputMemory<N: Network> {
    /// The mapping of `transition ID` to `output IDs`.
    id_map: MemoryMap<N::TransitionID, Vec<Field<N>>>,
    /// The mapping of `output ID` to `transition ID`.
    reverse_id_map: MemoryMap<Field<N>, N::TransitionID>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    constant: MemoryMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    public: MemoryMap<Field<N>, Option<Plaintext<N>>>,
    /// The mapping of `ciphertext hash` to `(optional) ciphertext`.
    private: MemoryMap<Field<N>, Option<Ciphertext<N>>>,
    /// The mapping of `commitment` to `(checksum, (optional) record ciphertext)`.
    record: MemoryMap<Field<N>, (Field<N>, Option<Record<N, Ciphertext<N>>>)>,
    /// The mapping of `record nonce` to `commitment`.
    record_nonce: MemoryMap<Group<N>, Field<N>>,
    /// The mapping of `record nonce` to `sender ciphertext`.
    record_sender: MemoryMap<Group<N>, Option<Field<N>>>,
    /// The mapping of `external hash` to `()`. Note: This is **not** the record commitment.
    external_record: MemoryMap<Field<N>, ()>,
    /// The mapping of `future hash` to `(optional) future`.
    future: MemoryMap<Field<N>, Option<Future<N>>>,
    /// The mapping of `dynamic hash` to `()`. Note: This is **not** the dynamic record commitment.
    dynamic_record: MemoryMap<Field<N>, ()>,
    /// The mapping of `output ID` to `dynamic ID` for outputs with dynamic IDs.
    dynamic_id: MemoryMap<Field<N>, Field<N>>,
    /// The storage mode.
    storage_mode: StorageMode,
}

#[rustfmt::skip]
impl<N: Network> OutputStorage<N> for OutputMemory<N> {
    type IDMap = MemoryMap<N::TransitionID, Vec<Field<N>>>;
    type ReverseIDMap = MemoryMap<Field<N>, N::TransitionID>;
    type ConstantMap = MemoryMap<Field<N>, Option<Plaintext<N>>>;
    type PublicMap = MemoryMap<Field<N>, Option<Plaintext<N>>>;
    type PrivateMap = MemoryMap<Field<N>, Option<Ciphertext<N>>>;
    type RecordMap = MemoryMap<Field<N>, (Field<N>, Option<Record<N, Ciphertext<N>>>)>;
    type RecordNonceMap = MemoryMap<Group<N>, Field<N>>;
    type RecordSenderMap = MemoryMap<Group<N>, Option<Field<N>>>;
    type ExternalRecordMap = MemoryMap<Field<N>, ()>;
    type FutureMap = MemoryMap<Field<N>, Option<Future<N>>>;
    type DynamicRecordMap = MemoryMap<Field<N>, ()>;
    type DynamicIDMap = MemoryMap<Field<N>, Field<N>>;


    /// Initializes the transition output storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        Ok(Self {
            id_map: Default::default(),
            reverse_id_map: Default::default(),
            constant: Default::default(),
            public: Default::default(),
            private: Default::default(),
            record: Default::default(),
            record_nonce: Default::default(),
            record_sender: Default::default(),
            external_record: Default::default(),
            future: Default::default(),
            dynamic_record: Default::default(),
            dynamic_id: Default::default(),
            storage_mode: storage.into(),
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
