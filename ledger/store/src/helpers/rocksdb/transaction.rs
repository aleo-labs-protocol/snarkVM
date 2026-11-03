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
    DeploymentStorage,
    DeploymentStore,
    ExecutionStorage,
    ExecutionStore,
    FeeStorage,
    FeeStore,
    TransactionStorage,
    TransactionType,
    TransitionStore,
    helpers::rocksdb::{
        self,
        DataMap,
        Database,
        DeploymentMap,
        ExecutionMap,
        FeeMap,
        MapID,
        TransactionMap,
        TransitionDB,
    },
};
use console::{
    prelude::*,
    program::{Identifier, ProgramID, ProgramOwner},
    types::U8,
};
use snarkvm_synthesizer_program::Program;
use snarkvm_synthesizer_snark::{Certificate, Proof, VerifyingKey};

/// A database transaction storage.
#[derive(Clone)]
pub struct TransactionDB<N: Network> {
    /// The mapping of `transaction ID` to `transaction type`.
    id_map: DataMap<N::TransactionID, TransactionType>,
    /// The deployment store.
    deployment_store: DeploymentStore<N, DeploymentDB<N>>,
    /// The execution store.
    execution_store: ExecutionStore<N, ExecutionDB<N>>,
    /// The fee store.
    fee_store: FeeStore<N, FeeDB<N>>,
}

#[rustfmt::skip]
impl<N: Network> TransactionStorage<N> for TransactionDB<N> {
    type IDMap = DataMap<N::TransactionID, TransactionType>;
    type DeploymentStorage = DeploymentDB<N>;
    type ExecutionStorage = ExecutionDB<N>;
    type FeeStorage = FeeDB<N>;
    type TransitionStorage = TransitionDB<N>;

    /// Initializes the transaction storage.
    fn open(transition_store: TransitionStore<N, Self::TransitionStorage>) -> Result<Self> {
        // Initialize the fee store.
        let fee_store = FeeStore::<N, FeeDB<N>>::open(transition_store)?;
        // Initialize the deployment store.
        let deployment_store = DeploymentStore::<N, DeploymentDB<N>>::open(fee_store.clone())?;
        // Initialize the execution store.
        let execution_store = ExecutionStore::<N, ExecutionDB<N>>::open(fee_store.clone())?;
        // Return the transaction storage.
        Ok(Self { id_map: rocksdb::RocksDB::open_map(N::ID, execution_store.storage_mode().clone(), MapID::Transaction(TransactionMap::ID))?, deployment_store, execution_store, fee_store })
    }

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap {
        &self.id_map
    }

    /// Returns the deployment store.
    fn deployment_store(&self) -> &DeploymentStore<N, Self::DeploymentStorage> {
        &self.deployment_store
    }

    /// Returns the execution store.
    fn execution_store(&self) -> &ExecutionStore<N, Self::ExecutionStorage> {
        &self.execution_store
    }

    /// Returns the fee store.
    fn fee_store(&self) -> &FeeStore<N, Self::FeeStorage> {
        &self.fee_store
    }
}

/// A database deployment storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct DeploymentDB<N: Network> {
    /// The ID map.
    id_map: DataMap<N::TransactionID, ProgramID<N>>,
    /// The ID edition map.
    id_edition_map: DataMap<N::TransactionID, u16>,
    /// The edition map.
    edition_map: DataMap<ProgramID<N>, u16>,
    /// The reverse ID map.
    reverse_id_map: DataMap<(ProgramID<N>, u16), N::TransactionID>,
    /// The program owner map.
    owner_map: DataMap<(ProgramID<N>, u16), ProgramOwner<N>>,
    /// The program map.
    program_map: DataMap<(ProgramID<N>, u16), Program<N>>,
    /// The checksum map.
    checksum_map: DataMap<(ProgramID<N>, u16), [U8<N>; 32]>,
    /// The verifying key map.
    verifying_key_map: DataMap<(ProgramID<N>, Identifier<N>, u16), VerifyingKey<N>>,
    /// The certificate map.
    certificate_map: DataMap<(ProgramID<N>, Identifier<N>, u16), Certificate<N>>,
    /// The fee store.
    fee_store: FeeStore<N, FeeDB<N>>,
    /// The amendment next index map.
    amendment_next_index_map: DataMap<(ProgramID<N>, u16), u64>,
    /// The amendment ID map.
    amendment_id_map: DataMap<(ProgramID<N>, u16, u64), N::TransactionID>,
    /// The reverse amendment ID map.
    reverse_amendment_id_map: DataMap<N::TransactionID, (ProgramID<N>, u16, u64)>,
    /// The amendment verifying key map.
    amendment_verifying_key_map: DataMap<(ProgramID<N>, Identifier<N>, u16, u64), VerifyingKey<N>>,
    /// The amendment certificate map.
    amendment_certificate_map: DataMap<(ProgramID<N>, Identifier<N>, u16, u64), Certificate<N>>,
    /// The amendment owner map.
    amendment_owner_map: DataMap<(ProgramID<N>, u16, u64), ProgramOwner<N>>,
}

#[rustfmt::skip]
impl<N: Network> DeploymentStorage<N> for DeploymentDB<N> {
    type IDMap = DataMap<N::TransactionID, ProgramID<N>>;
    type IDEditionMap = DataMap<N::TransactionID, u16>;
    type EditionMap = DataMap<ProgramID<N>, u16>;
    type ReverseIDMap = DataMap<(ProgramID<N>, u16), N::TransactionID>;
    type OwnerMap = DataMap<(ProgramID<N>, u16), ProgramOwner<N>>;
    type ProgramMap = DataMap<(ProgramID<N>, u16), Program<N>>;
    type ChecksumMap = DataMap<(ProgramID<N>, u16), [U8<N>; 32]>;
    type VerifyingKeyMap = DataMap<(ProgramID<N>, Identifier<N>, u16), VerifyingKey<N>>;
    type CertificateMap = DataMap<(ProgramID<N>, Identifier<N>, u16), Certificate<N>>;
    type FeeStorage = FeeDB<N>;
    type AmendmentNextIndexMap = DataMap<(ProgramID<N>, u16), u64>;
    type AmendmentIDMap = DataMap<(ProgramID<N>, u16, u64), N::TransactionID>;
    type ReverseAmendmentIDMap = DataMap<N::TransactionID, (ProgramID<N>, u16, u64)>;
    type AmendmentVerifyingKeyMap = DataMap<(ProgramID<N>, Identifier<N>, u16, u64), VerifyingKey<N>>;
    type AmendmentCertificateMap = DataMap<(ProgramID<N>, Identifier<N>, u16, u64), Certificate<N>>;
    type AmendmentOwnerMap = DataMap<(ProgramID<N>, u16, u64), ProgramOwner<N>>;

    /// Initializes the deployment storage.
    fn open(fee_store: FeeStore<N, Self::FeeStorage>) -> Result<Self> {
        // Retrieve the storage mode.
        let storage_mode = fee_store.storage_mode();
        Ok(Self {
            id_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::ID))?,
            id_edition_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::IDEdition))?,
            edition_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::Edition))?,
            reverse_id_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::ReverseID))?,
            owner_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::Owner))?,
            program_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::Program))?,
            checksum_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::Checksum))?,
            verifying_key_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::VerifyingKey))?,
            certificate_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::Certificate))?,
            amendment_next_index_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::AmendmentNextIndex))?,
            amendment_id_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::AmendmentID))?,
            reverse_amendment_id_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::ReverseAmendmentID))?,
            amendment_verifying_key_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::AmendmentVerifyingKey))?,
            amendment_certificate_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::AmendmentCertificate))?,
            amendment_owner_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Deployment(DeploymentMap::AmendmentOwner))?,
            fee_store,
        })
    }

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap {
        &self.id_map
    }

    /// Returns the ID edition map.
    fn id_edition_map(&self) -> &Self::IDEditionMap {
        &self.id_edition_map
    }

    /// Returns the edition map.
    fn edition_map(&self) -> &Self::EditionMap {
        &self.edition_map
    }

    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap {
        &self.reverse_id_map
    }

    /// Returns the program owner map.
    fn owner_map(&self) -> &Self::OwnerMap {
        &self.owner_map
    }

    /// Returns the program map.
    fn program_map(&self) -> &Self::ProgramMap {
        &self.program_map
    }

    /// Returns the checksum map.
    fn checksum_map(&self) -> &Self::ChecksumMap {
        &self.checksum_map
    }

    /// Returns the verifying key map.
    fn verifying_key_map(&self) -> &Self::VerifyingKeyMap {
        &self.verifying_key_map
    }

    /// Returns the certificate map.
    fn certificate_map(&self) -> &Self::CertificateMap {
        &self.certificate_map
    }

    /// Returns the fee store.
    fn fee_store(&self) -> &FeeStore<N, Self::FeeStorage> {
        &self.fee_store
    }

    /// Returns the amendment next index map.
    fn amendment_next_index_map(&self) -> &Self::AmendmentNextIndexMap {
        &self.amendment_next_index_map
    }

    /// Returns the amendment ID map.
    fn amendment_id_map(&self) -> &Self::AmendmentIDMap {
        &self.amendment_id_map
    }

    /// Returns the reverse amendment ID map.
    fn reverse_amendment_id_map(&self) -> &Self::ReverseAmendmentIDMap {
        &self.reverse_amendment_id_map
    }

    /// Returns the amendment verifying key map.
    fn amendment_verifying_key_map(&self) -> &Self::AmendmentVerifyingKeyMap {
        &self.amendment_verifying_key_map
    }

    /// Returns the amendment certificate map.
    fn amendment_certificate_map(&self) -> &Self::AmendmentCertificateMap {
        &self.amendment_certificate_map
    }

    /// Returns the amendment owner map.
    fn amendment_owner_map(&self) -> &Self::AmendmentOwnerMap {
        &self.amendment_owner_map
    }
}

/// A database execution storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct ExecutionDB<N: Network> {
    /// The ID map.
    id_map: DataMap<N::TransactionID, (Vec<N::TransitionID>, bool)>,
    /// The reverse ID map.
    reverse_id_map: DataMap<N::TransitionID, N::TransactionID>,
    /// The inclusion map.
    inclusion_map: DataMap<N::TransactionID, (N::StateRoot, Option<Proof<N>>)>,
    /// The fee store.
    fee_store: FeeStore<N, FeeDB<N>>,
}

#[rustfmt::skip]
impl<N: Network> ExecutionStorage<N> for ExecutionDB<N> {
    type IDMap = DataMap<N::TransactionID, (Vec<N::TransitionID>, bool)>;
    type ReverseIDMap = DataMap<N::TransitionID, N::TransactionID>;
    type InclusionMap = DataMap<N::TransactionID, (N::StateRoot, Option<Proof<N>>)>;
    type FeeStorage = FeeDB<N>;

    /// Initializes the execution storage.
    fn open(fee_store: FeeStore<N, Self::FeeStorage>) -> Result<Self> {
        // Retrieve the storage mode.
        let storage_mode = fee_store.storage_mode();
        Ok(Self {
            id_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Execution(ExecutionMap::ID))?,
            reverse_id_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Execution(ExecutionMap::ReverseID))?,
            inclusion_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Execution(ExecutionMap::Inclusion))?,
            fee_store,
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

    /// Returns the inclusion map.
    fn inclusion_map(&self) -> &Self::InclusionMap {
        &self.inclusion_map
    }

    /// Returns the fee store.
    fn fee_store(&self) -> &FeeStore<N, Self::FeeStorage> {
        &self.fee_store
    }
}

/// A database for fee storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct FeeDB<N: Network> {
    /// The fee map.
    fee_map: DataMap<N::TransactionID, (N::TransitionID, N::StateRoot, Option<Proof<N>>)>,
    /// The reverse fee map.
    reverse_fee_map: DataMap<N::TransitionID, N::TransactionID>,
    /// The transition store.
    transition_store: TransitionStore<N, TransitionDB<N>>,
}

#[rustfmt::skip]
impl<N: Network> FeeStorage<N> for FeeDB<N> {
    type FeeMap = DataMap<N::TransactionID, (N::TransitionID, N::StateRoot, Option<Proof<N>>)>;
    type ReverseFeeMap = DataMap<N::TransitionID, N::TransactionID>;
    type TransitionStorage = TransitionDB<N>;

    /// Initializes the fee storage.
    fn open(transition_store: TransitionStore<N, Self::TransitionStorage>) -> Result<Self> {
        // Retrieve the storage mode.
        let storage_mode = transition_store.storage_mode();
        Ok(Self {
            fee_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Fee(FeeMap::Fee))?,
            reverse_fee_map: rocksdb::RocksDB::open_map(N::ID, storage_mode.clone(), MapID::Fee(FeeMap::ReverseFee))?,
            transition_store,
        })
    }

    /// Returns the fee map.
    fn fee_map(&self) -> &Self::FeeMap {
        &self.fee_map
    }

    /// Returns the reverse fee map.
    fn reverse_fee_map(&self) -> &Self::ReverseFeeMap {
        &self.reverse_fee_map
    }

    /// Returns the transition store.
    fn transition_store(&self) -> &TransitionStore<N, Self::TransitionStorage> {
        &self.transition_store
    }
}
