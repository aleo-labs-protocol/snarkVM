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
    helpers::memory::{MemoryMap, TransitionMemory},
};
use console::{
    prelude::*,
    program::{Identifier, ProgramID, ProgramOwner},
    types::U8,
};
use snarkvm_synthesizer_program::Program;
use snarkvm_synthesizer_snark::{Certificate, Proof, VerifyingKey};

/// An in-memory transaction storage.
#[derive(Clone)]
pub struct TransactionMemory<N: Network> {
    /// The mapping of `transaction ID` to `transaction type`.
    id_map: MemoryMap<N::TransactionID, TransactionType>,
    /// The deployment store.
    deployment_store: DeploymentStore<N, DeploymentMemory<N>>,
    /// The execution store.
    execution_store: ExecutionStore<N, ExecutionMemory<N>>,
    /// The fee store.
    fee_store: FeeStore<N, FeeMemory<N>>,
}

#[rustfmt::skip]
impl<N: Network> TransactionStorage<N> for TransactionMemory<N> {
    type IDMap = MemoryMap<N::TransactionID, TransactionType>;
    type DeploymentStorage = DeploymentMemory<N>;
    type ExecutionStorage = ExecutionMemory<N>;
    type FeeStorage = FeeMemory<N>;
    type TransitionStorage = TransitionMemory<N>;

    /// Initializes the transaction storage.
    fn open(transition_store: TransitionStore<N, Self::TransitionStorage>) -> Result<Self> {
        // Initialize the fee store.
        let fee_store = FeeStore::<N, FeeMemory<N>>::open(transition_store)?;
        // Initialize the deployment store.
        let deployment_store = DeploymentStore::<N, DeploymentMemory<N>>::open(fee_store.clone())?;
        // Initialize the execution store.
        let execution_store = ExecutionStore::<N, ExecutionMemory<N>>::open(fee_store.clone())?;
        // Return the transaction storage.
        Ok(Self { id_map: MemoryMap::default(), deployment_store, execution_store, fee_store })
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

/// An in-memory deployment storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct DeploymentMemory<N: Network> {
    /// The ID map.
    id_map: MemoryMap<N::TransactionID, ProgramID<N>>,
    /// The ID edition map.
    id_edition_map: MemoryMap<N::TransactionID, u16>,
    /// The edition map.
    edition_map: MemoryMap<ProgramID<N>, u16>,
    /// The reverse ID map.
    reverse_id_map: MemoryMap<(ProgramID<N>, u16), N::TransactionID>,
    /// The owner map.
    owner_map: MemoryMap<(ProgramID<N>, u16), ProgramOwner<N>>,
    /// The program map.
    program_map: MemoryMap<(ProgramID<N>, u16), Program<N>>,
    /// The checksum map.
    checksum_map: MemoryMap<(ProgramID<N>, u16), [U8<N>; 32]>,
    /// The verifying key map.
    verifying_key_map: MemoryMap<(ProgramID<N>, Identifier<N>, u16), VerifyingKey<N>>,
    /// The certificate map.
    certificate_map: MemoryMap<(ProgramID<N>, Identifier<N>, u16), Certificate<N>>,
    /// The fee store.
    fee_store: FeeStore<N, FeeMemory<N>>,
    /// The amendment next index map.
    amendment_next_index_map: MemoryMap<(ProgramID<N>, u16), u64>,
    /// The amendment ID map.
    amendment_id_map: MemoryMap<(ProgramID<N>, u16, u64), N::TransactionID>,
    /// The reverse amendment ID map.
    reverse_amendment_id_map: MemoryMap<N::TransactionID, (ProgramID<N>, u16, u64)>,
    /// The amendment verifying key map.
    amendment_verifying_key_map: MemoryMap<(ProgramID<N>, Identifier<N>, u16, u64), VerifyingKey<N>>,
    /// The amendment certificate map.
    amendment_certificate_map: MemoryMap<(ProgramID<N>, Identifier<N>, u16, u64), Certificate<N>>,
    /// The amendment owner map.
    amendment_owner_map: MemoryMap<(ProgramID<N>, u16, u64), ProgramOwner<N>>,
}

#[rustfmt::skip]
impl<N: Network> DeploymentStorage<N> for DeploymentMemory<N> {
    type IDMap = MemoryMap<N::TransactionID, ProgramID<N>>;
    type IDEditionMap = MemoryMap<N::TransactionID, u16>;
    type EditionMap = MemoryMap<ProgramID<N>, u16>;
    type ReverseIDMap = MemoryMap<(ProgramID<N>, u16), N::TransactionID>;
    type OwnerMap = MemoryMap<(ProgramID<N>, u16), ProgramOwner<N>>;
    type ProgramMap = MemoryMap<(ProgramID<N>, u16), Program<N>>;
    type ChecksumMap = MemoryMap<(ProgramID<N>, u16), [U8<N>; 32]>;
    type VerifyingKeyMap = MemoryMap<(ProgramID<N>, Identifier<N>, u16), VerifyingKey<N>>;
    type CertificateMap = MemoryMap<(ProgramID<N>, Identifier<N>, u16), Certificate<N>>;
    type FeeStorage = FeeMemory<N>;
    type AmendmentNextIndexMap = MemoryMap<(ProgramID<N>, u16), u64>;
    type AmendmentIDMap = MemoryMap<(ProgramID<N>, u16, u64), N::TransactionID>;
    type ReverseAmendmentIDMap = MemoryMap<N::TransactionID, (ProgramID<N>, u16, u64)>;
    type AmendmentVerifyingKeyMap = MemoryMap<(ProgramID<N>, Identifier<N>, u16, u64), VerifyingKey<N>>;
    type AmendmentCertificateMap = MemoryMap<(ProgramID<N>, Identifier<N>, u16, u64), Certificate<N>>;
    type AmendmentOwnerMap = MemoryMap<(ProgramID<N>, u16, u64), ProgramOwner<N>>;

    /// Initializes the deployment storage.
    fn open(fee_store: FeeStore<N, Self::FeeStorage>) -> Result<Self> {
        Ok(Self {
            id_map: MemoryMap::default(),
            id_edition_map: MemoryMap::default(),
            edition_map: MemoryMap::default(),
            reverse_id_map: MemoryMap::default(),
            owner_map: MemoryMap::default(),
            program_map: MemoryMap::default(),
            checksum_map: MemoryMap::default(),
            verifying_key_map: MemoryMap::default(),
            certificate_map: MemoryMap::default(),
            fee_store,
            amendment_next_index_map: MemoryMap::default(),
            amendment_id_map: MemoryMap::default(),
            reverse_amendment_id_map: MemoryMap::default(),
            amendment_verifying_key_map: MemoryMap::default(),
            amendment_certificate_map: MemoryMap::default(),
            amendment_owner_map: MemoryMap::default(),
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

    /// Returns the owner map.
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

/// An in-memory execution storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct ExecutionMemory<N: Network> {
    /// The ID map.
    id_map: MemoryMap<N::TransactionID, (Vec<N::TransitionID>, bool)>,
    /// The reverse ID map.
    reverse_id_map: MemoryMap<N::TransitionID, N::TransactionID>,
    /// The inclusion map.
    inclusion_map: MemoryMap<N::TransactionID, (N::StateRoot, Option<Proof<N>>)>,
    /// The fee store.
    fee_store: FeeStore<N, FeeMemory<N>>,
}

#[rustfmt::skip]
impl<N: Network> ExecutionStorage<N> for ExecutionMemory<N> {
    type IDMap = MemoryMap<N::TransactionID, (Vec<N::TransitionID>, bool)>;
    type ReverseIDMap = MemoryMap<N::TransitionID, N::TransactionID>;
    type InclusionMap = MemoryMap<N::TransactionID, (N::StateRoot, Option<Proof<N>>)>;
    type FeeStorage = FeeMemory<N>;

    /// Initializes the execution storage.
    fn open(fee_store: FeeStore<N, Self::FeeStorage>) -> Result<Self> {
        Ok(Self {
            id_map: MemoryMap::default(),
            reverse_id_map: MemoryMap::default(),
            inclusion_map: MemoryMap::default(),
            fee_store
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

/// An in-memory fee storage.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct FeeMemory<N: Network> {
    /// The fee map.
    fee_map: MemoryMap<N::TransactionID, (N::TransitionID, N::StateRoot, Option<Proof<N>>)>,
    /// The reverse fee map.
    reverse_fee_map: MemoryMap<N::TransitionID, N::TransactionID>,
    /// The transition store.
    transition_store: TransitionStore<N, TransitionMemory<N>>,
}

#[rustfmt::skip]
impl<N: Network> FeeStorage<N> for FeeMemory<N> {
    type FeeMap = MemoryMap<N::TransactionID, (N::TransitionID, N::StateRoot, Option<Proof<N>>)>;
    type ReverseFeeMap = MemoryMap<N::TransitionID, N::TransactionID>;
    type TransitionStorage = TransitionMemory<N>;

    /// Initializes the fee storage.
    fn open(transition_store: TransitionStore<N, Self::TransitionStorage>) -> Result<Self> {
        Ok(Self {
            fee_map: MemoryMap::default(),
            reverse_fee_map: MemoryMap::default(),
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
