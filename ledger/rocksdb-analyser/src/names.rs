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

use snarkvm_ledger_store::helpers::rocksdb::{
    BFTMap,
    BlockMap,
    CommitteeMap,
    DeploymentMap,
    ExecutionMap,
    FeeMap,
    ProgramMap,
    TransactionMap,
    TransitionInputMap,
    TransitionMap,
    TransitionOutputMap,
};

use std::{collections::HashMap, sync::LazyLock};

/// Returns the ledger map name for a RocksDB map id, when the id is one this crate knows.
pub fn map_label(map_id: u16) -> Option<&'static str> {
    LABELS.get(&map_id).copied()
}

fn label_pairs() -> Vec<(u16, &'static str)> {
    let mut pairs = Vec::with_capacity(77);
    pairs.extend(bft_labels());
    pairs.extend(block_labels());
    pairs.extend(committee_labels());
    pairs.extend(deployment_labels());
    pairs.extend(execution_labels());
    pairs.extend(fee_labels());
    pairs.extend(input_labels());
    pairs.extend(output_labels());
    pairs.extend(transaction_labels());
    pairs.extend(transition_labels());
    pairs.extend(program_labels());
    pairs
}

fn bft_labels() -> [(u16, &'static str); 2] {
    [
        (BFTMap::Transmissions as u16, "BFT::Transmissions"),
        (BFTMap::AbortedTransmissionIDs as u16, "BFT::AbortedTransmissionIDs"),
    ]
}

fn block_labels() -> [(u16, &'static str); 17] {
    [
        (BlockMap::StateRoot as u16, "Block::StateRoot"),
        (BlockMap::ReverseStateRoot as u16, "Block::ReverseStateRoot"),
        (BlockMap::ID as u16, "Block::ID"),
        (BlockMap::ReverseID as u16, "Block::ReverseID"),
        (BlockMap::Header as u16, "Block::Header"),
        (BlockMap::Authority as u16, "Block::Authority"),
        (BlockMap::Certificate as u16, "Block::Certificate"),
        (BlockMap::Ratifications as u16, "Block::Ratifications"),
        (BlockMap::Solutions as u16, "Block::Solutions"),
        (BlockMap::PuzzleCommitments as u16, "Block::PuzzleCommitments"),
        (BlockMap::AbortedSolutionIDs as u16, "Block::AbortedSolutionIDs"),
        (BlockMap::AbortedSolutionHeights as u16, "Block::AbortedSolutionHeights"),
        (BlockMap::Transactions as u16, "Block::Transactions"),
        (BlockMap::AbortedTransactionIDs as u16, "Block::AbortedTransactionIDs"),
        (BlockMap::RejectedOrAbortedTransactionID as u16, "Block::RejectedOrAbortedTransactionID"),
        (BlockMap::ConfirmedTransactions as u16, "Block::ConfirmedTransactions"),
        (BlockMap::RejectedDeploymentOrExecution as u16, "Block::RejectedDeploymentOrExecution"),
    ]
}

fn committee_labels() -> [(u16, &'static str); 3] {
    [
        (CommitteeMap::CurrentRound as u16, "Committee::CurrentRound"),
        (CommitteeMap::RoundToHeight as u16, "Committee::RoundToHeight"),
        (CommitteeMap::Committee as u16, "Committee::Committee"),
    ]
}

fn deployment_labels() -> [(u16, &'static str); 15] {
    [
        (DeploymentMap::ID as u16, "Deployment::ID"),
        (DeploymentMap::IDEdition as u16, "Deployment::IDEdition"),
        (DeploymentMap::Edition as u16, "Deployment::Edition"),
        (DeploymentMap::ReverseID as u16, "Deployment::ReverseID"),
        (DeploymentMap::Owner as u16, "Deployment::Owner"),
        (DeploymentMap::Program as u16, "Deployment::Program"),
        (DeploymentMap::Checksum as u16, "Deployment::Checksum"),
        (DeploymentMap::VerifyingKey as u16, "Deployment::VerifyingKey"),
        (DeploymentMap::Certificate as u16, "Deployment::Certificate"),
        (DeploymentMap::AmendmentNextIndex as u16, "Deployment::AmendmentNextIndex"),
        (DeploymentMap::AmendmentID as u16, "Deployment::AmendmentID"),
        (DeploymentMap::ReverseAmendmentID as u16, "Deployment::ReverseAmendmentID"),
        (DeploymentMap::AmendmentVerifyingKey as u16, "Deployment::AmendmentVerifyingKey"),
        (DeploymentMap::AmendmentCertificate as u16, "Deployment::AmendmentCertificate"),
        (DeploymentMap::AmendmentOwner as u16, "Deployment::AmendmentOwner"),
    ]
}

fn execution_labels() -> [(u16, &'static str); 3] {
    [
        (ExecutionMap::ID as u16, "Execution::ID"),
        (ExecutionMap::ReverseID as u16, "Execution::ReverseID"),
        (ExecutionMap::Inclusion as u16, "Execution::Inclusion"),
    ]
}

fn fee_labels() -> [(u16, &'static str); 2] {
    [(FeeMap::Fee as u16, "Fee::Fee"), (FeeMap::ReverseFee as u16, "Fee::ReverseFee")]
}

fn input_labels() -> [(u16, &'static str); 10] {
    [
        (TransitionInputMap::ID as u16, "TransitionInput::ID"),
        (TransitionInputMap::ReverseID as u16, "TransitionInput::ReverseID"),
        (TransitionInputMap::Constant as u16, "TransitionInput::Constant"),
        (TransitionInputMap::Public as u16, "TransitionInput::Public"),
        (TransitionInputMap::Private as u16, "TransitionInput::Private"),
        (TransitionInputMap::Record as u16, "TransitionInput::Record"),
        (TransitionInputMap::RecordTag as u16, "TransitionInput::RecordTag"),
        (TransitionInputMap::ExternalRecord as u16, "TransitionInput::ExternalRecord"),
        (TransitionInputMap::DynamicRecord as u16, "TransitionInput::DynamicRecord"),
        (TransitionInputMap::DynamicID as u16, "TransitionInput::DynamicID"),
    ]
}

fn output_labels() -> [(u16, &'static str); 12] {
    [
        (TransitionOutputMap::ID as u16, "TransitionOutput::ID"),
        (TransitionOutputMap::ReverseID as u16, "TransitionOutput::ReverseID"),
        (TransitionOutputMap::Constant as u16, "TransitionOutput::Constant"),
        (TransitionOutputMap::Public as u16, "TransitionOutput::Public"),
        (TransitionOutputMap::Private as u16, "TransitionOutput::Private"),
        (TransitionOutputMap::Record as u16, "TransitionOutput::Record"),
        (TransitionOutputMap::RecordNonce as u16, "TransitionOutput::RecordNonce"),
        (TransitionOutputMap::RecordSender as u16, "TransitionOutput::RecordSender"),
        (TransitionOutputMap::ExternalRecord as u16, "TransitionOutput::ExternalRecord"),
        (TransitionOutputMap::Future as u16, "TransitionOutput::Future"),
        (TransitionOutputMap::DynamicRecord as u16, "TransitionOutput::DynamicRecord"),
        (TransitionOutputMap::DynamicID as u16, "TransitionOutput::DynamicID"),
    ]
}

fn transaction_labels() -> [(u16, &'static str); 1] {
    [(TransactionMap::ID as u16, "Transaction::ID")]
}

fn transition_labels() -> [(u16, &'static str); 6] {
    [
        (TransitionMap::Locator as u16, "Transition::Locator"),
        (TransitionMap::TPK as u16, "Transition::TPK"),
        (TransitionMap::ReverseTPK as u16, "Transition::ReverseTPK"),
        (TransitionMap::TCM as u16, "Transition::TCM"),
        (TransitionMap::ReverseTCM as u16, "Transition::ReverseTCM"),
        (TransitionMap::SCM as u16, "Transition::SCM"),
    ]
}

fn program_labels() -> [(u16, &'static str); 6] {
    [
        (ProgramMap::ProgramID as u16, "Program::ProgramID"),
        (ProgramMap::KeyValueID as u16, "Program::KeyValueID"),
        (ProgramMap::MappingUpdate as u16, "Program::MappingUpdate"),
        (ProgramMap::MappingUpdateHeights as u16, "Program::MappingUpdateHeights"),
        (ProgramMap::StakingRewards as u16, "Program::StakingRewards"),
        (ProgramMap::RejectedReason as u16, "Program::RejectedReason"),
    ]
}

static LABELS: LazyLock<HashMap<u16, &'static str>> = LazyLock::new(|| {
    let pairs = label_pairs();
    let mut labels = HashMap::with_capacity(pairs.len());
    for (id, label) in pairs {
        labels.insert(id, label);
    }
    labels
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_map_id_is_unique() {
        let pairs = label_pairs();
        let mut ids = HashMap::new();
        for (id, label) in pairs {
            assert!(ids.insert(id, label).is_none(), "duplicate map id {id}");
        }
        assert_eq!(ids.len(), 77);
        assert_eq!(map_label(BlockMap::Header as u16), Some("Block::Header"));
        assert_eq!(map_label(ProgramMap::KeyValueID as u16), Some("Program::KeyValueID"));
        assert_eq!(map_label(u16::MAX), None);
    }
}
