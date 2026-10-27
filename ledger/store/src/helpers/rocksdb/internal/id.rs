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

/// The RocksDB map prefix broken down into the entry category and the specific type of the entry.
// Note: the order of these variants can be changed at any point in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MapID {
    BFT(BFTMap),
    Block(BlockMap),
    Committee(CommitteeMap),
    Deployment(DeploymentMap),
    Execution(ExecutionMap),
    Fee(FeeMap),
    Transaction(TransactionMap),
    Transition(TransitionMap),
    TransitionInput(TransitionInputMap),
    TransitionOutput(TransitionOutputMap),
    Program(ProgramMap),
    Metadata(MetadataMap),
    #[cfg(test)]
    Test(TestMap),
}

impl From<MapID> for u16 {
    fn from(id: MapID) -> u16 {
        match id {
            MapID::BFT(id) => id as u16,
            MapID::Block(id) => id as u16,
            MapID::Committee(id) => id as u16,
            MapID::Deployment(id) => id as u16,
            MapID::Execution(id) => id as u16,
            MapID::Fee(id) => id as u16,
            MapID::Transaction(id) => id as u16,
            MapID::Transition(id) => id as u16,
            MapID::TransitionInput(id) => id as u16,
            MapID::TransitionOutput(id) => id as u16,
            MapID::Program(id) => id as u16,
            MapID::Metadata(id) => id as u16,
            #[cfg(test)]
            MapID::Test(id) => id as u16,
        }
    }
}

/// The RocksDB map prefix for BFT-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BFTMap {
    Transmissions = DataID::BFTTransmissionsMap as u16,
    AbortedTransmissionIDs = DataID::BFTAbortedTransmissionIDsMap as u16,
}

/// The RocksDB map prefix for block-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BlockMap {
    StateRoot = DataID::BlockStateRootMap as u16,
    ReverseStateRoot = DataID::BlockReverseStateRootMap as u16,
    ID = DataID::BlockIDMap as u16,
    ReverseID = DataID::BlockReverseIDMap as u16,
    Header = DataID::BlockHeaderMap as u16,
    Authority = DataID::BlockAuthorityMap as u16,
    Certificate = DataID::BlockCertificateMap as u16,
    Ratifications = DataID::BlockRatificationsMap as u16,
    Solutions = DataID::BlockSolutionsMap as u16,
    PuzzleCommitments = DataID::BlockSolutionIDsMap as u16,
    AbortedSolutionIDs = DataID::BlockAbortedSolutionIDsMap as u16,
    AbortedSolutionHeights = DataID::BlockAbortedSolutionHeightsMap as u16,
    Transactions = DataID::BlockTransactionsMap as u16,
    AbortedTransactionIDs = DataID::BlockAbortedTransactionIDsMap as u16,
    RejectedOrAbortedTransactionID = DataID::BlockRejectedOrAbortedTransactionIDMap as u16,
    ConfirmedTransactions = DataID::BlockConfirmedTransactionsMap as u16,
    RejectedDeploymentOrExecution = DataID::BlockRejectedDeploymentOrExecutionMap as u16,
}

/// The RocksDB map prefix for committee-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CommitteeMap {
    CurrentRound = DataID::CurrentRoundMap as u16,
    RoundToHeight = DataID::RoundToHeightMap as u16,
    Committee = DataID::CommitteeMap as u16,
}

/// The RocksDB map prefix for deployment-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DeploymentMap {
    ID = DataID::DeploymentIDMap as u16,
    IDEdition = DataID::IDEditionMap as u16,
    Edition = DataID::DeploymentEditionMap as u16,
    ReverseID = DataID::DeploymentReverseIDMap as u16,
    Owner = DataID::DeploymentOwnerMap as u16,
    Program = DataID::DeploymentProgramMap as u16,
    Checksum = DataID::DeploymentChecksumMap as u16,
    VerifyingKey = DataID::DeploymentVerifyingKeyMap as u16,
    Certificate = DataID::DeploymentCertificateMap as u16,
    AmendmentNextIndex = DataID::DeploymentAmendmentCountMap as u16,
    AmendmentID = DataID::DeploymentAmendmentIDMap as u16,
    ReverseAmendmentID = DataID::DeploymentReverseAmendmentIDMap as u16,
    AmendmentVerifyingKey = DataID::DeploymentAmendmentVerifyingKeyMap as u16,
    AmendmentCertificate = DataID::DeploymentAmendmentCertificateMap as u16,
    AmendmentOwner = DataID::DeploymentAmendmentOwnerMap as u16,
}

/// The RocksDB map prefix for execution-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExecutionMap {
    ID = DataID::ExecutionIDMap as u16,
    ReverseID = DataID::ExecutionReverseIDMap as u16,
    Inclusion = DataID::ExecutionInclusionMap as u16,
}

/// The RocksDB map prefix for fee-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FeeMap {
    Fee = DataID::FeeFeeMap as u16,
    ReverseFee = DataID::FeeReverseFeeMap as u16,
}

/// The RocksDB map prefix for transition input entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TransitionInputMap {
    ID = DataID::InputIDMap as u16,
    ReverseID = DataID::InputReverseIDMap as u16,
    Constant = DataID::InputConstantMap as u16,
    Public = DataID::InputPublicMap as u16,
    Private = DataID::InputPrivateMap as u16,
    Record = DataID::InputRecordMap as u16,
    RecordTag = DataID::InputRecordTagMap as u16,
    ExternalRecord = DataID::InputExternalRecordMap as u16,
    DynamicRecord = DataID::InputDynamicRecordMap as u16,
    DynamicID = DataID::InputDynamicIDMap as u16,
}

/// The RocksDB map prefix for transition output entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TransitionOutputMap {
    ID = DataID::OutputIDMap as u16,
    ReverseID = DataID::OutputReverseIDMap as u16,
    Constant = DataID::OutputConstantMap as u16,
    Public = DataID::OutputPublicMap as u16,
    Private = DataID::OutputPrivateMap as u16,
    Record = DataID::OutputRecordMap as u16,
    RecordNonce = DataID::OutputRecordNonceMap as u16,
    RecordSender = DataID::OutputRecordSenderMap as u16,
    ExternalRecord = DataID::OutputExternalRecordMap as u16,
    Future = DataID::OutputFutureMap as u16,
    DynamicRecord = DataID::OutputDynamicRecordMap as u16,
    DynamicID = DataID::OutputDynamicIDMap as u16,
}

/// The RocksDB map prefix for transaction-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TransactionMap {
    ID = DataID::TransactionIDMap as u16,
}

/// The RocksDB map prefix for transition-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TransitionMap {
    Locator = DataID::TransitionLocatorMap as u16,
    TPK = DataID::TransitionTPKMap as u16,
    ReverseTPK = DataID::TransitionReverseTPKMap as u16,
    TCM = DataID::TransitionTCMMap as u16,
    ReverseTCM = DataID::TransitionReverseTCMMap as u16,
    SCM = DataID::TransitionSCMMap as u16,
}

/// The RocksDB map prefix for program-related entries.
// Note: the order of these variants can be changed at any point in time,
// as long as the corresponding DataID values remain the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ProgramMap {
    ProgramID = DataID::ProgramIDMap as u16,
    KeyValueID = DataID::KeyValueMap as u16,
    MappingUpdate = DataID::MappingUpdateMap as u16,
    MappingUpdateHeights = DataID::MappingUpdateHeightsMap as u16,
    StakingRewards = DataID::StakingRewardsMap as u16,
    RejectedReason = DataID::RejectedReasonMap as u16,
}

/// The RocksDB map prefix for storage metadata.
///
/// One map holds the well-known metadata keys, so later metadata does not need another `DataID`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MetadataMap {
    Metadata = DataID::StorageMetadataMap as u16,
}

/// The RocksDB map prefix for test-related entries.
// Note: the order of these variants can be changed at any point in time.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TestMap {
    Test = DataID::Test as u16,
    Test2 = DataID::Test2 as u16,
    Test3 = DataID::Test3 as u16,
    Test4 = DataID::Test4 as u16,
    Test5 = DataID::Test5 as u16,
}

/// The RocksDB map prefix.
// Note: the order of these variants can NOT be changed once the database is populated:
// - any new variant MUST be added as the last one (ignoring the Test one)
// - any deprecated variant MUST remain in its position (it can't be removed)
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum DataID {
    // BFT
    BFTTransmissionsMap,
    BFTAbortedTransmissionIDsMap,
    // Block
    BlockStateRootMap,
    BlockReverseStateRootMap,
    BlockIDMap,
    BlockReverseIDMap,
    BlockHeaderMap,
    BlockAuthorityMap,
    BlockCertificateMap,
    BlockRatificationsMap,
    BlockSolutionsMap,
    BlockSolutionIDsMap,
    BlockAbortedSolutionIDsMap,
    BlockAbortedSolutionHeightsMap,
    BlockTransactionsMap,
    BlockAbortedTransactionIDsMap,
    BlockRejectedOrAbortedTransactionIDMap,
    BlockConfirmedTransactionsMap,
    BlockRejectedDeploymentOrExecutionMap,
    // Committee
    CurrentRoundMap,
    RoundToHeightMap,
    CommitteeMap,
    // Deployment
    DeploymentIDMap,
    DeploymentEditionMap,
    DeploymentReverseIDMap,
    DeploymentOwnerMap,
    DeploymentProgramMap,
    DeploymentVerifyingKeyMap,
    DeploymentCertificateMap,
    // Execution
    ExecutionIDMap,
    ExecutionReverseIDMap,
    ExecutionInclusionMap,
    // Fee
    FeeFeeMap,
    FeeReverseFeeMap,
    // Input
    InputIDMap,
    InputReverseIDMap,
    InputConstantMap,
    InputPublicMap,
    InputPrivateMap,
    InputRecordMap,
    InputRecordTagMap,
    InputExternalRecordMap,
    // Output
    OutputIDMap,
    OutputReverseIDMap,
    OutputConstantMap,
    OutputPublicMap,
    OutputPrivateMap,
    OutputRecordMap,
    OutputRecordNonceMap,
    OutputExternalRecordMap,
    OutputFutureMap,
    // Transaction
    TransactionIDMap,
    // Transition
    TransitionLocatorMap,
    TransitionTPKMap,
    TransitionReverseTPKMap,
    TransitionTCMMap,
    TransitionReverseTCMMap,
    TransitionSCMMap,
    // Program
    ProgramIDMap,
    KeyValueMap,

    // For Backwards Compatibility with Existing Databases
    OutputRecordSenderMap,
    // Track edition based on transaction ID
    IDEditionMap,
    // Track deployments that contain an optional checksum
    DeploymentChecksumMap,
    // Historical mappings.
    MappingUpdateMap,
    // Historical mapping update heights.
    MappingUpdateHeightsMap,
    /// Historical staking rewards.
    StakingRewardsMap,

    // Track dynamic record inputs.
    InputDynamicRecordMap,
    // Track dynamic record outputs.
    OutputDynamicRecordMap,

    // Track dynamic IDs for inputs.
    InputDynamicIDMap,
    // Track dynamic IDs for outputs.
    OutputDynamicIDMap,

    // Amendment maps.
    DeploymentAmendmentCountMap,
    DeploymentAmendmentIDMap,
    DeploymentReverseAmendmentIDMap,
    DeploymentAmendmentVerifyingKeyMap,
    DeploymentAmendmentCertificateMap,
    DeploymentAmendmentOwnerMap,

    // Track rejection reasons for rejected transactions
    RejectedReasonMap,

    // Storage metadata: the schema version and the history sync cursor.
    StorageMetadataMap,

    // Testing
    #[cfg(test)]
    Test,
    #[cfg(test)]
    Test2,
    #[cfg(test)]
    Test3,
    #[cfg(test)]
    Test4,
    #[cfg(test)]
    Test5,
}
