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

use crate::{FromBytes, ToBytes, io_error};

use enum_iterator::{Sequence, last};
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use std::io;

/// The different consensus versions.
/// If you need the version active for a specific height, see: `N::CONSENSUS_VERSION`.
///
/// At an upgrade height, snarkOS nodes stop communicating with nodes of a lower
/// `ConsensusVersion` by default. A height of `u32::MAX` is an unscheduled stub and is not an upgrade.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Sequence)]
#[repr(u16)]
pub enum ConsensusVersion {
    /// V1: The initial genesis consensus version.
    V1 = 1,
    /// V2: Update to the block reward and execution cost algorithms.
    V2 = 2,
    /// V3: Update to the number of validators and finalize scope RNG seed.
    V3 = 3,
    /// V4: Update to the Varuna version.
    V4 = 4,
    /// V5: Update to the number of validators and enable batch proposal spend limits.
    V5 = 5,
    /// V6: Update to the number of validators.
    V6 = 6,
    /// V7: Update to program rules.
    V7 = 7,
    /// V8: Update to inclusion version, record commitment version, and introduces sender ciphertexts.
    V8 = 8,
    /// V9: Support for program upgradability.
    V9 = 9,
    /// V10: Lower fees, appropriate record output type checking.
    V10 = 10,
    /// V11: Expand array size limit to 512 and introduce ECDSA signature verification opcodes.
    V11 = 11,
    /// V12: Prevent connection to forked nodes, disable StringType, enable block timestamp.
    V12 = 12,
    /// V13: Introduces external structs.
    V13 = 13,
    /// V14: Increase the program size limit to 512 kB, the transaction size limit to 540 kB,
    ///      the array size limit to 2048, and the `Future` argument bit size to 32 bits.
    ///      Introduces `aleo::GENERATOR`, `aleo::GENERATOR_POWERS`, `snark.verify` opcodes,
    ///      and dynamic dispatch, and identifier literal types.
    V14 = 14,
    /// V15: Introduces the record-existence check and `commit.*.raw` instruction variants.
    ///      Increase the anchor time to 35.
    V15 = 15,
    /// V16: Moves the block's spend limit check to the finalize phase.
    ///      Supports storing of transaction rejection reasons.
    ///      Increase the program size limit to 2048 kB and the transaction size limit to 2304 kB.
    ///      Update the deployment storage cost for programs exceeding 512 kB.
    V16 = 16,
    /// V17: NOTE: V17 landed chronologically on mainnet before it landed on testnet.
    ///      Reverts the anchor time to 25.
    V17 = 17,
    /// V18: Enables native credits record translation, introduces block-wide deployment limits,
    ///      and enforces canonical subDAG certificate ordering.
    V18 = 18,
    /// V19: Reverts from the V18 block-wide synthesis limit to per-transaction
    ///      deployment variable and constraint limits. The first V19 block still
    ///      uses the block-wide synthesis limit.
    V19 = 19,
    /// V20: Adds more accurate type checking for the root call, and bounds the size of every
    /// `PlaintextType` declared in a deployed program.
    V20 = 20,
    /// V21:  Activates Varuna V3.
    V21 = 21,
    /// V22: Increases the maximum number of mappings in a program to 128.
    ///      Lowers the maximum committee size on testnet to 40.
    ///      Modifies the cost of the rand.chacha opcode to a more accurate value.
    V22 = 22,
}

impl ToBytes for ConsensusVersion {
    fn write_le<W: io::Write>(&self, writer: W) -> io::Result<()> {
        (*self as u16).write_le(writer)
    }
}

impl FromBytes for ConsensusVersion {
    fn read_le<R: io::Read>(reader: R) -> io::Result<Self> {
        match u16::read_le(reader)? {
            0 => Err(io_error("Zero is not a valid consensus version")),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            6 => Ok(Self::V6),
            7 => Ok(Self::V7),
            8 => Ok(Self::V8),
            9 => Ok(Self::V9),
            10 => Ok(Self::V10),
            11 => Ok(Self::V11),
            12 => Ok(Self::V12),
            13 => Ok(Self::V13),
            14 => Ok(Self::V14),
            15 => Ok(Self::V15),
            16 => Ok(Self::V16),
            17 => Ok(Self::V17),
            18 => Ok(Self::V18),
            19 => Ok(Self::V19),
            20 => Ok(Self::V20),
            21 => Ok(Self::V21),
            22 => Ok(Self::V22),
            _ => Err(io_error("Invalid consensus version")),
        }
    }
}

impl ConsensusVersion {
    pub fn latest() -> Self {
        last::<ConsensusVersion>().expect("At least one ConsensusVersion should be defined.")
    }
}

impl std::fmt::Display for ConsensusVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use Debug formatting for Display.
        write!(f, "{self:?}")
    }
}

/// The number of consensus versions.
pub(crate) const NUM_CONSENSUS_VERSIONS: usize = enum_iterator::cardinality::<ConsensusVersion>();

/// The consensus version height for `CanaryV0`.
pub const CANARY_V0_CONSENSUS_VERSION_HEIGHTS: [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] = [
    (ConsensusVersion::V1, 0),
    (ConsensusVersion::V2, 2_900_000),
    (ConsensusVersion::V3, 4_560_000),
    (ConsensusVersion::V4, 5_730_000),
    (ConsensusVersion::V5, 5_780_000),
    (ConsensusVersion::V6, 6_240_000),
    (ConsensusVersion::V7, 6_880_000),
    (ConsensusVersion::V8, 7_565_000),
    (ConsensusVersion::V9, 8_028_000),
    (ConsensusVersion::V10, 8_600_000),
    (ConsensusVersion::V11, 9_510_000),
    (ConsensusVersion::V12, 10_030_000),
    (ConsensusVersion::V13, 10_881_000),
    (ConsensusVersion::V14, 11_960_000),
    (ConsensusVersion::V15, u32::MAX),
    (ConsensusVersion::V16, u32::MAX),
    (ConsensusVersion::V17, u32::MAX),
    (ConsensusVersion::V18, u32::MAX),
    (ConsensusVersion::V19, u32::MAX),
    (ConsensusVersion::V20, u32::MAX),
    (ConsensusVersion::V21, u32::MAX),
    (ConsensusVersion::V22, u32::MAX),
];

/// The consensus version height for `MainnetV0`.
pub const MAINNET_V0_CONSENSUS_VERSION_HEIGHTS: [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] = [
    (ConsensusVersion::V1, 0),
    (ConsensusVersion::V2, 2_800_000),
    (ConsensusVersion::V3, 4_900_000),
    (ConsensusVersion::V4, 6_135_000),
    (ConsensusVersion::V5, 7_060_000),
    (ConsensusVersion::V6, 7_560_000),
    (ConsensusVersion::V7, 7_570_000),
    (ConsensusVersion::V8, 9_430_000),
    (ConsensusVersion::V9, 10_272_000),
    (ConsensusVersion::V10, 11_205_000),
    (ConsensusVersion::V11, 12_870_000),
    (ConsensusVersion::V12, 13_815_000),
    (ConsensusVersion::V13, 16_850_000),
    (ConsensusVersion::V14, 17_700_000),
    (ConsensusVersion::V15, 19_264_000),
    (ConsensusVersion::V16, 19_860_000),
    (ConsensusVersion::V17, 19_860_001),
    (ConsensusVersion::V18, 20_794_000),
    (ConsensusVersion::V19, 21_342_000),
    (ConsensusVersion::V20, 22_175_000),
    // Target: October 1, 2026 at 21:00 UTC (2 PM PDT)
    (ConsensusVersion::V21, 22_437_000),
    // Target: October 20, 2026 at ~18:00 UTC
    (ConsensusVersion::V22, 22_962_000),
];

/// The consensus version heights for `TestnetV0`.
pub const TESTNET_V0_CONSENSUS_VERSION_HEIGHTS: [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] = [
    (ConsensusVersion::V1, 0),
    (ConsensusVersion::V2, 2_950_000),
    (ConsensusVersion::V3, 4_800_000),
    (ConsensusVersion::V4, 6_625_000),
    (ConsensusVersion::V5, 6_765_000),
    (ConsensusVersion::V6, 7_600_000),
    (ConsensusVersion::V7, 8_365_000),
    (ConsensusVersion::V8, 9_173_000),
    (ConsensusVersion::V9, 9_800_000),
    (ConsensusVersion::V10, 10_525_000),
    (ConsensusVersion::V11, 11_952_000),
    (ConsensusVersion::V12, 12_669_000),
    (ConsensusVersion::V13, 14_906_000),
    (ConsensusVersion::V14, 15_370_000),
    (ConsensusVersion::V15, 16_886_000),
    (ConsensusVersion::V16, 17_319_000),
    (ConsensusVersion::V17, 18_295_000),
    (ConsensusVersion::V18, 18_296_000),
    (ConsensusVersion::V19, 18_813_000),
    (ConsensusVersion::V20, 19_374_000),
    (ConsensusVersion::V21, 20_234_000),
    // Target: October 13, 2026 at ~08:00 UTC (evening of October 12 PT)
    (ConsensusVersion::V22, 20_415_000),
];

/// The consensus version heights when the `test_consensus_heights` feature is enabled.
// We want each to come immediately after the previous one by default for faster testing.
// Whether activating them all at height 0 is possible is open for investigation.
// If a test needs to stay on one consensus version for a while, consider just locally testing or using a custom `CONSENSUS_VERSION_HEIGHTS` environment variable.
pub const TEST_CONSENSUS_VERSION_HEIGHTS: [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] = [
    (ConsensusVersion::V1, 0),
    (ConsensusVersion::V2, 5),
    (ConsensusVersion::V3, 6),
    (ConsensusVersion::V4, 7),
    (ConsensusVersion::V5, 8),
    (ConsensusVersion::V6, 9),
    (ConsensusVersion::V7, 10),
    (ConsensusVersion::V8, 11),
    (ConsensusVersion::V9, 12),
    (ConsensusVersion::V10, 13),
    (ConsensusVersion::V11, 14),
    (ConsensusVersion::V12, 15),
    (ConsensusVersion::V13, 16),
    (ConsensusVersion::V14, 17),
    (ConsensusVersion::V15, 18),
    (ConsensusVersion::V16, 19),
    (ConsensusVersion::V17, 20),
    (ConsensusVersion::V18, 21),
    (ConsensusVersion::V19, 22),
    (ConsensusVersion::V20, 23),
    (ConsensusVersion::V21, 24),
    (ConsensusVersion::V22, 25),
];

/// Asserts that the given consensus version heights are well-formed.
///
/// A height of `u32::MAX` means the version is unscheduled. Scheduled heights strictly increase,
/// and once a version is unscheduled every later version must also be unscheduled.
#[cfg(any(test, feature = "test", feature = "test_consensus_heights", feature = "wasm"))]
pub(crate) fn verify_consensus_heights(heights: &[(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS]) {
    assert_eq!(heights[0].1, 0, "Genesis height must be 0.");
    for window in heights.windows(2) {
        let ((previous_version, previous_height), (version, height)) = (window[0], window[1]);
        if previous_height == u32::MAX {
            assert!(
                height == u32::MAX,
                "{previous_version:?} is unscheduled, so all later versions must be unscheduled, but {version:?} is at height {height}."
            );
        } else {
            assert!(
                height > previous_height,
                "Scheduled heights must strictly increase, but {previous_version:?} is at height {previous_height} and {version:?} is at height {height}."
            );
        }
    }
}

#[cfg(any(test, feature = "test", feature = "test_consensus_heights"))]
pub fn load_test_consensus_heights() -> [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] {
    // Attempt to read the test consensus heights from the environment variable.
    load_test_consensus_heights_inner(std::env::var("CONSENSUS_VERSION_HEIGHTS").ok())
}

#[cfg(any(test, feature = "test", feature = "test_consensus_heights", feature = "wasm"))]
pub(crate) fn load_test_consensus_heights_inner(
    consensus_version_heights: Option<String>,
) -> [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] {
    // Define consensus version heights container used for testing.
    let mut test_consensus_heights = TEST_CONSENSUS_VERSION_HEIGHTS;

    // If version heights have been specified, verify and return them.
    match consensus_version_heights {
        Some(height_string) => {
            let parsing_error = format!("Expected exactly {NUM_CONSENSUS_VERSIONS} ConsensusVersion heights.");
            // Parse the heights from the environment variable.
            let parsed_test_consensus_heights: [u32; NUM_CONSENSUS_VERSIONS] = height_string
                .replace(" ", "")
                .split(",")
                .map(|height| height.parse::<u32>().expect("Heights should be valid u32 values."))
                .collect::<Vec<u32>>()
                .try_into()
                .expect(&parsing_error);
            // Set the parsed heights in the test consensus heights.
            for (i, height) in parsed_test_consensus_heights.into_iter().enumerate() {
                test_consensus_heights[i] = (TEST_CONSENSUS_VERSION_HEIGHTS[i].0, height);
            }
            // Verify and return the parsed test consensus heights.
            verify_consensus_heights(&test_consensus_heights);
            test_consensus_heights
        }
        None => {
            // Verify and return the default test consensus heights.
            verify_consensus_heights(&test_consensus_heights);
            test_consensus_heights
        }
    }
}

/// Returns the consensus configuration value for the specified height.
///
/// Arguments:
/// - `$network`: The network to use the constant of.
/// - `$constant`: The constant to search a value of.
/// - `$seek_height`: The block height to search the value for.
#[macro_export]
macro_rules! consensus_config_value {
    ($network:ident, $constant:ident, $seek_height:expr) => {
        // Search the consensus version enacted at the specified height.
        $network::CONSENSUS_VERSION($seek_height).map_or(None, |seek_version| {
            // Search the consensus value for the specified version.
            // NOTE: calling `consensus_config_value_by_version!` here would require callers to import both macros.
            match $network::$constant.binary_search_by(|(version, _)| version.cmp(&seek_version)) {
                // If a value was found for this consensus version, return it.
                Ok(index) => Some($network::$constant[index].1),
                // If the specified version was not found exactly, determine whether to return an appropriate value anyway.
                Err(index) => {
                    // This constant is not yet in effect at this consensus version.
                    if index == 0 {
                        None
                    // Return the appropriate value belonging to the consensus version *lower* than the sought version.
                    } else {
                        Some($network::$constant[index - 1].1)
                    }
                }
            }
        })
    };
}

/// Returns the consensus configuration value for the specified ConsensusVersion.
///
/// Arguments:
/// - `$network`: The network to use the constant of.
/// - `$constant`: The constant to search a value of.
/// - `$seek_version`: The ConsensusVersion to search the value for.
#[macro_export]
macro_rules! consensus_config_value_by_version {
    ($network:ident, $constant:ident, $seek_version:expr) => {
        // Search the consensus value for the specified version.
        match $network::$constant.binary_search_by(|(version, _)| version.cmp(&$seek_version)) {
            // If a value was found for this consensus version, return it.
            Ok(index) => Some($network::$constant[index].1),
            // If the specified version was not found exactly, determine whether to return an appropriate value anyway.
            Err(index) => {
                // This constant is not yet in effect at this consensus version.
                if index == 0 {
                    None
                // Return the appropriate value belonging to the consensus version *lower* than the sought version.
                } else {
                    Some($network::$constant[index - 1].1)
                }
            }
        }
    };
}

/// Returns the Varuna version for the specified consensus version.
pub fn varuna_version_from_consensus(consensus_version: ConsensusVersion) -> VarunaVersion {
    // If new varuna versions are added, test_varuna_version_from_consensus below must be updated accordingly.
    if consensus_version >= ConsensusVersion::V21 {
        VarunaVersion::V3
    } else if consensus_version >= ConsensusVersion::V4 {
        VarunaVersion::V2
    } else {
        VarunaVersion::V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanaryV0, MainnetV0, Network, TestnetV0};

    /// Ensure that the consensus constants are defined and correct at genesis.
    /// It is possible this invariant no longer holds in the future, e.g. due to pruning or novel types of constants.
    fn consensus_constants_at_genesis<N: Network>() {
        let height = N::_CONSENSUS_VERSION_HEIGHTS.first().unwrap().1;
        assert_eq!(height, 0);
        let consensus_version = N::_CONSENSUS_VERSION_HEIGHTS.first().unwrap().0;
        assert_eq!(consensus_version, ConsensusVersion::V1);
        assert_eq!(consensus_version as usize, 1);
    }

    /// Ensure that the consensus *versions* are unique, incrementing and start with 1.
    fn consensus_versions<N: Network>() {
        let mut previous_version = N::_CONSENSUS_VERSION_HEIGHTS.first().unwrap().0;
        // Ensure that the consensus versions start with 1.
        assert_eq!(previous_version as usize, 1);
        // Ensure that the consensus versions are unique and incrementing by 1.
        for (version, _) in N::_CONSENSUS_VERSION_HEIGHTS.iter().skip(1) {
            assert_eq!(*version as usize, previous_version as usize + 1);
            previous_version = *version;
        }
        // Ensure that the consensus versions are unique and incrementing.
        let mut previous_version = N::MAX_CERTIFICATES.first().unwrap().0;
        for (version, _) in N::MAX_CERTIFICATES.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::TRANSACTION_SPEND_LIMIT.first().unwrap().0;
        for (version, _) in N::TRANSACTION_SPEND_LIMIT.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::CREDITS_PER_SECOND_OF_RUNTIME.first().unwrap().0;
        for (version, _) in N::CREDITS_PER_SECOND_OF_RUNTIME.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::MAX_ARRAY_ELEMENTS.first().unwrap().0;
        for (version, _) in N::MAX_ARRAY_ELEMENTS.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::MAX_MAPPINGS.first().unwrap().0;
        for (version, _) in N::MAX_MAPPINGS.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::MAX_PROGRAM_SIZE.first().unwrap().0;
        for (version, _) in N::MAX_PROGRAM_SIZE.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::MAX_TRANSACTION_SIZE.first().unwrap().0;
        for (version, _) in N::MAX_TRANSACTION_SIZE.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::MAX_WRITES.first().unwrap().0;
        for (version, _) in N::MAX_WRITES.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
        let mut previous_version = N::ANCHOR_TIMES.first().unwrap().0;
        for (version, _) in N::ANCHOR_TIMES.iter().skip(1) {
            assert!(*version > previous_version);
            previous_version = *version;
        }
    }

    /// Ensure that consensus *heights* are unique and incrementing.
    fn consensus_constants_increasing_heights<N: Network>() {
        let mut previous_height = N::CONSENSUS_VERSION_HEIGHTS().first().unwrap().1;
        for (version, height) in N::CONSENSUS_VERSION_HEIGHTS().iter().skip(1) {
            assert!(*height > previous_height);
            previous_height = *height;
            // Ensure that N::CONSENSUS_VERSION returns the expected value.
            assert_eq!(N::CONSENSUS_VERSION(*height).unwrap(), *version);
            // Ensure that N::CONSENSUS_HEIGHT returns the expected value.
            assert_eq!(N::CONSENSUS_HEIGHT(*version).unwrap(), *height);
        }
    }

    /// Ensure that version of all consensus-relevant constants are present in the consensus version heights.
    fn consensus_constants_valid_heights<N: Network>() {
        for (version, value) in N::MAX_CERTIFICATES.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, MAX_CERTIFICATES, height).unwrap(), *value);
        }
        for (version, value) in N::TRANSACTION_SPEND_LIMIT.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, TRANSACTION_SPEND_LIMIT, height).unwrap(), *value);
        }
        for (version, value) in N::CREDITS_PER_SECOND_OF_RUNTIME.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, CREDITS_PER_SECOND_OF_RUNTIME, height).unwrap(), *value);
        }
        for (version, value) in N::MAX_ARRAY_ELEMENTS.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, MAX_ARRAY_ELEMENTS, height).unwrap(), *value);
        }
        for (version, value) in N::MAX_MAPPINGS.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, MAX_MAPPINGS, height).unwrap(), *value);
        }
        for (version, value) in N::MAX_PROGRAM_SIZE.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, MAX_PROGRAM_SIZE, height).unwrap(), *value);
        }
        for (version, value) in N::MAX_TRANSACTION_SIZE.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, MAX_TRANSACTION_SIZE, height).unwrap(), *value);
        }
        for (version, value) in N::MAX_WRITES.iter() {
            // Ensure that the height at which an update occurs are present in CONSENSUS_VERSION_HEIGHTS.
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| *c_version == *version).unwrap().1;
            // Double-check that consensus_config_value returns the correct value.
            assert_eq!(consensus_config_value!(N, MAX_WRITES, height).unwrap(), *value);
        }
        for (version, value) in N::ANCHOR_TIMES.iter() {
            let height = N::CONSENSUS_VERSION_HEIGHTS().iter().find(|(c_version, _)| c_version == version).unwrap().1;
            assert_eq!(consensus_config_value!(N, ANCHOR_TIMES, height).unwrap(), *value);
        }
    }

    /// Ensure that consensus_config_value returns a valid value for all consensus versions.
    fn consensus_config_returns_some<N: Network>() {
        for (_, height) in N::CONSENSUS_VERSION_HEIGHTS().iter() {
            assert!(consensus_config_value!(N, MAX_CERTIFICATES, *height).is_some());
            assert!(consensus_config_value!(N, TRANSACTION_SPEND_LIMIT, *height).is_some());
            assert!(consensus_config_value!(N, CREDITS_PER_SECOND_OF_RUNTIME, *height).is_some());
            assert!(consensus_config_value!(N, MAX_ARRAY_ELEMENTS, *height).is_some());
            assert!(consensus_config_value!(N, MAX_MAPPINGS, *height).is_some());
            assert!(consensus_config_value!(N, MAX_PROGRAM_SIZE, *height).is_some());
            assert!(consensus_config_value!(N, MAX_TRANSACTION_SIZE, *height).is_some());
            assert!(consensus_config_value!(N, MAX_WRITES, *height).is_some());
            assert!(consensus_config_value!(N, ANCHOR_TIMES, *height).is_some());
        }
    }

    /// Ensure that `MAX_CERTIFICATES` increases and is correctly defined.
    /// See the constant declaration for an explanation why.
    /// The versions in `exempt_versions` are permitted to decrease the value.
    fn max_certificates_increasing<N: Network>(exempt_versions: &[ConsensusVersion]) {
        let mut previous_value = N::MAX_CERTIFICATES.first().unwrap().1;
        for (version, value) in N::MAX_CERTIFICATES.iter().skip(1) {
            if !exempt_versions.contains(version) {
                assert!(*value >= previous_value, "MAX_CERTIFICATES must not decrease at {version:?}");
            }
            previous_value = *value;
        }
    }

    /// Ensure that `MAX_ARRAY_ELEMENTS` increases and is correctly defined.
    /// See the constant declaration for an explanation why.
    fn max_array_elements_increasing<N: Network>() {
        let mut previous_value = N::MAX_ARRAY_ELEMENTS.first().unwrap().1;
        for (_, value) in N::MAX_ARRAY_ELEMENTS.iter().skip(1) {
            assert!(*value >= previous_value);
            previous_value = *value;
        }
    }

    /// Ensure that `MAX_MAPPINGS` increases and is correctly defined.
    fn max_mappings_increasing<N: Network>() {
        let mut previous_value = N::MAX_MAPPINGS.first().unwrap().1;
        for (_, value) in N::MAX_MAPPINGS.iter().skip(1) {
            assert!(*value >= previous_value);
            previous_value = *value;
        }
    }

    /// Ensure that `MAX_TRANSACTION_SIZE` is at least 28KB greater than `MAX_PROGRAM_SIZE` for all consensus versions.
    /// This overhead accounts for proofs, signatures, and other transaction metadata.
    fn transaction_size_exceeds_program_size<N: Network>() {
        const MIN_OVERHEAD: usize = 28_000; // 28 kB minimum overhead

        for (_, height) in N::CONSENSUS_VERSION_HEIGHTS().iter() {
            let max_program_size = consensus_config_value!(N, MAX_PROGRAM_SIZE, *height).unwrap();
            let max_transaction_size = consensus_config_value!(N, MAX_TRANSACTION_SIZE, *height).unwrap();

            assert!(
                max_transaction_size >= max_program_size + MIN_OVERHEAD,
                "At height {height}: MAX_TRANSACTION_SIZE ({max_transaction_size}) must be at least {MIN_OVERHEAD} bytes greater than MAX_PROGRAM_SIZE ({max_program_size})"
            );
        }
    }

    /// Ensure that `MAX_PROGRAM_SIZE` and `MAX_TRANSACTION_SIZE` are defined in lockstep:
    /// the same number of entries, keyed by the same consensus versions in the same order, with the
    /// transaction size strictly exceeding the program size at every version. The latest transaction
    /// size must likewise exceed the latest program size, since a transaction must hold a program
    /// plus its proofs, signatures, and metadata.
    fn program_and_transaction_size_aligned<N: Network>() {
        // Ensure both constants define the same number of entries.
        assert_eq!(
            N::MAX_PROGRAM_SIZE.len(),
            N::MAX_TRANSACTION_SIZE.len(),
            "MAX_PROGRAM_SIZE and MAX_TRANSACTION_SIZE must define the same number of entries"
        );
        // Ensure both constants are keyed by the same consensus versions, in the same order, and that
        // the transaction size exceeds the program size at each corresponding version.
        for (index, (program_version, program_size)) in N::MAX_PROGRAM_SIZE.iter().enumerate() {
            let (transaction_version, transaction_size) = &N::MAX_TRANSACTION_SIZE[index];
            assert_eq!(
                program_version, transaction_version,
                "MAX_PROGRAM_SIZE and MAX_TRANSACTION_SIZE must be keyed by the same consensus version at index {index}, but found {program_version} and {transaction_version}"
            );
            assert!(
                transaction_size > program_size,
                "At consensus version {program_version}: MAX_TRANSACTION_SIZE ({transaction_size}) must be greater than MAX_PROGRAM_SIZE ({program_size})"
            );
        }
        // Ensure the latest transaction size exceeds the latest program size.
        assert!(
            N::LATEST_MAX_TRANSACTION_SIZE() > N::LATEST_MAX_PROGRAM_SIZE(),
            "LATEST_MAX_TRANSACTION_SIZE ({}) must be greater than LATEST_MAX_PROGRAM_SIZE ({})",
            N::LATEST_MAX_TRANSACTION_SIZE(),
            N::LATEST_MAX_PROGRAM_SIZE()
        );
    }

    /// Ensure that the number of constant definitions is the same across networks.
    fn constants_equal_length<N1: Network, N2: Network, N3: Network>() {
        // If we can construct an array, that means the underlying types must be the same.
        let _ = [N1::CONSENSUS_VERSION_HEIGHTS, N2::CONSENSUS_VERSION_HEIGHTS, N3::CONSENSUS_VERSION_HEIGHTS];
        let _ = [N1::MAX_CERTIFICATES, N2::MAX_CERTIFICATES, N3::MAX_CERTIFICATES];
        let _ = [N1::TRANSACTION_SPEND_LIMIT, N2::TRANSACTION_SPEND_LIMIT, N3::TRANSACTION_SPEND_LIMIT];
        let _ =
            [N1::CREDITS_PER_SECOND_OF_RUNTIME, N2::CREDITS_PER_SECOND_OF_RUNTIME, N3::CREDITS_PER_SECOND_OF_RUNTIME];
        let _ = [N1::MAX_ARRAY_ELEMENTS, N2::MAX_ARRAY_ELEMENTS, N3::MAX_ARRAY_ELEMENTS];
        let _ = [N1::MAX_MAPPINGS, N2::MAX_MAPPINGS, N3::MAX_MAPPINGS];
        let _ = [N1::MAX_PROGRAM_SIZE, N2::MAX_PROGRAM_SIZE, N3::MAX_PROGRAM_SIZE];
        let _ = [N1::MAX_TRANSACTION_SIZE, N2::MAX_TRANSACTION_SIZE, N3::MAX_TRANSACTION_SIZE];
        let _ = [N1::MAX_WRITES, N2::MAX_WRITES, N3::MAX_WRITES];
        let _ = [N1::ANCHOR_TIMES, N2::ANCHOR_TIMES, N3::ANCHOR_TIMES];
    }

    /// Ensure that `LATEST_MAX_*` functions return valid values without panicking.
    /// These functions use `.expect()` internally, so this test verifies the arrays are non-empty.
    fn latest_max_functions_are_safe<N: Network>() {
        // Verify LATEST_MAX_CERTIFICATES returns a positive value.
        assert!(N::LATEST_MAX_CERTIFICATES() > 0, "LATEST_MAX_CERTIFICATES must be positive");
        // Verify LATEST_MAX_MAPPINGS returns a positive value.
        assert!(N::LATEST_MAX_MAPPINGS() > 0, "LATEST_MAX_MAPPINGS must be positive");
        // Verify LATEST_MAX_PROGRAM_SIZE returns a positive value.
        assert!(N::LATEST_MAX_PROGRAM_SIZE() > 0, "LATEST_MAX_PROGRAM_SIZE must be positive");
        // Verify LATEST_MAX_TRANSACTION_SIZE returns a positive value.
        assert!(N::LATEST_MAX_TRANSACTION_SIZE() > 0, "LATEST_MAX_TRANSACTION_SIZE must be positive");
        // Verify LATEST_MAX_WRITES returns a positive value.
        assert!(N::LATEST_MAX_WRITES() > 0, "LATEST_MAX_WRITES must be positive");
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_consensus_constants() {
        consensus_constants_at_genesis::<MainnetV0>();
        consensus_constants_at_genesis::<TestnetV0>();
        consensus_constants_at_genesis::<CanaryV0>();

        consensus_versions::<MainnetV0>();
        consensus_versions::<TestnetV0>();
        consensus_versions::<CanaryV0>();

        consensus_constants_increasing_heights::<MainnetV0>();
        consensus_constants_increasing_heights::<TestnetV0>();
        consensus_constants_increasing_heights::<CanaryV0>();

        consensus_constants_valid_heights::<MainnetV0>();
        consensus_constants_valid_heights::<TestnetV0>();
        consensus_constants_valid_heights::<CanaryV0>();

        consensus_config_returns_some::<MainnetV0>();
        consensus_config_returns_some::<TestnetV0>();
        consensus_config_returns_some::<CanaryV0>();

        max_certificates_increasing::<MainnetV0>(&[]);
        // Testnet lowers the maximum committee size at `V22`.
        max_certificates_increasing::<TestnetV0>(&[ConsensusVersion::V22]);
        max_certificates_increasing::<CanaryV0>(&[]);

        max_array_elements_increasing::<MainnetV0>();
        max_array_elements_increasing::<TestnetV0>();
        max_array_elements_increasing::<CanaryV0>();

        max_mappings_increasing::<MainnetV0>();
        max_mappings_increasing::<TestnetV0>();
        max_mappings_increasing::<CanaryV0>();

        transaction_size_exceeds_program_size::<MainnetV0>();
        transaction_size_exceeds_program_size::<TestnetV0>();
        transaction_size_exceeds_program_size::<CanaryV0>();

        program_and_transaction_size_aligned::<MainnetV0>();
        program_and_transaction_size_aligned::<TestnetV0>();
        program_and_transaction_size_aligned::<CanaryV0>();

        latest_max_functions_are_safe::<MainnetV0>();
        latest_max_functions_are_safe::<TestnetV0>();
        latest_max_functions_are_safe::<CanaryV0>();

        constants_equal_length::<MainnetV0, TestnetV0, CanaryV0>();
    }

    /// Ensure (de-)serialization works correctly.
    #[test]
    fn test_to_bytes() {
        let version = ConsensusVersion::V8;
        let bytes = version.to_bytes_le().unwrap();
        let result = ConsensusVersion::from_bytes_le(&bytes).unwrap();
        assert_eq!(result, version);

        let version = ConsensusVersion::latest();
        let bytes = version.to_bytes_le().unwrap();
        let result = ConsensusVersion::from_bytes_le(&bytes).unwrap();
        assert_eq!(result, version);

        let invalid_bytes = u16::MAX.to_bytes_le().unwrap();
        let result = ConsensusVersion::from_bytes_le(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_reward_anchor_time() {
        assert_eq!(MainnetV0::REWARD_ANCHOR_TIME, MainnetV0::ANCHOR_TIMES.first().unwrap().1);
        assert_eq!(TestnetV0::REWARD_ANCHOR_TIME, TestnetV0::ANCHOR_TIMES.first().unwrap().1);
        assert_eq!(CanaryV0::REWARD_ANCHOR_TIME, CanaryV0::ANCHOR_TIMES.first().unwrap().1);
    }

    #[test]
    fn test_varuna_version_from_consensus() {
        // Check that all consensus versions map to a valid Varuna version.
        for consensus_version in enum_iterator::all::<ConsensusVersion>() {
            let varuna_version = varuna_version_from_consensus(consensus_version);
            let valid = match varuna_version {
                VarunaVersion::V1 => consensus_version < ConsensusVersion::V4,
                VarunaVersion::V2 => (ConsensusVersion::V4..ConsensusVersion::V21).contains(&consensus_version),
                VarunaVersion::V3 => consensus_version >= ConsensusVersion::V21,
            };
            assert!(valid, "{consensus_version:?} incorrectly maps to {varuna_version:?}");
        }

        // Add spot checks.
        assert_eq!(varuna_version_from_consensus(ConsensusVersion::V3), VarunaVersion::V1);
        assert_eq!(varuna_version_from_consensus(ConsensusVersion::V4), VarunaVersion::V2);
        assert_eq!(varuna_version_from_consensus(ConsensusVersion::V20), VarunaVersion::V2);
        assert_eq!(varuna_version_from_consensus(ConsensusVersion::V21), VarunaVersion::V3);
        assert_eq!(varuna_version_from_consensus(ConsensusVersion::V22), VarunaVersion::V3);
    }

    /// Ensure that every published consensus height table is well-formed.
    #[test]
    fn test_published_consensus_heights_are_valid() {
        verify_consensus_heights(&CANARY_V0_CONSENSUS_VERSION_HEIGHTS);
        verify_consensus_heights(&MAINNET_V0_CONSENSUS_VERSION_HEIGHTS);
        verify_consensus_heights(&TESTNET_V0_CONSENSUS_VERSION_HEIGHTS);
        verify_consensus_heights(&TEST_CONSENSUS_VERSION_HEIGHTS);
    }

    /// Renders the default test heights as a `CONSENSUS_VERSION_HEIGHTS` string, with the given overrides applied.
    fn test_heights_string(overrides: &[(usize, u32)]) -> String {
        let mut heights = TEST_CONSENSUS_VERSION_HEIGHTS.map(|(_, height)| height);
        for (index, height) in overrides {
            heights[*index] = *height;
        }
        heights.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
    }

    /// Ensure that a decreasing height is rejected.
    #[test]
    #[should_panic(expected = "must strictly increase")]
    fn test_consensus_heights_reject_decreasing() {
        load_test_consensus_heights_inner(Some(test_heights_string(&[(2, 4)])));
    }

    /// Ensure that a duplicated height is rejected.
    #[test]
    #[should_panic(expected = "must strictly increase")]
    fn test_consensus_heights_reject_duplicate() {
        load_test_consensus_heights_inner(Some(test_heights_string(&[(2, 5)])));
    }

    /// Ensure that a scheduled version following an unscheduled one is rejected.
    #[test]
    #[should_panic(expected = "all later versions must be unscheduled")]
    fn test_consensus_heights_reject_scheduled_after_unscheduled() {
        load_test_consensus_heights_inner(Some(test_heights_string(&[(18, u32::MAX)])));
    }

    /// Ensure that a trailing run of unscheduled versions is accepted.
    #[test]
    fn test_consensus_heights_accept_trailing_unscheduled() {
        let heights = load_test_consensus_heights_inner(Some(test_heights_string(&[
            (18, u32::MAX),
            (19, u32::MAX),
            (20, u32::MAX),
            (21, u32::MAX),
        ])));
        assert_eq!(heights[17].1, 21);
        assert_eq!(heights[18].1, u32::MAX);
        assert_eq!(heights[19].1, u32::MAX);
        assert_eq!(heights[20].1, u32::MAX);
        assert_eq!(heights[21].1, u32::MAX);
    }
}
