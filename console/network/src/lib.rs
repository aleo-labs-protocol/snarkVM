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
#![allow(clippy::too_many_arguments)]
#![warn(clippy::cast_possible_truncation)]

#[macro_use]
extern crate lazy_static;

pub use snarkvm_console_network_environment as environment;
pub use snarkvm_console_network_environment::*;

mod helpers;
pub use helpers::*;

/// Checks `file` against the shipped proving key file for `credits.aleo/{$function_name}` in the
/// `snarkvm_parameters` module `$network`, as `Network::verify_credits_proving_key_file` does.
macro_rules! verify_credits_proving_key_file {
    ($network:ident, $function_name:expr, $file:expr) => {{
        use snarkvm_parameters::$network::*;
        match $function_name {
            "bond_public" => BondPublicProver::verify_bytes($file)?,
            "bond_validator" => BondValidatorProver::verify_bytes($file)?,
            "unbond_public" => UnbondPublicProver::verify_bytes($file)?,
            "claim_unbond_public" => ClaimUnbondPublicProver::verify_bytes($file)?,
            "set_validator_state" => SetValidatorStateProver::verify_bytes($file)?,
            "transfer_private" => TransferPrivateProver::verify_bytes($file)?,
            "transfer_public" => TransferPublicProver::verify_bytes($file)?,
            "transfer_public_as_signer" => TransferPublicAsSignerProver::verify_bytes($file)?,
            "transfer_private_to_public" => TransferPrivateToPublicProver::verify_bytes($file)?,
            "transfer_public_to_private" => TransferPublicToPrivateProver::verify_bytes($file)?,
            "join" => JoinProver::verify_bytes($file)?,
            "split" => SplitProver::verify_bytes($file)?,
            "fee_private" => FeePrivateProver::verify_bytes($file)?,
            "fee_public" => FeePublicProver::verify_bytes($file)?,
            "upgrade" => UpgradeProver::verify_bytes($file)?,
            function_name => bail!("'credits.aleo/{function_name}' has no proving key file"),
        }
        Ok(())
    }};
}

mod canary_v0;
pub use canary_v0::*;

mod consensus_heights;
pub use consensus_heights::*;

mod mainnet_v0;
pub use mainnet_v0::*;

mod testnet_v0;

pub use testnet_v0::*;

pub mod prelude {
    #[cfg(feature = "wasm")]
    pub use crate::get_or_init_consensus_version_heights;
    pub use crate::{
        CANARY_V0_CONSENSUS_VERSION_HEIGHTS,
        CanaryV0,
        ConsensusVersion,
        MAINNET_V0_CONSENSUS_VERSION_HEIGHTS,
        MainnetV0,
        Network,
        TEST_CONSENSUS_VERSION_HEIGHTS,
        TESTNET_V0_CONSENSUS_VERSION_HEIGHTS,
        TestnetV0,
        consensus_config_value,
        consensus_config_value_by_version,
        environment::prelude::*,
    };
}

pub use crate::environment::prelude::*;

use snarkvm_algorithms::{
    AlgebraicSponge,
    crypto_hash::PoseidonSponge,
    snark::varuna::{CircuitProvingKey, CircuitVerifyingKey, VarunaHidingMode},
    srs::{UniversalProver, UniversalVerifier},
};
use snarkvm_console_algorithms::{BHP512, BHP1024, Poseidon2, Poseidon4, Poseidon8};
use snarkvm_console_collections::merkle_tree::{MerklePath, MerkleTree};
use snarkvm_console_types::{Field, Group, Scalar};
use snarkvm_curves::PairingEngine;

use snarkvm_algorithms::polycommit::kzg10::UniversalParams;

use indexmap::IndexMap;
use std::sync::{Arc, OnceLock};

pub use snarkvm_console_collections::merkle_tree::MerkleTreeState;

/// A helper type for the BHP Merkle tree.
pub type BHPMerkleTree<N, const DEPTH: u8> = MerkleTree<N, BHP1024<N>, BHP512<N>, DEPTH>;
/// A helper type for the Poseidon Merkle tree.
pub type PoseidonMerkleTree<N, const DEPTH: u8> = MerkleTree<N, Poseidon4<N>, Poseidon2<N>, DEPTH>;

/// Helper types for the Varuna parameters.
type Fq<N> = <<N as Environment>::PairingCurve as PairingEngine>::Fq;
pub type FiatShamir<N> = PoseidonSponge<Fq<N>, 2, 1>;
pub type FiatShamirParameters<N> = <FiatShamir<N> as AlgebraicSponge<Fq<N>, 2>>::Parameters;

/// Helper types for the Varuna proving and verifying key.
pub(crate) type VarunaProvingKey<N> = CircuitProvingKey<<N as Environment>::PairingCurve, VarunaHidingMode>;
pub(crate) type VarunaVerifyingKey<N> = CircuitVerifyingKey<<N as Environment>::PairingCurve>;

/// A list of consensus versions and their corresponding block heights.
static CONSENSUS_VERSION_HEIGHTS: OnceLock<[(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS]> = OnceLock::new();

pub trait Network:
    'static
    + Environment
    + Copy
    + Clone
    + Debug
    + Eq
    + PartialEq
    + core::hash::Hash
    + Serialize
    + DeserializeOwned
    + for<'a> Deserialize<'a>
    + Send
    + Sync
{
    /// The network ID.
    const ID: u16;
    /// The (long) network name.
    const NAME: &'static str;
    /// The short network name (used, for example, in query URLs).
    const SHORT_NAME: &'static str;

    /// The function name for the inclusion circuit.
    const INCLUSION_FUNCTION_NAME: &'static str;

    /// The fixed timestamp of the genesis block.
    const GENESIS_TIMESTAMP: i64;
    /// The genesis block coinbase target.
    const GENESIS_COINBASE_TARGET: u64;
    /// The genesis block proof target.
    const GENESIS_PROOF_TARGET: u64;
    /// The maximum number of solutions that can be included per block as a power of 2.
    const MAX_SOLUTIONS_AS_POWER_OF_TWO: u8 = 2; // 4 solutions
    /// The maximum number of solutions that can be included per block.
    const MAX_SOLUTIONS: usize = 1 << Self::MAX_SOLUTIONS_AS_POWER_OF_TWO; // 4 solutions

    /// The starting supply of Aleo credits.
    const STARTING_SUPPLY: u64 = 1_500_000_000_000_000; // 1.5B credits
    /// The maximum supply of Aleo credits.
    /// This value represents the absolute upper bound on all ALEO created over the lifetime of the network.
    const MAX_SUPPLY: u64 = 5_000_000_000_000_000; // 5B credits
    /// The block height that upper bounds the total supply of Aleo credits to 5 billion.
    #[cfg(not(feature = "test"))]
    const MAX_SUPPLY_LIMIT_HEIGHT: u32 = 263_527_685;
    /// The block height that upper bounds the total supply of Aleo credits to 5 billion.
    /// This is deliberately set to a low value for testing purposes only.
    #[cfg(feature = "test")]
    const MAX_SUPPLY_LIMIT_HEIGHT: u32 = 5;
    /// The cost in microcredits per byte for the deployment transaction.
    const DEPLOYMENT_FEE_MULTIPLIER: u64 = 1_000; // 1 millicredit per byte
    /// The multiplier in microcredits for each command in the constructor.
    const CONSTRUCTOR_FEE_MULTIPLIER: u64 = 100; // 100x per command
    /// The constant that divides the storage polynomial.
    const EXECUTION_STORAGE_FEE_SCALING_FACTOR: u64 = 5000;
    /// The maximum size execution transactions can be before a quadratic storage penalty applies.
    const EXECUTION_STORAGE_PENALTY_THRESHOLD: u64 = 5000;
    /// The cost in microcredits per constraint for the deployment transaction.
    const SYNTHESIS_FEE_MULTIPLIER: u64 = 25; // 25 microcredits per constraint
    /// The maximum number of variables in a deployment. This limit was enforced at the transaction level up to
    /// consensus version V17 (inclusive), skipped at V18 in favor of a block-wide synthesis limit, and
    /// replaced by `MAX_DEPLOYMENT_VARIABLES_V2` from V19. This corresponds to ~0.5 second single-threaded
    /// runtime at mainnet launch reference validator hardware.
    const MAX_DEPLOYMENT_VARIABLES: u64 = 1 << 21; // 2,097,152 variables
    /// The maximum number of constraints in a deployment. This limit was enforced at the transaction level up to
    /// consensus version V17 (inclusive), skipped at V18 in favor of a block-wide synthesis limit, and
    /// replaced by `MAX_DEPLOYMENT_CONSTRAINTS_V2` from V19. This corresponds to ~0.5 second single-threaded
    /// runtime at mainnet launch reference validator hardware.
    const MAX_DEPLOYMENT_CONSTRAINTS: u64 = 1 << 21; // 2,097,152 constraints
    /// The maximum number of variables in a deployment. Enforced at the transaction level from consensus
    /// version V19.
    const MAX_DEPLOYMENT_VARIABLES_V2: u64 = 1 << 22; // 4,194,304 variables
    /// The maximum number of constraints in a deployment. Enforced at the transaction level from consensus
    /// version V19.
    const MAX_DEPLOYMENT_CONSTRAINTS_V2: u64 = 1 << 22; // 4,194,304 constraints
    /// Approximate conversion factor from non-zero circuit entries to seconds of certificate-verification work
    /// when checking a deployment. From it, a per-proposal synthesis limit is enforced at consensus
    /// version V18 which overrides the two per-transaction limits above.
    const SYNTHESIS_PER_SECOND_OF_RUNTIME: u64 = 1_500_000;
    const MAX_BATCH_PROOF_INSTANCES: usize = 128;
    /// The maximum number of microcredits that can be spent as a fee.
    const MAX_FEE: u64 = 1_000_000_000_000_000;
    /// A list of consensus versions and their corresponding transaction spend limits in microcredits.
    //  Note: This value must **not** decrease without considering the impact on transaction validity.
    const TRANSACTION_SPEND_LIMIT: [(ConsensusVersion, u64); 2] =
        [(ConsensusVersion::V1, 100_000_000), (ConsensusVersion::V10, 4_000_000)];
    /// The compute discount approved by ARC 0005.
    const ARC_0005_COMPUTE_DISCOUNT: u64 =
        Self::CREDITS_PER_SECOND_OF_RUNTIME[0].1 / Self::CREDITS_PER_SECOND_OF_RUNTIME[1].1;
    /// The number of microcredits representing a second of runtime.
    const CREDITS_PER_SECOND_OF_RUNTIME: [(ConsensusVersion, u64); 2] =
        [(ConsensusVersion::V1, 100_000_000), (ConsensusVersion::V10, 4_000_000)];

    /// The anchor height, defined as the expected number of blocks to reach the coinbase target.
    /// Note: The anchor height used exclusively by `coinbase_reward_v1`.
    const ANCHOR_HEIGHT: u32 = Self::REWARD_ANCHOR_TIME as u32 / Self::BLOCK_TIME as u32;
    /// The anchor time used specifically for calculating the coinbase reward.
    /// We ensure that the reward anchor time matches the original ConsensusVersion::V1 anchor time
    /// to maintain the original coinbase reward schedule.
    const REWARD_ANCHOR_TIME: u16 = 25;
    /// A list of (consensus_version, anchor_time_in_seconds) pairs (sparse).
    /// Each entry takes effect at the specified version and remains active until the next entry.
    /// The anchor time, defined as the expected time in seconds to reach the coinbase target.
    const ANCHOR_TIMES: [(ConsensusVersion, u16); 3] = [
        (ConsensusVersion::V1, Self::REWARD_ANCHOR_TIME),
        (ConsensusVersion::V15, 35),
        (ConsensusVersion::V17, Self::REWARD_ANCHOR_TIME),
    ];
    /// The expected time per block in seconds.
    const BLOCK_TIME: u16 = 10;
    /// The number of blocks per epoch.
    #[cfg(not(feature = "test"))]
    const NUM_BLOCKS_PER_EPOCH: u32 = 3600 / Self::BLOCK_TIME as u32; // 360 blocks == ~1 hour
    /// The number of blocks per epoch.
    /// This is deliberately set to a low value for testing purposes only.
    #[cfg(feature = "test")]
    const NUM_BLOCKS_PER_EPOCH: u32 = 10;

    /// The maximum number of entries in data.
    const MAX_DATA_ENTRIES: usize = 32;
    /// The maximum recursive depth of an entry.
    /// Note: This value must be strictly less than u8::MAX.
    const MAX_DATA_DEPTH: usize = 32;
    /// The maximum number of fields in data (must not exceed u16::MAX).
    #[allow(clippy::cast_possible_truncation)]
    const MAX_DATA_SIZE_IN_FIELDS: u32 = ((128 * 1024 * 8) / Field::<Self>::SIZE_IN_DATA_BITS) as u32;
    /// A list of (consensus_version, size) pairs indicating the maximum size in bits of any single
    /// `PlaintextType` declared in a program. This mirrors the runtime budget `to_fields` enforces.
    const MAX_PLAINTEXT_TYPE_SIZE_IN_BITS: [(ConsensusVersion, usize); 1] =
        [(ConsensusVersion::V20, Self::MAX_DATA_SIZE_IN_FIELDS as usize * Field::<Self>::SIZE_IN_DATA_BITS)];

    /// The minimum number of entries in a struct.
    const MIN_STRUCT_ENTRIES: usize = 1; // This ensures the struct is not empty.
    /// The maximum number of entries in a struct.
    const MAX_STRUCT_ENTRIES: usize = Self::MAX_DATA_ENTRIES;

    /// The minimum number of elements in an array.
    const MIN_ARRAY_ELEMENTS: usize = 1; // This ensures the array is not empty.
    ///  A list of (consensus_version, size) pairs indicating the maximum number of elements in an array.
    const MAX_ARRAY_ELEMENTS: [(ConsensusVersion, usize); 3] =
        [(ConsensusVersion::V1, 32), (ConsensusVersion::V11, 512), (ConsensusVersion::V14, 2048)];

    /// The minimum number of entries in a record.
    const MIN_RECORD_ENTRIES: usize = 1; // This accounts for 'record.owner'.
    /// The maximum number of entries in a record.
    const MAX_RECORD_ENTRIES: usize = Self::MIN_RECORD_ENTRIES.saturating_add(Self::MAX_DATA_ENTRIES);

    /// The maximum program size by number of characters.
    const MAX_PROGRAM_SIZE: [(ConsensusVersion, usize); 3] = [
        (ConsensusVersion::V1, 100_000),    // 100 kB
        (ConsensusVersion::V14, 512_000),   // 512 kB
        (ConsensusVersion::V16, 2_048_000), // 2048 kB
    ];
    /// A list of consensus versions and their corresponding maximum number of mappings in a program.
    const MAX_MAPPINGS: [(ConsensusVersion, usize); 2] = [(ConsensusVersion::V1, 31), (ConsensusVersion::V22, 128)];
    /// The maximum number of functions in a program.
    const MAX_FUNCTIONS: usize = 31;
    /// The maximum number of structs in a program.
    const MAX_STRUCTS: usize = 10 * Self::MAX_FUNCTIONS;
    /// The maximum number of records in a program.
    const MAX_RECORDS: usize = 10 * Self::MAX_FUNCTIONS;
    /// The maximum number of closures in a program.
    const MAX_CLOSURES: usize = 2 * Self::MAX_FUNCTIONS;
    /// The maximum number of view functions in a program.
    const MAX_VIEWS: usize = 2 * Self::MAX_FUNCTIONS;
    /// The maximum number of operands in an instruction.
    const MAX_OPERANDS: usize = Self::MAX_INPUTS;
    /// The maximum number of instructions in a closure or function.
    const MAX_INSTRUCTIONS: usize = u16::MAX as usize;
    /// The maximum number of commands in finalize.
    const MAX_COMMANDS: usize = u16::MAX as usize;
    /// The maximum number of `call` commands in a finalize body. Matched to
    /// `Transaction::MAX_TRANSITIONS` so view-call arity in a finalize is bounded analogously
    /// to the static-call bound on transition graphs.
    const MAX_CALLS: usize = 32;
    /// The maximum number of write commands in finalize.
    const MAX_WRITES: [(ConsensusVersion, u16); 2] = [(ConsensusVersion::V1, 16), (ConsensusVersion::V14, 32)];
    /// The maximum number of `position` commands in finalize.
    const MAX_POSITIONS: usize = u8::MAX as usize;

    /// The maximum number of inputs per transition.
    const MAX_INPUTS: usize = 16;
    /// The maximum number of outputs per transition.
    const MAX_OUTPUTS: usize = 16;

    /// The maximum number of imports.
    const MAX_IMPORTS: usize = 64;

    /// A list of consensus versions and their corresponding maximum transaction sizes in bytes.
    ///
    /// A transaction consists of fixed identifiers, deployment data, and fees.
    /// Fixed components include identifiers, ownership, checksums, and fees.
    /// Variable components include the program bytecode and verifying-key entries.
    /// Verifying-key entries scale with the number of functions and records.
    ///
    /// MAX_TRANSACTION_SIZE = C + MAX_PROGRAM_SIZE + (673 + 58) * (MAX_FUNCTIONS + MAX_RECORDS)
    /// C = fixed size components (Up to 2367 bytes)
    // Note: This value must **not** decrease without considering the impact on transaction validity.
    const MAX_TRANSACTION_SIZE: [(ConsensusVersion, usize); 3] = [
        (ConsensusVersion::V1, 128_000),    // 128 kB
        (ConsensusVersion::V14, 768_000),   // 768 kB
        (ConsensusVersion::V16, 2_304_000), // 2304 kB
    ];

    /// The state root type.
    type StateRoot: Bech32ID<Field<Self>>;
    /// The block hash type.
    type BlockHash: Bech32ID<Field<Self>>;
    /// The ratification ID type.
    type RatificationID: Bech32ID<Field<Self>>;
    /// The transaction ID type.
    type TransactionID: Bech32ID<Field<Self>>;
    /// The transition ID type.
    type TransitionID: Bech32ID<Field<Self>>;
    /// The transmission checksum type.
    type TransmissionChecksum: IntegerType;

    /// A list of (consensus_version, block_height) pairs indicating when each consensus version takes effect.
    /// Documentation for what is changed at each version can be found in `N::CONSENSUS_VERSION`
    /// Do not read this directly outside of tests, use `N::CONSENSUS_VERSION_HEIGHTS()` instead.
    const _CONSENSUS_VERSION_HEIGHTS: [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS];

    ///  A list of (consensus_version, size) pairs indicating the maximum number of validators in a committee.
    //  Note: This value must **not** decrease without considering the impact on serialization.
    //  Decreasing this value will break backwards compatibility of serialization without explicit
    //  declaration of migration based on round number rather than block height.
    //  Increasing this value will require a migration to prevent forking during network upgrades.
    const MAX_CERTIFICATES: [(ConsensusVersion, u16); 6];

    /// Returns the list of consensus versions.
    #[allow(non_snake_case)]
    #[cfg(not(any(test, feature = "test", feature = "test_consensus_heights")))]
    fn CONSENSUS_VERSION_HEIGHTS() -> &'static [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] {
        // Initialize the consensus version heights directly from the constant.
        CONSENSUS_VERSION_HEIGHTS.get_or_init(|| Self::_CONSENSUS_VERSION_HEIGHTS)
    }
    /// Returns the list of test consensus versions.
    #[allow(non_snake_case)]
    #[cfg(any(test, feature = "test", feature = "test_consensus_heights"))]
    fn CONSENSUS_VERSION_HEIGHTS() -> &'static [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] {
        CONSENSUS_VERSION_HEIGHTS.get_or_init(load_test_consensus_heights)
    }

    /// A set of incrementing consensus version heights used for tests.
    #[allow(non_snake_case)]
    #[cfg(any(test, feature = "test", feature = "test_consensus_heights"))]
    const TEST_CONSENSUS_VERSION_HEIGHTS: [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] =
        TEST_CONSENSUS_VERSION_HEIGHTS;
    /// Returns the consensus version which is active at the given height.
    #[allow(non_snake_case)]
    fn CONSENSUS_VERSION(seek_height: u32) -> anyhow::Result<ConsensusVersion> {
        match Self::CONSENSUS_VERSION_HEIGHTS().binary_search_by(|(_, height)| height.cmp(&seek_height)) {
            // If a consensus version was found at this height, return it.
            Ok(index) => Ok(Self::CONSENSUS_VERSION_HEIGHTS()[index].0),
            // If the specified height was not found, determine whether to return an appropriate version.
            Err(index) => {
                if index == 0 {
                    Err(anyhow!("Expected consensus version 1 to exist at height 0."))
                } else {
                    // Return the appropriate version belonging to the height *lower* than the sought height.
                    Ok(Self::CONSENSUS_VERSION_HEIGHTS()[index - 1].0)
                }
            }
        }
    }
    /// Returns the height at which a specified consensus version becomes active.
    #[allow(non_snake_case)]
    fn CONSENSUS_HEIGHT(version: ConsensusVersion) -> Result<u32> {
        Ok(Self::CONSENSUS_VERSION_HEIGHTS().get(version as usize - 1).ok_or(anyhow!("Invalid consensus version"))?.1)
    }
    /// Returns the last `MAX_ARRAY_ELEMENTS` value.
    #[allow(non_snake_case)]
    fn LATEST_MAX_ARRAY_ELEMENTS() -> usize {
        Self::MAX_ARRAY_ELEMENTS.last().expect("MAX_ARRAY_ELEMENTS must have at least one entry").1
    }
    /// Returns the last `MAX_PLAINTEXT_TYPE_SIZE_IN_BITS` value.
    #[allow(non_snake_case)]
    fn LATEST_MAX_PLAINTEXT_TYPE_SIZE_IN_BITS() -> usize {
        Self::MAX_PLAINTEXT_TYPE_SIZE_IN_BITS
            .last()
            .expect("MAX_PLAINTEXT_TYPE_SIZE_IN_BITS must have at least one entry")
            .1
    }
    /// Returns the last `MAX_CERTIFICATES` value.
    #[allow(non_snake_case)]
    fn LATEST_MAX_CERTIFICATES() -> u16 {
        Self::MAX_CERTIFICATES.last().expect("MAX_CERTIFICATES must have at least one entry").1
    }

    /// Returns the last `MAX_MAPPINGS` value.
    #[allow(non_snake_case)]
    fn LATEST_MAX_MAPPINGS() -> usize {
        Self::MAX_MAPPINGS.last().expect("MAX_MAPPINGS must have at least one entry").1
    }

    /// Returns the last `MAX_PROGRAM_SIZE` value.
    #[allow(non_snake_case)]
    fn LATEST_MAX_PROGRAM_SIZE() -> usize {
        Self::MAX_PROGRAM_SIZE.last().expect("MAX_PROGRAM_SIZE must have at least one entry").1
    }

    /// Returns the last `MAX_WRITES` value.
    #[allow(non_snake_case)]
    fn LATEST_MAX_WRITES() -> u16 {
        Self::MAX_WRITES.last().expect("MAX_WRITES must have at least one entry").1
    }

    /// Returns the last `MAX_TRANSACTION_SIZE` value.
    #[allow(non_snake_case)]
    fn LATEST_MAX_TRANSACTION_SIZE() -> usize {
        Self::MAX_TRANSACTION_SIZE.last().expect("MAX_TRANSACTION_SIZE must have at least one entry").1
    }

    /// Returns the block height where the the inclusion proof will be updated.
    #[allow(non_snake_case)]
    fn INCLUSION_UPGRADE_HEIGHT() -> Result<u32>;

    /// Returns the genesis block bytes.
    fn genesis_bytes() -> &'static [u8];

    /// Returns the restrictions list as a JSON-compatible string.
    fn restrictions_list_as_str() -> &'static str;

    /// Returns the proving key for the given function name in the v0 version of `credits.aleo`.
    fn get_credits_v0_proving_key(function_name: String) -> Result<&'static Arc<VarunaProvingKey<Self>>>;

    /// Returns the verifying key for the given function name in the v0 version of `credits.aleo`.
    fn get_credits_v0_verifying_key(function_name: String) -> Result<&'static Arc<VarunaVerifyingKey<Self>>>;

    /// Returns the proving key for the given function name in `credits.aleo`.
    fn get_credits_proving_key(function_name: String) -> Result<&'static Arc<VarunaProvingKey<Self>>>;

    /// Returns the verifying key for the given function name in `credits.aleo`.
    fn get_credits_verifying_key(function_name: String) -> Result<&'static Arc<VarunaVerifyingKey<Self>>>;

    /// Checks that `file` is the shipped proving key file for `credits.aleo/{function_name}`, by its size and
    /// checksum. The file is a version byte, then the key.
    fn verify_credits_proving_key_file(function_name: &str, _file: &[u8]) -> Result<()> {
        bail!("{} has no proving key file for 'credits.aleo/{function_name}'", Self::NAME)
    }

    #[cfg(not(feature = "wasm"))]
    /// Returns the `proving key` for the inclusion_v0 circuit.
    fn inclusion_v0_proving_key() -> &'static Arc<VarunaProvingKey<Self>>;

    #[cfg(feature = "wasm")]
    /// Returns the `proving key` for the inclusion_v0 circuit.
    fn inclusion_v0_proving_key(bytes: Option<Vec<u8>>) -> &'static Arc<VarunaProvingKey<Self>>;

    /// Returns the `verifying key` for the inclusion_v0 circuit.
    fn inclusion_v0_verifying_key() -> &'static Arc<VarunaVerifyingKey<Self>>;

    #[cfg(not(feature = "wasm"))]
    /// Returns the `proving key` for the inclusion circuit.
    fn inclusion_proving_key() -> &'static Arc<VarunaProvingKey<Self>>;

    #[cfg(feature = "wasm")]
    fn inclusion_proving_key(bytes: Option<Vec<u8>>) -> &'static Arc<VarunaProvingKey<Self>>;

    /// Returns the `verifying key` for the inclusion circuit.
    fn inclusion_verifying_key() -> &'static Arc<VarunaVerifyingKey<Self>>;

    /// Sets the inclusion proving key to the key in `file`, read against `srs` so that it shares its powers. `file`
    /// must be the shipped inclusion proving key file, which this checks by its size and checksum. Call it before
    /// anything proves inclusion. Fails if the key is already set, if `file` is not the shipped file, or if `srs`
    /// does not hold the powers the key needs. A failed load leaves the key unset.
    fn load_inclusion_proving_key(_file: &[u8], _srs: &UniversalParams<Self::PairingCurve>) -> Result<()> {
        bail!("{} cannot load its inclusion proving key against an SRS", Self::NAME)
    }

    #[cfg(not(feature = "wasm"))]
    /// Returns the `proving key` for the translation circuit.
    fn translation_credits_proving_key() -> &'static Arc<VarunaProvingKey<Self>>;

    #[cfg(feature = "wasm")]
    /// Returns the `proving key` for the translation circuit.
    fn translation_credits_proving_key(bytes: Option<Vec<u8>>) -> &'static Arc<VarunaProvingKey<Self>>;

    /// Returns the `verifying key` for the translation circuit.
    fn translation_credits_verifying_key() -> &'static Arc<VarunaVerifyingKey<Self>>;

    /// Returns the powers of `G`.
    fn g_powers() -> &'static Vec<Group<Self>>;

    /// Returns the scalar multiplication on the generator `G`.
    fn g_scalar_multiply(scalar: &Scalar<Self>) -> Group<Self>;

    /// Returns the Varuna universal prover.
    fn varuna_universal_prover() -> &'static UniversalProver<Self::PairingCurve>;

    /// Returns the Varuna universal verifier.
    fn varuna_universal_verifier() -> &'static UniversalVerifier<Self::PairingCurve>;

    /// Returns the sponge parameters for Varuna.
    fn varuna_fs_parameters() -> &'static FiatShamirParameters<Self>;

    /// Returns the commitment domain as a constant field element.
    fn commitment_domain() -> Field<Self>;

    /// Returns the encryption domain as a constant field element.
    fn encryption_domain() -> Field<Self>;

    /// Returns the graph key domain as a constant field element.
    fn graph_key_domain() -> Field<Self>;

    /// Returns the serial number domain as a constant field element.
    fn serial_number_domain() -> Field<Self>;

    /// Returns a BHP commitment with an input hasher of 256-bits and randomizer.
    fn commit_bhp256(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>>;

    /// Returns a BHP commitment with an input hasher of 512-bits and randomizer.
    fn commit_bhp512(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>>;

    /// Returns a BHP commitment with an input hasher of 768-bits and randomizer.
    fn commit_bhp768(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>>;

    /// Returns a BHP commitment with an input hasher of 1024-bits and randomizer.
    fn commit_bhp1024(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>>;

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_ped64(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>>;

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_ped128(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>>;

    /// Returns a BHP commitment with an input hasher of 256-bits and randomizer.
    fn commit_to_group_bhp256(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>>;

    /// Returns a BHP commitment with an input hasher of 512-bits and randomizer.
    fn commit_to_group_bhp512(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>>;

    /// Returns a BHP commitment with an input hasher of 768-bits and randomizer.
    fn commit_to_group_bhp768(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>>;

    /// Returns a BHP commitment with an input hasher of 1024-bits and randomizer.
    fn commit_to_group_bhp1024(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>>;

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_to_group_ped64(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>>;

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_to_group_ped128(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>>;

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_bhp256(input: &[bool]) -> Result<Field<Self>>;

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_bhp512(input: &[bool]) -> Result<Field<Self>>;

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_bhp768(input: &[bool]) -> Result<Field<Self>>;

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_bhp1024(input: &[bool]) -> Result<Field<Self>>;

    /// Returns the Keccak hash with a 256-bit output.
    fn hash_keccak256(input: &[bool]) -> Result<Vec<bool>>;

    /// Returns the Keccak hash with a 384-bit output.
    fn hash_keccak384(input: &[bool]) -> Result<Vec<bool>>;

    /// Returns the Keccak hash with a 512-bit output.
    fn hash_keccak512(input: &[bool]) -> Result<Vec<bool>>;

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_ped64(input: &[bool]) -> Result<Field<Self>>;

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_ped128(input: &[bool]) -> Result<Field<Self>>;

    /// Returns the Poseidon hash with an input rate of 2.
    fn hash_psd2(input: &[Field<Self>]) -> Result<Field<Self>>;

    /// Returns the Poseidon hash with an input rate of 4.
    fn hash_psd4(input: &[Field<Self>]) -> Result<Field<Self>>;

    /// Returns the Poseidon hash with an input rate of 8.
    fn hash_psd8(input: &[Field<Self>]) -> Result<Field<Self>>;

    /// Returns the SHA-3 hash with a 256-bit output.
    fn hash_sha3_256(input: &[bool]) -> Result<Vec<bool>>;

    /// Returns the SHA-3 hash with a 384-bit output.
    fn hash_sha3_384(input: &[bool]) -> Result<Vec<bool>>;

    /// Returns the SHA-3 hash with a 512-bit output.
    fn hash_sha3_512(input: &[bool]) -> Result<Vec<bool>>;

    /// Returns the extended Poseidon hash with an input rate of 2.
    fn hash_many_psd2(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>>;

    /// Returns the extended Poseidon hash with an input rate of 4.
    fn hash_many_psd4(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>>;

    /// Returns the extended Poseidon hash with an input rate of 8.
    fn hash_many_psd8(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>>;

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_to_group_bhp256(input: &[bool]) -> Result<Group<Self>>;

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_to_group_bhp512(input: &[bool]) -> Result<Group<Self>>;

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_to_group_bhp768(input: &[bool]) -> Result<Group<Self>>;

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_to_group_bhp1024(input: &[bool]) -> Result<Group<Self>>;

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_to_group_ped64(input: &[bool]) -> Result<Group<Self>>;

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_to_group_ped128(input: &[bool]) -> Result<Group<Self>>;

    /// Returns the Poseidon hash with an input rate of 2 on the affine curve.
    fn hash_to_group_psd2(input: &[Field<Self>]) -> Result<Group<Self>>;

    /// Returns the Poseidon hash with an input rate of 4 on the affine curve.
    fn hash_to_group_psd4(input: &[Field<Self>]) -> Result<Group<Self>>;

    /// Returns the Poseidon hash with an input rate of 8 on the affine curve.
    fn hash_to_group_psd8(input: &[Field<Self>]) -> Result<Group<Self>>;

    /// Returns the Poseidon hash with an input rate of 2 on the scalar field.
    fn hash_to_scalar_psd2(input: &[Field<Self>]) -> Result<Scalar<Self>>;

    /// Returns the Poseidon hash with an input rate of 4 on the scalar field.
    fn hash_to_scalar_psd4(input: &[Field<Self>]) -> Result<Scalar<Self>>;

    /// Returns the Poseidon hash with an input rate of 8 on the scalar field.
    fn hash_to_scalar_psd8(input: &[Field<Self>]) -> Result<Scalar<Self>>;

    /// Returns a Merkle tree with a BHP leaf hasher of 1024-bits and a BHP path hasher of 512-bits.
    fn merkle_tree_bhp<const DEPTH: u8>(leaves: &[Vec<bool>]) -> Result<BHPMerkleTree<Self, DEPTH>>;

    /// Recreates a Merkle tree with a BHP leaf hasher of 1024-bits and a BHP path hasher of
    /// 512-bits from the given state, e.g. one that was previously cached on disk.
    fn merkle_tree_bhp_from_state<const DEPTH: u8>(
        state: MerkleTreeState<'_, Self>,
    ) -> Result<BHPMerkleTree<Self, DEPTH>>;

    /// Returns a Merkle tree with a Poseidon leaf hasher with input rate of 4 and a Poseidon path hasher with input rate of 2.
    fn merkle_tree_psd<const DEPTH: u8>(leaves: &[Vec<Field<Self>>]) -> Result<PoseidonMerkleTree<Self, DEPTH>>;

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    #[allow(clippy::ptr_arg)]
    fn verify_merkle_path_bhp<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<bool>,
    ) -> bool;

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    #[allow(clippy::ptr_arg)]
    fn verify_merkle_path_psd<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Field<Self>>,
    ) -> bool;

    /// Returns the Poseidon leaf hasher for dynamic records (rate 8).
    fn dynamic_record_leaf_hasher() -> &'static Poseidon8<Self>;

    /// Returns the Poseidon path hasher for dynamic records (rate 2).
    fn dynamic_record_path_hasher() -> &'static Poseidon2<Self>;
}

/// Reads the proving key in the file `file`, sharing its committer key's powers with `srs`.
fn read_proving_key_with_srs<N: Environment>(
    file: &[u8],
    srs: &UniversalParams<N::PairingCurve>,
) -> Result<VarunaProvingKey<N>> {
    // The first byte is the encoded version.
    let Some((&1, mut bytes)) = file.split_first() else { bail!("The proving key file is not version 1") };
    let key = VarunaProvingKey::<N>::read_le_with_srs(&mut bytes, srs)?;
    ensure!(bytes.is_empty(), "{} bytes follow the proving key", bytes.len());
    Ok(key)
}

/// Returns the consensus version heights, initializing them if necessary.
///
/// If a `heights` string is provided, it must be a comma-separated list of ascending block heights
/// starting from zero (e.g., `"0,2,3,4,..."`) with a number of heights exactly equal to the value
/// of the Network trait's `NUM_CONSENSUS_VERSIONS` constant. These heights correspond to the
/// activation block of each `ConsensusVersion`.
///
/// If `heights` is `None`, the function will use SnarkVM's default test consensus heights.
///
/// This function caches the initialized heights, and can be set only once. Further calls will
/// return the cached heights.
///
/// This method should be called by `wasm` users who need to set test values for consensus heights
/// for purposes such as testing on a local devnet. If this method needs to be used, it should be
/// called immediately after the wasm module is initialized.
#[cfg(feature = "wasm")]
pub fn get_or_init_consensus_version_heights(
    heights: Option<String>,
) -> [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] {
    let heights = load_test_consensus_heights_inner(heights);
    *CONSENSUS_VERSION_HEIGHTS.get_or_init(|| heights)
}
