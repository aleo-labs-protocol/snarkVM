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

use super::*;
use crate::TRANSACTION_PREFIX;
use snarkvm_console_algorithms::{
    BHP256,
    BHP512,
    BHP768,
    BHP1024,
    Blake2Xs,
    Keccak256,
    Keccak384,
    Keccak512,
    Pedersen64,
    Pedersen128,
    Poseidon2,
    Poseidon4,
    Poseidon8,
    Sha3_256,
    Sha3_384,
    Sha3_512,
};

lazy_static! {
    /// The group bases for the Aleo signature and encryption schemes.
    static ref GENERATOR_G: Vec<Group<CanaryV0 >> = CanaryV0::new_bases("AleoAccountEncryptionAndSignatureScheme0");

    /// The Varuna sponge parameters.
    static ref VARUNA_FS_PARAMETERS: FiatShamirParameters<CanaryV0> = FiatShamir::<CanaryV0>::sample_parameters();

    /// The commitment domain as a constant field element.
    static ref COMMITMENT_DOMAIN: Field<CanaryV0> = Field::<CanaryV0>::new_domain_separator("AleoCommitment0");
    /// The encryption domain as a constant field element.
    static ref ENCRYPTION_DOMAIN: Field<CanaryV0> = Field::<CanaryV0>::new_domain_separator("AleoSymmetricEncryption0");
    /// The graph key domain as a constant field element.
    static ref GRAPH_KEY_DOMAIN: Field<CanaryV0> = Field::<CanaryV0>::new_domain_separator("AleoGraphKey0");
    /// The serial number domain as a constant field element.
    static ref SERIAL_NUMBER_DOMAIN: Field<CanaryV0> = Field::<CanaryV0>::new_domain_separator("AleoSerialNumber0");

    /// The BHP hash function, which can take an input of up to 256 bits.
    pub static ref CANARY_BHP_256: BHP256<CanaryV0> = BHP256::<CanaryV0>::setup("AleoBHP256").expect("Failed to setup BHP256");
    /// The BHP hash function, which can take an input of up to 512 bits.
    pub static ref CANARY_BHP_512: BHP512<CanaryV0> = BHP512::<CanaryV0>::setup("AleoBHP512").expect("Failed to setup BHP512");
    /// The BHP hash function, which can take an input of up to 768 bits.
    pub static ref CANARY_BHP_768: BHP768<CanaryV0> = BHP768::<CanaryV0>::setup("AleoBHP768").expect("Failed to setup BHP768");
    /// The BHP hash function, which can take an input of up to 1024 bits.
    pub static ref CANARY_BHP_1024: BHP1024<CanaryV0> = BHP1024::<CanaryV0>::setup("AleoBHP1024").expect("Failed to setup BHP1024");

    /// The Pedersen hash function, which can take an input of up to 64 bits.
    pub static ref CANARY_PEDERSEN_64: Pedersen64<CanaryV0> = Pedersen64::<CanaryV0>::setup("AleoPedersen64");
    /// The Pedersen hash function, which can take an input of up to 128 bits.
    pub static ref CANARY_PEDERSEN_128: Pedersen128<CanaryV0> = Pedersen128::<CanaryV0>::setup("AleoPedersen128");

    /// The Poseidon hash function, using a rate of 2.
    pub static ref CANARY_POSEIDON_2: Poseidon2<CanaryV0> = Poseidon2::<CanaryV0>::setup("AleoPoseidon2").expect("Failed to setup Poseidon2");
    /// The Poseidon hash function, using a rate of 4.
    pub static ref CANARY_POSEIDON_4: Poseidon4<CanaryV0> = Poseidon4::<CanaryV0>::setup("AleoPoseidon4").expect("Failed to setup Poseidon4");
    /// The Poseidon hash function, using a rate of 8.
    pub static ref CANARY_POSEIDON_8: Poseidon8<CanaryV0> = Poseidon8::<CanaryV0>::setup("AleoPoseidon8").expect("Failed to setup Poseidon8");

    /// The Poseidon leaf hasher for dynamic records, using a rate of 8.
    pub static ref CANARY_DYNAMIC_RECORD_LEAF_HASHER: Poseidon8<CanaryV0> = Poseidon8::<CanaryV0>::setup("DynamicRecordLeafHasher").expect("Failed to setup DynamicRecordLeafHasher");
    /// The Poseidon path hasher for dynamic records, using a rate of 2.
    pub static ref CANARY_DYNAMIC_RECORD_PATH_HASHER: Poseidon2<CanaryV0> = Poseidon2::<CanaryV0>::setup("DynamicRecordPathHasher").expect("Failed to setup DynamicRecordPathHasher");

    pub static ref CANARY_CREDITS_V0_PROVING_KEYS: IndexMap<String, Arc<VarunaProvingKey<Console>>> = {
        let mut map = IndexMap::new();
        snarkvm_parameters::insert_canary_credit_v0_keys!(map, VarunaProvingKey<Console>, Prover);
        map
    };
    pub static ref CANARY_CREDITS_V0_VERIFYING_KEYS: IndexMap<String, Arc<VarunaVerifyingKey<Console>>> = {
        let mut map = IndexMap::new();
        snarkvm_parameters::insert_canary_credit_v0_keys!(map, VarunaVerifyingKey<Console>, Verifier);
        map
    };

    pub static ref CANARY_CREDITS_PROVING_KEYS: IndexMap<String, Arc<VarunaProvingKey<Console>>> = {
        let mut map = IndexMap::new();
        snarkvm_parameters::insert_canary_credit_keys!(map, VarunaProvingKey<Console>, Prover);
        map
    };
    pub static ref CANARY_CREDITS_VERIFYING_KEYS: IndexMap<String, Arc<VarunaVerifyingKey<Console>>> = {
        let mut map = IndexMap::new();
        snarkvm_parameters::insert_canary_credit_keys!(map, VarunaVerifyingKey<Console>, Verifier);
        map
    };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanaryV0;

impl CanaryV0 {
    /// Initializes a new instance of group bases from a given input domain message.
    fn new_bases(message: &str) -> Vec<Group<Self>> {
        // Hash the given message to a point on the curve, to initialize the starting base.
        let (base, _, _) = Blake2Xs::hash_to_curve::<<Self as Environment>::Affine>(message);

        // Compute the bases up to the size of the scalar field (in bits).
        let mut g = Group::<Self>::new(base);
        let mut g_bases = Vec::with_capacity(Scalar::<Self>::size_in_bits());
        for _ in 0..Scalar::<Self>::size_in_bits() {
            g_bases.push(g);
            g = g.double();
        }
        g_bases
    }
}

impl Environment for CanaryV0 {
    type Affine = <Console as Environment>::Affine;
    type BigInteger = <Console as Environment>::BigInteger;
    type Field = <Console as Environment>::Field;
    type PairingCurve = <Console as Environment>::PairingCurve;
    type Projective = <Console as Environment>::Projective;
    type Scalar = <Console as Environment>::Scalar;

    /// The coefficient `A` of the twisted Edwards curve.
    const EDWARDS_A: Self::Field = Console::EDWARDS_A;
    /// The coefficient `D` of the twisted Edwards curve.
    const EDWARDS_D: Self::Field = Console::EDWARDS_D;
    /// The coefficient `A` of the Montgomery curve.
    const MONTGOMERY_A: Self::Field = Console::MONTGOMERY_A;
    /// The coefficient `B` of the Montgomery curve.
    const MONTGOMERY_B: Self::Field = Console::MONTGOMERY_B;
}

/// The inclusion proving key, read from the shipped bytes or loaded against an SRS.
static INCLUSION_PROVING_KEY: OnceLock<Arc<VarunaProvingKey<Console>>> = OnceLock::new();

impl Network for CanaryV0 {
    /// The block hash type.
    type BlockHash = AleoID<Field<Self>, { hrp2!("ab") }>;
    /// The ratification ID type.
    type RatificationID = AleoID<Field<Self>, { hrp2!("ar") }>;
    /// The state root type.
    type StateRoot = AleoID<Field<Self>, { hrp2!("sr") }>;
    /// The transaction ID type.
    type TransactionID = AleoID<Field<Self>, { hrp2!(TRANSACTION_PREFIX) }>;
    /// The transition ID type.
    type TransitionID = AleoID<Field<Self>, { hrp2!("au") }>;
    /// The transmission checksum type.
    type TransmissionChecksum = u128;

    /// The genesis block coinbase target.
    #[cfg(not(feature = "test_targets"))]
    const GENESIS_COINBASE_TARGET: u64 = (1u64 << 29).saturating_sub(1);
    #[cfg(feature = "test_targets")]
    const GENESIS_COINBASE_TARGET: u64 = (1u64 << 5).saturating_sub(1);
    /// The genesis block proof target.
    #[cfg(not(feature = "test_targets"))]
    const GENESIS_PROOF_TARGET: u64 = 1u64 << 27;
    #[cfg(feature = "test_targets")]
    const GENESIS_PROOF_TARGET: u64 = 1u64 << 3;
    /// The fixed timestamp of the genesis block.
    const GENESIS_TIMESTAMP: i64 = 1715776496 /* 2024-05-15 12:34:56 UTC */;
    /// The network ID.
    const ID: u16 = 2;
    /// The function name for the inclusion circuit.
    const INCLUSION_FUNCTION_NAME: &'static str = snarkvm_parameters::canary::NETWORK_INCLUSION_FUNCTION_NAME;
    /// A list of (consensus_version, size) pairs indicating the maximum number of certificates in a batch.
    #[cfg(not(any(test, feature = "test")))]
    const MAX_CERTIFICATES: [(ConsensusVersion, u16); 6] = [
        (ConsensusVersion::V1, 100),
        (ConsensusVersion::V3, 100),
        (ConsensusVersion::V5, 100),
        (ConsensusVersion::V6, 100),
        (ConsensusVersion::V9, 100),
        (ConsensusVersion::V20, 100),
    ];
    /// A list of (consensus_version, size) pairs indicating the maximum number of certificates in a batch.
    #[cfg(any(test, feature = "test"))]
    const MAX_CERTIFICATES: [(ConsensusVersion, u16); 6] = [
        (ConsensusVersion::V1, 25),
        (ConsensusVersion::V3, 25),
        (ConsensusVersion::V5, 25),
        (ConsensusVersion::V6, 25),
        (ConsensusVersion::V9, 25),
        (ConsensusVersion::V20, 25),
    ];
    /// The (long) network name.
    const NAME: &'static str = "Aleo Canary (v0)";
    /// The short network name.
    const SHORT_NAME: &'static str = "canary";
    /// A list of (consensus_version, block_height) pairs indicating when each consensus version takes effect.
    /// Documentation for what is changed at each version can be found in `ConsensusVersion`.
    /// Do not read this directly outside of tests, use `N::CONSENSUS_VERSION_HEIGHTS()` instead.
    const _CONSENSUS_VERSION_HEIGHTS: [(ConsensusVersion, u32); NUM_CONSENSUS_VERSIONS] =
        CANARY_V0_CONSENSUS_VERSION_HEIGHTS;

    /// Returns the block height where the the inclusion proof will be updated.
    #[allow(non_snake_case)]
    fn INCLUSION_UPGRADE_HEIGHT() -> Result<u32> {
        Self::CONSENSUS_HEIGHT(ConsensusVersion::V8)
    }

    /// Returns the genesis block bytes.
    fn genesis_bytes() -> &'static [u8] {
        snarkvm_parameters::canary::GenesisBytes::load_bytes()
    }

    /// Returns the restrictions list as a JSON-compatible string.
    fn restrictions_list_as_str() -> &'static str {
        snarkvm_parameters::canary::RESTRICTIONS_LIST
    }

    /// Returns the proving key for the given function name in the v0 version of `credits.aleo`.
    fn get_credits_v0_proving_key(function_name: String) -> Result<&'static Arc<VarunaProvingKey<Self>>> {
        CANARY_CREDITS_V0_PROVING_KEYS
            .get(&function_name)
            .ok_or_else(|| anyhow!("Proving key (v0) for credits.aleo/{function_name}' not found"))
    }

    /// Returns the verifying key for the given function name in the v0 version of `credits.aleo`.
    fn get_credits_v0_verifying_key(function_name: String) -> Result<&'static Arc<VarunaVerifyingKey<Self>>> {
        CANARY_CREDITS_V0_VERIFYING_KEYS
            .get(&function_name)
            .ok_or_else(|| anyhow!("Verifying key (v0) for credits_v0.aleo/{function_name}' not found"))
    }

    /// Returns the proving key for the given function name in `credits.aleo`.
    fn get_credits_proving_key(function_name: String) -> Result<&'static Arc<VarunaProvingKey<Self>>> {
        CANARY_CREDITS_PROVING_KEYS
            .get(&function_name)
            .ok_or_else(|| anyhow!("Proving key for credits.aleo/{function_name}' not found"))
    }

    /// Returns the verifying key for the given function name in `credits.aleo`.
    fn get_credits_verifying_key(function_name: String) -> Result<&'static Arc<VarunaVerifyingKey<Self>>> {
        CANARY_CREDITS_VERIFYING_KEYS
            .get(&function_name)
            .ok_or_else(|| anyhow!("Verifying key for credits.aleo/{function_name}' not found"))
    }

    /// Checks that `file` is the shipped proving key file for `credits.aleo/{function_name}`.
    fn verify_credits_proving_key_file(function_name: &str, file: &[u8]) -> Result<()> {
        verify_credits_proving_key_file!(canary, function_name, file)
    }

    #[cfg(not(feature = "wasm"))]
    /// Returns the `proving key` for the inclusion_v0 circuit.
    fn inclusion_v0_proving_key() -> &'static Arc<VarunaProvingKey<Self>> {
        static INSTANCE: OnceLock<Arc<VarunaProvingKey<Console>>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            // Skipping the first byte, which is the encoded version.
            Arc::new(
                CircuitProvingKey::from_bytes_le(&snarkvm_parameters::canary::INCLUSION_V0_PROVING_KEY[1..])
                    .expect("Failed to load inclusion_v0 proving key."),
            )
        })
    }

    #[cfg(feature = "wasm")]
    /// Returns the `proving key` for the inclusion_v0 circuit.
    fn inclusion_v0_proving_key(inclusion_key_bytes: Option<Vec<u8>>) -> &'static Arc<VarunaProvingKey<Self>> {
        static INSTANCE: OnceLock<Arc<VarunaProvingKey<Console>>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            inclusion_key_bytes
                .map(|bytes| {
                    snarkvm_parameters::canary::InclusionV0Prover::verify_bytes(&bytes)
                        .expect("Bytes provided did not match expected inclusion checksum.");
                    Arc::new(
                        CircuitProvingKey::from_bytes_le(&bytes[1..]).expect("Failed to load inclusion proving key."),
                    )
                })
                .unwrap_or_else(|| {
                    Arc::new(
                        CircuitProvingKey::from_bytes_le(&snarkvm_parameters::canary::INCLUSION_V0_PROVING_KEY[1..])
                            .expect("Failed to load inclusion proving key."),
                    )
                })
        })
    }

    /// Returns the `verifying key` for the inclusion_v0 circuit.
    fn inclusion_v0_verifying_key() -> &'static Arc<VarunaVerifyingKey<Self>> {
        static INSTANCE: OnceLock<Arc<VarunaVerifyingKey<Console>>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            // Skipping the first byte, which is the encoded version.
            Arc::new(
                CircuitVerifyingKey::from_bytes_le(&snarkvm_parameters::canary::INCLUSION_V0_VERIFYING_KEY[1..])
                    .expect("Failed to load inclusion_v0 verifying key."),
            )
        })
    }

    #[cfg(not(feature = "wasm"))]
    /// Returns the `proving key` for the inclusion circuit.
    fn inclusion_proving_key() -> &'static Arc<VarunaProvingKey<Self>> {
        INCLUSION_PROVING_KEY.get_or_init(|| {
            // Skipping the first byte, which is the encoded version.
            Arc::new(
                CircuitProvingKey::from_bytes_le(&snarkvm_parameters::canary::INCLUSION_PROVING_KEY[1..])
                    .expect("Failed to load inclusion proving key."),
            )
        })
    }

    /// Sets the inclusion proving key to the key in `file`, read against `srs` so that it shares its powers.
    fn load_inclusion_proving_key(file: &[u8], srs: &UniversalParams<Self::PairingCurve>) -> Result<()> {
        ensure!(INCLUSION_PROVING_KEY.get().is_none(), "The inclusion proving key is already loaded");
        snarkvm_parameters::canary::InclusionProver::verify_bytes(file)?;
        let key = read_proving_key_with_srs::<Self>(file, srs)?;
        INCLUSION_PROVING_KEY.set(Arc::new(key)).map_err(|_| anyhow!("The inclusion proving key is already loaded"))
    }

    #[cfg(feature = "wasm")]
    /// Returns the `proving key` for the inclusion circuit.
    fn inclusion_proving_key(inclusion_key_bytes: Option<Vec<u8>>) -> &'static Arc<VarunaProvingKey<Self>> {
        INCLUSION_PROVING_KEY.get_or_init(|| {
            inclusion_key_bytes
                .map(|bytes| {
                    snarkvm_parameters::canary::InclusionProver::verify_bytes(&bytes)
                        .expect("Bytes provided did not match expected inclusion checksum.");
                    Arc::new(
                        CircuitProvingKey::from_bytes_le(&bytes[1..]).expect("Failed to load inclusion proving key."),
                    )
                })
                .unwrap_or_else(|| {
                    Arc::new(
                        CircuitProvingKey::from_bytes_le(&snarkvm_parameters::canary::INCLUSION_PROVING_KEY[1..])
                            .expect("Failed to load inclusion proving key."),
                    )
                })
        })
    }

    /// Returns the `verifying key` for the inclusion circuit.
    fn inclusion_verifying_key() -> &'static Arc<VarunaVerifyingKey<Self>> {
        static INSTANCE: OnceLock<Arc<VarunaVerifyingKey<Console>>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            // Skipping the first byte, which is the encoded version.
            Arc::new(
                CircuitVerifyingKey::from_bytes_le(&snarkvm_parameters::canary::INCLUSION_VERIFYING_KEY[1..])
                    .expect("Failed to load inclusion verifying key."),
            )
        })
    }

    #[cfg(not(feature = "wasm"))]
    /// Returns the `proving key` for the credits.aleo credits record translation circuit.
    fn translation_credits_proving_key() -> &'static Arc<VarunaProvingKey<Self>> {
        static INSTANCE: OnceLock<Arc<VarunaProvingKey<Console>>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            // Skipping the first byte, which is the encoded version.
            Arc::new(
                CircuitProvingKey::from_bytes_le(&snarkvm_parameters::canary::TRANSLATION_CREDITS_PROVING_KEY[1..])
                    .expect("Failed to load translation credits proving key."),
            )
        })
    }

    #[cfg(feature = "wasm")]
    /// Returns the `proving key` for the translation credits circuit.
    fn translation_credits_proving_key(
        translation_credits_key_bytes: Option<Vec<u8>>,
    ) -> &'static Arc<VarunaProvingKey<Self>> {
        static INSTANCE: OnceLock<Arc<VarunaProvingKey<Console>>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            translation_credits_key_bytes
                .map(|bytes| {
                    snarkvm_parameters::canary::TranslationCreditsProver::verify_bytes(&bytes)
                        .expect("Bytes provided did not match expected translation credits checksum.");
                    Arc::new(
                        CircuitProvingKey::from_bytes_le(&bytes[1..])
                            .expect("Failed to load translation credits proving key."),
                    )
                })
                .unwrap_or_else(|| {
                    Arc::new(
                        CircuitProvingKey::from_bytes_le(
                            &snarkvm_parameters::canary::TRANSLATION_CREDITS_PROVING_KEY[1..],
                        )
                        .expect("Failed to load translation credits proving key."),
                    )
                })
        })
    }

    /// Returns the `verifying key` for the translation circuit.
    fn translation_credits_verifying_key() -> &'static Arc<VarunaVerifyingKey<Self>> {
        static INSTANCE: OnceLock<Arc<VarunaVerifyingKey<Console>>> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            Arc::new(
                CircuitVerifyingKey::from_bytes_le(&snarkvm_parameters::canary::TRANSLATION_CREDITS_VERIFYING_KEY[1..])
                    .expect("Failed to load translation verifying key."),
            )
        })
    }

    /// Returns the powers of `G`.
    fn g_powers() -> &'static Vec<Group<Self>> {
        &GENERATOR_G
    }

    /// Returns the scalar multiplication on the generator `G`.
    fn g_scalar_multiply(scalar: &Scalar<Self>) -> Group<Self> {
        GENERATOR_G
            .iter()
            .zip_eq(&scalar.to_bits_le())
            .filter_map(|(base, bit)| match bit {
                true => Some(base),
                false => None,
            })
            .sum()
    }

    /// Returns the Varuna universal prover.
    fn varuna_universal_prover() -> &'static UniversalProver<Self::PairingCurve> {
        MainnetV0::varuna_universal_prover()
    }

    /// Returns the Varuna universal verifier.
    fn varuna_universal_verifier() -> &'static UniversalVerifier<Self::PairingCurve> {
        MainnetV0::varuna_universal_verifier()
    }

    /// Returns the sponge parameters used for the sponge in the Varuna SNARK.
    fn varuna_fs_parameters() -> &'static FiatShamirParameters<Self> {
        &VARUNA_FS_PARAMETERS
    }

    /// Returns the commitment domain as a constant field element.
    fn commitment_domain() -> Field<Self> {
        *COMMITMENT_DOMAIN
    }

    /// Returns the encryption domain as a constant field element.
    fn encryption_domain() -> Field<Self> {
        *ENCRYPTION_DOMAIN
    }

    /// Returns the graph key domain as a constant field element.
    fn graph_key_domain() -> Field<Self> {
        *GRAPH_KEY_DOMAIN
    }

    /// Returns the serial number domain as a constant field element.
    fn serial_number_domain() -> Field<Self> {
        *SERIAL_NUMBER_DOMAIN
    }

    /// Returns a BHP commitment with an input hasher of 256-bits and randomizer.
    fn commit_bhp256(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>> {
        CANARY_BHP_256.commit(input, randomizer)
    }

    /// Returns a BHP commitment with an input hasher of 512-bits and randomizer.
    fn commit_bhp512(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>> {
        CANARY_BHP_512.commit(input, randomizer)
    }

    /// Returns a BHP commitment with an input hasher of 768-bits and randomizer.
    fn commit_bhp768(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>> {
        CANARY_BHP_768.commit(input, randomizer)
    }

    /// Returns a BHP commitment with an input hasher of 1024-bits and randomizer.
    fn commit_bhp1024(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>> {
        CANARY_BHP_1024.commit(input, randomizer)
    }

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_ped64(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>> {
        CANARY_PEDERSEN_64.commit(input, randomizer)
    }

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_ped128(input: &[bool], randomizer: &Scalar<Self>) -> Result<Field<Self>> {
        CANARY_PEDERSEN_128.commit(input, randomizer)
    }

    /// Returns a BHP commitment with an input hasher of 256-bits and randomizer.
    fn commit_to_group_bhp256(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>> {
        CANARY_BHP_256.commit_uncompressed(input, randomizer)
    }

    /// Returns a BHP commitment with an input hasher of 512-bits and randomizer.
    fn commit_to_group_bhp512(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>> {
        CANARY_BHP_512.commit_uncompressed(input, randomizer)
    }

    /// Returns a BHP commitment with an input hasher of 768-bits and randomizer.
    fn commit_to_group_bhp768(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>> {
        CANARY_BHP_768.commit_uncompressed(input, randomizer)
    }

    /// Returns a BHP commitment with an input hasher of 1024-bits and randomizer.
    fn commit_to_group_bhp1024(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>> {
        CANARY_BHP_1024.commit_uncompressed(input, randomizer)
    }

    /// Returns a Pedersen commitment for the given (up to) 64-bit input and randomizer.
    fn commit_to_group_ped64(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>> {
        CANARY_PEDERSEN_64.commit_uncompressed(input, randomizer)
    }

    /// Returns a Pedersen commitment for the given (up to) 128-bit input and randomizer.
    fn commit_to_group_ped128(input: &[bool], randomizer: &Scalar<Self>) -> Result<Group<Self>> {
        CANARY_PEDERSEN_128.commit_uncompressed(input, randomizer)
    }

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_bhp256(input: &[bool]) -> Result<Field<Self>> {
        CANARY_BHP_256.hash(input)
    }

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_bhp512(input: &[bool]) -> Result<Field<Self>> {
        CANARY_BHP_512.hash(input)
    }

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_bhp768(input: &[bool]) -> Result<Field<Self>> {
        CANARY_BHP_768.hash(input)
    }

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_bhp1024(input: &[bool]) -> Result<Field<Self>> {
        CANARY_BHP_1024.hash(input)
    }

    /// Returns the Keccak hash with a 256-bit output.
    fn hash_keccak256(input: &[bool]) -> Result<Vec<bool>> {
        Keccak256::default().hash(input)
    }

    /// Returns the Keccak hash with a 384-bit output.
    fn hash_keccak384(input: &[bool]) -> Result<Vec<bool>> {
        Keccak384::default().hash(input)
    }

    /// Returns the Keccak hash with a 512-bit output.
    fn hash_keccak512(input: &[bool]) -> Result<Vec<bool>> {
        Keccak512::default().hash(input)
    }

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_ped64(input: &[bool]) -> Result<Field<Self>> {
        CANARY_PEDERSEN_64.hash(input)
    }

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_ped128(input: &[bool]) -> Result<Field<Self>> {
        CANARY_PEDERSEN_128.hash(input)
    }

    /// Returns the Poseidon hash with an input rate of 2.
    fn hash_psd2(input: &[Field<Self>]) -> Result<Field<Self>> {
        CANARY_POSEIDON_2.hash(input)
    }

    /// Returns the Poseidon hash with an input rate of 4.
    fn hash_psd4(input: &[Field<Self>]) -> Result<Field<Self>> {
        CANARY_POSEIDON_4.hash(input)
    }

    /// Returns the Poseidon hash with an input rate of 8.
    fn hash_psd8(input: &[Field<Self>]) -> Result<Field<Self>> {
        CANARY_POSEIDON_8.hash(input)
    }

    /// Returns the SHA-3 hash with a 256-bit output.
    fn hash_sha3_256(input: &[bool]) -> Result<Vec<bool>> {
        Sha3_256::default().hash(input)
    }

    /// Returns the SHA-3 hash with a 384-bit output.
    fn hash_sha3_384(input: &[bool]) -> Result<Vec<bool>> {
        Sha3_384::default().hash(input)
    }

    /// Returns the SHA-3 hash with a 512-bit output.
    fn hash_sha3_512(input: &[bool]) -> Result<Vec<bool>> {
        Sha3_512::default().hash(input)
    }

    /// Returns the extended Poseidon hash with an input rate of 2.
    fn hash_many_psd2(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        CANARY_POSEIDON_2.hash_many(input, num_outputs)
    }

    /// Returns the extended Poseidon hash with an input rate of 4.
    fn hash_many_psd4(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        CANARY_POSEIDON_4.hash_many(input, num_outputs)
    }

    /// Returns the extended Poseidon hash with an input rate of 8.
    fn hash_many_psd8(input: &[Field<Self>], num_outputs: u16) -> Vec<Field<Self>> {
        CANARY_POSEIDON_8.hash_many(input, num_outputs)
    }

    /// Returns the BHP hash with an input hasher of 256-bits.
    fn hash_to_group_bhp256(input: &[bool]) -> Result<Group<Self>> {
        CANARY_BHP_256.hash_uncompressed(input)
    }

    /// Returns the BHP hash with an input hasher of 512-bits.
    fn hash_to_group_bhp512(input: &[bool]) -> Result<Group<Self>> {
        CANARY_BHP_512.hash_uncompressed(input)
    }

    /// Returns the BHP hash with an input hasher of 768-bits.
    fn hash_to_group_bhp768(input: &[bool]) -> Result<Group<Self>> {
        CANARY_BHP_768.hash_uncompressed(input)
    }

    /// Returns the BHP hash with an input hasher of 1024-bits.
    fn hash_to_group_bhp1024(input: &[bool]) -> Result<Group<Self>> {
        CANARY_BHP_1024.hash_uncompressed(input)
    }

    /// Returns the Pedersen hash for a given (up to) 64-bit input.
    fn hash_to_group_ped64(input: &[bool]) -> Result<Group<Self>> {
        CANARY_PEDERSEN_64.hash_uncompressed(input)
    }

    /// Returns the Pedersen hash for a given (up to) 128-bit input.
    fn hash_to_group_ped128(input: &[bool]) -> Result<Group<Self>> {
        CANARY_PEDERSEN_128.hash_uncompressed(input)
    }

    /// Returns the Poseidon hash with an input rate of 2 on the affine curve.
    fn hash_to_group_psd2(input: &[Field<Self>]) -> Result<Group<Self>> {
        CANARY_POSEIDON_2.hash_to_group(input)
    }

    /// Returns the Poseidon hash with an input rate of 4 on the affine curve.
    fn hash_to_group_psd4(input: &[Field<Self>]) -> Result<Group<Self>> {
        CANARY_POSEIDON_4.hash_to_group(input)
    }

    /// Returns the Poseidon hash with an input rate of 8 on the affine curve.
    fn hash_to_group_psd8(input: &[Field<Self>]) -> Result<Group<Self>> {
        CANARY_POSEIDON_8.hash_to_group(input)
    }

    /// Returns the Poseidon hash with an input rate of 2 on the scalar field.
    fn hash_to_scalar_psd2(input: &[Field<Self>]) -> Result<Scalar<Self>> {
        CANARY_POSEIDON_2.hash_to_scalar(input)
    }

    /// Returns the Poseidon hash with an input rate of 4 on the scalar field.
    fn hash_to_scalar_psd4(input: &[Field<Self>]) -> Result<Scalar<Self>> {
        CANARY_POSEIDON_4.hash_to_scalar(input)
    }

    /// Returns the Poseidon hash with an input rate of 8 on the scalar field.
    fn hash_to_scalar_psd8(input: &[Field<Self>]) -> Result<Scalar<Self>> {
        CANARY_POSEIDON_8.hash_to_scalar(input)
    }

    /// Returns a Merkle tree with a BHP leaf hasher of 1024-bits and a BHP path hasher of 512-bits.
    fn merkle_tree_bhp<const DEPTH: u8>(leaves: &[Vec<bool>]) -> Result<BHPMerkleTree<Self, DEPTH>> {
        MerkleTree::new(&*CANARY_BHP_1024, &*CANARY_BHP_512, leaves)
    }

    /// Recreates a Merkle tree with a BHP leaf hasher of 1024-bits and a BHP path hasher of
    /// 512-bits from the given state, e.g. one that was previously cached on disk.
    fn merkle_tree_bhp_from_state<const DEPTH: u8>(
        state: MerkleTreeState<'_, Self>,
    ) -> Result<BHPMerkleTree<Self, DEPTH>> {
        MerkleTree::from_state(&*CANARY_BHP_1024, &*CANARY_BHP_512, state)
    }

    /// Returns a Merkle tree with a Poseidon leaf hasher with input rate of 4 and a Poseidon path hasher with input rate of 2.
    fn merkle_tree_psd<const DEPTH: u8>(leaves: &[Vec<Field<Self>>]) -> Result<PoseidonMerkleTree<Self, DEPTH>> {
        MerkleTree::new(&*CANARY_POSEIDON_4, &*CANARY_POSEIDON_2, leaves)
    }

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    fn verify_merkle_path_bhp<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<bool>,
    ) -> bool {
        path.verify(&*CANARY_BHP_1024, &*CANARY_BHP_512, root, leaf)
    }

    /// Returns `true` if the given Merkle path is valid for the given root and leaf.
    fn verify_merkle_path_psd<const DEPTH: u8>(
        path: &MerklePath<Self, DEPTH>,
        root: &Field<Self>,
        leaf: &Vec<Field<Self>>,
    ) -> bool {
        path.verify(&*CANARY_POSEIDON_4, &*CANARY_POSEIDON_2, root, leaf)
    }

    /// Returns the Poseidon leaf hasher for dynamic records (rate 8).
    fn dynamic_record_leaf_hasher() -> &'static Poseidon8<Self> {
        &CANARY_DYNAMIC_RECORD_LEAF_HASHER
    }

    /// Returns the Poseidon path hasher for dynamic records (rate 2).
    fn dynamic_record_path_hasher() -> &'static Poseidon2<Self> {
        &CANARY_DYNAMIC_RECORD_PATH_HASHER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = CanaryV0;

    #[test]
    fn test_g_scalar_multiply() {
        // Compute G^r.
        let scalar = Scalar::rand(&mut TestRng::default());
        let group = CurrentNetwork::g_scalar_multiply(&scalar);
        assert_eq!(group, CurrentNetwork::g_powers()[0] * scalar);
    }
}
