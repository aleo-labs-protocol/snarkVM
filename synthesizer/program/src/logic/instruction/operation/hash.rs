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
    FinalizeRegistersState,
    FinalizeStoreTrait,
    Opcode,
    Operand,
    RegistersCircuit,
    RegistersTrait,
    StackTrait,
};
use console::{
    network::prelude::*,
    program::{Identifier, Literal, LiteralType, Locator, Plaintext, PlaintextType, Register, RegisterType, Value},
};

use enum_iterator::Sequence;

/// BHP256 is a collision-resistant hash function that processes inputs in 256-bit chunks.
pub type HashBHP256<N> = HashInstruction<N, { HashVariant::HashBHP256 as u8 }>;
/// BHP512 is a collision-resistant hash function that processes inputs in 512-bit chunks.
pub type HashBHP512<N> = HashInstruction<N, { HashVariant::HashBHP512 as u8 }>;
/// BHP768 is a collision-resistant hash function that processes inputs in 768-bit chunks.
pub type HashBHP768<N> = HashInstruction<N, { HashVariant::HashBHP768 as u8 }>;
/// BHP1024 is a collision-resistant hash function that processes inputs in 1024-bit chunks.
pub type HashBHP1024<N> = HashInstruction<N, { HashVariant::HashBHP1024 as u8 }>;

/// BHP256Raw is a collision-resistant hash function that processes the input's raw bits in 256-bit chunks.
pub type HashBHP256Raw<N> = HashInstruction<N, { HashVariant::HashBHP256Raw as u8 }>;
/// BHP512Raw is a collision-resistant hash function that processes the input's raw bits in 512-bit chunks.
pub type HashBHP512Raw<N> = HashInstruction<N, { HashVariant::HashBHP512Raw as u8 }>;
/// BHP768Raw is a collision-resistant hash function that processes the input's raw bits in 768-bit chunks.
pub type HashBHP768Raw<N> = HashInstruction<N, { HashVariant::HashBHP768Raw as u8 }>;
/// BHP1024Raw is a collision-resistant hash function that processes the input's raw bits in 1024-bit chunks.
pub type HashBHP1024Raw<N> = HashInstruction<N, { HashVariant::HashBHP1024Raw as u8 }>;

/// Keccak256 is a cryptographic hash function that outputs a 256-bit digest.
pub type HashKeccak256<N> = HashInstruction<N, { HashVariant::HashKeccak256 as u8 }>;
/// Keccak384 is a cryptographic hash function that outputs a 384-bit digest.
pub type HashKeccak384<N> = HashInstruction<N, { HashVariant::HashKeccak384 as u8 }>;
/// Keccak512 is a cryptographic hash function that outputs a 512-bit digest.
pub type HashKeccak512<N> = HashInstruction<N, { HashVariant::HashKeccak512 as u8 }>;

/// Keccak256Raw is a cryptographic hash function that outputs a 256-bit digest using the input's raw bits.
pub type HashKeccak256Raw<N> = HashInstruction<N, { HashVariant::HashKeccak256Raw as u8 }>;
/// Keccak384Raw is a cryptographic hash function that outputs a 384-bit digest using the input's raw bits.
pub type HashKeccak384Raw<N> = HashInstruction<N, { HashVariant::HashKeccak384Raw as u8 }>;
/// Keccak512Raw is a cryptographic hash function that outputs a 512-bit digest using the input's raw bits.
pub type HashKeccak512Raw<N> = HashInstruction<N, { HashVariant::HashKeccak512Raw as u8 }>;

/// Keccak256Native is a cryptographic hash function that outputs a 256-bit digest as a bit array.
pub type HashKeccak256Native<N> = HashInstruction<N, { HashVariant::HashKeccak256Native as u8 }>;
/// Keccak384Native is a cryptographic hash function that outputs a 384-bit digest as a bit array.
pub type HashKeccak384Native<N> = HashInstruction<N, { HashVariant::HashKeccak384Native as u8 }>;
/// Keccak512Native is a cryptographic hash function that outputs a 512-bit digest as a bit array.
pub type HashKeccak512Native<N> = HashInstruction<N, { HashVariant::HashKeccak512Native as u8 }>;

/// Keccak256NativeRaw is a cryptographic hash function that outputs a 256-bit digest as a bit array using the input's raw bits.
pub type HashKeccak256NativeRaw<N> = HashInstruction<N, { HashVariant::HashKeccak256NativeRaw as u8 }>;
/// Keccak384NativeRaw is a cryptographic hash function that outputs a 384-bit digest as a bit array using the input's raw bits.
pub type HashKeccak384NativeRaw<N> = HashInstruction<N, { HashVariant::HashKeccak384NativeRaw as u8 }>;
/// Keccak512NativeRaw is a cryptographic hash function that outputs a 512-bit digest as a bit array using the input's raw bits.
pub type HashKeccak512NativeRaw<N> = HashInstruction<N, { HashVariant::HashKeccak512NativeRaw as u8 }>;

/// Pedersen64 is a collision-resistant hash function that processes inputs in 64-bit chunks.
pub type HashPED64<N> = HashInstruction<N, { HashVariant::HashPED64 as u8 }>;
/// Pedersen128 is a collision-resistant hash function that processes inputs in 128-bit chunks.
pub type HashPED128<N> = HashInstruction<N, { HashVariant::HashPED128 as u8 }>;

/// Pedersen64Raw is a collision-resistant hash function that processes the input's raw bits in 64-bit chunks.
pub type HashPED64Raw<N> = HashInstruction<N, { HashVariant::HashPED64Raw as u8 }>;
/// Pedersen128Raw is a collision-resistant hash function that processes the input's raw bits in 128-bit chunks.
pub type HashPED128Raw<N> = HashInstruction<N, { HashVariant::HashPED128Raw as u8 }>;

/// Poseidon2 is a cryptographic hash function that processes inputs in 2-field chunks.
pub type HashPSD2<N> = HashInstruction<N, { HashVariant::HashPSD2 as u8 }>;
/// Poseidon4 is a cryptographic hash function that processes inputs in 4-field chunks.
pub type HashPSD4<N> = HashInstruction<N, { HashVariant::HashPSD4 as u8 }>;
/// Poseidon8 is a cryptographic hash function that processes inputs in 8-field chunks.
pub type HashPSD8<N> = HashInstruction<N, { HashVariant::HashPSD8 as u8 }>;

/// Poseidon2Raw is a cryptographic hash function that processes the input's raw fields in 2-field chunks.
pub type HashPSD2Raw<N> = HashInstruction<N, { HashVariant::HashPSD2Raw as u8 }>;
/// Poseidon4Raw is a cryptographic hash function that processes the input's raw fields in 4-field chunks.
pub type HashPSD4Raw<N> = HashInstruction<N, { HashVariant::HashPSD4Raw as u8 }>;
/// Poseidon8Raw is a cryptographic hash function that processes the input's raw fields in 8-field chunks.
pub type HashPSD8Raw<N> = HashInstruction<N, { HashVariant::HashPSD8Raw as u8 }>;

/// SHA3-256 is a cryptographic hash function that outputs a 256-bit digest.
pub type HashSha3_256<N> = HashInstruction<N, { HashVariant::HashSha3_256 as u8 }>;
/// SHA3-384 is a cryptographic hash function that outputs a 384-bit digest.
pub type HashSha3_384<N> = HashInstruction<N, { HashVariant::HashSha3_384 as u8 }>;
/// SHA3-512 is a cryptographic hash function that outputs a 512-bit digest.
pub type HashSha3_512<N> = HashInstruction<N, { HashVariant::HashSha3_512 as u8 }>;

/// SHA3-256Raw is a cryptographic hash function that outputs a 256-bit digest using the input's raw bits.
pub type HashSha3_256Raw<N> = HashInstruction<N, { HashVariant::HashSha3_256Raw as u8 }>;
/// SHA3-384Raw is a cryptographic hash function that outputs a 384-bit digest using the input's raw bits.
pub type HashSha3_384Raw<N> = HashInstruction<N, { HashVariant::HashSha3_384Raw as u8 }>;
/// SHA3-512Raw is a cryptographic hash function that outputs a 512-bit digest using the input's raw bits.
pub type HashSha3_512Raw<N> = HashInstruction<N, { HashVariant::HashSha3_512Raw as u8 }>;

/// SHA3-256Native is a cryptographic hash function that outputs a 256-bit digest as a bit array.
pub type HashSha3_256Native<N> = HashInstruction<N, { HashVariant::HashSha3_256Native as u8 }>;
/// SHA3-384Native is a cryptographic hash function that outputs a 384-bit digest as a bit array.
pub type HashSha3_384Native<N> = HashInstruction<N, { HashVariant::HashSha3_384Native as u8 }>;
/// SHA3-512Native is a cryptographic hash function that outputs a 512-bit digest as a bit array.
pub type HashSha3_512Native<N> = HashInstruction<N, { HashVariant::HashSha3_512Native as u8 }>;

/// SHA3-256NativeRaw is a cryptographic hash function that outputs a 256-bit digest as a bit array using the input's raw bits.
pub type HashSha3_256NativeRaw<N> = HashInstruction<N, { HashVariant::HashSha3_256NativeRaw as u8 }>;
/// SHA3-384NativeRaw is a cryptographic hash function that outputs a 384-bit digest as a bit array using the input's raw bits.
pub type HashSha3_384NativeRaw<N> = HashInstruction<N, { HashVariant::HashSha3_384NativeRaw as u8 }>;
/// SHA3-512NativeRaw is a cryptographic hash function that outputs a 512-bit digest as a bit array using the input's raw bits.
pub type HashSha3_512NativeRaw<N> = HashInstruction<N, { HashVariant::HashSha3_512NativeRaw as u8 }>;

/// Poseidon2 is a cryptographic hash function that processes inputs in 2-field chunks.
pub type HashManyPSD2<N> = HashInstruction<N, { HashVariant::HashManyPSD2 as u8 }>;
/// Poseidon4 is a cryptographic hash function that processes inputs in 4-field chunks.
pub type HashManyPSD4<N> = HashInstruction<N, { HashVariant::HashManyPSD4 as u8 }>;
/// Poseidon8 is a cryptographic hash function that processes inputs in 8-field chunks.
pub type HashManyPSD8<N> = HashInstruction<N, { HashVariant::HashManyPSD8 as u8 }>;

/// Which hash function to use.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Sequence)]
pub enum HashVariant {
    HashBHP256,
    HashBHP512,
    HashBHP768,
    HashBHP1024,
    HashKeccak256,
    HashKeccak384,
    HashKeccak512,
    HashPED64,
    HashPED128,
    HashPSD2,
    HashPSD4,
    HashPSD8,
    HashSha3_256,
    HashSha3_384,
    HashSha3_512,
    HashManyPSD2,
    HashManyPSD4,
    HashManyPSD8,
    // The variants that hash the raw inputs.
    HashBHP256Raw,
    HashBHP512Raw,
    HashBHP768Raw,
    HashBHP1024Raw,
    HashKeccak256Raw,
    HashKeccak384Raw,
    HashKeccak512Raw,
    HashPED64Raw,
    HashPED128Raw,
    HashPSD2Raw,
    HashPSD4Raw,
    HashPSD8Raw,
    HashSha3_256Raw,
    HashSha3_384Raw,
    HashSha3_512Raw,
    // The variants that perform the underlying hash, returning bit arrays.
    HashKeccak256Native,
    HashKeccak256NativeRaw,
    HashKeccak384Native,
    HashKeccak384NativeRaw,
    HashKeccak512Native,
    HashKeccak512NativeRaw,
    HashSha3_256Native,
    HashSha3_256NativeRaw,
    HashSha3_384Native,
    HashSha3_384NativeRaw,
    HashSha3_512Native,
    HashSha3_512NativeRaw,
}

impl HashVariant {
    // Initializes a new `HashVariant`.
    pub const fn new(variant: u8) -> Self {
        match variant {
            0 => Self::HashBHP256,
            1 => Self::HashBHP512,
            2 => Self::HashBHP768,
            3 => Self::HashBHP1024,
            4 => Self::HashKeccak256,
            5 => Self::HashKeccak384,
            6 => Self::HashKeccak512,
            7 => Self::HashPED64,
            8 => Self::HashPED128,
            9 => Self::HashPSD2,
            10 => Self::HashPSD4,
            11 => Self::HashPSD8,
            12 => Self::HashSha3_256,
            13 => Self::HashSha3_384,
            14 => Self::HashSha3_512,
            15 => Self::HashManyPSD2,
            16 => Self::HashManyPSD4,
            17 => Self::HashManyPSD8,
            // The variants that hash the raw inputs.
            18 => Self::HashBHP256Raw,
            19 => Self::HashBHP512Raw,
            20 => Self::HashBHP768Raw,
            21 => Self::HashBHP1024Raw,
            22 => Self::HashKeccak256Raw,
            23 => Self::HashKeccak384Raw,
            24 => Self::HashKeccak512Raw,
            25 => Self::HashPED64Raw,
            26 => Self::HashPED128Raw,
            27 => Self::HashPSD2Raw,
            28 => Self::HashPSD4Raw,
            29 => Self::HashPSD8Raw,
            30 => Self::HashSha3_256Raw,
            31 => Self::HashSha3_384Raw,
            32 => Self::HashSha3_512Raw,
            // The variants that perform the underlying hash, returning bit arrays.
            33 => Self::HashKeccak256Native,
            34 => Self::HashKeccak256NativeRaw,
            35 => Self::HashKeccak384Native,
            36 => Self::HashKeccak384NativeRaw,
            37 => Self::HashKeccak512Native,
            38 => Self::HashKeccak512NativeRaw,
            39 => Self::HashSha3_256Native,
            40 => Self::HashSha3_256NativeRaw,
            41 => Self::HashSha3_384Native,
            42 => Self::HashSha3_384NativeRaw,
            43 => Self::HashSha3_512Native,
            44 => Self::HashSha3_512NativeRaw,
            _ => panic!("Invalid 'hash' instruction opcode"),
        }
    }

    // Returns the opcode associated with the variant.
    pub const fn opcode(&self) -> &'static str {
        match self {
            Self::HashBHP256 => "hash.bhp256",
            Self::HashBHP512 => "hash.bhp512",
            Self::HashBHP768 => "hash.bhp768",
            Self::HashBHP1024 => "hash.bhp1024",
            Self::HashKeccak256 => "hash.keccak256",
            Self::HashKeccak384 => "hash.keccak384",
            Self::HashKeccak512 => "hash.keccak512",
            Self::HashPED64 => "hash.ped64",
            Self::HashPED128 => "hash.ped128",
            Self::HashPSD2 => "hash.psd2",
            Self::HashPSD4 => "hash.psd4",
            Self::HashPSD8 => "hash.psd8",
            Self::HashSha3_256 => "hash.sha3_256",
            Self::HashSha3_384 => "hash.sha3_384",
            Self::HashSha3_512 => "hash.sha3_512",
            Self::HashManyPSD2 => "hash_many.psd2",
            Self::HashManyPSD4 => "hash_many.psd4",
            Self::HashManyPSD8 => "hash_many.psd8",
            // The variants that hash the raw inputs.
            Self::HashBHP256Raw => "hash.bhp256.raw",
            Self::HashBHP512Raw => "hash.bhp512.raw",
            Self::HashBHP768Raw => "hash.bhp768.raw",
            Self::HashBHP1024Raw => "hash.bhp1024.raw",
            Self::HashKeccak256Raw => "hash.keccak256.raw",
            Self::HashKeccak384Raw => "hash.keccak384.raw",
            Self::HashKeccak512Raw => "hash.keccak512.raw",
            Self::HashPED64Raw => "hash.ped64.raw",
            Self::HashPED128Raw => "hash.ped128.raw",
            Self::HashPSD2Raw => "hash.psd2.raw",
            Self::HashPSD4Raw => "hash.psd4.raw",
            Self::HashPSD8Raw => "hash.psd8.raw",
            Self::HashSha3_256Raw => "hash.sha3_256.raw",
            Self::HashSha3_384Raw => "hash.sha3_384.raw",
            Self::HashSha3_512Raw => "hash.sha3_512.raw",
            // The variants that perform the underlying hash returning bit arrays.
            Self::HashKeccak256Native => "hash.keccak256.native",
            Self::HashKeccak256NativeRaw => "hash.keccak256.native.raw",
            Self::HashKeccak384Native => "hash.keccak384.native",
            Self::HashKeccak384NativeRaw => "hash.keccak384.native.raw",
            Self::HashKeccak512Native => "hash.keccak512.native",
            Self::HashKeccak512NativeRaw => "hash.keccak512.native.raw",
            Self::HashSha3_256Native => "hash.sha3_256.native",
            Self::HashSha3_256NativeRaw => "hash.sha3_256.native.raw",
            Self::HashSha3_384Native => "hash.sha3_384.native",
            Self::HashSha3_384NativeRaw => "hash.sha3_384.native.raw",
            Self::HashSha3_512Native => "hash.sha3_512.native",
            Self::HashSha3_512NativeRaw => "hash.sha3_512.native.raw",
        }
    }

    // Returns true if the variant requires byte alignment.
    pub const fn requires_byte_alignment(&self) -> bool {
        match self {
            Self::HashBHP256
            | Self::HashBHP512
            | Self::HashBHP768
            | Self::HashBHP1024
            | Self::HashKeccak256
            | Self::HashKeccak384
            | Self::HashKeccak512
            | Self::HashPED64
            | Self::HashPED128
            | Self::HashPSD2
            | Self::HashPSD4
            | Self::HashPSD8
            | Self::HashSha3_256
            | Self::HashSha3_384
            | Self::HashSha3_512
            | Self::HashManyPSD2
            | Self::HashManyPSD4
            | Self::HashManyPSD8 => false,
            // The variants that hash the raw inputs.
            Self::HashBHP256Raw | Self::HashBHP512Raw | Self::HashBHP768Raw | Self::HashBHP1024Raw => false,
            Self::HashKeccak256Raw | Self::HashKeccak384Raw | Self::HashKeccak512Raw => true,
            Self::HashPED64Raw | Self::HashPED128Raw | Self::HashPSD2Raw | Self::HashPSD4Raw | Self::HashPSD8Raw => {
                false
            }
            Self::HashSha3_256Raw | Self::HashSha3_384Raw | Self::HashSha3_512Raw => true,
            // The variants that perform the underlying hash returning bit arrays.
            Self::HashKeccak256Native
            | Self::HashKeccak256NativeRaw
            | Self::HashKeccak384Native
            | Self::HashKeccak384NativeRaw
            | Self::HashKeccak512Native
            | Self::HashKeccak512NativeRaw
            | Self::HashSha3_256Native
            | Self::HashSha3_256NativeRaw
            | Self::HashSha3_384Native
            | Self::HashSha3_384NativeRaw
            | Self::HashSha3_512Native
            | Self::HashSha3_512NativeRaw => true,
        }
    }

    // Returns `true` if the variant uses raw bits.
    pub const fn is_raw(&self) -> bool {
        match self {
            Self::HashBHP256
            | Self::HashBHP512
            | Self::HashBHP768
            | Self::HashBHP1024
            | Self::HashKeccak256
            | Self::HashKeccak384
            | Self::HashKeccak512
            | Self::HashPED64
            | Self::HashPED128
            | Self::HashPSD2
            | Self::HashPSD4
            | Self::HashPSD8
            | Self::HashSha3_256
            | Self::HashSha3_384
            | Self::HashSha3_512
            | Self::HashManyPSD2
            | Self::HashManyPSD4
            | Self::HashManyPSD8 => false,
            // The variants that hash the raw inputs.
            Self::HashBHP256Raw
            | Self::HashBHP512Raw
            | Self::HashBHP768Raw
            | Self::HashBHP1024Raw
            | Self::HashKeccak256Raw
            | Self::HashKeccak384Raw
            | Self::HashKeccak512Raw
            | Self::HashPED64Raw
            | Self::HashPED128Raw
            | Self::HashPSD2Raw
            | Self::HashPSD4Raw
            | Self::HashPSD8Raw
            | Self::HashSha3_256Raw
            | Self::HashSha3_384Raw
            | Self::HashSha3_512Raw => true,
            // The variants that perform the underlying hash returning bit arrays.
            Self::HashKeccak256Native
            | Self::HashKeccak256NativeRaw
            | Self::HashKeccak384Native
            | Self::HashKeccak384NativeRaw
            | Self::HashKeccak512Native
            | Self::HashKeccak512NativeRaw
            | Self::HashSha3_256Native
            | Self::HashSha3_256NativeRaw
            | Self::HashSha3_384Native
            | Self::HashSha3_384NativeRaw
            | Self::HashSha3_512Native
            | Self::HashSha3_512NativeRaw => true,
        }
    }

    /// Returns the expected number of operands given the variant.
    pub const fn expected_num_operands(&self) -> usize {
        match self {
            Self::HashManyPSD2 | Self::HashManyPSD4 | Self::HashManyPSD8 => 2,
            _ => 1,
        }
    }
}

/// Returns 'Ok(())' if the number of operands is correct.
/// Otherwise, returns an error.
fn check_number_of_operands(variant: u8, opcode: Opcode, num_operands: usize) -> Result<()> {
    let variant = HashVariant::new(variant);
    let expected = variant.expected_num_operands();
    if expected != num_operands {
        bail!("Instruction '{opcode}' expects {expected} operands, found {num_operands} operands")
    }
    Ok(())
}

/// Returns 'true' if the destination type is valid.
fn is_valid_destination_type<N: Network>(variant: u8, destination_type: &PlaintextType<N>) -> bool {
    match variant {
        0..=32 => !matches!(
            destination_type,
            PlaintextType::Literal(LiteralType::Boolean)
                | PlaintextType::Literal(LiteralType::String)
                | PlaintextType::Literal(LiteralType::Identifier)
                | PlaintextType::Struct(..)
                | PlaintextType::ExternalStruct(..)
                | PlaintextType::Array(..)
        ),
        33..=44 => matches!(destination_type, PlaintextType::Array(array_type) if array_type.is_bit_array()),
        _ => panic!("Invalid 'hash' instruction opcode"),
    }
}

/// Hashes the operand into the declared type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HashInstruction<N: Network, const VARIANT: u8> {
    /// The operand as `input`.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
    /// The destination register type.
    destination_type: PlaintextType<N>,
}

impl<N: Network, const VARIANT: u8> HashInstruction<N, VARIANT> {
    /// Initializes a new `hash` instruction.
    pub fn new(
        operands: Vec<Operand<N>>,
        destination: Register<N>,
        destination_type: PlaintextType<N>,
    ) -> Result<Self> {
        // Sanity check the number of operands.
        check_number_of_operands(VARIANT, Self::opcode(), operands.len())?;
        // Sanity check the destination type.
        if !is_valid_destination_type(VARIANT, &destination_type) {
            bail!("Invalid destination type for 'hash' instruction")
        }
        // Return the instruction.
        Ok(Self { operands, destination, destination_type })
    }

    /// Returns the opcode.
    pub const fn opcode() -> Opcode {
        Opcode::Hash(HashVariant::new(VARIANT).opcode())
    }

    /// Returns the operands in the operation.
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that the operands is the correct length.
        debug_assert!(
            check_number_of_operands(VARIANT, Self::opcode(), self.operands.len()).is_ok(),
            "Invalid number of operands for '{}'",
            Self::opcode()
        );
        // Return the operand.
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }

    /// Returns the destination register type.
    #[inline]
    pub const fn destination_type(&self) -> &PlaintextType<N> {
        &self.destination_type
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        self.destination_type.contains_external_struct()
    }
}

// This code is nearly identical in `execute` and `evaluate`; we
// extract it here in a macro.
//
// The `$q` parameter allows us to wrap a value in `Result::Ok`, since
// the `Aleo` functions don't return a `Result` but the `Network` ones do.
#[rustfmt::skip]
macro_rules! do_hash {
    ($N: ident, $variant: expr, $destination_type: expr, $input: expr, $pt: ty, $lt: ty, $q: expr) => {{
        let bits = || $input.to_bits_le();
        let bits_raw = || $input.to_bits_raw_le();

        let fields = || $q($input.to_fields());
        let fields_raw = || $q($input.to_fields_raw());

        let check_multiple_of_8 = |bits: Vec<_>| -> Result<Vec<_>> {
            ensure!(bits.len() % 8 == 0, "The opcode '{}' expects input whose size in bits is a multiple of 8.", $variant.opcode());
            Ok(bits)
        };

        match ($variant, $destination_type) {
            (HashVariant::HashBHP256,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp256(&bits()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashBHP512,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&bits()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashBHP768,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp768(&bits()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashBHP1024,   PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp1024(&bits()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashKeccak256, PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp256(&$q($N::hash_keccak256(&bits()))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashKeccak384, PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_keccak384(&bits()))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashKeccak512, PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_keccak512(&bits()))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPED64,     PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_ped64(&bits()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPED128,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_ped128(&bits()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD2,      PlaintextType::Literal(literal_type @ LiteralType::Address) | PlaintextType::Literal(literal_type @ LiteralType::Group)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_psd2(&fields()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD2,      PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_psd2(&fields()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD4,      PlaintextType::Literal(literal_type @ LiteralType::Address) | PlaintextType::Literal(literal_type @ LiteralType::Group)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_psd4(&fields()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD4,      PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_psd4(&fields()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD8,      PlaintextType::Literal(literal_type @ LiteralType::Address) | PlaintextType::Literal(literal_type @ LiteralType::Group)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_psd8(&fields()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD8,      PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_psd8(&fields()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashSha3_256,  PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp256(&$q($N::hash_sha3_256(&bits()))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashSha3_384,  PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_sha3_384(&bits()))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashSha3_512,  PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_sha3_512(&bits()))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashManyPSD2,  PlaintextType::Literal(_)) => bail!("'hash_many.psd2' is not yet implemented"),
            (HashVariant::HashManyPSD4,  PlaintextType::Literal(_)) => bail!("'hash_many.psd4' is not yet implemented"),
            (HashVariant::HashManyPSD8,  PlaintextType::Literal(_)) => bail!("'hash_many.psd8' is not yet implemented"),

            // The variants that hash the raw inputs.
            (HashVariant::HashBHP256Raw,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp256(&bits_raw()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashBHP512Raw,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&bits_raw()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashBHP768Raw,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp768(&bits_raw()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashBHP1024Raw,   PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp1024(&bits_raw()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashKeccak256Raw, PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp256(&$q($N::hash_keccak256(&check_multiple_of_8(bits_raw())?))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashKeccak384Raw, PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_keccak384(&check_multiple_of_8(bits_raw())?))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashKeccak512Raw, PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_keccak512(&check_multiple_of_8(bits_raw())?))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPED64Raw,     PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_ped64(&bits_raw()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPED128Raw,    PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_ped128(&bits_raw()))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD2Raw,      PlaintextType::Literal(literal_type @ LiteralType::Address) | PlaintextType::Literal(literal_type @ LiteralType::Group)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_psd2(&fields_raw()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD2Raw,      PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_psd2(&fields_raw()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD4Raw,      PlaintextType::Literal(literal_type @ LiteralType::Address) | PlaintextType::Literal(literal_type @ LiteralType::Group)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_psd4(&fields_raw()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD4Raw,      PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_psd4(&fields_raw()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD8Raw,      PlaintextType::Literal(literal_type @ LiteralType::Address) | PlaintextType::Literal(literal_type @ LiteralType::Group)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_psd8(&fields_raw()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashPSD8Raw,      PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_psd8(&fields_raw()?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashSha3_256Raw,  PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp256(&$q($N::hash_sha3_256(&check_multiple_of_8(bits_raw())?))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashSha3_384Raw,  PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_sha3_384(&check_multiple_of_8(bits_raw())?))?))?).cast_lossy(*literal_type)?),
            (HashVariant::HashSha3_512Raw,  PlaintextType::Literal(literal_type)) => <$pt>::from(<$lt>::from($q($N::hash_to_group_bhp512(&$q($N::hash_sha3_512(&check_multiple_of_8(bits_raw())?))?))?).cast_lossy(*literal_type)?),

            // The variants that perform the underlying hash, returning bit arrays.
            (HashVariant::HashKeccak256Native,    PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_keccak256(&bits()))?, **array_type.length())?,
            (HashVariant::HashKeccak256NativeRaw, PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_keccak256(&check_multiple_of_8(bits_raw())?))?, **array_type.length())?,
            (HashVariant::HashKeccak384Native,    PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_keccak384(&bits()))?, **array_type.length())?,
            (HashVariant::HashKeccak384NativeRaw, PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_keccak384(&check_multiple_of_8(bits_raw())?))?, **array_type.length())?,
            (HashVariant::HashKeccak512Native,    PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_keccak512(&bits()))?, **array_type.length())?,
            (HashVariant::HashKeccak512NativeRaw, PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_keccak512(&check_multiple_of_8(bits_raw())?))?, **array_type.length())?,
            (HashVariant::HashSha3_256Native,     PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_sha3_256(&bits()))?, **array_type.length())?,
            (HashVariant::HashSha3_256NativeRaw,  PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_sha3_256(&check_multiple_of_8(bits_raw())?))?, **array_type.length())?,
            (HashVariant::HashSha3_384Native,     PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_sha3_384(&bits()))?, **array_type.length())?,
            (HashVariant::HashSha3_384NativeRaw,  PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_sha3_384(&check_multiple_of_8(bits_raw())?))?, **array_type.length())?,
            (HashVariant::HashSha3_512Native,     PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_sha3_512(&bits()))?, **array_type.length())?,
            (HashVariant::HashSha3_512NativeRaw,  PlaintextType::Array(array_type)) => <$pt>::from_bit_array($q($N::hash_sha3_512(&check_multiple_of_8(bits_raw())?))?, **array_type.length())?,
            (_, destination_type) => bail!("Invalid destination type '{destination_type}' for 'hash' variant: {}", $variant.opcode()),
        }
    }};
}

/// Evaluate a hash operation.
///
/// This allows running the hash without the machinery of stacks and registers.
/// This is necessary for the Leo interpreter.
pub fn evaluate_hash<N: Network>(
    variant: HashVariant,
    input: &Value<N>,
    destination_type: &PlaintextType<N>,
) -> Result<Plaintext<N>> {
    evaluate_hash_internal(variant, input, destination_type)
}

fn evaluate_hash_internal<N: Network>(
    variant: HashVariant,
    input: &Value<N>,
    destination_type: &PlaintextType<N>,
) -> Result<Plaintext<N>> {
    Ok(do_hash!(N, variant, destination_type, input, Plaintext::<N>, Literal::<N>, |x| x))
}

impl<N: Network, const VARIANT: u8> HashInstruction<N, VARIANT> {
    /// Evaluates the instruction.
    pub fn evaluate(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersTrait<N>) -> Result<()> {
        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, Self::opcode(), self.operands.len())?;
        // Ensure the destination type is valid.
        ensure!(
            is_valid_destination_type(VARIANT, &self.destination_type),
            "Invalid destination type in 'hash' instruction"
        );

        // Load the operand.
        let input = registers.load(stack, &self.operands[0])?;

        // Compute the output.
        let output = evaluate_hash_internal(HashVariant::new(VARIANT), &input, &self.destination_type)?;

        // Store the output.
        registers.store(stack, &self.destination, Value::Plaintext(output))
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        use circuit::traits::{ToBits, ToBitsRaw, ToFields, ToFieldsRaw};

        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, Self::opcode(), self.operands.len())?;
        // Ensure the destination type is valid.
        ensure!(
            is_valid_destination_type(VARIANT, &self.destination_type),
            "Invalid destination type in 'hash' instruction"
        );

        // Load the operand.
        let input = registers.load_circuit(stack, &self.operands[0])?;

        // Compute the output.
        let output = do_hash!(
            A,
            HashVariant::new(VARIANT),
            &self.destination_type,
            input,
            circuit::Plaintext::<A>,
            circuit::Literal::<A>,
            Result::<_>::Ok
        );

        // Store the output.
        registers.store_circuit(stack, &self.destination, circuit::Value::Plaintext(output))
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        self.evaluate(stack, registers)
    }

    /// Returns the output type from the given program and input types.
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        check_number_of_operands(VARIANT, Self::opcode(), input_types.len())?;
        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, Self::opcode(), self.operands.len())?;
        // Ensure the destination type is valid.
        ensure!(
            is_valid_destination_type(VARIANT, &self.destination_type),
            "Invalid destination type in 'hash' instruction"
        );

        // Get the variant.
        let variant = HashVariant::new(VARIANT);

        // If the variant needs to be byte aligned, check that its size in bits is a multiple of 8.
        if variant.requires_byte_alignment() {
            // Check that there is only one operand type.
            ensure!(
                variant.expected_num_operands() == 1,
                "Expected one operand for '{}', found '{}'",
                variant.opcode(),
                variant.expected_num_operands()
            );

            // A helper to get a struct declaration.
            let get_struct = |identifier: &Identifier<N>| stack.program().get_struct(identifier).cloned();

            // A helper to get an external struct declaration.
            let get_external_struct = |locator: &Locator<N>| {
                stack.get_external_stack(locator.program_id())?.program().get_struct(locator.resource()).cloned()
            };

            // A helper to get a record declaration.
            let get_record = |identifier: &Identifier<N>| stack.program().get_record(identifier).cloned();

            // A helper to get an external record declaration.
            let get_external_record = |locator: &Locator<N>| {
                stack.get_external_stack(locator.program_id())?.program().get_record(locator.resource()).cloned()
            };

            // A helper to get the argument types of a future.
            let get_future = |locator: &Locator<N>| {
                Ok(match stack.program_id() == locator.program_id() {
                    true => stack
                        .program()
                        .get_function_ref(locator.resource())?
                        .finalize_logic()
                        .ok_or_else(|| anyhow!("'{locator}' does not have a finalize scope"))?
                        .input_types(),
                    false => stack
                        .get_external_stack(locator.program_id())?
                        .program()
                        .get_function_ref(locator.resource())?
                        .finalize_logic()
                        .ok_or_else(|| anyhow!("Failed to find function '{locator}'"))?
                        .input_types(),
                })
            };

            // Get the size in bits.
            let size_in_bits = match variant.is_raw() {
                false => input_types[0].size_in_bits(
                    &get_struct,
                    &get_external_struct,
                    &get_record,
                    &get_external_record,
                    &get_future,
                )?,
                true => input_types[0].size_in_bits_raw(
                    &get_struct,
                    &get_external_struct,
                    &get_record,
                    &get_external_record,
                    &get_future,
                )?,
            };
            // Check the number of bits.
            ensure!(
                size_in_bits % 8 == 0,
                "Expected a multiple of 8 bits for '{}', found '{size_in_bits}'",
                variant.opcode()
            );
        }

        // TODO (howardwu): If the operation is Pedersen, check that it is within the number of bits.

        match variant {
            HashVariant::HashManyPSD2 | HashVariant::HashManyPSD4 | HashVariant::HashManyPSD8 => {
                bail!("'hash_many' is not yet implemented")
            }
            _ => Ok(vec![RegisterType::Plaintext(self.destination_type.clone())]),
        }
    }
}

impl<N: Network, const VARIANT: u8> Parser for HashInstruction<N, VARIANT> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parse the operands from the string.
        fn parse_operands<N: Network>(string: &str, num_operands: usize) -> ParserResult<'_, Vec<Operand<N>>> {
            let mut operands = Vec::with_capacity(num_operands);
            let mut string = string;

            for _ in 0..num_operands {
                // Parse the whitespace from the string.
                let (next_string, _) = Sanitizer::parse_whitespaces(string)?;
                // Parse the operand from the string.
                let (next_string, operand) = Operand::parse(next_string)?;
                // Update the string.
                string = next_string;
                // Push the operand.
                operands.push(operand);
            }

            Ok((string, operands))
        }

        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the operands from the string.
        let (string, operands) = parse_operands(string, HashVariant::new(VARIANT).expected_num_operands())?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "into" from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "as" from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register type from the string.
        let (string, destination_type) = PlaintextType::parse(string)?;
        // Ensure the destination type is allowed.
        match destination_type {
            PlaintextType::Literal(LiteralType::Boolean)
            | PlaintextType::Literal(LiteralType::String)
            | PlaintextType::Literal(LiteralType::Identifier) => map_res(fail, |_: ParserResult<Self>| {
                Err(error(format!("Failed to parse 'hash': '{destination_type}' is invalid")))
            })(string),
            _ => Ok((string, Self { operands, destination, destination_type })),
        }
    }
}

impl<N: Network, const VARIANT: u8> FromStr for HashInstruction<N, VARIANT> {
    type Err = Error;

    /// Parses a string into an operation.
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network, const VARIANT: u8> Debug for HashInstruction<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for HashInstruction<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, Self::opcode(), self.operands.len()).map_err(|_| fmt::Error)?;
        // Print the operation.
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {} as {}", self.destination, self.destination_type)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for HashInstruction<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Prepare the number of operands.
        let num_operands = HashVariant::new(VARIANT).expected_num_operands();
        // Read the operands.
        let operands = (0..num_operands).map(|_| Operand::read_le(&mut reader)).collect::<Result<_, _>>()?;
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;
        // Read the destination register type.
        let destination_type = PlaintextType::read_le(&mut reader)?;
        // Return the operation.
        Ok(Self { operands, destination, destination_type })
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for HashInstruction<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is correct.
        check_number_of_operands(VARIANT, Self::opcode(), self.operands.len()).map_err(|e| error(format!("{e}")))?;
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the destination register.
        self.destination.write_le(&mut writer)?;
        // Write the destination register type.
        self.destination_type.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{network::MainnetV0, program::ArrayType, types::U32};

    type CurrentNetwork = MainnetV0;

    /// **Attention**: When changing this, also update in `tests/instruction/hash.rs`.
    fn sample_valid_destination_types<N: Network, R: CryptoRng + Rng>(
        variant: u8,
        rng: &mut R,
    ) -> Vec<PlaintextType<N>> {
        match variant {
            0..=32 => vec![
                PlaintextType::Literal(LiteralType::Address),
                PlaintextType::Literal(LiteralType::Field),
                PlaintextType::Literal(LiteralType::Group),
                PlaintextType::Literal(LiteralType::I8),
                PlaintextType::Literal(LiteralType::I16),
                PlaintextType::Literal(LiteralType::I32),
                PlaintextType::Literal(LiteralType::I64),
                PlaintextType::Literal(LiteralType::I128),
                PlaintextType::Literal(LiteralType::U8),
                PlaintextType::Literal(LiteralType::U16),
                PlaintextType::Literal(LiteralType::U32),
                PlaintextType::Literal(LiteralType::U64),
                PlaintextType::Literal(LiteralType::U128),
                PlaintextType::Literal(LiteralType::Scalar),
            ],
            33..=44 => (0..10)
                .map(|_| {
                    PlaintextType::Array(
                        ArrayType::new(PlaintextType::Literal(LiteralType::Boolean), vec![U32::new(
                            u32::try_from(rng.random_range(1..=CurrentNetwork::LATEST_MAX_ARRAY_ELEMENTS())).unwrap(),
                        )])
                        .unwrap(),
                    )
                })
                .collect(),
            _ => panic!("Invalid 'hash' instruction opcode"),
        }
    }

    // A helper function to run a test.
    fn run_test<N: Network, const VARIANT: u8>() {
        // Initialize the RNG.
        let rng = &mut TestRng::default();

        // Get the opcode.
        let opcode = HashInstruction::<N, VARIANT>::opcode();

        for destination_type in sample_valid_destination_types(VARIANT, rng) {
            let instruction = format!("{opcode} r0 into r1 as {destination_type}");
            println!("Testing instruction: '{instruction}'");

            let (string, hash) = HashInstruction::<CurrentNetwork, VARIANT>::parse(&instruction).unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            assert_eq!(hash.operands.len(), 1, "The number of operands is incorrect");
            assert_eq!(hash.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
            assert_eq!(hash.destination, Register::Locator(1), "The destination register is incorrect");
            assert_eq!(&hash.destination_type, &destination_type, "The destination type is incorrect");
        }
    }

    #[test]
    fn test_parse() {
        run_test::<CurrentNetwork, { HashVariant::HashBHP256 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashBHP512 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashBHP768 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashBHP1024 as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashKeccak256 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak384 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak512 as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashPED64 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashPED128 as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashPSD2 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashPSD4 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashPSD8 as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashSha3_256 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_384 as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_512 as u8 }>();

        // Note: `run_test` needs to be updated when `hash_many` is implemented.
        //run_test::<CurrentNetwork, { HashVariant::HashManyPSD2 as u8 }>();
        //run_test::<CurrentNetwork, { HashVariant::HashManyPSD4 as u8 }>();
        //run_test::<CurrentNetwork, { HashVariant::HashManyPSD8 as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashBHP256Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashBHP512Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashBHP768Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashBHP1024Raw as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashKeccak256Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak384Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak512Raw as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashPED64Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashPED128Raw as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashPSD2Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashPSD4Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashPSD8Raw as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashSha3_256Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_384Raw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_512Raw as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashKeccak256Native as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak384Native as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak512Native as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashSha3_256Native as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_384Native as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_512Native as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashKeccak256NativeRaw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak384NativeRaw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashKeccak512NativeRaw as u8 }>();

        run_test::<CurrentNetwork, { HashVariant::HashSha3_256NativeRaw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_384NativeRaw as u8 }>();
        run_test::<CurrentNetwork, { HashVariant::HashSha3_512NativeRaw as u8 }>();
    }

    #[test]
    fn check_number_of_hash_variants() {
        assert_eq!(enum_iterator::cardinality::<HashVariant>(), 45);
    }

    #[test]
    fn check_byte_aligned_variants_all_have_one_opcode() {
        for variant in enum_iterator::all::<HashVariant>() {
            if variant.requires_byte_alignment() {
                assert_eq!(variant.expected_num_operands(), 1)
            }
        }
    }
}
