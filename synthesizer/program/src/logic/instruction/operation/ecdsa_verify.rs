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
    algorithms::{ECDSASignature, Keccak256, Keccak384, Keccak512, Sha3_256, Sha3_384, Sha3_512},
    network::prelude::*,
    program::{Boolean, Identifier, Literal, LiteralType, Locator, PlaintextType, Register, RegisterType, Value},
};
use snarkvm_utilities::bytes_from_bits_le;

/// The ECDSA signature verification instruction using a precomputed digest.
pub type ECDSAVerifyDigest<N> = ECDSAVerify<N, { ECDSAVerifyVariant::Digest as u8 }>;
/// The ECDSA signature verification instruction using a precomputed digest and an Ethereum address.
pub type ECDSAVerifyDigestEth<N> = ECDSAVerify<N, { ECDSAVerifyVariant::DigestEth as u8 }>;

/// The ECDSA signature verification instruction using Keccak256.
pub type ECDSAVerifyKeccak256<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak256 as u8 }>;
/// The ECDSA signature verification instruction using Keccak256 with raw inputs.
pub type ECDSAVerifyKeccak256Raw<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak256Raw as u8 }>;
/// The ECDSA signature verification instruction using Keccak256 and an Ethereum address.
pub type ECDSAVerifyKeccak256Eth<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak256Eth as u8 }>;
/// The ECDSA signature verification instruction using Keccak384.
pub type ECDSAVerifyKeccak384<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak384 as u8 }>;
/// The ECDSA signature verification instruction using Keccak384 with raw inputs.
pub type ECDSAVerifyKeccak384Raw<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak384Raw as u8 }>;
/// The ECDSA signature verification instruction using Keccak384 and an Ethereum address.
pub type ECDSAVerifyKeccak384Eth<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak384Eth as u8 }>;
/// The ECDSA signature verification instruction using Keccak512.
pub type ECDSAVerifyKeccak512<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak512 as u8 }>;
/// The ECDSA signature verification instruction using Keccak512 with raw inputs.
pub type ECDSAVerifyKeccak512Raw<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak512Raw as u8 }>;
/// The ECDSA signature verification instruction using Keccak512 and an Ethereum address.
pub type ECDSAVerifyKeccak512Eth<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashKeccak512Eth as u8 }>;

/// The ECDSA signature verification instruction using SHA3-256.
pub type ECDSAVerifySha3_256<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_256 as u8 }>;
/// The ECDSA signature verification instruction using SHA3-256 with raw inputs.
pub type ECDSAVerifySha3_256Raw<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_256Raw as u8 }>;
/// The ECDSA signature verification instruction using SHA3-256 and an Ethereum address.
pub type ECDSAVerifySha3_256Eth<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_256Eth as u8 }>;
/// The ECDSA signature verification instruction using SHA3-384.
pub type ECDSAVerifySha3_384<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_384 as u8 }>;
/// The ECDSA signature verification instruction using SHA3-384 with raw inputs.
pub type ECDSAVerifySha3_384Raw<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_384Raw as u8 }>;
/// The ECDSA signature verification instruction using SHA3-384 and an Ethereum address.
pub type ECDSAVerifySha3_384Eth<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_384Eth as u8 }>;
/// The ECDSA signature verification instruction using SHA3-512.
pub type ECDSAVerifySha3_512<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_512 as u8 }>;
/// The ECDSA signature verification instruction using SHA3-512 with raw inputs.
pub type ECDSAVerifySha3_512Raw<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_512Raw as u8 }>;
/// The ECDSA signature verification instruction using SHA3-512 and an Ethereum address.
pub type ECDSAVerifySha3_512Eth<N> = ECDSAVerify<N, { ECDSAVerifyVariant::HashSha3_512Eth as u8 }>;

/// Which hash function to use.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ECDSAVerifyVariant {
    Digest,
    DigestEth,
    HashKeccak256,
    HashKeccak256Raw,
    HashKeccak256Eth,
    HashKeccak384,
    HashKeccak384Raw,
    HashKeccak384Eth,
    HashKeccak512,
    HashKeccak512Raw,
    HashKeccak512Eth,
    HashSha3_256,
    HashSha3_256Raw,
    HashSha3_256Eth,
    HashSha3_384,
    HashSha3_384Raw,
    HashSha3_384Eth,
    HashSha3_512,
    HashSha3_512Raw,
    HashSha3_512Eth,
}

impl ECDSAVerifyVariant {
    // Initializes a new `ECDSAVerifyVariant`.
    pub const fn new(variant: u8) -> Self {
        match variant {
            0 => Self::Digest,
            1 => Self::DigestEth,
            2 => Self::HashKeccak256,
            3 => Self::HashKeccak256Raw,
            4 => Self::HashKeccak256Eth,
            5 => Self::HashKeccak384,
            6 => Self::HashKeccak384Raw,
            7 => Self::HashKeccak384Eth,
            8 => Self::HashKeccak512,
            9 => Self::HashKeccak512Raw,
            10 => Self::HashKeccak512Eth,
            11 => Self::HashSha3_256,
            12 => Self::HashSha3_256Raw,
            13 => Self::HashSha3_256Eth,
            14 => Self::HashSha3_384,
            15 => Self::HashSha3_384Raw,
            16 => Self::HashSha3_384Eth,
            17 => Self::HashSha3_512,
            18 => Self::HashSha3_512Raw,
            19 => Self::HashSha3_512Eth,
            _ => panic!("Invalid 'ecdsa.verify' instruction opcode"),
        }
    }

    // Returns the opcode associated with the variant.
    pub const fn opcode(&self) -> &'static str {
        match self {
            Self::Digest => "ecdsa.verify.digest",
            Self::DigestEth => "ecdsa.verify.digest.eth",
            Self::HashKeccak256 => "ecdsa.verify.keccak256",
            Self::HashKeccak256Raw => "ecdsa.verify.keccak256.raw",
            Self::HashKeccak256Eth => "ecdsa.verify.keccak256.eth",
            Self::HashKeccak384 => "ecdsa.verify.keccak384",
            Self::HashKeccak384Raw => "ecdsa.verify.keccak384.raw",
            Self::HashKeccak384Eth => "ecdsa.verify.keccak384.eth",
            Self::HashKeccak512 => "ecdsa.verify.keccak512",
            Self::HashKeccak512Raw => "ecdsa.verify.keccak512.raw",
            Self::HashKeccak512Eth => "ecdsa.verify.keccak512.eth",
            Self::HashSha3_256 => "ecdsa.verify.sha3_256",
            Self::HashSha3_256Raw => "ecdsa.verify.sha3_256.raw",
            Self::HashSha3_256Eth => "ecdsa.verify.sha3_256.eth",
            Self::HashSha3_384 => "ecdsa.verify.sha3_384",
            Self::HashSha3_384Raw => "ecdsa.verify.sha3_384.raw",
            Self::HashSha3_384Eth => "ecdsa.verify.sha3_384.eth",
            Self::HashSha3_512 => "ecdsa.verify.sha3_512",
            Self::HashSha3_512Raw => "ecdsa.verify.sha3_512.raw",
            Self::HashSha3_512Eth => "ecdsa.verify.sha3_512.eth",
        }
    }

    // Returns true if the variant requires byte alignment.
    pub const fn requires_byte_alignment(&self) -> bool {
        match self {
            Self::Digest => true,
            Self::DigestEth => true,
            Self::HashKeccak256 => false,
            Self::HashKeccak256Raw => true,
            Self::HashKeccak256Eth => true,
            Self::HashKeccak384 => false,
            Self::HashKeccak384Raw => true,
            Self::HashKeccak384Eth => true,
            Self::HashKeccak512 => false,
            Self::HashKeccak512Raw => true,
            Self::HashKeccak512Eth => true,
            Self::HashSha3_256 => false,
            Self::HashSha3_256Raw => true,
            Self::HashSha3_256Eth => true,
            Self::HashSha3_384 => false,
            Self::HashSha3_384Raw => true,
            Self::HashSha3_384Eth => true,
            Self::HashSha3_512 => false,
            Self::HashSha3_512Raw => true,
            Self::HashSha3_512Eth => true,
        }
    }

    // Returns `true` if the variant uses raw bits.
    pub const fn is_raw(&self) -> bool {
        match self {
            Self::Digest => true,
            Self::DigestEth => true,
            Self::HashKeccak256 => false,
            Self::HashKeccak256Raw => true,
            Self::HashKeccak256Eth => true,
            Self::HashKeccak384 => false,
            Self::HashKeccak384Raw => true,
            Self::HashKeccak384Eth => true,
            Self::HashKeccak512 => false,
            Self::HashKeccak512Raw => true,
            Self::HashKeccak512Eth => true,
            Self::HashSha3_256 => false,
            Self::HashSha3_256Raw => true,
            Self::HashSha3_256Eth => true,
            Self::HashSha3_384 => false,
            Self::HashSha3_384Raw => true,
            Self::HashSha3_384Eth => true,
            Self::HashSha3_512 => false,
            Self::HashSha3_512Raw => true,
            Self::HashSha3_512Eth => true,
        }
    }
}

/// Computes whether `signature` is valid for the given `address` and `message`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ECDSAVerify<N: Network, const VARIANT: u8> {
    /// The operands.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
}

impl<N: Network, const VARIANT: u8> ECDSAVerify<N, VARIANT> {
    /// Initializes a new `ecdsa.verify` instruction.
    #[inline]
    pub fn new(operands: Vec<Operand<N>>, destination: Register<N>) -> Result<Self> {
        // Sanity check the number of operands.
        ensure!(operands.len() == 3, "Instruction '{}' must have three operands", Self::opcode());
        // Return the instruction.
        Ok(Self { operands, destination })
    }

    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::ECDSA(ECDSAVerifyVariant::new(VARIANT).opcode())
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that there are exactly three operands.
        debug_assert!(self.operands.len() == 3, "Instruction '{}' must have three operands", Self::opcode());
        // Return the operands.
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

// Perform the ECDSA verification based on the variant.
#[rustfmt::skip]
macro_rules! do_ecdsa_verification {
    ($variant: expr, $signature: expr, $pub_key: expr, $message: expr) => {{
        let bits = || $message.to_bits_le();
        let bits_raw = || $message.to_bits_raw_le();

        let pub_key = || ECDSASignature::verifying_key_from_bytes(&bytes_from_bits_le(&$pub_key.to_bits_raw_le()));
        let ethereum_address = || {
            bytes_from_bits_le(&$pub_key.to_bits_raw_le())
                .try_into()
                .map_err(|_| anyhow!("Failed to parse Ethereum address"))
        };

        let signature_bytes = bytes_from_bits_le(&$signature.to_bits_raw_le());
        let ecdsa_signature = ECDSASignature::from_bytes_le(&signature_bytes)?;

        let output = match $variant {
            ECDSAVerifyVariant::Digest           => ecdsa_signature.verify_with_digest(&pub_key()?, &bits_raw()),
            ECDSAVerifyVariant::DigestEth        => ecdsa_signature.verify_ethereum_with_digest(&ethereum_address()?, &bits_raw()),
            ECDSAVerifyVariant::HashKeccak256    => ecdsa_signature.verify(&pub_key()?, &Keccak256::default(), &bits()),
            ECDSAVerifyVariant::HashKeccak256Raw => ecdsa_signature.verify(&pub_key()?, &Keccak256::default(), &bits_raw()),
            ECDSAVerifyVariant::HashKeccak256Eth => ecdsa_signature.verify_ethereum(&ethereum_address()?, &Keccak256::default(), &bits_raw()),
            ECDSAVerifyVariant::HashKeccak384    => ecdsa_signature.verify(&pub_key()?, &Keccak384::default(), &bits()),
            ECDSAVerifyVariant::HashKeccak384Raw => ecdsa_signature.verify(&pub_key()?, &Keccak384::default(), &bits_raw()),
            ECDSAVerifyVariant::HashKeccak384Eth => ecdsa_signature.verify_ethereum(&ethereum_address()?, &Keccak384::default(), &bits_raw()),
            ECDSAVerifyVariant::HashKeccak512    => ecdsa_signature.verify(&pub_key()?, &Keccak512::default(), &bits()),
            ECDSAVerifyVariant::HashKeccak512Raw => ecdsa_signature.verify(&pub_key()?, &Keccak512::default(), &bits_raw()),
            ECDSAVerifyVariant::HashKeccak512Eth => ecdsa_signature.verify_ethereum(&ethereum_address()?, &Keccak512::default(), &bits_raw()),
            ECDSAVerifyVariant::HashSha3_256     => ecdsa_signature.verify(&pub_key()?, &Sha3_256::default(), &bits()),
            ECDSAVerifyVariant::HashSha3_256Raw  => ecdsa_signature.verify(&pub_key()?, &Sha3_256::default(), &bits_raw()),
            ECDSAVerifyVariant::HashSha3_256Eth  => ecdsa_signature.verify_ethereum(&ethereum_address()?, &Sha3_256::default(), &bits_raw()),
            ECDSAVerifyVariant::HashSha3_384     => ecdsa_signature.verify(&pub_key()?, &Sha3_384::default(), &bits()),
            ECDSAVerifyVariant::HashSha3_384Raw  => ecdsa_signature.verify(&pub_key()?, &Sha3_384::default(), &bits_raw()),
            ECDSAVerifyVariant::HashSha3_384Eth  => ecdsa_signature.verify_ethereum(&ethereum_address()?, &Sha3_384::default(), &bits_raw()),
            ECDSAVerifyVariant::HashSha3_512     => ecdsa_signature.verify(&pub_key()?, &Sha3_512::default(), &bits()),
            ECDSAVerifyVariant::HashSha3_512Raw  => ecdsa_signature.verify(&pub_key()?, &Sha3_512::default(), &bits_raw()),
            ECDSAVerifyVariant::HashSha3_512Eth  => ecdsa_signature.verify_ethereum(&ethereum_address()?, &Sha3_512::default(), &bits_raw()),
        };

        output.is_ok()
    }};
}

/// Evaluate an ECDSA verification operation.
///
/// This allows running the verification without the machinery of stacks and registers.
/// This is necessary for the Leo interpreter.
pub fn evaluate_ecdsa_verification<N: Network>(
    variant: ECDSAVerifyVariant,
    signature: &Value<N>,
    public_key: &Value<N>,
    message: &Value<N>,
) -> Result<bool> {
    evaluate_ecdsa_verification_internal(variant, signature, public_key, message)
}

fn evaluate_ecdsa_verification_internal<N: Network>(
    variant: ECDSAVerifyVariant,
    signature: &Value<N>,
    public_key: &Value<N>,
    message: &Value<N>,
) -> Result<bool> {
    Ok(do_ecdsa_verification!(variant, signature, public_key, message))
}

impl<N: Network, const VARIANT: u8> ECDSAVerify<N, VARIANT> {
    /// Evaluates the instruction.
    #[inline]
    pub fn evaluate(&self, _stack: &impl StackTrait<N>, _registers: &mut impl RegistersTrait<N>) -> Result<()> {
        bail!("Instruction '{}' is currently only supported in finalize", Self::opcode());
    }

    /// Executes the instruction.
    #[inline]
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        _stack: &impl StackTrait<N>,
        _registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        bail!("Instruction '{}' is currently only supported in finalize", Self::opcode());
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        // Ensure the number of operands is correct.
        if self.operands.len() != 3 {
            bail!("Instruction '{}' expects 3 operands, found {} operands", Self::opcode(), self.operands.len())
        }

        // Retrieve the inputs.
        // Note: There is no need to check the types here, as this is done in `output_types`.
        let signature = registers.load(stack, &self.operands[0])?;
        let public_key = registers.load(stack, &self.operands[1])?;
        let message = registers.load(stack, &self.operands[2])?;

        // Perform the verification.
        let output =
            evaluate_ecdsa_verification_internal(ECDSAVerifyVariant::new(VARIANT), &signature, &public_key, &message)?;
        let output = Literal::Boolean(Boolean::new(output));

        // Store the output.
        registers.store_literal(stack, &self.destination, output)
    }

    /// Returns the output type from the given program and input types.
    #[inline]
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        if input_types.len() != 3 {
            bail!("Instruction '{}' expects 3 inputs, found {} inputs", Self::opcode(), input_types.len())
        }

        // Enforce that the signature is an array of 65 bytes.
        match &input_types[0] {
            RegisterType::Plaintext(PlaintextType::Array(array_type))
                if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                    && **array_type.length() as usize == ECDSASignature::SIGNATURE_SIZE_IN_BYTES =>
            {
                // valid signature array
            }
            _ => bail!(
                "Instruction '{}' expects the first input to be a {}-byte array. Found input of type '{}'",
                Self::opcode(),
                ECDSASignature::SIGNATURE_SIZE_IN_BYTES,
                input_types[0]
            ),
        }

        // Get the variant.
        let variant = ECDSAVerifyVariant::new(VARIANT);

        // Expected byte length for the public key input depending on the variant.
        let expected_length = match variant {
            // Non-Ethereum address variant expects a compressed verifying key.
            ECDSAVerifyVariant::Digest
            | ECDSAVerifyVariant::HashKeccak256
            | ECDSAVerifyVariant::HashKeccak256Raw
            | ECDSAVerifyVariant::HashKeccak384
            | ECDSAVerifyVariant::HashKeccak384Raw
            | ECDSAVerifyVariant::HashKeccak512
            | ECDSAVerifyVariant::HashKeccak512Raw
            | ECDSAVerifyVariant::HashSha3_256
            | ECDSAVerifyVariant::HashSha3_256Raw
            | ECDSAVerifyVariant::HashSha3_384
            | ECDSAVerifyVariant::HashSha3_384Raw
            | ECDSAVerifyVariant::HashSha3_512
            | ECDSAVerifyVariant::HashSha3_512Raw => ECDSASignature::VERIFYING_KEY_SIZE_IN_BYTES,
            // Ethereum address variant expects a 20-byte array.
            ECDSAVerifyVariant::DigestEth
            | ECDSAVerifyVariant::HashKeccak256Eth
            | ECDSAVerifyVariant::HashKeccak384Eth
            | ECDSAVerifyVariant::HashKeccak512Eth
            | ECDSAVerifyVariant::HashSha3_256Eth
            | ECDSAVerifyVariant::HashSha3_384Eth
            | ECDSAVerifyVariant::HashSha3_512Eth => ECDSASignature::ETHEREUM_ADDRESS_SIZE_IN_BYTES,
        };

        // Validate that the public key input type is correct.
        match &input_types[1] {
            RegisterType::Plaintext(PlaintextType::Array(array_type))
                if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                    && expected_length == **array_type.length() as usize => {}

            invalid_input_type => bail!(
                "Instruction '{}' expects the second input to be a {}-byte array. Found '{}'",
                Self::opcode(),
                expected_length,
                invalid_input_type
            ),
        }

        // If the variant uses a precomputed digest, ensure the message is a 32-byte array.
        if matches!(variant, ECDSAVerifyVariant::Digest | ECDSAVerifyVariant::DigestEth) {
            // Expected byte length for the digest input.
            let expected_message_length = ECDSASignature::PREHASH_SIZE_IN_BYTES;

            match &input_types[2] {
                RegisterType::Plaintext(PlaintextType::Array(array_type))
                    if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                        && expected_message_length == **array_type.length() as usize => {}

                invalid_input_type => bail!(
                    "Instruction '{}' expects the third input to be a {}-byte array. Found '{}'",
                    Self::opcode(),
                    expected_message_length,
                    invalid_input_type
                ),
            }
        }
        // Otherwise if the variant needs to be byte aligned, check that its size in bits is a multiple of 8.
        else if variant.requires_byte_alignment() {
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

            // Get the size in bits of the message.
            let size_in_bits = match variant.is_raw() {
                false => input_types[2].size_in_bits(
                    &get_struct,
                    &get_external_struct,
                    &get_record,
                    &get_external_record,
                    &get_future,
                )?,
                true => input_types[2].size_in_bits_raw(
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

        Ok(vec![RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Boolean))])
    }
}

impl<N: Network, const VARIANT: u8> Parser for ECDSAVerify<N, VARIANT> {
    /// Parses a string into an operation.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the first operand from the string.
        let (string, first) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the second operand from the string.
        let (string, second) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the third operand from the string.
        let (string, third) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "into" from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;

        Ok((string, Self { operands: vec![first, second, third], destination }))
    }
}

impl<N: Network, const VARIANT: u8> FromStr for ECDSAVerify<N, VARIANT> {
    type Err = Error;

    /// Parses a string into an operation.
    #[inline]
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

impl<N: Network, const VARIANT: u8> Debug for ECDSAVerify<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for ECDSAVerify<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is 3.
        if self.operands.len() != 3 {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {}", self.destination)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for ECDSAVerify<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(3);
        // Read the operands.
        for _ in 0..3 {
            operands.push(Operand::read_le(&mut reader)?);
        }
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;

        // Return the operation.
        Ok(Self { operands, destination })
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for ECDSAVerify<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is 3.
        if self.operands.len() != 3 {
            return Err(error(format!("The number of operands must be 3, found {}", self.operands.len())));
        }
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the destination register.
        self.destination.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, is) = ECDSAVerifyDigest::<CurrentNetwork>::parse("ecdsa.verify.digest r0 r1 r2 into r3").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 3, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(3), "The destination register is incorrect");

        let (string, is) =
            ECDSAVerifyDigestEth::<CurrentNetwork>::parse("ecdsa.verify.digest.eth r0 r1 r2 into r3").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 3, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(3), "The destination register is incorrect");

        let (string, is) =
            ECDSAVerifyKeccak256::<CurrentNetwork>::parse("ecdsa.verify.keccak256 r0 r1 r2 into r3").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 3, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(3), "The destination register is incorrect");

        let (string, is) =
            ECDSAVerifyKeccak256Raw::<CurrentNetwork>::parse("ecdsa.verify.keccak256.raw r0 r1 r2 into r3").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 3, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(3), "The destination register is incorrect");

        let (string, is) =
            ECDSAVerifyKeccak256Eth::<CurrentNetwork>::parse("ecdsa.verify.keccak256.eth r0 r1 r2 into r3").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 3, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(3), "The destination register is incorrect");
    }
}
