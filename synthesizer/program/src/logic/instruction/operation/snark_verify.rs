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
    program::{Literal, LiteralType, Plaintext, PlaintextType, Register, RegisterType, Value},
    types::Boolean,
};
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_synthesizer_snark::{Proof, VerifyingKey};

/// Computes whether `proof` is valid for the given `verifying_key` and `public inputs`.
pub type SnarkVerify<N> = SnarkVerification<N, { SnarkVerifyVariant::Varuna as u8 }>;
/// Computes whether a `batch_proof` is valid for the given `verifying_keys` and `public inputs`.
pub type SnarkVerifyBatch<N> = SnarkVerification<N, { SnarkVerifyVariant::VarunaBatch as u8 }>;

// TODO (raychu86): SnarkVerify - Consider increasing this limit in the future.
/// The maximum number of `snark.verify` circuits supported in a batch verification.
pub const MAX_SNARK_VERIFY_CIRCUITS: u32 = 1 << 5; // 32
/// The maximum number of proof instances that can be verified in a single `snark.verify.batch` instruction.
/// Note: This limit is independent to the total number of circuit instances that may exist in an `Execution` proof.
pub const MAX_SNARK_VERIFY_INSTANCES: u32 = 1 << 7; // 128

/// Which verification variant to use (single-proof or batch).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SnarkVerifyVariant {
    Varuna,
    VarunaBatch,
}

impl SnarkVerifyVariant {
    // Initializes a new `SnarkVerifyVariant`.
    pub const fn new(variant: u8) -> Self {
        match variant {
            0 => Self::Varuna,
            1 => Self::VarunaBatch,
            // Only `SnarkVerify` (VARIANT=0) and `SnarkVerifyBatch` (VARIANT=1) are publicly exposed.
            _ => panic!("Invalid 'snark.verify' instruction opcode"),
        }
    }

    // Returns the opcode associated with the variant.
    pub const fn opcode(&self) -> &'static str {
        match self {
            Self::Varuna => "snark.verify",
            Self::VarunaBatch => "snark.verify.batch",
        }
    }
}

/// Computes whether `proof` is valid for the given `verifying_key` and `public inputs`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SnarkVerification<N: Network, const VARIANT: u8> {
    /// The operands.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
}

impl<N: Network, const VARIANT: u8> SnarkVerification<N, VARIANT> {
    /// Initializes a new `snark.verify` instruction.
    #[inline]
    pub fn new(operands: Vec<Operand<N>>, destination: Register<N>) -> Result<Self> {
        // Sanity check the number of operands.
        ensure!(operands.len() == 4, "Instruction '{}' must have four operands", Self::opcode());
        // Return the instruction.
        Ok(Self { operands, destination })
    }

    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Snark(SnarkVerifyVariant::new(VARIANT).opcode())
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that there are exactly four operands.
        debug_assert!(self.operands.len() == 4, "Instruction '{}' must have four operands", Self::opcode());
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

/// Perform the snark verification based on the variant.
#[rustfmt::skip]
macro_rules! do_snark_verification {
    ($variant: expr, $function_name: expr, $verifying_key: expr, $varuna_version: expr, $inputs: expr, $proof: expr, $consensus_version: expr) => {{
        let verifying_key = || match $verifying_key {
            Value::Plaintext(plaintext) => VerifyingKey::<N>::from_bytes_le(&plaintext.as_byte_array()?),
            _ => bail!("Expected the first operand to be a byte array."),
        };
        let verifying_keys = || match $verifying_key {
            Value::Plaintext(Plaintext::Array(array, _)) => {
                array
                    .into_iter()
                    .map(|plaintext| {
                        VerifyingKey::<N>::from_bytes_le(&plaintext.as_byte_array()?)
                    })
                    .collect::<Result<Vec<VerifyingKey<N>>, _>>()
            }
            _ => bail!("Expected the first operand to be a two-dimensional byte array."),
        };

        let varuna_version = || match $varuna_version {
            Value::Plaintext(Plaintext::Literal(Literal::U8(version), _)) => {
                let version = VarunaVersion::from_bytes_le(&[*version])?;
                match version {
                    VarunaVersion::V1 | VarunaVersion::V2 => {
                        if $consensus_version.is_some_and(|version| version >= ConsensusVersion::V21) {
                            return Err(io_error("Varuna V3 is required for snark verification").into());
                        }
                    }
                    VarunaVersion::V3 => {
                        if $consensus_version.is_some_and(|version| version < ConsensusVersion::V21) {
                            return Err(io_error("Invalid Varuna version").into());
                        }
                    }
                }
                Ok(version)
            }
            _ => bail!("Expected the Varuna version to be a U8 literal."),
        };

        let inputs = || match $inputs {
            Value::Plaintext(plaintext) => Ok(plaintext.as_field_array()?.into_iter().map(|f| *f).collect::<Vec<_>>()),
            _ => bail!("Expected the second operand to be an array of fields."),
        };
        let batch_inputs = || match $inputs {
            Value::Plaintext(Plaintext::Array(outer, _)) => {
                outer
                    .into_iter()
                    .map(|mid| {
                        match mid {
                            Plaintext::Array(inner, _) => {
                                inner
                                    .into_iter()
                                    .map(|row| {
                                        let fs = row.as_field_array()?;
                                        Ok(fs.into_iter().map(|f| *f).collect::<Vec<N::Field>>())
                                    })
                                    .collect::<Result<Vec<Vec<N::Field>>>>()
                            }
                            _ => bail!("Expected an inner array (second dimension) of fields."),
                        }
                    })
                    .collect::<Result<Vec<Vec<Vec<N::Field>>>>>()
            }
            _ => bail!("Expected the second operand to be a three-dimensional array of fields."),
        };

        let varuna_proof = || match $proof {
            Value::Plaintext(plaintext) => {
                // Get the plaintext as a byte array.
                let bytes = plaintext.as_byte_array()?;
                // Deserialize the proof.
                Proof::<N>::from_bytes_le(&bytes)
            }
            _ => bail!("Expected the third operand to be a byte array."),
        };

        // Checks that the number of public inputs matches the verifying key's expectation and any excess inputs are zero.
        // Returns the trimmed inputs.
        let trimmed_inputs = |vk: &VerifyingKey<N>, inputs: &[N::Field]| -> Result<Vec<N::Field>> {
            // Ensure there are at least as many public inputs as expected.
            let num_public_inputs = vk.circuit_info.num_public_inputs as usize;
            ensure!(
                inputs.len() >= num_public_inputs,
                "The number of public inputs ({}) is less than the expected number of public inputs ({}).",
                inputs.len(),
                num_public_inputs
            );
            // Ensure any excess public inputs are zero.
            for input in &inputs[num_public_inputs..] {
                ensure!(input.is_zero(), "Excess public inputs must be zero.");
            }
            // Return the inputs trimmed to the expected length.
            Ok(inputs[..num_public_inputs].to_vec())
        };

        match $variant {
            SnarkVerifyVariant::Varuna => {
                let vk = verifying_key()?;
                let inputs_vec = inputs()?;
                let trimmed = trimmed_inputs(&vk, &inputs_vec)?;
                vk.verify($function_name, varuna_version()?, &trimmed, &varuna_proof()?)
            }
            SnarkVerifyVariant::VarunaBatch => {
                let vks = verifying_keys()?;
                let batch_inputs_vec = batch_inputs()?;
                // Ensure the number of verifying keys matches the number of input batches.
                ensure!(
                    vks.len() == batch_inputs_vec.len(),
                    "The number of verifying keys ({}) does not match the number of input batches ({})",
                    vks.len(),
                    batch_inputs_vec.len()
                );
                // Validate and trim each instance against its verifying key
                let trimmed_batch: Vec<Vec<Vec<N::Field>>> = vks
                    .iter()
                    .zip_eq(batch_inputs_vec.iter())
                    .map(|(vk, instances)| {
                        instances
                            .iter()
                            .map(|instance_inputs| trimmed_inputs(vk, instance_inputs))
                            .collect::<Result<Vec<Vec<N::Field>>>>()
                    })
                    .collect::<Result<Vec<Vec<Vec<N::Field>>>>>()?;
                VerifyingKey::verify_batch(
                    $function_name,
                    varuna_version()?,
                    vks.into_iter().zip_eq(trimmed_batch).collect(),
                    &varuna_proof()?
                ).is_ok()
            }
        }
    }};
}

/// Evaluate a snark verification operation.
///
/// This is necessary for the Leo interpreter.
pub fn evaluate_varuna_proof<N: Network>(
    variant: SnarkVerifyVariant,
    _function_name: &str,
    verifying_key: &Value<N>,
    varuna_version: Value<N>,
    inputs: &Value<N>,
    proof: &Value<N>,
) -> Result<bool> {
    evaluate_varuna_proof_internal(variant, _function_name, verifying_key, varuna_version, inputs, proof, None)
}

fn evaluate_varuna_proof_internal<N: Network>(
    variant: SnarkVerifyVariant,
    _function_name: &str,
    verifying_key: &Value<N>,
    varuna_version: Value<N>,
    inputs: &Value<N>,
    proof: &Value<N>,
    consensus_version: Option<ConsensusVersion>,
) -> Result<bool> {
    Ok(do_snark_verification!(variant, _function_name, verifying_key, varuna_version, inputs, proof, consensus_version))
}

// Helper function to check if a type is a N-dimensional array of a given base literal type.
fn check_nd_array_type<N: Network>(
    register_type: &RegisterType<N>,
    base_literal_type: LiteralType,
    dimensions: usize,
) -> bool {
    // Special-case 0D: the type itself must be the literal.
    if dimensions == 0 {
        return matches!(register_type, RegisterType::Plaintext(PlaintextType::Literal(lit)) if *lit == base_literal_type);
    }

    // First dimension must be an array.
    let mut arr = match register_type {
        RegisterType::Plaintext(PlaintextType::Array(a)) => a,
        _ => return false,
    };

    // Walk through (dimensions - 1) inner array levels.
    for _ in 1..dimensions {
        match arr.next_element_type() {
            PlaintextType::Array(next) => arr = next,
            _ => return false,
        }
    }

    // Final base element must be the requested literal type.
    matches!(arr.next_element_type(), PlaintextType::Literal(lit) if *lit == base_literal_type)
        && matches!(arr.base_element_type(), PlaintextType::Literal(lit) if *lit == base_literal_type)
}

impl<N: Network, const VARIANT: u8> SnarkVerification<N, VARIANT> {
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
        if self.operands.len() != 4 {
            bail!("Instruction '{}' expects 4 operands, found {} operands", Self::opcode(), self.operands.len())
        }

        // Retrieve the inputs.
        let verifying_key = registers.load(stack, &self.operands[0])?;
        let varuna_version = registers.load(stack, &self.operands[1])?;
        let inputs = registers.load(stack, &self.operands[2])?;
        let proof = registers.load(stack, &self.operands[3])?;

        // Verify the proof.
        let _function_name = "snark.verify";
        let output = evaluate_varuna_proof_internal(
            SnarkVerifyVariant::new(VARIANT),
            _function_name,
            &verifying_key,
            varuna_version,
            &inputs,
            &proof,
            Some(N::CONSENSUS_VERSION(registers.state().block_height())?),
        )?;
        let output = Literal::Boolean(Boolean::new(output));

        // Store the output.
        registers.store_literal(stack, &self.destination, output)
    }

    /// Returns the output type from the given program and input types.
    #[inline]
    pub fn output_types(
        &self,
        _stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        if input_types.len() != 4 {
            bail!("Instruction '{}' expects 4 inputs, found {} inputs", Self::opcode(), input_types.len())
        }

        // Enforce that the verifying key input matches the expected type based on the variant.
        let variant = SnarkVerifyVariant::new(VARIANT);

        // Ensure the array type for the first operand (the VKs) is correct.
        let (result, expected_type, num_vks) = match variant {
            SnarkVerifyVariant::Varuna => (check_nd_array_type(&input_types[0], LiteralType::U8, 1), "a byte array", 1),
            SnarkVerifyVariant::VarunaBatch => {
                // For batch verification, extract the number of circuits from the outer array dimension.
                // Zero is allowed here; non-zero is enforced later when comparing against num_circuits.
                let num_vks = match &input_types[0] {
                    RegisterType::Plaintext(PlaintextType::Array(array_type)) => **array_type.length(),
                    _ => 0,
                };
                (check_nd_array_type(&input_types[0], LiteralType::U8, 2), "a 2-dimensional byte array", num_vks)
            }
        };
        if !result {
            bail!(
                "Instruction '{}' expects the first input to be {}. Found input of type '{}'",
                Self::opcode(),
                expected_type,
                &input_types[0]
            );
        }

        // Ensure the second operand (the Varuna version) is a U8 literal.
        ensure!(
            matches!(input_types[1], RegisterType::Plaintext(PlaintextType::Literal(LiteralType::U8))),
            "Instruction '{}' expects the second input to be a U8 literal. Found input of type '{}'",
            Self::opcode(),
            &input_types[1]
        );

        // Ensure the array type for the third operand (the inputs) is correct.
        let (result, expected_type, num_circuits, num_instances) = match variant {
            SnarkVerifyVariant::Varuna => {
                (check_nd_array_type(&input_types[2], LiteralType::Field, 1), "an array of fields", 1, 1)
            }
            SnarkVerifyVariant::VarunaBatch => {
                // Count the number of circuits and total instances from the outer array length.
                let (num_circuits, num_instances) = match &input_types[2] {
                    RegisterType::Plaintext(PlaintextType::Array(array_type)) => {
                        // The number of circuits with unique verifying keys.
                        let num_circuits = **array_type.length();
                        // The total number of instances across all circuits.
                        let num_instances = match array_type.next_element_type() {
                            PlaintextType::Array(inner_array_type) => **inner_array_type.length() * num_circuits,
                            _ => bail!(
                                "Instruction '{}' expects the third input to be a 3-dimensional array of fields. Found input of type '{}'",
                                Self::opcode(),
                                &input_types[2]
                            ),
                        };
                        (num_circuits, num_instances)
                    }
                    _ => (0, 0),
                };
                (
                    check_nd_array_type(&input_types[2], LiteralType::Field, 3),
                    "a 3-dimensional array of fields",
                    num_circuits,
                    num_instances,
                )
            }
        };
        if !result {
            bail!(
                "Instruction '{}' expects the third input to be {}. Found input of type '{}'",
                Self::opcode(),
                expected_type,
                &input_types[2]
            );
        }

        // Check the number of batched instances is correct.
        ensure!(
            num_circuits == num_vks,
            "Instruction '{}' expects the number of circuits ({num_circuits}) to match the number of verifying keys ({num_vks}).",
            Self::opcode()
        );
        // Check that the number of circuits is properly bound.
        ensure!(
            num_circuits <= MAX_SNARK_VERIFY_CIRCUITS,
            "Instruction '{}' supports a maximum of {MAX_SNARK_VERIFY_CIRCUITS} batched circuits, found {num_circuits} circuits.",
            Self::opcode()
        );
        // Check that the total number of instances/assignments is properly bound.
        ensure!(
            num_instances <= MAX_SNARK_VERIFY_INSTANCES,
            "Instruction '{}' supports a maximum of {MAX_SNARK_VERIFY_INSTANCES} batched instances, found {num_instances} instances.",
            Self::opcode()
        );

        // Ensure the fourth operand (the proof) is an array of bytes.
        match &input_types[3] {
            RegisterType::Plaintext(PlaintextType::Array(array_type))
                if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8) =>
            {
                // valid byte array
            }
            _ => bail!(
                "Instruction '{}' expects the fourth input to be a byte array. Found input of type '{}'",
                Self::opcode(),
                input_types[3]
            ),
        }

        Ok(vec![RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Boolean))])
    }
}

impl<N: Network, const VARIANT: u8> Parser for SnarkVerification<N, VARIANT> {
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
        // Parse the fourth operand from the string.
        let (string, fourth) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "into" from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;

        Ok((string, Self { operands: vec![first, second, third, fourth], destination }))
    }
}

impl<N: Network, const VARIANT: u8> FromStr for SnarkVerification<N, VARIANT> {
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

impl<N: Network, const VARIANT: u8> Debug for SnarkVerification<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for SnarkVerification<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is 4.
        if self.operands.len() != 4 {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {}", self.destination)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for SnarkVerification<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(4);
        // Read the operands.
        for _ in 0..4 {
            operands.push(Operand::read_le(&mut reader)?);
        }
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;

        // Return the operation.
        Ok(Self { operands, destination })
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for SnarkVerification<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is 4.
        if self.operands.len() != 4 {
            return Err(error(format!("The number of operands must be 4, found {}", self.operands.len())));
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
        let (string, is) = SnarkVerify::<CurrentNetwork>::parse("snark.verify r0 r1 r2 r3 into r4").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 4, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.operands[3], Operand::Register(Register::Locator(3)), "The fourth operand is incorrect");
        assert_eq!(is.destination, Register::Locator(4), "The destination register is incorrect");

        let (string, is) = SnarkVerifyBatch::<CurrentNetwork>::parse("snark.verify.batch r0 r1 r2 r3 into r4").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 4, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.operands[3], Operand::Register(Register::Locator(3)), "The fourth operand is incorrect");
        assert_eq!(is.destination, Register::Locator(4), "The destination register is incorrect");
    }
}
