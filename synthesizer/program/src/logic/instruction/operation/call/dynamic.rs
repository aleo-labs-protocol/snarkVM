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
    Opcode,
    Operand,
    traits::{FinalizeRegistersState, FinalizeStoreTrait, RegistersCircuit, RegistersTrait, StackTrait},
};

use console::{
    network::prelude::*,
    program::{LiteralType, PlaintextType, Register, RegisterType, ValueType},
};

/// Dynamically calls the operands into the declared type.
/// The first operand must resolve to a field element representing the program name.
/// The second operand must resolve to a field element representing the program network.
/// The third operand must resolve to a field element representing the function name.
/// The remaining operands are the arguments to the call.
/// The destination registers along with their expected types are specified after the `into` keyword.
/// i.e. `call.dynamic r0 r1 r2 with r3 r4 (as address.private u64.private) into r5 r6 (as u64 dynamic.future);`
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CallDynamic<N: Network> {
    /// The operands.
    operands: Vec<Operand<N>>,
    /// The operand types.
    operand_types: Vec<ValueType<N>>,
    /// The destination registers.
    destinations: Vec<Register<N>>,
    /// The destination types.
    destination_types: Vec<ValueType<N>>,
}

impl<N: Network> CallDynamic<N> {
    /// Creates a new dynamic call operation.
    pub fn new(
        operands: Vec<Operand<N>>,
        operand_types: Vec<ValueType<N>>,
        destinations: Vec<Register<N>>,
        destination_types: Vec<ValueType<N>>,
    ) -> Result<Self> {
        // Ensure that there are at least three operands: program name, program network, and function name.
        ensure!(
            operands.len() >= 3,
            "There must be at least three operands: program name, program network, and function name"
        );
        // Ensure that the number of operands is within the bounds.
        // Note that the unwrap is safe since we check that `MAX_OPERANDS` is within `u8::MAX`.
        ensure!(
            operands.len() <= N::MAX_OPERANDS.checked_add(3).expect("MAX_OPERANDS + 3 overflows"),
            "The number of operands must be <= {}",
            N::MAX_OPERANDS.checked_add(3).expect("MAX_OPERANDS + 3 overflows")
        );
        // Ensure that the number of operands and operand types match.
        // Note that the unwrap is safe since we check that there are at least three operands.
        ensure!(
            operands.len().checked_sub(3).expect("operands.len() >= 3 is checked above") == operand_types.len(),
            "The number of operands and operand types must match"
        );
        // Ensure that the operand types do not contain a future, dynamic future, record, external record type, or a constant type.
        // Note: `dynamic.record` (i.e. `ValueType::DynamicRecord`) IS allowed as an input operand type.
        for type_ in &operand_types {
            match type_ {
                ValueType::Constant(_) => bail!("A constant cannot be passed in as input to a dynamic call."),
                ValueType::Record(_) => {
                    bail!("A record cannot be passed in as input to a dynamic call, use `dynamic.record` instead.")
                }
                ValueType::ExternalRecord(_) => {
                    bail!(
                        "An external record cannot be passed in as input to a dynamic call, use `dynamic.record` instead."
                    )
                }
                ValueType::Future(_) => bail!("A future cannot be passed in as input to a dynamic call."),
                ValueType::DynamicFuture => bail!("A dynamic future cannot be passed in as input to a dynamic call."),
                _ => {}
            }
        }
        // Ensure that the number of destinations is within the bounds.
        ensure!(destinations.len() <= N::MAX_OUTPUTS, "The number of destinations must be <= {}", N::MAX_OUTPUTS);
        // Ensure that the number of destinations and destination types match.
        ensure!(
            destinations.len() == destination_types.len(),
            "The number of destination registers and destination types must match"
        );
        // Ensure that the destination types do not contain a future, record, external record type, or a constant type.
        for type_ in &destination_types {
            match type_ {
                ValueType::Constant(_) => bail!("A dynamic call cannot return a constant output."),
                ValueType::Record(_) => bail!("A dynamic call cannot return a record, use `dynamic.record` instead."),
                ValueType::ExternalRecord(_) => {
                    bail!("A dynamic call cannot return an external record, use `dynamic.record` instead.")
                }
                ValueType::Future(_) => bail!("A dynamic call cannot return a future, use `dynamic.future` instead."),
                _ => {}
            }
        }
        Ok(Self { operands, operand_types, destinations, destination_types })
    }
}

impl<N: Network> CallDynamic<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Call("call.dynamic")
    }

    /// Returns the operands.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the operand types.
    #[inline]
    pub fn operand_types(&self) -> &Vec<ValueType<N>> {
        &self.operand_types
    }

    /// Returns the destination registers.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        self.destinations.clone()
    }

    /// Returns the destination types.
    #[inline]
    pub fn destination_types(&self) -> &Vec<ValueType<N>> {
        &self.destination_types
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        self.operand_types.iter().any(|t| t.contains_external_struct())
            || self.destination_types.iter().any(|t| t.contains_external_struct())
    }
}

impl<N: Network> CallDynamic<N> {
    /// Returns `true` if the instruction is a function call.
    #[inline]
    pub fn is_function_call(&self, _stack: &impl StackTrait<N>) -> Result<bool> {
        Ok(true)
    }

    /// Evaluates the instruction.
    pub fn evaluate(&self, _stack: &impl StackTrait<N>, _registers: &mut impl RegistersTrait<N>) -> Result<()> {
        bail!("Forbidden operation: Evaluate cannot invoke a 'call.dynamic' directly.")
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        _stack: &impl StackTrait<N>,
        _registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        bail!("Forbidden operation: Execute cannot invoke a 'call.dynamic' directly.")
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(
        &self,
        _stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        _registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        bail!("Forbidden operation: Finalize cannot invoke a 'call.dynamic'.")
    }

    /// Returns the output type from the given program and input types.
    #[inline]
    pub fn output_types(
        &self,
        _stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        if input_types.len() < 3 {
            bail!("Instruction '{}' expects at least 3 inputs, found {} inputs", Self::opcode(), input_types.len())
        }
        // Ensure the number of input types matches the number of operands.
        if input_types.len() != self.operands.len() {
            bail!(
                "Instruction '{}' expects {} inputs, found {} inputs",
                Self::opcode(),
                self.operands.len(),
                input_types.len()
            )
        }
        // Ensure the number of the input types minus 3 matches the number of operand types.
        // Note that the unwrap is safe since we check that there are at least three input types.
        if input_types.len().checked_sub(3).expect("input_types.len() >= 3 is checked above")
            != self.operand_types.len()
        {
            bail!(
                "Instruction '{}' expects {} operand types, found {} operand types",
                Self::opcode(),
                self.operand_types.len(),
                input_types.len().checked_sub(3).expect("input_types.len() >= 3 is checked above")
            )
        }
        // Ensure the first three input types are field or identifier elements.
        for (i, input_type) in input_types.iter().enumerate().take(3) {
            match input_type {
                RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Field))
                | RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Identifier)) => {}
                _ => bail!(
                    "Instruction '{}' expects input {i} to be a field or identifier element, found '{input_type}'",
                    Self::opcode()
                ),
            }
        }
        // Ensure the remaining input types match the operand types.
        for (i, operand_type) in self.operand_types.iter().enumerate() {
            let input_type = &input_types[i + 3];
            if RegisterType::from(operand_type) != *input_type {
                bail!(
                    "Instruction '{}' expects input {} to be of type '{}', found '{}'",
                    Self::opcode(),
                    i + 3,
                    RegisterType::from(operand_type),
                    input_type
                )
            }
        }
        // Return the output types.
        Ok(self.destination_types.iter().cloned().map(RegisterType::from).collect())
    }
}

impl<N: Network> Parser for CallDynamic<N> {
    /// Parses a string into an operation.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses an operand from the string.
        fn parse_operand<N: Network>(string: &str) -> ParserResult<'_, Operand<N>> {
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the operand from the string.
            Operand::parse(string)
        }

        /// Parses a destination register from the string.
        fn parse_destination<N: Network>(string: &str) -> ParserResult<'_, Register<N>> {
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the destination from the string.
            Register::parse(string)
        }

        /// Parses a value type from the string.
        fn parse_value_type<N: Network>(string: &str) -> ParserResult<'_, ValueType<N>> {
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the destination type from the string.
            ValueType::parse(string)
        }

        /// A helper function to parse a non-empty, parenthesis-delimited sequence of value types.
        /// For example, `(as u64.public dynamic.future)`.
        fn parse_value_types<N: Network>(string: &str) -> ParserResult<'_, Vec<ValueType<N>>> {
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the "(" from the string.
            let (string, _) = tag("(")(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the "as" from the string.
            let (string, _) = tag("as")(string)?;
            // Parse the destination types from the string.
            let (string, destination_types) =
                map_res(many1(parse_value_type), |destination_types: Vec<ValueType<N>>| {
                    // Ensure the number of destination types is within the bounds.
                    match destination_types.len() <= N::MAX_OPERANDS {
                        true => Ok(destination_types),
                        false => Err(error("Failed to parse 'call.dynamic' opcode: too many destination types")),
                    }
                })(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the ")" from the string.
            let (string, _) = tag(")")(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Return the types.
            Ok((string, destination_types))
        }

        // Initialize the operands.
        let mut operands = Vec::new();

        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program name of the call from the string.
        let (string, program_name) = Operand::parse(string)?;
        operands.push(program_name);
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program network of the call from the string.
        let (string, program_network) = Operand::parse(string)?;
        operands.push(program_network);
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the function name of the call from the string.
        let (string, function_name) = Operand::parse(string)?;
        operands.push(function_name);
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Optionally parse the "with" from the string.
        let (string, ops, operand_types) = match opt(tag("with"))(string)? {
            // If the "with" was not parsed, return the string and an empty vector of destinations.
            (string, None) => (string, vec![], vec![]),
            // If the "with" was parsed, parse the operands from the string.
            (string, Some(_)) => {
                // Parse the whitespace from the string.
                let (string, _) = Sanitizer::parse_whitespaces(string)?;
                // Parse the operands from the string.
                let (string, operands) = many_m_n(1, N::MAX_OPERANDS, complete(parse_operand))(string)?;
                // Parse the operand types from the string.
                let (string, operand_types) = parse_value_types(string)?;
                // Return the string, the operands, and the operand types.
                (string, operands, operand_types)
            }
        };
        operands.extend(ops);

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Optionally parse the "into" from the string.
        let (string, destinations, destination_types) = match opt(tag("into"))(string)? {
            // If the "into" was not parsed, return the string and an empty vector of destinations.
            (string, None) => (string, vec![], vec![]),
            // If the "into" was parsed, parse the destinations from the string.
            (string, Some(_)) => {
                // Parse the whitespace from the string.
                let (string, _) = Sanitizer::parse_whitespaces(string)?;
                // Parse the destinations from the string.
                let (string, destinations) = many_m_n(1, N::MAX_OPERANDS, complete(parse_destination))(string)?;
                // Parse the destination types from the string.
                let (string, destination_types) = parse_value_types(string)?;

                // Return the string, the destinations, and the destination types.
                (string, destinations, destination_types)
            }
        };

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Construct the dynamic call operation.
        let instruction = match Self::new(operands, operand_types, destinations, destination_types) {
            Ok(instruction) => instruction,
            Err(_) => {
                return map_res(take(0usize), |_| Err(error("Failed to parse `call.dynamic` instruction".to_string())))(
                    string,
                );
            }
        };

        // Return the remaining string and the instruction.
        Ok((string, instruction))
    }
}

impl<N: Network> FromStr for CallDynamic<N> {
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

impl<N: Network> Debug for CallDynamic<N> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for CallDynamic<N> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure there are at least three operands.
        if self.operands.len() < 3 {
            return Err(fmt::Error);
        }
        // Get the operands.
        let program_name = &self.operands[0];
        let program_network = &self.operands[1];
        let function_name = &self.operands[2];
        let rest = &self.operands[3..];
        // Print the operation.
        write!(f, "{} {program_name} {program_network} {function_name}", Self::opcode())?;
        if !rest.is_empty() {
            write!(f, " with")?;
            rest.iter().try_for_each(|operand| write!(f, " {operand}"))?;
            write!(f, " (as {})", self.operand_types.iter().join(" "))?;
        }
        if !self.destinations.is_empty() {
            write!(f, " into")?;
            self.destinations.iter().try_for_each(|destination| write!(f, " {destination}"))?;
            write!(f, " (as {})", self.destination_types.iter().join(" "))?;
        }
        Ok(())
    }
}

impl<N: Network> FromBytes for CallDynamic<N> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the number of operands.
        let num_operands = u8::read_le(&mut reader)? as usize;
        // Ensure that the number of operands is at least three.
        if num_operands < 3 {
            return Err(error("Failed to read 'call.dynamic' opcode: too few operands."));
        }
        // Determine the number of operand types.
        let num_operand_types = num_operands.checked_sub(3).expect("num_operands >= 3 is checked above");
        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(num_operands);
        // Read the operands.
        for _ in 0..num_operands {
            operands.push(Operand::read_le(&mut reader)?);
        }
        // Initialize the vector for the operand types.
        let mut operand_types = Vec::with_capacity(num_operand_types);
        for _ in 0..num_operand_types {
            operand_types.push(ValueType::read_le(&mut reader)?);
        }
        // Read the number of destination registers.
        let num_destinations = u8::read_le(&mut reader)? as usize;
        // Initialize the vector for the destinations.
        let mut destinations = Vec::with_capacity(num_destinations);
        // Read the destination registers.
        for _ in 0..num_destinations {
            destinations.push(Register::read_le(&mut reader)?);
        }
        // Initialize the vector for the destination types.
        let mut destination_types = Vec::with_capacity(num_destinations);
        for _ in 0..num_destinations {
            destination_types.push(ValueType::read_le(&mut reader)?);
        }
        // Return the operation.
        Self::new(operands, operand_types, destinations, destination_types)
            .map_err(|e| error(format!("Failed to read 'call.dynamic' opcode: {e}.")))
    }
}

impl<N: Network> ToBytes for CallDynamic<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the number of operands.
        u8::try_from(self.operands.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the operand types.
        self.operand_types.iter().try_for_each(|operand_type| operand_type.write_le(&mut writer))?;
        // Write the number of destination register.
        u8::try_from(self.destinations.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the destination registers.
        self.destinations.iter().try_for_each(|destination| destination.write_le(&mut writer))?;
        // Write the destination types.
        self.destination_types.iter().try_for_each(|destination_type| destination_type.write_le(&mut writer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        network::MainnetV0,
        program::{Access, Identifier, LiteralType, PlaintextType},
    };

    type CurrentNetwork = MainnetV0;

    const TEST_CASES: &[&str] = &[
        "call.dynamic r0 r1 r2",
        "call.dynamic r0 r1 r2 with r3 (as u8.public)",
        "call.dynamic r0 r1 r2 with r3.owner (as address.private)",
        "call.dynamic r0 r1 r2 with r3 r4 (as u8.public u64.private)",
        "call.dynamic r0 r1 r2 into r3 r4 (as foo.public bar.private)",
        "call.dynamic r0 r1 r2 into r3 r4 r5 (as u64.public address.private dynamic.future)",
        "call.dynamic r0 r1 r2 with r3 (as boolean.private) into r4 (as u8.private)",
        "call.dynamic r0 r1 r2 with r3 r4 (as u8.public foo.private) into r5 (as boolean.public)",
        "call.dynamic r0 r1 r2 with r3 r4 (as u8.public foo.private) into r5 r6 (as u8.private u64.public)",
        "call.dynamic r0 r1 r2 with r3 r4 r5 (as foo.private dynamic.record boolean.public) into r6 r7 (as u8.private u64.public)",
        "call.dynamic r0 r1 r2 with r3 r4 r5 (as foo.private bar.public boolean.public) into r6 r7 r8 (as u8.private dynamic.record dynamic.future)",
        "call.dynamic r0 r1 r2 with r3 r4 (as address.public u64.public) into r5 (as dynamic.future)",
        "call.dynamic 'credits' 'aleo' 'transfer_public' with aleo1wfyyj2uvwuqw0c0dqa5x70wrawnlkkvuepn4y08xyaqfqqwweqys39jayw 100u64 (as address.private u64.private) into r0 (as dynamic.future)",
    ];

    fn check_parser(
        string: &str,
        expected_operands: Vec<Operand<CurrentNetwork>>,
        expected_destinations: Vec<Register<CurrentNetwork>>,
        expected_destination_types: Vec<ValueType<CurrentNetwork>>,
    ) {
        println!("Checking parser for string: '{string}'");
        // Check that the parser works.
        let (string, call) = CallDynamic::<CurrentNetwork>::parse(string).unwrap();

        // Check that the entire string was consumed.
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        // Check that the operands are correct.
        assert_eq!(call.operands.len(), expected_operands.len(), "The number of operands is incorrect");
        for (i, (given, expected)) in call.operands.iter().zip(expected_operands.iter()).enumerate() {
            assert_eq!(given, expected, "The {i}-th operand is incorrect");
        }

        // Check that the number of destinations and destination types match.
        assert_eq!(
            call.destinations.len(),
            call.destination_types.len(),
            "The number of destinations and destination types do not match"
        );

        // Check that the destinations are correct.
        assert_eq!(call.destinations.len(), expected_destinations.len(), "The number of destinations is incorrect");
        for (i, (given, expected)) in call.destinations.iter().zip(expected_destinations.iter()).enumerate() {
            assert_eq!(given, expected, "The {i}-th destination is incorrect");
        }

        // Check that the destination types are correct.
        assert_eq!(
            call.destination_types.len(),
            expected_destination_types.len(),
            "The number of destination types is incorrect"
        );
        for (i, (given, expected)) in call.destination_types.iter().zip(expected_destination_types.iter()).enumerate() {
            assert_eq!(given, expected, "The {i}-th destination type is incorrect");
        }
    }

    #[test]
    fn test_parse() {
        check_parser(
            "call.dynamic r4 r5 r6 with r0.owner r0.token_amount (as address.private u64.private) into r1 r2 r3 (as u64.public u8.private dynamic.future)",
            vec![
                Operand::Register(Register::Locator(4)),
                Operand::Register(Register::Locator(5)),
                Operand::Register(Register::Locator(6)),
                Operand::Register(Register::Access(0, vec![Access::from(Identifier::from_str("owner").unwrap())])),
                Operand::Register(Register::Access(0, vec![Access::from(
                    Identifier::from_str("token_amount").unwrap(),
                )])),
            ],
            vec![Register::Locator(1), Register::Locator(2), Register::Locator(3)],
            vec![
                ValueType::Public(PlaintextType::Literal(LiteralType::U64)),
                ValueType::Private(PlaintextType::Literal(LiteralType::U8)),
                ValueType::DynamicFuture,
            ],
        );

        check_parser(
            "call.dynamic 'credits' 'aleo' 'transfer_public' with aleo1wfyyj2uvwuqw0c0dqa5x70wrawnlkkvuepn4y08xyaqfqqwweqys39jayw 100u64 (as address.private u64.private) into r0 (as dynamic.future)",
            vec![
                Operand::from_str("'credits'").unwrap(),
                Operand::from_str("'aleo'").unwrap(),
                Operand::from_str("'transfer_public'").unwrap(),
                Operand::from_str("aleo1wfyyj2uvwuqw0c0dqa5x70wrawnlkkvuepn4y08xyaqfqqwweqys39jayw").unwrap(),
                Operand::from_str("100u64").unwrap(),
            ],
            vec![Register::Locator(0)],
            vec![ValueType::DynamicFuture],
        );

        check_parser(
            "call.dynamic r0 r1 r0",
            vec![
                Operand::Register(Register::Locator(0)),
                Operand::Register(Register::Locator(1)),
                Operand::Register(Register::Locator(0)),
            ],
            vec![],
            vec![],
        )
    }

    #[test]
    fn test_display() {
        for expected in TEST_CASES {
            println!("Checking display for string: '{expected}'");
            assert_eq!(CallDynamic::<CurrentNetwork>::from_str(expected).unwrap().to_string(), *expected);
        }
    }

    #[test]
    fn test_bytes() {
        for case in TEST_CASES {
            println!("Checking bytes for string: '{case}'");
            let expected = CallDynamic::<CurrentNetwork>::from_str(case).unwrap();

            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, CallDynamic::read_le(&expected_bytes[..]).unwrap());
        }
    }

    #[test]
    fn test_max_operands() {
        // Sanity check that the max operands is within bounds.
        assert!(CurrentNetwork::MAX_OPERANDS <= usize::from(u8::MAX));
    }

    #[test]
    fn test_external_record_not_allowed_as_input() {
        let result = CallDynamic::<CurrentNetwork>::from_str("call.dynamic r0 r1 r2 with r3 (as foo.aleo/bar.record)");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_not_allowed_as_input() {
        let result = CallDynamic::<CurrentNetwork>::from_str("call.dynamic r0 r1 r2 with r3 (as bar.record)");
        assert!(result.is_err());
    }

    #[test]
    fn test_future_not_allowed_as_input() {
        let result = CallDynamic::<CurrentNetwork>::from_str("call.dynamic r0 r1 r2 with r3 (as foo.aleo/bar.future)");
        assert!(result.is_err());
    }

    #[test]
    fn test_dynamic_record_allowed_as_input() {
        let result = CallDynamic::<CurrentNetwork>::from_str("call.dynamic r0 r1 r2 with r3 (as dynamic.record)");
        assert!(result.is_ok());
    }
}
