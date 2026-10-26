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
    register_types_equivalent,
};
use console::{
    network::prelude::*,
    program::{FinalizeType, Identifier, Locator, Register, RegisterType, Value},
};

/// The operator references a function name or closure name.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum CallOperator<N: Network> {
    /// The reference to a non-local function or closure.
    Locator(Locator<N>),
    /// The reference to a local function or closure.
    Resource(Identifier<N>),
}

impl<N: Network> Parser for CallOperator<N> {
    /// Parses a string into an operator.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        alt((map(Locator::parse, CallOperator::Locator), map(Identifier::parse, CallOperator::Resource)))(string)
    }
}

impl<N: Network> FromStr for CallOperator<N> {
    type Err = Error;

    /// Parses a string into an operator.
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

impl<N: Network> Debug for CallOperator<N> {
    /// Prints the operator as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for CallOperator<N> {
    /// Prints the operator to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CallOperator::Locator(locator) => Display::fmt(locator, f),
            CallOperator::Resource(resource) => Display::fmt(resource, f),
        }
    }
}

impl<N: Network> FromBytes for CallOperator<N> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the variant.
        let variant = u8::read_le(&mut reader)?;
        // Match the variant.
        match variant {
            0 => Ok(CallOperator::Locator(Locator::read_le(&mut reader)?)),
            1 => Ok(CallOperator::Resource(Identifier::read_le(&mut reader)?)),
            _ => Err(error("Failed to read CallOperator. Invalid variant.")),
        }
    }
}

impl<N: Network> ToBytes for CallOperator<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            CallOperator::Locator(locator) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the locator.
                locator.write_le(&mut writer)
            }
            CallOperator::Resource(resource) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the resource.
                resource.write_le(&mut writer)
            }
        }
    }
}

/// Calls the operands into the declared type.
/// i.e. `call transfer r0.owner 0u64 r1.amount into r1 r2;`
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Call<N: Network> {
    /// The reference.
    operator: CallOperator<N>,
    /// The operands.
    operands: Vec<Operand<N>>,
    /// The destination registers.
    destinations: Vec<Register<N>>,
}

impl<N: Network> Call<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Call("call")
    }

    /// Return the operator.
    #[inline]
    pub const fn operator(&self) -> &CallOperator<N> {
        &self.operator
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the destination registers.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        self.destinations.clone()
    }

    /// Returns whether this instruction refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }

    /// Returns `true` if the instruction is a function call.
    #[inline]
    pub fn is_function_call(&self, stack: &impl StackTrait<N>) -> Result<bool> {
        match self.operator() {
            // Check if the locator is for a function.
            CallOperator::Locator(locator) => {
                // Get the external stack.
                let external_stack = stack.get_external_stack(locator.program_id())?;
                // Retrieve the program.
                let program = external_stack.program();
                // Check if the resource is a function.
                Ok(program.contains_function(locator.resource()))
            }
            // Check if the resource is a function.
            CallOperator::Resource(resource) => Ok(stack.program().contains_function(resource)),
        }
    }

    /// Evaluates the instruction.
    pub fn evaluate(&self, _stack: &impl StackTrait<N>, _registers: &mut impl RegistersTrait<N>) -> Result<()> {
        bail!("Forbidden operation: Evaluate cannot invoke a 'call' directly. Use 'call' in 'Stack' instead.")
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        _stack: &impl StackTrait<N>,
        _registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        bail!("Forbidden operation: Execute cannot invoke a 'call' directly. Use 'call' in 'Stack' instead.")
    }

    /// Finalizes the instruction.
    ///
    /// In a finalize context, the only legal `call` target is a view function (gated at
    /// deploy time by `check_instruction_opcode`). Loads operand values from `caller_registers`,
    /// dispatches the view body through `StackTrait::evaluate_view` against the appropriate
    /// target stack (same-program for `CallOperator::Resource`, external for `Locator`), and
    /// writes outputs back into the caller's destination registers.
    #[inline]
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        store: Option<&dyn FinalizeStoreTrait<N>>,
        caller_registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        // A finalize-context `call` actually executes a view body, which reads from the
        // finalize store; reject the storeless dispatch path explicitly.
        let store = store.ok_or_else(|| anyhow!("`call` from a finalize context requires a finalize store"))?;

        // Load inputs from the caller's registers (operands resolve against the caller's stack).
        let inputs: Vec<Value<N>> =
            self.operands.iter().map(|op| caller_registers.load(stack, op)).collect::<Result<_>>()?;

        // Inherit the caller's global finalize state for the view body.
        let state = *caller_registers.state();

        // Dispatch to the target stack (external for locator-typed targets, current stack for
        // resource-typed targets). Views are leaves — their bodies reject `is_call` at
        // construction — so this never recurses through `Command::finalize` back into another
        // view call.
        let outputs = match &self.operator {
            CallOperator::Locator(locator) => {
                let external_stack = stack.get_external_stack(locator.program_id())?;
                external_stack.evaluate_view(state, store, locator.resource(), inputs)?
            }
            CallOperator::Resource(name) => stack.evaluate_view(state, store, name, inputs)?,
        };

        // Type-check at deploy time guarantees this match, but we sanity-check at runtime too.
        ensure!(
            self.destinations.len() == outputs.len(),
            "View returned {} outputs but the call expects {}",
            outputs.len(),
            self.destinations.len(),
        );

        // Write the view's outputs into the caller's destination registers.
        for (dest, value) in self.destinations.iter().zip_eq(outputs) {
            caller_registers.store(stack, dest, value)?;
        }
        Ok(())
    }

    /// Returns the output type from the given program and input types.
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Retrieve the program (external if necessary) and the name of the function or closure.
        let stack_value;
        let (is_external, program, name) = match &self.operator {
            CallOperator::Locator(locator) => {
                let program_name = locator.program_id();
                stack_value = Some(stack.get_external_stack(program_name)?);
                (true, stack_value.as_ref().unwrap().program(), locator.resource())
            }
            CallOperator::Resource(resource) => {
                // TODO (howardwu): Revisit this decision to forbid calling internal functions. A record cannot be spent again.
                //  But there are legitimate uses for passing a record through to an internal function.
                //  We could invoke the internal function without a state transition, but need to match visibility.
                if stack.program().contains_function(resource) {
                    bail!("Cannot call '{resource}'. Use a closure ('closure {resource}:') instead.")
                }
                (false, stack.program(), resource)
            }
        };

        // If the operator is a view function, retrieve the view and compute the output types.
        // Views are externally-callable and declared as `FinalizeType::Plaintext(_)` for both
        // inputs and outputs (enforced by `ViewCore::add_input`/`add_output`); we therefore
        // pattern-match `FinalizeType::Plaintext` directly when constructing the `RegisterType`.
        if let Ok(view) = program.get_view_ref(name) {
            if view.inputs().len() != self.operands.len() {
                bail!("Expected {} inputs, found {}", view.inputs().len(), self.operands.len())
            }
            if view.inputs().len() != input_types.len() {
                bail!("Expected {} input types, found {}", view.inputs().len(), input_types.len())
            }
            if view.outputs().len() != self.destinations.len() {
                bail!("Expected {} outputs, found {}", view.outputs().len(), self.destinations.len())
            }

            // Per-operand type-equivalence check, against the view's declared input types. For a
            // cross-program target, `qualify` rewrites local struct references to `ExternalStruct`
            // locators so `register_types_equivalent` resolves them through the target stack.
            for (index, (operand_type, input)) in input_types.iter().zip(view.inputs().iter()).enumerate() {
                let plaintext_type = match input.finalize_type() {
                    FinalizeType::Plaintext(plaintext_type) => plaintext_type.clone(),
                    FinalizeType::Future(_) | FinalizeType::DynamicFuture => {
                        bail!("View '{name}' input '{index}' must be a plaintext type")
                    }
                };
                let mut expected_type = RegisterType::Plaintext(plaintext_type);
                if is_external {
                    expected_type = expected_type.qualify(*program.id());
                }
                if !register_types_equivalent(stack, &expected_type, stack, operand_type)? {
                    bail!("Input '{index}' of view '{name}' expects '{expected_type}', found '{operand_type}'");
                }
            }

            view.outputs()
                .iter()
                .map(|output| match output.finalize_type() {
                    FinalizeType::Plaintext(plaintext_type) => Ok(RegisterType::Plaintext(plaintext_type.clone())),
                    FinalizeType::Future(_) | FinalizeType::DynamicFuture => {
                        bail!("View '{name}' output must be a plaintext type")
                    }
                })
                .map(|result| {
                    result.map(
                        |register_type| {
                            if is_external { register_type.qualify(*program.id()) } else { register_type }
                        },
                    )
                })
                .collect::<Result<Vec<_>>>()
        }
        // If the operator is a closure, retrieve the closure and compute the output types.
        else if let Ok(closure) = program.get_closure(name) {
            // Ensure the number of operands matches the number of input statements.
            if closure.inputs().len() != self.operands.len() {
                bail!("Expected {} inputs, found {}", closure.inputs().len(), self.operands.len())
            }
            // Ensure the number of inputs matches the number of input statements.
            if closure.inputs().len() != input_types.len() {
                bail!("Expected {} input types, found {}", closure.inputs().len(), input_types.len())
            }
            // Ensure the number of destinations matches the number of output statements.
            if closure.outputs().len() != self.destinations.len() {
                bail!("Expected {} outputs, found {}", closure.outputs().len(), self.destinations.len())
            }
            // Retrieve the output types.
            Ok(closure
                .output_types()
                .into_iter()
                // If the callee is an external program, qualify its local types with its program ID.
                .map(|output_type| if is_external { output_type.qualify(*program.id()) } else { output_type })
                .collect::<Vec<_>>())
        }
        // If the operator is a function, retrieve the function and compute the output types.
        else if let Ok(function) = program.get_function(name) {
            // Ensure the number of operands matches the number of input statements.
            if function.inputs().len() != self.operands.len() {
                bail!("Expected {} inputs, found {}", function.inputs().len(), self.operands.len())
            }
            // Ensure the number of inputs matches the number of input statements.
            if function.inputs().len() != input_types.len() {
                bail!("Expected {} input types, found {}", function.inputs().len(), input_types.len())
            }
            // Ensure the number of destinations matches the number of output statements.
            if function.outputs().len() != self.destinations.len() {
                bail!("Expected {} outputs, found {}", function.outputs().len(), self.destinations.len())
            }
            // Return the output register types.
            Ok(function
                .output_types()
                .into_iter()
                .map(RegisterType::from)
                // If the function is an external program, we need to qualify its structs or records with
                // the appropriate `ProgramID`.
                .map(|register_type| if is_external { register_type.qualify(*program.id()) } else { register_type })
                .collect::<Vec<_>>())
        }
        // Else, throw an error.
        else {
            bail!("Call operator '{}' is invalid or unsupported.", self.operator)
        }
    }
}

impl<N: Network> Parser for Call<N> {
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

        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the name of the call from the string.
        let (string, operator) = CallOperator::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the operands from the string.
        let (string, operands) = map_res(many0(complete(parse_operand)), |operands: Vec<Operand<N>>| {
            // Ensure the number of operands is within the bounds.
            match operands.len() <= N::MAX_OPERANDS {
                true => Ok(operands),
                false => Err(error("Failed to parse 'call' opcode: too many operands")),
            }
        })(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Optionally parse the "into" from the string.
        let (string, destinations) = match opt(tag("into"))(string)? {
            // If the "into" was not parsed, return the string and an empty vector of destinations.
            (string, None) => (string, vec![]),
            // If the "into" was parsed, parse the destinations from the string.
            (string, Some(_)) => {
                // Parse the whitespace from the string.
                let (string, _) = Sanitizer::parse_whitespaces(string)?;
                // Parse the destinations from the string.
                let (string, destinations) =
                    map_res(many1(complete(parse_destination)), |destinations: Vec<Register<N>>| {
                        // Ensure the number of destinations is within the bounds.
                        match destinations.len() <= N::MAX_OPERANDS {
                            true => Ok(destinations),
                            false => Err(error("Failed to parse 'call' opcode: too many destinations")),
                        }
                    })(string)?;
                // Return the string and the destinations.
                (string, destinations)
            }
        };

        Ok((string, Self { operator, operands, destinations }))
    }
}

impl<N: Network> FromStr for Call<N> {
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

impl<N: Network> Debug for Call<N> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Call<N> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is within the bounds.
        if self.operands.len() > N::MAX_OPERANDS {
            return Err(fmt::Error);
        }
        // Ensure the number of destinations is within the bounds.
        if self.destinations.len() > N::MAX_OPERANDS {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{} {}", Self::opcode(), self.operator)?;
        self.operands.iter().try_for_each(|operand| write!(f, " {operand}"))?;
        if !self.destinations.is_empty() {
            write!(f, " into")?;
            self.destinations.iter().try_for_each(|destination| write!(f, " {destination}"))?;
        }
        Ok(())
    }
}

impl<N: Network> FromBytes for Call<N> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the operator of the call.
        let operator = CallOperator::read_le(&mut reader)?;

        // Read the number of operands.
        let num_operands = u8::read_le(&mut reader)? as usize;
        // Ensure the number of operands is within the bounds.
        if num_operands > N::MAX_OPERANDS {
            return Err(error(format!("The number of operands must be <= {}", N::MAX_OPERANDS)));
        }

        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(num_operands);
        // Read the operands.
        for _ in 0..num_operands {
            operands.push(Operand::read_le(&mut reader)?);
        }

        // Read the number of destination registers.
        let num_destinations = u8::read_le(&mut reader)? as usize;
        // Ensure the number of destinations is within the bounds.
        if num_destinations > N::MAX_OPERANDS {
            return Err(error(format!("The number of destinations must be <= {}", N::MAX_OPERANDS)));
        }

        // Initialize the vector for the destinations.
        let mut destinations = Vec::with_capacity(num_destinations);
        // Read the destination registers.
        for _ in 0..num_destinations {
            destinations.push(Register::read_le(&mut reader)?);
        }

        // Return the operation.
        Ok(Self { operator, operands, destinations })
    }
}

impl<N: Network> ToBytes for Call<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is within the bounds.
        if self.operands.len() > N::MAX_OPERANDS {
            return Err(error(format!("The number of operands must be <= {}", N::MAX_OPERANDS)));
        }
        // Ensure the number of destinations is within the bounds.
        if self.destinations.len() > N::MAX_OPERANDS {
            return Err(error(format!("The number of destinations must be <= {}", N::MAX_OPERANDS)));
        }

        // Write the name of the call.
        self.operator.write_le(&mut writer)?;
        // Write the number of operands.
        u8::try_from(self.operands.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the number of destination register.
        u8::try_from(self.destinations.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the destination registers.
        self.destinations.iter().try_for_each(|destination| destination.write_le(&mut writer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        network::MainnetV0,
        program::{Access, Address, Identifier, Literal, U64},
    };

    type CurrentNetwork = MainnetV0;

    const TEST_CASES: &[&str] = &[
        "call foo",
        "call foo r0",
        "call foo r0.owner",
        "call foo r0 r1",
        "call foo into r0",
        "call foo into r0 r1",
        "call foo into r0 r1 r2",
        "call foo r0 into r1",
        "call foo r0 r1 into r2",
        "call foo r0 r1 into r2 r3",
        "call foo r0 r1 r2 into r3 r4",
        "call foo r0 r1 r2 into r3 r4 r5",
    ];

    fn check_parser(
        string: &str,
        expected_operator: CallOperator<CurrentNetwork>,
        expected_operands: Vec<Operand<CurrentNetwork>>,
        expected_destinations: Vec<Register<CurrentNetwork>>,
    ) {
        // Check that the parser works.
        let (string, call) = Call::<CurrentNetwork>::parse(string).unwrap();

        // Check that the entire string was consumed.
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        // Check that the operator is correct.
        assert_eq!(call.operator, expected_operator, "The call operator is incorrect");

        // Check that the operands are correct.
        assert_eq!(call.operands.len(), expected_operands.len(), "The number of operands is incorrect");
        for (i, (given, expected)) in call.operands.iter().zip(expected_operands.iter()).enumerate() {
            assert_eq!(given, expected, "The {i}-th operand is incorrect");
        }

        // Check that the destinations are correct.
        assert_eq!(call.destinations.len(), expected_destinations.len(), "The number of destinations is incorrect");
        for (i, (given, expected)) in call.destinations.iter().zip(expected_destinations.iter()).enumerate() {
            assert_eq!(given, expected, "The {i}-th destination is incorrect");
        }
    }

    #[test]
    fn test_parse() {
        check_parser(
            "call transfer r0.owner r0.token_amount into r1 r2 r3",
            CallOperator::from_str("transfer").unwrap(),
            vec![
                Operand::Register(Register::Access(0, vec![Access::from(Identifier::from_str("owner").unwrap())])),
                Operand::Register(Register::Access(0, vec![Access::from(
                    Identifier::from_str("token_amount").unwrap(),
                )])),
            ],
            vec![Register::Locator(1), Register::Locator(2), Register::Locator(3)],
        );

        check_parser(
            "call mint_public aleo1wfyyj2uvwuqw0c0dqa5x70wrawnlkkvuepn4y08xyaqfqqwweqys39jayw 100u64",
            CallOperator::from_str("mint_public").unwrap(),
            vec![
                Operand::Literal(Literal::Address(
                    Address::from_str("aleo1wfyyj2uvwuqw0c0dqa5x70wrawnlkkvuepn4y08xyaqfqqwweqys39jayw").unwrap(),
                )),
                Operand::Literal(Literal::U64(U64::from_str("100u64").unwrap())),
            ],
            vec![],
        );

        check_parser(
            "call get_magic_number into r0",
            CallOperator::from_str("get_magic_number").unwrap(),
            vec![],
            vec![Register::Locator(0)],
        );

        check_parser("call noop", CallOperator::from_str("noop").unwrap(), vec![], vec![])
    }

    #[test]
    fn test_display() {
        for expected in TEST_CASES {
            assert_eq!(Call::<CurrentNetwork>::from_str(expected).unwrap().to_string(), *expected);
        }
    }

    #[test]
    fn test_bytes() {
        for case in TEST_CASES {
            let expected = Call::<CurrentNetwork>::from_str(case).unwrap();

            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le().unwrap();
            assert_eq!(expected, Call::read_le(&expected_bytes[..]).unwrap());
        }
    }
}
