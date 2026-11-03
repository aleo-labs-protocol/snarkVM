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
    Result,
    StackTrait,
    types_equivalent,
};

use console::{
    network::prelude::*,
    program::{Argument, FinalizeType, Future, Identifier, Locator, Register, RegisterType, Value},
};

/// Invokes the asynchronous call on the operands, producing a future.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Async<N: Network> {
    /// The function name.
    function_name: Identifier<N>,
    /// The operands.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
}

impl<N: Network> Async<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Async
    }

    /// Returns the function name.
    #[inline]
    pub const fn function_name(&self) -> &Identifier<N> {
        &self.function_name
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that there is less than or equal to MAX_INPUTS operands.
        debug_assert!(self.operands.len() <= N::MAX_INPUTS, "`async` must have less than {} operands", N::MAX_INPUTS);
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

impl<N: Network> Async<N> {
    /// Evaluates the instruction.
    #[inline]
    pub fn evaluate(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersTrait<N>) -> Result<()> {
        // Ensure the number of operands is correct.
        if self.operands.len() > N::MAX_INPUTS {
            bail!("'{}' expects <= {} operands, found {} operands", Self::opcode(), N::MAX_INPUTS, self.operands.len())
        }

        // Load the operand values and check that they are valid arguments.
        let arguments: Vec<_> = self
            .operands
            .iter()
            .map(|operand| match registers.load(stack, operand)? {
                Value::Plaintext(plaintext) => Ok(Argument::Plaintext(plaintext)),
                Value::Record(_) => bail!("Cannot pass a record into an `async` instruction"),
                Value::Future(future) => Ok(Argument::Future(future)),
                Value::DynamicRecord(_) => bail!("Cannot pass a dynamic record into an `async` instruction"),
                Value::DynamicFuture(dynamic_future) => Ok(Argument::DynamicFuture(dynamic_future)),
            })
            .try_collect()?;

        // Initialize a future.
        let future = Value::Future(Future::new(*stack.program_id(), *self.function_name(), arguments));
        // Store the future in the destination register.
        registers.store(stack, &self.destination, future)?;

        Ok(())
    }

    /// Executes the instruction.
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        // Ensure the number of operands is correct.
        if self.operands.len() > N::MAX_INPUTS {
            bail!("'{}' expects <= {} operands, found {} operands", Self::opcode(), N::MAX_INPUTS, self.operands.len())
        }

        // Load the operand values and check that they are valid arguments.
        let arguments: Vec<_> = self
            .operands
            .iter()
            .map(|operand| match registers.load_circuit(stack, operand)? {
                circuit::Value::Plaintext(plaintext) => Ok(circuit::Argument::Plaintext(plaintext)),
                circuit::Value::Record(_) => bail!("Cannot pass a record into an `async` instruction"),
                circuit::Value::Future(future) => Ok(circuit::Argument::Future(future)),
                circuit::Value::DynamicRecord(_) => bail!("Cannot pass a dynamic record into an `async` instruction"),
                circuit::Value::DynamicFuture(dynamic_future) => Ok(circuit::Argument::DynamicFuture(dynamic_future)),
            })
            .try_collect()?;

        // Initialize a future.
        let future = circuit::Value::Future(circuit::Future::from(
            circuit::ProgramID::constant(*stack.program_id()),
            circuit::Identifier::constant(*self.function_name()),
            arguments,
        ));
        // Store the future in the destination register.
        registers.store_circuit(stack, &self.destination, future)?;

        Ok(())
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(
        &self,
        _stack: &impl StackTrait<N>,
        _store: Option<&dyn FinalizeStoreTrait<N>>,
        _registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<()> {
        bail!("Forbidden operation: Finalize cannot invoke 'async'.")
    }

    /// Returns the output type from the given program and input types.
    #[inline]
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure that an associated finalize block exists.
        let function = stack.get_function(self.function_name())?;
        let finalize = match function.finalize_logic() {
            Some(finalize) => finalize,
            None => bail!("'{}/{}' does not have a finalize block", stack.program_id(), self.function_name()),
        };

        // Check that the number of inputs matches the number of arguments.
        if input_types.len() != finalize.input_types().len() {
            bail!(
                "'{}/{}' finalize expects {} arguments, found {} arguments",
                stack.program_id(),
                self.function_name(),
                finalize.input_types().len(),
                input_types.len()
            );
        }

        // Check the type of each operand.
        for (input_type, finalize_type) in input_types.iter().zip_eq(finalize.input_types()) {
            match (input_type, finalize_type) {
                (RegisterType::Plaintext(input_type), FinalizeType::Plaintext(finalize_type)) => {
                    ensure!(
                        types_equivalent(stack, input_type, stack, &finalize_type)?,
                        "'{}/{}' finalize expects a '{}' argument, found a '{}' argument",
                        stack.program_id(),
                        self.function_name(),
                        finalize_type,
                        input_type
                    );
                }
                (RegisterType::Record(..), _) => bail!("Attempted to pass a 'record' into 'async'"),
                (RegisterType::ExternalRecord(..), _) => {
                    bail!("Attempted to pass an 'external record' into 'async'")
                }
                (RegisterType::Future(input_locator), FinalizeType::Future(expected_locator)) => {
                    ensure!(
                        input_locator == &expected_locator,
                        "'{}/{}' async expects a '{}.future' argument, found a '{}.future' argument",
                        stack.program_id(),
                        self.function_name(),
                        expected_locator,
                        input_locator
                    );
                }
                (RegisterType::DynamicFuture, FinalizeType::DynamicFuture) => {}
                (input_type, finalize_type) => bail!(
                    "'{}/{}' async expects a '{}' argument, found a '{}' argument",
                    stack.program_id(),
                    self.function_name(),
                    finalize_type,
                    input_type
                ),
            }
        }

        Ok(vec![RegisterType::Future(Locator::new(*stack.program_id(), *self.function_name()))])
    }
}

impl<N: Network> Parser for Async<N> {
    /// Parses a string into an operation.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses an operand.
        fn parse_operand<N: Network>(string: &str) -> ParserResult<'_, Operand<N>> {
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the operand from the string.
            let (string, operand) = Operand::parse(string)?;
            // Return the remaining string and operand.
            Ok((string, operand))
        }

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the function name from the string.
        let (string, function_name) = Identifier::parse(string)?;
        // Parse the operands from the string.
        let (string, operands) = many0(parse_operand)(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the 'into' from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Ensure the number of operands is less than or equal to MAX_INPUTS.
        match operands.len() <= N::MAX_INPUTS {
            true => Ok((string, Self { function_name, operands, destination })),
            false => map_res(fail, |_: ParserResult<Self>| {
                Err(error(format!("The number of operands must be <= {}, found {}", N::MAX_INPUTS, operands.len())))
            })(string),
        }
    }
}

impl<N: Network> FromStr for Async<N> {
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

impl<N: Network> Debug for Async<N> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Async<N> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is less than or equal to MAX_INPUTS.
        if self.operands.len() > N::MAX_INPUTS {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{} {}", Self::opcode(), self.function_name)?;
        self.operands.iter().try_for_each(|operand| write!(f, " {operand}"))?;
        write!(f, " into {}", self.destination)
    }
}

impl<N: Network> FromBytes for Async<N> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the function name.
        let function_name = Identifier::read_le(&mut reader)?;

        // Read the number of operands.
        let num_operands = u8::read_le(&mut reader)?;
        // Ensure the number of operands is less than or equal to MAX_INPUTS.
        if num_operands as usize > N::MAX_INPUTS {
            return Err(error(format!("The number of operands must be <= {}, found {}", N::MAX_INPUTS, num_operands)));
        }

        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(num_operands as usize);
        // Read the operands.
        for _ in 0..(num_operands as usize) {
            operands.push(Operand::read_le(&mut reader)?);
        }

        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;

        // Return the operation.
        Ok(Self { function_name, operands, destination })
    }
}

impl<N: Network> ToBytes for Async<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is less than or equal to MAX_INPUTS.
        if self.operands.len() > N::MAX_INPUTS {
            return Err(error(format!(
                "The number of operands must be <= {}, found {}",
                N::MAX_INPUTS,
                self.operands.len()
            )));
        }
        // Write the function name.
        self.function_name.write_le(&mut writer)?;
        // Write the number of operands.
        u8::try_from(self.operands.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the destination register.
        self.destination.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use circuit::AleoV0;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;
    // type CurrentAleo = AleoV0;
    //
    // /// Samples the stack. Note: Do not replicate this for real program use, it is insecure.
    // fn sample_stack(
    //     opcode: Opcode,
    //     type_a: LiteralType,
    //     type_b: LiteralType,
    //     mode_a: circuit::Mode,
    //     mode_b: circuit::Mode,
    // ) -> Result<(Stack<CurrentNetwork>, Vec<Operand<CurrentNetwork>>)> {
    //     use crate::{Process, Program};
    //     use console::program::Identifier;
    //
    //     // Initialize the opcode.
    //     let opcode = opcode.to_string();
    //
    //     // Initialize the function name.
    //     let function_name = Identifier::<CurrentNetwork>::from_str("run")?;
    //
    //     // Initialize the registers.
    //     let r0 = Register::Locator(0);
    //     let r1 = Register::Locator(1);
    //
    //     // Initialize the program.
    //     let program = Program::from_str(&format!(
    //         "program testing.aleo;
    //         function {function_name}:
    //             input {r0} as {type_a}.{mode_a};
    //             input {r1} as {type_b}.{mode_b};
    //             {opcode} {r0} {r1};
    //     "
    //     ))?;
    //
    //     // Initialize the operands.
    //     let operand_a = Operand::Register(r0);
    //     let operand_b = Operand::Register(r1);
    //     let operands = vec![operand_a, operand_b];
    //
    //     // Initialize the stack.
    //     let stack = Stack::new(&Process::load()?, &program)?;
    //
    //     Ok((stack, operands))
    // }
    //
    // /// Samples the registers. Note: Do not replicate this for real program use, it is insecure.
    // fn sample_registers(
    //     stack: &Stack<CurrentNetwork>,
    //     literal_a: &Literal<CurrentNetwork>,
    //     literal_b: &Literal<CurrentNetwork>,
    // ) -> Result<Registers<CurrentNetwork, CurrentAleo>> {
    //     use crate::{Authorization, CallStack};
    //     use console::program::{Identifier, Plaintext, Value};
    //
    //     // Initialize the function name.
    //     let function_name = Identifier::from_str("run")?;
    //
    //     // Initialize the registers.
    //     let mut registers = Registers::<CurrentNetwork, CurrentAleo>::new(
    //         CallStack::evaluate(Authorization::new(&[]))?,
    //         stack.get_register_types(&function_name)?.clone(),
    //     );
    //
    //     // Initialize the registers.
    //     let r0 = Register::Locator(0);
    //     let r1 = Register::Locator(1);
    //
    //     // Initialize the console values.
    //     let value_a = Value::Plaintext(Plaintext::from(literal_a));
    //     let value_b = Value::Plaintext(Plaintext::from(literal_b));
    //
    //     // Store the values in the console registers.
    //     registers.store(stack, &r0, value_a.clone())?;
    //     registers.store(stack, &r1, value_b.clone())?;
    //
    //     Ok(registers)
    // }
    //
    // fn check_finalize(
    //     operation: impl FnOnce(Vec<Operand<CurrentNetwork>>) -> FinalizeOperation<CurrentNetwork, VARIANT>,
    //     opcode: Opcode,
    //     literal_a: &Literal<CurrentNetwork>,
    //     literal_b: &Literal<CurrentNetwork>,
    //     mode_a: &circuit::Mode,
    //     mode_b: &circuit::Mode,
    // ) {
    //     // Initialize the types.
    //     let type_a = literal_a.to_type();
    //     let type_b = literal_b.to_type();
    //     assert_eq!(type_a, type_b, "The two literals must be the *same* type for this test");
    //
    //     // Initialize the stack.
    //     let (stack, operands) = sample_stack(opcode, type_a, type_b, *mode_a, *mode_b).unwrap();
    //     // Initialize the operation.
    //     let operation = operation(operands);
    //
    //     /* First, check the operation *succeeds* when both operands are `literal_a.mode_a`. */
    //     {
    //         // Attempt to compute the valid operand case.
    //         let mut registers = sample_registers(&stack, literal_a, literal_a).unwrap();
    //         let result_a = operation.evaluate(&stack, &mut registers);
    //
    //         // Ensure the result is correct.
    //         match VARIANT {
    //             0 => assert!(result_a.is_ok(), "Instruction '{operation}' failed (console): {literal_a} {literal_a}"),
    //             _ => panic!("Found an invalid 'finalize' variant in the test"),
    //         }
    //     }
    //     /* Next, check the mismatching literals *fail*. */
    //     if literal_a != literal_b {
    //         // Attempt to compute the valid operand case.
    //         let mut registers = sample_registers(&stack, literal_a, literal_b).unwrap();
    //         let result_a = operation.evaluate(&stack, &mut registers);
    //
    //         // Ensure the result is correct.
    //         match VARIANT {
    //             0 => assert!(
    //                 result_a.is_err(),
    //                 "Instruction '{operation}' should have failed (console): {literal_a} {literal_b}"
    //             ),
    //             _ => panic!("Found an invalid 'finalize' variant in the test"),
    //         }
    //     }
    // }
    //
    // fn check_finalize_fails(
    //     opcode: Opcode,
    //     literal_a: &Literal<CurrentNetwork>,
    //     literal_b: &Literal<CurrentNetwork>,
    //     mode_a: &circuit::Mode,
    //     mode_b: &circuit::Mode,
    // ) {
    //     // Initialize the types.
    //     let type_a = literal_a.to_type();
    //     let type_b = literal_b.to_type();
    //     assert_ne!(type_a, type_b, "The two literals must be *different* types for this test");
    //
    //     // If the types mismatch, ensure the stack fails to initialize.
    //     let result = sample_stack(opcode, type_a, type_b, *mode_a, *mode_b);
    //     assert!(
    //         result.is_err(),
    //         "Stack should have failed to initialize for: {opcode} {type_a}.{mode_a} {type_b}.{mode_b}"
    //     );
    // }
    //
    // #[test]
    // fn test_finalize_eq_succeeds() {
    //     // Initialize the operation.
    //     let operation = |operands| Async::<CurrentNetwork> { operands };
    //     // Initialize the opcode.
    //     let opcode = Async::<CurrentNetwork>::opcode();
    //
    //     let mut rng = TestRng::default();
    //
    //     // Prepare the test.
    //     let literals_a = crate::sample_literals!(CurrentNetwork, &mut rng);
    //     let literals_b = crate::sample_literals!(CurrentNetwork, &mut rng);
    //     let modes_a = [/* circuit::Mode::Constant, */ circuit::Mode::Public, circuit::Mode::Private];
    //     let modes_b = [/* circuit::Mode::Constant, */ circuit::Mode::Public, circuit::Mode::Private];
    //
    //     for (literal_a, literal_b) in literals_a.iter().zip_eq(literals_b.iter()) {
    //         for mode_a in &modes_a {
    //             for mode_b in &modes_b {
    //                 // Check the operation.
    //                 check_finalize(operation, opcode, literal_a, literal_b, mode_a, mode_b);
    //             }
    //         }
    //     }
    // }
    //
    // #[test]
    // fn test_finalize_evaluate() {
    //     use rayon::prelude::*;
    //
    //     // Initialize the opcode.
    //     let opcode = Async::<CurrentNetwork>::opcode();
    //
    //     let mut rng = TestRng::default();
    //
    //     // Prepare the test.
    //     let literals_a = crate::sample_literals!(CurrentNetwork, &mut rng);
    //     let literals_b = crate::sample_literals!(CurrentNetwork, &mut rng);
    //     let modes_a = [/* circuit::Mode::Constant, */ circuit::Mode::Public, circuit::Mode::Private];
    //     let modes_b = [/* circuit::Mode::Constant, */ circuit::Mode::Public, circuit::Mode::Private];
    //
    //     literals_a.par_iter().for_each(|literal_a| {
    //         for literal_b in &literals_b {
    //             for mode_a in &modes_a {
    //                 for mode_b in &modes_b {
    //                     if literal_a.to_type() != literal_b.to_type() {
    //                         // Check the operation fails.
    //                         check_finalize_fails(opcode, literal_a, literal_b, mode_a, mode_b);
    //                     }
    //                 }
    //             }
    //         }
    //     });
    // }

    #[test]
    fn test_parse() {
        let expected = "async foo r0 r1 into r3";
        let (string, async_) = Async::<CurrentNetwork>::parse(expected).unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(expected, async_.to_string(), "Display.fmt() did not match expected: '{string}'");
        assert_eq!(async_.operands.len(), 2, "The number of operands is incorrect");
        assert_eq!(async_.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(async_.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(async_.destination, Register::Locator(3), "The destination is incorrect");
    }
}
