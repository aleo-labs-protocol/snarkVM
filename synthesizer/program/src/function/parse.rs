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

impl<N: Network> Parser for FunctionCore<N> {
    /// Parses a string into a function.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'function' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the function name from the string.
        let (string, name) = Identifier::<N>::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the inputs from the string.
        let (string, inputs) = many0(Input::parse)(string)?;
        // Parse the instructions from the string.
        let (string, instructions) = many0(Instruction::parse)(string)?;
        // Parse the outputs from the string.
        let (string, outputs) = many0(Output::parse)(string)?;

        // Parse an optional finalize command from the string.
        let (string, finalize) = opt(FinalizeCore::parse)(string)?;

        map_res(take(0usize), move |_| {
            // Initialize a new function.
            let mut function = Self::new(name);
            if let Err(error) = inputs.iter().cloned().try_for_each(|input| function.add_input(input)) {
                eprintln!("{error}");
                return Err(error);
            }
            if let Err(error) =
                instructions.iter().cloned().try_for_each(|instruction| function.add_instruction(instruction))
            {
                eprintln!("{error}");
                return Err(error);
            }
            if let Err(error) = outputs.iter().cloned().try_for_each(|output| function.add_output(output)) {
                eprintln!("{error}");
                return Err(error);
            }
            if let Some(finalize) = &finalize
                && let Err(error) = function.add_finalize(finalize.clone())
            {
                eprintln!("{error}");
                return Err(error);
            }
            Ok::<_, Error>(function)
        })(string)
    }
}

impl<N: Network> FromStr for FunctionCore<N> {
    type Err = Error;

    /// Returns a function from a string literal.
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

impl<N: Network> Debug for FunctionCore<N> {
    /// Prints the function as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for FunctionCore<N> {
    /// Prints the function as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Write the function to a string.
        write!(f, "{} {}:", Self::type_name(), self.name)?;
        self.inputs.iter().try_for_each(|input| write!(f, "\n    {input}"))?;
        self.instructions.iter().try_for_each(|instruction| write!(f, "\n    {instruction}"))?;
        self.outputs.iter().try_for_each(|output| write!(f, "\n    {output}"))?;

        // If finalize exists, write it out.
        if let Some(finalize) = &self.finalize_logic {
            write!(f, "\n\n")?;
            write!(f, "{finalize}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Function;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_function_parse() {
        let function = Function::<CurrentNetwork>::parse(
            r"
function foo:
    input r0 as field.public;
    input r1 as field.private;
    add r0 r1 into r2;
    output r2 as field.private;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", function.name().to_string());
        assert_eq!(2, function.inputs().len());
        assert_eq!(1, function.instructions().len());
        assert_eq!(1, function.outputs().len());

        // Function with 0 inputs.
        let function = Function::<CurrentNetwork>::parse(
            r"
function foo:
    add 1u32 2u32 into r0;
    output r0 as u32.private;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", function.name().to_string());
        assert_eq!(0, function.inputs().len());
        assert_eq!(1, function.instructions().len());
        assert_eq!(1, function.outputs().len());
    }

    #[test]
    fn test_function_parse_cast() {
        let function = Function::<CurrentNetwork>::parse(
            r"
function foo:
    input r0 as token.record;
    cast r0.owner r0.token_amount into r1 as token.record;
    output r1 as token.record;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", function.name().to_string());
        assert_eq!(1, function.inputs().len());
        assert_eq!(1, function.instructions().len());
        assert_eq!(1, function.outputs().len());
    }

    #[test]
    fn test_function_parse_no_instruction_or_output() {
        let function = Function::<CurrentNetwork>::parse(
            r"
function foo:
    input r0 as token.record;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", function.name().to_string());
        assert_eq!(1, function.inputs().len());
        assert_eq!(0, function.instructions().len());
        assert_eq!(0, function.outputs().len());
    }

    #[test]
    fn test_function_parse_finalize() {
        let function = Function::<CurrentNetwork>::parse(
            r"
function mint_public:
    // Input the token receiver.
    input r0 as address.public;
    // Input the token amount.
    input r1 as u64.public;
    // Mint the tokens via an asynchronous call.
    async mint_public r0 r1 into r2;
    // Output the future.
    output r2 as foo.aleo/mint_public.future;

// The finalize scope of `mint_public` increments the
// `account` of the token receiver by the specified amount.
finalize mint_public:
    // Input the token receiver.
    input r0 as address.public;
    // Input the token amount.
    input r1 as u64.public;

    // Get `account[r0]` into `r2`, defaulting to 0u64 if the entry does not exist.
    get.or_use account[r0] 0u64 into r2;
    // Add `r1` to `r2`. If the operation overflows, `mint_public` is reverted.
    add r2 r1 into r3;
    // Set `r3` into `account[r0]`.
    set r3 into account[r0];
",
        )
        .unwrap()
        .1;
        assert_eq!("mint_public", function.name().to_string());
        assert_eq!(2, function.inputs().len());
        assert_eq!(1, function.instructions().len());
        assert_eq!(1, function.outputs().len());
        assert_eq!(2, function.finalize_logic().as_ref().unwrap().inputs().len());
        assert_eq!(3, function.finalize_logic().as_ref().unwrap().commands().len());

        let function = Function::<CurrentNetwork>::parse(
            r"
function foo:
    input r0 as token.record;
    cast r0.owner r0.token_amount into r1 as token.record;
    async foo r1.token_amount into r2;
    output r2 as foo.aleo/foo.future;

finalize foo:
    input r0 as u64.public;
    add r0 r0 into r1;
",
        )
        .unwrap()
        .1;
        assert_eq!("foo", function.name().to_string());
        assert_eq!(1, function.inputs().len());
        assert_eq!(2, function.instructions().len());
        assert_eq!(1, function.outputs().len());
        assert_eq!(1, function.finalize_logic().as_ref().unwrap().inputs().len());
        assert_eq!(1, function.finalize_logic().as_ref().unwrap().commands().len());

        let function = Function::<CurrentNetwork>::parse(
            r"
function compute:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    add r1 r2 into r3;
    async compute r0 r3 into r4;
    output r4 as foo.aleo/compute.future;

finalize compute:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];
    ",
        )
        .unwrap()
        .1;
        assert_eq!(3, function.inputs().len());
        assert_eq!(2, function.instructions().len());
        assert_eq!(1, function.outputs().len());
        assert_eq!(2, function.finalize_logic().as_ref().unwrap().inputs().len());
        assert_eq!(3, function.finalize_logic().as_ref().unwrap().commands().len());
    }

    #[test]
    fn test_function_display() {
        let expected = r"function foo:
    input r0 as field.public;
    input r1 as field.private;
    add r0 r1 into r2;
    output r2 as field.private;";
        let function = Function::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{function}"),);
    }
}
