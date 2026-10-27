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

impl<N: Network> Parser for ViewCore<N> {
    /// Parses a string into a view function.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'view' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the view name from the string.
        let (string, name) = Identifier::<N>::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the inputs, commands, and outputs from the string. All three are `many0` —
        // views permit zero commands (passthrough / no-op shapes) and zero outputs (assertional
        // / guard views; the Aleo analogue of Solidity `view` functions that don't return
        // anything). The constraints that matter (no record-touching ops, no state writes, no
        // `async`/`await`/`call`/`rand.chacha`) are enforced by `ViewCore::add_command`, not by
        // the parser arity.
        let (string, inputs) = many0(Input::parse)(string)?;
        let (string, commands) = many0(Command::<N>::parse)(string)?;
        let (string, outputs) = many0(Output::parse)(string)?;

        map_res(take(0usize), move |_| {
            let mut view = Self::new(name);
            inputs.iter().cloned().try_for_each(|input| view.add_input(input))?;
            commands.iter().cloned().try_for_each(|command| view.add_command(command))?;
            outputs.iter().cloned().try_for_each(|output| view.add_output(output))?;
            Ok::<_, Error>(view)
        })(string)
    }
}

impl<N: Network> FromStr for ViewCore<N> {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for ViewCore<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for ViewCore<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}:", Self::type_name(), self.name)?;
        self.inputs.iter().try_for_each(|input| write!(f, "\n    {input}"))?;
        self.commands.iter().try_for_each(|command| write!(f, "\n    {command}"))?;
        self.outputs.iter().try_for_each(|output| write!(f, "\n    {output}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_view_parse() {
        let view = ViewCore::<CurrentNetwork>::parse(
            r"
view foo:
    input r0 as field.public;
    input r1 as field.public;
    add r0 r1 into r2;
    output r2 as field.public;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", view.name().to_string());
        assert_eq!(2, view.inputs().len());
        assert_eq!(1, view.commands().len());
        assert_eq!(1, view.outputs().len());
    }

    #[test]
    fn test_view_parse_no_inputs() {
        let view = ViewCore::<CurrentNetwork>::parse(
            r"
view foo:
    add 1u64 2u64 into r0;
    output r0 as u64.public;",
        )
        .unwrap()
        .1;
        assert_eq!("foo", view.name().to_string());
        assert_eq!(0, view.inputs().len());
        assert_eq!(1, view.commands().len());
        assert_eq!(1, view.outputs().len());
    }

    #[test]
    fn test_view_display() {
        let expected = r"view foo:
    input r0 as field.public;
    input r1 as field.public;
    add r0 r1 into r2;
    output r2 as field.public;";
        let view = ViewCore::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{view}"));
    }

    #[test]
    fn test_view_parse_fails() {
        // Missing 'view' keyword.
        assert!(
            ViewCore::<CurrentNetwork>::from_str(
                r"
foo:
    add 1u64 2u64 into r0;
    output r0 as u64.public;"
            )
            .is_err()
        );
        // Missing colon after the view name.
        assert!(
            ViewCore::<CurrentNetwork>::from_str(
                r"
view foo
    add 1u64 2u64 into r0;
    output r0 as u64.public;"
            )
            .is_err()
        );
        // 'set' is forbidden in a view.
        assert!(
            ViewCore::<CurrentNetwork>::from_str(
                r"
view foo:
    input r0 as u64.public;
    set r0 into balances[r0];
    output r0 as u64.public;"
            )
            .is_err()
        );
    }

    #[test]
    fn test_view_parse_no_outputs_guard() {
        // A guard view: asserts a precondition and returns nothing. Callers observe success
        // via tx acceptance and failure (assertion fails) via tx rejection.
        let view = ViewCore::<CurrentNetwork>::parse(
            r"
view require_zero:
    input r0 as u64.public;
    assert.eq r0 0u64;",
        )
        .unwrap()
        .1;
        assert_eq!("require_zero", view.name().to_string());
        assert_eq!(1, view.inputs().len());
        assert_eq!(1, view.commands().len());
        assert_eq!(0, view.outputs().len());
    }

    #[test]
    fn test_view_parse_no_commands_passthrough() {
        // A passthrough view: no commands, output is the input register directly.
        let view = ViewCore::<CurrentNetwork>::parse(
            r"
view identity:
    input r0 as u64.public;
    output r0 as u64.public;",
        )
        .unwrap()
        .1;
        assert_eq!("identity", view.name().to_string());
        assert_eq!(1, view.inputs().len());
        assert_eq!(0, view.commands().len());
        assert_eq!(1, view.outputs().len());
    }

    #[test]
    fn test_view_parse_fully_empty() {
        // A no-op view: no inputs, commands, or outputs. Permitted for symmetry with `function`.
        let view = ViewCore::<CurrentNetwork>::parse(
            r"
view noop:",
        )
        .unwrap()
        .1;
        assert_eq!("noop", view.name().to_string());
        assert_eq!(0, view.inputs().len());
        assert_eq!(0, view.commands().len());
        assert_eq!(0, view.outputs().len());
    }
}
