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

impl<N: Network> Parser for ProgramCore<N> {
    /// Parses a string into a program.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // A helper to parse a program.
        enum P<N: Network> {
            Constructor(ConstructorCore<N>),
            M(Mapping<N>),
            S(StructType<N>),
            R(RecordType<N>),
            C(ClosureCore<N>),
            F(FunctionCore<N>),
            V(ViewCore<N>),
        }

        // Parse the imports from the string.
        let (string, imports) = many0(Import::parse)(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'program' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program ID from the string.
        let (string, id) = ProgramID::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the semicolon ';' keyword from the string.
        let (string, _) = tag(";")(string)?;

        fn intermediate<N: Network>(string: &str) -> ParserResult<'_, P<N>> {
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;

            if string.starts_with(ConstructorCore::<N>::type_name()) {
                map(ConstructorCore::parse, |constructor| P::<N>::Constructor(constructor))(string)
            } else if string.starts_with(Mapping::<N>::type_name()) {
                map(Mapping::parse, |mapping| P::<N>::M(mapping))(string)
            } else if string.starts_with(StructType::<N>::type_name()) {
                map(StructType::parse, |struct_| P::<N>::S(struct_))(string)
            } else if string.starts_with(RecordType::<N>::type_name()) {
                map(RecordType::parse, |record| P::<N>::R(record))(string)
            } else if string.starts_with(ClosureCore::<N>::type_name()) {
                map(ClosureCore::parse, |closure| P::<N>::C(closure))(string)
            } else if string.starts_with(FunctionCore::<N>::type_name()) {
                map(FunctionCore::parse, |function| P::<N>::F(function))(string)
            } else if string.starts_with(ViewCore::<N>::type_name()) {
                map(ViewCore::parse, |view| P::<N>::V(view))(string)
            } else {
                Err(Err::Error(make_error(string, ErrorKind::Alt)))
            }
        }

        // Parse the struct or function from the string.
        let (string, components) = many1(intermediate)(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;

        // Initialize a new program.
        let mut program = match ProgramCore::<N>::new(id) {
            Ok(program) => program,
            Err(error) => {
                eprintln!("{error}");
                return map_res(take(0usize), Err)(string);
            }
        };

        // Add the imports (if any) to the program.
        for import in imports {
            match program.add_import(import) {
                Ok(_) => (),
                Err(error) => {
                    eprintln!("{error}");
                    return map_res(take(0usize), Err)(string);
                }
            }
        }

        // Construct the program with the parsed components.
        for component in components {
            let result = match component {
                P::Constructor(constructor) => program.add_constructor(constructor),
                P::M(mapping) => program.add_mapping(mapping),
                P::S(struct_) => program.add_struct(struct_),
                P::R(record) => program.add_record(record),
                P::C(closure) => program.add_closure(closure),
                P::F(function) => program.add_function(function),
                P::V(view) => program.add_view(view),
            };

            match result {
                Ok(_) => (),
                Err(error) => {
                    eprintln!("{error}");
                    return map_res(take(0usize), Err)(string);
                }
            }
        }

        Ok((string, program))
    }
}

impl<N: Network> FromStr for ProgramCore<N> {
    type Err = Error;

    /// Returns a program from a string literal.
    fn from_str(string: &str) -> Result<Self> {
        // Ensure the raw program string is less than MAX_PROGRAM_SIZE.
        ensure!(string.len() <= N::LATEST_MAX_PROGRAM_SIZE(), "Program length exceeds N::MAX_PROGRAM_SIZE.");

        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Remaining invalid string is: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for ProgramCore<N> {
    /// Prints the program as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for ProgramCore<N> {
    /// Prints the program as a string.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !self.imports.is_empty() {
            // Print the imports.
            for import in self.imports.values() {
                writeln!(f, "{import}")?;
            }

            // Print a newline.
            writeln!(f)?;
        }

        // Print the program name.
        write!(f, "{} {};\n\n", Self::type_name(), self.id)?;

        // Write the components.
        let mut components_iter = self.components.iter().peekable();
        while let Some((label, definition)) = components_iter.next() {
            match label {
                ProgramLabel::Constructor => {
                    // Write the constructor, if it exists.
                    if let Some(constructor) = &self.constructor {
                        writeln!(f, "{constructor}")?;
                    }
                }
                ProgramLabel::Identifier(identifier) => match definition {
                    ProgramDefinition::Constructor => return Err(fmt::Error),
                    ProgramDefinition::Mapping => match self.mappings.get(identifier) {
                        Some(mapping) => writeln!(f, "{mapping}")?,
                        None => return Err(fmt::Error),
                    },
                    ProgramDefinition::Struct => match self.structs.get(identifier) {
                        Some(struct_) => writeln!(f, "{struct_}")?,
                        None => return Err(fmt::Error),
                    },
                    ProgramDefinition::Record => match self.records.get(identifier) {
                        Some(record) => writeln!(f, "{record}")?,
                        None => return Err(fmt::Error),
                    },
                    ProgramDefinition::Closure => match self.closures.get(identifier) {
                        Some(closure) => writeln!(f, "{closure}")?,
                        None => return Err(fmt::Error),
                    },
                    ProgramDefinition::Function => match self.functions.get(identifier) {
                        Some(function) => writeln!(f, "{function}")?,
                        None => return Err(fmt::Error),
                    },
                    ProgramDefinition::View => match self.views.get(identifier) {
                        Some(view) => writeln!(f, "{view}")?,
                        None => return Err(fmt::Error),
                    },
                },
            }

            // Omit the last newline.
            if components_iter.peek().is_some() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Program;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_program_parse() -> Result<()> {
        // Initialize a new program.
        let (string, program) = Program::<CurrentNetwork>::parse(
            r"
program to_parse.aleo;

struct message:
    first as field;
    second as field;

function compute:
    input r0 as message.private;
    add r0.first r0.second into r1;
    output r1 as field.private;",
        )
        .unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        // Ensure the program contains the struct.
        assert!(program.contains_struct(&Identifier::from_str("message")?));
        // Ensure the program contains the function.
        assert!(program.contains_function(&Identifier::from_str("compute")?));

        Ok(())
    }

    #[test]
    fn test_program_parse_with_view_zero_inputs() -> Result<()> {
        let program = Program::<CurrentNetwork>::from_str(
            r"
program qy_zeroin.aleo;

function noop:
    input r0 as u64.private;
    output r0 as u64.private;

view fixed_value:
    add 0u64 1234u64 into r0;
    output r0 as u64.public;",
        )?;
        assert_eq!(program.views().len(), 1);
        Ok(())
    }

    #[test]
    fn test_program_parse_with_view() -> Result<()> {
        let (string, program) = Program::<CurrentNetwork>::parse(
            r"
program token_with_view.aleo;

mapping balances:
    key as address.public;
    value as u64.public;

function noop:
    input r0 as u64.private;
    output r0 as u64.private;

view total_balance:
    input r0 as address.public;
    get.or_use balances[r0] 0u64 into r1;
    output r1 as u64.public;",
        )
        .unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        // The program should expose the view by name.
        let view_name = Identifier::from_str("total_balance")?;
        assert!(program.contains_view(&view_name));
        assert_eq!(1, program.views().len());
        let view = program.get_view_ref(&view_name)?;
        assert_eq!(1, view.inputs().len());
        assert_eq!(1, view.commands().len());
        assert_eq!(1, view.outputs().len());

        Ok(())
    }

    #[test]
    fn test_program_view_rejects_writes() {
        let result = Program::<CurrentNetwork>::from_str(
            r"
program bad_view.aleo;

mapping balances:
    key as address.public;
    value as u64.public;

view mutate:
    input r0 as address.public;
    set 1u64 into balances[r0];
    output r0 as address.public;",
        );
        assert!(result.is_err(), "expected program parse to fail when view contains 'set'");
    }

    #[test]
    fn test_program_view_rejects_call() {
        let result = Program::<CurrentNetwork>::from_str(
            r"
program bad_view.aleo;

closure helper:
    input r0 as field;
    output r0 as field;

view uses_call:
    input r0 as field.public;
    call helper r0 into r1;
    output r1 as field.public;",
        );
        assert!(result.is_err(), "expected program parse to fail when view contains 'call'");
    }

    #[test]
    fn test_program_rejects_duplicate_view_names() {
        let result = Program::<CurrentNetwork>::from_str(
            r"
program dup_view.aleo;

view foo:
    add 0u64 1u64 into r0;
    output r0 as u64.public;

view foo:
    add 0u64 2u64 into r0;
    output r0 as u64.public;",
        );
        assert!(result.is_err(), "expected program parse to fail with two views named 'foo'");
    }

    #[test]
    fn test_program_rejects_view_name_colliding_with_function() {
        let result = Program::<CurrentNetwork>::from_str(
            r"
program qf_collision.aleo;

function foo:
    input r0 as u64.private;
    output r0 as u64.private;

view foo:
    add 0u64 1u64 into r0;
    output r0 as u64.public;",
        );
        assert!(result.is_err(), "expected program parse to fail when a view reuses a function name");
    }

    #[test]
    fn test_program_rejects_view_name_colliding_with_closure() {
        let result = Program::<CurrentNetwork>::from_str(
            r"
program qc_collision.aleo;

closure foo:
    input r0 as field;
    output r0 as field;

function noop:
    input r0 as u64.private;
    output r0 as u64.private;

view foo:
    add 0u64 1u64 into r0;
    output r0 as u64.public;",
        );
        assert!(result.is_err(), "expected program parse to fail when a view reuses a closure name");
    }

    #[test]
    fn test_program_parse_function_zero_inputs() -> Result<()> {
        // Initialize a new program.
        let (string, program) = Program::<CurrentNetwork>::parse(
            r"
program to_parse.aleo;

function compute:
    add 1u32 2u32 into r0;
    output r0 as u32.private;",
        )
        .unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        // Ensure the program contains the function.
        assert!(program.contains_function(&Identifier::from_str("compute")?));

        Ok(())
    }

    #[test]
    fn test_program_display() -> Result<()> {
        let expected = r"program to_parse.aleo;

struct message:
    first as field;
    second as field;

function compute:
    input r0 as message.private;
    add r0.first r0.second into r1;
    output r1 as field.private;
";
        // Parse a new program.
        let program = Program::<CurrentNetwork>::from_str(expected)?;
        // Ensure the program string matches.
        assert_eq!(expected, format!("{program}"));

        Ok(())
    }

    #[test]
    fn test_program_size() {
        let max_program_size: usize = CurrentNetwork::LATEST_MAX_PROGRAM_SIZE();

        // Define variable name for easy experimentation with program sizes.
        let var_name = "a";

        // Helper function to generate imports.
        let gen_import_string = |n: usize| -> String {
            let mut s = String::new();
            for i in 0..n {
                s.push_str(&format!("import foo{i}.aleo;\n"));
            }
            s
        };

        // Helper function to generate large structs.
        let gen_struct_string = |n: usize| -> String {
            let mut s = String::with_capacity(max_program_size);
            for i in 0..n {
                s.push_str(&format!("struct m{i}:\n"));
                for j in 0..10 {
                    s.push_str(&format!("    {var_name}{j} as u128;\n"));
                }
            }
            s
        };

        // Helper function to generate large records.
        let gen_record_string = |n: usize| -> String {
            let mut s = String::with_capacity(max_program_size);
            for i in 0..n {
                s.push_str(&format!("record r{i}:\n    owner as address.private;\n"));
                for j in 0..10 {
                    s.push_str(&format!("    {var_name}{j} as u128.private;\n"));
                }
            }
            s
        };

        // Helper function to generate large mappings.
        let gen_mapping_string = |n: usize| -> String {
            let mut s = String::with_capacity(max_program_size);
            for i in 0..n {
                s.push_str(&format!("mapping {var_name}{i}:\n    key as field.public;\n    value as field.public;\n"));
            }
            s
        };

        // Helper function to generate large closures.
        let gen_closure_string = |n: usize| -> String {
            let mut s = String::with_capacity(max_program_size);
            for i in 0..n {
                s.push_str(&format!("closure c{i}:\n    input r0 as u128;\n"));
                for j in 0..30 {
                    s.push_str(&format!("    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r{j} as [u128; 64u32];\n"));
                }
                s.push_str(&format!("    output r{} as [u128; 32u32];\n", 4000));
            }
            s
        };

        // Helper function to generate large functions.
        let gen_function_string = |n: usize| -> String {
            let mut s = String::with_capacity(max_program_size);
            for i in 0..n {
                s.push_str(&format!("function f{i}:\n    add 1u128 1u128 into r0;\n"));
                for j in 0..250 {
                    s.push_str(&format!("    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r{j} as [u128; 64u32];\n"));
                }
            }
            s
        };

        // Helper function to generate and parse a program.
        let test_parse = |imports: &str, body: &str, should_succeed: bool| {
            let program = format!("{imports}\nprogram to_parse.aleo;\n\n{body}");
            let result = Program::<CurrentNetwork>::from_str(&program);
            if result.is_ok() != should_succeed {
                println!("Program failed to parse");
            }
            assert_eq!(result.is_ok(), should_succeed);
        };

        // A program with MAX_IMPORTS should succeed.
        test_parse(&gen_import_string(CurrentNetwork::MAX_IMPORTS), &gen_struct_string(1), true);
        // A program with more than MAX_IMPORTS should fail.
        test_parse(&gen_import_string(CurrentNetwork::MAX_IMPORTS + 1), &gen_struct_string(1), false);
        // A program with MAX_STRUCTS should succeed.
        test_parse("", &gen_struct_string(CurrentNetwork::MAX_STRUCTS), true);
        // A program with more than MAX_STRUCTS should fail.
        test_parse("", &gen_struct_string(CurrentNetwork::MAX_STRUCTS + 1), false);
        // A program with MAX_RECORDS should succeed.
        test_parse("", &gen_record_string(CurrentNetwork::MAX_RECORDS), true);
        // A program with more than MAX_RECORDS should fail.
        test_parse("", &gen_record_string(CurrentNetwork::MAX_RECORDS + 1), false);
        // A program with MAX_MAPPINGS should succeed.
        test_parse("", &gen_mapping_string(CurrentNetwork::LATEST_MAX_MAPPINGS()), true);
        // A program with more than MAX_MAPPINGS should fail.
        test_parse("", &gen_mapping_string(CurrentNetwork::LATEST_MAX_MAPPINGS() + 1), false);
        // A program with MAX_CLOSURES should succeed.
        test_parse("", &gen_closure_string(CurrentNetwork::MAX_CLOSURES), true);
        // A program with more than MAX_CLOSURES should fail.
        test_parse("", &gen_closure_string(CurrentNetwork::MAX_CLOSURES + 1), false);
        // A program with MAX_FUNCTIONS should succeed.
        test_parse("", &gen_function_string(CurrentNetwork::MAX_FUNCTIONS), true);
        // A program with more than MAX_FUNCTIONS should fail.
        test_parse("", &gen_function_string(CurrentNetwork::MAX_FUNCTIONS + 1), false);

        // Initialize a program which is too big.
        let program_too_big = format!(
            "{} {} {} {} {}",
            gen_struct_string(CurrentNetwork::MAX_STRUCTS),
            gen_record_string(CurrentNetwork::MAX_RECORDS),
            gen_mapping_string(CurrentNetwork::LATEST_MAX_MAPPINGS()),
            gen_closure_string(CurrentNetwork::MAX_CLOSURES),
            gen_function_string(CurrentNetwork::MAX_FUNCTIONS)
        );
        // A program which is too big should fail.
        test_parse("", &program_too_big, false);
    }
}
